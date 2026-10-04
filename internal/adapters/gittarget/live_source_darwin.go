//go:build darwin && arm64

package gittarget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var errLiveDirectory = errors.New("source path is a directory")
var errLiveNotRegular = errors.New("source path is not a regular file")

// LiveSourceAdapter opens original sources without materializing copies.
type LiveSourceAdapter struct {
	runner         Runner
	protectedRoots []ports.AnchoredRoot
}

func NewLiveSourceAdapter(runner Runner, protectedRoots []ports.AnchoredRoot) (*LiveSourceAdapter, error) {
	if runner == nil {
		return nil, fmt.Errorf("live source: runner is required")
	}
	resolvedRoots := make([]ports.AnchoredRoot, 0, len(protectedRoots))
	for _, root := range protectedRoots {
		if !root.Valid() {
			return nil, fmt.Errorf("live source: invalid protected root")
		}
		canonical, err := filepath.EvalSymlinks(root.String())
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		source, directory, err := openCanonicalRepositoryRoot(canonical)
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		var stat unix.Stat_t
		err = unix.Fstat(int(directory.file.Fd()), &stat)
		var resolved ports.AnchoredRoot
		if err == nil {
			resolved, err = bindingDescriptorRoot(directory.file, stat)
		}
		if err = errors.Join(err, source.close()); err != nil {
			return nil, sourceError(ports.LiveSourceUnsafe, err)
		}
		resolvedRoots = append(resolvedRoots, resolved)
	}
	return &LiveSourceAdapter{runner: runner, protectedRoots: resolvedRoots}, nil
}

var _ ports.LiveSourceOpener = (*LiveSourceAdapter)(nil)

type liveSourceReader struct {
	mu             sync.Mutex
	runner         Runner
	root           ports.AnchoredRoot
	target         ports.LiveSourceTarget
	lease          ports.ProjectBindingLease
	source         *canonicalRepositorySource
	rootDir        *canonicalMetadataDirectory
	gitDir         ports.AnchoredRoot
	protectedRoots []ports.AnchoredRoot
	closed         bool
}

func (adapter *LiveSourceAdapter) OpenLiveSource(ctx context.Context, root ports.AnchoredRoot, selector ports.LiveSourceSelector) (ports.LiveSourceReader, error) {
	if adapter == nil || ctx == nil || !root.Valid() || !selector.Valid() {
		return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("invalid source request"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(root.String())
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnsafe, err)
	}
	root, err = ports.NewAnchoredRoot(canonical)
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnsafe, err)
	}
	reader := &liveSourceReader{runner: adapter.runner, root: root, protectedRoots: adapter.protectedRoots}
	reader.source, reader.rootDir, err = openCanonicalRepositoryRoot(root.String())
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnsafe, err)
	}
	fail := func(code ports.LiveSourceErrorCode, cause error) (ports.LiveSourceReader, error) {
		return nil, sourceError(code, errors.Join(cause, reader.Close()))
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(int(reader.rootDir.file.Fd()), &rootStat); err != nil {
		return fail(ports.LiveSourceUnsafe, err)
	}
	reader.root, err = bindingDescriptorRoot(reader.rootDir.file, rootStat)
	if err != nil {
		return fail(ports.LiveSourceUnsafe, err)
	}
	root = reader.root
	if reader.protectedPath(root.String()) {
		return fail(ports.LiveSourceUnsafe, fmt.Errorf("protected source root"))
	}
	_, gitErr := os.Lstat(filepath.Join(root.String(), ".git"))
	if gitErr == nil {
		reader.lease, err = (ProjectBindingObserver{}).ObserveProjectBinding(ctx, root)
		if err != nil {
			return fail(ports.LiveSourceUnsafe, err)
		}
		observation := reader.lease.Observation()
		reader.gitDir = observation.GitDirectory
		if reader.protectedPath(reader.gitDir.String()) || reader.protectedPath(observation.CommonDirectory.String()) {
			return fail(ports.LiveSourceUnsafe, fmt.Errorf("protected Git directory"))
		}
		if err := reader.checkGitMetadata(); err != nil {
			return fail(ports.LiveSourceUnsafe, err)
		}
	} else if !os.IsNotExist(gitErr) {
		return fail(ports.LiveSourceUnsafe, gitErr)
	} else if selector.Scope() != domain.LiveSourceWorkspace {
		return fail(ports.LiveSourceRevision, fmt.Errorf("Git source is unavailable"))
	}
	if err := reader.revalidate(ctx); err != nil {
		_ = reader.Close()
		return nil, err
	}
	if err := reader.admit(ctx, selector); err != nil {
		_ = reader.Close()
		return nil, err
	}
	return reader, nil
}

func (reader *liveSourceReader) Root() ports.AnchoredRoot       { return reader.root }
func (reader *liveSourceReader) Target() ports.LiveSourceTarget { return reader.target }

func (reader *liveSourceReader) RevalidateExecution(ctx context.Context) (ports.ProjectBindingObservation, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if ctx == nil {
		return ports.ProjectBindingObservation{}, sourceError(ports.LiveSourceInvalid, fmt.Errorf("nil execution context"))
	}
	if err := reader.revalidate(ctx); err != nil {
		return ports.ProjectBindingObservation{}, err
	}
	if reader.lease != nil {
		if err := reader.checkGitMetadata(); err != nil {
			return ports.ProjectBindingObservation{}, err
		}
		return reader.lease.Observation(), nil
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(reader.rootDir.file.Fd()), &stat); err != nil {
		return ports.ProjectBindingObservation{}, sourceError(ports.LiveSourceUnsafe, err)
	}
	return ports.ProjectBindingObservation{Root: reader.root, RootIdentity: ports.ProjectDirectoryIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, BirthSeconds: stat.Btim.Sec, BirthNanoseconds: stat.Btim.Nsec}}, nil
}

func (reader *liveSourceReader) revalidate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if reader.closed {
		return sourceError(ports.LiveSourceUnavailable, fmt.Errorf("source reader is closed"))
	}
	// Capture's directory verifier also pins mtime/size. Live reads bind the
	// namespace and descriptor, allowing ordinary directory-content changes.
	var stat unix.Stat_t
	if err := unix.Fstat(int(reader.rootDir.file.Fd()), &stat); err != nil {
		return sourceError(ports.LiveSourceUnsafe, err)
	}
	actual := canonicalMetadataIdentityForStat(&stat)
	if !reader.rootDir.identity.sameLocation(actual) || reader.rootDir.identity.generation != actual.generation ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
		return sourceError(ports.LiveSourceUnsafe, fmt.Errorf("source root changed"))
	}
	root, err := bindingDescriptorRoot(reader.rootDir.file, stat)
	if err != nil || root != reader.root {
		return sourceError(ports.LiveSourceUnsafe, fmt.Errorf("source root namespace changed"))
	}
	if reader.lease != nil {
		if err := reader.lease.Revalidate(ctx); err != nil {
			return sourceError(ports.LiveSourceUnsafe, err)
		}
	}
	return nil
}

func (reader *liveSourceReader) checkGitMetadata() error {
	// Git reads original local configuration. Admit regular local files, and
	// override executable-bearing policies on every invocation. This check
	// rejects config replacement by an unsafe path without freezing its bytes.
	for _, path := range []string{
		filepath.Join(reader.lease.Observation().CommonDirectory.String(), "config"),
		filepath.Join(reader.gitDir.String(), "config.worktree"),
	} {
		if _, err := readCanonicalGitMetadata(path); err != nil && !os.IsNotExist(err) {
			return sourceError(ports.LiveSourceUnsafe, err)
		}
	}
	// Alternate databases escape the admitted Git binding, including chained
	// stores. Reject them rather than authorizing additional source locations.
	alternates := filepath.Join(reader.lease.Observation().CommonDirectory.String(), "objects", "info", "alternates")
	if _, err := readCanonicalGitMetadata(alternates); !os.IsNotExist(err) {
		if err == nil {
			err = fmt.Errorf("alternate object databases are unsupported")
		}
		return sourceError(ports.LiveSourceUnsafe, err)
	}
	return nil
}

func (reader *liveSourceReader) run(ctx context.Context, args ...string) (Result, error) {
	if err := reader.revalidate(ctx); err != nil {
		return Result{}, err
	}
	if err := reader.checkGitMetadata(); err != nil {
		return Result{}, err
	}
	prefix := []string{"--no-pager", "--literal-pathspecs", "--git-dir=" + reader.gitDir.String(), "--work-tree=" + reader.root.String()}
	for _, setting := range []string{
		"core.hooksPath=/dev/null", "core.fsmonitor=false", "core.untrackedCache=false",
		"core.attributesFile=/dev/null", "core.excludesFile=/dev/null", "core.bare=false",
		"gc.auto=0", "maintenance.auto=false", "protocol.allow=never", "diff.external=", "diff.renames=true", "color.ui=false",
	} {
		prefix = append(prefix, "-c", setting)
	}
	command := Command{Dir: reader.root.String(), Args: append(prefix, args...)}
	if len(args) > 0 && (args[0] == "cat-file" || args[0] == "ls-files" || args[0] == "ls-tree" || args[0] == "diff" || args[0] == "diff-tree") {
		command = command.withSourceSizedStdout()
	}
	result, err := reader.runner.Run(ctx, command)
	if checkErr := reader.revalidate(ctx); checkErr != nil {
		return Result{}, checkErr
	}
	return result, err
}

func (reader *liveSourceReader) resolve(ctx context.Context, revision string) (ports.GitObjectID, error) {
	result, err := reader.run(ctx, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return ports.GitObjectID{}, sourceError(ports.LiveSourceRevision, err)
	}
	oid, err := parseObjectID(result.Stdout, "commit")
	if err != nil {
		return ports.GitObjectID{}, sourceError(ports.LiveSourceRevision, err)
	}
	return oid, nil
}

func (reader *liveSourceReader) admit(ctx context.Context, selector ports.LiveSourceSelector) error {
	var base, head ports.GitObjectID
	var changes []ports.LiveSourceChange
	emptyBase := false
	var err error
	switch selector.Scope() {
	case domain.LiveSourceWorkspace:
		reader.target, err = ports.NewLiveSourceTarget(selector, base, head, false, nil)
		if err != nil {
			return sourceError(ports.LiveSourceInvalid, err)
		}
		paths, listErr := reader.list(ctx, domain.LiveSourceWorktree)
		if listErr != nil {
			return listErr
		}
		for _, path := range paths {
			changes = append(changes, ports.LiveSourceChange{Kind: "included", After: path})
		}
	case domain.LiveSourceStage:
		if _, err := reader.index(ctx, nil); err != nil {
			return err
		}
		base, err = reader.resolve(ctx, "HEAD")
		if err != nil {
			// Only a verified missing branch is an unborn HEAD. Other failed
			// resolutions must not become an empty-tree comparison.
			branch, branchErr := reader.run(ctx, "symbolic-ref", "--quiet", "HEAD")
			if branchErr != nil {
				return err
			}
			ref := strings.TrimSpace(string(branch.Stdout))
			if !strings.HasPrefix(ref, "refs/heads/") || strings.ContainsAny(ref, "\x00\r\n") {
				return err
			}
			_, missingErr := reader.run(ctx, "show-ref", "--verify", "--quiet", "--", ref)
			var exit *exec.ExitError
			if !errors.As(missingErr, &exit) || exit.ExitCode() != 1 {
				return err
			}
			emptyBase = true
		}
	case domain.LiveSourceHead, domain.LiveSourceCommit:
		revision := "HEAD"
		if selector.Scope() == domain.LiveSourceCommit {
			revision = selector.Value()
		}
		head, err = reader.resolve(ctx, revision)
		if err != nil {
			return err
		}
		if selector.Scope() == domain.LiveSourceCommit {
			result, err := reader.run(ctx, "rev-list", "--parents", "--no-walk", "-n", "1", head.String())
			if err != nil {
				return sourceError(ports.LiveSourceRevision, err)
			}
			parents := strings.Fields(string(result.Stdout))
			if len(parents) == 0 || parents[0] != head.String() {
				return sourceError(ports.LiveSourceRevision, fmt.Errorf("invalid commit parents"))
			}
			emptyBase = len(parents) == 1
			if !emptyBase {
				base, err = ports.ParseGitObjectID(parents[1])
				if err != nil {
					return sourceError(ports.LiveSourceRevision, err)
				}
			}
		}
	case domain.LiveSourceDiff:
		left, right, operator := selector.RangeOperands()
		base, err = reader.resolve(ctx, left)
		if err != nil {
			return err
		}
		head, err = reader.resolve(ctx, right)
		if err != nil {
			return err
		}
		if operator == "..." {
			result, err := reader.run(ctx, "merge-base", base.String(), head.String())
			if err != nil {
				return sourceError(ports.LiveSourceNoMergeBase, err)
			}
			base, err = parseObjectID(result.Stdout, "merge base")
			if err != nil {
				return sourceError(ports.LiveSourceNoMergeBase, err)
			}
		}
	}
	reader.target, err = ports.NewLiveSourceTarget(selector, base, head, emptyBase, changes)
	if err != nil {
		return sourceError(ports.LiveSourceInvalid, err)
	}
	if selector.Scope() != domain.LiveSourceWorkspace {
		afterSide := domain.LiveSourceAfter
		if selector.Scope() == domain.LiveSourceStage {
			afterSide = domain.LiveSourceIndex
		}
		after, err := reader.list(ctx, afterSide)
		if err != nil {
			return err
		}
		if selector.Scope() == domain.LiveSourceHead {
			for _, path := range after {
				changes = append(changes, ports.LiveSourceChange{Kind: "included", After: path})
			}
		} else {
			if !emptyBase {
				if _, err := reader.list(ctx, domain.LiveSourceBefore); err != nil {
					return err
				}
			}
			changes, err = reader.changedPaths(ctx)
			if err != nil {
				return err
			}
		}
		target, targetErr := ports.NewLiveSourceTarget(selector, base, head, emptyBase, changes)
		if targetErr != nil {
			return sourceError(ports.LiveSourceInvalid, targetErr)
		}
		reader.target = target
	}
	return err
}

func (reader *liveSourceReader) changedPaths(ctx context.Context) ([]ports.LiveSourceChange, error) {
	args := []string{"diff", "--name-status", "-z", "--find-renames=50%", "-l0", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all", "--no-relative"}
	switch {
	case reader.target.Selector().Scope() == domain.LiveSourceStage:
		args = append(args, "--cached")
		if !reader.target.EmptyBase() {
			args = append(args, reader.target.Base().String())
		}
	case reader.target.EmptyBase():
		args = []string{"diff-tree", "--root", "--no-commit-id", "-r", "--name-status", "-z", "--find-renames=50%", "-l0", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all", reader.target.Head().String()}
	default:
		args = append(args, reader.target.Base().String(), reader.target.Head().String())
	}
	args = append(args, "--")
	result, err := reader.run(ctx, args...)
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnavailable, err)
	}
	fields, err := liveNULFields(result.Stdout)
	if err != nil {
		return nil, err
	}
	var changes []ports.LiveSourceChange
	for i := 0; i < len(fields); {
		status := fields[i]
		i++
		if status == "" || i >= len(fields) {
			return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("invalid change record"))
		}
		first, err := livePath(fields[i])
		if err != nil {
			return nil, err
		}
		i++
		change := ports.LiveSourceChange{}
		switch status[0] {
		case 'A':
			change = ports.LiveSourceChange{Kind: "added", After: first}
		case 'D':
			change = ports.LiveSourceChange{Kind: "deleted", Before: first}
		case 'M', 'T':
			change = ports.LiveSourceChange{Kind: "modified", Before: first, After: first}
		case 'R':
			if i >= len(fields) {
				return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("missing rename destination"))
			}
			second, err := livePath(fields[i])
			if err != nil {
				return nil, err
			}
			i++
			change = ports.LiveSourceChange{Kind: "renamed", Before: first, After: second}
		default:
			return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("unsupported change record"))
		}
		beforeExcluded := !change.Before.Valid() || reader.excluded(change.Before.String())
		afterExcluded := !change.After.Valid() || reader.excluded(change.After.String())
		if beforeExcluded && afterExcluded {
			continue
		}
		if change.Kind == "renamed" {
			if beforeExcluded {
				change = ports.LiveSourceChange{Kind: "added", After: change.After}
			} else if afterExcluded {
				change = ports.LiveSourceChange{Kind: "deleted", Before: change.Before}
			}
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func (reader *liveSourceReader) List(ctx context.Context, side domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if err := reader.revalidate(ctx); err != nil {
		return nil, err
	}
	paths, err := reader.list(ctx, side)
	if err != nil {
		return nil, err
	}
	if err := reader.revalidate(ctx); err != nil {
		return nil, err
	}
	return paths, nil
}

func (reader *liveSourceReader) list(ctx context.Context, side domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	if side == domain.LiveSourceWorktree && reader.target.Selector().Scope() == domain.LiveSourceWorkspace {
		if reader.lease == nil {
			return reader.workspacePaths(ctx)
		}
		result, err := reader.run(ctx, "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--")
		if err != nil {
			return nil, sourceError(ports.LiveSourceUnavailable, err)
		}
		fields, err := liveNULFields(result.Stdout)
		if err != nil {
			return nil, err
		}
		paths := make(map[string]ports.GitObjectID)
		for _, value := range fields {
			if reader.excluded(value) {
				continue
			}
			if strings.HasSuffix(value, "/") {
				continue // Git lists an untracked nested repository as a directory.
			}
			path, err := livePath(value)
			if err != nil {
				return nil, err
			}
			fd, err := reader.openRegular(path)
			if os.IsNotExist(err) || errors.Is(err, errLiveDirectory) {
				continue // Tracked deletions have no current workspace file.
			}
			if err != nil {
				return nil, sourceError(ports.LiveSourceUnsafe, err)
			}
			_ = unix.Close(fd)
			paths[value] = ports.GitObjectID{}
		}
		return liveSortedPaths(paths)
	}
	entries, err := reader.entries(ctx, side, nil)
	if err != nil {
		return nil, err
	}
	return liveSortedPaths(entries)
}

func (reader *liveSourceReader) entries(ctx context.Context, side domain.LiveSourceSide, path *ports.SafeRelativePath) (map[string]ports.GitObjectID, error) {
	scope := reader.target.Selector().Scope()
	if side == domain.LiveSourceIndex && scope == domain.LiveSourceStage {
		return reader.index(ctx, path)
	}
	var oid ports.GitObjectID
	switch {
	case side == domain.LiveSourceBefore && (scope == domain.LiveSourceStage || scope == domain.LiveSourceCommit || scope == domain.LiveSourceDiff):
		if reader.target.EmptyBase() {
			return map[string]ports.GitObjectID{}, nil
		}
		oid = reader.target.Base()
	case side == domain.LiveSourceAfter && (scope == domain.LiveSourceHead || scope == domain.LiveSourceCommit || scope == domain.LiveSourceDiff):
		oid = reader.target.Head()
	default:
		return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("side is unavailable for selector"))
	}
	args := []string{"ls-tree", "-r", "-z", "--full-tree", oid.String()}
	if path != nil {
		args = append(args, "--", path.String())
	}
	result, err := reader.run(ctx, args...)
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnavailable, err)
	}
	return liveObjectEntries(result.Stdout, false, reader.excluded)
}

func (reader *liveSourceReader) index(ctx context.Context, path *ports.SafeRelativePath) (map[string]ports.GitObjectID, error) {
	args := []string{"ls-files", "--stage", "-z", "--"}
	if path != nil {
		args = append(args, path.String())
	}
	result, err := reader.run(ctx, args...)
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnavailable, err)
	}
	return liveObjectEntries(result.Stdout, true, reader.excluded)
}

func liveObjectEntries(data []byte, index bool, excluded func(string) bool) (map[string]ports.GitObjectID, error) {
	fields, err := liveNULFields(data)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]ports.GitObjectID)
	for _, entry := range fields {
		metadata, value, ok := strings.Cut(entry, "\t")
		parts := strings.Fields(metadata)
		if !ok || len(parts) != 3 {
			return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("invalid object inventory"))
		}
		if index && parts[2] != "0" {
			return nil, sourceError(ports.LiveSourceConflict, fmt.Errorf("index has unmerged entries"))
		}
		if excluded(value) || parts[0] == "160000" {
			continue
		}
		if parts[0] != "100644" && parts[0] != "100755" || !index && parts[1] != "blob" {
			return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("selected path is not a regular blob"))
		}
		if _, err := livePath(value); err != nil {
			return nil, err
		}
		oidValue := parts[2]
		if index {
			oidValue = parts[1]
		}
		oid, err := ports.ParseGitObjectID(oidValue)
		if err != nil {
			return nil, sourceError(ports.LiveSourceInvalid, err)
		}
		if _, exists := entries[value]; exists {
			return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("duplicate object path"))
		}
		entries[value] = oid
	}
	if _, err := liveSortedPaths(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (reader *liveSourceReader) Read(ctx context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !path.Valid() || reader.excluded(path.String()) {
		return ports.LiveSourceFile{}, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("invalid source path"))
	}
	if err := reader.revalidate(ctx); err != nil {
		return ports.LiveSourceFile{}, err
	}
	var data []byte
	var err error
	if side == domain.LiveSourceWorktree && reader.target.Selector().Scope() == domain.LiveSourceWorkspace {
		// Ignore rules select candidates; they do not forbid relevant support.
		data, err = reader.readRegular(path)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, errLiveDirectory) || errors.Is(err, errLiveNotRegular) {
			return ports.LiveSourceFile{}, sourceError(ports.LiveSourceUnsafe, err)
		}
	} else {
		entries, entriesErr := reader.entries(ctx, side, &path)
		if entriesErr != nil {
			return ports.LiveSourceFile{}, entriesErr
		}
		oid, found := entries[path.String()]
		if !found {
			return ports.LiveSourceFile{}, sourceError(ports.LiveSourceUnavailable, fmt.Errorf("path is absent from source side"))
		}
		result, readErr := reader.run(ctx, "cat-file", "blob", oid.String())
		data, err = result.Stdout, readErr
	}
	if err != nil {
		return ports.LiveSourceFile{}, sourceError(ports.LiveSourceUnavailable, err)
	}
	if err := reader.revalidate(ctx); err != nil {
		return ports.LiveSourceFile{}, err
	}
	mediaType := rasterMediaType(path.String())
	if mediaType == "" {
		mediaType = "text/plain"
		if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			mediaType = "application/octet-stream"
		}
	}
	file, err := ports.NewLiveSourceFile(path, data, mediaType)
	if err != nil {
		return ports.LiveSourceFile{}, sourceError(ports.LiveSourceUnsupported, err)
	}
	return file, nil
}

func (reader *liveSourceReader) openRegular(path ports.SafeRelativePath) (int, error) {
	fd, err := reader.openPath(path.String(), false)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			return -1, errLiveDirectory
		}
		return -1, errLiveNotRegular
	}
	return fd, nil
}

func (reader *liveSourceReader) openPath(relative string, directory bool) (int, error) {
	fd, err := unix.Openat(int(reader.rootDir.file.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil || relative == "" {
		return fd, err
	}
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func (reader *liveSourceReader) readRegular(path ports.SafeRelativePath) ([]byte, error) {
	return reader.readRegularWithLimit(path, 0)
}

func (reader *liveSourceReader) readRegularWithLimit(path ports.SafeRelativePath, limit int64) ([]byte, error) {
	fd, err := reader.openRegular(path)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path.String())
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	var input io.Reader = file
	if limit > 0 {
		input = io.LimitReader(file, limit+1)
	}
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, fmt.Errorf("source configuration exceeds its byte limit")
	}
	if err := unix.Fstat(fd, &after); err != nil || !sameStableFile(before, after) {
		return nil, fmt.Errorf("source file changed during read")
	}
	reopened, err := reader.openRegular(path)
	if err != nil {
		return nil, err
	}
	statErr := unix.Fstat(reopened, &after)
	_ = unix.Close(reopened)
	if statErr != nil || !sameStableFile(before, after) {
		return nil, fmt.Errorf("source file namespace changed during read")
	}
	return data, nil
}

func (reader *liveSourceReader) Close() error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	var err error
	if reader.lease != nil {
		err = reader.lease.Close()
	}
	return errors.Join(err, reader.source.close())
}

func sourceError(code ports.LiveSourceErrorCode, cause error) error {
	var typed *ports.LiveSourceError
	if errors.As(cause, &typed) || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return ports.NewLiveSourceError(code, cause)
}

func liveExcluded(path string) bool {
	for _, part := range strings.Split(path, "/") {
		switch strings.ToLower(part) {
		case ".git", ".mulgae", ".codex", ".grok", ".zcode":
			return true
		}
	}
	return false
}

func (reader *liveSourceReader) excluded(path string) bool {
	return liveExcluded(path) || reader.protectedPath(filepath.Join(reader.root.String(), filepath.FromSlash(path)))
}

// Protected roots are canonical machine-owned credential/runtime locations
// supplied by application admission, including named Codex profile homes.
func (reader *liveSourceReader) protectedPath(path string) bool {
	fold := cases.Fold()
	full := fold.String(norm.NFC.String(path))
	for _, root := range reader.protectedRoots {
		relative, err := filepath.Rel(fold.String(norm.NFC.String(root.String())), full)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, "../") {
			return true
		}
	}
	return false
}

func livePath(value string) (ports.SafeRelativePath, error) {
	path, err := ports.NewSafeRelativePath(value)
	if err != nil || !utf8.ValidString(value) || norm.NFC.String(value) != value {
		return ports.SafeRelativePath{}, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("non-canonical source path"))
	}
	return path, nil
}

func liveNULFields(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != 0 {
		return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("inventory is not NUL-terminated"))
	}
	fields := strings.Split(string(data[:len(data)-1]), "\x00")
	return fields, nil
}

func liveSortedPaths(entries map[string]ports.GitObjectID) ([]ports.SafeRelativePath, error) {
	values := make([]string, 0, len(entries))
	for value := range entries {
		values = append(values, value)
	}
	sort.Strings(values)
	seen := make(map[string]bool)
	fold := cases.Fold()
	paths := make([]ports.SafeRelativePath, 0, len(values))
	for _, value := range values {
		path, err := livePath(value)
		if err != nil {
			return nil, err
		}
		key := fold.String(value)
		if seen[key] {
			return nil, sourceError(ports.LiveSourceUnsafe, fmt.Errorf("source path collision"))
		}
		seen[key] = true
		paths = append(paths, path)
	}
	return paths, nil
}

// OpenUnboundWorkspaceRoot pins only a non-Git root, without selecting or reading
// source files. It cannot turn failed Git binding into a new startup anchor.
func OpenUnboundWorkspaceRoot(ctx context.Context, root ports.AnchoredRoot) (ports.WorkspaceRootLease, error) {
	if ctx == nil || !root.Valid() {
		return nil, sourceError(ports.LiveSourceInvalid, fmt.Errorf("invalid workspace root"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, directory, err := openCanonicalRepositoryRoot(root.String())
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnsafe, err)
	}
	reader := &liveSourceReader{root: root, source: source, rootDir: directory}
	var observed unix.Stat_t
	err = unix.Fstat(int(directory.file.Fd()), &observed)
	if err == nil {
		reader.root, err = bindingDescriptorRoot(directory.file, observed)
	}
	lease := &unboundWorkspaceRootLease{reader: reader}
	if err == nil {
		err = lease.Revalidate(ctx)
	}
	if err != nil {
		return nil, sourceError(ports.LiveSourceUnsafe, errors.Join(err, reader.Close()))
	}
	return lease, nil
}

type unboundWorkspaceRootLease struct{ reader *liveSourceReader }

func (lease *unboundWorkspaceRootLease) Revalidate(ctx context.Context) error {
	reader := lease.reader
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if err := reader.revalidate(ctx); err != nil {
		return err
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(int(reader.rootDir.file.Fd()), ".git", &entry, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		if err == nil {
			err = fmt.Errorf("non-Git startup root acquired Git metadata")
		}
		return sourceError(ports.LiveSourceUnsafe, err)
	}
	return ctx.Err()
}

func (lease *unboundWorkspaceRootLease) Close() error { return lease.reader.Close() }
