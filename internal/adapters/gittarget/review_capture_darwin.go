//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// ReviewTargetAdapter captures the provider-visible target and a separate,
// immutable reference snapshot. It deliberately has no authority to write the
// source repository.
type ReviewTargetAdapter struct {
	runner         Runner
	stdin          ports.CapturedStdinStore
	detector       ports.ReviewInputContentDetector
	detectorPolicy string
}

var _ ports.ReviewTargetCapturer = (*ReviewTargetAdapter)(nil)

// NewReviewTargetCapturer constructs the production review-input capturer.
func NewReviewTargetCapturer(runner Runner, stdin ports.CapturedStdinStore, detector ports.ReviewInputContentDetector) (*ReviewTargetAdapter, error) {
	identity, ok := detector.(ports.ReviewInputContentDetectorIdentity)
	if runner == nil || stdin == nil || detector == nil || !ok || !validPolicyIdentity(identity.ReviewInputDetectorIdentity()) {
		return nil, fmt.Errorf("review target capturer: runner, stdin store, and identified detector are required")
	}
	return &ReviewTargetAdapter{runner: runner, stdin: stdin, detector: detector, detectorPolicy: identity.ReviewInputDetectorIdentity()}, nil
}

func (adapter *ReviewTargetAdapter) CaptureReviewTarget(ctx context.Context, root ports.AnchoredRoot, selector ports.ReviewTargetSelector) (ports.CapturedReviewMaterial, error) {
	if adapter == nil || adapter.runner == nil || adapter.stdin == nil || adapter.detector == nil || ctx == nil || !root.Valid() || !selector.Valid() {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("review target capture: invalid input")
	}
	switch selector.Kind() {
	case ports.ReviewTargetDiff:
		return adapter.captureDiff(ctx, root, selector.Value())
	case ports.ReviewTargetPatch:
		return adapter.capturePatch(ctx, root, selector.Value())
	case ports.ReviewTargetStdin:
		return adapter.captureStdin(ctx, root, selector.Value())
	default:
		return ports.CapturedReviewMaterial{}, fmt.Errorf("review target capture: unsupported selector")
	}
}

func (adapter *ReviewTargetAdapter) captureDiff(ctx context.Context, root ports.AnchoredRoot, value string) (ports.CapturedReviewMaterial, error) {
	if value == "git" {
		return adapter.captureDirty(ctx, root)
	}
	parts := strings.Split(value, "...")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || validateReference(parts[0]) != nil || validateReference(parts[1]) != nil {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("review target capture: diff must be git or base...head")
	}
	repo, cleanup, err := newCanonicalRepository(root, parts[0], parts[1], "HEAD")
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	defer func() { _ = cleanup() }()
	base, err := adapter.resolve(ctx, repo, parts[0])
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	head, err := adapter.resolve(ctx, repo, parts[1])
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	tree, err := adapter.tree(ctx, repo, head)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	patch, err := adapter.gitDiff(ctx, repo, base.String(), head.String())
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	if err := adapter.clean(ctx, ports.ReviewInputTarget, "diff", patch); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	baseFiles, err := adapter.objectSnapshot(ctx, root, base)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	headFiles, err := adapter.objectSnapshot(ctx, root, head)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	return adapter.materialize(patch, headFiles, map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceBase: baseFiles,
		ports.CapturedEvidenceHead: headFiles,
	}, "diff;git=canonical-v1;ignore=none;detector="+adapter.detectorPolicy, func() (ports.CapturedReviewTarget, error) {
		return ports.NewCapturedReviewGitTarget(repo.repositoryID, base, head, tree, nil, patch)
	})
}

func (adapter *ReviewTargetAdapter) capturePatch(ctx context.Context, root ports.AnchoredRoot, path string) (ports.CapturedReviewMaterial, error) {
	bytes, err := readStableRegular(root.String(), path, ports.ReviewTargetMaxBytes)
	if err != nil {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("review patch: %w", err)
	}
	if err := adapter.clean(ctx, ports.ReviewInputTarget, path, bytes); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	_, files, err := adapter.headSnapshot(ctx, root)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	return adapter.materialize(bytes, files, map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: files,
	}, "patch;git=canonical-v1;ignore=none;detector="+adapter.detectorPolicy, func() (ports.CapturedReviewTarget, error) { return ports.NewCapturedReviewPatchTarget(bytes) })
}

func (adapter *ReviewTargetAdapter) captureStdin(ctx context.Context, root ports.AnchoredRoot, token string) (ports.CapturedReviewMaterial, error) {
	bytes, err := adapter.stdin.TakeCapturedStdin(ctx, token)
	if err != nil {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("review stdin: %w", err)
	}
	if err := validateInput(bytes, false); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	if err := adapter.clean(ctx, ports.ReviewInputTarget, "stdin", bytes); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	_, files, err := adapter.headSnapshot(ctx, root)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	return adapter.materialize(bytes, files, map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: files,
	}, "stdin;git=canonical-v1;ignore=none;detector="+adapter.detectorPolicy, func() (ports.CapturedReviewTarget, error) { return ports.NewCapturedReviewStdinTarget(bytes) })
}

func (adapter *ReviewTargetAdapter) materialize(bytes []byte, files []ports.WorkspaceSnapshotFile, evidenceSides map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile, policy string, build func() (ports.CapturedReviewTarget, error)) (ports.CapturedReviewMaterial, error) {
	target, err := build()
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, policy)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	if target.NoChange() {
		return ports.NewCapturedReviewMaterial(target, snapshot, nil)
	}
	evidence, err := ports.NewCapturedTargetEvidence(evidenceSides)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	return ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
}

func (adapter *ReviewTargetAdapter) clean(ctx context.Context, channel ports.ReviewInputChannel, name string, bytes []byte) error {
	limit := int64(ports.ReviewTargetMaxBytes)
	allowEmpty := false
	if channel == ports.ReviewInputReference {
		limit = ports.WorkspaceSnapshotMaxFileBytes
		allowEmpty = true
	}
	if err := validateText(bytes, limit, allowEmpty); err != nil {
		return err
	}
	detection, err := adapter.detector.DetectReviewInput(ctx, channel, name, append([]byte(nil), bytes...))
	if err != nil {
		return fmt.Errorf("review input detector: %w", err)
	}
	if !detection.Valid() || detection.Verdict() != ports.ReviewInputClean {
		return fmt.Errorf("review input blocked")
	}
	return nil
}

func validateInput(bytes []byte, empty bool) error {
	return validateText(bytes, ports.ReviewTargetMaxBytes, empty)
}

func validateText(bytes []byte, limit int64, empty bool) error {
	if (!empty && len(bytes) == 0) || int64(len(bytes)) > limit || !utf8.Valid(bytes) || strings.IndexByte(string(bytes), 0) >= 0 {
		return fmt.Errorf("review input is not bounded UTF-8 text")
	}
	return nil
}

func validPolicyIdentity(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func (adapter *ReviewTargetAdapter) resolve(ctx context.Context, repo canonicalRepository, ref string) (ports.GitObjectID, error) {
	out, err := adapter.run(ctx, repo.command("rev-parse", "--verify", "--end-of-options", ref+"^{commit}"))
	if err != nil {
		return ports.GitObjectID{}, err
	}
	return parseObjectID(out.Stdout, "commit")
}
func (adapter *ReviewTargetAdapter) tree(ctx context.Context, repo canonicalRepository, oid ports.GitObjectID) (ports.GitObjectID, error) {
	out, err := adapter.run(ctx, repo.command("rev-parse", "--verify", "--end-of-options", oid.String()+"^{tree}"))
	if err != nil {
		return ports.GitObjectID{}, err
	}
	return parseObjectID(out.Stdout, "tree")
}
func (adapter *ReviewTargetAdapter) gitDiff(ctx context.Context, repo canonicalRepository, left, right string) ([]byte, error) {
	out, err := adapter.run(ctx, repo.command("diff", "--no-ext-diff", "--no-color", "--no-renames", "--no-indent-heuristic", "--diff-algorithm=myers", "--no-textconv", "--no-relative", "--unified=3", "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/", "--ignore-submodules=all", left, right))
	if err != nil {
		return nil, err
	}
	if err := validateInput(out.Stdout, true); err != nil {
		return nil, err
	}
	return out.Stdout, nil
}

func (adapter *ReviewTargetAdapter) headSnapshot(ctx context.Context, root ports.AnchoredRoot) (ports.GitObjectID, []ports.WorkspaceSnapshotFile, error) {
	repo, cleanup, err := newCanonicalRepository(root, "HEAD")
	if err != nil {
		return ports.GitObjectID{}, nil, err
	}
	defer func() { _ = cleanup() }()
	head, err := adapter.resolve(ctx, repo, "HEAD")
	if err != nil {
		return ports.GitObjectID{}, nil, err
	}
	files, err := adapter.objectSnapshot(ctx, root, head)
	return head, files, err
}

func (adapter *ReviewTargetAdapter) objectSnapshot(ctx context.Context, root ports.AnchoredRoot, commit ports.GitObjectID) ([]ports.WorkspaceSnapshotFile, error) {
	repo, cleanup, err := newCanonicalObjectRepository(root, commit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	out, err := adapter.run(ctx, repo.command("ls-tree", "-r", "-z", "--full-tree", commit.String()))
	if err != nil {
		return nil, err
	}
	var files []ports.WorkspaceSnapshotFile
	for _, entry := range strings.Split(string(out.Stdout), "\x00") {
		if entry == "" {
			continue
		}
		split := strings.SplitN(entry, "\t", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid tree entry")
		}
		fields := strings.Fields(split[0])
		if len(fields) != 3 || (fields[0] != "100644" && fields[0] != "100755") || fields[1] != "blob" {
			continue
		}
		path, err := ports.NewSafeRelativePath(split[1])
		if err != nil || reservedReviewPath(split[1]) {
			continue
		}
		blob, err := adapter.run(ctx, repo.command("cat-file", "blob", fields[2]))
		if err != nil {
			return nil, err
		}
		if int64(len(blob.Stdout)) > ports.WorkspaceSnapshotMaxFileBytes {
			return nil, fmt.Errorf("reference file exceeds limit")
		}
		if err := adapter.clean(ctx, ports.ReviewInputReference, path.String(), blob.Stdout); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(blob.Stdout)
		file, err := ports.NewWorkspaceSnapshotFile(path, blob.Stdout, "sha256:"+hex.EncodeToString(digest[:]))
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return sortFiles(files)
}

func sortFiles(files []ports.WorkspaceSnapshotFile) ([]ports.WorkspaceSnapshotFile, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path().String() < files[j].Path().String() })
	folder := cases.Fold()
	seen := map[string]struct{}{}
	for _, file := range files {
		path := file.Path().String()
		if !utf8.ValidString(path) || norm.NFC.String(path) != path {
			return nil, fmt.Errorf("non-normalized path")
		}
		key := folder.String(norm.NFC.String(path))
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("path collision")
		}
		seen[key] = struct{}{}
	}
	return files, nil
}
func reservedReviewPath(path string) bool {
	return path == ".git" || path == ".kar" || strings.HasPrefix(path, ".git/") || strings.HasPrefix(path, ".kar/")
}
func (adapter *ReviewTargetAdapter) captureDirty(ctx context.Context, root ports.AnchoredRoot) (ports.CapturedReviewMaterial, error) {
	repo, cleanup, err := newCanonicalRepository(root, "HEAD")
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	defer func() { _ = cleanup() }()
	head, err := adapter.resolve(ctx, repo, "HEAD")
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	tree, err := adapter.tree(ctx, repo, head)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	indexOut, err := adapter.run(ctx, Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "write-tree"}})
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	indexTree, err := parseObjectID(indexOut.Stdout, "index tree")
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	eligible, err := adapter.capturedIgnorePaths(ctx, root)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	out, err := adapter.run(ctx, Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "diff", "--no-ext-diff", "--no-color", "--no-renames", "--no-indent-heuristic", "--diff-algorithm=myers", "--no-textconv", "--no-relative", "--unified=3", "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/", "--ignore-submodules=all", head.String()}})
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	untracked, err := untrackedPatch(root, eligible.eligible)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	patch := append(append([]byte(nil), out.Stdout...), untracked...)
	if err := adapter.clean(ctx, ports.ReviewInputTarget, "git", patch); err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	baseFiles, err := adapter.objectSnapshot(ctx, root, head)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	files, err := adapter.worktreeSnapshot(ctx, root, eligible.eligible)
	if err != nil {
		return ports.CapturedReviewMaterial{}, err
	}
	verifyIndex, err := adapter.run(ctx, Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "write-tree"}})
	if err != nil || !bytes.Equal(indexOut.Stdout, verifyIndex.Stdout) {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("dirty source changed while capturing")
	}
	verifyDiff, err := adapter.run(ctx, Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "diff", "--no-ext-diff", "--no-color", "--no-renames", "--no-indent-heuristic", "--diff-algorithm=myers", "--no-textconv", "--no-relative", "--unified=3", "--inter-hunk-context=0", "--src-prefix=a/", "--dst-prefix=b/", "--ignore-submodules=all", head.String()}})
	if err != nil || !bytes.Equal(out.Stdout, verifyDiff.Stdout) {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("dirty source changed while capturing")
	}
	verifyUntracked, err := untrackedPatch(root, eligible.eligible)
	if err != nil || !bytes.Equal(untracked, verifyUntracked) {
		return ports.CapturedReviewMaterial{}, fmt.Errorf("dirty source changed while capturing")
	}
	return adapter.materialize(patch, files, map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceBase:     baseFiles,
		ports.CapturedEvidenceWorktree: files,
	}, "dirty;git=canonical-v1;ignore="+eligible.identity+";detector="+adapter.detectorPolicy, func() (ports.CapturedReviewTarget, error) {
		return ports.NewCapturedReviewGitTarget(repo.repositoryID, head, head, tree, &indexTree, patch)
	})
}

// untrackedPatch produces deterministic new-file hunks from the exact eligible
// paths returned by Git's captured ignore decision. It never asks Git to read a
// mutable path after that decision.
func untrackedPatch(root ports.AnchoredRoot, eligible map[string]bool) ([]byte, error) {
	paths := make([]string, 0, len(eligible))
	for path := range eligible {
		if !utf8.ValidString(path) || norm.NFC.String(path) != path {
			return nil, fmt.Errorf("non-normalized untracked path")
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var patch []byte
	for _, path := range paths {
		bytes, err := readStableRegular(root.String(), path, int(ports.ReviewTargetMaxBytes))
		if err != nil {
			return nil, fmt.Errorf("untracked %q: %w", path, err)
		}
		if len(patch)+len(bytes) > ports.ReviewTargetMaxBytes {
			return nil, fmt.Errorf("dirty patch exceeds limit")
		}
		oldPath := quoteGitPath("a/" + path)
		newPath := quoteGitPath("b/" + path)
		patch = append(patch, "diff --git "...)
		patch = append(patch, oldPath...)
		patch = append(patch, ' ')
		patch = append(patch, newPath...)
		patch = append(patch, "\nnew file mode 100644\n--- /dev/null\n+++ "...)
		patch = append(patch, newPath...)
		patch = append(patch, '\n')
		if len(bytes) == 0 {
			continue
		}
		lines := strings.Count(string(bytes), "\n")
		if bytes[len(bytes)-1] != '\n' {
			lines++
		}
		patch = append(patch, fmt.Sprintf("@@ -0,0 +1,%d @@\n", lines)...)
		for len(bytes) > 0 {
			lineEnd := strings.IndexByte(string(bytes), '\n')
			if lineEnd < 0 {
				patch = append(patch, '+')
				patch = append(patch, bytes...)
				patch = append(patch, "\n\\ No newline at end of file\n"...)
				break
			}
			patch = append(patch, '+')
			patch = append(patch, bytes[:lineEnd+1]...)
			bytes = bytes[lineEnd+1:]
		}
		if len(patch) > ports.ReviewTargetMaxBytes {
			return nil, fmt.Errorf("dirty patch exceeds limit")
		}
	}
	return patch, nil
}

func quoteGitPath(path string) string {
	safe := true
	for _, character := range path {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("/._-", character) {
			safe = false
			break
		}
	}
	if safe {
		return path
	}
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, value := range []byte(path) {
		switch value {
		case '\\', '"':
			quoted.WriteByte('\\')
			quoted.WriteByte(value)
		default:
			if value < 0x20 || value >= 0x7f {
				fmt.Fprintf(&quoted, "\\%03o", value)
			} else {
				quoted.WriteByte(value)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

func (adapter *ReviewTargetAdapter) worktreeSnapshot(ctx context.Context, root ports.AnchoredRoot, eligible map[string]bool) ([]ports.WorkspaceSnapshotFile, error) {
	trackedOut, err := adapter.run(ctx, Command{Dir: root.String(), Args: []string{"-c", "core.attributesFile=/dev/null", "ls-files", "-z"}})
	if err != nil {
		return nil, err
	}
	tracked := map[string]bool{}
	for _, path := range strings.Split(string(trackedOut.Stdout), "\x00") {
		if path == "" {
			continue
		}
		if _, err := ports.NewSafeRelativePath(path); err != nil || !utf8.ValidString(path) || norm.NFC.String(path) != path || reservedReviewPath(path) {
			return nil, fmt.Errorf("non-canonical tracked path")
		}
		if tracked[path] {
			return nil, fmt.Errorf("duplicate tracked path")
		}
		tracked[path] = true
	}
	if err := validateCapturedPathSet(tracked, eligible); err != nil {
		return nil, err
	}
	var files []ports.WorkspaceSnapshotFile
	err = filepath.WalkDir(root.String(), func(full string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if full == root.String() {
			return nil
		}
		relative, err := filepath.Rel(root.String(), full)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if reservedReviewPath(relative) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		selected := tracked[relative] || eligible[relative]
		if entry.Type()&os.ModeSymlink != 0 {
			if selected {
				return fmt.Errorf("captured path is a symlink")
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			if selected {
				return fmt.Errorf("captured path is not a regular file")
			}
			return nil
		}
		if !selected {
			return nil
		}
		bytes, err := readStableRegular(root.String(), relative, int(ports.WorkspaceSnapshotMaxFileBytes))
		if err != nil {
			return err
		}
		if err := adapter.clean(ctx, ports.ReviewInputReference, relative, bytes); err != nil {
			return err
		}
		path, err := ports.NewSafeRelativePath(relative)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(bytes)
		file, err := ports.NewWorkspaceSnapshotFile(path, bytes, "sha256:"+hex.EncodeToString(digest[:]))
		if err != nil {
			return err
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sortFiles(files)
}

func validateCapturedPathSet(sets ...map[string]bool) error {
	folder := cases.Fold()
	seen := make(map[string]struct{})
	for _, paths := range sets {
		for path := range paths {
			if _, err := ports.NewSafeRelativePath(path); err != nil || !utf8.ValidString(path) || norm.NFC.String(path) != path || reservedReviewPath(path) {
				return fmt.Errorf("non-canonical capture path")
			}
			key := folder.String(path)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("capture path collision")
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

// readStableRegular opens every namespace component with O_NOFOLLOW, keeps the
// opened descriptor pinned while reading, then repeats the descriptor walk to
// reject replacement races.
func readStableRegular(root, relative string, limit int) ([]byte, error) {
	path, err := ports.NewSafeRelativePath(relative)
	if err != nil || reservedReviewPath(relative) || !utf8.ValidString(relative) || norm.NFC.String(relative) != relative || limit <= 0 {
		return nil, fmt.Errorf("invalid capture path")
	}
	fd, err := openNofollowRegular(root, path.String())
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), relative)
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("capture path is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	var afterRead unix.Stat_t
	if err := unix.Fstat(fd, &afterRead); err != nil || !sameStableFile(before, afterRead) {
		return nil, fmt.Errorf("capture path changed while reading")
	}
	reopened, err := openNofollowRegular(root, path.String())
	if err != nil {
		return nil, fmt.Errorf("capture path changed while reading")
	}
	var afterPath unix.Stat_t
	statErr := unix.Fstat(reopened, &afterPath)
	unix.Close(reopened)
	if statErr != nil || !sameStableFile(before, afterPath) {
		return nil, fmt.Errorf("capture path changed while reading")
	}
	if len(data) > limit || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, fmt.Errorf("capture file is not bounded UTF-8 text")
	}
	return data, nil
}

func openNofollowRegular(root, relative string) (int, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for index, part := range strings.Split(relative, "/") {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < strings.Count(relative, "/") {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func sameStableFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func (adapter *ReviewTargetAdapter) run(ctx context.Context, command Command) (Result, error) {
	return adapter.runner.Run(ctx, command)
}
