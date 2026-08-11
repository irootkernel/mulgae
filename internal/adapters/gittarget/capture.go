//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/irootkernel/mulgae/internal/ports"
)

// Adapter captures immutable Git targets and reads trusted project files from
// already-resolved commits.
type Adapter struct {
	runner                       Runner
	newCanonicalRepository       canonicalRepositoryFactory
	newCanonicalObjectRepository canonicalObjectRepositoryFactory

	transcriptMu sync.Mutex
	transcript   []Command
}

type canonicalRepositoryFactory func(ports.AnchoredRoot, ...string) (canonicalRepository, func() error, error)

type canonicalObjectRepositoryFactory func(ports.AnchoredRoot, ports.GitObjectID) (canonicalRepository, func() error, error)

var _ ports.GitTargetCapture = (*Adapter)(nil)
var _ ports.TrustedProjectReader = (*Adapter)(nil)

// New constructs a Git target adapter around an injectable direct-argv runner.
func New(runner Runner) (*Adapter, error) {
	if runner == nil {
		return nil, fmt.Errorf("Git target adapter: nil runner")
	}
	return &Adapter{
		runner:                       runner,
		newCanonicalRepository:       newCanonicalRepository,
		newCanonicalObjectRepository: newCanonicalObjectRepository,
	}, nil
}

// Transcript returns caller-owned copies of every attempted direct Git command
// in invocation order.
func (adapter *Adapter) Transcript() []Command {
	if adapter == nil {
		return nil
	}
	adapter.transcriptMu.Lock()
	defer adapter.transcriptMu.Unlock()
	transcript := make([]Command, len(adapter.transcript))
	for index, command := range adapter.transcript {
		transcript[index] = command.Clone()
	}
	return transcript
}

// Capture resolves base and head exactly once, then captures only immutable OID
// inputs. It never invokes Git commands that write repository state.
func (adapter *Adapter) Capture(ctx context.Context, request ports.GitCaptureRequest) (target ports.CapturedGitTarget, captureErr error) {
	if adapter == nil || adapter.runner == nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture: nil adapter")
	}
	if ctx == nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture: nil context")
	}
	if !request.ProjectRoot().Valid() {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture: invalid project root")
	}

	repository, cleanup, err := adapter.newCanonicalRepository(request.ProjectRoot(), request.BaseReference(), request.HeadReference())
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture canonical repository: %w", err)
	}
	defer finalizeCanonicalCleanup(cleanup, "Git capture", &captureErr, func() {
		target = ports.CapturedGitTarget{}
	})

	baseObjectID, err := adapter.resolveCommit(ctx, repository, request.BaseReference())
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture resolve base: %w", err)
	}
	headObjectID, err := adapter.resolveCommit(ctx, repository, request.HeadReference())
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture resolve head: %w", err)
	}
	headTreeID, err := adapter.headTree(ctx, repository, headObjectID)
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture head tree: %w", err)
	}
	diff, err := adapter.diff(ctx, repository, baseObjectID, headObjectID)
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture diff: %w", err)
	}

	var inventory []byte
	if request.IncludeUntracked() {
		inventory, err = adapter.untrackedInventory(ctx, request.ProjectRoot())
		if err != nil {
			return ports.CapturedGitTarget{}, fmt.Errorf("Git capture untracked inventory: %w", err)
		}
	}

	capturedBytes := canonicalCapturedBytes(
		repository.repositoryID,
		baseObjectID,
		headObjectID,
		headTreeID,
		nil,
		request.IncludeUntracked(),
		diff,
		inventory,
	)
	target, err = ports.NewCapturedGitTarget(repository.repositoryID, baseObjectID, headObjectID, headTreeID, nil, capturedBytes)
	if err != nil {
		return ports.CapturedGitTarget{}, fmt.Errorf("Git capture target: %w", err)
	}
	return target, nil
}

// ResolveCommit resolves reference exactly once to a canonical immutable commit
// ID. Callers must pass the returned ID to ReadFileAtCommit rather than a ref.
func (adapter *Adapter) ResolveCommit(ctx context.Context, root ports.AnchoredRoot, reference string) (commit ports.GitObjectID, resolveErr error) {
	if adapter == nil || adapter.runner == nil {
		return ports.GitObjectID{}, fmt.Errorf("Git resolve commit: nil adapter")
	}
	if ctx == nil {
		return ports.GitObjectID{}, fmt.Errorf("Git resolve commit: nil context")
	}
	if !root.Valid() {
		return ports.GitObjectID{}, fmt.Errorf("Git resolve commit: invalid project root")
	}
	if err := validateReference(reference); err != nil {
		return ports.GitObjectID{}, fmt.Errorf("Git resolve commit: %w", err)
	}

	repository, cleanup, err := adapter.newCanonicalRepository(root, reference)
	if err != nil {
		return ports.GitObjectID{}, fmt.Errorf("Git resolve commit canonical repository: %w", err)
	}
	defer finalizeCanonicalCleanup(cleanup, "Git resolve commit", &resolveErr, func() {
		commit = ports.GitObjectID{}
	})
	return adapter.resolveCommit(ctx, repository, reference)
}

func (adapter *Adapter) resolveCommit(ctx context.Context, repository canonicalRepository, reference string) (ports.GitObjectID, error) {
	result, err := adapter.run(ctx, repository.command(
		"rev-parse", "--verify", "--end-of-options", reference+"^{commit}",
	))
	if err != nil {
		return ports.GitObjectID{}, err
	}
	objectID, err := parseObjectID(result.Stdout, "commit")
	if err != nil {
		return ports.GitObjectID{}, err
	}
	return objectID, nil
}

// ReadFileAtCommit reads a trusted project file from the supplied immutable
// commit. It never falls back to a working-tree path.
func (adapter *Adapter) ReadFileAtCommit(ctx context.Context, root ports.AnchoredRoot, commit ports.GitObjectID, file ports.SafeRelativePath) (data []byte, readErr error) {
	if adapter == nil || adapter.runner == nil {
		return nil, fmt.Errorf("Git read file: nil adapter")
	}
	if ctx == nil {
		return nil, fmt.Errorf("Git read file: nil context")
	}
	if !root.Valid() || !commit.Valid() || !file.Valid() {
		return nil, fmt.Errorf("Git read file: invalid root, commit, or path")
	}

	repository, cleanup, err := adapter.newCanonicalObjectRepository(root, commit)
	if err != nil {
		return nil, fmt.Errorf("Git read file canonical repository: %w", err)
	}
	defer finalizeCanonicalCleanup(cleanup, "Git read file", &readErr, func() {
		data = nil
	})

	tree, err := adapter.run(ctx, repository.command(
		"ls-tree", "-z", "--full-tree", commit.String(), "--", ":(literal)"+file.String(),
	))
	if err != nil {
		return nil, err
	}
	blob, err := parseRegularBlobTreeEntry(tree.Stdout, file)
	if err != nil {
		return nil, err
	}
	if !blob.Valid() {
		return nil, fmt.Errorf("Git tree path %q: %w", file.String(), fs.ErrNotExist)
	}

	result, err := adapter.run(ctx, repository.sourceCommand("cat-file", "blob", blob.String()))
	if err != nil {
		return nil, err
	}
	return cloneBytes(result.Stdout), nil
}

func (adapter *Adapter) headTree(ctx context.Context, repository canonicalRepository, head ports.GitObjectID) (ports.GitObjectID, error) {
	result, err := adapter.run(ctx, repository.command(
		"rev-parse", "--verify", "--end-of-options", head.String()+"^{tree}",
	))
	if err != nil {
		return ports.GitObjectID{}, err
	}
	return parseObjectID(result.Stdout, "head tree")
}

func (adapter *Adapter) diff(ctx context.Context, repository canonicalRepository, base, head ports.GitObjectID) ([]byte, error) {
	result, err := adapter.run(ctx, repository.sourceCommand(
		"diff",
		"--binary",
		"--full-index",
		"--no-ext-diff",
		"--no-color",
		"--no-renames",
		"--no-indent-heuristic",
		"--diff-algorithm=myers",
		"--no-textconv",
		"--no-relative",
		"--unified=3",
		"--inter-hunk-context=0",
		"--src-prefix=a/",
		"--dst-prefix=b/",
		"--submodule=short",
		"--ignore-submodules=none",
		base.String(),
		head.String(),
	))
	if err != nil {
		return nil, err
	}
	return cloneBytes(result.Stdout), nil
}

func (adapter *Adapter) untrackedInventory(ctx context.Context, root ports.AnchoredRoot) ([]byte, error) {
	result, err := adapter.run(ctx, (Command{
		Dir:  root.String(),
		Args: []string{"ls-files", "--others", "--exclude-standard", "-z"},
	}).withSourceSizedStdout())
	if err != nil {
		return nil, err
	}
	return cloneBytes(result.Stdout), nil
}

func (adapter *Adapter) run(ctx context.Context, command Command) (Result, error) {
	transcriptCommand := command.Clone()
	adapter.transcriptMu.Lock()
	adapter.transcript = append(adapter.transcript, transcriptCommand)
	adapter.transcriptMu.Unlock()
	return adapter.runner.Run(ctx, command.Clone())
}

func finalizeCanonicalCleanup(cleanup func() error, operation string, operationErr *error, clearResult func()) {
	if cleanupErr := cleanup(); cleanupErr != nil {
		clearResult()
		*operationErr = errors.Join(
			*operationErr,
			fmt.Errorf("%s canonical cleanup: %w", operation, cleanupErr),
		)
	}
}
func parseObjectID(value []byte, field string) (ports.GitObjectID, error) {
	text, err := parseSingleLine(value, field, 65)
	if err != nil {
		return ports.GitObjectID{}, err
	}
	objectID, err := ports.ParseGitObjectID(text)
	if err != nil {
		return ports.GitObjectID{}, fmt.Errorf("Git %s object ID: %w", field, err)
	}
	return objectID, nil
}

func parseSingleLine(value []byte, field string, maximumLength int) (string, error) {
	if len(value) == 0 || len(value) > maximumLength || value[len(value)-1] != '\n' {
		return "", fmt.Errorf("Git %s output must be one bounded newline-terminated line", field)
	}
	text := string(value[:len(value)-1])
	if text == "" || strings.TrimSpace(text) != text || strings.ContainsAny(text, "\x00\r\n") {
		return "", fmt.Errorf("Git %s output must be non-empty canonical text", field)
	}
	return text, nil
}
func parseRegularBlobTreeEntry(value []byte, file ports.SafeRelativePath) (ports.GitObjectID, error) {
	if len(value) == 0 {
		return ports.GitObjectID{}, nil
	}
	if value[len(value)-1] != '\x00' {
		return ports.GitObjectID{}, fmt.Errorf("Git tree entry output must be NUL-terminated")
	}

	entries := bytes.Split(value[:len(value)-1], []byte{'\x00'})
	if len(entries) != 1 || len(entries[0]) == 0 {
		return ports.GitObjectID{}, fmt.Errorf("Git tree entry output must contain exactly one entry")
	}
	parts := bytes.SplitN(entries[0], []byte{'\t'}, 2)
	if len(parts) != 2 || string(parts[1]) != file.String() {
		return ports.GitObjectID{}, fmt.Errorf("Git tree entry output must name the requested path exactly")
	}

	fields := strings.Split(string(parts[0]), " ")
	if len(fields) != 3 || (fields[0] != "100644" && fields[0] != "100755") || fields[1] != "blob" {
		return ports.GitObjectID{}, fmt.Errorf("Git tree entry output must describe one regular blob")
	}
	blob, err := ports.ParseGitObjectID(fields[2])
	if err != nil {
		return ports.GitObjectID{}, fmt.Errorf("Git tree entry object ID: %w", err)
	}
	return blob, nil
}

func validateReference(reference string) error {
	if reference == "" || len(reference) > 4096 {
		return fmt.Errorf("reference must be non-empty and at most 4096 bytes")
	}
	if strings.TrimSpace(reference) != reference || strings.Contains(reference, "\\") || strings.ContainsAny(reference, "\x00\r\n") {
		return fmt.Errorf("reference must be canonical and safe")
	}
	return nil
}
