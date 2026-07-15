//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type scriptedResponse struct {
	args      []string
	canonical bool
	stdout    []byte
	stderr    []byte
	err       error
}

type scriptedRunner struct {
	responses      []scriptedResponse
	commands       []Command
	rejectedRefUse []string
	next           int
}

func (runner *scriptedRunner) Run(_ context.Context, command Command) (Result, error) {
	runner.commands = append(runner.commands, command.Clone())
	if runner.next >= len(runner.responses) {
		return Result{}, fmt.Errorf("unexpected Git command: %v", command.Argv())
	}
	if runner.next >= 2 {
		for _, reference := range runner.rejectedRefUse {
			for _, arg := range command.Args {
				if strings.Contains(arg, reference) {
					return Result{}, fmt.Errorf("mutable reference reused after resolution: %q", reference)
				}
			}
		}
	}
	response := runner.responses[runner.next]
	runner.next++
	if response.canonical {
		if !matchesCanonicalCommand(command, response.args) {
			return Result{}, fmt.Errorf("canonical Git argv = %v, want suffix %v", command.Args, response.args)
		}
	} else if !reflect.DeepEqual(command.Args, response.args) {
		return Result{}, fmt.Errorf("Git argv = %v, want %v", command.Args, response.args)
	}
	return Result{Stdout: response.stdout, Stderr: response.stderr}, response.err
}

func TestCaptureResolvesReferencesBeforeEveryOtherCommand(t *testing.T) {
	root := scriptedGitRoot(t)
	baseReference := "refs/heads/base"
	headReference := "refs/heads/head"
	baseObjectID := strings.Repeat("a", 40)
	headObjectID := strings.Repeat("b", 40)
	headTreeID := strings.Repeat("c", 40)
	diff := []byte("diff --git a/file b/file\n")
	inventory := []byte("new-file\x00")

	runner := &scriptedRunner{
		rejectedRefUse: []string{baseReference, headReference},
		responses: []scriptedResponse{
			{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", baseReference + "^{commit}"}, stdout: []byte(baseObjectID + "\n")},
			{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", headReference + "^{commit}"}, stdout: []byte(headObjectID + "\n")},
			{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", headObjectID + "^{tree}"}, stdout: []byte(headTreeID + "\n")},
			{canonical: true, args: captureDiffArgs(baseObjectID, headObjectID), stdout: diff},
			{args: []string{"ls-files", "--others", "--exclude-standard", "-z"}, stdout: inventory},
		},
	}
	adapter, err := New(runner)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewGitCaptureRequest(root, baseReference, headReference, true)
	if err != nil {
		t.Fatal(err)
	}

	target, err := adapter.Capture(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, commonGitDir, err := canonicalGitDirectories(root.String())
	if err != nil {
		t.Fatal(err)
	}
	if target.RepositoryID() != canonicalRepositoryID(commonGitDir) {
		t.Fatalf("repository identity = %q", target.RepositoryID())
	}
	if target.BaseObjectID().String() != baseObjectID || target.HeadObjectID().String() != headObjectID || target.HeadTreeID().String() != headTreeID {
		t.Fatalf("captured immutable IDs = %q, %q, %q", target.BaseObjectID(), target.HeadObjectID(), target.HeadTreeID())
	}
	if _, ok := target.IndexTreeID(); ok {
		t.Fatal("capture reported an index tree without a non-mutating source")
	}
	if runner.next != len(runner.responses) {
		t.Fatalf("executed %d commands, want %d", runner.next, len(runner.responses))
	}
	if !reflect.DeepEqual(adapter.Transcript(), runner.commands) {
		t.Fatalf("adapter transcript = %#v, runner transcript = %#v", adapter.Transcript(), runner.commands)
	}
	for _, command := range runner.commands {
		if got := command.Argv()[0]; got != gitExecutable {
			t.Fatalf("transcript executable = %q, want %q", got, gitExecutable)
		}
	}
	for _, command := range runner.commands[2:] {
		for _, arg := range command.Args {
			if strings.Contains(arg, baseReference) || strings.Contains(arg, headReference) {
				t.Fatalf("post-resolution command reused mutable reference: %v", command.Argv())
			}
		}
	}
	if !matchesCanonicalCommand(runner.commands[3], captureDiffArgs(baseObjectID, headObjectID)) {
		t.Fatalf("diff argv = %v, want canonical diff command", runner.commands[3].Argv())
	}
	captured := target.Bytes()
	captured[0] ^= 0xff
	if bytes.Equal(captured, target.Bytes()) {
		t.Fatal("CapturedGitTarget.Bytes returned aliased storage")
	}
}

func TestCaptureRejectsMalformedResolvedObjectIDs(t *testing.T) {
	root := scriptedGitRoot(t)
	request, err := ports.NewGitCaptureRequest(root, "refs/heads/base", "refs/heads/head", false)
	if err != nil {
		t.Fatal(err)
	}

	for _, malformed := range []string{
		strings.Repeat("A", 40),
		strings.Repeat("a", 39),
		strings.Repeat("g", 40),
		strings.Repeat("a", 41),
	} {
		t.Run(malformed[:3], func(t *testing.T) {
			runner := &scriptedRunner{responses: []scriptedResponse{{
				canonical: true,
				args:      []string{"rev-parse", "--verify", "--end-of-options", "refs/heads/base^{commit}"},
				stdout:    []byte(malformed + "\n"),
			}}}
			adapter, err := New(runner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Capture(context.Background(), request); err == nil {
				t.Fatalf("malformed object ID %q was accepted", malformed)
			}
			if len(runner.commands) != 1 {
				t.Fatalf("malformed object ID ran %d commands, want one", len(runner.commands))
			}
		})
	}
}

func TestTrustedReadUsesOnlyResolvedCommitPathAndCopiesBytes(t *testing.T) {
	root := scriptedGitRoot(t)
	commitText := strings.Repeat("d", 40)
	contents := []byte("provider: kimi\n")
	runner := &scriptedRunner{responses: []scriptedResponse{
		{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", "trusted-base^{commit}"}, stdout: []byte(commitText + "\n")},
		{canonical: true, args: []string{"cat-file", "blob", commitText + ":config/project.yaml"}, stdout: contents},
	}}
	adapter, err := New(runner)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := adapter.ResolveCommit(context.Background(), root, "trusted-base")
	if err != nil {
		t.Fatal(err)
	}
	file, err := ports.NewSafeRelativePath("config/project.yaml")
	if err != nil {
		t.Fatal(err)
	}
	read, err := adapter.ReadFileAtCommit(context.Background(), root, commit, file)
	if err != nil {
		t.Fatal(err)
	}
	if !matchesCanonicalCommand(runner.commands[1], []string{"cat-file", "blob", commitText + ":config/project.yaml"}) {
		t.Fatalf("trusted read argv = %v, want canonical cat-file command", runner.commands[1].Argv())
	}
	read[0] = 'X'
	if contents[0] != 'p' {
		t.Fatal("ReadFileAtCommit returned aliased runner bytes")
	}
}
func TestTrustedReadExactOIDIgnoresReferenceMetadata(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"HEAD", "refs", "logs", "ORIG_HEAD", "FETCH_HEAD"} {
		if err := os.Symlink("missing", filepath.Join(gitDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	commitText := strings.Repeat("e", 40)
	commit, err := ports.ParseGitObjectID(commitText)
	if err != nil {
		t.Fatal(err)
	}
	file, err := ports.NewSafeRelativePath("config/project.yaml")
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{responses: []scriptedResponse{{
		canonical: true,
		args:      []string{"cat-file", "blob", commitText + ":config/project.yaml"},
		stdout:    []byte("provider: kimi\n"),
	}}}
	adapter, err := New(runner)
	if err != nil {
		t.Fatal(err)
	}

	contents, err := adapter.ReadFileAtCommit(context.Background(), mustAnchoredRoot(t, root), commit, file)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "provider: kimi\n" {
		t.Fatalf("trusted file contents = %q", contents)
	}
	if runner.next != 1 || len(runner.commands) != 1 {
		t.Fatalf("exact OID read executed %d commands, want one", len(runner.commands))
	}
}

func TestDeterministicEnvironmentDisablesReplacementAndLazyFetch(t *testing.T) {
	environment := make(map[string]bool)
	for _, entry := range DeterministicEnvironment() {
		environment[entry] = true
	}
	for _, required := range []string{
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"PATH=/usr/bin:/bin",
	} {
		if !environment[required] {
			t.Fatalf("deterministic Git environment omitted %q", required)
		}
	}
}
func TestExecRunnerCapsFailClosed(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	commandRunner := NewExecRunner()
	commandRunner.MaxCommandBytes = 4
	result, err := commandRunner.Run(ctx, Command{Dir: root, Args: []string{"--version"}})
	var commandLimit *CommandLimitError
	if !errors.As(err, &commandLimit) {
		t.Fatalf("command cap error = %v, want CommandLimitError", err)
	}
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatal("command cap returned command output")
	}

	stdoutRunner := NewExecRunner()
	stdoutRunner.MaxStdoutBytes = 1
	result, err = stdoutRunner.Run(ctx, Command{Dir: root, Args: []string{"--version"}})
	assertOutputLimit(t, err, "stdout")
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatal("stdout cap returned partial output")
	}

	stderrRunner := NewExecRunner()
	stderrRunner.MaxStderrBytes = 1
	result, err = stderrRunner.Run(ctx, Command{Dir: root, Args: []string{"rev-parse", "--verify", "missing^{commit}"}})
	assertOutputLimit(t, err, "stderr")
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatal("stderr cap returned partial output")
	}
}
func TestExecRunnerPinsGitExecutableAgainstAmbientPATHShadow(t *testing.T) {
	root := t.TempDir()
	shadowDirectory := t.TempDir()
	shadowGit := filepath.Join(shadowDirectory, "git")
	writeTestFile(t, shadowGit, []byte("#!/bin/sh\nexit 99\n"))
	if err := os.Chmod(shadowGit, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shadowDirectory)

	command := Command{Dir: root, Args: []string{"--version"}}
	if _, err := NewExecRunner().Run(context.Background(), command); err != nil {
		t.Fatalf("pinned Git invocation failed: %v", err)
	}
	if got, want := command.Argv(), []string{gitExecutable, "--version"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transcript argv = %v, want %v", got, want)
	}
}

func TestCommandErrorRedactsRawArgv(t *testing.T) {
	secret := "not-for-error-output"
	_, err := NewExecRunner().Run(context.Background(), Command{
		Dir:  t.TempDir(),
		Args: []string{"rev-parse", "--verify", secret + "^{commit}"},
	})
	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("command error = %v, want CommandError", err)
	}
	if strings.Contains(commandErr.Error(), secret) {
		t.Fatalf("command error leaked argv: %q", commandErr.Error())
	}
	if got, want := commandErr.Command().Argv(), []string{gitExecutable, "rev-parse", "--verify", secret + "^{commit}"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("structured command argv = %v, want %v", got, want)
	}
}

func TestCappedBufferWriteReportsConsumedBytes(t *testing.T) {
	for _, test := range []struct {
		name       string
		limit      int
		input      string
		wantN      int
		wantErr    error
		wantBuffer string
	}{
		{name: "exact limit", limit: 3, input: "abc", wantN: 3, wantBuffer: "abc"},
		{name: "one over", limit: 3, input: "abcd", wantN: 3, wantErr: errStreamLimit, wantBuffer: "abc"},
		{name: "oversized", limit: 3, input: "abcdefgh", wantN: 3, wantErr: errStreamLimit, wantBuffer: "abc"},
	} {
		t.Run(test.name, func(t *testing.T) {
			buffer := cappedBuffer{limit: test.limit}
			gotN, gotErr := buffer.Write([]byte(test.input))
			if gotN != test.wantN || !errors.Is(gotErr, test.wantErr) || string(buffer.Bytes()) != test.wantBuffer {
				t.Fatalf("Write(%q) = (%d, %v, %q), want (%d, %v, %q)", test.input, gotN, gotErr, buffer.Bytes(), test.wantN, test.wantErr, test.wantBuffer)
			}
		})
	}
}

func TestCaptureRealTemporaryRepository(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "Test User")
	runGit(t, root, "remote", "add", "origin", "https://example.test/repository.git")
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("first\n"))
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "base")
	baseObjectID := strings.TrimSpace(string(runGit(t, root, "rev-parse", "HEAD")))
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("second\n"))
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "head")
	headObjectID := strings.TrimSpace(string(runGit(t, root, "rev-parse", "HEAD")))
	writeTestFile(t, filepath.Join(root, "untracked.txt"), []byte("untracked\n"))
	before := runGit(t, root, "status", "--porcelain=v1")

	anchoredRoot := mustAnchoredRoot(t, root)
	request, err := ports.NewGitCaptureRequest(anchoredRoot, "HEAD~1", "HEAD", true)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	target, err := adapter.Capture(context.Background(), request)
	requireNoGitError(t, err)
	after := runGit(t, root, "status", "--porcelain=v1")

	if !bytes.Equal(before, after) {
		t.Fatalf("capture changed repository state: before %q, after %q", before, after)
	}
	_, commonGitDir, err := canonicalGitDirectories(anchoredRoot.String())
	if err != nil {
		t.Fatal(err)
	}
	if target.RepositoryID() != canonicalRepositoryID(commonGitDir) {
		t.Fatalf("repository identity = %q", target.RepositoryID())
	}
	if target.BaseObjectID().String() != baseObjectID || target.HeadObjectID().String() != headObjectID {
		t.Fatalf("captured commits = %q, %q", target.BaseObjectID(), target.HeadObjectID())
	}
	if !bytes.Contains(target.Bytes(), []byte("untracked.txt\x00")) {
		t.Fatal("captured target does not contain the requested untracked inventory")
	}
}
func requireNoGitError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var commandError *CommandError
	if errors.As(err, &commandError) {
		t.Fatalf("Git operation failed: command=%q\nstderr:\n%s\ncause=%v", commandError.Command().Args, commandError.Stderr(), commandError.Unwrap())
	}
	t.Fatal(err)
}
func TestCaptureCanonicalBytesIgnoreMutableConfigAndAttributes(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "Test User")
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("first\n"))
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "base")
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("second\n"))
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "head")

	anchoredRoot := mustAnchoredRoot(t, root)
	request, err := ports.NewGitCaptureRequest(anchoredRoot, "HEAD~1", "HEAD", false)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	before, err := adapter.Capture(context.Background(), request)
	requireNoGitError(t, err)
	path, err := ports.NewSafeRelativePath("tracked.txt")
	if err != nil {
		t.Fatal(err)
	}
	beforeFile, err := adapter.ReadFileAtCommit(context.Background(), anchoredRoot, before.HeadObjectID(), path)
	requireNoGitError(t, err)

	externalDiff := filepath.Join(root, "external-diff")
	writeTestFile(t, externalDiff, []byte("#!/bin/sh\nexit 99\n"))
	if err := os.Chmod(externalDiff, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "config", "diff.external", externalDiff)
	runGit(t, root, "config", "diff.context", "99")
	runGit(t, root, "config", "diff.interHunkContext", "42")
	writeTestFile(t, filepath.Join(root, ".gitattributes"), []byte("tracked.txt diff=shadow\n"))
	writeTestFile(t, filepath.Join(root, ".git", "info", "attributes"), []byte("tracked.txt diff=shadow\n"))

	after, err := adapter.Capture(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	afterFile, err := adapter.ReadFileAtCommit(context.Background(), anchoredRoot, before.HeadObjectID(), path)
	requireNoGitError(t, err)
	if !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatal("canonical capture bytes changed after mutable config or attribute mutation")
	}
	if !bytes.Equal(beforeFile, afterFile) {
		t.Fatal("canonical file read changed after mutable config or attribute mutation")
	}
}

func TestCanonicalCleanupFailureClearsResultsAndPreservesCauses(t *testing.T) {
	operations := []struct {
		name   string
		invoke func(*testing.T, error, error) (bool, error)
	}{
		{
			name: "capture",
			invoke: func(t *testing.T, primaryErr, cleanupErr error) (bool, error) {
				root := scriptedGitRoot(t)
				baseReference := "refs/heads/base"
				headReference := "refs/heads/head"
				baseObjectID := strings.Repeat("a", 40)
				headObjectID := strings.Repeat("b", 40)
				headTreeID := strings.Repeat("c", 40)
				runner := &scriptedRunner{responses: []scriptedResponse{
					{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", baseReference + "^{commit}"}, stdout: []byte(baseObjectID + "\n"), err: primaryErr},
					{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", headReference + "^{commit}"}, stdout: []byte(headObjectID + "\n")},
					{canonical: true, args: []string{"rev-parse", "--verify", "--end-of-options", headObjectID + "^{tree}"}, stdout: []byte(headTreeID + "\n")},
					{canonical: true, args: captureDiffArgs(baseObjectID, headObjectID), stdout: []byte("diff\n")},
				}}
				adapter := cleanupFailureAdapter(t, runner, cleanupErr)
				request, err := ports.NewGitCaptureRequest(root, baseReference, headReference, false)
				if err != nil {
					t.Fatal(err)
				}
				target, err := adapter.Capture(context.Background(), request)
				return target.RepositoryID() == "" &&
					!target.BaseObjectID().Valid() &&
					!target.HeadObjectID().Valid() &&
					!target.HeadTreeID().Valid() &&
					target.SHA256() == "" &&
					target.Bytes() == nil, err
			},
		},
		{
			name: "resolve commit",
			invoke: func(t *testing.T, primaryErr, cleanupErr error) (bool, error) {
				root := scriptedGitRoot(t)
				reference := "refs/heads/base"
				runner := &scriptedRunner{responses: []scriptedResponse{{
					canonical: true,
					args:      []string{"rev-parse", "--verify", "--end-of-options", reference + "^{commit}"},
					stdout:    []byte(strings.Repeat("a", 40) + "\n"),
					err:       primaryErr,
				}}}
				adapter := cleanupFailureAdapter(t, runner, cleanupErr)
				commit, err := adapter.ResolveCommit(context.Background(), root, reference)
				return !commit.Valid(), err
			},
		},
		{
			name: "read file at commit",
			invoke: func(t *testing.T, primaryErr, cleanupErr error) (bool, error) {
				root := scriptedGitRoot(t)
				commit, err := ports.ParseGitObjectID(strings.Repeat("a", 40))
				if err != nil {
					t.Fatal(err)
				}
				file, err := ports.NewSafeRelativePath("config/project.yaml")
				if err != nil {
					t.Fatal(err)
				}
				runner := &scriptedRunner{responses: []scriptedResponse{{
					canonical: true,
					args:      []string{"cat-file", "blob", commit.String() + ":" + file.String()},
					stdout:    []byte("provider: test\n"),
					err:       primaryErr,
				}}}
				adapter := cleanupFailureAdapter(t, runner, cleanupErr)
				data, err := adapter.ReadFileAtCommit(context.Background(), root, commit, file)
				return data == nil, err
			},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name+"/cleanup only", func(t *testing.T) {
			cleanupErr := errors.New("cleanup failure")
			resultIsZero, err := operation.invoke(t, nil, cleanupErr)
			if !resultIsZero {
				t.Fatal("successful result survived cleanup failure")
			}
			if !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup error = %v, want cleanup failure", err)
			}
			var commandErr *CommandError
			if errors.As(err, &commandErr) {
				t.Fatalf("cleanup-only error retained command failure: %v", commandErr)
			}
		})

		t.Run(operation.name+"/primary and cleanup", func(t *testing.T) {
			cleanupErr := errors.New("cleanup failure")
			primaryCause := errors.New("primary failure")
			primaryErr := &CommandError{cause: primaryCause}
			resultIsZero, err := operation.invoke(t, primaryErr, cleanupErr)
			if !resultIsZero {
				t.Fatal("primary result survived cleanup failure")
			}
			if !errors.Is(err, cleanupErr) {
				t.Fatalf("cleanup error = %v, want cleanup failure", err)
			}
			if !errors.Is(err, primaryCause) {
				t.Fatalf("primary cause = %v, want primary failure", err)
			}
			var commandErr *CommandError
			if !errors.As(err, &commandErr) || commandErr != primaryErr {
				t.Fatalf("command error = %v, want original command error", commandErr)
			}
		})
	}
}

func cleanupFailureAdapter(t *testing.T, runner Runner, cleanupErr error) *Adapter {
	t.Helper()
	adapter, err := New(runner)
	if err != nil {
		t.Fatal(err)
	}
	repository := canonicalRepository{
		gitDir:       t.TempDir(),
		repositoryID: "cleanup-test",
	}
	cleanup := func() error {
		return cleanupErr
	}
	adapter.newCanonicalRepository = func(ports.AnchoredRoot, ...string) (canonicalRepository, func() error, error) {
		return repository, cleanup, nil
	}
	adapter.newCanonicalObjectRepository = func(ports.AnchoredRoot, ports.GitObjectID) (canonicalRepository, func() error, error) {
		return repository, cleanup, nil
	}
	return adapter
}
func captureDiffArgs(baseObjectID, headObjectID string) []string {
	return []string{
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
		baseObjectID,
		headObjectID,
	}
}
func matchesCanonicalCommand(command Command, suffix []string) bool {
	prefix := []string{
		"--no-replace-objects",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.quotePath=true",
		"-c", "color.ui=false",
		"-c", "pager.diff=false",
	}
	if len(command.Args) != len(prefix)+len(suffix)+1 || !strings.HasPrefix(command.Args[0], "--git-dir=") {
		return false
	}
	gitDir := strings.TrimPrefix(command.Args[0], "--git-dir=")
	if gitDir == "" || !filepath.IsAbs(gitDir) || filepath.Clean(gitDir) != gitDir || command.Dir != gitDir {
		return false
	}
	return reflect.DeepEqual(command.Args[1:len(prefix)+1], prefix) && reflect.DeepEqual(command.Args[len(prefix)+1:], suffix)
}

func scriptedGitRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))
	writeTestFile(t, filepath.Join(root, ".git", "config"), []byte("[core]\nrepositoryformatversion = 0\n"))
	return mustAnchoredRoot(t, root)
}

func assertOutputLimit(t *testing.T, err error, stream string) {
	t.Helper()
	var limit *OutputLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("output cap error = %v, want OutputLimitError", err)
	}
	if limit.Stream != stream {
		t.Fatalf("output cap stream = %q, want %q", limit.Stream, stream)
	}
}

func mustAnchoredRoot(t *testing.T, value string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(value)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runGit(t *testing.T, directory string, args ...string) []byte {
	t.Helper()
	command := exec.CommandContext(context.Background(), gitExecutable, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return output
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func TestResolveCommitRefLessSHA256Repository(t *testing.T) {
	root := t.TempDir()
	command := exec.CommandContext(context.Background(), gitExecutable, "init", "--object-format=sha256")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.ToLower(string(output))
		if strings.Contains(message, "unknown hash algorithm") ||
			strings.Contains(message, "unsupported hash") ||
			(strings.Contains(message, "unknown option") && strings.Contains(message, "object-format")) ||
			(strings.Contains(message, "object format") && strings.Contains(message, "not supported")) {
			t.Skipf("Git does not support SHA-256 repositories: %s", output)
		}
		t.Fatalf("git init --object-format=sha256: %v\n%s", err, output)
	}
	runGit(t, root, "config", "user.email", "test@example.test")
	runGit(t, root, "config", "user.name", "Test User")
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("content\n"))
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "unreferenced SHA-256 commit")
	commit := strings.TrimSpace(string(runGit(t, root, "rev-parse", "HEAD")))
	if len(commit) != 64 {
		t.Fatalf("SHA-256 commit ID = %q", commit)
	}
	branch := strings.TrimSpace(string(runGit(t, root, "symbolic-ref", "--short", "HEAD")))
	if err := os.Remove(filepath.Join(root, ".git", "refs", "heads", branch)); err != nil {
		t.Fatal(err)
	}

	adapter, err := New(NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := adapter.ResolveCommit(context.Background(), mustAnchoredRoot(t, root), commit)
	requireNoGitError(t, err)
	if resolved.String() != commit {
		t.Fatalf("resolved SHA-256 commit = %q, want %q", resolved, commit)
	}
}
