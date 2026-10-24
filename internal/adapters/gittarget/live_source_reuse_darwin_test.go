//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// A HEAD commit with an empty tree is the head-scope whole-tree no-change
// state: admission succeeds, the target reports no changes, and every path is
// absent from the selected side.
func TestIntegrationLiveSourceEmptyTreeHeadNoChange(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	reviewGit(t, root, "init")
	reviewGit(t, root, "config", "user.email", "test@example.invalid")
	reviewGit(t, root, "config", "user.name", "Test")
	reviewGit(t, root, "config", "commit.gpgsign", "false")
	reviewGit(t, root, "commit", "--allow-empty", "-m", "empty tree")
	reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	defer reader.Close()
	if !reader.Target().NoChange() {
		t.Fatal("empty-tree HEAD commit was not a head-scope no-change target")
	}
	paths, err := reader.List(context.Background(), domain.LiveSourceAfter)
	if err != nil || len(paths) != 0 {
		t.Fatalf("empty-tree listing = %v, %v", paths, err)
	}
	absent, _ := ports.NewSafeRelativePath("absent.txt")
	_, err = reader.Read(context.Background(), domain.LiveSourceAfter, absent)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
	assertLiveError(t, reader.AdmitPath(context.Background(), domain.LiveSourceAfter, absent), ports.LiveSourceUnavailable)
}

func gitStdinOutput(t *testing.T, root string, input, subcommand string, args ...string) string {
	t.Helper()
	command := exec.Command("/usr/bin/git", append([]string{subcommand}, args...)...)
	command.Dir = root
	command.Stdin = strings.NewReader(input)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s %v: %v", subcommand, args, err)
	}
	return strings.TrimSpace(string(output))
}

// Object paths whose spelling differs only by case from the built-in
// protected names stay excluded from committed inventories. The fixture tree
// is built through plumbing so the case-insensitive worktree never sees these
// spellings, and ls-tree confirms the committed tree really contains them.
func TestIntegrationLiveSourceInventoryCaseVariants(t *testing.T) {
	root := canonicalTestRoot(t, t.TempDir())
	reviewGit(t, root, "init")
	reviewGit(t, root, "config", "user.email", "test@example.invalid")
	reviewGit(t, root, "config", "user.name", "Test")
	reviewGit(t, root, "config", "commit.gpgsign", "false")
	blob := gitStdinOutput(t, root, "private\n", "hash-object", "-w", "--stdin")
	variants := []string{".GIT", ".MulGae", ".CODEX", ".GROK", ".ZCode"}
	mktreeInput := strings.Builder{}
	mktreeInput.WriteString("100644 blob " + blob + "\tcontrol.txt\n")
	for _, variant := range variants {
		subtree := gitStdinOutput(t, root, "100644 blob "+blob+"\tsecret.txt\n", "mktree")
		mktreeInput.WriteString("040000 tree " + subtree + "\t" + variant + "\n")
	}
	tree := gitStdinOutput(t, root, mktreeInput.String(), "mktree")
	commit := gitStdinOutput(t, root, "case variants\n", "commit-tree", tree)
	reviewGit(t, root, "update-ref", "HEAD", commit)
	listed := reviewGitOutput(t, root, "ls-tree", "-r", "--name-only", "HEAD")
	for _, variant := range variants {
		if !strings.Contains(listed, variant+"/secret.txt") {
			t.Fatalf("fixture tree is missing protected-name variant %q: %q", variant, listed)
		}
	}

	reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	defer reader.Close()
	paths, err := reader.List(context.Background(), domain.LiveSourceAfter)
	if err != nil || len(paths) != 1 || paths[0].String() != "control.txt" {
		t.Fatalf("case-variant listing = %v, %v", paths, err)
	}
	readTestLiveSource(t, reader, domain.LiveSourceAfter, "control.txt", "private\n")
	for _, variant := range variants {
		path, pathErr := ports.NewSafeRelativePath(variant + "/secret.txt")
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		_, err := reader.Read(context.Background(), domain.LiveSourceAfter, path)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
		assertLiveError(t, reader.AdmitPath(context.Background(), domain.LiveSourceAfter, path), ports.LiveSourceUnsafe)
	}
}

// Git metadata rejection precedes inventory use: after a successful listing
// and admission (which also arms inventory retention after the TASK-057
// change), a config-path symlink swap or a newly appeared alternates file
// fails List, committed-side AdmitPath and committed-side Read — including an
// absent path — with the same typed code as before the change.
func TestIntegrationLiveSourceMetadataRejectionControls(t *testing.T) {
	for _, mutation := range []struct {
		name string
		arm  func(t *testing.T, root string)
	}{
		{name: "config-symlink-swap", arm: func(t *testing.T, root string) {
			config := filepath.Join(root, ".git", "config")
			if err := os.Rename(config, config+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("config.original", config); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "alternates-appear", arm: func(t *testing.T, root string) {
			info := filepath.Join(root, ".git", "objects", "info")
			if err := os.MkdirAll(info, 0o700); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, filepath.Join(info, "alternates"), "/elsewhere\n")
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			root := canonicalTestRoot(t, reviewCaptureRepository(t))
			reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
			present, _ := ports.NewSafeRelativePath("tracked.txt")
			absent, _ := ports.NewSafeRelativePath("absent.txt")
			paths, err := reader.List(context.Background(), domain.LiveSourceAfter)
			if err != nil || len(paths) == 0 {
				t.Fatalf("precondition listing failed: %v, %v", paths, err)
			}
			if err := reader.AdmitPath(context.Background(), domain.LiveSourceAfter, present); err != nil {
				t.Fatalf("precondition admission failed: %v", err)
			}
			mutation.arm(t, root)
			_, err = reader.List(context.Background(), domain.LiveSourceAfter)
			assertLiveError(t, err, ports.LiveSourceUnsafe)
			assertLiveError(t, reader.AdmitPath(context.Background(), domain.LiveSourceAfter, present), ports.LiveSourceUnsafe)
			_, err = reader.Read(context.Background(), domain.LiveSourceAfter, absent)
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		})
	}
}

// liveCommandCount counts reader commands whose argv contains the exact
// subcommand token. Recorded reader commands carry a trusted --no-pager/-c
// prefix before the subcommand, so token membership is the stable matcher;
// fixture Git calls run outside the recorder and are never counted.
func liveCommandCount(runner *liveCommandRecorder, subcommand string) int {
	count := 0
	for _, command := range runner.commands {
		for _, arg := range command.Args {
			if arg == subcommand {
				count++
				break
			}
		}
	}
	return count
}

func openRecordedLiveSource(t *testing.T, runner *liveCommandRecorder, root string, scope domain.LiveSourceScope, value string) ports.LiveSourceReader {
	t.Helper()
	adapter, err := NewLiveSourceAdapter(runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(scope, value)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

// Fixed commit-side inventories are listed once per reader lifetime: a
// head-scope reader pays one whole-side ls-tree at admission and every later
// List, Read and AdmitPath reuses it. Mutable index and worktree listings
// stay fresh on every call, and a second reader starts from nothing.
func TestIntegrationLiveSourceReusesCommitInventories(t *testing.T) {
	t.Run("head-inventory-reuse", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		if got := liveCommandCount(runner, "ls-tree"); got != 1 {
			t.Fatalf("admission ls-tree count = %d, want 1", got)
		}
		for i := 0; i < 3; i++ {
			readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
		}
		for i := 0; i < 2; i++ {
			paths, err := reader.List(context.Background(), domain.LiveSourceAfter)
			if err != nil || len(paths) == 0 {
				t.Fatalf("listing %d: %v, %v", i, paths, err)
			}
		}
		path, _ := ports.NewSafeRelativePath("tracked.txt")
		for i := 0; i < 4; i++ {
			if err := reader.AdmitPath(context.Background(), domain.LiveSourceAfter, path); err != nil {
				t.Fatalf("admission %d: %v", i, err)
			}
		}
		if got := liveCommandCount(runner, "ls-tree"); got != 1 {
			t.Fatalf("reader-lifetime ls-tree count = %d, want 1", got)
		}
		if got := liveCommandCount(runner, "cat-file"); got != 3 {
			t.Fatalf("cat-file count = %d, want 3", got)
		}
	})
	t.Run("diff-both-sides-reuse", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceDiff, "HEAD~1..HEAD")
		defer reader.Close()
		if got := liveCommandCount(runner, "ls-tree"); got != 2 {
			t.Fatalf("admission ls-tree count = %d, want 2", got)
		}
		readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
		readTestLiveSource(t, reader, domain.LiveSourceBefore, "tracked.txt", "base\n")
		for _, side := range []domain.LiveSourceSide{domain.LiveSourceAfter, domain.LiveSourceBefore} {
			paths, err := reader.List(context.Background(), side)
			if err != nil || len(paths) == 0 {
				t.Fatalf("listing %s: %v, %v", side, paths, err)
			}
		}
		path, _ := ports.NewSafeRelativePath("tracked.txt")
		if err := reader.AdmitPath(context.Background(), domain.LiveSourceAfter, path); err != nil {
			t.Fatal(err)
		}
		if err := reader.AdmitPath(context.Background(), domain.LiveSourceBefore, path); err != nil {
			t.Fatal(err)
		}
		if got := liveCommandCount(runner, "ls-tree"); got != 2 {
			t.Fatalf("reader-lifetime ls-tree count = %d, want 2", got)
		}
		if got := liveCommandCount(runner, "cat-file"); got != 2 {
			t.Fatalf("cat-file count = %d, want 2", got)
		}
	})
	t.Run("stage-index-stays-fresh", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceStage, "")
		defer reader.Close()
		for i := 0; i < 2; i++ {
			paths, err := reader.List(context.Background(), domain.LiveSourceIndex)
			if err != nil || len(paths) == 0 {
				t.Fatalf("index listing %d: %v, %v", i, paths, err)
			}
		}
		readTestLiveSource(t, reader, domain.LiveSourceIndex, "tracked.txt", "second\n")
		readTestLiveSource(t, reader, domain.LiveSourceBefore, "tracked.txt", "second\n")
		for i := 0; i < 2; i++ {
			paths, err := reader.List(context.Background(), domain.LiveSourceBefore)
			if err != nil || len(paths) == 0 {
				t.Fatalf("before listing %d: %v, %v", i, paths, err)
			}
		}
		if got := liveCommandCount(runner, "ls-files"); got != 5 {
			t.Fatalf("index ls-files count = %d, want 5 (admission 2, listings 2, read 1)", got)
		}
		if got := liveCommandCount(runner, "ls-tree"); got != 1 {
			t.Fatalf("before-side ls-tree count = %d, want 1 (admission listing only; the Before side is a fixed commit)", got)
		}
	})
	t.Run("workspace-worktree-stays-fresh", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceWorkspace, "")
		defer reader.Close()
		for i := 0; i < 2; i++ {
			paths, err := reader.List(context.Background(), domain.LiveSourceWorktree)
			if err != nil || len(paths) == 0 {
				t.Fatalf("worktree listing %d: %v, %v", i, paths, err)
			}
		}
		readTestLiveSource(t, reader, domain.LiveSourceWorktree, "tracked.txt", "second\n")
		if got := liveCommandCount(runner, "ls-files"); got != 3 {
			t.Fatalf("worktree ls-files count = %d, want 3 (admission 1, listings 2)", got)
		}
		if got := liveCommandCount(runner, "ls-tree"); got != 0 {
			t.Fatalf("worktree ls-tree count = %d, want 0", got)
		}
	})
	t.Run("second-reader-starts-fresh", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		first := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		readTestLiveSource(t, first, domain.LiveSourceAfter, "tracked.txt", "second\n")
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		second := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer second.Close()
		readTestLiveSource(t, second, domain.LiveSourceAfter, "tracked.txt", "second\n")
		if got := liveCommandCount(runner, "ls-tree"); got != 2 {
			t.Fatalf("two-reader ls-tree count = %d, want 2 (one admission listing each)", got)
		}
	})
}

func revalidateExecutionChecked(t *testing.T, reader ports.LiveSourceReader) {
	t.Helper()
	binding, err := reader.RevalidateExecution(context.Background())
	if err != nil || binding.Root != reader.Root() {
		t.Fatalf("execution revalidation: %+v, %v", binding, err)
	}
}

func executionConfigParses(runner *liveCommandRecorder) int {
	return liveCommandCount(runner, "config")
}

// Execution Git configuration parsing skips the parse subprocess only when
// freshly verified bytes match the retained last successful digest;
// otherwise it parses, and replaces that digest only on success. Failures
// are never cached, and a second reader starts from nothing. Safe contents
// A -> B -> A therefore parse three times within one reader, while every
// revalidation still reads and verifies the current bytes.
func TestIntegrationLiveSourceExecutionConfigRetention(t *testing.T) {
	t.Run("identical-bytes-skip-parse", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 1 {
			t.Fatalf("baseline config parses = %d, want 1", got)
		}
		for i := 0; i < 2; i++ {
			revalidateExecutionChecked(t, reader)
		}
		if got := executionConfigParses(runner); got != 1 {
			t.Fatalf("identical-byte config parses = %d, want 1", got)
		}
	})
	t.Run("mtime-change-without-byte-change-skips-parse", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		revalidateExecutionChecked(t, reader)
		config := filepath.Join(root, ".git", "config")
		stamped := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
		if err := os.Chtimes(config, stamped, stamped); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 1 {
			t.Fatalf("config parses after mtime-only change = %d, want 1", got)
		}
	})
	t.Run("changed-safe-bytes-reparse-and-restore", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		config := filepath.Join(root, ".git", "config")
		original, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		reviewGit(t, root, "config", "remote.origin.url", "https://example.invalid/source.git")
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 2 {
			t.Fatalf("config parses after changed safe bytes = %d, want 2", got)
		}
		// Safe contents A -> B -> A parse three times: restoring A does not
		// match the retained digest of B.
		if err := os.WriteFile(config, original, 0o600); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("config parses after restoring A = %d, want 3", got)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("config parses after identical repeat = %d, want 3", got)
		}
	})
	t.Run("same-length-unsafe-rewrite-fails", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		config := filepath.Join(root, ".git", "config")
		original, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(config)
		if err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		// A length/mtime control: the rewrite keeps the original length and
		// mtime while the bytes differ, so a shortcut keyed on those
		// properties cannot detect it. The direct read-count observation in
		// TestIntegrationLiveSourceRetentionState supplies the proof that
		// bytes are still read on every revalidation.
		prefix := []byte("[core]\n\tpager = pad")
		if len(prefix) >= len(original) {
			t.Fatalf("fixture config too short for a same-length rewrite: %d", len(original))
		}
		unsafe := append(bytes.Clone(prefix), bytes.Repeat([]byte(" "), len(original)-len(prefix))...)
		if len(unsafe) != len(original) {
			t.Fatalf("unsafe rewrite length = %d, want %d", len(unsafe), len(original))
		}
		if err := os.WriteFile(config, unsafe, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(config, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		_, err = reader.RevalidateExecution(context.Background())
		assertLiveError(t, err, ports.LiveSourceUnsafe)
		if err := os.WriteFile(config, original, 0o600); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 2 {
			t.Fatalf("config parses = %d, want 2 (initial and unsafe rewrite; restored original adds none)", got)
		}
	})
	t.Run("unsafe-bytes-never-cached", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		reviewGit(t, root, "config", "core.pager", "less -FX")
		for i := 0; i < 2; i++ {
			_, err := reader.RevalidateExecution(context.Background())
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		}
		if got := executionConfigParses(runner); got != 2 {
			t.Fatalf("unsafe-byte config parses = %d, want 2", got)
		}
	})
	t.Run("parser-failure-never-cached", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		config := filepath.Join(root, ".git", "config")
		original, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config, []byte("[unterminated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			_, err := reader.RevalidateExecution(context.Background())
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		}
		if got := executionConfigParses(runner); got != 2 {
			t.Fatalf("parser-failure config parses = %d, want 2", got)
		}
		if err := os.WriteFile(config, original, 0o600); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("config parses after restoration = %d, want 3", got)
		}
	})
	t.Run("worktree-config-appearance-and-disappearance", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 1 {
			t.Fatalf("baseline config parses = %d, want 1", got)
		}
		reviewGit(t, root, "config", "extensions.worktreeConfig", "true")
		reviewGit(t, root, "config", "--worktree", "core.filemode", "true")
		worktreeConfig := filepath.Join(root, ".git", "config.worktree")
		stored, err := os.ReadFile(worktreeConfig)
		if err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("appearance config parses = %d, want 3 (changed config plus new worktree file)", got)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("identical repeat config parses = %d, want 3", got)
		}
		if err := os.Remove(worktreeConfig); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("disappearance config parses = %d, want 3", got)
		}
		// Reappearing with the identical bytes stays admitted without a new
		// parse: the freshly read bytes match the retained digest.
		if err := os.WriteFile(worktreeConfig, stored, 0o600); err != nil {
			t.Fatal(err)
		}
		revalidateExecutionChecked(t, reader)
		if got := executionConfigParses(runner); got != 3 {
			t.Fatalf("reappearance config parses = %d, want 3", got)
		}
	})
	t.Run("symlink-replacement-fails", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		revalidateExecutionChecked(t, reader)
		config := filepath.Join(root, ".git", "config")
		if err := os.Rename(config, config+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("config.original", config); err != nil {
			t.Fatal(err)
		}
		_, err := reader.RevalidateExecution(context.Background())
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
	t.Run("second-reader-starts-fresh", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		first := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		for i := 0; i < 2; i++ {
			revalidateExecutionChecked(t, first)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		second := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer second.Close()
		for i := 0; i < 2; i++ {
			revalidateExecutionChecked(t, second)
		}
		if got := executionConfigParses(runner); got != 2 {
			t.Fatalf("two-reader config parses = %d, want 2 (one per reader)", got)
		}
	})
}

// Concurrent use of one reader must stay within today's contract. A
// synchronized phase first proves successful concurrent rounds of every
// operation, arming both inventory and config retention; only then does
// Close race the callers, where every call either succeeds or reports the
// closed-reader typed code. No timing or sleep is involved.
func TestIntegrationLiveSourceRetentionConcurrency(t *testing.T) {
	root := canonicalTestRoot(t, reviewCaptureRepository(t))
	runner := &liveCommandRecorder{}
	reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
	path, _ := ports.NewSafeRelativePath("tracked.txt")
	round := func(rounds int, acceptClosed bool) {
		for j := 0; j < rounds; j++ {
			paths, listErr := reader.List(context.Background(), domain.LiveSourceAfter)
			if acceptClosed {
				acceptClosedReaderOutcome(t, listErr)
			} else if listErr != nil || len(paths) == 0 {
				t.Errorf("concurrent listing: %v, %v", paths, listErr)
			}
			admitErr := reader.AdmitPath(context.Background(), domain.LiveSourceAfter, path)
			if acceptClosed {
				acceptClosedReaderOutcome(t, admitErr)
			} else if admitErr != nil {
				t.Errorf("concurrent admission: %v", admitErr)
			}
			file, readErr := reader.Read(context.Background(), domain.LiveSourceAfter, path)
			if acceptClosed {
				acceptClosedReaderOutcome(t, readErr)
			} else if readErr != nil || len(file.Bytes()) == 0 {
				t.Errorf("concurrent read: %d bytes, %v", len(file.Bytes()), readErr)
			}
			_, bindErr := reader.RevalidateExecution(context.Background())
			if acceptClosed {
				acceptClosedReaderOutcome(t, bindErr)
			} else if bindErr != nil {
				t.Errorf("concurrent revalidation: %v", bindErr)
			}
		}
	}
	var synchronized sync.WaitGroup
	for i := 0; i < 4; i++ {
		synchronized.Add(1)
		go func() {
			defer synchronized.Done()
			round(4, false)
		}()
	}
	synchronized.Wait()
	if got := liveCommandCount(runner, "ls-tree"); got != 1 {
		t.Fatalf("ls-tree count after synchronized rounds = %d, want 1", got)
	}
	if got := executionConfigParses(runner); got != 1 {
		t.Fatalf("config parses after synchronized rounds = %d, want 1", got)
	}
	var racing sync.WaitGroup
	for i := 0; i < 4; i++ {
		racing.Add(1)
		go func() {
			defer racing.Done()
			round(8, true)
		}()
	}
	racing.Add(1)
	go func() {
		defer racing.Done()
		acceptClosedReaderOutcome(t, reader.Close())
	}()
	racing.Wait()
}

func acceptClosedReaderOutcome(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if code, ok := liveSourceTypedCode(err); ok && code == ports.LiveSourceUnavailable {
		return
	}
	t.Errorf("concurrent reader outcome = %v, want nil or source_unavailable", err)
}

// Direct observation of the reader's unexported retention state: identical
// revalidations keep reading descriptor-verified config bytes, the retained
// maps stay bounded, and Close clears them.
func TestIntegrationLiveSourceRetentionState(t *testing.T) {
	t.Run("config-bytes-reread-every-revalidation", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceHead, "")
		defer reader.Close()
		concrete, ok := reader.(*liveSourceReader)
		if !ok {
			t.Fatalf("reader is %T, want *liveSourceReader", reader)
		}
		reads := map[string]int{}
		delegate := concrete.readExecutionConfig
		concrete.readExecutionConfig = func(path string) ([]byte, error) {
			data, err := delegate(path)
			if err == nil {
				reads[path]++
			}
			return data, err
		}
		for i := 0; i < 3; i++ {
			revalidateExecutionChecked(t, reader)
		}
		if got := executionConfigParses(runner); got != 1 {
			t.Fatalf("config parses = %d, want 1", got)
		}
		for path, count := range reads {
			if count != 3 {
				t.Fatalf("config reads of %q = %d, want 3 (one per revalidation)", path, count)
			}
		}
		if len(reads) != 1 {
			t.Fatalf("config files read = %d, want 1", len(reads))
		}
	})
	t.Run("bounded-retention-and-close-clears", func(t *testing.T) {
		root := canonicalTestRoot(t, reviewCaptureRepository(t))
		runner := &liveCommandRecorder{}
		reader := openRecordedLiveSource(t, runner, root, domain.LiveSourceDiff, "HEAD~1..HEAD")
		concrete, ok := reader.(*liveSourceReader)
		if !ok {
			t.Fatalf("reader is %T, want *liveSourceReader", reader)
		}
		reviewGit(t, root, "config", "extensions.worktreeConfig", "true")
		reviewGit(t, root, "config", "--worktree", "core.filemode", "true")
		revalidateExecutionChecked(t, reader)
		readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
		readTestLiveSource(t, reader, domain.LiveSourceBefore, "tracked.txt", "base\n")
		concrete.mu.Lock()
		inventories, configDigests := concrete.inventories, concrete.configDigests
		concrete.mu.Unlock()
		if len(inventories) != 2 {
			t.Fatalf("retained inventories = %d, want 2 (one per fixed side)", len(inventories))
		}
		if len(configDigests) != 2 {
			t.Fatalf("retained config digests = %d, want 2 (one per existing config file)", len(configDigests))
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		concrete.mu.Lock()
		defer concrete.mu.Unlock()
		if concrete.inventories != nil || concrete.configDigests != nil {
			t.Fatal("Close did not clear the reader's retention state")
		}
	})
}
