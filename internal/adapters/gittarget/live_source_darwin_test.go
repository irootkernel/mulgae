//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
	"golang.org/x/text/unicode/norm"
)

func openTestLiveSource(t *testing.T, root string, scope domain.LiveSourceScope, value string) ports.LiveSourceReader {
	t.Helper()
	adapter, err := NewLiveSourceAdapter(NewExecRunner(), nil)
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
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	return reader
}

func readTestLiveSource(t *testing.T, reader ports.LiveSourceReader, side domain.LiveSourceSide, path, expected string) {
	t.Helper()
	safe, err := ports.NewSafeRelativePath(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := reader.Read(context.Background(), side, safe)
	if err != nil || string(file.Bytes()) != expected {
		t.Fatalf("read %s %s: bytes=%q error=%v", side, path, file.Bytes(), err)
	}
}

func assertLiveError(t *testing.T, err error, code ports.LiveSourceErrorCode) {
	t.Helper()
	var typed *ports.LiveSourceError
	if !errors.As(err, &typed) || typed.Code() != code {
		t.Fatalf("source error = %v, want %s", err, code)
	}
	if err.Error() != "live source: "+string(code) {
		t.Fatal("source error exposed information beyond its typed code")
	}
}

func TestIntegrationLiveSourceExecutionBinding(t *testing.T) {
	for _, git := range []bool{false, true} {
		t.Run(fmt.Sprint(git), func(t *testing.T) {
			root := t.TempDir()
			if git {
				root = reviewCaptureRepository(t)
			}
			reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
			binding, err := reader.RevalidateExecution(context.Background())
			if err != nil || binding.Root != reader.Root() || binding.RootIdentity.Inode == 0 || binding.GitDirectory.Valid() != git {
				t.Fatalf("original execution binding: %+v, %v", binding, err)
			}
			writeReviewFile(t, filepath.Join(root, "live-change.txt"), "live content")
			after, err := reader.RevalidateExecution(context.Background())
			if err != nil || after != binding {
				t.Fatal("live content change incorrectly became a snapshot binding")
			}
			if err := os.Rename(root, root+"-old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			_, err = reader.RevalidateExecution(context.Background())
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		})
	}
}

func TestIntegrationLiveSourceStageUsesIndexForCandidatesAndSupport(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, "support.txt"), "committed support\n")
	writeReviewFile(t, filepath.Join(root, "[literal].txt"), "literal support\n")
	reviewGit(t, root, "add", "support.txt", "[literal].txt")
	reviewGit(t, root, "commit", "-m", "support")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "staged\n")
	reviewGit(t, root, "add", "tracked.txt")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "unstaged candidate\n")
	writeReviewFile(t, filepath.Join(root, "support.txt"), "unstaged support\n")
	before := liveTreeState(t, root)
	reader := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	readTestLiveSource(t, reader, domain.LiveSourceIndex, "tracked.txt", "staged\n")
	readTestLiveSource(t, reader, domain.LiveSourceIndex, "support.txt", "committed support\n")
	readTestLiveSource(t, reader, domain.LiveSourceIndex, "[literal].txt", "literal support\n")
	readTestLiveSource(t, reader, domain.LiveSourceBefore, "[literal].txt", "literal support\n")
	readTestLiveSource(t, reader, domain.LiveSourceBefore, "tracked.txt", "second\n")
	changes := reader.Target().Changes()
	if len(changes) != 1 || changes[0].Kind != "modified" || changes[0].After.String() != "tracked.txt" {
		t.Fatalf("index candidates = %+v", changes)
	}
	if !reflect.DeepEqual(before, liveTreeState(t, root)) {
		t.Fatal("source reading mutated the original repository")
	}
	// Index support remains live, without an immutable-index claim.
	reviewGit(t, root, "add", "support.txt")
	readTestLiveSource(t, reader, domain.LiveSourceIndex, "support.txt", "unstaged support\n")
}

func TestIntegrationLiveSourceStageRetainsBinaryIndexEvidence(t *testing.T) {
	root := reviewCaptureRepository(t)
	png := []byte("\x89PNG\r\n\x1a\n\x00\xff")
	if err := os.WriteFile(filepath.Join(root, "stage.png"), png, 0o600); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "stage.png")
	writeReviewFile(t, filepath.Join(root, "stage.png"), "unstaged invalid PNG")
	reader := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	path, _ := ports.NewSafeRelativePath("stage.png")
	file, err := reader.Read(context.Background(), domain.LiveSourceIndex, path)
	if err != nil || file.MediaType() != "image/png" || file.IsText() || !bytes.Equal(file.Bytes(), png) {
		t.Fatalf("index raster was decoded or replaced by worktree bytes: %v", err)
	}
}

func TestIntegrationLiveSourceWorkspaceSelectionAndLiveBytes(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "tracked.txt\nignored.txt\n")
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "untracked.txt\n")
	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored\n")
	writeReviewFile(t, filepath.Join(root, "untracked.txt"), "included\n")
	for _, name := range []string{".mulgae", ".codex", ".grok", ".zcode"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		writeReviewFile(t, filepath.Join(root, name, "private.txt"), "private\n")
	}
	reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
	readTestLiveSource(t, reader, domain.LiveSourceWorktree, "ignored.txt", "ignored\n")
	paths, err := reader.List(context.Background(), domain.LiveSourceWorktree)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, path := range paths {
		names = append(names, path.String())
	}
	if !reflect.DeepEqual(names, []string{".gitignore", ".mulgaeignore", "tracked.txt", "untracked.txt"}) {
		t.Fatalf("workspace candidates = %v", names)
	}
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "live\n")
	readTestLiveSource(t, reader, domain.LiveSourceWorktree, "tracked.txt", "live\n")
	if err := os.Remove(filepath.Join(root, "untracked.txt")); err != nil {
		t.Fatal(err)
	}
	path, _ := ports.NewSafeRelativePath("untracked.txt")
	_, err = reader.Read(context.Background(), domain.LiveSourceWorktree, path)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
	if err := os.Remove(filepath.Join(root, "tracked.txt")); err != nil {
		t.Fatal(err)
	}
	remaining, err := reader.List(context.Background(), domain.LiveSourceWorktree)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range remaining {
		if path.String() == "tracked.txt" {
			t.Fatal("deleted tracked file remained a workspace candidate")
		}
	}
	stage := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	if !stage.Target().NoChange() {
		t.Fatal("workspace deletion became an index candidate")
	}
	readTestLiveSource(t, stage, domain.LiveSourceIndex, "tracked.txt", "second\n")
}

func TestIntegrationLiveSourceCommittedTargetsResolveOnceAndKeepRenameDeletion(t *testing.T) {
	root := reviewCaptureRepository(t)
	base := reviewGitOutput(t, root, "rev-parse", "HEAD")
	reviewGit(t, root, "mv", "tracked.txt", "renamed.txt")
	writeReviewFile(t, filepath.Join(root, "deleted.txt"), "delete later\n")
	reviewGit(t, root, "add", ".")
	reviewGit(t, root, "commit", "-m", "rename")
	readers := []ports.LiveSourceReader{
		openTestLiveSource(t, root, domain.LiveSourceHead, ""),
		openTestLiveSource(t, root, domain.LiveSourceCommit, "HEAD"),
		openTestLiveSource(t, root, domain.LiveSourceDiff, base+"..HEAD"),
	}
	for _, reader := range readers[1:] {
		found := false
		for _, change := range reader.Target().Changes() {
			found = found || change.Kind == "renamed" && change.Before.String() == "tracked.txt" && change.After.String() == "renamed.txt"
		}
		if !found {
			t.Fatal("rename lost its source or destination")
		}
		readTestLiveSource(t, reader, domain.LiveSourceBefore, "tracked.txt", "second\n")
	}
	reviewGit(t, root, "rm", "deleted.txt")
	writeReviewFile(t, filepath.Join(root, "renamed.txt"), "new HEAD\n")
	reviewGit(t, root, "commit", "-am", "delete and change")
	for _, reader := range readers {
		readTestLiveSource(t, reader, domain.LiveSourceAfter, "renamed.txt", "second\n")
	}
	deleted := openTestLiveSource(t, root, domain.LiveSourceCommit, "HEAD")
	readTestLiveSource(t, deleted, domain.LiveSourceBefore, "deleted.txt", "delete later\n")
	path, _ := ports.NewSafeRelativePath("deleted.txt")
	_, err := deleted.Read(context.Background(), domain.LiveSourceAfter, path)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
}

func TestIntegrationLiveSourceRootUnbornAndNoChange(t *testing.T) {
	root := t.TempDir()
	reviewGit(t, root, "init")
	reviewGit(t, root, "config", "user.name", "Test")
	reviewGit(t, root, "config", "user.email", "test@example.invalid")
	writeReviewFile(t, filepath.Join(root, "root.txt"), "root\n")
	reviewGit(t, root, "add", "root.txt")
	stage := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	if !stage.Target().EmptyBase() || stage.Target().NoChange() {
		t.Fatal("unborn stage lost the empty-tree transition")
	}
	readTestLiveSource(t, stage, domain.LiveSourceIndex, "root.txt", "root\n")
	reviewGit(t, root, "commit", "-m", "root")
	commit := openTestLiveSource(t, root, domain.LiveSourceCommit, "HEAD")
	if !commit.Target().EmptyBase() || len(commit.Target().Changes()) != 1 {
		t.Fatal("root commit was not compared against the empty tree")
	}
	for _, selector := range []struct {
		scope domain.LiveSourceScope
		value string
	}{
		{domain.LiveSourceStage, ""}, {domain.LiveSourceDiff, "HEAD..HEAD"}, {domain.LiveSourceDiff, "HEAD...HEAD"},
	} {
		if !openTestLiveSource(t, root, selector.scope, selector.value).Target().NoChange() {
			t.Fatalf("nonempty identical transition: %+v", selector)
		}
	}
	if openTestLiveSource(t, root, domain.LiveSourceHead, "").Target().NoChange() {
		t.Fatal("whole-tree HEAD was treated as an empty diff")
	}
	writeReviewFile(t, filepath.Join(root, "root.txt"), "unstaged only\n")
	if !openTestLiveSource(t, root, domain.LiveSourceStage, "").Target().NoChange() {
		t.Fatal("unstaged-only edits became index candidates")
	}
}

func TestIntegrationLiveSourceRenamePolicy(t *testing.T) {
	root := reviewCaptureRepository(t)
	for i := 0; i < 3; i++ {
		common := strings.Repeat(fmt.Sprintf("common source file %d\n", i), 30)
		writeReviewFile(t, filepath.Join(root, fmt.Sprintf("old-%d.txt", i)), common+"old ending\n")
	}
	reviewGit(t, root, "add", "--all")
	reviewGit(t, root, "commit", "-m", "rename base")
	reviewGit(t, root, "config", "diff.renameLimit", "1")
	reviewGit(t, root, "config", "diff.renames", "copies")
	for i := 0; i < 3; i++ {
		if err := os.Remove(filepath.Join(root, fmt.Sprintf("old-%d.txt", i))); err != nil {
			t.Fatal(err)
		}
		common := strings.Repeat(fmt.Sprintf("common source file %d\n", i), 30)
		writeReviewFile(t, filepath.Join(root, fmt.Sprintf("new-%d.txt", i)), common+"new ending\n")
	}
	reviewGit(t, root, "add", "--all")
	assertRenames := func(reader ports.LiveSourceReader) {
		t.Helper()
		changes := reader.Target().Changes()
		if len(changes) != 3 {
			t.Fatalf("repository policy changed rename pairing: %+v", changes)
		}
		for _, change := range changes {
			if change.Kind != "renamed" {
				t.Fatalf("edited move lost its rename pair: %+v", change)
			}
		}
	}
	assertRenames(openTestLiveSource(t, root, domain.LiveSourceStage, ""))
	reviewGit(t, root, "commit", "-m", "edited moves")
	assertRenames(openTestLiveSource(t, root, domain.LiveSourceCommit, "HEAD"))
	assertRenames(openTestLiveSource(t, root, domain.LiveSourceDiff, "HEAD~1..HEAD"))
}

func TestIntegrationLiveSourceMergeAndTripleDotSemantics(t *testing.T) {
	root := reviewCaptureRepository(t)
	common := reviewGitOutput(t, root, "rev-parse", "HEAD")
	reviewGit(t, root, "checkout", "-b", "topic")
	writeReviewFile(t, filepath.Join(root, "topic.txt"), "topic\n")
	reviewGit(t, root, "add", "topic.txt")
	reviewGit(t, root, "commit", "-m", "topic")
	topic := reviewGitOutput(t, root, "rev-parse", "HEAD")
	reviewGit(t, root, "checkout", "-b", "other", common)
	writeReviewFile(t, filepath.Join(root, "other.txt"), "other\n")
	reviewGit(t, root, "add", "other.txt")
	reviewGit(t, root, "commit", "-m", "other")
	firstParent := reviewGitOutput(t, root, "rev-parse", "HEAD")
	triple := openTestLiveSource(t, root, domain.LiveSourceDiff, "other...topic")
	if triple.Target().Base().String() != common || triple.Target().Head().String() != topic || len(triple.Target().Changes()) != 1 {
		t.Fatal("triple-dot did not use merge-base-to-right")
	}
	double := openTestLiveSource(t, root, domain.LiveSourceDiff, "other..topic")
	if double.Target().Base().String() != firstParent || double.Target().Head().String() != topic {
		t.Fatal("double-dot replaced its left operand with merge-base")
	}
	changes := double.Target().Changes()
	if len(changes) != 2 || changes[0].Kind != "deleted" || changes[0].Before.String() != "other.txt" || changes[1].Kind != "added" || changes[1].After.String() != "topic.txt" {
		t.Fatalf("divergent double-dot changes = %+v", changes)
	}
	reviewGit(t, root, "merge", "--no-ff", "topic", "-m", "merge")
	merge := openTestLiveSource(t, root, domain.LiveSourceCommit, "HEAD")
	if merge.Target().Base().String() != firstParent || len(merge.Target().Changes()) != 1 || merge.Target().Changes()[0].After.String() != "topic.txt" {
		t.Fatal("merge commit did not use its first parent")
	}
}

func TestIntegrationLiveSourceLinkedWorktreeAndDistinctEqualRoots(t *testing.T) {
	root := reviewCaptureRepository(t)
	linked := filepath.Join(t.TempDir(), "linked")
	reviewGit(t, root, "worktree", "add", "-b", "linked", linked)
	reader := openTestLiveSource(t, linked, domain.LiveSourceStage, "")
	readTestLiveSource(t, reader, domain.LiveSourceIndex, "tracked.txt", "second\n")
	root2 := reviewCaptureRepository(t)
	first := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	second := openTestLiveSource(t, root2, domain.LiveSourceHead, "")
	if first.Root() == second.Root() {
		t.Fatal("equal-content roots collapsed into one project")
	}
}

func TestIntegrationLiveSourceNonGitWorkspaceAndImages(t *testing.T) {
	root := t.TempDir()
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignore\n")
	images := map[string][]byte{
		"image.png":  []byte("\x89PNG\r\n\x1a\n\x00\xff"),
		"image.jpg":  {0xff, 0xd8, 0xff, 0x00},
		"image.webp": []byte("RIFF0000WEBP\x00\xff"),
		"other.bin":  {0, 0xff, 0x01},
	}
	for path, data := range images {
		if err := os.WriteFile(filepath.Join(root, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
	for path, data := range images {
		safe, _ := ports.NewSafeRelativePath(path)
		file, err := reader.Read(context.Background(), domain.LiveSourceWorktree, safe)
		if err != nil || file.IsText() || !bytes.Equal(file.Bytes(), data) {
			t.Fatalf("binary %s: %v", path, err)
		}
	}
	writeReviewFile(t, filepath.Join(root, "image.png"), "invalid PNG")
	path, _ := ports.NewSafeRelativePath("image.png")
	_, err := reader.Read(context.Background(), domain.LiveSourceWorktree, path)
	assertLiveError(t, err, ports.LiveSourceUnsupported)
	empty := openTestLiveSource(t, t.TempDir(), domain.LiveSourceWorkspace, "")
	if !empty.Target().NoChange() {
		t.Fatal("empty workspace was not provider-free")
	}
}

type liveCommandRecorder struct{ commands []Command }

func (runner *liveCommandRecorder) Run(ctx context.Context, command Command) (Result, error) {
	runner.commands = append(runner.commands, command.Clone())
	return NewExecRunner().Run(ctx, command)
}

func TestIntegrationLiveSourceDisablesExecutableGitPolicies(t *testing.T) {
	root := reviewCaptureRepository(t)
	marker := filepath.Join(root, "executed.txt")
	hook := filepath.Join(root, "hostile.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf called > '"+marker+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "config", "core.fsmonitor", hook)
	reviewGit(t, root, "config", "diff.external", hook)
	reviewGit(t, root, "config", "diff.hostile.textconv", hook)
	reviewGit(t, root, "config", "color.ui", "always")
	writeReviewFile(t, filepath.Join(root, ".gitattributes"), "*.txt diff=hostile\n")
	t.Setenv("GIT_EXTERNAL_DIFF", hook)
	t.Setenv("GIT_EXEC_PATH", root)
	runner := &liveCommandRecorder{}
	adapter, _ := NewLiveSourceAdapter(runner, nil)
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceDiff, "HEAD~1..HEAD")
	reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("source inspection executed a project-selected command")
	}
	for _, command := range runner.commands {
		if command.Argv()[0] != "/usr/bin/git" || command.Dir != reader.Root().String() ||
			!strings.Contains(strings.Join(command.Args, "\x00"), "--git-dir="+filepath.Join(reader.Root().String(), ".git")) {
			t.Fatalf("command used a copied or project-selected Git source: %v", command.Argv())
		}
		for _, arg := range command.Args {
			if arg == "write-tree" || arg == "checkout" || arg == "archive" || arg == "worktree" {
				t.Fatalf("source reader invoked a mutating/materializing operation: %v", command.Args)
			}
		}
	}
}

func TestIntegrationLiveSourceRejectsRootAndConfigReplacement(t *testing.T) {
	t.Run("support-symlink", func(t *testing.T) {
		root := t.TempDir()
		writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
		reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
		if err := os.Symlink(".gitignore", filepath.Join(root, "ignored.txt")); err != nil {
			t.Fatal(err)
		}
		path, _ := ports.NewSafeRelativePath("ignored.txt")
		_, err := reader.Read(context.Background(), domain.LiveSourceWorktree, path)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
	t.Run("root", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
		if err := os.Rename(root, root+"-moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		path, _ := ports.NewSafeRelativePath("tracked.txt")
		_, err := reader.Read(context.Background(), domain.LiveSourceAfter, path)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
	t.Run("config", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
		config := filepath.Join(root, ".git", "config")
		if err := os.Rename(config, config+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("config.original", config); err != nil {
			t.Fatal(err)
		}
		path, _ := ports.NewSafeRelativePath("tracked.txt")
		_, err := reader.Read(context.Background(), domain.LiveSourceAfter, path)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
}

func TestLiveSourceObjectInventoryRejectsUnsafePathsAndModes(t *testing.T) {
	oid := strings.Repeat("a", 40)
	for _, test := range []struct {
		name  string
		data  string
		index bool
		code  ports.LiveSourceErrorCode
	}{
		{"symlink", "120000 blob " + oid + "\tlink\x00", false, ports.LiveSourceUnsafe},
		{"conflict", "100644 " + oid + " 1\tfile.txt\x00", true, ports.LiveSourceConflict},
		{"traversal", "100644 blob " + oid + "\t../outside\x00", false, ports.LiveSourceUnsafe},
		{"case-collision", "100644 blob " + oid + "\tFILE\x00100644 blob " + oid + "\tfile\x00", false, ports.LiveSourceUnsafe},
		{"unicode-alias", "100644 blob " + oid + "\te\u0301.txt\x00", false, ports.LiveSourceUnsafe},
		{"truncated", "100644 blob " + oid + "\tfile", false, ports.LiveSourceInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := liveObjectEntries([]byte(test.data), test.index, liveExcluded)
			assertLiveError(t, err, test.code)
		})
	}
}

func TestIntegrationLiveSourceMissingObjectsAndUnboundedContent(t *testing.T) {
	root := reviewCaptureRepository(t)
	payload := bytes.Repeat([]byte("complete source line\n"), defaultMaxStdoutBytes/20+2)
	if err := os.WriteFile(filepath.Join(root, "large.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "large.txt")
	reviewGit(t, root, "commit", "-m", "large source")
	reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	path, _ := ports.NewSafeRelativePath("large.txt")
	file, err := reader.Read(context.Background(), domain.LiveSourceAfter, path)
	if err != nil || len(file.Bytes()) <= defaultMaxStdoutBytes || !bytes.Equal(file.Bytes(), payload) {
		t.Fatalf("source body was bounded or incomplete: %v", err)
	}
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "large.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	live := openTestLiveSource(t, workspace, domain.LiveSourceWorkspace, "")
	file, err = live.Read(context.Background(), domain.LiveSourceWorktree, path)
	if err != nil || !bytes.Equal(file.Bytes(), payload) {
		t.Fatalf("worktree source body was bounded or incomplete: %v", err)
	}
	blob := reviewGitOutput(t, root, "rev-parse", "HEAD:tracked.txt")
	if err := os.Remove(filepath.Join(root, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	path, _ = ports.NewSafeRelativePath("tracked.txt")
	_, err = reader.Read(context.Background(), domain.LiveSourceAfter, path)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = reader.List(ctx, domain.LiveSourceAfter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = reader.List(context.Background(), domain.LiveSourceAfter)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
}

func TestIntegrationLiveSourceInventoriesPreserveSourceSizePolicy(t *testing.T) {
	root := reviewCaptureRepository(t)
	name := strings.Repeat("long", 50) + ".txt"
	writeReviewFile(t, filepath.Join(root, name), "source\n")
	reviewGit(t, root, "add", name)
	runner := NewExecRunner()
	runner.MaxStdoutBytes = 64 // Commit IDs fit; source path records do not.
	adapter, err := NewLiveSourceAdapter(runner, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
	if err != nil {
		t.Fatalf("control-stream cap limited the source inventory: %v", err)
	}
	defer reader.Close()
	readTestLiveSource(t, reader, domain.LiveSourceIndex, name, "source\n")
	workspace := t.TempDir()
	for i := 0; i < 273; i++ {
		writeReviewFile(t, filepath.Join(workspace, fmt.Sprintf("file-%03d.txt", i)), "source\n")
	}
	files := openTestLiveSource(t, workspace, domain.LiveSourceWorkspace, "")
	if len(files.Target().Changes()) != 273 {
		t.Fatal("directory enumeration discarded a later batch")
	}
}

func TestIntegrationLiveSourceExcludesConfiguredCredentialRoots(t *testing.T) {
	for _, names := range [][2]string{{"named-profile", "NAMED-PROFILE"}, {"cafe\u0301-profile", "café-profile"}} {
		t.Run(names[0], func(t *testing.T) {
			root := reviewCaptureRepository(t)
			home := filepath.Join(root, names[0])
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, filepath.Join(home, "auth.json"), "private fixture\n")
			reviewGit(t, root, "config", "core.precomposeUnicode", "true")
			reviewGit(t, root, "add", names[0]+"/auth.json")
			reviewGit(t, root, "commit", "-m", "profile fixture")
			// A Git path can spell the same configured home differently on macOS.
			indexed := norm.NFC.String(names[0])
			if names[1] != indexed {
				object := reviewGitOutput(t, root, "rev-parse", "HEAD:"+indexed+"/auth.json")
				reviewGit(t, root, "update-index", "--force-remove", indexed+"/auth.json")
				reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+object+","+names[1]+"/auth.json")
				reviewGit(t, root, "commit", "-m", "profile path alias")
			}
			originalInfo, err := os.Stat(home)
			if err != nil {
				t.Fatal(err)
			}
			aliasInfo, err := os.Stat(filepath.Join(root, names[1]))
			if err != nil || !os.SameFile(originalInfo, aliasInfo) {
				t.Fatalf("profile spellings are not filesystem aliases: %v", err)
			}
			canonicalHome, err := filepath.EvalSymlinks(home)
			if err != nil {
				t.Fatal(err)
			}
			protected, err := ports.NewAnchoredRoot(canonicalHome)
			if err != nil {
				t.Fatal(err)
			}
			aliasHome := filepath.Join(t.TempDir(), "profile-link")
			if err := os.Symlink(protected.String(), aliasHome); err != nil {
				t.Fatal(err)
			}
			protected, err = ports.NewAnchoredRoot(aliasHome)
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := NewLiveSourceAdapter(NewExecRunner(), []ports.AnchoredRoot{protected})
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				scope domain.LiveSourceScope
				value string
				side  domain.LiveSourceSide
			}{
				{domain.LiveSourceWorkspace, "", domain.LiveSourceWorktree},
				{domain.LiveSourceStage, "", domain.LiveSourceIndex},
				{domain.LiveSourceHead, "", domain.LiveSourceAfter},
				{domain.LiveSourceCommit, "HEAD", domain.LiveSourceAfter},
				{domain.LiveSourceDiff, "HEAD~1..HEAD", domain.LiveSourceAfter},
			} {
				selector, _ := ports.NewLiveSourceSelector(test.scope, test.value)
				reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
				if err != nil {
					t.Fatal(err)
				}
				paths, err := reader.List(context.Background(), test.side)
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range paths {
					if strings.HasPrefix(norm.NFC.String(strings.ToLower(path.String())), norm.NFC.String(strings.ToLower(names[0]))+"/") {
						t.Fatalf("credential root entered %s source inventory", test.scope)
					}
				}
				if test.scope == domain.LiveSourceCommit || test.scope == domain.LiveSourceDiff {
					if !reader.Target().NoChange() {
						t.Fatal("credential-only transition acquired review candidates")
					}
				}
				path, _ := ports.NewSafeRelativePath(names[0] + "/auth.json")
				_, err = reader.Read(context.Background(), test.side, path)
				assertLiveError(t, err, ports.LiveSourceUnsafe)
				alias, _ := ports.NewSafeRelativePath(names[1] + "/auth.json")
				_, err = reader.Read(context.Background(), test.side, alias)
				assertLiveError(t, err, ports.LiveSourceUnsafe)
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntegrationLiveSourceRejectsProtectedGitDirectory(t *testing.T) {
	protected := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(protected, "tracked.txt"), "private Git fixture\n")
	reviewGit(t, protected, "add", "tracked.txt")
	reviewGit(t, protected, "commit", "-m", "private fixture")
	canonical, err := filepath.EvalSymlinks(protected)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"source", "git", "common"} {
		t.Run(kind, func(t *testing.T) {
			root := protected
			if kind != "source" {
				root = t.TempDir()
				gitDir := filepath.Join(canonical, ".git")
				if kind == "common" {
					admin := t.TempDir()
					gitDir, err = filepath.EvalSymlinks(admin)
					if err != nil {
						t.Fatal(err)
					}
					writeReviewFile(t, filepath.Join(admin, "commondir"), filepath.Join(canonical, ".git")+"\n")
					writeReviewFile(t, filepath.Join(admin, "HEAD"), reviewGitOutput(t, protected, "rev-parse", "HEAD")+"\n")
				}
				writeReviewFile(t, filepath.Join(root, ".git"), "gitdir: "+gitDir+"\n")
			}
			// Verify the fixture is usable before applying its protected-root policy.
			baseline := openTestLiveSource(t, root, domain.LiveSourceHead, "")
			readTestLiveSource(t, baseline, domain.LiveSourceAfter, "tracked.txt", "private Git fixture\n")
			adapter, err := NewLiveSourceAdapter(NewExecRunner(), []ports.AnchoredRoot{mustAnchoredRoot(t, protected)})
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
			reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
			if err == nil {
				defer reader.Close()
				t.Fatal("protected source binding was admitted")
			}
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		})
	}
}

func TestIntegrationLiveSourceRejectsAlternateObjectStores(t *testing.T) {
	t.Run("after-admission", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		linked := filepath.Join(t.TempDir(), "linked")
		reviewGit(t, root, "worktree", "add", "-b", "alternate-linked", linked)
		reader := openTestLiveSource(t, linked, domain.LiveSourceHead, "")
		readTestLiveSource(t, reader, domain.LiveSourceAfter, "tracked.txt", "second\n")
		writeReviewFile(t, filepath.Join(root, ".git", "objects", "info", "alternates"), "")
		path, _ := ports.NewSafeRelativePath("tracked.txt")
		_, err := reader.Read(context.Background(), domain.LiveSourceAfter, path)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
		_, err = reader.List(context.Background(), domain.LiveSourceAfter)
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
	protected := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(protected, "private.txt"), "alternate private fixture\n")
	reviewGit(t, protected, "add", "private.txt")
	reviewGit(t, protected, "commit", "-m", "private alternate")
	oid := reviewGitOutput(t, protected, "rev-parse", "HEAD:private.txt")
	canonical, err := filepath.EvalSymlinks(protected)
	if err != nil {
		t.Fatal(err)
	}
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, ".git", "objects", "info", "alternates"), filepath.Join(canonical, ".git", "objects")+"\n")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+oid+",external.txt")
	if got := reviewGitOutput(t, root, "cat-file", "blob", oid); got != "alternate private fixture" {
		t.Fatalf("alternate fixture unavailable: %q", got)
	}
	adapter, err := NewLiveSourceAdapter(NewExecRunner(), []ports.AnchoredRoot{mustAnchoredRoot(t, protected)})
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
	if err == nil {
		defer reader.Close()
		path, _ := ports.NewSafeRelativePath("external.txt")
		file, readErr := reader.Read(context.Background(), domain.LiveSourceIndex, path)
		if readErr == nil && string(file.Bytes()) == "alternate private fixture\n" {
			t.Fatal("protected alternate object was admitted")
		}
		t.Fatalf("alternate source was admitted: %v", readErr)
	}
	assertLiveError(t, err, ports.LiveSourceUnsafe)
}

func TestIntegrationLiveSourceRejectsGitDirectoryReplacement(t *testing.T) {
	root := reviewCaptureRepository(t)
	reader := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	gitDir := filepath.Join(root, ".git")
	if err := os.Rename(gitDir, gitDir+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := reader.List(context.Background(), domain.LiveSourceAfter)
	assertLiveError(t, err, ports.LiveSourceUnsafe)
	path, _ := ports.NewSafeRelativePath("tracked.txt")
	_, err = reader.Read(context.Background(), domain.LiveSourceAfter, path)
	assertLiveError(t, err, ports.LiveSourceUnsafe)
}

func TestIntegrationLiveSourceNonGitBoundaries(t *testing.T) {
	t.Run("unsafe-root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o770); err != nil {
			t.Fatal(err)
		}
		adapter, err := NewLiveSourceAdapter(NewExecRunner(), nil)
		if err != nil {
			t.Fatal(err)
		}
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
		reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
		if err == nil {
			defer reader.Close()
			t.Fatal("unsafe root was admitted")
		}
		assertLiveError(t, err, ports.LiveSourceUnsafe)
	})
	for _, test := range []struct {
		scope domain.LiveSourceScope
		value string
	}{
		{domain.LiveSourceStage, ""}, {domain.LiveSourceHead, ""},
		{domain.LiveSourceCommit, "HEAD"}, {domain.LiveSourceDiff, "HEAD~1..HEAD"},
	} {
		t.Run(string(test.scope), func(t *testing.T) {
			adapter, err := NewLiveSourceAdapter(NewExecRunner(), nil)
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(test.scope, test.value)
			_, err = adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, t.TempDir()), selector)
			assertLiveError(t, err, ports.LiveSourceRevision)
		})
	}
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "selected")
			if kind == "symlink" {
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			} else if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			adapter, err := NewLiveSourceAdapter(NewExecRunner(), nil)
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			_, err = adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
			assertLiveError(t, err, ports.LiveSourceUnsafe)
		})
	}
}

func TestIntegrationLiveSourceNonGitIgnoreAdmission(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		".gitignore": "ignored.txt\n", ".mulgaeignore": "keep.txt\n",
		"keep.txt": "kept\n", "ignored.txt": "ignored\n",
		"folder/.gitignore": "*.tmp\n!keep.tmp\n", "folder/ignored.txt": "ignored\n",
		"folder/drop.tmp": "ignored\n", "folder/keep.tmp": "kept\n", "folder/plain.txt": "kept\n",
	} {
		writeReviewFile(t, filepath.Join(root, path), body)
	}
	reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
	paths, err := reader.List(context.Background(), domain.LiveSourceWorktree)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, path := range paths {
		names = append(names, path.String())
	}
	expected := []string{".gitignore", ".mulgaeignore", "folder/.gitignore", "folder/keep.tmp", "folder/plain.txt", "keep.txt"}
	if !reflect.DeepEqual(names, expected) {
		t.Fatalf("non-Git ignore selection: %v", names)
	}
	readTestLiveSource(t, reader, domain.LiveSourceWorktree, "ignored.txt", "ignored\n")
	for _, test := range []struct {
		name, content string
		code          ports.LiveSourceErrorCode
	}{
		{"oversized", strings.Repeat("a", (256<<10)+1), ports.LiveSourceUnsafe},
		{"invalid-utf8", "\xff", ports.LiveSourceUnsafe},
		{"nul", "\x00", ports.LiveSourceUnsafe},
		{"malformed-rule", "!\n", ports.LiveSourceInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeReviewFile(t, filepath.Join(root, ".gitignore"), test.content)
			adapter, _ := NewLiveSourceAdapter(NewExecRunner(), nil)
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			_, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
			assertLiveError(t, err, test.code)
		})
	}
}

func TestIntegrationLiveSourceSkipsNestedRepositoriesAndGitlinks(t *testing.T) {
	root := reviewCaptureRepository(t)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, nested, "init")
	reviewGit(t, nested, "config", "user.name", "Test")
	reviewGit(t, nested, "config", "user.email", "test@example.invalid")
	writeReviewFile(t, filepath.Join(nested, "source.txt"), "nested\n")
	reviewGit(t, nested, "add", "source.txt")
	reviewGit(t, nested, "commit", "-m", "nested fixture")
	workspace := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
	for _, change := range workspace.Target().Changes() {
		if strings.HasPrefix(change.After.String(), "nested/") {
			t.Fatal("nested repository became a workspace candidate")
		}
	}
	object := reviewGitOutput(t, root, "rev-parse", "HEAD")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "160000,"+object+",vendor/lib")
	stage := openTestLiveSource(t, root, domain.LiveSourceStage, "")
	if !stage.Target().NoChange() {
		t.Fatal("gitlink-only transition acquired file candidates")
	}
	path, _ := ports.NewSafeRelativePath("vendor/lib")
	_, err := stage.Read(context.Background(), domain.LiveSourceIndex, path)
	assertLiveError(t, err, ports.LiveSourceUnavailable)
	reviewGit(t, root, "commit", "-m", "gitlink fixture")
	head := openTestLiveSource(t, root, domain.LiveSourceHead, "")
	for _, change := range head.Target().Changes() {
		if change.After == path {
			t.Fatal("gitlink became a committed file candidate")
		}
	}
}

func TestIntegrationLiveSourceRenameAcrossProtectedBoundary(t *testing.T) {
	for _, into := range []bool{true, false} {
		root := reviewCaptureRepository(t)
		home := filepath.Join(root, "named-profile")
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
		from, to, kind := "tracked.txt", "named-profile/source.txt", "deleted"
		if !into {
			from, to, kind = "named-profile/source.txt", "public.txt", "added"
			writeReviewFile(t, filepath.Join(root, from), "fixture\n")
			reviewGit(t, root, "add", from)
			reviewGit(t, root, "commit", "-m", "protected rename base")
		}
		reviewGit(t, root, "mv", "--", from, to)
		canonical, err := filepath.EvalSymlinks(home)
		if err != nil {
			t.Fatal(err)
		}
		protected, _ := ports.NewAnchoredRoot(canonical)
		adapter, err := NewLiveSourceAdapter(NewExecRunner(), []ports.AnchoredRoot{protected})
		if err != nil {
			t.Fatal(err)
		}
		selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
		reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
		if err != nil {
			t.Fatal(err)
		}
		changes := reader.Target().Changes()
		if len(changes) != 1 || changes[0].Kind != kind ||
			into && (changes[0].Before.String() != from || changes[0].After.Valid()) ||
			!into && (changes[0].After.String() != to || changes[0].Before.Valid()) {
			t.Fatalf("protected rename endpoint escaped: %+v", changes)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationLiveSourceSideAvailability(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "changed\n")
	reviewGit(t, root, "add", "tracked.txt")
	reviewGit(t, root, "commit", "-m", "second commit")
	path, _ := ports.NewSafeRelativePath("tracked.txt")
	for _, test := range []struct {
		scope domain.LiveSourceScope
		value string
		sides []domain.LiveSourceSide
	}{
		{domain.LiveSourceWorkspace, "", []domain.LiveSourceSide{domain.LiveSourceWorktree}},
		{domain.LiveSourceStage, "", []domain.LiveSourceSide{domain.LiveSourceBefore, domain.LiveSourceIndex}},
		{domain.LiveSourceHead, "", []domain.LiveSourceSide{domain.LiveSourceAfter}},
		{domain.LiveSourceCommit, "HEAD", []domain.LiveSourceSide{domain.LiveSourceBefore, domain.LiveSourceAfter}},
		{domain.LiveSourceDiff, "HEAD~1..HEAD", []domain.LiveSourceSide{domain.LiveSourceBefore, domain.LiveSourceAfter}},
	} {
		reader := openTestLiveSource(t, root, test.scope, test.value)
		for _, side := range []domain.LiveSourceSide{domain.LiveSourceWorktree, domain.LiveSourceIndex, domain.LiveSourceBefore, domain.LiveSourceAfter, "unknown"} {
			available := false
			for _, allowed := range test.sides {
				available = available || side == allowed
			}
			_, listErr := reader.List(context.Background(), side)
			_, readErr := reader.Read(context.Background(), side, path)
			if available {
				if listErr != nil || readErr != nil {
					t.Fatalf("available %s/%s: %v; %v", test.scope, side, listErr, readErr)
				}
			} else {
				assertLiveError(t, listErr, ports.LiveSourceInvalid)
				assertLiveError(t, readErr, ports.LiveSourceInvalid)
			}
		}
	}
}

func TestIntegrationLiveSourceConcurrentReadsAndClose(t *testing.T) {
	root := reviewCaptureRepository(t)
	reader := openTestLiveSource(t, root, domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("tracked.txt")
	start := make(chan struct{})
	ready := make(chan struct{}, 8)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := reader.Read(context.Background(), domain.LiveSourceWorktree, path)
			if err != nil {
				assertLiveError(t, err, ports.LiveSourceUnavailable)
			}
			ready <- struct{}{}
			_, err = reader.List(context.Background(), domain.LiveSourceWorktree)
			if err != nil {
				assertLiveError(t, err, ports.LiveSourceUnavailable)
			}
		}()
	}
	close(start)
	<-ready
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
}

func TestIntegrationLiveSourceRejectsUnsafeAndUnavailableSources(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string)
		scope   domain.LiveSourceScope
		value   string
		code    ports.LiveSourceErrorCode
	}{
		{"broken-head", func(t *testing.T, root string) {
			ref := reviewGitOutput(t, root, "symbolic-ref", "HEAD")
			writeReviewFile(t, filepath.Join(root, ".git", filepath.FromSlash(ref)), strings.Repeat("f", 40)+"\n")
		}, domain.LiveSourceStage, "", ports.LiveSourceRevision},
		{"missing-revision", func(*testing.T, string) {}, domain.LiveSourceCommit, "missing", ports.LiveSourceRevision},
		{"selected-symlink", func(t *testing.T, root string) {
			if err := os.Symlink("tracked.txt", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		}, domain.LiveSourceWorkspace, "", ports.LiveSourceUnsafe},
		{"selected-fifo", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "tracked.txt")); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(root, "tracked.txt"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, domain.LiveSourceWorkspace, "", ports.LiveSourceUnsafe},
		{"conflict", func(t *testing.T, root string) {
			reviewGit(t, root, "checkout", "-b", "conflict")
			writeReviewFile(t, filepath.Join(root, "tracked.txt"), "conflict\n")
			reviewGit(t, root, "commit", "-am", "conflict")
			reviewGit(t, root, "checkout", "-b", "other", "HEAD~1")
			writeReviewFile(t, filepath.Join(root, "tracked.txt"), "other\n")
			reviewGit(t, root, "commit", "-am", "other")
			// A nonzero merge result creates the genuine unmerged index fixture.
			_, _ = (NewExecRunner()).Run(context.Background(), Command{Dir: root, Args: []string{"merge", "conflict"}})
		}, domain.LiveSourceStage, "", ports.LiveSourceConflict},
		{"unrelated-triple-dot", func(t *testing.T, root string) {
			reviewGit(t, root, "branch", "original")
			reviewGit(t, root, "checkout", "--orphan", "unrelated")
			reviewGit(t, root, "commit", "-m", "unrelated root")
		}, domain.LiveSourceDiff, "original...unrelated", ports.LiveSourceNoMergeBase},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := reviewCaptureRepository(t)
			test.prepare(t, root)
			selector, err := ports.NewLiveSourceSelector(test.scope, test.value)
			if err != nil {
				t.Fatal(err)
			}
			adapter, _ := NewLiveSourceAdapter(NewExecRunner(), nil)
			reader, err := adapter.OpenLiveSource(context.Background(), mustAnchoredRoot(t, root), selector)
			if reader != nil {
				_ = reader.Close()
			}
			assertLiveError(t, err, test.code)
		})
	}
}

func liveTreeState(t *testing.T, root string) map[string]string {
	t.Helper()
	state := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity := fmt.Sprintf("%s", info.Mode())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			identity += fmt.Sprintf(":%x", sha256.Sum256(data))
		}
		state[relative] = identity
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return state
}
