//go:build darwin && arm64

package gittarget

import (
	"context"
	"errors"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type oneShotStdin struct {
	bytes []byte
	taken bool
}

func (store *oneShotStdin) TakeCapturedStdin(_ context.Context, token string) ([]byte, error) {
	if token != "captured" || store.taken {
		return nil, errors.New("stdin was already consumed")
	}
	store.taken = true
	return append([]byte(nil), store.bytes...), nil
}

func TestReviewCaptureRealGitRangeDirtyPatchAndStdin(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &oneShotStdin{bytes: []byte("diff --git a/x b/x\n")}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), store, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("range preserves resolved objects", func(t *testing.T) {
		selector := reviewSelector(t, ports.ReviewTargetDiff, "HEAD~1...HEAD")
		material, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector)
		if err != nil || material.Target().NoChange() || !material.Valid() {
			t.Fatalf("range capture = %#v, %v", material, err)
		}
	})

	t.Run("dirty includes eligible untracked and index identity", func(t *testing.T) {
		writeReviewFile(t, filepath.Join(root, "tracked.txt"), "changed\n")
		writeReviewFile(t, filepath.Join(root, "untracked.txt"), "new\n")
		writeReviewFile(t, filepath.Join(root, "untracked space.txt"), "space\n")
		writeReviewFile(t, filepath.Join(root, "untracked-한글.txt"), "unicode\n")
		writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored\n")
		if err := os.MkdirAll(filepath.Join(root, ".kar", "diagnostics"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeReviewFile(t, filepath.Join(root, ".kar", "diagnostics", "doctor.json"), "{}\n")
		material, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDiff, "git"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := material.Target().IndexTreeID(); !ok {
			t.Fatal("dirty target did not bind index tree")
		}
		patch := string(material.Target().Bytes())
		if !strings.Contains(patch, "diff --git a/untracked.txt b/untracked.txt") ||
			!strings.Contains(patch, "diff --git \"a/untracked space.txt\" \"b/untracked space.txt\"") ||
			strings.Contains(patch, "diff --git a/ignored.txt b/ignored.txt") ||
			strings.Contains(patch, ".kar/") {
			t.Fatalf("dirty patch did not apply captured ignore decision: %q", patch)
		}
		if parsed, privateFree := parseUnifiedDiffPrivatePathFree(material.Target().Bytes()); !parsed || !privateFree {
			t.Fatalf("dirty patch with quoted paths = parsed %t private_free %t", parsed, privateFree)
		}
	})

	t.Run("patch rejects symlinks and source replacement", func(t *testing.T) {
		if err := os.Symlink("tracked.txt", filepath.Join(root, "link.patch")); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "link.patch")); err == nil {
			t.Fatal("symlink patch was accepted")
		}
		writeReviewFile(t, filepath.Join(root, "patch.diff"), "diff --git a/a b/a\n")
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "patch.diff")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "patch.diff")); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "patch.diff")); err == nil {
			t.Fatal("removed patch source was accepted")
		}
	})

	t.Run("stdin is one shot", func(t *testing.T) {
		selector := reviewSelector(t, ports.ReviewTargetStdin, "captured")
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector); err == nil {
			t.Fatal("stdin capture was reusable")
		}
	})
}

func TestReviewCaptureRejectsUnicodeAndCaseCollisions(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "Readme"), "one\n")
	reviewGit(t, root, "add", "Readme")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+reviewGitOutput(t, root, "hash-object", "-w", "Readme")+",README")
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDiff, "git")); err == nil {
		t.Fatal("case-colliding index paths were accepted")
	}

	root = reviewCaptureRepository(t)
	anchored, err = ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "config", "core.precomposeunicode", "false")
	writeReviewFile(t, filepath.Join(root, "é"), "one\n")
	reviewGit(t, root, "add", "é")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+reviewGitOutput(t, root, "hash-object", "-w", "é")+",e\u0301")
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDiff, "git")); err == nil {
		t.Fatal("NFC/NFD-colliding index paths were accepted")
	}
}

func TestReviewCaptureRejectsEligibleSpecialFile(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "capture.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDiff, "git")); err == nil {
		t.Fatal("eligible special file was accepted")
	}
}
func reviewCaptureRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	reviewGit(t, root, "init")
	reviewGit(t, root, "config", "user.email", "test@example.invalid")
	reviewGit(t, root, "config", "user.name", "Test")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "base\n")
	reviewGit(t, root, "add", "tracked.txt")
	reviewGit(t, root, "commit", "-m", "base")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "second\n")
	reviewGit(t, root, "commit", "-am", "second")
	return root
}

func reviewGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("/usr/bin/git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
func reviewGitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("/usr/bin/git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}

func writeReviewFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func reviewSelector(t *testing.T, kind ports.ReviewTargetSelectorKind, value string) ports.ReviewTargetSelector {
	t.Helper()
	selector, err := ports.NewReviewTargetSelector(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}
