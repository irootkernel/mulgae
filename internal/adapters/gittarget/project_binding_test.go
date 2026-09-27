//go:build darwin && arm64

package gittarget

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func bindingLease(t *testing.T, root string) ports.ProjectBindingLease {
	t.Helper()
	anchor, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := (ProjectBindingObserver{}).ObserveProjectBinding(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	return lease
}

func TestProjectBindingIdentityAndAliases(t *testing.T) {
	root := reviewCaptureRepository(t)
	original := bindingLease(t, root)
	if got := bindingLease(t, root).Observation(); got != original.Observation() {
		t.Fatal("same root differs")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if got := bindingLease(t, alias).Observation(); got != original.Observation() {
		t.Fatal("canonical alias differs")
	}
	other := filepath.Join(t.TempDir(), "clone")
	reviewGit(t, root, "clone", "--local", root, other)
	if bindingLease(t, other).Observation() == original.Observation() {
		t.Fatal("equal-content checkout reused identity")
	}
	linked := filepath.Join(t.TempDir(), "linked")
	reviewGit(t, root, "worktree", "add", "--detach", linked)
	linkedObservation := bindingLease(t, linked).Observation()
	if linkedObservation.RootIdentity == original.Observation().RootIdentity || linkedObservation.GitIdentity == original.Observation().GitIdentity || linkedObservation.CommonIdentity != original.Observation().CommonIdentity {
		t.Fatal("linked worktree anchors incorrect")
	}
	writeReviewFile(t, filepath.Join(root, "new.txt"), "ordinary worktree change")
	reviewGit(t, root, "add", "new.txt")
	if err := original.Revalidate(context.Background()); err != nil {
		t.Fatalf("ordinary content changed binding: %v", err)
	}
}

func TestProjectBindingRejectsDriftAndUnsafeMetadata(t *testing.T) {
	for _, target := range []string{"root", "git", "common", "alias", "permissions", "metadata_symlink", "malformed_pointer", "writable_pointer", "missing"} {
		t.Run(target, func(t *testing.T) {
			root := reviewCaptureRepository(t)
			requested := root
			if target == "common" {
				requested = filepath.Join(t.TempDir(), "linked")
				reviewGit(t, root, "worktree", "add", "--detach", requested)
			}
			if target == "alias" {
				requested = filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, requested); err != nil {
					t.Fatal(err)
				}
			}
			lease := bindingLease(t, requested)
			switch target {
			case "root", "git", "common":
				path := root
				if target != "root" {
					path = filepath.Join(root, ".git")
				}
				t.Cleanup(func() { _ = os.RemoveAll(path + "-old") })
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.Remove(requested); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(reviewCaptureRepository(t), requested); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(root, 0777); err != nil {
					t.Fatal(err)
				}
			case "metadata_symlink":
				path := filepath.Join(root, ".git")
				t.Cleanup(func() { _ = os.RemoveAll(path + "-old") })
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-old", path); err != nil {
					t.Fatal(err)
				}
			case "malformed_pointer", "writable_pointer":
				path := filepath.Join(root, ".git")
				t.Cleanup(func() { _ = os.RemoveAll(path + "-old") })
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				writeReviewFile(t, path, "gitdir: unsafe\x00path\n")
				if target == "writable_pointer" {
					writeReviewFile(t, path, "gitdir: "+path+"-old\n")
					if err := os.Chmod(path, 0666); err != nil {
						t.Fatal(err)
					}
				}
			case "missing":
				t.Cleanup(func() { _ = os.RemoveAll(root + "-old") })
				if err := os.Rename(root, root+"-old"); err != nil {
					t.Fatal(err)
				}
			}
			if err := lease.Revalidate(context.Background()); err == nil {
				t.Fatal("drift admitted")
			}
			anchor, _ := ports.NewAnchoredRoot(requested)
			fresh, err := (ProjectBindingObserver{}).ObserveProjectBinding(context.Background(), anchor)
			if target != "alias" && err == nil {
				_ = fresh.Close()
				t.Fatal("unsafe new observation admitted")
			}
			if fresh != nil {
				_ = fresh.Close()
			}
		})
	}
}

func TestProjectBindingCanonicalFilesystemSpelling(t *testing.T) {
	root := reviewCaptureRepository(t)
	path := filepath.Join(root, "MixedCase")
	reviewGit(t, root, "clone", "--local", root, path)
	alias := filepath.Join(root, "mixedcase")
	if _, err := os.Stat(alias); os.IsNotExist(err) {
		t.Skip("fixture filesystem is case-sensitive")
	} else if err != nil {
		t.Fatal(err)
	}
	original := bindingLease(t, path)
	if got := bindingLease(t, alias).Observation(); got != original.Observation() {
		t.Fatal("filesystem case alias produced a different identity")
	}
}
