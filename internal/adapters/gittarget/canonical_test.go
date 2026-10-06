//go:build darwin && arm64

package gittarget

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func mustObjectID(t *testing.T, character string) ports.GitObjectID {
	t.Helper()
	objectID, err := ports.ParseGitObjectID(strings.Repeat(character, 40))
	if err != nil {
		t.Fatal(err)
	}
	return objectID
}
func TestCanonicalMetadataFailsClosedOnOversizeSymlinkAndSwap(t *testing.T) {
	directory := t.TempDir()

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(directory, "oversize")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, maxCanonicalGitMetadataBytes+1); err != nil {
			t.Fatal(err)
		}
		if _, err := readCanonicalGitMetadata(path); err == nil {
			t.Fatal("oversize metadata was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("metadata"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "symlink")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := readCanonicalGitMetadata(path); err == nil {
			t.Fatal("symlink metadata was accepted")
		}
	})

	t.Run("swap", func(t *testing.T) {
		path := filepath.Join(directory, "swap")
		if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
		expected, err := inspectCanonicalMetadataPath(path, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("after"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCanonicalGitMetadataExpected(path, &expected); err == nil {
			t.Fatal("swapped metadata was accepted")
		}
	})
	t.Run("same length rewrite", func(t *testing.T) {
		path := filepath.Join(directory, "same-length")
		if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		mutated := make(chan error, 1)
		canonicalMetadataReadHook = func(candidate string) {
			if candidate != path {
				return
			}
			close(entered)
			<-release
		}
		defer func() {
			canonicalMetadataReadHook = nil
		}()
		go func() {
			<-entered
			mutated <- os.WriteFile(path, []byte("after!"), 0o600)
			close(release)
		}()
		if _, err := readCanonicalGitMetadata(path); err == nil {
			t.Fatal("same-length rewritten metadata was accepted")
		}
		if err := <-mutated; err != nil {
			t.Fatal(err)
		}
	})

	if err := validateCanonicalMetadataPath(strings.Repeat("x", maxCanonicalGitMetadataPathBytes+1)); err == nil {
		t.Fatal("overlong metadata path was accepted")
	}
}

func TestCanonicalMetadataDirectoryPlanningFailsClosedBeforeCopy(t *testing.T) {
	assertRejected := func(t *testing.T, prepare func(source string), traversal canonicalMetadataTraversal, copiedBytes int64) {
		t.Helper()
		source := t.TempDir()
		destination := filepath.Join(t.TempDir(), "destination")
		prepare(source)
		if err := copyCanonicalGitDirectory(source, destination, &copiedBytes, &traversal); err == nil {
			t.Fatal("unsafe metadata directory was accepted")
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatalf("destination exists after rejected metadata plan: %v", err)
		}
	}

	t.Run("aggregate entry limit", func(t *testing.T) {
		assertRejected(t, func(source string) {
			for _, name := range []string{"first", "second"} {
				if err := os.WriteFile(filepath.Join(source, name), []byte(name), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}, canonicalMetadataTraversal{entries: maxCanonicalGitMetadataEntries - 1}, 0)
	})

	t.Run("aggregate byte limit", func(t *testing.T) {
		assertRejected(t, func(source string) {
			if err := os.WriteFile(filepath.Join(source, "entry"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, canonicalMetadataTraversal{}, maxCanonicalGitMetadataBytes)
	})

	t.Run("deep tree", func(t *testing.T) {
		assertRejected(t, func(source string) {
			path := source
			for index := 0; index <= maxCanonicalGitMetadataDepth; index++ {
				path = filepath.Join(path, "d")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}, canonicalMetadataTraversal{}, 0)
	})

	t.Run("symlink", func(t *testing.T) {
		assertRejected(t, func(source string) {
			if err := os.Symlink("missing", filepath.Join(source, "ref")); err != nil {
				t.Fatal(err)
			}
		}, canonicalMetadataTraversal{}, 0)
	})
}

func TestCanonicalObjectFormatForTypedObjectID(t *testing.T) {
	sha1 := mustObjectID(t, "a")
	if format, err := canonicalObjectFormatForObjectID(sha1); err != nil || format != "sha1" {
		t.Fatalf("SHA-1 object format = %q, %v", format, err)
	}
	sha256, err := ports.ParseGitObjectID(strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if format, err := canonicalObjectFormatForObjectID(sha256); err != nil || format != "sha256" {
		t.Fatalf("SHA-256 object format = %q, %v", format, err)
	}
}
func TestCanonicalMetadataFailsClosedOnAncestorSwap(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "metadata")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ref"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	mutated := make(chan error, 1)
	canonicalMetadataReadHook = func(candidate string) {
		if candidate != source {
			return
		}
		close(entered)
		<-release
	}
	defer func() {
		canonicalMetadataReadHook = nil
	}()
	go func() {
		<-entered
		backup := filepath.Join(parent, "metadata-before-swap")
		if err := os.Rename(source, backup); err != nil {
			mutated <- err
			close(release)
			return
		}
		if err := os.Mkdir(source, 0o700); err != nil {
			mutated <- err
			close(release)
			return
		}
		mutated <- os.WriteFile(filepath.Join(source, "ref"), []byte("after!\n"), 0o600)
		close(release)
	}()

	var copiedBytes int64
	if err := copyCanonicalGitDirectory(source, destination, &copiedBytes, &canonicalMetadataTraversal{}); err == nil {
		t.Fatal("ancestor-swapped metadata was accepted")
	}
	if err := <-mutated; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination exists after ancestor swap: %v", err)
	}
}

func TestCanonicalGitDirectoriesFailClosedOnGitEntrySwap(t *testing.T) {
	root := t.TempDir()
	gitDirectory := filepath.Join(root, ".git")
	if err := os.MkdirAll(filepath.Join(gitDirectory, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDirectory, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDirectory, "config"), []byte("[core]\nrepositoryformatversion = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	anchoredRoot, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	mutated := make(chan error, 1)
	canonicalMetadataReadHook = func(candidate string) {
		if candidate != filepath.Join(gitDirectory, "HEAD") {
			return
		}
		close(entered)
		<-release
	}
	defer func() {
		canonicalMetadataReadHook = nil
	}()
	go func() {
		<-entered
		backup := filepath.Join(root, "git-before-swap")
		if err := os.Rename(gitDirectory, backup); err != nil {
			mutated <- err
			close(release)
			return
		}
		mutated <- os.Symlink(backup, gitDirectory)
		close(release)
	}()

	repository, cleanup, err := newCanonicalRepository(anchoredRoot, "HEAD")
	if cleanup != nil {
		_ = cleanup()
	}
	if err == nil {
		t.Fatalf("Git entry swap produced canonical repository %#v", repository)
	}
	if err := <-mutated; err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalGitDirectoriesSupportRelativeLinkedWorktreeMetadata(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "worktree")
	common := filepath.Join(parent, "main", ".git")
	worktreeGitDirectory := filepath.Join(common, "worktrees", "worktree")
	if err := os.MkdirAll(filepath.Join(common, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(worktreeGitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: ../main/.git/worktrees/worktree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGitDirectory, "commondir"), []byte("../..\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	worktree, resolvedCommon, err := canonicalGitDirectories(root)
	if err != nil {
		t.Fatal(err)
	}
	if worktree != worktreeGitDirectory || resolvedCommon != common {
		t.Fatalf("linked worktree directories = (%q, %q), want (%q, %q)", worktree, resolvedCommon, worktreeGitDirectory, common)
	}
}

func TestCanonicalObjectFormatRequiresStructuralEvidence(t *testing.T) {
	if _, err := canonicalObjectFormat(newCanonicalMetadataSnapshot()); err == nil {
		t.Fatal("indeterminate object format was accepted")
	}

	sha1 := newCanonicalMetadataSnapshot()
	sha1.config = []byte("[core]\nrepositoryformatversion = 0\n")
	if format, err := canonicalObjectFormat(sha1); err != nil || format != "sha1" {
		t.Fatalf("structural SHA-1 format = %q, %v", format, err)
	}

	sha256 := newCanonicalMetadataSnapshot()
	sha256.config = []byte("[core]\nrepositoryformatversion = 1\n[extensions]\nobjectformat = sha256\n")
	if format, err := canonicalObjectFormat(sha256); err != nil || format != "sha256" {
		t.Fatalf("structural SHA-256 format = %q, %v", format, err)
	}
}

func TestJoinCanonicalConstructionCleanupPreservesBothCauses(t *testing.T) {
	primary := errors.New("primary")
	cleanupFailure := errors.New("cleanup")
	calls := 0
	joined := joinCanonicalConstructionCleanup(primary, "close descriptors", func() error {
		calls++
		return cleanupFailure
	})
	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls)
	}
	if !errors.Is(joined, primary) || !errors.Is(joined, cleanupFailure) {
		t.Fatalf("joined error = %v, want both causes", joined)
	}

	cleanupOnly := joinCanonicalConstructionCleanup(nil, "close descriptors", func() error {
		return cleanupFailure
	})
	if !errors.Is(cleanupOnly, cleanupFailure) {
		t.Fatalf("cleanup-only error = %v, want cleanup cause", cleanupOnly)
	}
}
