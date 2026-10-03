//go:build darwin && arm64

package providercli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func TestReviewerHomeCreatesPreservesAndRevalidatesGuide(t *testing.T) {
	root := reviewerHomeTestRoot(t)
	guide := []byte(strings.Repeat("shared instruction\n", 65536))
	home, err := OpenReviewerHome(root, guide)
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	path := filepath.Join(root.String(), ".mulgae", "home", "AGENTS.md")
	if string(home.Guide()) != string(guide) {
		t.Fatal("guide bytes were shortened or changed")
	}
	home.Guide()[0] = 'X'
	if home.Guide()[0] == 'X' {
		t.Fatal("guide accessor returned mutable authority")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("new guide permissions: %v, %v", err, info)
	}
	second, err := OpenReviewerHome(root, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if string(second.Guide()) != string(guide) {
		t.Fatal("existing guide overwritten")
	}
	directory, err := home.DuplicateLaunchDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := home.Revalidate(); err == nil {
		t.Fatal("changed guide admitted")
	}
	if _, err := home.DuplicateLaunchDirectory(); err == nil {
		t.Fatal("changed guide gained launch authority")
	}
}

func TestReviewerHomeRejectsOperatorPermissionDrift(t *testing.T) {
	root := reviewerHomeTestRoot(t)
	home, err := OpenReviewerHome(root, []byte("default guide"))
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	if err := os.Chmod(root.String(), 0770); err != nil {
		t.Fatal(err)
	}
	if err := home.Revalidate(); err == nil {
		t.Fatal("group-writable operator root admitted")
	}
	if directory, err := home.DuplicateLaunchDirectory(); err == nil {
		_ = directory.Close()
		t.Fatal("unsafe operator root gained launch authority")
	}
}

func TestReviewerHomeConcurrentCreationIsAtomic(t *testing.T) {
	root := reviewerHomeTestRoot(t)
	guide := []byte(strings.Repeat("complete default guide\n", 32768))
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			home, err := OpenReviewerHome(root, guide)
			if err != nil {
				t.Error(err)
				return
			}
			defer home.Close()
			if string(home.Guide()) != string(guide) {
				t.Error("partial concurrent guide")
			}
		}()
	}
	close(start)
	workers.Wait()
	entries, err := os.ReadDir(filepath.Join(root.String(), ".mulgae", "home"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "AGENTS.md" {
		t.Fatalf("candidate residue: %v, %v", err, entries)
	}
}

func TestReviewerHomeRejectsUnsafePathsAndReplacement(t *testing.T) {
	for _, kind := range []string{"symlink-directory", "symlink-guide", "fifo-guide", "hardlink-guide", "writable-guide", "replacement-directory"} {
		t.Run(kind, func(t *testing.T) {
			root := reviewerHomeTestRoot(t)
			path := filepath.Join(root.String(), ".mulgae", "home")
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			guide := filepath.Join(path, "AGENTS.md")
			other := filepath.Join(root.String(), "other")
			if err := os.WriteFile(other, []byte("preserved other file"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink-directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(root.String(), path); err != nil {
					t.Fatal(err)
				}
			case "symlink-guide":
				if err := os.Symlink(other, guide); err != nil {
					t.Fatal(err)
				}
			case "fifo-guide":
				if err := unix.Mkfifo(guide, 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink-guide":
				if err := os.Link(other, guide); err != nil {
					t.Fatal(err)
				}
			case "writable-guide":
				if err := os.WriteFile(guide, []byte("writable"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(guide, 0666); err != nil {
					t.Fatal(err)
				}
			}
			home, err := OpenReviewerHome(root, []byte("default"))
			if kind == "replacement-directory" {
				if err != nil {
					t.Fatal(err)
				}
				defer home.Close()
				if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := home.Revalidate(); err == nil {
					t.Fatal("replacement directory admitted")
				}
				return
			}
			if home != nil || err == nil {
				if home != nil {
					_ = home.Close()
				}
				t.Fatal("unsafe path admitted")
			}
			data, err := os.ReadFile(other)
			if err != nil || string(data) != "preserved other file" {
				t.Fatal("unrelated file changed")
			}
		})
	}
}

func reviewerHomeTestRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return root
}
