//go:build darwin && arm64

package gittarget

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
