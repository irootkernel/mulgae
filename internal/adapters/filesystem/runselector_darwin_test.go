//go:build darwin && arm64

package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestRunSelectorEnumeratesOnlyCanonicalSafeDirectories(t *testing.T) {
	rootPath := t.TempDir()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	const session = "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	const run = "r_019f596a-cf80-7c67-b265-f37053d51ccf"
	mustSelectorMkdir(t, filepath.Join(rootPath, session), 0o700)
	mustSelectorMkdir(t, filepath.Join(rootPath, session, run), 0o700)
	mustSelectorMkdir(t, filepath.Join(rootPath, "not-a-session"), 0o700)
	if err := os.Symlink(t.TempDir(), filepath.Join(rootPath, session, "r_019f596a-cf80-7c67-b265-f37053d51ccd")); err != nil {
		t.Fatal(err)
	}

	candidates, diagnostics, err := NewRunSelector().Enumerate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].SessionID.String() != session || candidates[0].RunID.String() != run {
		t.Fatalf("candidates = %#v", candidates)
	}
	wantDiagnostics := []RunSelectorDiagnostic{
		{Path: "not-a-session", Reason: "malformed session ID"},
		{Path: session + "/r_019f596a-cf80-7c67-b265-f37053d51ccd", Reason: "unsafe run directory"},
	}
	if !reflect.DeepEqual(diagnostics, wantDiagnostics) {
		t.Fatalf("diagnostics = %#v, want %#v", diagnostics, wantDiagnostics)
	}
}

func mustSelectorMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
}
