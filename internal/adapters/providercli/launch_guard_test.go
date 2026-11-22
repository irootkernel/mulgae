//go:build darwin && arm64

package providercli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestLaunchGuardRejectsContainedLaunchAndRuntimeHomeExposure(t *testing.T) {
	base := credentialSourceTempDir(t)
	runtime := filepath.Join(base, "runtime")
	source := filepath.Join(base, "source")
	nested := filepath.Join(source, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectContainedLaunch(source, nested); err == nil {
		t.Fatal("contained child launch root was admitted")
	}
	if err := rejectContainedLaunch(nested, source); err == nil {
		t.Fatal("containing ancestor launch root was admitted")
	}
	if err := rejectContainedLaunch(source, runtime); err != nil {
		t.Fatalf("disjoint launch root rejected: %v", err)
	}
	for _, exposed := range []string{runtime, base} {
		err := rejectRuntimeHomeExposure(runtime, exposed)
		var boundaryErr *launchBoundaryError
		if !errors.As(err, &boundaryErr) {
			t.Fatalf("rejectRuntimeHomeExposure(%q, %q) = %v, want *launchBoundaryError", runtime, exposed, err)
		}
	}
	if err := rejectRuntimeHomeExposure(runtime, source); err != nil {
		t.Fatalf("disjoint root rejected: %v", err)
	}
}

func TestBoundaryCredentialsDeduplicatesAndIncludesExistingDirectories(t *testing.T) {
	base := credentialSourceTempDir(t)
	authDir := filepath.Join(base, "auth")
	extraDir := filepath.Join(base, "extra")
	absentDir := filepath.Join(base, "absent")
	regularFile := filepath.Join(base, "file.txt")
	for _, dir := range []string{authDir, extraDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	authRoot, err := ports.NewAnchoredRoot(authDir)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := boundaryCredentials([]ports.AnchoredRoot{authRoot}, authDir, []string{extraDir, extraDir, absentDir, regularFile})
	if err != nil {
		t.Fatalf("boundaryCredentials: %v", err)
	}
	if len(roots) != 2 || roots[0].String() != authDir || roots[1].String() != extraDir {
		t.Fatalf("roots = %v, want [%s %s]", roots, authDir, extraDir)
	}
}

func anchoredContains(roots []ports.AnchoredRoot, target string) bool {
	for _, root := range roots {
		if root.String() == target {
			return true
		}
	}
	return false
}
