//go:build darwin && arm64

package herdr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	raw := t.TempDir()
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func writeFakeBinary(t *testing.T, path string, mode os.FileMode, content []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestResolveExecutableOverridePrecedenceAndNoFallback(t *testing.T) {
	t.Parallel()

	base := canonicalTempDir(t)
	safePathDir := filepath.Join(base, "safe-path")
	localBinDir := filepath.Join(base, "home", ".local", "bin")
	overrideBin := filepath.Join(base, "override", "hc")
	wantDigest := writeFakeBinary(t, overrideBin, 0o755, []byte("#!/bin/sh\necho override\n"))
	writeFakeBinary(t, filepath.Join(safePathDir, "hc"), 0o755, []byte("#!/bin/sh\necho path\n"))
	writeFakeBinary(t, filepath.Join(localBinDir, "hc"), 0o755, []byte("#!/bin/sh\necho local\n"))

	resolved, err := ResolveExecutable(ResolveOptions{
		OverridePath: overrideBin,
		HasOverride:  true,
		PathEnv:      safePathDir,
		NativeHome:   filepath.Join(base, "home"),
	})
	if err != nil {
		t.Fatalf("ResolveExecutable(valid override): %v", err)
	}
	if resolved.Path != overrideBin || resolved.SHA256 != wantDigest {
		t.Fatalf("resolved = %+v, want path=%s sha256=%s", resolved, overrideBin, wantDigest)
	}

	// Symlink in safe dir pointing to safe executable resolves canonically.
	symlinkOverride := filepath.Join(base, "override", "hc-link")
	if err := os.Symlink(overrideBin, symlinkOverride); err != nil {
		t.Fatal(err)
	}
	resolvedLink, err := ResolveExecutable(ResolveOptions{
		OverridePath: symlinkOverride,
		HasOverride:  true,
		PathEnv:      safePathDir,
		NativeHome:   filepath.Join(base, "home"),
	})
	if err != nil {
		t.Fatalf("ResolveExecutable(valid symlink override): %v", err)
	}
	if resolvedLink.Path != overrideBin || resolvedLink.SHA256 != wantDigest {
		t.Fatalf("resolved symlink = %+v, want path=%s sha256=%s", resolvedLink, overrideBin, wantDigest)
	}

	// Invalid / unsafe overrides MUST NOT fall back to safe PATH or ~/.local/bin.
	excludedDir := filepath.Join(base, "project")
	excludedBin := filepath.Join(excludedDir, "hc")
	writeFakeBinary(t, excludedBin, 0o755, []byte("#!/bin/sh\necho proj\n"))

	worldWritableBin := filepath.Join(base, "badbin", "hc")
	writeFakeBinary(t, worldWritableBin, 0o777, []byte("#!/bin/sh\necho ww\n"))

	groupWritableDir := filepath.Join(base, "gwdir")
	groupWritableDirBin := filepath.Join(groupWritableDir, "hc")
	writeFakeBinary(t, groupWritableDirBin, 0o755, []byte("#!/bin/sh\necho gwd\n"))
	if err := os.Chmod(groupWritableDir, 0o775); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(groupWritableDir, 0o700) })

	nonExecBin := filepath.Join(base, "noexec", "hc")
	writeFakeBinary(t, nonExecBin, 0o600, []byte("not executable"))

	for _, tc := range []struct {
		name     string
		override string
	}{
		{"empty", ""},
		{"relative", "./hc"},
		{"non-clean", filepath.Join(base, "override") + "/../override/hc"},
		{"missing", filepath.Join(base, "missing", "hc")},
		{"directory", filepath.Join(base, "override")},
		{"excluded project root", excludedBin},
		{"world writable binary", worldWritableBin},
		{"group writable parent dir", groupWritableDirBin},
		{"non executable file", nonExecBin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveExecutable(ResolveOptions{
				OverridePath:  tc.override,
				HasOverride:   true,
				PathEnv:       safePathDir,
				NativeHome:    filepath.Join(base, "home"),
				ExcludedRoots: []string{excludedDir},
			})
			if !errors.Is(err, ErrUnsafeExecutable) {
				t.Fatalf("ResolveExecutable(invalid override %q) err = %v, want ErrUnsafeExecutable (no fallback)", tc.override, err)
			}
		})
	}
}

func TestResolveExecutableSafePATHRejectionsAndFallbacks(t *testing.T) {
	t.Parallel()

	base := canonicalTempDir(t)
	projectDir := filepath.Join(base, "project")
	writableDir := filepath.Join(base, "writable")
	gwDir := filepath.Join(base, "group-writable")
	wwBinDir := filepath.Join(base, "safe-dir-bad-bin")
	safePathDir := filepath.Join(base, "safe-bin")
	homeDir := filepath.Join(base, "home")
	localBinDir := filepath.Join(homeDir, ".local", "bin")

	writeFakeBinary(t, filepath.Join(projectDir, "hc"), 0o755, []byte("#!/bin/sh\necho project\n"))
	writeFakeBinary(t, filepath.Join(writableDir, "hc"), 0o755, []byte("#!/bin/sh\necho writable\n"))
	writeFakeBinary(t, filepath.Join(gwDir, "hc"), 0o755, []byte("#!/bin/sh\necho gw\n"))
	if err := os.Chmod(gwDir, 0o775); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gwDir, 0o700) })

	writeFakeBinary(t, filepath.Join(wwBinDir, "hc"), 0o777, []byte("#!/bin/sh\necho ww\n"))
	safeDigest := writeFakeBinary(t, filepath.Join(safePathDir, "herdr-core"), 0o755, []byte("#!/bin/sh\necho safe-core\n"))
	localDigest := writeFakeBinary(t, filepath.Join(localBinDir, "hc"), 0o755, []byte("#!/bin/sh\necho local-hc\n"))

	// Relative, excluded, group-writable, and world-writable PATH candidates are
	// skipped in favor of the safe PATH binary.
	pathEnv := ".:" + filepath.Join("rel", "bin") + ":" + projectDir + ":" + writableDir + ":" + gwDir + ":" + wwBinDir + ":" + safePathDir
	resolved, err := ResolveExecutable(ResolveOptions{
		PathEnv:       pathEnv,
		NativeHome:    homeDir,
		ExcludedRoots: []string{projectDir, writableDir},
	})
	if err != nil {
		t.Fatalf("ResolveExecutable(safe PATH): %v", err)
	}
	wantSafe := filepath.Join(safePathDir, "herdr-core")
	if resolved.Path != wantSafe || resolved.SHA256 != safeDigest {
		t.Fatalf("resolved = %+v, want %s (%s)", resolved, wantSafe, safeDigest)
	}

	// When no safe PATH candidate exists, falls back to <nativeHome>/.local/bin/{hc,herdr-core}.
	unsafePathOnly := ".:" + projectDir + ":" + writableDir + ":" + gwDir
	resolvedLocal, err := ResolveExecutable(ResolveOptions{
		PathEnv:       unsafePathOnly,
		NativeHome:    homeDir,
		ExcludedRoots: []string{projectDir, writableDir},
	})
	if err != nil {
		t.Fatalf("ResolveExecutable(local bin fallback): %v", err)
	}
	wantLocal := filepath.Join(localBinDir, "hc")
	if resolvedLocal.Path != wantLocal || resolvedLocal.SHA256 != localDigest {
		t.Fatalf("resolved local = %+v, want %s (%s)", resolvedLocal, wantLocal, localDigest)
	}

	// Symlink inside a safe PATH dir pointing into excluded project root is rejected.
	escapeDir := filepath.Join(base, "escape-path")
	if err := os.MkdirAll(escapeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(projectDir, "hc"), filepath.Join(escapeDir, "hc")); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveExecutable(ResolveOptions{
		PathEnv:       escapeDir,
		NativeHome:    filepath.Join(base, "empty-home"),
		ExcludedRoots: []string{projectDir},
	})
	if !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("symlink into excluded root err = %v, want ErrUnsafeExecutable", err)
	}

	// Missing everywhere returns ErrExecutableNotFound.
	_, err = ResolveExecutable(ResolveOptions{
		PathEnv:    filepath.Join(base, "nonexistent"),
		NativeHome: filepath.Join(base, "empty-home"),
	})
	if !errors.Is(err, ErrExecutableNotFound) {
		t.Fatalf("missing everywhere err = %v, want ErrExecutableNotFound", err)
	}
}

func TestResolveExecutableHardeningNegatives(t *testing.T) {
	t.Parallel()

	base := canonicalTempDir(t)

	// 1. SUID and SGID binaries must be rejected even when owned by euid.
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"setuid", 0o755 | os.ModeSetuid},
		{"setgid", 0o755 | os.ModeSetgid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binPath := filepath.Join(base, tc.name, "hc")
			writeFakeBinary(t, binPath, tc.mode, []byte("#!/bin/sh\necho suid\n"))
			// Confirm OS preserved the setuid/setgid bit before testing.
			info, err := os.Stat(binPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				t.Fatalf("filesystem stripped %s bit on %s", tc.name, binPath)
			}
			_, err = ResolveExecutable(ResolveOptions{
				OverridePath: binPath,
				HasOverride:  true,
			})
			if !errors.Is(err, ErrUnsafeExecutable) {
				t.Fatalf("ResolveExecutable(%s) err = %v, want ErrUnsafeExecutable", tc.name, err)
			}
		})
	}

	// 2. Missing excluded root whose existing parent prefix is a symlink still
	// excludes paths under its canonical resolved target.
	realParent := filepath.Join(base, "real-parent")
	if err := os.MkdirAll(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(base, "link-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	missingExcludedViaLink := filepath.Join(linkParent, "future-proj")
	normalized, err := normalizeExcludedRoots([]string{missingExcludedViaLink})
	if err != nil {
		t.Fatalf("normalizeExcludedRoots: %v", err)
	}
	wantResolvedExcluded := filepath.Join(realParent, "future-proj")
	if !pathWithinAnyRoot(filepath.Join(wantResolvedExcluded, "bin", "hc"), normalized) {
		t.Fatalf("missing excluded root %q did not resolve parent symlink into %v", missingExcludedViaLink, normalized)
	}

	// 3. Intermediate symlink hop inside an excluded root pointing back outside
	// excluded root MUST be rejected during traversal.
	safeTarget := filepath.Join(base, "safe-outside", "hc")
	writeFakeBinary(t, safeTarget, 0o755, []byte("#!/bin/sh\necho safe\n"))
	excludedHopDir := filepath.Join(base, "excluded-hop")
	if err := os.MkdirAll(excludedHopDir, 0o700); err != nil {
		t.Fatal(err)
	}
	midLink := filepath.Join(excludedHopDir, "hop")
	if err := os.Symlink(safeTarget, midLink); err != nil {
		t.Fatal(err)
	}
	entryLink := filepath.Join(base, "safe-entry", "hc")
	if err := os.MkdirAll(filepath.Dir(entryLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(midLink, entryLink); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveExecutable(ResolveOptions{
		OverridePath:  entryLink,
		HasOverride:   true,
		ExcludedRoots: []string{excludedHopDir},
	})
	if !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("intermediate excluded symlink hop err = %v, want ErrUnsafeExecutable", err)
	}

	// 4. Component count > 4096 must be rejected on initial path split.
	deepPath := "/" + strings.Repeat("a/", maxResolvePathComponents+2) + "hc"
	if _, _, err := resolveSafePathChain(deepPath, uint32(os.Geteuid()), nil); err == nil {
		t.Fatal("resolveSafePathChain unexpectedly accepted > 4096 path components")
	}
}
