//go:build darwin && arm64

package environment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

func TestObservePlatformUsesInjectedRuntimeValues(t *testing.T) {
	inspector := newInspector(inspectorDependencies{
		platform: func() (string, string) { return "darwin", "arm64" },
	})

	observation, err := inspector.ObservePlatform(context.Background())
	if err != nil {
		t.Fatalf("ObservePlatform() error = %v", err)
	}
	if observation.OperatingSystem() != "darwin" || observation.Architecture() != "arm64" {
		t.Fatalf("ObservePlatform() = %q/%q, want darwin/arm64", observation.OperatingSystem(), observation.Architecture())
	}
}

func TestObservationContextPreservesCancellationIdentity(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := NewInspector().ObservePlatform(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ObservePlatform() error = %v, want context.Canceled", err)
		}
	})
	t.Run("deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		_, err := NewInspector().ObservePlatform(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ObservePlatform() error = %v, want context.DeadlineExceeded", err)
		}
	})
}

func TestObserveExecutableReturnsAbsentWithoutPATHSubstitution(t *testing.T) {
	var lookups []string
	inspector := newInspector(inspectorDependencies{
		lookup: func(name string) (string, error) {
			lookups = append(lookups, name)
			return "", exec.ErrNotFound
		},
	})

	observation, err := inspector.ObserveExecutable(context.Background(), "zcode")
	if err != nil {
		t.Fatalf("ObserveExecutable() error = %v", err)
	}
	if observation.Found() {
		t.Fatal("ObserveExecutable() promoted an absent executable")
	}
	if observation.Name() != "zcode" || observation.ResolvedPath() != "" || observation.Version() != "" || observation.SHA256() != "" {
		t.Fatalf("absent observation = %#v, want no provenance for zcode", observation)
	}
	if len(lookups) != 1 || lookups[0] != "zcode" {
		t.Fatalf("lookup names = %q, want only zcode", lookups)
	}
}

func TestObserveExecutableResolvesSymlinkAndHashesExactBytes(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "kimi")
	contents := []byte("provider executable\n")
	writeExecutable(t, target, contents)
	link := filepath.Join(directory, "kimi-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("EvalSymlinks() error = %v", err)
	}

	inspector := newInspector(inspectorDependencies{
		lookup: func(name string) (string, error) {
			if name != "kimi" {
				t.Fatalf("lookup name = %q, want kimi", name)
			}
			return link, nil
		},
	})

	observation, err := inspector.ObserveExecutable(context.Background(), "kimi")
	if err != nil {
		t.Fatalf("ObserveExecutable() error = %v", err)
	}
	sum := sha256.Sum256(contents)
	if !observation.Found() || observation.ResolvedPath() != resolvedTarget || observation.SHA256() != "sha256:"+hex.EncodeToString(sum[:]) || observation.Version() != "" {
		t.Fatalf("observation = found=%t path=%q hash=%q version=%q", observation.Found(), observation.ResolvedPath(), observation.SHA256(), observation.Version())
	}
}

func TestObserveExecutableRejectsNonRegularAndNonEffectiveTargets(t *testing.T) {
	for _, test := range []struct {
		name       string
		descriptor *testExecutableDescriptor
	}{
		{
			name: "directory",
			descriptor: &testExecutableDescriptor{
				snapshots: []executableSnapshot{directorySnapshot()},
			},
		},
		{
			name: "non-effective executable",
			descriptor: &testExecutableDescriptor{
				snapshots:  []executableSnapshot{regularSnapshot(0)},
				executable: false,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := injectedExecutableInspector(t, test.descriptor)

			if _, err := inspector.ObserveExecutable(context.Background(), "agy"); err == nil {
				t.Fatal("ObserveExecutable() succeeded for rejected target")
			}
			if test.descriptor.reads != 0 {
				t.Fatal("ObserveExecutable() hashed a rejected target")
			}
		})
	}
}

func TestObserveExecutableRejectsOversizedTarget(t *testing.T) {
	descriptor := &testExecutableDescriptor{
		snapshots:  []executableSnapshot{regularSnapshot(maximumExecutableSize + 1)},
		executable: true,
	}
	inspector := injectedExecutableInspector(t, descriptor)

	if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
		t.Fatal("ObserveExecutable() accepted an oversized target")
	}
	if descriptor.reads != 0 {
		t.Fatal("ObserveExecutable() hashed an oversized target")
	}
}

func TestObserveExecutableRejectsSymlinkResolutionFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		resolved string
		err      error
	}{
		{name: "cycle", err: errors.New("symlink cycle")},
		{name: "uncanonical target", resolved: "/approved/../provider"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := newInspector(inspectorDependencies{
				lookup:        func(string) (string, error) { return "/approved/provider", nil },
				evaluateLinks: func(string) (string, error) { return test.resolved, test.err },
			})
			if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
				t.Fatal("ObserveExecutable() succeeded for unsafe resolution")
			}
		})
	}
}

func TestObserveExecutablePreservesCancellationDuringHash(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	descriptor := &testExecutableDescriptor{
		snapshots:  []executableSnapshot{regularSnapshot(3), regularSnapshot(3)},
		executable: true,
		reader: readFunc(func(buffer []byte) (int, error) {
			cancel()
			copy(buffer, "abc")
			return 3, io.EOF
		}),
	}
	inspector := injectedExecutableInspector(t, descriptor)

	_, err := inspector.ObserveExecutable(ctx, "kimi")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ObserveExecutable() error = %v, want context.Canceled", err)
	}
	if descriptor.reads != 1 {
		t.Fatalf("hash reads = %d, want one chunk before cancellation", descriptor.reads)
	}
}

func TestObserveExecutableRejectsDescriptorMutationDuringHash(t *testing.T) {
	before := regularSnapshot(3)
	after := before
	after.mtimeNsec++
	descriptor := &testExecutableDescriptor{
		snapshots:  []executableSnapshot{before, after},
		executable: true,
		reader:     bytes.NewReader([]byte("abc")),
	}
	inspector := injectedExecutableInspector(t, descriptor)

	if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
		t.Fatal("ObserveExecutable() accepted a descriptor whose mtime changed during hashing")
	}
}
func TestObserveExecutableRejectsEarlyEOF(t *testing.T) {
	descriptor := &testExecutableDescriptor{
		snapshots:  []executableSnapshot{regularSnapshot(3)},
		executable: true,
		reader:     bytes.NewReader([]byte("ab")),
	}
	inspector := injectedExecutableInspector(t, descriptor)

	if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
		t.Fatal("ObserveExecutable() accepted a truncated executable")
	}
	if descriptor.reads != 2 {
		t.Fatalf("hash reads = %d, want reads bounded by the snapshotted size", descriptor.reads)
	}
}

func TestObserveExecutableRejectsGrowingReaderWithOneOverflowRead(t *testing.T) {
	var readSizes []int
	descriptor := &testExecutableDescriptor{
		snapshots:  []executableSnapshot{regularSnapshot(3)},
		executable: true,
		reader: readFunc(func(buffer []byte) (int, error) {
			readSizes = append(readSizes, len(buffer))
			switch len(readSizes) {
			case 1:
				copy(buffer, "abc")
				return 3, nil
			case 2:
				buffer[0] = 'd'
				return 1, io.EOF
			default:
				t.Fatalf("Read() called %d times, want exactly two reads", len(readSizes))
				return 0, io.EOF
			}
		}),
	}
	inspector := injectedExecutableInspector(t, descriptor)

	if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
		t.Fatal("ObserveExecutable() accepted a growing executable")
	}
	if len(readSizes) != 2 || readSizes[0] != 3 || readSizes[1] != 1 {
		t.Fatalf("read sizes = %v, want [3 1]", readSizes)
	}
}

func TestDarwinExecutableDescriptorRejectsRenameAndSymlinkSwaps(t *testing.T) {
	for _, test := range []struct {
		name string
		swap func(t *testing.T, directory, target string)
	}{
		{
			name: "rename",
			swap: func(t *testing.T, directory, target string) {
				t.Helper()
				replacement := filepath.Join(directory, "replacement")
				writeExecutable(t, replacement, []byte("replacement"))
				if err := os.Rename(replacement, target); err != nil {
					t.Fatalf("Rename() error = %v", err)
				}
			},
		},
		{
			name: "symlink",
			swap: func(t *testing.T, directory, target string) {
				t.Helper()
				replacement := filepath.Join(directory, "replacement")
				writeExecutable(t, replacement, []byte("replacement"))
				original := filepath.Join(directory, "original")
				if err := os.Rename(target, original); err != nil {
					t.Fatalf("Rename() error = %v", err)
				}
				if err := os.Symlink(replacement, target); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(directory, "provider")
			writeExecutable(t, target, []byte("original"))

			descriptor, err := openCanonicalExecutable(target)
			if err != nil {
				t.Fatalf("openCanonicalExecutable() error = %v", err)
			}
			defer descriptor.Close()
			snapshot, err := descriptor.Stat()
			if err != nil {
				t.Fatalf("descriptor.Stat() error = %v", err)
			}

			test.swap(t, directory, target)

			if _, err := descriptor.EffectiveExecutable(snapshot); err == nil {
				t.Fatal("EffectiveExecutable() accepted a swapped pathname")
			}
		})
	}
}
func TestObserveExecutableRejectsAncestorRenameAndPathReplacement(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(directory, "ancestor")
	replacement := filepath.Join(directory, "replacement")
	moved := filepath.Join(directory, "moved")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	target := filepath.Join(ancestor, "provider")
	writeExecutable(t, target, []byte("original"))
	writeExecutable(t, filepath.Join(replacement, "provider"), []byte("original"))

	descriptor, err := openCanonicalExecutable(target)
	if err != nil {
		t.Fatalf("openCanonicalExecutable() error = %v", err)
	}
	wrapped := &synchronizedExecutableDescriptor{
		executableDescriptor: descriptor,
		afterFirstRead: func() {
			if err := os.Rename(ancestor, moved); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
			if err := os.Rename(replacement, ancestor); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
		},
	}

	opens := 0
	inspector := newInspector(inspectorDependencies{
		lookup:        func(string) (string, error) { return target, nil },
		evaluateLinks: func(path string) (string, error) { return path, nil },
		executable: func(path string) (executableDescriptor, error) {
			if path != target {
				t.Fatalf("executable path = %q, want %q", path, target)
			}
			opens++
			if opens == 1 {
				return wrapped, nil
			}
			return openCanonicalExecutable(path)
		},
	})

	if _, err := inspector.ObserveExecutable(context.Background(), "kimi"); err == nil {
		t.Fatal("ObserveExecutable() accepted an executable replaced through an ancestor rename")
	}
	if opens != 2 {
		t.Fatalf("executable opens = %d, want initial open and canonical re-open", opens)
	}
}

func TestObservePermissionRejectsInvalidPath(t *testing.T) {
	root := mustAnchoredRoot(t, "/approved")
	inspector := newInspector(inspectorDependencies{})

	if _, err := inspector.ObservePermission(context.Background(), root, ports.SafeRelativePath{}); err == nil {
		t.Fatal("ObservePermission() accepted an invalid relative path")
	}
	if _, err := ports.NewSafeRelativePath("../outside"); err == nil {
		t.Fatal("NewSafeRelativePath() accepted traversal")
	}
}

func TestObservePermissionUsesCompleteEffectiveAccessResult(t *testing.T) {
	root := mustAnchoredRoot(t, "/approved")
	relative := mustSafeRelativePath(t, "provider")
	for _, test := range []struct {
		name string
		want [3]bool
	}{
		{name: "read-only filesystem", want: [3]bool{true, false, false}},
		{name: "acl denies execute", want: [3]bool{true, true, false}},
		{name: "private executable", want: [3]bool{true, true, true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := newInspector(inspectorDependencies{
				permission: func(gotRoot ports.AnchoredRoot, gotRelative ports.SafeRelativePath) (bool, bool, bool, error) {
					if gotRoot != root || gotRelative != relative {
						t.Fatal("ObservePermission() supplied an unexpected path")
					}
					return test.want[0], test.want[1], test.want[2], nil
				},
			})

			observation, err := inspector.ObservePermission(context.Background(), root, relative)
			if err != nil {
				t.Fatalf("ObservePermission() error = %v", err)
			}
			got := [3]bool{observation.Readable(), observation.Writable(), observation.Executable()}
			if got != test.want {
				t.Fatalf("access = %v, want %v", got, test.want)
			}
		})
	}
}

func TestObservePermissionPropagatesEffectiveAccessEvaluationFailure(t *testing.T) {
	root := mustAnchoredRoot(t, "/approved")
	relative := mustSafeRelativePath(t, "provider")
	evaluationErr := errors.New("permission observation access failed")
	inspector := newInspector(inspectorDependencies{
		permission: func(ports.AnchoredRoot, ports.SafeRelativePath) (bool, bool, bool, error) {
			return false, false, false, evaluationErr
		},
	})

	_, err := inspector.ObservePermission(context.Background(), root, relative)
	if !errors.Is(err, evaluationErr) {
		t.Fatalf("ObservePermission() error = %v, want propagated evaluation failure", err)
	}
}

func TestObservePermissionPreservesCancellationAfterEvaluation(t *testing.T) {
	root := mustAnchoredRoot(t, "/approved")
	relative := mustSafeRelativePath(t, "provider")
	ctx, cancel := context.WithCancel(context.Background())
	inspector := newInspector(inspectorDependencies{
		permission: func(ports.AnchoredRoot, ports.SafeRelativePath) (bool, bool, bool, error) {
			cancel()
			return true, true, true, nil
		},
	})

	_, err := inspector.ObservePermission(ctx, root, relative)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ObservePermission() error = %v, want context.Canceled", err)
	}
}

func TestObservePermissionUsesDescriptorWalkForRealPaths(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "safe", "artifact.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := mustAnchoredRoot(t, rootPath)
	inspector := NewInspector()

	observation, err := inspector.ObservePermission(
		context.Background(),
		root,
		mustSafeRelativePath(t, "safe/artifact.json"),
	)
	if err != nil {
		t.Fatalf("ObservePermission() descriptor walk error = %v", err)
	}
	if !observation.Readable() || !observation.Writable() || observation.Executable() {
		t.Fatalf(
			"descriptor access = (%t,%t,%t), want read/write only",
			observation.Readable(),
			observation.Writable(),
			observation.Executable(),
		)
	}
	directory, err := inspector.ObservePermission(
		context.Background(),
		root,
		mustSafeRelativePath(t, "safe"),
	)
	if err != nil {
		t.Fatalf("ObservePermission() directory walk error = %v", err)
	}
	if !directory.Readable() || !directory.Writable() || !directory.Executable() {
		t.Fatalf(
			"directory access = (%t,%t,%t), want read/write/execute",
			directory.Readable(),
			directory.Writable(),
			directory.Executable(),
		)
	}

	if err := os.Symlink(filepath.Join(rootPath, "safe"), filepath.Join(rootPath, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.ObservePermission(
		context.Background(),
		root,
		mustSafeRelativePath(t, "linked/artifact.json"),
	); err == nil {
		t.Fatal("ObservePermission() followed an intermediate symlink")
	}
}
func TestRevalidatePermissionTargetRejectsIntermediateDirectoryRename(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(rootPath, "safe")
	replacement := filepath.Join(rootPath, "replacement")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	relative := mustSafeRelativePath(t, "safe/artifact.json")
	if err := os.WriteFile(filepath.Join(safe, "artifact.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "artifact.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	root := mustAnchoredRoot(t, rootPath)
	target, err := openPermissionTarget(root, relative)
	if err != nil {
		t.Fatalf("openPermissionTarget() error = %v", err)
	}
	defer target.Close()

	if err := os.Rename(safe, filepath.Join(t.TempDir(), "moved")); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Rename(replacement, safe); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}

	if err := revalidatePermissionTarget(root, relative, target.identity); err == nil {
		t.Fatal("revalidatePermissionTarget() accepted a target reached through a replaced intermediate directory")
	}
}

func TestObservePermissionRejectsIntermediateRenameBeforeReturn(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(rootPath, "safe")
	replacement := filepath.Join(rootPath, "replacement")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{safe, replacement} {
		if err := os.WriteFile(filepath.Join(directory, "artifact.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved := filepath.Join(t.TempDir(), "moved")
	permissionRevalidateHook = func() {
		permissionRevalidateHook = nil
		if err := os.Rename(safe, moved); err != nil {
			t.Fatalf("Rename safe: %v", err)
		}
		if err := os.Rename(replacement, safe); err != nil {
			t.Fatalf("Rename replacement: %v", err)
		}
	}
	t.Cleanup(func() {
		permissionRevalidateHook = nil
	})

	_, err = NewInspector().ObservePermission(
		context.Background(),
		mustAnchoredRoot(t, rootPath),
		mustSafeRelativePath(t, "safe/artifact.json"),
	)
	if err == nil {
		t.Fatal("ObservePermission() accepted an intermediate-directory replacement before return")
	}
}

func TestObservePermissionDescriptorWalkRejectsFinalSymlinks(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(rootPath, "safe", "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspector := NewInspector()
	root := mustAnchoredRoot(t, rootPath)

	t.Run("symlink to regular file", func(t *testing.T) {
		if err := os.Symlink(target, filepath.Join(rootPath, "safe", "linked.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := inspector.ObservePermission(
			context.Background(),
			root,
			mustSafeRelativePath(t, "safe/linked.json"),
		); err == nil {
			t.Fatal("ObservePermission() followed a final symlink to a regular file")
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		missingTarget := filepath.Join(t.TempDir(), "missing.json")
		if err := os.Symlink(missingTarget, filepath.Join(rootPath, "safe", "dangling.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := inspector.ObservePermission(
			context.Background(),
			root,
			mustSafeRelativePath(t, "safe/dangling.json"),
		); err == nil {
			t.Fatal("ObservePermission() accepted a dangling final symlink")
		}
	})
}

func TestEffectiveAccessAtRejectsRenamedTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "provider")
	writeExecutable(t, target, []byte("original"))
	replacement := filepath.Join(directory, "replacement")
	writeExecutable(t, replacement, []byte("replacement"))

	parentFD, err := unix.Open(directory, unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer unix.Close(parentFD)
	targetFD, err := unix.Openat(parentFD, "provider", unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Openat() error = %v", err)
	}
	defer unix.Close(targetFD)
	var stat unix.Stat_t
	if err := unix.Fstat(targetFD, &stat); err != nil {
		t.Fatalf("Fstat() error = %v", err)
	}
	expected, err := permissionNodeFromStat(stat)
	if err != nil {
		t.Fatalf("permissionNodeFromStat() error = %v", err)
	}

	if err := os.Rename(replacement, target); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if _, err := effectiveAccessAt(parentFD, "provider", expected, unix.R_OK); err == nil {
		t.Fatal("effectiveAccessAt() accepted a renamed target")
	}
}

func writeExecutable(t *testing.T, path string, contents []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		t.Fatalf("Write() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func injectedExecutableInspector(t *testing.T, descriptor executableDescriptor) *Inspector {
	t.Helper()
	return newInspector(inspectorDependencies{
		lookup:        func(string) (string, error) { return "/approved/provider", nil },
		evaluateLinks: func(path string) (string, error) { return path, nil },
		executable: func(path string) (executableDescriptor, error) {
			if path != "/approved/provider" {
				t.Fatalf("executable path = %q, want /approved/provider", path)
			}
			return descriptor, nil
		},
	})
}

type synchronizedExecutableDescriptor struct {
	executableDescriptor
	afterFirstRead func()
	once           sync.Once
}

func (descriptor *synchronizedExecutableDescriptor) Read(buffer []byte) (int, error) {
	read, err := descriptor.executableDescriptor.Read(buffer)
	if read > 0 && descriptor.afterFirstRead != nil {
		descriptor.once.Do(descriptor.afterFirstRead)
	}
	return read, err
}

type testExecutableDescriptor struct {
	reader     io.Reader
	snapshots  []executableSnapshot
	statErr    error
	executable bool
	executeErr error
	reads      int
}

func (descriptor *testExecutableDescriptor) Read(buffer []byte) (int, error) {
	descriptor.reads++
	if descriptor.reader == nil {
		return 0, io.EOF
	}
	return descriptor.reader.Read(buffer)
}

func (descriptor *testExecutableDescriptor) Close() error {
	return nil
}

func (descriptor *testExecutableDescriptor) Stat() (executableSnapshot, error) {
	if descriptor.statErr != nil {
		return executableSnapshot{}, descriptor.statErr
	}
	if len(descriptor.snapshots) == 0 {
		return executableSnapshot{}, errors.New("missing executable snapshot")
	}
	index := descriptor.reads
	if index >= len(descriptor.snapshots) {
		index = len(descriptor.snapshots) - 1
	}
	return descriptor.snapshots[index], nil
}

func (descriptor *testExecutableDescriptor) EffectiveExecutable(executableSnapshot) (bool, error) {
	return descriptor.executable, descriptor.executeErr
}

type readFunc func([]byte) (int, error)

func (read readFunc) Read(buffer []byte) (int, error) {
	return read(buffer)
}

func regularSnapshot(size int64) executableSnapshot {
	return executableSnapshot{
		device:    1,
		inode:     2,
		mode:      unix.S_IFREG | 0o700,
		size:      size,
		mtimeSec:  1,
		mtimeNsec: 2,
		ctimeSec:  3,
		ctimeNsec: 4,
	}
}

func directorySnapshot() executableSnapshot {
	snapshot := regularSnapshot(0)
	snapshot.mode = unix.S_IFDIR | 0o700
	return snapshot
}

func mustAnchoredRoot(t *testing.T, value string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(value)
	if err != nil {
		t.Fatalf("NewAnchoredRoot(%q) error = %v", value, err)
	}
	return root
}

func mustSafeRelativePath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatalf("NewSafeRelativePath(%q) error = %v", value, err)
	}
	return path
}
