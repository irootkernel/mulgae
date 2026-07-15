//go:build darwin && arm64

package lanelock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	lockerHelperEnvironment = "KAR_LANELOCK_HELPER"
	lockerHelperAction      = "KAR_LANELOCK_ACTION"
	lockerHelperRoot        = "KAR_LANELOCK_ROOT"
	lockerHelperKey         = "KAR_LANELOCK_KEY"
	lockerHelperReady       = "KAR_LANELOCK_READY"
	lockerHelperControl     = "KAR_LANELOCK_CONTROL"
	lockerHelperTimeout     = 5 * time.Second
)

func TestLockerMutualExclusion(t *testing.T) {
	locker, _ := testLocker(t)
	key := testKey(t, "shared-provider")

	first := mustAcquire(t, locker, context.Background(), key)
	defer func() {
		if first != nil {
			if err := first.Release(); err != nil {
				t.Errorf("first Release() error = %v", err)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	secondResult := make(chan acquireResult, 1)
	go func() {
		close(started)
		lease, err := locker.Acquire(ctx, key)
		secondResult <- acquireResult{lease: lease, err: err}
	}()
	<-started

	select {
	case result := <-secondResult:
		if result.lease != nil {
			_ = result.lease.Release()
		}
		t.Fatalf("second Acquire() returned before first Release(): %v", result.err)
	default:
	}

	releaseErr := first.Release()
	first = nil
	if releaseErr != nil {
		t.Fatalf("first Release() error = %v", releaseErr)
	}

	result := <-secondResult
	if result.err != nil {
		t.Fatalf("second Acquire() error = %v", result.err)
	}
	if result.lease.Key() != key {
		t.Fatalf("second lease key = %q, want %q", result.lease.Key().String(), key.String())
	}
	if err := result.lease.Release(); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}
}

func TestLockerAllowsIndependentKeys(t *testing.T) {
	locker, _ := testLocker(t)
	firstKey := testKey(t, "provider-one")
	secondKey := testKey(t, "provider-two")

	first := mustAcquire(t, locker, context.Background(), firstKey)
	defer func() {
		if err := first.Release(); err != nil {
			t.Errorf("first Release() error = %v", err)
		}
	}()
	second := mustAcquire(t, locker, context.Background(), secondKey)
	defer func() {
		if err := second.Release(); err != nil {
			t.Errorf("second Release() error = %v", err)
		}
	}()

	if first.Key() != firstKey || second.Key() != secondKey {
		t.Fatalf("leases do not retain their independent concurrency keys")
	}
}
func TestLockerSameKeyAcrossDifferentRootsDoesNotCollide(t *testing.T) {
	parent := t.TempDir()
	firstRoot := filepath.Join(parent, "first")
	secondRoot := filepath.Join(parent, "second")
	for _, root := range []string{firstRoot, secondRoot} {
		if err := os.Mkdir(root, lockDirectoryMode); err != nil {
			t.Fatal(err)
		}
	}
	key := testKey(t, "shared-provider")

	holder := startLockerHelper(t, firstRoot, key, "hold")
	holder.waitReady(t)

	locker := testLockerAt(t, secondRoot)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease := mustAcquire(t, locker, ctx, key)
	if err := lease.Release(); err != nil {
		t.Fatalf("second-root Release() error = %v", err)
	}
	holder.stop(t)
}

func TestLockerWaitStopsAtContextCancellation(t *testing.T) {
	locker, _ := testLocker(t)
	key := testKey(t, "cancelled-provider")
	first := mustAcquire(t, locker, context.Background(), key)
	defer func() {
		if err := first.Release(); err != nil {
			t.Errorf("first Release() error = %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan acquireResult, 1)
	go func() {
		lease, err := locker.Acquire(ctx, key)
		result <- acquireResult{lease: lease, err: err}
	}()
	cancel()

	acquired := <-result
	if acquired.lease != nil {
		_ = acquired.lease.Release()
		t.Fatal("Acquire() returned a lease after context cancellation")
	}
	if !errors.Is(acquired.err, context.Canceled) {
		t.Fatalf("Acquire() error = %v, want context.Canceled", acquired.err)
	}
}

func TestLockerIgnoresStaleLockMetadata(t *testing.T) {
	locker, root := testLocker(t)
	key := testKey(t, "stale-provider")
	lease := mustAcquire(t, locker, context.Background(), key)
	if err := lease.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	lockPath := filepath.Join(root, locksDirectory.String(), lockFileName(key))
	if err := os.WriteFile(lockPath, []byte("pid=99999\nacquired_at=stale\n"), lockFileMode); err != nil {
		t.Fatal(err)
	}

	lease = mustAcquire(t, locker, context.Background(), key)
	if err := lease.Release(); err != nil {
		t.Fatalf("Release() after stale metadata error = %v", err)
	}
}

func TestLockerRejectsUnsafeLockNodes(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, root, path string)
	}{
		{
			name: "symlink",
			prepare: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(target, []byte("outside"), lockFileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			prepare: func(t *testing.T, root, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(root, "hardlink-target")
				if err := os.WriteFile(target, []byte("outside"), lockFileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-regular node",
			prepare: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, lockFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe mode",
			prepare: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			locker, root := testLocker(t)
			key := testKey(t, "attacked-provider")
			lease := mustAcquire(t, locker, context.Background(), key)
			if err := lease.Release(); err != nil {
				t.Fatalf("Release() error = %v", err)
			}

			path := filepath.Join(root, locksDirectory.String(), lockFileName(key))
			test.prepare(t, root, path)
			runLockerHelper(t, root, key, "unavailable")
		})
	}
}

func TestLockerReleaseIsIdempotentAndAllowsReacquisition(t *testing.T) {
	locker, _ := testLocker(t)
	key := testKey(t, "reacquired-provider")

	first := mustAcquire(t, locker, context.Background(), key)
	if err := first.Release(); err != nil {
		t.Fatalf("first Release() error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release() error = %v, want nil", err)
	}

	second := mustAcquire(t, locker, context.Background(), key)
	if err := second.Release(); err != nil {
		t.Fatalf("reacquired Release() error = %v", err)
	}
}

func TestLeaseRetainsExactValidatedKeyIdentity(t *testing.T) {
	locker, _ := testLocker(t)
	key := testKey(t, "Provider_A")
	other := testKey(t, "provider-b")

	lease := mustAcquire(t, locker, context.Background(), key)
	if lease.Key() != key {
		t.Fatalf("lease Key() = %q, want %q", lease.Key().String(), key.String())
	}
	if lease.Key() == other {
		t.Fatalf("lease Key() = %q, unexpectedly equals %q", lease.Key().String(), other.String())
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if lease.Key() != key {
		t.Fatalf("released lease Key() = %q, want %q", lease.Key().String(), key.String())
	}
}

func TestLockerCrossProcessFlockContentionAndRecovery(t *testing.T) {
	key := testKey(t, "shared-provider")

	t.Run("actual guard flock contention cancels deterministically", func(t *testing.T) {
		root := t.TempDir()
		holder := startLockerHelper(t, root, key, "hold")
		holder.waitReady(t)
		contender := startLockerHelper(t, root, key, "cancel")
		contender.waitReady(t)
		contender.stop(t)
		holder.stop(t)
		runLockerHelper(t, root, key, "acquire")
	})

	t.Run("acquire after explicit release", func(t *testing.T) {
		root := t.TempDir()
		holder := startLockerHelper(t, root, key, "release")
		holder.waitReady(t)
		holder.stop(t)
		runLockerHelper(t, root, key, "acquire")
	})

	t.Run("acquire after holder exits without release", func(t *testing.T) {
		root := t.TempDir()
		holder := startLockerHelper(t, root, key, "hold")
		holder.waitReady(t)
		holder.stop(t)
		runLockerHelper(t, root, key, "acquire")
	})
}

func TestLockerCrossProcessGuardPreventsAuthorityReplacement(t *testing.T) {
	key := testKey(t, "replaced-provider")

	for _, action := range []string{
		"replace-internal-guard-and-lock",
		"replace-internal-guard-and-locks-directory",
		"recreate-authority",
	} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			holder := startLockerHelper(t, root, key, "hold")
			holder.waitReady(t)
			assertGuardImmutable(t, root, key, true)

			runLockerHelper(t, root, key, action)
			assertGuardImmutable(t, root, key, true)

			contender := startLockerHelper(t, root, key, "cancel")
			contender.waitReady(t)
			contender.stop(t)
			holder.stop(t)
			runLockerHelper(t, root, key, "acquire")
		})
	}
}

func TestLockerRecoversCrashLeftImmutableGuard(t *testing.T) {
	root := t.TempDir()
	key := testKey(t, "crash-left-guard")
	crashed := startLockerHelper(t, root, key, "crash")
	crashed.waitReady(t)
	if err := crashed.command.Wait(); err != nil {
		t.Fatalf("crashed holder failed: %v", err)
	}
	assertGuardImmutable(t, root, key, true)

	runLockerHelper(t, root, key, "acquire")
	assertGuardImmutable(t, root, key, false)
}

func TestLockerReleaseHandoffRetainsImmutableGuard(t *testing.T) {
	root := t.TempDir()
	key := testKey(t, "release-handoff")
	holder := startLockerHelper(t, root, key, "release-window")
	holder.waitReady(t)

	holder.beginRelease(t)
	holder.waitHandoff(t)

	contender := startLockerHelper(t, root, key, "guard-handoff")
	contender.waitReady(t)

	holder.resumeRelease(t)
	holder.wait(t)
	contender.stop(t)
	assertGuardImmutable(t, root, key, false)
}

func TestLockerHelperProcess(t *testing.T) {
	if os.Getenv(lockerHelperEnvironment) != "1" {
		return
	}

	rootPath := os.Getenv(lockerHelperRoot)
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey(os.Getenv(lockerHelperKey))
	if err != nil {
		t.Fatal(err)
	}
	locker, err := New(root, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}

	switch os.Getenv(lockerHelperAction) {
	case "hold":
		lease := mustAcquire(t, locker, context.Background(), key)
		writeLockerHelperReady(t)
		waitForLockerHelperControl(t)
		_ = lease
	case "release":
		lease := mustAcquire(t, locker, context.Background(), key)
		writeLockerHelperReady(t)
		waitForLockerHelperControl(t)
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	case "cancel":
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		previousHook := retryableGuardContentionHook
		retryableGuardContentionHook = func() {
			retryableGuardContentionHook = nil
			writeLockerHelperReady(t)
		}
		defer func() {
			retryableGuardContentionHook = previousHook
		}()

		result := make(chan acquireResult, 1)
		go func() {
			lease, err := locker.Acquire(ctx, key)
			result <- acquireResult{lease: lease, err: err}
		}()
		waitForLockerHelperControl(t)
		cancel()
		acquired := <-result
		if acquired.lease != nil {
			_ = acquired.lease.Release()
			t.Fatal("Acquire() returned a lease while another process held the key")
		}
		if !errors.Is(acquired.err, context.Canceled) {
			t.Fatalf("Acquire() error = %v, want context.Canceled", acquired.err)
		}
	case "acquire":
		lease := mustAcquire(t, locker, context.Background(), key)
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	case "crash":
		lease := mustAcquire(t, locker, context.Background(), key)
		writeLockerHelperReady(t)
		_ = lease
		os.Exit(0)
	case "release-window":
		lease := mustAcquire(t, locker, context.Background(), key)
		writeLockerHelperReady(t)
		waitForLockerHelperControl(t)
		releaseAfterGuardUnlockHook = func() {
			writeLockerHelperHandoff(t)
			waitForLockerHelperResume(t)
		}
		if err := lease.Release(); err != nil {
			t.Fatal(err)
		}
	case "guard-handoff":
		authority, err := openLockAuthority(root, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := authority.openLockNamespace(); err != nil {
			t.Fatal(errors.Join(err, authority.close()))
		}
		fd, _, err := openPinnedLockFile(authority, key)
		if err != nil {
			t.Fatal(errors.Join(err, authority.close()))
		}
		if err := unix.Flock(authority.guardFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		writeLockerHelperReady(t)
		waitForLockerHelperControl(t)

		flags, err := guardFlagsForFD(authority.guardFD, authority.guardIdentity)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.UF_IMMUTABLE == 0 {
			t.Fatal("release cleared the guard immutable flag while a contender held the guard")
		}
		authority.guardImmutable = true
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if err := releaseLease(fd, authority); err != nil {
			t.Fatal(err)
		}
	case "replace-internal-guard-and-lock":
		if err := replaceInternalGuardAndLock(rootPath, key); err != nil {
			t.Fatal(err)
		}
	case "replace-internal-guard-and-locks-directory":
		if err := replaceInternalGuardAndLocksDirectory(rootPath, key); err != nil {
			t.Fatal(err)
		}
	case "recreate-authority":
		if err := recreateAuthority(rootPath); err != nil {
			t.Fatal(err)
		}
	case "unavailable":
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		lease, err := locker.Acquire(ctx, key)
		if lease != nil {
			_ = lease.Release()
			t.Fatal("Acquire() returned a lease in a replacement namespace")
		}
		assertSecurityFailure(t, err)
	default:
		t.Fatalf("unknown locker helper action %q", os.Getenv(lockerHelperAction))
	}
}

type lockerHelper struct {
	command *exec.Cmd
	ready   string
	control string
}

func startLockerHelper(t *testing.T, root string, key ports.ConcurrencyKey, action string) *lockerHelper {
	t.Helper()
	registerExternalGuardCleanup(t, root, key)
	state := t.TempDir()
	helper := &lockerHelper{
		ready:   filepath.Join(state, "ready"),
		control: filepath.Join(state, "control"),
	}
	helper.command = exec.Command(os.Args[0], "-test.run=^TestLockerHelperProcess$", "--")
	helper.command.Env = append(os.Environ(),
		lockerHelperEnvironment+"=1",
		lockerHelperAction+"="+action,
		lockerHelperRoot+"="+root,
		lockerHelperKey+"="+key.String(),
		lockerHelperReady+"="+helper.ready,
		lockerHelperControl+"="+helper.control,
	)
	helper.command.Stderr = os.Stderr
	if err := helper.command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if helper.command.ProcessState == nil {
			_ = helper.command.Process.Kill()
			_ = helper.command.Wait()
		}
	})
	return helper
}

func runLockerHelper(t *testing.T, root string, key ports.ConcurrencyKey, action string) {
	t.Helper()
	helper := startLockerHelper(t, root, key, action)
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("helper %q failed: %v", action, err)
	}
}

func (helper *lockerHelper) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(lockerHelperTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(helper.ready); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("holder did not report acquisition readiness; process state=%v", helper.command.ProcessState)
}

func (helper *lockerHelper) stop(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(helper.control, nil, lockFileMode); err != nil {
		t.Fatal(err)
	}
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("holder helper failed: %v", err)
	}
}
func (helper *lockerHelper) beginRelease(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(helper.control, nil, lockFileMode); err != nil {
		t.Fatal(err)
	}
}

func (helper *lockerHelper) waitHandoff(t *testing.T) {
	t.Helper()
	handoff := helper.control + ".handoff"
	deadline := time.Now().Add(lockerHelperTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(handoff); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("holder did not release the namespace guard; process state=%v", helper.command.ProcessState)
}

func (helper *lockerHelper) resumeRelease(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(helper.control+".resume", nil, lockFileMode); err != nil {
		t.Fatal(err)
	}
}

func (helper *lockerHelper) wait(t *testing.T) {
	t.Helper()
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("holder helper failed: %v", err)
	}
}

func writeLockerHelperReady(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(os.Getenv(lockerHelperReady), []byte("held"), lockFileMode); err != nil {
		t.Fatal(err)
	}
}

func waitForLockerHelperControl(t *testing.T) {
	t.Helper()
	control := os.Getenv(lockerHelperControl)
	for {
		if _, err := os.Stat(control); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func writeLockerHelperHandoff(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(os.Getenv(lockerHelperControl)+".handoff", []byte("guard-unlocked"), lockFileMode); err != nil {
		t.Fatal(err)
	}
}

func waitForLockerHelperResume(t *testing.T) {
	t.Helper()
	resume := os.Getenv(lockerHelperControl) + ".resume"
	for {
		if _, err := os.Stat(resume); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func replaceInternalGuardAndLock(root string, key ports.ConcurrencyKey) error {
	guard := filepath.Join(root, lockGuardPrefix+key.String()+lockGuardSuffix)
	if err := os.WriteFile(guard, []byte("internal guard"), lockFileMode); err != nil {
		return err
	}
	if err := replaceFile(guard); err != nil {
		return err
	}
	return replaceFile(filepath.Join(root, locksDirectory.String(), lockFileName(key)))
}

func replaceInternalGuardAndLocksDirectory(root string, key ports.ConcurrencyKey) error {
	guard := filepath.Join(root, lockGuardPrefix+key.String()+lockGuardSuffix)
	if err := os.WriteFile(guard, []byte("internal guard"), lockFileMode); err != nil {
		return err
	}
	if err := replaceFile(guard); err != nil {
		return err
	}
	return replaceDirectory(filepath.Join(root, locksDirectory.String()))
}

func recreateAuthority(root string) error {
	if err := os.Rename(root, root+".replaced"); err != nil {
		return err
	}
	if err := os.Mkdir(root, lockDirectoryMode); err != nil {
		return err
	}
	return os.Mkdir(filepath.Join(root, locksDirectory.String()), lockDirectoryMode)
}

func replaceFile(path string) error {
	if err := os.Rename(path, path+".replaced"); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("replacement"), lockFileMode)
}

func replaceDirectory(path string) error {
	if err := os.Rename(path, path+".replaced"); err != nil {
		return err
	}
	return os.Mkdir(path, lockDirectoryMode)
}

func externalGuardPath(root string, key ports.ConcurrencyKey) string {
	anchoredRoot, err := ports.NewAnchoredRoot(root)
	if err != nil {
		panic(err)
	}
	return filepath.Join(filepath.Dir(root), externalGuardName(anchoredRoot, key))
}

func assertGuardImmutable(t *testing.T, root string, key ports.ConcurrencyKey, want bool) {
	t.Helper()
	fd, err := unix.Open(
		externalGuardPath(root, key),
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = unix.Close(fd)
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	got := stat.Flags&unix.UF_IMMUTABLE != 0
	if got != want {
		t.Fatalf("namespace guard immutable = %t, want %t", got, want)
	}
}
func registerExternalGuardCleanup(t *testing.T, root string, key ports.ConcurrencyKey) {
	t.Helper()
	path := externalGuardPath(root, key)
	t.Cleanup(func() {
		clearImmutableGuardFlag(t, path)
	})
}

func clearExternalGuardFlags(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Errorf("ReadDir(%q) for external guard cleanup: %v", parent, err)
		return
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), lockGuardPrefix) && strings.HasSuffix(entry.Name(), lockGuardSuffix) {
			clearImmutableGuardFlag(t, filepath.Join(parent, entry.Name()))
		}
	}
}

func clearImmutableGuardFlag(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return
	}
	if err != nil {
		t.Errorf("open external guard %q for cleanup: %v", path, err)
		return
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close external guard %q after cleanup: %v", path, err)
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Errorf("stat external guard %q for cleanup: %v", path, err)
		return
	}
	if stat.Flags&unix.UF_IMMUTABLE == 0 {
		return
	}
	if err := unix.Fchflags(fd, int(stat.Flags&^unix.UF_IMMUTABLE)); err != nil {
		t.Errorf("clear immutable external guard %q: %v", path, err)
	}
}

type acquireResult struct {
	lease ports.LaneLease
	err   error
}

func testLocker(t *testing.T) (*Locker, string) {
	t.Helper()
	rootPath := t.TempDir()
	return testLockerAt(t, rootPath), rootPath
}

func testLockerAt(t *testing.T, rootPath string) *Locker {
	t.Helper()
	t.Cleanup(func() {
		clearExternalGuardFlags(t, filepath.Dir(rootPath))
	})
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := New(root, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	return locker
}

func testKey(t *testing.T, value string) ports.ConcurrencyKey {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustAcquire(t *testing.T, locker *Locker, ctx context.Context, key ports.ConcurrencyKey) ports.LaneLease {
	t.Helper()
	lease, err := locker.Acquire(ctx, key)
	if err != nil {
		t.Fatalf("Acquire(%q) error = %v", key.String(), err)
	}
	return lease
}

func assertSecurityFailure(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("Acquire() error = %v, unexpectedly fallback-eligible", err)
	}
	var acquireErr *AcquireError
	if !errors.As(err, &acquireErr) {
		t.Fatalf("Acquire() error = %v, want *AcquireError", err)
	}
	if got := acquireErr.LaneAcquisitionFailureClass(); got != ports.LaneAcquisitionSecurity {
		t.Fatalf("Acquire() class = %q, want security", got)
	}
}
