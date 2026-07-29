//go:build darwin && arm64

package lanelock

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	lockDirectoryMode  = 0o700
	lockFileMode       = 0o600
	flockRetryInterval = 10 * time.Millisecond
	lockGuardPrefix    = ".mulgae-lane-"
	lockGuardSuffix    = ".guard"
)

var (
	retryableGuardContentionHook func()
	releaseAfterGuardUnlockHook  func()
)

var _ ports.LaneLocker = (*Locker)(nil)

// Acquire obtains an exclusive operating-system lock for key. The lock file is
// only a stable flock target; its contents are deliberately never read or used
// to decide whether the lane is available.
func (locker *Locker) Acquire(ctx context.Context, key ports.ConcurrencyKey) (ports.LaneLease, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if locker == nil || !locker.root.Valid() || isNilInterface(locker.writer) {
		return nil, acquisitionError(ports.LaneAcquisitionInternal, "initialize", errors.New("invalid locker"))
	}
	if !key.Valid() {
		return nil, ErrInvalidKey
	}

	for {
		authority, err := openLockAuthority(locker.root, key)
		if err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "pin lock namespace", err)
		}
		if err := authority.validateExternal(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, closeAttempt(-1, authority)))
		}

		// This guard pins only this root and key's namespace. The locks/{key}.lock
		// flock remains the execution authority and permits different keys to run
		// concurrently.
		guardErr := unix.Flock(authority.guardFD, unix.LOCK_EX|unix.LOCK_NB)
		if guardErr != nil {
			if !retryableFlockError(guardErr) {
				return nil, acquisitionError(ports.LaneAcquisitionInternal, "acquire namespace guard", errors.Join(guardErr, closeAttempt(-1, authority)))
			}
			if (errors.Is(guardErr, unix.EWOULDBLOCK) || errors.Is(guardErr, unix.EAGAIN)) && retryableGuardContentionHook != nil {
				retryableGuardContentionHook()
			}
			if closeErr := closeAttempt(-1, authority); closeErr != nil {
				return nil, acquisitionError(ports.LaneAcquisitionInternal, "release namespace guard attempt", errors.Join(guardErr, closeErr))
			}
			if err := waitForFlockRetry(ctx); err != nil {
				return nil, err
			}
			continue
		}

		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, closeAttempt(-1, authority))
		}
		if err := authority.validateExternal(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, closeAttempt(-1, authority)))
		}
		if err := authority.enableImmutableGuard(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "make namespace guard immutable", errors.Join(err, closeAttempt(-1, authority)))
		}
		if err := authority.validateExternal(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, abandonUncommittedAuthority(-1, authority)))
		}
		if err := locker.writer.EnsurePrivateDir(locker.root, locksDirectory); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "ensure private lock directory", errors.Join(err, abandonUncommittedAuthority(-1, authority)))
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, abandonUncommittedAuthority(-1, authority))
		}
		if err := authority.openLockNamespace(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "open lock namespace", errors.Join(err, abandonUncommittedAuthority(-1, authority)))
		}
		if err := authority.validate(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, abandonUncommittedAuthority(-1, authority)))
		}

		fd, lockIdentity, err := openPinnedLockFile(authority, key)
		if err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "open lock file", errors.Join(err, abandonUncommittedAuthority(fd, authority)))
		}
		if err := authority.validate(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, abandonUncommittedAuthority(fd, authority)))
		}
		if err := validateFileAt(authority.locksFD, lockFileName(key), lockIdentity); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock file", errors.Join(err, abandonUncommittedAuthority(fd, authority)))
		}

		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err != nil {
			if !retryableFlockError(err) {
				return nil, acquisitionError(ports.LaneAcquisitionInternal, "acquire", errors.Join(err, abandonUncommittedAuthority(fd, authority)))
			}
			// Another lease may still own the key after releasing its external
			// flock. Keep this immutable guard set until that holder can finish
			// handoff, then retry the current root authority.
			if closeErr := closeAttempt(fd, authority); closeErr != nil {
				return nil, acquisitionError(ports.LaneAcquisitionInternal, "release lock attempt", errors.Join(err, closeErr))
			}
			if err := waitForFlockRetry(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, errors.Join(ctxErr, releaseLease(fd, authority))
		}
		if err := authority.validate(); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock namespace", errors.Join(err, releaseLease(fd, authority)))
		}
		if err := validateFileAt(authority.locksFD, lockFileName(key), lockIdentity); err != nil {
			return nil, acquisitionError(ports.LaneAcquisitionSecurity, "validate lock file", errors.Join(err, releaseLease(fd, authority)))
		}

		return &lease{key: key, fd: fd, authority: authority}, nil
	}
}

type nodeIdentity struct {
	device uint64
	inode  uint64
	owner  uint32
	mode   uint32
}

func identityForFD(fd int, operation string) (nodeIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nodeIdentity{}, fmt.Errorf("stat %s: %w", operation, err)
	}
	return nodeIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		owner:  stat.Uid,
		mode:   uint32(stat.Mode),
	}, nil
}

func sameIdentity(expected, actual nodeIdentity) bool {
	return expected == actual
}

// openLockAuthority establishes the parent-controlled namespace shared by
// cooperating Mulgae processes for one root and key. It is not privilege isolation
// from an actively malicious same-UID process. The root's parent is the explicit
// trust boundary: it must remain current-user owned, non-group/world-writable,
// and path-stable for a lease.
func openLockAuthority(root ports.AnchoredRoot, key ports.ConcurrencyKey) (*lockAuthority, error) {
	parentPath, rootName, err := canonicalRootParent(root)
	if err != nil {
		return nil, err
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open anchored root parent: %w", err)
	}
	parentIdentity, err := verifiedPinnedParentIdentity(parentFD)
	if err != nil {
		return nil, errors.Join(err, unix.Close(parentFD))
	}

	rootFD, err := unix.Openat(parentFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open anchored root entry: %w", err), unix.Close(parentFD))
	}
	rootIdentity, err := verifiedAnchoredDirectoryIdentity(rootFD)
	if err != nil {
		return nil, errors.Join(err, unix.Close(rootFD), unix.Close(parentFD))
	}

	guardName := externalGuardName(root, key)
	guardFD, guardIdentity, err := openPrivateLockGuard(parentFD, guardName)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open namespace guard: %w", err), unix.Close(rootFD), unix.Close(parentFD))
	}

	authority := &lockAuthority{
		parentPath:     parentPath,
		parentFD:       parentFD,
		parentIdentity: parentIdentity,
		rootName:       rootName,
		rootFD:         rootFD,
		rootIdentity:   rootIdentity,
		locksFD:        -1,
		guardFD:        guardFD,
		guardIdentity:  guardIdentity,
		guardName:      guardName,
	}
	if err := authority.validateExternal(); err != nil {
		return nil, errors.Join(err, authority.close())
	}
	return authority, nil
}

type lockAuthority struct {
	parentPath     string
	parentFD       int
	parentIdentity nodeIdentity
	rootName       string
	rootFD         int
	rootIdentity   nodeIdentity
	locksFD        int
	locksIdentity  nodeIdentity
	guardFD        int
	guardIdentity  nodeIdentity
	guardImmutable bool
	guardName      string
}

func (authority *lockAuthority) openLockNamespace() error {
	if err := authority.validateExternal(); err != nil {
		return err
	}
	if authority.locksFD >= 0 {
		return errors.New("lock namespace is already open")
	}
	locksFD, err := unix.Openat(authority.rootFD, locksDirectory.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open lock directory: %w", err)
	}
	locksIdentity, err := verifiedLockDirectoryIdentity(locksFD)
	if err != nil {
		return errors.Join(err, unix.Close(locksFD))
	}
	authority.locksFD = locksFD
	authority.locksIdentity = locksIdentity
	if err := authority.validate(); err != nil {
		return errors.Join(err, authority.closeLocks())
	}
	return nil
}

func (authority *lockAuthority) validate() error {
	if err := authority.validateExternal(); err != nil {
		return err
	}
	if authority.locksFD < 0 {
		return errors.New("invalid pinned lock authority")
	}
	if actual, err := verifiedLockDirectoryIdentity(authority.locksFD); err != nil {
		return err
	} else if !sameIdentity(authority.locksIdentity, actual) {
		return errors.New("pinned lock directory changed")
	}
	if err := validateDirectoryAt(authority.rootFD, locksDirectory.String(), authority.locksIdentity); err != nil {
		return err
	}
	return nil
}

func (authority *lockAuthority) validateExternal() error {
	if authority == nil || authority.parentFD < 0 || authority.rootFD < 0 || authority.guardFD < 0 {
		return errors.New("invalid pinned lock authority")
	}
	if actual, err := verifiedPinnedParentIdentity(authority.parentFD); err != nil {
		return err
	} else if !sameIdentity(authority.parentIdentity, actual) {
		return errors.New("pinned anchored root parent changed")
	}
	if actual, err := verifiedAnchoredDirectoryIdentity(authority.rootFD); err != nil {
		return err
	} else if !sameIdentity(authority.rootIdentity, actual) {
		return errors.New("pinned anchored root changed")
	}
	if err := validateParentPath(authority.parentPath, authority.parentIdentity); err != nil {
		return err
	}
	if err := validateRootEntry(authority.parentFD, authority.rootName, authority.rootIdentity); err != nil {
		return err
	}
	if err := validateFileAt(authority.parentFD, authority.guardName, authority.guardIdentity); err != nil {
		return err
	}
	if !authority.guardImmutable {
		return nil
	}
	flags, err := guardFlagsForFD(authority.guardFD, authority.guardIdentity)
	if err != nil {
		return err
	}
	if flags&unix.UF_IMMUTABLE == 0 {
		return errors.New("namespace guard immutable flag is not set")
	}
	return nil
}

func (authority *lockAuthority) enableImmutableGuard() error {
	flags, err := guardFlagsForFD(authority.guardFD, authority.guardIdentity)
	if err != nil {
		return err
	}
	if flags&unix.UF_IMMUTABLE == 0 {
		if err := unix.Fchflags(authority.guardFD, int(flags|unix.UF_IMMUTABLE)); err != nil {
			return fmt.Errorf("set namespace guard immutable: %w", err)
		}
	}
	flags, err = guardFlagsForFD(authority.guardFD, authority.guardIdentity)
	if err != nil {
		return err
	}
	if flags&unix.UF_IMMUTABLE == 0 {
		return errors.New("namespace guard immutable flag is not set")
	}
	authority.guardImmutable = true
	return nil
}

func (authority *lockAuthority) clearImmutableGuard() error {
	flags, err := guardFlagsForFD(authority.guardFD, authority.guardIdentity)
	if err != nil {
		return err
	}
	if flags&unix.UF_IMMUTABLE == 0 {
		return errors.New("namespace guard immutable flag is not set")
	}
	if err := unix.Fchflags(authority.guardFD, int(flags&^unix.UF_IMMUTABLE)); err != nil {
		return fmt.Errorf("clear namespace guard immutable: %w", err)
	}
	flags, err = guardFlagsForFD(authority.guardFD, authority.guardIdentity)
	if err != nil {
		return err
	}
	if flags&unix.UF_IMMUTABLE != 0 {
		return errors.New("namespace guard immutable flag remains set")
	}
	authority.guardImmutable = false
	return nil
}

func guardFlagsForFD(fd int, expected nodeIdentity) (uint32, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, fmt.Errorf("stat namespace guard: %w", err)
	}
	actual, err := verifiedLockFileIdentityFromStat(&stat)
	if err != nil {
		return 0, err
	}
	if !sameIdentity(expected, actual) {
		return 0, errors.New("namespace guard descriptor changed")
	}
	return stat.Flags, nil
}

func canonicalRootParent(root ports.AnchoredRoot) (string, string, error) {
	parentPath := filepath.Dir(root.String())
	if parentPath == root.String() {
		return "", "", errors.New("anchored root has no external parent namespace")
	}
	rootName := filepath.Base(root.String())
	if rootName == "." || rootName == string(filepath.Separator) {
		return "", "", errors.New("anchored root has an invalid parent entry name")
	}
	return parentPath, rootName, nil
}

func validateParentPath(parentPath string, expected nodeIdentity) error {
	fd, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("reopen anchored root parent: %w", err)
	}
	actual, identityErr := verifiedPinnedParentIdentity(fd)
	closeErr := unix.Close(fd)
	if identityErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close reopened anchored root parent: %w", closeErr)
	}
	if !sameIdentity(expected, actual) {
		return errors.New("anchored root parent namespace changed")
	}
	return nil
}

func validateRootEntry(parentFD int, rootName string, expected nodeIdentity) error {
	fd, err := unix.Openat(parentFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("reopen anchored root entry: %w", err)
	}
	actual, identityErr := verifiedAnchoredDirectoryIdentity(fd)
	closeErr := unix.Close(fd)
	if identityErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close reopened anchored root entry: %w", closeErr)
	}
	if !sameIdentity(expected, actual) {
		return errors.New("anchored root namespace changed")
	}
	return nil
}

func validateDirectoryAt(directoryFD int, name string, expected nodeIdentity) error {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("reopen lock directory: %w", err)
	}
	actual, identityErr := verifiedLockDirectoryIdentity(fd)
	closeErr := unix.Close(fd)
	if identityErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close reopened lock directory: %w", closeErr)
	}
	if !sameIdentity(expected, actual) {
		return errors.New("lock directory namespace changed")
	}
	return nil
}

func openPinnedLockFile(authority *lockAuthority, key ports.ConcurrencyKey) (int, nodeIdentity, error) {
	if authority == nil || authority.locksFD < 0 {
		return -1, nodeIdentity{}, errors.New("invalid pinned lock authority")
	}
	return openPrivateLockFile(authority.locksFD, lockFileName(key))
}

func openPrivateLockFile(directoryFD int, name string) (int, nodeIdentity, error) {
	fd, err := unix.Openat(
		directoryFD,
		name,
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		lockFileMode,
	)
	if err != nil {
		return -1, nodeIdentity{}, err
	}
	identity, verifyErr := verifiedLockFileIdentity(fd)
	if verifyErr != nil {
		return -1, nodeIdentity{}, errors.Join(verifyErr, unix.Close(fd))
	}
	return fd, identity, nil
}

func openPrivateLockGuard(directoryFD int, name string) (int, nodeIdentity, error) {
	for attempt := 0; attempt < 2; attempt++ {
		fd, err := unix.Openat(
			directoryFD,
			name,
			unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err == nil {
			identity, verifyErr := verifiedLockFileIdentity(fd)
			if verifyErr != nil {
				return -1, nodeIdentity{}, errors.Join(verifyErr, unix.Close(fd))
			}
			return fd, identity, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, nodeIdentity{}, err
		}

		fd, err = unix.Openat(
			directoryFD,
			name,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			lockFileMode,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return -1, nodeIdentity{}, err
		}
		identity, verifyErr := verifiedLockFileIdentity(fd)
		if verifyErr != nil {
			return -1, nodeIdentity{}, errors.Join(verifyErr, unix.Close(fd))
		}
		return fd, identity, nil
	}
	return -1, nodeIdentity{}, errors.New("namespace guard changed while opening")
}

func lockFileName(key ports.ConcurrencyKey) string {
	return key.String() + ".lock"
}

// externalGuardName is parent-safe and stable across processes. The NUL
// separator prevents root/key concatenation aliases before lower-hex encoding.
func externalGuardName(root ports.AnchoredRoot, key ports.ConcurrencyKey) string {
	sum := sha256.Sum256([]byte(root.String() + "\x00" + key.String()))
	return lockGuardPrefix + fmt.Sprintf("%x", sum) + lockGuardSuffix
}

func validateFileAt(directoryFD int, name string, expected nodeIdentity) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat lock file: %w", err)
	}
	actual, err := verifiedLockFileIdentityFromStat(&stat)
	if err != nil {
		return err
	}
	if !sameIdentity(expected, actual) {
		return errors.New("lock file namespace changed")
	}
	return nil
}

func (authority *lockAuthority) close() error {
	if authority == nil {
		return nil
	}
	var closeErrors []error
	if authority.guardFD >= 0 {
		closeErrors = append(closeErrors, unix.Close(authority.guardFD))
		authority.guardFD = -1
	}
	closeErrors = append(closeErrors, authority.closeLocks())
	if authority.rootFD >= 0 {
		closeErrors = append(closeErrors, unix.Close(authority.rootFD))
		authority.rootFD = -1
	}
	if authority.parentFD >= 0 {
		closeErrors = append(closeErrors, unix.Close(authority.parentFD))
		authority.parentFD = -1
	}
	return errors.Join(closeErrors...)
}

func (authority *lockAuthority) closeLocks() error {
	if authority == nil || authority.locksFD < 0 {
		return nil
	}
	err := unix.Close(authority.locksFD)
	authority.locksFD = -1
	return err
}

func verifiedAnchoredDirectoryIdentity(fd int) (nodeIdentity, error) {
	identity, err := identityForFD(fd, "anchored root")
	if err != nil {
		return nodeIdentity{}, err
	}
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return nodeIdentity{}, errors.New("anchored root is not a directory")
	}
	if identity.owner != uint32(os.Geteuid()) {
		return nodeIdentity{}, errors.New("anchored root is not owned by the current user")
	}
	if identity.mode&0o022 != 0 {
		return nodeIdentity{}, errors.New("anchored root is writable by another principal")
	}
	return identity, nil
}

func verifiedPinnedParentIdentity(fd int) (nodeIdentity, error) {
	identity, err := identityForFD(fd, "anchored root parent")
	if err != nil {
		return nodeIdentity{}, err
	}
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return nodeIdentity{}, errors.New("anchored root parent is not a directory")
	}
	if identity.owner != uint32(os.Geteuid()) {
		return nodeIdentity{}, errors.New("anchored root parent is not owned by the current user")
	}
	if identity.mode&0o022 != 0 {
		return nodeIdentity{}, errors.New("anchored root parent is writable by another principal")
	}
	return identity, nil
}

func verifiedLockDirectoryIdentity(fd int) (nodeIdentity, error) {
	identity, err := identityForFD(fd, "lock directory")
	if err != nil {
		return nodeIdentity{}, err
	}
	if identity.mode&unix.S_IFMT != unix.S_IFDIR {
		return nodeIdentity{}, errors.New("lock directory is not a directory")
	}
	if identity.owner != uint32(os.Geteuid()) {
		return nodeIdentity{}, errors.New("lock directory is not owned by the current user")
	}
	if identity.mode&0o7777 != lockDirectoryMode {
		return nodeIdentity{}, errors.New("lock directory mode is not 0700")
	}
	return identity, nil
}

func verifiedLockFileIdentity(fd int) (nodeIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nodeIdentity{}, fmt.Errorf("stat lock file: %w", err)
	}
	return verifiedLockFileIdentityFromStat(&stat)
}

func verifiedLockFileIdentityFromStat(stat *unix.Stat_t) (nodeIdentity, error) {
	if stat == nil {
		return nodeIdentity{}, errors.New("missing lock file stat")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nodeIdentity{}, errors.New("lock node is not a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return nodeIdentity{}, errors.New("lock file is not owned by the current user")
	}
	if stat.Mode&0o7777 != lockFileMode {
		return nodeIdentity{}, errors.New("lock file mode is not 0600")
	}
	if stat.Nlink != 1 {
		return nodeIdentity{}, errors.New("lock file has multiple links")
	}
	return nodeIdentity{
		device: uint64(stat.Dev),
		inode:  uint64(stat.Ino),
		owner:  stat.Uid,
		mode:   uint32(stat.Mode),
	}, nil
}

func retryableFlockError(err error) bool {
	return errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR)
}

func waitForFlockRetry(ctx context.Context) error {
	timer := time.NewTimer(flockRetryInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type lease struct {
	key       ports.ConcurrencyKey
	authority *lockAuthority

	mu         sync.Mutex
	fd         int
	released   bool
	releaseErr error
}

var _ ports.LaneLease = (*lease)(nil)

func (lease *lease) Key() ports.ConcurrencyKey {
	if lease == nil {
		return ports.ConcurrencyKey{}
	}
	return lease.key
}

// Release relinquishes the exclusive flock and closes every descriptor that
// authorizes the lease. Repeated releases preserve the first release result.
func (lease *lease) Release() error {
	if lease == nil {
		return errors.New("lane lock: nil lease")
	}

	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return lease.releaseErr
	}
	lease.released = true
	lease.releaseErr = releaseLease(lease.fd, lease.authority)
	lease.fd = -1
	lease.authority = nil
	return lease.releaseErr
}

func closeAttempt(fd int, authority *lockAuthority) error {
	var closeErrors []error
	if fd >= 0 {
		closeErrors = append(closeErrors, unix.Close(fd))
	}
	if authority != nil {
		closeErrors = append(closeErrors, authority.close())
	}
	return errors.Join(closeErrors...)
}
func abandonUncommittedAuthority(fd int, authority *lockAuthority) error {
	var releaseErrors []error
	if fd >= 0 {
		releaseErrors = append(releaseErrors, unix.Close(fd))
	}
	if authority != nil {
		if authority.guardImmutable && authority.guardFD >= 0 {
			releaseErrors = append(releaseErrors, authority.clearImmutableGuard())
		}
		releaseErrors = append(releaseErrors, authority.close())
	}
	return errors.Join(releaseErrors...)
}

func releaseLease(fd int, authority *lockAuthority) error {
	var releaseErrors []error

	keyReleased := true
	if fd >= 0 {
		keyUnlockErr := unix.Flock(fd, unix.LOCK_UN)
		releaseErrors = append(releaseErrors, keyUnlockErr)
		keyReleased = keyUnlockErr == nil
	}

	guardReleased := false
	if keyReleased && authority != nil && authority.guardFD >= 0 {
		guardUnlockErr := unix.Flock(authority.guardFD, unix.LOCK_UN)
		releaseErrors = append(releaseErrors, guardUnlockErr)
		guardReleased = guardUnlockErr == nil
		if guardReleased && releaseAfterGuardUnlockHook != nil {
			releaseAfterGuardUnlockHook()
		}
	}

	if keyReleased && guardReleased && authority != nil && authority.guardFD >= 0 && authority.guardImmutable {
		reacquired, err := reacquireGuardForClear(authority.guardFD)
		if err != nil {
			releaseErrors = append(releaseErrors, err)
		} else if reacquired {
			releaseErrors = append(releaseErrors, authority.clearImmutableGuard())
		}
	}

	if fd >= 0 {
		releaseErrors = append(releaseErrors, unix.Close(fd))
	}
	if authority != nil {
		releaseErrors = append(releaseErrors, authority.close())
	}
	return errors.Join(releaseErrors...)
}

func reacquireGuardForClear(fd int) (bool, error) {
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
			return false, nil
		default:
			return false, err
		}
	}
}
