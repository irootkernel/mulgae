package providercli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/ports"
)

// unlinkNamespaceEntry is the single unlink operation boundary. Callers verify
// the descriptor identity immediately before this call. A pathname substitution
// made after that verification inside the kernel syscall cannot be observed in
// userspace before the unlink takes effect; retries still locate and remove the
// retained descriptor identity without trusting its prior name.
var (
	openNamespaceRootDescriptor   = unix.Openat
	closeNamespaceDescriptor      = (*os.File).Close
	closeNamespaceChildDescriptor = unix.Close
	unlinkNamespaceEntry          = unix.Unlinkat
)

// NamespaceFactory allocates private, per-instance process namespaces beneath
// one caller-selected private root. It never consults the host environment.
type NamespaceFactory struct {
	root          string
	rootInfo      os.FileInfo
	rootDirectory *os.File
}

var _ ports.ProviderNamespaceFactory = (*NamespaceFactory)(nil)

// NewNamespaceFactory constructs a namespace authority rooted at root. Root is
// created with owner-only permissions when absent. An existing root may be
// readable, but must be a real directory that no non-owner can modify.
func NewNamespaceFactory(root string) (*NamespaceFactory, error) {
	if !validCanonicalAbsolute(root) {
		return nil, fmt.Errorf("provider namespace factory: invalid root")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("provider namespace factory: create root: %w", err)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("provider namespace factory: open root: %w", err)
	}
	directory := os.NewFile(uintptr(rootFD), "provider namespace factory root")
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		cause := fmt.Errorf("provider namespace factory: unsafe root")
		if err != nil {
			cause = errors.Join(cause, err)
		}
		owner := &namespaceLease{
			rootDirectory:      directory,
			cleanupStage:       namespaceCleanupDetached,
			closeRootDirectory: closeNamespaceDescriptor,
		}
		return nil, namespaceConstructionError(cause, owner.closeNamespaceDescriptors(), owner)
	}
	return &NamespaceFactory{root: root, rootInfo: info, rootDirectory: directory}, nil
}
func (factory *NamespaceFactory) validatePinnedRoot() error {
	pinned, pinnedErr := factory.rootDirectory.Stat()
	info, err := os.Lstat(factory.root)
	if err != nil || pinnedErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(factory.rootInfo, info) || !os.SameFile(factory.rootInfo, pinned) {
		return fmt.Errorf("provider namespace factory: root drift")
	}
	return nil
}

// AcquireProviderNamespace creates one generation for exactly one provider
// instance. Registries retain the returned lease for their complete lifetime.
func (factory *NamespaceFactory) AcquireProviderNamespace(ctx context.Context, instance string) (ports.ProviderNamespaceLease, error) {
	return ports.AcquireProviderNamespaceLease(ctx, instance, factory.acquireProviderNamespace)
}

func (factory *NamespaceFactory) acquireProviderNamespace(ctx context.Context, instance string, binding ports.ProviderNamespaceTerminalBinding) (ports.ProviderNamespaceLease, error) {
	if factory == nil || factory.rootDirectory == nil || !validCanonicalAbsolute(factory.root) || !validProviderInstanceID(instance) {
		return nil, fmt.Errorf("provider namespace factory: invalid request")
	}
	if err := factory.validatePinnedRoot(); err != nil {
		return nil, err
	}
	generation, err := namespaceGeneration()
	if err != nil {
		return nil, err
	}
	rootName := "provider-" + instance + "-" + generation
	parentFD, err := unix.Dup(int(factory.rootDirectory.Fd()))
	if err != nil {
		return nil, fmt.Errorf("provider namespace factory: duplicate root authority: %w", err)
	}
	parentDirectory := os.NewFile(uintptr(parentFD), "provider namespace parent")
	if err := unix.Mkdirat(parentFD, rootName, 0700); err != nil {
		return nil, namespaceConstructionDescriptorError(
			fmt.Errorf("provider namespace factory: create namespace: %w", err), parentDirectory,
		)
	}
	var rootEntry unix.Stat_t
	if err := unix.Fstatat(parentFD, rootName, &rootEntry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		cleanupErr := unix.Unlinkat(parentFD, rootName, unix.AT_REMOVEDIR)
		return nil, namespaceConstructionDescriptorError(
			errors.Join(fmt.Errorf("provider namespace factory: inspect namespace: %w", err), cleanupErr), parentDirectory,
		)
	}
	if rootEntry.Mode&unix.S_IFMT != unix.S_IFDIR {
		cleanupErr := unix.Unlinkat(parentFD, rootName, unix.AT_REMOVEDIR)
		return nil, namespaceConstructionDescriptorError(
			errors.Join(fmt.Errorf("provider namespace factory: unsafe namespace"), cleanupErr), parentDirectory,
		)
	}
	rootFD, err := openNamespaceRootDescriptor(parentFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		cleanupErr := unix.Unlinkat(parentFD, rootName, unix.AT_REMOVEDIR)
		cause := fmt.Errorf("provider namespace factory: open namespace: %w", err)
		if cleanupErr == nil {
			return nil, namespaceConstructionDescriptorError(cause, parentDirectory)
		}
		owner := &namespaceLease{
			parentDirectory:      parentDirectory,
			rootName:             rootName,
			cleanupDevice:        rootEntry.Dev,
			cleanupInode:         rootEntry.Ino,
			closeRootDirectory:   closeNamespaceDescriptor,
			closeParentDirectory: closeNamespaceDescriptor,
		}
		return nil, namespaceConstructionError(cause, cleanupErr, owner)
	}
	rootDirectory := os.NewFile(uintptr(rootFD), "provider namespace root")
	root := filepath.Join(factory.root, rootName)
	lease, err := newNamespaceLease(instance, generation, root, rootName, parentDirectory, rootDirectory, binding)
	if err == nil {
		err = factory.validatePinnedRoot()
		if err == nil {
			err = lease.ValidateForSpawn()
		}
		if err != nil {
			err = fmt.Errorf("provider namespace factory: root drift after construction: %w", err)
		}
	}
	if err != nil {
		cleanupErr := lease.removeNamespaceRoot()
		if cleanupErr == nil {
			cleanupErr = lease.closeNamespaceDescriptors()
		}
		return nil, namespaceConstructionError(err, cleanupErr, lease)
	}
	return lease, nil
}

// NamespaceConstructionError retains the descriptor-owning lease when a
// namespace could not be handed to its caller and its rollback was incomplete.
type NamespaceConstructionError struct {
	cause error
	lease *namespaceLease
}

func (err *NamespaceConstructionError) Error() string { return err.cause.Error() }
func (err *NamespaceConstructionError) Unwrap() error { return err.cause }

func namespaceConstructionDescriptorError(cause error, parent *os.File) error {
	owner := &namespaceLease{
		parentDirectory:      parent,
		cleanupStage:         namespaceCleanupDetached,
		closeParentDirectory: closeNamespaceDescriptor,
	}
	closeErr := owner.closeNamespaceDescriptors()
	return namespaceConstructionError(cause, closeErr, owner)
}
func namespaceConstructionError(cause, cleanupErr error, lease *namespaceLease) error {
	if cleanupErr == nil {
		return cause
	}
	return &NamespaceConstructionError{cause: errors.Join(cause, cleanupErr), lease: lease}
}

// NamespaceFromConstructionError returns the retained cleanup owner. The owner
// must be retried with RetryConstructionCleanup before it is discarded.
func NamespaceFromConstructionError(err error) (*namespaceLease, bool) {
	var construction *NamespaceConstructionError
	if !errors.As(err, &construction) || construction.lease == nil {
		return nil, false
	}
	return construction.lease, true
}

// RetryConstructionCleanup retries rollback owned by a failed construction.
func (lease *namespaceLease) RetryConstructionCleanup() error {
	if lease == nil {
		return fmt.Errorf("provider namespace: invalid construction cleanup")
	}
	lease.terminalMu.Lock()
	defer lease.terminalMu.Unlock()
	if err := lease.removeNamespaceRoot(); err != nil {
		return err
	}
	if err := lease.closeNamespaceDescriptors(); err != nil {
		return err
	}
	lease.cleanupStage = namespaceCleanupDescriptorsClosed
	return nil
}

func safeNamespaceRootInfo(root string) (os.FileInfo, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("unsafe namespace root")
	}
	return info, nil
}

type namespaceCleanupStage uint8

const (
	namespaceCleanupInitial namespaceCleanupStage = iota
	namespaceCleanupQuarantined
	namespaceCleanupContentsDeleted
	namespaceCleanupFinalIdentityChecked
	namespaceCleanupUnlinked
	namespaceCleanupDetached
	namespaceCleanupDescriptorsClosed
)

type namespaceLease struct {
	instance                  string
	generation                string
	root                      string
	rootInfo                  os.FileInfo
	parentDirectory           *os.File
	rootDirectory             *os.File
	rootName                  string
	environment               []ports.EnvironmentVariable
	directoryInfo             map[string]os.FileInfo
	nativeHome                string
	nativeHomeInfo            os.FileInfo
	seedMu                    sync.RWMutex
	nativeHomeLaunchAuthority ports.NativeHomeLaunchAuthority
	seeds                     map[ports.CredentialProjectionDestination]credentialSeed
	policyMu                  sync.RWMutex
	policy                    RuntimeSafetyPolicy
	policyInfo                os.FileInfo
	terminalMu                sync.Mutex
	terminalDrain             ports.ProviderNamespaceTerminalDrain
	drained                   bool
	policyCleaned             bool
	cleanupStage              namespaceCleanupStage
	cleanupDevice             int32
	cleanupInode              uint64
	afterFinalCheckHook       func(*namespaceLease)
	afterQuarantineHook       func(*namespaceLease) error
	afterContentsDeletedHook  func(*namespaceLease) error
	afterUnlinkHook           func(*namespaceLease) error
	afterDetachedHook         func(*namespaceLease) error
	closeRootDirectory        func(*os.File) error
	closeParentDirectory      func(*os.File) error
	pendingDescriptors        []*os.File
	traversal                 *namespaceTraversal
}

var _ ports.ProviderNamespaceLease = (*namespaceLease)(nil)

func newNamespaceLease(instance, generation, root, rootName string, parentDirectory, rootDirectory *os.File, binding ports.ProviderNamespaceTerminalBinding) (*namespaceLease, error) {
	if !validProviderInstanceID(instance) || generation == "" || !validCanonicalAbsolute(root) || rootName == "" ||
		parentDirectory == nil || rootDirectory == nil {
		return nil, fmt.Errorf("provider namespace: invalid identity")
	}
	lease := &namespaceLease{
		instance: instance, generation: generation, root: root, parentDirectory: parentDirectory, rootDirectory: rootDirectory,
		rootName: rootName, seeds: make(map[ports.CredentialProjectionDestination]credentialSeed),
		closeRootDirectory: closeNamespaceDescriptor, closeParentDirectory: closeNamespaceDescriptor,
	}
	directories := []string{
		"home", "home/.kimi-code", "home/.kimi-code/credentials",
		"home/.zcode", "home/.zcode/cli", "home/.gemini", "home/.gemini/antigravity-cli",
		"home/.codex",
		"settings", "auth", "cache", "tmp", "scratch",
	}
	directoryInfo := make(map[string]os.FileInfo, len(directories))
	constructionDirectories := map[string]*os.File{"": rootDirectory}
	for _, name := range directories {
		parentName, baseName := filepath.Split(name)
		parentName = strings.TrimSuffix(parentName, string(filepath.Separator))
		parent := constructionDirectories[parentName]
		if parent == nil {
			return lease, fmt.Errorf("provider namespace: missing parent %s", parentName)
		}
		if err := unix.Mkdirat(int(parent.Fd()), baseName, 0700); err != nil && err != unix.EEXIST {
			return lease, fmt.Errorf("provider namespace: create %s: %w", name, err)
		}
		fd, err := unix.Openat(int(parent.Fd()), baseName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return lease, fmt.Errorf("provider namespace: open %s: %w", name, err)
		}
		directory := os.NewFile(uintptr(fd), "provider namespace construction directory")
		lease.pendingDescriptors = append(lease.pendingDescriptors, directory)
		info, err := directory.Stat()
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return lease, fmt.Errorf("provider namespace: unsafe %s: %w", name, errors.Join(err, fmt.Errorf("unsafe directory")))
		}
		constructionDirectories[name] = directory
		directoryInfo[name] = info
	}
	rootInfo, err := rootDirectory.Stat()
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0077 != 0 {
		return lease, fmt.Errorf("provider namespace: unsafe root")
	}
	environment, err := namespaceEnvironment(root)
	if err != nil {
		return lease, err
	}
	lease.rootInfo, lease.environment, lease.directoryInfo = rootInfo, environment, directoryInfo
	if err := lease.closePendingDescriptors(); err != nil {
		return lease, err
	}
	terminalDrain, err := binding.Bind(generation, lease.drainTerminalEffects)
	if err != nil {
		return lease, err
	}
	lease.terminalDrain = terminalDrain
	return lease, nil
}

func mkdirNamespaceDirectory(lease *namespaceLease, rootFD int, name string) error {
	current := rootFD
	for _, part := range strings.Split(name, "/") {
		if err := unix.Mkdirat(current, part, 0700); err != nil && err != unix.EEXIST {
			return err
		}
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		lease.pendingDescriptors = append(lease.pendingDescriptors, os.NewFile(uintptr(next), "provider namespace construction directory"))
		current = next
	}
	return nil
}

func namespaceDirectoryInfo(lease *namespaceLease, rootFD int, name string) (os.FileInfo, error) {
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "provider namespace directory")
	lease.pendingDescriptors = append(lease.pendingDescriptors, file)
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(err, fmt.Errorf("unsafe directory"))
	}
	return info, nil
}

func namespaceGeneration() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("provider namespace: generate identity: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func namespaceEnvironment(root string) ([]ports.EnvironmentVariable, error) {
	values := []struct{ name, directory string }{
		{"HOME", "home"},
		{"XDG_CONFIG_HOME", "settings"},
		{"XDG_DATA_HOME", "auth"},
		{"XDG_CACHE_HOME", "cache"},
		{"TMPDIR", "tmp"},
		{"TMP", "tmp"},
		{"TEMP", "tmp"},
		{"MULGAE_PROVIDER_SCRATCH", "scratch"},
	}
	environment := make([]ports.EnvironmentVariable, 0, len(values))
	for _, value := range values {
		variable, err := ports.NewEnvironmentVariable(value.name, filepath.Join(root, value.directory))
		if err != nil {
			return nil, fmt.Errorf("provider namespace: environment: %w", err)
		}
		environment = append(environment, variable)
	}
	return environment, nil
}

func (lease *namespaceLease) ProviderInstance() string { return lease.instance }
func (lease *namespaceLease) Generation() string       { return lease.generation }
func (lease *namespaceLease) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), lease.environment...)
}

func (lease *namespaceLease) bindRuntimeHome(home string, homeInfo os.FileInfo, launchAuthority ports.NativeHomeLaunchAuthority) error {
	if lease == nil || home != launchAuthority.Path() || !launchAuthority.Valid() || homeInfo == nil {
		return fmt.Errorf("provider namespace: invalid runtime home")
	}
	if lease.nativeHome != "" || lease.policy.identity != "" {
		return fmt.Errorf("provider namespace: runtime home already bound")
	}
	for index, variable := range lease.environment {
		if variable.Name() != "HOME" {
			continue
		}
		replacement, err := ports.NewEnvironmentVariable("HOME", home)
		if err != nil {
			return fmt.Errorf("provider namespace: runtime home")
		}
		lease.environment[index] = replacement
		lease.nativeHome = home
		lease.nativeHomeInfo = homeInfo
		lease.nativeHomeLaunchAuthority = launchAuthority
		return nil
	}
	return fmt.Errorf("provider namespace: missing home environment")
}

func (lease *namespaceLease) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	if lease == nil || !lease.nativeHomeLaunchAuthority.Valid() {
		return ports.NativeHomeLaunchAuthority{}, false
	}
	return lease.nativeHomeLaunchAuthority, true
}

func (lease *namespaceLease) ValidateForSpawn() error {
	if lease == nil || !validProviderInstanceID(lease.instance) || lease.generation == "" || !validCanonicalAbsolute(lease.root) {
		return fmt.Errorf("provider namespace: invalid lease")
	}
	if lease.terminallyDrained() {
		return fmt.Errorf("provider namespace: lease is closed")
	}
	rootInfo, err := os.Lstat(lease.root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lease.rootInfo, rootInfo) ||
		rootInfo.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("provider namespace: namespace drift")
	}
	for name, expected := range lease.directoryInfo {
		info, err := os.Lstat(filepath.Join(lease.root, name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, info) || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("provider namespace: namespace drift")
		}
	}
	if lease.nativeHome != "" {
		authority, ok := lease.NativeHomeLaunchAuthority()
		homeInfo, err := os.Lstat(lease.nativeHome)
		if !ok || err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(lease.nativeHomeInfo, homeInfo) || authority.Path() != lease.nativeHome {
			return fmt.Errorf("provider namespace: runtime home drift")
		}
	}
	if err := lease.validateSeeds(); err != nil {
		return fmt.Errorf("provider namespace: credential seed drift")
	}
	lease.policyMu.RLock()
	hasPolicy := lease.policy.identity != ""
	lease.policyMu.RUnlock()
	if hasPolicy {
		if err := lease.validateRuntimeSafetyPolicy(); err != nil {
			return fmt.Errorf("provider namespace: runtime safety policy drift")
		}
	}
	return nil
}

func (lease *namespaceLease) terminallyDrained() bool {
	if lease == nil {
		return true
	}
	lease.terminalMu.Lock()
	defer lease.terminalMu.Unlock()
	return lease.drained
}

func (lease *namespaceLease) DrainTerminal(ctx context.Context) (ports.ProviderNamespaceTerminalReceipt, error) {
	if lease == nil || lease.terminalDrain == nil {
		return ports.ProviderNamespaceTerminalReceipt{}, fmt.Errorf("provider namespace: invalid terminal drain")
	}
	return lease.terminalDrain(ctx)
}

func (lease *namespaceLease) drainTerminalEffects(ctx context.Context) error {
	lease.terminalMu.Lock()
	defer lease.terminalMu.Unlock()
	if lease.drained {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lease.zeroAndUnlinkRuntimeSafetyPolicy(); err != nil {
		return err
	}
	if err := lease.zeroAndUnlinkSeeds(); err != nil {
		return err
	}
	if err := lease.removeNamespaceRoot(); err != nil {
		return err
	}
	if err := lease.closeNamespaceDescriptors(); err != nil {
		return err
	}
	lease.cleanupStage = namespaceCleanupDescriptorsClosed
	lease.drained = true
	return nil
}

func openNamespaceDescriptors(root string, rootInfo os.FileInfo) (*os.File, *os.File, string, error) {
	parentPath, rootName := filepath.Dir(root), filepath.Base(root)
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, "", err
	}
	parent := os.NewFile(uintptr(parentFD), "provider namespace parent")
	rootFD, err := openNamespaceRootDescriptor(parentFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if closeErr := closeNamespaceDescriptor(parent); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("provider namespace: close parent descriptor: %w", closeErr))
		}
		return nil, nil, "", err
	}
	directory := os.NewFile(uintptr(rootFD), "provider namespace root")
	info, err := directory.Stat()
	if err != nil || !os.SameFile(rootInfo, info) {
		identityErr := fmt.Errorf("root identity drift")
		if err != nil {
			identityErr = fmt.Errorf("root identity drift: %w", err)
		}
		if closeErr := closeNamespaceDescriptor(directory); closeErr != nil {
			identityErr = errors.Join(identityErr, fmt.Errorf("provider namespace: close root descriptor: %w", closeErr))
		}
		if closeErr := closeNamespaceDescriptor(parent); closeErr != nil {
			identityErr = errors.Join(identityErr, fmt.Errorf("provider namespace: close parent descriptor: %w", closeErr))
		}
		return nil, nil, "", identityErr
	}
	return parent, directory, rootName, nil
}

func (lease *namespaceLease) closePendingDescriptors() error {
	var errs []error
	for index := len(lease.pendingDescriptors) - 1; index >= 0; index-- {
		directory := lease.pendingDescriptors[index]
		if err := closeNamespaceDescriptor(directory); err != nil {
			errs = append(errs, fmt.Errorf("provider namespace: close construction descriptor: %w", err))
			continue
		}
		lease.pendingDescriptors = append(lease.pendingDescriptors[:index], lease.pendingDescriptors[index+1:]...)
	}
	return errors.Join(errs...)
}

func (lease *namespaceLease) closeNamespaceDescriptors() error {
	var errs []error
	if err := lease.closePendingDescriptors(); err != nil {
		errs = append(errs, err)
	}
	if lease.rootDirectory != nil {
		closeRoot := lease.closeRootDirectory
		if closeRoot == nil {
			closeRoot = closeNamespaceDescriptor
		}
		if err := closeRoot(lease.rootDirectory); err != nil {
			errs = append(errs, fmt.Errorf("provider namespace: close root descriptor: %w", err))
		} else {
			lease.rootDirectory = nil
		}
	}
	if lease.parentDirectory != nil {
		closeParent := lease.closeParentDirectory
		if closeParent == nil {
			closeParent = closeNamespaceDescriptor
		}
		if err := closeParent(lease.parentDirectory); err != nil {
			errs = append(errs, fmt.Errorf("provider namespace: close parent descriptor: %w", err))
		} else {
			lease.parentDirectory = nil
		}
	}
	return errors.Join(errs...)
}

func (lease *namespaceLease) removeNamespaceRoot() error {
	if lease.cleanupStage == namespaceCleanupDetached || lease.cleanupStage == namespaceCleanupDescriptorsClosed {
		return nil
	}
	if lease.parentDirectory == nil || lease.rootName == "" {
		return fmt.Errorf("provider namespace: missing root descriptor")
	}
	if lease.rootDirectory == nil {
		name, err := lease.locateNamespaceEntry(int(lease.parentDirectory.Fd()), lease.rootName, lease.cleanupDevice, lease.cleanupInode)
		if err != nil {
			return fmt.Errorf("provider namespace: locate construction root: %w", err)
		}
		fd, err := unix.Openat(int(lease.parentDirectory.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("provider namespace: reopen construction root: %w", err)
		}
		directory := os.NewFile(uintptr(fd), "provider namespace construction root")
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil || info.Dev != lease.cleanupDevice || info.Ino != lease.cleanupInode || info.Mode&unix.S_IFMT != unix.S_IFDIR {
			identityErr := fmt.Errorf("provider namespace: construction root identity drift")
			if err != nil {
				identityErr = errors.Join(identityErr, err)
			}
			if closeErr := closeNamespaceDescriptor(directory); closeErr != nil {
				lease.pendingDescriptors = append(lease.pendingDescriptors, directory)
				identityErr = errors.Join(identityErr, closeErr)
			}
			return identityErr
		}
		lease.rootDirectory = directory
		lease.rootName = name
	}
	rootFD := int(lease.rootDirectory.Fd())
	parentFD := int(lease.parentDirectory.Fd())
	var current unix.Stat_t
	if err := unix.Fstat(rootFD, &current); err != nil {
		return fmt.Errorf("provider namespace: inspect root descriptor: %w", err)
	}
	if lease.cleanupStage == namespaceCleanupInitial {
		lease.cleanupDevice, lease.cleanupInode = current.Dev, current.Ino
	} else if current.Dev != lease.cleanupDevice || current.Ino != lease.cleanupInode || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("provider namespace: root descriptor drift")
	}
	expectedDevice, expectedInode := lease.cleanupDevice, lease.cleanupInode

	if lease.cleanupStage == namespaceCleanupInitial {
		sourceName, err := lease.locateNamespaceEntry(parentFD, lease.rootName, expectedDevice, expectedInode)
		if err != nil {
			return fmt.Errorf("provider namespace: locate root: %w", err)
		}
		lease.rootName = sourceName
		tombName, err := namespaceTombName(sourceName)
		if err != nil {
			return err
		}
		if err := unix.RenameatxNp(parentFD, sourceName, parentFD, tombName, unix.RENAME_EXCL); err != nil {
			return fmt.Errorf("provider namespace: quarantine root: %w", err)
		}
		if err := namespaceEntryMatches(parentFD, tombName, expectedDevice, expectedInode); err != nil {
			return restoreUnexpectedQuarantine(parentFD, tombName, sourceName)
		}
		lease.rootName = tombName
		lease.cleanupStage = namespaceCleanupQuarantined
		if lease.afterQuarantineHook != nil {
			if err := lease.afterQuarantineHook(lease); err != nil {
				return err
			}
		}
	}
	if lease.cleanupStage == namespaceCleanupQuarantined {
		name, err := lease.locateNamespaceEntry(parentFD, lease.rootName, expectedDevice, expectedInode)
		if err != nil {
			return fmt.Errorf("provider namespace: quarantine identity drift: %w", err)
		}
		lease.rootName = name
		if err := lease.removeNamespaceContents(); err != nil {
			return fmt.Errorf("provider namespace: unlink: %w", err)
		}
		lease.cleanupStage = namespaceCleanupContentsDeleted
		if lease.afterContentsDeletedHook != nil {
			if err := lease.afterContentsDeletedHook(lease); err != nil {
				return err
			}
		}
	}
	if lease.cleanupStage == namespaceCleanupContentsDeleted {
		name, err := lease.locateNamespaceEntry(parentFD, lease.rootName, expectedDevice, expectedInode)
		if err != nil {
			return fmt.Errorf("provider namespace: quarantine identity drift: %w", err)
		}
		lease.rootName = name
		if lease.afterFinalCheckHook != nil {
			lease.afterFinalCheckHook(lease)
		}
		sourceName, err := lease.locateNamespaceEntry(parentFD, lease.rootName, expectedDevice, expectedInode)
		if err != nil {
			return fmt.Errorf("provider namespace: final quarantine identity drift: %w", err)
		}
		lease.rootName = sourceName
		finalTombName, err := namespaceTombName(sourceName)
		if err != nil {
			return err
		}
		if err := unix.RenameatxNp(parentFD, sourceName, parentFD, finalTombName, unix.RENAME_EXCL); err != nil {
			return fmt.Errorf("provider namespace: final quarantine root: %w", err)
		}
		if err := namespaceEntryMatches(parentFD, finalTombName, expectedDevice, expectedInode); err != nil {
			return restoreUnexpectedQuarantine(parentFD, finalTombName, sourceName)
		}
		lease.rootName = finalTombName
		lease.cleanupStage = namespaceCleanupFinalIdentityChecked
	}
	if lease.cleanupStage == namespaceCleanupFinalIdentityChecked {
		sourceName, err := lease.locateNamespaceEntry(parentFD, lease.rootName, expectedDevice, expectedInode)
		if err != nil {
			return fmt.Errorf("provider namespace: final unlink identity drift: %w", err)
		}
		finalName, err := namespaceTombName(sourceName)
		if err != nil {
			return err
		}
		if err := unix.RenameatxNp(parentFD, sourceName, parentFD, finalName, unix.RENAME_EXCL); err != nil {
			return fmt.Errorf("provider namespace: final re-quarantine root: %w", err)
		}
		if err := namespaceEntryMatches(parentFD, finalName, expectedDevice, expectedInode); err != nil {
			return restoreUnexpectedQuarantine(parentFD, finalName, sourceName)
		}
		lease.rootName = finalName
		if err := unlinkNamespaceEntry(parentFD, finalName, unix.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("provider namespace: unlink: %w", err)
		}
		var hookErr error
		if lease.afterUnlinkHook != nil {
			hookErr = lease.afterUnlinkHook(lease)
		}
		if err := verifyDescriptorDetached(rootFD, expectedDevice, expectedInode); err != nil {
			// Keep final identity state so retry scans the pinned parent for this inode.
			return errors.Join(hookErr, fmt.Errorf("provider namespace: root descriptor remains linked: %w", err))
		}
		lease.cleanupStage = namespaceCleanupDetached
		if lease.afterDetachedHook != nil {
			hookErr = errors.Join(hookErr, lease.afterDetachedHook(lease))
		}
		if hookErr != nil {
			return hookErr
		}
	}
	if lease.cleanupStage == namespaceCleanupUnlinked {
		if err := verifyDescriptorDetached(rootFD, expectedDevice, expectedInode); err != nil {
			return fmt.Errorf("provider namespace: root descriptor remains linked: %w", err)
		}
		lease.cleanupStage = namespaceCleanupDetached
		if lease.afterDetachedHook != nil {
			if err := lease.afterDetachedHook(lease); err != nil {
				return err
			}
		}
	}
	return nil
}

func locateNamespaceEntry(parentFD int, preferred string, expectedDevice int32, expectedInode uint64) (string, *os.File, error) {
	if err := namespaceEntryMatches(parentFD, preferred, expectedDevice, expectedInode); err == nil {
		return preferred, nil, nil
	}
	duplicate, err := unix.Dup(parentFD)
	if err != nil {
		return "", nil, err
	}
	directory := os.NewFile(uintptr(duplicate), "provider namespace parent scan")
	if _, err := unix.Seek(duplicate, 0, 0); err != nil {
		closeErr := closeNamespaceDescriptor(directory)
		if closeErr != nil {
			return "", directory, errors.Join(err, closeErr)
		}
		return "", nil, err
	}
	names, readErr := directory.Readdirnames(-1)
	if closeErr := closeNamespaceDescriptor(directory); closeErr != nil {
		return "", directory, errors.Join(readErr, closeErr)
	}
	if readErr != nil {
		return "", nil, readErr
	}
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		if err := namespaceEntryMatches(parentFD, name, expectedDevice, expectedInode); err == nil {
			return name, nil, nil
		}
	}
	return "", nil, fmt.Errorf("retained root entry not found")
}

func (lease *namespaceLease) locateNamespaceEntry(parentFD int, preferred string, expectedDevice int32, expectedInode uint64) (string, error) {
	name, pending, err := locateNamespaceEntry(parentFD, preferred, expectedDevice, expectedInode)
	if pending != nil {
		lease.pendingDescriptors = append(lease.pendingDescriptors, pending)
	}
	return name, err
}
func namespaceEntryMatches(parentFD int, name string, expectedDevice int32, expectedInode uint64) error {
	var entry unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if entry.Dev != expectedDevice || entry.Ino != expectedInode || entry.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("identity drift")
	}
	return nil
}

func namespaceTombName(rootName string) (string, error) {
	identity, err := namespaceGeneration()
	if err != nil {
		return "", fmt.Errorf("provider namespace: generate tomb identity: %w", err)
	}
	return "." + rootName + ".tomb-" + identity, nil
}

func restoreUnexpectedQuarantine(parentFD int, tombName, restoreName string) error {
	if err := unix.RenameatxNp(parentFD, tombName, parentFD, restoreName, unix.RENAME_EXCL); err != nil {
		return fmt.Errorf("provider namespace: quarantine identity drift; preserve unexpected root: %w", err)
	}
	return fmt.Errorf("provider namespace: quarantine identity drift")
}

type namespaceTraversalFrame struct {
	parentFD       int
	name           string
	fd             int
	device         int32
	inode          uint64
	names          []string
	next           int
	detached       bool
	refreshPending bool
}

type namespaceTraversal struct {
	frames       []*namespaceTraversalFrame
	pendingClose []*os.File
}

func (lease *namespaceLease) removeNamespaceContents() error {
	if lease.traversal == nil {
		traversal, err := newNamespaceTraversal(int(lease.rootDirectory.Fd()))
		lease.traversal = traversal
		if err != nil {
			return err
		}
	}
	if err := lease.traversal.advance(); err != nil {
		return err
	}
	lease.traversal = nil
	return nil
}

func newNamespaceTraversal(rootFD int) (*namespaceTraversal, error) {
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return nil, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		file := os.NewFile(uintptr(fd), "provider namespace traversal root")
		traversal := &namespaceTraversal{pendingClose: []*os.File{file}}
		closeErr := closeNamespaceDescriptor(file)
		if closeErr == nil {
			traversal.pendingClose = nil
		}
		return traversal, errors.Join(err, closeErr)
	}
	names, pending, err := namespaceDirectoryNames(fd)
	traversal := &namespaceTraversal{
		frames: []*namespaceTraversalFrame{{fd: fd, device: info.Dev, inode: info.Ino, names: names}},
	}
	if pending != nil {
		traversal.pendingClose = append(traversal.pendingClose, pending)
	}
	if err != nil {
		return traversal, err
	}
	return traversal, nil
}

func (traversal *namespaceTraversal) advance() error {
	for len(traversal.pendingClose) > 0 {
		index := len(traversal.pendingClose) - 1
		file := traversal.pendingClose[index]
		if err := closeNamespaceDescriptor(file); err != nil {
			return fmt.Errorf("provider namespace: close traversal descriptor: %w", err)
		}
		traversal.pendingClose = traversal.pendingClose[:index]
	}
	for len(traversal.frames) > 0 {
		frame := traversal.frames[len(traversal.frames)-1]
		if frame.refreshPending {
			names, pending, err := namespaceDirectoryNames(frame.fd)
			if pending != nil {
				traversal.pendingClose = append(traversal.pendingClose, pending)
			}
			if err != nil {
				return fmt.Errorf("provider namespace: refresh traversal parent: %w", err)
			}
			frame.names = names
			frame.next = 0
			frame.refreshPending = false
			continue
		}
		if frame.next < len(frame.names) {
			name := frame.names[frame.next]
			if name == "." || name == ".." {
				frame.next++
				continue
			}
			var info unix.Stat_t
			if err := unix.Fstatat(frame.fd, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if info.Mode&unix.S_IFMT != unix.S_IFDIR {
				if err := unix.Unlinkat(frame.fd, name, 0); err != nil {
					return err
				}
				frame.next++
				continue
			}
			childFD, err := unix.Openat(frame.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			names, pending, err := namespaceDirectoryNames(childFD)
			child := &namespaceTraversalFrame{
				parentFD: frame.fd, name: name, fd: childFD, device: info.Dev, inode: info.Ino, names: names,
			}
			traversal.frames = append(traversal.frames, child)
			if pending != nil {
				traversal.pendingClose = append(traversal.pendingClose, pending)
			}
			if err != nil {
				return err
			}
			continue
		}

		if len(traversal.frames) == 1 {
			if err := closeNamespaceChildDescriptor(frame.fd); err != nil {
				return fmt.Errorf("provider namespace: close traversal root: %w", err)
			}
			traversal.frames = traversal.frames[:0]
			return nil
		}
		if !frame.detached {
			name, pending, err := locateNamespaceEntry(frame.parentFD, frame.name, frame.device, frame.inode)
			if pending != nil {
				traversal.pendingClose = append(traversal.pendingClose, pending)
			}
			if err != nil {
				return fmt.Errorf("provider namespace: locate child: %w", err)
			}
			if err := unlinkNamespaceEntry(frame.parentFD, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
			if err := verifyDescriptorDetached(frame.fd, frame.device, frame.inode); err != nil {
				// The retained child FD and parent FD let retry find the inode by identity.
				return fmt.Errorf("provider namespace: child descriptor remains linked: %w", err)
			}
			frame.detached = true
		}
		if err := closeNamespaceChildDescriptor(frame.fd); err != nil {
			return fmt.Errorf("provider namespace: close child descriptor: %w", err)
		}
		traversal.frames = traversal.frames[:len(traversal.frames)-1]
		parent := traversal.frames[len(traversal.frames)-1]
		parent.refreshPending = true
	}
	return nil
}

func namespaceDirectoryNames(fd int) ([]string, *os.File, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, nil, err
	}
	directory := os.NewFile(uintptr(duplicate), "provider namespace traversal")
	if _, err := unix.Seek(duplicate, 0, 0); err != nil {
		closeErr := closeNamespaceDescriptor(directory)
		if closeErr != nil {
			return nil, directory, errors.Join(err, closeErr)
		}
		return nil, nil, err
	}
	names, readErr := directory.Readdirnames(-1)
	if closeErr := closeNamespaceDescriptor(directory); closeErr != nil {
		return names, directory, errors.Join(readErr, closeErr)
	}
	return names, nil, readErr
}

func removeNamespaceContents(directoryFD int) error {
	traversal, err := newNamespaceTraversal(directoryFD)
	if err != nil {
		return err
	}
	return traversal.advance()
}
