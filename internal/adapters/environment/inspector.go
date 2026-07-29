//go:build darwin && arm64

// Package environment provides Darwin environment-observation adapters for ports.
package environment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

// Inspector observes local platform, executable, and permission state. Identity
// observation never executes files; legacy version diagnostics remain separate.
type Inspector struct {
	lookup        func(string) (string, error)
	evaluateLinks func(string) (string, error)
	executable    func(string) (executableDescriptor, error)
	version       func(context.Context, string) ([]byte, error)
	permission    func(ports.AnchoredRoot, ports.SafeRelativePath) (bool, bool, bool, error)
	platform      func() (string, string)
}

var _ ports.EnvironmentInspector = (*Inspector)(nil)

// NewInspector returns an inspector using the current process's configured
// PATH only for executable lookup.
func NewInspector() *Inspector {
	return newInspector(inspectorDependencies{})
}

type inspectorDependencies struct {
	lookup        func(string) (string, error)
	evaluateLinks func(string) (string, error)
	executable    func(string) (executableDescriptor, error)
	version       func(context.Context, string) ([]byte, error)
	permission    func(ports.AnchoredRoot, ports.SafeRelativePath) (bool, bool, bool, error)
	platform      func() (string, string)
}

func newInspector(dependencies inspectorDependencies) *Inspector {
	inspector := &Inspector{
		lookup:        exec.LookPath,
		evaluateLinks: filepath.EvalSymlinks,
		executable:    openCanonicalExecutable,
		version:       observeExecutableVersion,
		permission:    observePermissionDescriptor,
		platform:      func() (string, string) { return runtime.GOOS, runtime.GOARCH },
	}
	if dependencies.lookup != nil {
		inspector.lookup = dependencies.lookup
	}
	if dependencies.evaluateLinks != nil {
		inspector.evaluateLinks = dependencies.evaluateLinks
	}
	if dependencies.executable != nil {
		inspector.executable = dependencies.executable
	}
	if dependencies.version != nil {
		inspector.version = dependencies.version
	}
	if dependencies.permission != nil {
		inspector.permission = dependencies.permission
	}
	if dependencies.platform != nil {
		inspector.platform = dependencies.platform
	}
	return inspector
}

// ObservePlatform returns the runtime operating system and architecture.
func (inspector *Inspector) ObservePlatform(ctx context.Context) (ports.PlatformObservation, error) {
	if err := observationContext(ctx, "platform observation"); err != nil {
		return ports.PlatformObservation{}, err
	}
	if inspector == nil || inspector.platform == nil {
		return ports.PlatformObservation{}, errors.New("platform observation unavailable")
	}
	operatingSystem, architecture := inspector.platform()
	observation, err := ports.NewPlatformObservation(operatingSystem, architecture)
	if err != nil {
		return ports.PlatformObservation{}, errors.New("platform observation failed")
	}
	return observation, nil
}

// ObservePermission reports effective access for a regular file or directory
// beneath root without following symlinks. It never changes ownership or modes.
func (inspector *Inspector) ObservePermission(ctx context.Context, root ports.AnchoredRoot, relative ports.SafeRelativePath) (ports.PermissionObservation, error) {
	if err := observationContext(ctx, "permission observation"); err != nil {
		return ports.PermissionObservation{}, err
	}
	if inspector == nil || inspector.permission == nil {
		return ports.PermissionObservation{}, errors.New("permission observation unavailable")
	}
	if !root.Valid() || !relative.Valid() {
		return ports.PermissionObservation{}, errors.New("permission observation invalid root or path")
	}

	readable, writable, executable, err := inspector.permission(root, relative)
	if err != nil {
		return ports.PermissionObservation{}, err
	}
	if err := observationContext(ctx, "permission observation"); err != nil {
		return ports.PermissionObservation{}, err
	}
	observation, err := ports.NewPermissionObservation(relative, readable, writable, executable)
	if err != nil {
		return ports.PermissionObservation{}, errors.New("permission observation failed")
	}
	return observation, nil
}

type permissionNodeIdentity struct {
	device    int32
	inode     uint64
	mode      uint16
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

type permissionTargetDescriptor struct {
	rootFD   int
	parentFD int
	targetFD int
	name     string
	identity permissionNodeIdentity
}

func (descriptor *permissionTargetDescriptor) Close() {
	_ = unix.Close(descriptor.targetFD)
	if descriptor.parentFD != descriptor.rootFD {
		_ = unix.Close(descriptor.parentFD)
	}
	_ = unix.Close(descriptor.rootFD)
}

// permissionRevalidateHook synchronizes deterministic namespace-mutation tests.
// Production leaves it nil.
var permissionRevalidateHook func()

func observePermissionDescriptor(root ports.AnchoredRoot, relative ports.SafeRelativePath) (bool, bool, bool, error) {
	target, err := openPermissionTarget(root, relative)
	if err != nil {
		return false, false, false, err
	}
	defer target.Close()

	readable, err := effectiveAccessAt(target.parentFD, target.name, target.identity, unix.R_OK)
	if err != nil {
		return false, false, false, err
	}
	writable, err := effectiveAccessAt(target.parentFD, target.name, target.identity, unix.W_OK)
	if err != nil {
		return false, false, false, err
	}
	executable, err := effectiveAccessAt(target.parentFD, target.name, target.identity, unix.X_OK)
	if err != nil {
		return false, false, false, err
	}
	if permissionRevalidateHook != nil {
		permissionRevalidateHook()
	}

	if err := revalidatePermissionTarget(root, relative, target.identity); err != nil {
		return false, false, false, err
	}
	return readable, writable, executable, nil
}

func revalidatePermissionTarget(root ports.AnchoredRoot, relative ports.SafeRelativePath, expected permissionNodeIdentity) error {
	reopened, err := openPermissionTarget(root, relative)
	if err != nil {
		return errors.New("permission observation target changed")
	}
	reopenedIdentity := reopened.identity
	reopened.Close()
	if reopenedIdentity != expected {
		return errors.New("permission observation target changed")
	}
	return nil
}
func openPermissionTarget(root ports.AnchoredRoot, relative ports.SafeRelativePath) (*permissionTargetDescriptor, error) {
	rootFD, err := unix.Open(root.String(), unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("permission observation invalid root")
	}

	parentFD := rootFD
	closePath := func() {
		if parentFD != rootFD {
			_ = unix.Close(parentFD)
		}
		_ = unix.Close(rootFD)
	}

	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		closePath()
		return nil, errors.New("permission observation invalid root")
	}

	components := strings.Split(relative.String(), "/")
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(
			parentFD,
			component,
			unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			closePath()
			return nil, errors.New("permission observation unsafe path")
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(nextFD, &stat); statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(nextFD)
			closePath()
			return nil, errors.New("permission observation unsafe path")
		}
		if parentFD != rootFD {
			_ = unix.Close(parentFD)
		}
		parentFD = nextFD
	}

	name := components[len(components)-1]
	targetFD, err := unix.Openat(parentFD, name, unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		closePath()
		return nil, errors.New("permission observation unsafe path")
	}
	var targetStat unix.Stat_t
	if err := unix.Fstat(targetFD, &targetStat); err != nil {
		_ = unix.Close(targetFD)
		closePath()
		return nil, errors.New("permission observation stat failed")
	}
	identity, err := permissionNodeFromStat(targetStat)
	if err != nil {
		_ = unix.Close(targetFD)
		closePath()
		return nil, errors.New("permission observation unsafe path")
	}
	return &permissionTargetDescriptor{
		rootFD:   rootFD,
		parentFD: parentFD,
		targetFD: targetFD,
		name:     name,
		identity: identity,
	}, nil
}

func effectiveAccessAt(parentFD int, name string, expected permissionNodeIdentity, mode uint32) (bool, error) {
	before, err := permissionNodeAt(parentFD, name)
	if err != nil || before != expected {
		return false, errors.New("permission observation target changed")
	}

	accessErr := unix.Faccessat(
		parentFD,
		name,
		mode,
		unix.AT_EACCESS|unix.AT_SYMLINK_NOFOLLOW,
	)

	after, err := permissionNodeAt(parentFD, name)
	if err != nil || after != expected {
		return false, errors.New("permission observation target changed")
	}
	if accessErr == nil {
		return true, nil
	}
	if accessDenied(accessErr) {
		return false, nil
	}
	return false, errors.New("permission observation access failed")
}

func permissionNodeAt(parentFD int, name string) (permissionNodeIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return permissionNodeIdentity{}, err
	}
	return permissionNodeFromStat(stat)
}

func permissionNodeFromStat(stat unix.Stat_t) (permissionNodeIdentity, error) {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return permissionNodeIdentity{}, errors.New("unsafe permission target")
	}
	return permissionNodeIdentity{
		device:    stat.Dev,
		inode:     stat.Ino,
		mode:      stat.Mode,
		size:      stat.Size,
		mtimeSec:  stat.Mtim.Sec,
		mtimeNsec: stat.Mtim.Nsec,
		ctimeSec:  stat.Ctim.Sec,
		ctimeNsec: stat.Ctim.Nsec,
	}, nil
}

func observationContext(ctx context.Context, operation string) error {
	if ctx == nil {
		return fmt.Errorf("%s: nil context", operation)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

// BootstrapEnvironment freezes production environment authority at startup.
type BootstrapEnvironment struct {
	home, xdgConfigHome, kimiCodeHome, path, tempRoot string
	pathEntries                                       []frozenPathEntry
	locales                                           map[string]string
	digest                                            string
	pathErr                                           error
	kimiCodeHomeErr                                   error
	projectRoot                                       string
}

type frozenPathEntry struct {
	path     string
	identity executableSnapshot
}

var allowedLocaleNames = map[string]struct{}{
	"LANG": {}, "LC_ALL": {}, "LC_COLLATE": {}, "LC_CTYPE": {},
	"LC_MESSAGES": {}, "LC_MONETARY": {}, "LC_NUMERIC": {}, "LC_TIME": {},
}

// NewBootstrapEnvironment captures explicit startup values. At most one project
// root is accepted; PATH directories beneath it are rejected.
func NewBootstrapEnvironment(home, xdgConfigHome, path, tempRoot string, locales map[string]string, projectRoots ...ports.AnchoredRoot) (*BootstrapEnvironment, error) {
	return NewBootstrapEnvironmentWithKimiCodeHome(home, xdgConfigHome, "", path, tempRoot, locales, projectRoots...)
}

// NewBootstrapEnvironmentWithKimiCodeHome captures the optional startup
// KIMI_CODE_HOME used only as local init discovery input.
func NewBootstrapEnvironmentWithKimiCodeHome(home, xdgConfigHome, kimiCodeHome, path, tempRoot string, locales map[string]string, projectRoots ...ports.AnchoredRoot) (*BootstrapEnvironment, error) {
	if len(projectRoots) > 1 {
		return nil, errors.New("environment bootstrap: multiple project roots")
	}
	for _, value := range []struct{ name, path string }{{"HOME", home}, {"temp root", tempRoot}} {
		if _, err := canonicalDirectoryIdentity(value.path); err != nil {
			return nil, fmt.Errorf("environment bootstrap: invalid %s", value.name)
		}
	}
	if xdgConfigHome != "" {
		if _, err := canonicalDirectoryIdentity(xdgConfigHome); err != nil {
			return nil, errors.New("environment bootstrap: invalid XDG_CONFIG_HOME")
		}
	}
	if kimiCodeHome != "" && (!filepath.IsAbs(kimiCodeHome) || filepath.Clean(kimiCodeHome) != kimiCodeHome || strings.ContainsRune(kimiCodeHome, 0)) {
		return nil, errors.New("environment bootstrap: invalid KIMI_CODE_HOME")
	}
	if path == "" {
		return nil, errors.New("environment bootstrap: empty PATH")
	}
	root := ""
	if len(projectRoots) == 1 {
		if !projectRoots[0].Valid() {
			return nil, errors.New("environment bootstrap: invalid project root")
		}
		root = projectRoots[0].String()
		if _, err := canonicalDirectoryIdentity(root); err != nil {
			return nil, errors.New("environment bootstrap: invalid project root")
		}
	}
	entries := strings.Split(path, ":")
	frozen := make([]frozenPathEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		identity, err := canonicalDirectoryIdentity(entry)
		if err != nil {
			return nil, errors.New("environment bootstrap: invalid PATH entry")
		}
		if _, exists := seen[entry]; exists {
			return nil, errors.New("environment bootstrap: duplicate PATH entry")
		}
		if root != "" && pathWithin(entry, root) {
			return nil, errors.New("environment bootstrap: PATH entry beneath project root")
		}
		seen[entry] = struct{}{}
		frozen = append(frozen, frozenPathEntry{path: entry, identity: identity})
	}
	frozenLocales := make(map[string]string, len(locales))
	for name, value := range locales {
		if _, allowed := allowedLocaleNames[name]; !allowed || strings.ContainsRune(value, 0) {
			return nil, errors.New("environment bootstrap: invalid locale")
		}
		frozenLocales[name] = value
	}
	environment := &BootstrapEnvironment{
		home: home, xdgConfigHome: xdgConfigHome, kimiCodeHome: kimiCodeHome, path: path, tempRoot: tempRoot,
		pathEntries: frozen, locales: frozenLocales,
	}
	environment.digest = environmentDigest(home, xdgConfigHome, kimiCodeHome, path, tempRoot, frozenLocales)
	return environment, nil
}

// NewStartupDiscoveryInspector captures PATH and KIMI_CODE_HOME once for init
// discovery. Invalid startup values are retained as deferred discovery errors
// so commands such as help do not become unavailable merely because discovery
// state is malformed. Relative executable lookup revalidates every captured
// PATH directory identity and never consults the ambient environment again.
func NewStartupDiscoveryInspector(pathValue, kimiCodeHome string, projectRoots ...ports.AnchoredRoot) *FrozenInspector {
	environment := &BootstrapEnvironment{
		path: pathValue, kimiCodeHome: kimiCodeHome, locales: map[string]string{},
	}
	if kimiCodeHome != "" && (!filepath.IsAbs(kimiCodeHome) || filepath.Clean(kimiCodeHome) != kimiCodeHome || strings.ContainsRune(kimiCodeHome, 0)) {
		environment.kimiCodeHome = ""
		environment.kimiCodeHomeErr = errors.New("environment bootstrap: invalid KIMI_CODE_HOME")
	}
	root := ""
	if len(projectRoots) > 1 || len(projectRoots) == 1 && !projectRoots[0].Valid() {
		environment.pathErr = errors.New("environment bootstrap: invalid project root")
	} else if len(projectRoots) == 1 {
		root = projectRoots[0].String()
		environment.projectRoot = root
	}
	if pathValue == "" {
		environment.pathErr = errors.Join(environment.pathErr, errors.New("environment bootstrap: empty PATH"))
	} else if environment.pathErr == nil {
		entries := strings.Split(pathValue, ":")
		seen := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			identity, err := canonicalDirectoryIdentity(entry)
			if err != nil {
				environment.pathErr = errors.New("environment bootstrap: invalid PATH entry")
				break
			}
			if _, exists := seen[entry]; exists {
				environment.pathErr = errors.New("environment bootstrap: duplicate PATH entry")
				break
			}
			if root != "" && pathWithin(entry, root) {
				environment.pathErr = errors.New("environment bootstrap: PATH entry beneath project root")
				break
			}
			seen[entry] = struct{}{}
			environment.pathEntries = append(environment.pathEntries, frozenPathEntry{path: entry, identity: identity})
		}
	}
	environment.digest = environmentDigest("", "", environment.kimiCodeHome, pathValue, "", nil)
	return &FrozenInspector{environment: environment}
}

func (environment *BootstrapEnvironment) Home() string {
	if environment == nil {
		return ""
	}
	return environment.home
}
func (environment *BootstrapEnvironment) XDGConfigHome() string {
	if environment == nil {
		return ""
	}
	return environment.xdgConfigHome
}
func (environment *BootstrapEnvironment) KimiCodeHome() string {
	if environment == nil {
		return ""
	}
	return environment.kimiCodeHome
}
func (environment *BootstrapEnvironment) Path() string {
	if environment == nil {
		return ""
	}
	return environment.path
}
func (environment *BootstrapEnvironment) TempRoot() string {
	if environment == nil {
		return ""
	}
	return environment.tempRoot
}
func (environment *BootstrapEnvironment) Digest() string {
	if environment == nil {
		return ""
	}
	return environment.digest
}

// Locales returns a caller-owned copy.
func (environment *BootstrapEnvironment) Locales() map[string]string {
	if environment == nil {
		return nil
	}
	values := make(map[string]string, len(environment.locales))
	for name, value := range environment.locales {
		values[name] = value
	}
	return values
}

func environmentDigest(home, xdgConfigHome, kimiCodeHome, path, tempRoot string, locales map[string]string) string {
	hash := sha256.New()
	for _, value := range []string{"HOME", home, "XDG_CONFIG_HOME", xdgConfigHome, "KIMI_CODE_HOME", kimiCodeHome, "PATH", path, "TEMP_ROOT", tempRoot} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	names := make([]string, 0, len(locales))
	for name := range locales {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(locales[name]))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, "../") && !filepath.IsAbs(relative)
}

func canonicalDirectoryIdentity(path string) (executableSnapshot, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return executableSnapshot{}, errors.New("not a canonical absolute directory")
	}
	fd, err := unix.Open("/", unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return executableSnapshot{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	if path != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			next, openErr := unix.Openat(fd, component, unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				return executableSnapshot{}, openErr
			}
			_ = unix.Close(fd)
			fd = next
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return executableSnapshot{}, errors.New("not a directory")
	}
	return snapshotFromStat(stat), nil
}

func observeNativeHomeIdentity(ctx context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	if err := observationContext(ctx, "native home observation"); err != nil {
		return ports.NativeHomeLaunchAuthority{}, err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ports.NativeHomeLaunchAuthority{}, identitySecurity("native home path is not canonical")
	}
	fd, err := unix.Open("/", unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.NativeHomeLaunchAuthority{}, identitySecurity("native home descriptor open failed")
	}
	defer func() { _ = unix.Close(fd) }()
	if path != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			next, openErr := unix.Openat(fd, component, unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				return ports.NativeHomeLaunchAuthority{}, identitySecurity("native home descriptor traversal failed")
			}
			_ = unix.Close(fd)
			fd = next
		}
	}
	if err := observationContext(ctx, "native home observation"); err != nil {
		return ports.NativeHomeLaunchAuthority{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(unix.Geteuid()) {
		return ports.NativeHomeLaunchAuthority{}, identitySecurity("native home identity is unsafe")
	}
	authority, err := ports.NewNativeHomeLaunchAuthority(path, uint64(stat.Dev), uint64(stat.Ino), stat.Uid)
	if err != nil {
		return ports.NativeHomeLaunchAuthority{}, identitySecurity("native home identity is invalid")
	}
	return authority, nil
}

func (environment *BootstrapEnvironment) revalidatePathEntry(entry frozenPathEntry) error {
	identity, err := canonicalDirectoryIdentity(entry.path)
	if err != nil || !entry.identity.stableSince(identity) {
		return errors.New("frozen PATH directory changed")
	}
	return nil
}

// FrozenInspector resolves executables through an immutable BootstrapEnvironment.
type FrozenInspector struct{ environment *BootstrapEnvironment }

var _ ports.EnvironmentInspector = (*FrozenInspector)(nil)

func NewFrozenInspector(environment *BootstrapEnvironment) (*FrozenInspector, error) {
	if environment == nil {
		return nil, errors.New("frozen inspector: environment unavailable")
	}
	return &FrozenInspector{environment: environment}, nil
}

func (environment *BootstrapEnvironment) Inspector() *FrozenInspector {
	inspector, _ := NewFrozenInspector(environment)
	return inspector
}

func (inspector *FrozenInspector) ObservePlatform(ctx context.Context) (ports.PlatformObservation, error) {
	if err := observationContext(ctx, "platform observation"); err != nil {
		return ports.PlatformObservation{}, err
	}
	return ports.NewPlatformObservation(runtime.GOOS, runtime.GOARCH)
}

func (inspector *FrozenInspector) ObservePermission(ctx context.Context, root ports.AnchoredRoot, relative ports.SafeRelativePath) (ports.PermissionObservation, error) {
	return NewInspector().ObservePermission(ctx, root, relative)
}

// ObserveNativeHomeIdentity captures one descriptor-bound native-home
// identity without consulting ambient HOME state.
func (inspector *FrozenInspector) ObserveNativeHomeIdentity(ctx context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	if inspector == nil || inspector.environment == nil {
		return ports.NativeHomeLaunchAuthority{}, errors.New("frozen native home observation unavailable")
	}
	return observeNativeHomeIdentity(ctx, path)
}

// ObserveExecutable never executes --version or consults ambient PATH.
func (inspector *FrozenInspector) ObserveExecutable(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	return inspector.ObserveExecutableIdentity(ctx, name)
}

// ObserveReadableFileIdentity observes only an exact canonical absolute file;
// readable launchers never consult startup or ambient PATH.
func (inspector *FrozenInspector) ObserveReadableFileIdentity(ctx context.Context, name string) (ports.FileIdentityObservation, error) {
	if inspector == nil || inspector.environment == nil {
		return ports.FileIdentityObservation{}, errors.New("frozen readable file observation unavailable")
	}
	return observeReadableFileIdentity(ctx, name)
}

// KimiCodeHome returns the startup-frozen optional KIMI_CODE_HOME authority.
func (inspector *FrozenInspector) KimiCodeHome() (string, error) {
	if inspector == nil || inspector.environment == nil {
		return "", errors.New("frozen environment unavailable")
	}
	return inspector.environment.KimiCodeHome(), inspector.environment.kimiCodeHomeErr
}

func (inspector *FrozenInspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	if inspector == nil || inspector.environment == nil {
		return ports.ExecutableObservation{}, errors.New("frozen executable observation unavailable")
	}
	absent, err := ports.NewExecutableObservation(name, false, "", "", "")
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable observation invalid name")
	}
	if filepath.IsAbs(name) {
		if filepath.Clean(name) != name {
			return ports.ExecutableObservation{}, identitySecurity("executable path is not canonical")
		}
		observation, observeErr := observeFrozenExecutable(ctx, name, name)
		if errors.Is(observeErr, fs.ErrNotExist) {
			return absent, nil
		}
		return observation, observeErr
	}
	if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
		return ports.ExecutableObservation{}, errors.New("executable observation invalid name")
	}
	if inspector.environment.pathErr != nil {
		return ports.ExecutableObservation{}, inspector.environment.pathErr
	}
	for _, entry := range inspector.environment.pathEntries {
		if err := inspector.environment.revalidatePathEntry(entry); err != nil {
			return ports.ExecutableObservation{}, err
		}
		candidate := filepath.Join(entry.path, name)
		resolved, resolveErr := filepath.EvalSymlinks(candidate)
		if resolveErr != nil {
			if errors.Is(resolveErr, fs.ErrNotExist) {
				continue
			}
			return ports.ExecutableObservation{}, errors.New("executable resolution failed")
		}
		resolved = filepath.Clean(resolved)
		if !filepath.IsAbs(resolved) || inspector.environment.projectRoot != "" && pathWithin(resolved, inspector.environment.projectRoot) {
			return ports.ExecutableObservation{}, errors.New("executable resolution escaped startup authority")
		}
		observation, observeErr := observeFrozenExecutable(ctx, name, resolved)
		if observeErr == nil {
			if err := inspector.environment.revalidatePathEntry(entry); err != nil {
				return ports.ExecutableObservation{}, err
			}
			return observation, nil
		}
		if errors.Is(observeErr, fs.ErrNotExist) {
			continue
		}
		return ports.ExecutableObservation{}, observeErr
	}
	return absent, nil
}

func observeFrozenExecutable(ctx context.Context, name, path string) (ports.ExecutableObservation, error) {
	parentIdentity, err := canonicalDirectoryIdentity(filepath.Dir(path))
	if err != nil {
		return ports.ExecutableObservation{}, identitySecurity("executable parent directory is unsafe")
	}
	file, err := openCanonicalExecutable(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return ports.ExecutableObservation{}, fs.ErrNotExist
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return ports.ExecutableObservation{}, identityUnavailable("executable is unavailable")
		}
		return ports.ExecutableObservation{}, identitySecurity("executable descriptor open failed")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return ports.ExecutableObservation{}, identityUnavailable("executable is not a bounded regular file")
	}
	executable, err := file.EffectiveExecutable(before)
	if err != nil || !executable {
		return ports.ExecutableObservation{}, identityUnavailable("executable permission is unavailable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, before.size+1)); err != nil {
		return ports.ExecutableObservation{}, identitySecurity("executable identity hash failed")
	}
	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	reopened, err := openCanonicalExecutable(path)
	if err != nil {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	reopenedSnapshot, statErr := reopened.Stat()
	_ = reopened.Close()
	if statErr != nil || !after.stableSince(reopenedSnapshot) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	parentAfter, err := canonicalDirectoryIdentity(filepath.Dir(path))
	if err != nil || !parentIdentity.stableSince(parentAfter) {
		return ports.ExecutableObservation{}, identitySecurity("executable parent directory changed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	return ports.NewExecutableObservation(name, true, path, "", "sha256:"+hex.EncodeToString(hash.Sum(nil)))
}
