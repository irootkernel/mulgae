//go:build darwin && arm64

// Package environment provides Darwin environment-observation adapters for ports.
package environment

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

// Inspector observes local platform, executable, and permission state without
// executing provider binaries or changing process state.
type Inspector struct {
	lookup        func(string) (string, error)
	evaluateLinks func(string) (string, error)
	executable    func(string) (executableDescriptor, error)
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
	permission    func(ports.AnchoredRoot, ports.SafeRelativePath) (bool, bool, bool, error)
	platform      func() (string, string)
}

func newInspector(dependencies inspectorDependencies) *Inspector {
	inspector := &Inspector{
		lookup:        exec.LookPath,
		evaluateLinks: filepath.EvalSymlinks,
		executable:    openCanonicalExecutable,
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
