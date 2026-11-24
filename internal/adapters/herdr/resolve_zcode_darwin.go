//go:build darwin && arm64

package herdr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const EnvHerdrZCodeBin = "MULGAE_HERDR_ZCODE_BIN"

const zcodeLauncherName = "herdr-zcode"

// ErrZCodeCompanionTeardown reports that the launcher did not establish that
// its supervised child was reaped.
var ErrZCodeCompanionTeardown = errors.New("companion teardown could not be verified")

// ErrZCodeCompanionTimeout reports expiration of the companion's own budget.
// The caller's context can still have budget when this error occurs.
var ErrZCodeCompanionTimeout = errors.New("companion command timed out")

// The runtime manifest excludes package documentation and tests.
var zcodeRuntimeFiles = [...]string{
	"bin/herdr-zcode",
	"bin/herdr-zcode-app.mjs",
	"lib/app-server-client.mjs",
	"lib/app-server-controller.mjs",
	"lib/desktop-account.mjs",
	"lib/desktop-catalog.mjs",
	"lib/desktop-keychain.mjs",
	"lib/desktop-runtime.mjs",
	"lib/error-classification.mjs",
	"lib/herdr-reporter.mjs",
	"lib/osc7501-reporter.mjs",
	"lib/prepare-isolated.mjs",
	"lib/runtime-profile.mjs",
	"lib/toolchain.mjs",
	"package.json",
	"scripts/desktop-bootstrap.pl",
	"scripts/tool-bin/npm",
	"scripts/tool-bin/npx",
	"scripts/toolchain.sh",
	"toolchains.env",
}

type ZCodePackage struct {
	Launcher      ResolvedExecutable
	PackageSHA256 string
}

func (p ZCodePackage) Device() int32 { return p.Launcher.device }
func (p ZCodePackage) Inode() uint64 { return p.Launcher.inode }

func DefaultZCodeResolveOptions(nativeHome string, excludedRoots ...string) ResolveOptions {
	opts := DefaultResolveOptions(nativeHome, excludedRoots...)
	opts.OverridePath, opts.HasOverride = os.LookupEnv(EnvHerdrZCodeBin)
	return opts
}

func ResolveZCodePackage(opts ResolveOptions) (ZCodePackage, error) {
	excluded, err := normalizeExcludedRoots(opts.ExcludedRoots)
	if err != nil {
		return ZCodePackage{}, fmt.Errorf("%w: invalid companion search exclusions", ErrUnsafeExecutable)
	}
	euid := uint32(unix.Geteuid())
	if opts.HasOverride {
		return verifyZCodePackage(opts.OverridePath, euid, excluded)
	}

	dirs := filepath.SplitList(opts.PathEnv)
	if validCanonicalAbsolutePath(opts.NativeHome) {
		dirs = append(dirs, filepath.Join(opts.NativeHome, ".local", "bin"))
	}
	var unsafe error
	for _, dir := range dirs {
		if _, err := resolveSafeDirectoryChain(dir, euid, excluded); err != nil {
			continue
		}
		candidate := filepath.Join(dir, zcodeLauncherName)
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			continue
		}
		pkg, err := verifyZCodePackage(candidate, euid, excluded)
		if err == nil {
			return pkg, nil
		}
		if unsafe == nil {
			unsafe = err
		}
	}
	if unsafe != nil {
		return ZCodePackage{}, unsafe
	}
	return ZCodePackage{}, ErrExecutableNotFound
}

func verifyZCodePackage(candidate string, euid uint32, excluded []string) (ZCodePackage, error) {
	launcher, err := verifyExecutableCandidate(candidate, euid, excluded)
	if err != nil {
		return ZCodePackage{}, fmt.Errorf("%w: companion launcher: %v", ErrUnsafeExecutable, err)
	}
	bin := filepath.Dir(launcher.Path)
	if filepath.Base(launcher.Path) != zcodeLauncherName || filepath.Base(bin) != "bin" {
		return ZCodePackage{}, fmt.Errorf("%w: companion launcher must be in package bin", ErrUnsafeExecutable)
	}
	root := filepath.Dir(bin)
	if pathWithinAnyRoot(root, excluded) {
		return ZCodePackage{}, fmt.Errorf("%w: companion package lies inside an excluded root", ErrUnsafeExecutable)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ZCodePackage{}, fmt.Errorf("%w: open companion package: %v", ErrUnsafeExecutable, err)
	}
	defer unix.Close(fd)
	if err := validateExecutableAncestorFD(fd, euid); err != nil {
		return ZCodePackage{}, fmt.Errorf("%w: companion package: %v", ErrUnsafeExecutable, err)
	}
	if err := descriptorPathMatches(fd, root); err != nil {
		return ZCodePackage{}, fmt.Errorf("%w: companion package: %v", ErrUnsafeExecutable, err)
	}

	aggregate := sha256.New()
	for _, member := range zcodeRuntimeFiles {
		if pathWithinAnyRoot(filepath.Join(root, member), excluded) {
			return ZCodePackage{}, fmt.Errorf("%w: companion member lies inside an excluded root", ErrUnsafeExecutable)
		}
		size, digest, stat, err := hashZCodePackageMember(fd, root, member, euid)
		if err != nil {
			return ZCodePackage{}, fmt.Errorf("%w: companion member %s: %v", ErrUnsafeExecutable, member, err)
		}
		if member == "bin/herdr-zcode" && (stat.Dev != launcher.device || stat.Ino != launcher.inode || "sha256:"+digest != launcher.SHA256) {
			return ZCodePackage{}, fmt.Errorf("%w: companion launcher changed during verification", ErrUnsafeExecutable)
		}
		_, _ = fmt.Fprintf(aggregate, "%s\t%d\t%s\n", member, size, digest)
	}
	return ZCodePackage{Launcher: launcher, PackageSHA256: hex.EncodeToString(aggregate.Sum(nil))}, nil
}

func hashZCodePackageMember(rootFD int, root, member string, euid uint32) (int64, string, unix.Stat_t, error) {
	dirFD := rootFD
	components := strings.Split(member, "/")
	for _, component := range components[:len(components)-1] {
		nextFD, err := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if dirFD != rootFD {
			_ = unix.Close(dirFD)
		}
		if err != nil {
			return 0, "", unix.Stat_t{}, err
		}
		dirFD = nextFD
		if err := validateExecutableAncestorFD(dirFD, euid); err != nil {
			_ = unix.Close(dirFD)
			return 0, "", unix.Stat_t{}, err
		}
	}
	if dirFD != rootFD {
		defer unix.Close(dirFD)
	}
	fd, err := unix.Openat(dirFD, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, "", unix.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), member)
	defer file.Close()
	if err := descriptorPathMatches(fd, filepath.Join(root, member)); err != nil {
		return 0, "", unix.Stat_t{}, err
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return 0, "", unix.Stat_t{}, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
		(before.Uid != 0 && before.Uid != euid) || before.Mode&0o7022 != 0 {
		return 0, "", unix.Stat_t{}, fmt.Errorf("unsafe runtime file identity")
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return 0, "", unix.Stat_t{}, err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return 0, "", unix.Stat_t{}, err
	}
	if size != before.Size || before.Size != after.Size || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Nlink != after.Nlink ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return 0, "", unix.Stat_t{}, fmt.Errorf("runtime file changed during verification")
	}
	return size, hex.EncodeToString(hasher.Sum(nil)), after, nil
}

// VerifySpawn revalidates the retained launcher identity and all runtime bytes.
func (p ZCodePackage) VerifySpawn() error {
	current, err := verifyZCodePackage(p.Launcher.Path, uint32(unix.Geteuid()), nil)
	if err != nil {
		return err
	}
	if current != p {
		return fmt.Errorf("%w: companion package identity drift", ErrUnsafeExecutable)
	}
	return nil
}

type ZCodeCompanionObservation struct {
	Version        string
	AppVersion     string
	AppBundle      string
	MinimumVersion string
}

// ObserveZCodeCompanion executes only the companion's offline diagnostics.
func ObserveZCodeCompanion(ctx context.Context, pkg ZCodePackage, appBundle string) (ZCodeCompanionObservation, error) {
	if ctx == nil || (appBundle != "" && !validCanonicalAbsolutePath(appBundle)) {
		return ZCodeCompanionObservation{}, fmt.Errorf("invalid companion diagnostic authority")
	}
	options := []string{"--json"}
	if appBundle != "" {
		options = append(options, "--app-bundle", appBundle)
	}
	var version struct {
		Name         string   `json:"name"`
		Version      string   `json:"version"`
		Runtimes     []string `json:"runtimes"`
		OSC7501      bool     `json:"osc7501"`
		Capabilities []string `json:"capabilities"`
	}
	if err := runZCodeDiagnostic(ctx, pkg, &version, append([]string{"--version"}, options...)...); err != nil {
		return ZCodeCompanionObservation{}, err
	}
	if version.Name != zcodeLauncherName || version.Version == "" || !version.OSC7501 || !slices.Contains(version.Runtimes, "core") {
		return ZCodeCompanionObservation{}, fmt.Errorf("invalid companion version observation")
	}
	for _, capability := range []string{"core", "osc7501", "catalogFile", "prepareIsolated", "checkDesktop"} {
		if !slices.Contains(version.Capabilities, capability) {
			return ZCodeCompanionObservation{}, fmt.Errorf("companion does not advertise %s", capability)
		}
	}
	var desktop struct {
		Compatible     bool   `json:"compatible"`
		AppVersion     string `json:"appVersion"`
		AppBundle      string `json:"appBundle"`
		MinimumVersion string `json:"minZcodeAppVersion"`
	}
	if err := runZCodeDiagnostic(ctx, pkg, &desktop, append([]string{"--check-desktop"}, options...)...); err != nil {
		return ZCodeCompanionObservation{}, err
	}
	if !desktop.Compatible || desktop.AppVersion == "" || desktop.MinimumVersion == "" ||
		!validCanonicalAbsolutePath(desktop.AppBundle) || (appBundle != "" && appBundle != desktop.AppBundle) {
		return ZCodeCompanionObservation{}, fmt.Errorf("invalid companion desktop observation")
	}
	return ZCodeCompanionObservation{
		Version: version.Version, AppVersion: desktop.AppVersion,
		AppBundle: desktop.AppBundle, MinimumVersion: desktop.MinimumVersion,
	}, nil
}

func runZCodeDiagnostic(ctx context.Context, pkg ZCodePackage, output any, args ...string) error {
	var capture zcodeDiagnosticCapture
	if err := pkg.RunOfflineCommand(ctx, 10*time.Second, "/private/var/empty", &capture, args...); err != nil {
		if errors.Is(err, ErrUnsafeExecutable) || errors.Is(err, ErrZCodeCompanionTeardown) || errors.Is(err, ErrZCodeCompanionTimeout) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("companion diagnostic failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(capture))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("invalid companion diagnostic JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing companion diagnostic content")
	}
	return nil
}

// RunOfflineCommand starts an exact verified companion. Cancellation first
// reaches the launcher's handlers because its bootstrap can own a child in a
// separate session. Killing the launcher's group alone would bypass its reap.
// A graceful normal exit means the pinned launcher completed its child wait.
// A forced exit, a surviving group, or an inherited open pipe cannot prove it.
func (p ZCodePackage) RunOfflineCommand(ctx context.Context, limit time.Duration, home string, stdout io.Writer, args ...string) error {
	const cleanupReserve = 2 * time.Second
	if ctx == nil || limit <= cleanupReserve || !validCanonicalAbsolutePath(home) || stdout == nil {
		return fmt.Errorf("invalid companion execution authority")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	workCtx, cancel := context.WithTimeoutCause(ctx, limit-cleanupReserve, ErrZCodeCompanionTimeout)
	defer cancel()
	if err := p.VerifySpawn(); err != nil {
		return err
	}
	cmd := exec.CommandContext(workCtx, p.Launcher.Path, args...)
	cmd.Dir = "/private/var/empty"
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "TMPDIR=/tmp"}
	cmd.Stdout = stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	// Leave budget after WaitDelay for forcing the identified original
	// process group to stop, including when stdout was held by a descendant.
	cmd.WaitDelay = cleanupReserve / 2
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if context.Cause(workCtx) == ErrZCodeCompanionTimeout {
			return ErrZCodeCompanionTimeout
		}
		return err
	}
	pid := cmd.Process.Pid
	// Retain the group's identity before Wait can reap and release the PID.
	info, inspectErr := inspectProcess(pid)
	if !validTargetPID(pid) || inspectErr != nil || !info.Exists || info.PGID != pid || !hasStartTime(info.StartSec, info.StartUsec) {
		// Process.Signal uses the owned os.Process handle. An unverified
		// group must not be signaled by its numeric ID.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return ErrZCodeCompanionTeardown
	}
	tracked := trackedProcess{PID: pid, StartSec: info.StartSec, StartUsec: info.StartUsec}
	err := cmd.Wait()
	state, stateErr := inspectTrackedProcessGroup(tracked)
	if stateErr != nil {
		return ErrZCodeCompanionTeardown
	}
	if state.groupStillExists {
		deadline := time.Now().Add(cleanupReserve / 2)
		if err := ensureTrackedProcessGroupStopped(tracked, deadline); err != nil {
			return errors.Join(ErrZCodeCompanionTeardown, err)
		}
		// Same-PGID cleanup cannot establish that a separate-session
		// producer child was reaped after a noncooperative exit.
		return ErrZCodeCompanionTeardown
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() || errors.Is(err, exec.ErrWaitDelay) {
		return ErrZCodeCompanionTeardown
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if context.Cause(workCtx) == ErrZCodeCompanionTimeout {
		return ErrZCodeCompanionTimeout
	}
	return err
}

type zcodeDiagnosticCapture []byte

func (capture *zcodeDiagnosticCapture) Write(p []byte) (int, error) {
	const limit = 16 * 1024
	if len(p) > limit-len(*capture) {
		return 0, fmt.Errorf("companion diagnostic output exceeds limit")
	}
	*capture = append(*capture, p...)
	return len(p), nil
}
