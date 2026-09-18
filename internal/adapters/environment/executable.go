//go:build darwin && arm64

package environment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

// maximumExecutableSize bounds executable observation I/O and hashing work to 512 MiB.
const maximumExecutableSize int64 = 512 * 1024 * 1024
const maximumApplicationMetadataSize int64 = 1 << 20
const executableVersionTimeout = 5 * time.Second
const maximumVersionOutputBytes = 64 << 10

var (
	executableSemanticVersionPattern = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+`)
	errUnsafeDirectoryComponent      = errors.New("unsafe directory component")
)

func identityUnavailable(text string) error {
	return ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, text)
}

func identityUnavailableFor(reason ports.IdentityObservationFailureReason, text string) error {
	return ports.NewIdentityObservationErrorWithReason(ports.IdentityObservationUnavailable, reason, text)
}

func identitySecurity(text string) error {
	return ports.NewIdentityObservationError(ports.IdentityObservationSecurity, text)
}

func observeExecutableVersion(ctx context.Context, path string) ([]byte, error) {
	command := exec.CommandContext(ctx, path, "--version")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 250 * time.Millisecond
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// ProviderVersionObserver executes only an adapter-owned local version argv.
// It uses a disposable empty home and never projects provider credentials or a
// project working directory.
type ProviderVersionObserver struct{}

func NewProviderVersionObserver() ProviderVersionObserver { return ProviderVersionObserver{} }

func (ProviderVersionObserver) ObserveProviderVersion(
	ctx context.Context, family string, argv []string, identity ports.ProviderVersionIdentity,
) (observation ports.ProviderVersionObservation, resultErr error) {
	if ctx == nil || len(argv) < 2 || argv[len(argv)-1] != "--version" {
		return ports.ProviderVersionObservation{}, fmt.Errorf("provider version observation: invalid request")
	}
	switch family {
	case providercli.FamilyZcode, providercli.FamilyGrok, providercli.FamilyCodex:
	default:
		return ports.ProviderVersionObservation{}, fmt.Errorf("provider version observation: unsupported family")
	}
	executable, launcher := argv[0], argv[0]
	if family == string(providercli.FamilyZcode) {
		if len(argv) != 3 || identity.ZCodeProviderConfig == "" || identity.ZCodeProviderConfigSHA256 == "" ||
			identity.ApplicationMetadata == "" || identity.ApplicationMetadataSHA256 == "" {
			return ports.ProviderVersionObservation{}, fmt.Errorf("provider version observation: invalid zcode argv")
		}
		launcher = argv[1]
	} else if len(argv) != 2 || identity.ZCodeProviderConfig != "" || identity.ZCodeProviderConfigSHA256 != "" ||
		identity.ApplicationMetadata != "" || identity.ApplicationMetadataSHA256 != "" {
		return ports.ProviderVersionObservation{}, fmt.Errorf("provider version observation: invalid direct argv")
	}
	if err := verifySpawnIdentity(ctx, executable, identity.ExecutableSHA256); err != nil {
		return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
	}
	verifyLauncher := verifySpawnIdentity
	if family == string(providercli.FamilyZcode) {
		verifyLauncher = verifyReadableSpawnIdentity
	}
	if err := verifyLauncher(ctx, launcher, identity.LauncherSHA256); err != nil {
		return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
	}
	if family == string(providercli.FamilyZcode) {
		if err := verifyReadableSpawnIdentity(ctx, identity.ZCodeProviderConfig, identity.ZCodeProviderConfigSHA256); err != nil {
			return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
		}
		if err := verifyReadableSpawnIdentity(ctx, identity.ApplicationMetadata, identity.ApplicationMetadataSHA256); err != nil {
			return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
		}
	}

	runtimeRoot, err := os.MkdirTemp("", "mulgae-version-")
	if err != nil {
		return ports.ProviderVersionObservation{}, fmt.Errorf("provider version observation: create runtime: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(runtimeRoot); cleanupErr != nil && resultErr == nil {
			observation = ports.ProviderVersionObservation{}
			resultErr = fmt.Errorf("provider version observation: cleanup runtime: %w", cleanupErr)
		}
	}()
	versionContext, cancel := context.WithTimeout(ctx, executableVersionTimeout)
	defer cancel()
	command := exec.CommandContext(versionContext, executable, argv[1:]...)
	command.Dir = runtimeRoot
	command.Env = []string{
		"HOME=" + runtimeRoot,
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeRoot, "config"),
		"XDG_DATA_HOME=" + filepath.Join(runtimeRoot, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeRoot, "cache"),
		"TMPDIR=" + runtimeRoot,
		"TMP=" + runtimeRoot,
		"TEMP=" + runtimeRoot,
	}
	if family == providercli.FamilyZcode {
		command.Env = append(command.Env, "ELECTRON_RUN_AS_NODE=1")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 250 * time.Millisecond
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		killErr := unix.Kill(-command.Process.Pid, unix.SIGKILL)
		if errors.Is(killErr, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return killErr
	}
	var stdout, stderr boundedVersionCapture
	command.Stdout, command.Stderr = &stdout, &stderr
	runErr := command.Run()
	if errors.Is(versionContext.Err(), context.DeadlineExceeded) {
		return ports.NewProviderVersionObservation(ports.ProviderVersionTimedOut, "")
	}
	if runErr != nil {
		return ports.NewProviderVersionObservation(ports.ProviderVersionExecutionFailed, "")
	}
	if stdout.overflow || stderr.overflow {
		return ports.NewProviderVersionObservation(ports.ProviderVersionMalformed, "")
	}
	if err := verifySpawnIdentity(ctx, executable, identity.ExecutableSHA256); err != nil {
		return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
	}
	if err := verifyLauncher(ctx, launcher, identity.LauncherSHA256); err != nil {
		return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
	}
	if family == string(providercli.FamilyZcode) {
		if err := verifyReadableSpawnIdentity(ctx, identity.ZCodeProviderConfig, identity.ZCodeProviderConfigSHA256); err != nil {
			return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
		}
		if err := verifyReadableSpawnIdentity(ctx, identity.ApplicationMetadata, identity.ApplicationMetadataSHA256); err != nil {
			return ports.NewProviderVersionObservation(ports.ProviderVersionUnsafeIdentity, "")
		}
	}
	version := safeExecutableVersion(stdout.Bytes())
	if version == "" {
		return ports.NewProviderVersionObservation(ports.ProviderVersionMalformed, "")
	}
	return ports.NewProviderVersionObservation(ports.ProviderVersionObserved, version)
}

type boundedVersionCapture struct {
	bytes.Buffer
	overflow bool
}

func (capture *boundedVersionCapture) Write(data []byte) (int, error) {
	original := len(data)
	remaining := maximumVersionOutputBytes - capture.Len()
	if remaining <= 0 {
		capture.overflow = capture.overflow || original > 0
		return original, nil
	}
	if len(data) > remaining {
		capture.overflow = true
		data = data[:remaining]
	}
	_, _ = capture.Buffer.Write(data)
	return original, nil
}

func safeExecutableVersion(output []byte) string {
	if !utf8.Valid(output) {
		return ""
	}
	text := strings.TrimSpace(string(output))
	for _, character := range text {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return ""
		}
	}
	indexes := executableSemanticVersionPattern.FindAllStringIndex(text, -1)
	if len(indexes) != 1 {
		return ""
	}
	start, end := indexes[0][0], indexes[0][1]
	if start > 0 && executableVersionTokenCharacter(text[start-1]) ||
		end < len(text) && executableVersionTokenCharacter(text[end]) {
		return ""
	}
	version := strings.TrimPrefix(strings.TrimPrefix(text[start:end], "v"), "V")
	if len(version) > 256 {
		return ""
	}
	return version
}
func executableVersionTokenCharacter(character byte) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character == '.' || character == '-' || character == '+'
}

type executableSnapshot struct {
	device    int32
	inode     uint64
	mode      uint16
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

func (snapshot executableSnapshot) isRegular() bool {
	return uint32(snapshot.mode)&unix.S_IFMT == unix.S_IFREG
}

func (snapshot executableSnapshot) sameFile(other executableSnapshot) bool {
	return snapshot.device == other.device && snapshot.inode == other.inode
}

func (snapshot executableSnapshot) stableSince(other executableSnapshot) bool {
	return snapshot.sameFile(other) &&
		snapshot.mode == other.mode &&
		snapshot.size == other.size &&
		snapshot.mtimeSec == other.mtimeSec &&
		snapshot.mtimeNsec == other.mtimeNsec &&
		snapshot.ctimeSec == other.ctimeSec &&
		snapshot.ctimeNsec == other.ctimeNsec
}

type executableDescriptor interface {
	io.Reader
	Close() error
	Stat() (executableSnapshot, error)
	EffectiveExecutable(executableSnapshot) (bool, error)
}

type darwinExecutableDescriptor struct {
	file     *os.File
	parentFD int
	name     string
}

func (descriptor *darwinExecutableDescriptor) Read(buffer []byte) (int, error) {
	return descriptor.file.Read(buffer)
}

func (descriptor *darwinExecutableDescriptor) Close() error {
	fileErr := descriptor.file.Close()
	parentErr := unix.Close(descriptor.parentFD)
	if fileErr != nil {
		return fileErr
	}
	return parentErr
}

func (descriptor *darwinExecutableDescriptor) Stat() (executableSnapshot, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(descriptor.file.Fd()), &stat); err != nil {
		return executableSnapshot{}, err
	}
	return snapshotFromStat(stat), nil
}

func (descriptor *darwinExecutableDescriptor) EffectiveExecutable(expected executableSnapshot) (bool, error) {
	before, err := executableSnapshotAt(descriptor.parentFD, descriptor.name)
	if err != nil || !before.sameFile(expected) {
		return false, fmt.Errorf("%w: executable target changed", ports.ErrProviderSpawnEnvironmentDrift)
	}

	accessErr := unix.Faccessat(
		descriptor.parentFD,
		descriptor.name,
		unix.X_OK,
		unix.AT_EACCESS|unix.AT_SYMLINK_NOFOLLOW,
	)

	after, err := executableSnapshotAt(descriptor.parentFD, descriptor.name)
	if err != nil || !after.sameFile(expected) {
		return false, fmt.Errorf("%w: executable target changed", ports.ErrProviderSpawnEnvironmentDrift)
	}
	if accessErr == nil {
		return true, nil
	}
	if accessDenied(accessErr) {
		return false, nil
	}
	return false, errors.New("executable access failed")
}

func openCanonicalExecutable(path string) (executableDescriptor, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("not a canonical absolute executable path")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(components) == 0 || components[0] == "" {
		return nil, errors.New("invalid executable path")
	}

	parentFD, err := unix.Open("/", unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := openCanonicalDirectoryComponent(parentFD, component)
		_ = unix.Close(parentFD)
		if openErr != nil {
			return nil, openErr
		}
		parentFD = nextFD
	}

	name := components[len(components)-1]
	fileFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, err
	}
	return &darwinExecutableDescriptor{
		file:     os.NewFile(uintptr(fileFD), path),
		parentFD: parentFD,
		name:     name,
	}, nil
}

func openCanonicalDirectoryComponent(parentFD int, component string) (int, error) {
	fd, err := unix.Openat(parentFD, component, unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, unix.ELOOP) {
		return -1, errUnsafeDirectoryComponent
	}
	if !errors.Is(err, unix.ENOTDIR) {
		return -1, err
	}
	var entry unix.Stat_t
	if statErr := unix.Fstatat(parentFD, component, &entry, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
		return -1, errUnsafeDirectoryComponent
	}
	if entry.Mode&unix.S_IFMT == unix.S_IFLNK || entry.Mode&unix.S_IFMT == unix.S_IFDIR {
		return -1, errUnsafeDirectoryComponent
	}
	return -1, err
}

func executableSnapshotAt(parentFD int, name string) (executableSnapshot, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return executableSnapshot{}, err
	}
	snapshot := snapshotFromStat(stat)
	if !snapshot.isRegular() {
		return executableSnapshot{}, errors.New("executable target is not a regular file")
	}
	return snapshot, nil
}

func snapshotFromStat(stat unix.Stat_t) executableSnapshot {
	return executableSnapshot{
		device:    stat.Dev,
		inode:     stat.Ino,
		mode:      stat.Mode,
		size:      stat.Size,
		mtimeSec:  stat.Mtim.Sec,
		mtimeNsec: stat.Mtim.Nsec,
		ctimeSec:  stat.Ctim.Sec,
		ctimeNsec: stat.Ctim.Nsec,
	}
}

func accessDenied(err error) bool {
	return errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EROFS)
}

// ObserveExecutableIdentity resolves name through PATH, verifies the final target,
// and records its exact byte hash without executing the discovered file.
func (inspector *Inspector) ObserveExecutableIdentity(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	absent, err := ports.NewExecutableObservation(name, false, "", "", "")
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable observation invalid name")
	}
	if inspector == nil || inspector.lookup == nil || inspector.evaluateLinks == nil || inspector.executable == nil {
		return ports.ExecutableObservation{}, errors.New("executable observation unavailable")
	}

	var absolute string
	if filepath.IsAbs(name) {
		if filepath.Clean(name) != name {
			return ports.ExecutableObservation{}, identitySecurity("executable path is not canonical")
		}
		absolute = name
	} else {
		located, lookupErr := inspector.lookup(name)
		if lookupErr != nil {
			if errors.Is(lookupErr, exec.ErrNotFound) || errors.Is(lookupErr, fs.ErrNotExist) || errors.Is(lookupErr, os.ErrNotExist) {
				return absent, nil
			}
			return ports.ExecutableObservation{}, errors.New("executable lookup failed")
		}
		if located == "" {
			return ports.ExecutableObservation{}, errors.New("executable lookup failed")
		}
		var err error
		absolute, err = filepath.Abs(located)
		if err != nil {
			return ports.ExecutableObservation{}, errors.New("executable resolution failed")
		}
	}
	resolved := absolute
	if !filepath.IsAbs(name) {
		var err error
		resolved, err = inspector.evaluateLinks(absolute)
		if err != nil {
			return ports.ExecutableObservation{}, errors.New("executable resolution failed")
		}
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return ports.ExecutableObservation{}, errors.New("executable resolution failed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}

	file, err := inspector.executable(resolved)
	if err != nil || file == nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return ports.ExecutableObservation{}, identityUnavailable("executable is unavailable")
		}
		return ports.ExecutableObservation{}, identitySecurity("executable descriptor open failed")
	}
	defer func() { _ = file.Close() }()

	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return ports.ExecutableObservation{}, identitySecurity("executable is not a bounded regular file")
	}
	executable, err := file.EffectiveExecutable(before)
	if err != nil {
		return ports.ExecutableObservation{}, identityUnavailable("executable access is unavailable")
	}
	if !executable {
		return ports.ExecutableObservation{}, identityUnavailableFor(ports.IdentityObservationReasonNonExecutable, "executable permission is unavailable")
	}

	hash := sha256.New()
	buffer := make([]byte, 32*1024)
	remaining := before.size
	for remaining > 0 {
		if err := observationContext(ctx, "executable observation"); err != nil {
			return ports.ExecutableObservation{}, err
		}
		chunk := buffer
		if remaining < int64(len(chunk)) {
			chunk = chunk[:int(remaining)]
		}
		read, readErr := file.Read(chunk)
		if read < 0 || read > len(chunk) {
			return ports.ExecutableObservation{}, identitySecurity("executable identity hash failed")
		}
		if read > 0 {
			if _, err := hash.Write(chunk[:read]); err != nil {
				return ports.ExecutableObservation{}, fmt.Errorf("executable hash failed: %w", err)
			}
			remaining -= int64(read)
		}
		if err := observationContext(ctx, "executable observation"); err != nil {
			return ports.ExecutableObservation{}, err
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && remaining == 0 {
				break
			}
			return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
		}
		if read == 0 {
			return ports.ExecutableObservation{}, identitySecurity("executable identity hash failed")
		}
	}

	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	var overflow [1]byte
	read, readErr := file.Read(overflow[:])
	if read < 0 || read > len(overflow) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity hash failed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	if read > 0 {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	if !errors.Is(readErr, io.EOF) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity hash failed")
	}

	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	reopened, err := inspector.executable(resolved)
	if err != nil || reopened == nil {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	defer func() { _ = reopened.Close() }()
	reopenedSnapshot, err := reopened.Stat()
	if err != nil || !after.stableSince(reopenedSnapshot) {
		return ports.ExecutableObservation{}, identitySecurity("executable identity changed during hash")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	version := ""
	observation, err := ports.NewExecutableObservation(name, true, resolved, version, "sha256:"+hex.EncodeToString(hash.Sum(nil)))
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable observation failed")
	}
	return observation, nil
}

// ObserveReadableFileIdentity descriptor-opens and hashes one exact canonical
// absolute regular file without imposing executable or version semantics.
func (inspector *Inspector) ObserveReadableFileIdentity(ctx context.Context, name string) (ports.FileIdentityObservation, error) {
	return observeReadableFileIdentity(ctx, name)
}

// ObserveApplicationMetadata descriptor-reads one exact Info.plist and binds
// CFBundleShortVersionString to its stable content identity.
func (inspector *Inspector) ObserveApplicationMetadata(ctx context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	return observeApplicationMetadata(ctx, name)
}

// ObserveNativeHomeIdentity captures one descriptor-bound native-home
// identity without consulting ambient HOME state.
func (inspector *Inspector) ObserveNativeHomeIdentity(ctx context.Context, path string) (ports.NativeHomeLaunchAuthority, error) {
	return observeNativeHomeIdentity(ctx, path)
}

func observeReadableFileIdentity(ctx context.Context, name string) (ports.FileIdentityObservation, error) {
	if err := observationContext(ctx, "readable file observation"); err != nil {
		return ports.FileIdentityObservation{}, err
	}
	absent, err := ports.NewFileIdentityObservation(name, false, "", "")
	if err != nil {
		return ports.FileIdentityObservation{}, errors.New("readable file observation invalid name")
	}
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ports.FileIdentityObservation{}, identitySecurity("readable file path is not canonical absolute")
	}
	parentIdentity, err := canonicalDirectoryIdentity(filepath.Dir(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return absent, nil
		}
		return ports.FileIdentityObservation{}, identitySecurity("readable file parent directory is unsafe")
	}
	file, err := openCanonicalExecutable(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return absent, nil
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return ports.FileIdentityObservation{}, identityUnavailableFor(ports.IdentityObservationReasonUnreadable, "readable file is unavailable")
		}
		return ports.FileIdentityObservation{}, identitySecurity("readable file descriptor open failed")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return ports.FileIdentityObservation{}, identitySecurity("readable file is not a bounded regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, before.size+1)); err != nil {
		return ports.FileIdentityObservation{}, identitySecurity("readable file identity hash failed")
	}
	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return ports.FileIdentityObservation{}, identitySecurity("readable file identity changed during hash")
	}
	reopened, err := openCanonicalExecutable(name)
	if err != nil {
		return ports.FileIdentityObservation{}, identitySecurity("readable file identity changed during hash")
	}
	reopenedSnapshot, statErr := reopened.Stat()
	_ = reopened.Close()
	if statErr != nil || !after.stableSince(reopenedSnapshot) {
		return ports.FileIdentityObservation{}, identitySecurity("readable file identity changed during hash")
	}
	parentAfter, err := canonicalDirectoryIdentity(filepath.Dir(name))
	if err != nil || !parentIdentity.stableSince(parentAfter) {
		return ports.FileIdentityObservation{}, identitySecurity("readable file parent directory changed")
	}
	if err := observationContext(ctx, "readable file observation"); err != nil {
		return ports.FileIdentityObservation{}, err
	}
	return ports.NewFileIdentityObservation(name, true, name, "sha256:"+hex.EncodeToString(hash.Sum(nil)))
}

func observeApplicationMetadata(ctx context.Context, name string) (ports.ApplicationMetadataObservation, error) {
	if err := observationContext(ctx, "application metadata observation"); err != nil {
		return ports.ApplicationMetadataObservation{}, err
	}
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata path is not canonical absolute")
	}
	parentIdentity, err := canonicalDirectoryIdentity(filepath.Dir(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return ports.ApplicationMetadataObservation{}, identityUnavailableFor(ports.IdentityObservationReasonUnreadable, "application metadata is unavailable")
		}
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata parent directory is unsafe")
	}
	file, err := openCanonicalExecutable(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return ports.ApplicationMetadataObservation{}, identityUnavailableFor(ports.IdentityObservationReasonUnreadable, "application metadata is unavailable")
		}
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata descriptor open failed")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size <= 0 || before.size > maximumApplicationMetadataSize {
		return ports.ApplicationMetadataObservation{}, identityUnavailableFor(ports.IdentityObservationReasonMalformed, "application metadata is not a bounded regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, before.size+1))
	if err != nil || int64(len(contents)) != before.size {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata identity read failed")
	}
	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata identity changed during read")
	}
	reopened, err := openCanonicalExecutable(name)
	if err != nil {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata identity changed during read")
	}
	reopenedSnapshot, statErr := reopened.Stat()
	_ = reopened.Close()
	if statErr != nil || !after.stableSince(reopenedSnapshot) {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata identity changed during read")
	}
	parentAfter, err := canonicalDirectoryIdentity(filepath.Dir(name))
	if err != nil || !parentIdentity.stableSince(parentAfter) {
		return ports.ApplicationMetadataObservation{}, identitySecurity("application metadata parent directory changed")
	}
	version, err := applicationShortVersion(contents)
	if err != nil {
		return ports.ApplicationMetadataObservation{}, identityUnavailableFor(ports.IdentityObservationReasonMalformed, "application metadata version is malformed")
	}
	if err := observationContext(ctx, "application metadata observation"); err != nil {
		return ports.ApplicationMetadataObservation{}, err
	}
	digest := sha256.Sum256(contents)
	observation, err := ports.NewApplicationMetadataObservation(name, "sha256:"+hex.EncodeToString(digest[:]), version)
	if err != nil {
		return ports.ApplicationMetadataObservation{}, identityUnavailableFor(ports.IdentityObservationReasonMalformed, "application metadata version is malformed")
	}
	return observation, nil
}

func applicationShortVersion(contents []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	depth := 0
	rootSeen := false
	dictionarySeen := false
	rootClosed := false
	wantValue := false
	versionKeySeen := false
	version := ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if rootClosed {
				return "", errors.New("invalid application metadata root")
			}
			if depth == 0 {
				if rootSeen || value.Name.Local != "plist" {
					return "", errors.New("invalid application metadata root")
				}
				rootSeen = true
				depth++
				continue
			}
			if depth == 1 {
				if dictionarySeen || value.Name.Local != "dict" {
					return "", errors.New("invalid application metadata dictionary")
				}
				dictionarySeen = true
				depth++
				continue
			}
			if depth == 2 && wantValue {
				if value.Name.Local != "string" || version != "" {
					return "", errors.New("invalid application version value")
				}
				if err := decoder.DecodeElement(&version, &value); err != nil {
					return "", err
				}
				wantValue = false
				continue
			}
			if depth == 2 && value.Name.Local == "key" {
				var key string
				if err := decoder.DecodeElement(&key, &value); err != nil {
					return "", err
				}
				if key == "CFBundleShortVersionString" {
					if versionKeySeen {
						return "", errors.New("duplicate application version")
					}
					versionKeySeen = true
					wantValue = true
				}
				continue
			}
			depth++
		case xml.EndElement:
			if depth == 2 && value.Name.Local == "dict" {
				if wantValue {
					return "", errors.New("missing application version value")
				}
			}
			if depth == 1 && value.Name.Local == "plist" {
				rootClosed = true
			}
			depth--
			if depth < 0 {
				return "", errors.New("invalid application metadata nesting")
			}
		case xml.CharData:
			if wantValue && strings.TrimSpace(string(value)) != "" {
				return "", errors.New("invalid application version value")
			}
		}
	}
	if !rootSeen || !dictionarySeen || !rootClosed || depth != 0 || wantValue || version == "" || strings.TrimSpace(version) != version {
		return "", errors.New("missing application version")
	}
	return version, nil
}

// ObserveExecutable provides legacy diagnostic version observation. Production
// qualification uses ObserveExecutableIdentity and never invokes this path.
func (inspector *Inspector) ObserveExecutable(ctx context.Context, name string) (ports.ExecutableObservation, error) {
	observation, err := inspector.ObserveExecutableIdentity(ctx, name)
	if err != nil || !observation.Found() {
		return observation, err
	}
	if inspector.version == nil {
		return observation, nil
	}
	versionContext, cancel := context.WithTimeout(ctx, executableVersionTimeout)
	versionOutput, versionErr := inspector.version(versionContext, observation.ResolvedPath())
	cancel()
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	version := ""
	if versionErr == nil {
		version = safeExecutableVersion(versionOutput)
	}
	return ports.NewExecutableObservation(
		observation.Name(), true, observation.ResolvedPath(), version, observation.SHA256(),
	)
}

// SpawnVerifier descriptor-opens and hashes current provider launch identities.
type SpawnVerifier struct{}

// NewSpawnVerifier returns the production provider spawn verifier.
func NewSpawnVerifier() providercli.SpawnVerifier { return SpawnVerifier{} }

// VerifyProviderSpawn revalidates both current identities immediately before spawn.
func (SpawnVerifier) VerifyProviderSpawn(ctx context.Context, definition providercli.RuntimeDefinition) error {
	if err := verifySpawnIdentity(ctx, definition.Executable(), definition.ExecutableSHA256()); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	verifyLauncher := verifySpawnIdentity
	if definition.Family() == providercli.FamilyZcode {
		verifyLauncher = verifyReadableSpawnIdentity
	}
	if err := verifyLauncher(ctx, definition.Launcher(), definition.LauncherSHA256()); err != nil {
		return fmt.Errorf("launcher: %w", err)
	}
	if definition.Family() == providercli.FamilyZcode {
		if err := verifyReadableSpawnIdentity(ctx, definition.ZCodeProviderConfig(), definition.ZCodeProviderConfigSHA256()); err != nil {
			return fmt.Errorf("provider config: %w", err)
		}
		if err := verifyReadableSpawnIdentity(ctx, definition.ApplicationMetadata(), definition.ApplicationMetadataSHA256()); err != nil {
			return fmt.Errorf("application metadata: %w", err)
		}
	}
	return nil
}

func verifySpawnIdentity(ctx context.Context, path, expectedHash string) error {
	return verifyCurrentIdentity(ctx, path, expectedHash, true)
}

func verifyReadableSpawnIdentity(ctx context.Context, path, expectedHash string) error {
	return verifyCurrentIdentity(ctx, path, expectedHash, false)
}

func verifyCurrentIdentity(ctx context.Context, path, expectedHash string, requireExecutable bool) error {
	if err := observationContext(ctx, "provider spawn verification"); err != nil {
		return err
	}
	file, err := openCanonicalExecutable(path)
	if err != nil {
		return errors.New("descriptor open failed")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return errors.New("invalid descriptor")
	}
	if requireExecutable {
		executable, err := file.EffectiveExecutable(before)
		if err != nil || !executable {
			return fmt.Errorf("%w: descriptor is not executable", ports.ErrProviderSpawnEnvironmentDrift)
		}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, before.size+1)); err != nil {
		return errors.New("descriptor hash failed")
	}
	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return errors.New("descriptor changed")
	}
	reopened, err := openCanonicalExecutable(path)
	if err != nil {
		return errors.New("descriptor reopen failed")
	}
	reopenedSnapshot, statErr := reopened.Stat()
	_ = reopened.Close()
	if statErr != nil || !after.stableSince(reopenedSnapshot) {
		return errors.New("descriptor changed")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return fmt.Errorf("%w: descriptor hash mismatch", ports.ErrProviderSpawnEnvironmentDrift)
	}
	return nil
}
