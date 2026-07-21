//go:build darwin && arm64

package environment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

// maximumExecutableSize bounds executable observation I/O and hashing work to 512 MiB.
const maximumExecutableSize int64 = 512 * 1024 * 1024
const (
	maximumExecutableVersionOutput = 1024
	executableVersionTimeout       = 2 * time.Second
)

var (
	errExecutableVersionOutputTooLarge = errors.New("executable version output too large")
	executableSemanticVersionPattern   = regexp.MustCompile(`[vV]?[0-9]+\.[0-9]+\.[0-9]+`)
)

func identityUnavailable(text string) error {
	return ports.NewIdentityObservationError(ports.IdentityObservationUnavailable, text)
}

func identitySecurity(text string) error {
	return ports.NewIdentityObservationError(ports.IdentityObservationSecurity, text)
}

type boundedCombinedOutput struct {
	data     []byte
	overflow bool
}

func (output *boundedCombinedOutput) Write(value []byte) (int, error) {
	remaining := maximumExecutableVersionOutput - len(output.data)
	if len(value) > remaining {
		output.data = append(output.data, value[:remaining]...)
		output.overflow = true
		return 0, errExecutableVersionOutputTooLarge
	}
	output.data = append(output.data, value...)
	return len(value), nil
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
	var output boundedCombinedOutput
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, err
	}
	if output.overflow {
		return nil, errExecutableVersionOutputTooLarge
	}
	return output.data, nil
}

func safeExecutableVersion(output []byte) string {
	if len(output) > maximumExecutableVersionOutput || !utf8.Valid(output) {
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
		return false, errors.New("executable target changed")
	}

	accessErr := unix.Faccessat(
		descriptor.parentFD,
		descriptor.name,
		unix.X_OK,
		unix.AT_EACCESS|unix.AT_SYMLINK_NOFOLLOW,
	)

	after, err := executableSnapshotAt(descriptor.parentFD, descriptor.name)
	if err != nil || !after.sameFile(expected) {
		return false, errors.New("executable target changed")
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
		nextFD, openErr := unix.Openat(
			parentFD,
			component,
			unix.O_EVTONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
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
		return ports.ExecutableObservation{}, identityUnavailable("executable is not a bounded regular file")
	}
	executable, err := file.EffectiveExecutable(before)
	if err != nil {
		return ports.ExecutableObservation{}, identityUnavailable("executable access is unavailable")
	}
	if !executable {
		return ports.ExecutableObservation{}, identityUnavailable("executable permission is unavailable")
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
		return ports.FileIdentityObservation{}, identitySecurity("readable file parent directory is unsafe")
	}
	file, err := openCanonicalExecutable(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return absent, nil
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return ports.FileIdentityObservation{}, identityUnavailable("readable file is unavailable")
		}
		return ports.FileIdentityObservation{}, identitySecurity("readable file descriptor open failed")
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return ports.FileIdentityObservation{}, identityUnavailable("readable file is not a bounded regular file")
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
			return errors.New("descriptor is not executable")
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
		return errors.New("descriptor hash mismatch")
	}
	return nil
}
