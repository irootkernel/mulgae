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
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

// maximumExecutableSize bounds executable observation memory, I/O, and hashing work to 128 MiB.
const maximumExecutableSize int64 = 128 * 1024 * 1024

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

// ObserveExecutable resolves name through PATH, verifies the final target, and
// records its exact byte hash. It never executes the executable.
func (inspector *Inspector) ObserveExecutable(ctx context.Context, name string) (ports.ExecutableObservation, error) {
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

	located, err := inspector.lookup(name)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
			return absent, nil
		}
		return ports.ExecutableObservation{}, errors.New("executable lookup failed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	if located == "" {
		return ports.ExecutableObservation{}, errors.New("executable lookup failed")
	}

	absolute, err := filepath.Abs(located)
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable resolution failed")
	}
	resolved, err := inspector.evaluateLinks(absolute)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return ports.ExecutableObservation{}, errors.New("executable resolution failed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}

	file, err := inspector.executable(resolved)
	if err != nil || file == nil {
		return ports.ExecutableObservation{}, errors.New("executable read failed")
	}
	defer file.Close()

	before, err := file.Stat()
	if err != nil || !before.isRegular() || before.size < 0 || before.size > maximumExecutableSize {
		return ports.ExecutableObservation{}, errors.New("executable target is not a regular executable")
	}
	executable, err := file.EffectiveExecutable(before)
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable access failed")
	}
	if !executable {
		return ports.ExecutableObservation{}, errors.New("executable target is not a regular executable")
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
			return ports.ExecutableObservation{}, errors.New("executable hash failed")
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
			return ports.ExecutableObservation{}, errors.New("executable target changed during hash")
		}
		if read == 0 {
			return ports.ExecutableObservation{}, errors.New("executable hash failed")
		}
	}

	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	var overflow [1]byte
	read, readErr := file.Read(overflow[:])
	if read < 0 || read > len(overflow) {
		return ports.ExecutableObservation{}, errors.New("executable hash failed")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	if read > 0 {
		return ports.ExecutableObservation{}, errors.New("executable target changed during hash")
	}
	if !errors.Is(readErr, io.EOF) {
		return ports.ExecutableObservation{}, errors.New("executable hash failed")
	}

	after, err := file.Stat()
	if err != nil || !before.stableSince(after) {
		return ports.ExecutableObservation{}, errors.New("executable target changed during hash")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	reopened, err := inspector.executable(resolved)
	if err != nil || reopened == nil {
		return ports.ExecutableObservation{}, errors.New("executable target changed during hash")
	}
	defer reopened.Close()
	reopenedSnapshot, err := reopened.Stat()
	if err != nil || !after.stableSince(reopenedSnapshot) {
		return ports.ExecutableObservation{}, errors.New("executable target changed during hash")
	}
	if err := observationContext(ctx, "executable observation"); err != nil {
		return ports.ExecutableObservation{}, err
	}
	observation, err := ports.NewExecutableObservation(name, true, resolved, "", "sha256:"+hex.EncodeToString(hash.Sum(nil)))
	if err != nil {
		return ports.ExecutableObservation{}, errors.New("executable observation failed")
	}
	return observation, nil
}
