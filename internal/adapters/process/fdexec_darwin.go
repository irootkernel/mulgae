//go:build darwin && arm64

package process

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	fdExecHiddenArgument           = "__mulgae_fdexec_v1"
	fdExecNativeHomeHiddenArgument = "__mulgae_fdexec_native_home_v1"
	cleanExecHiddenArgument        = "__mulgae_cleanexec_v1"
)

// ExecInheritedDirectory recognizes Mulgae's private provider-launch modes.
// A recognized request never returns successfully. Directory-bound modes
// validate and enter their inherited directory; every mode removes inherited
// descriptor capabilities before replacing itself with the guarded target.
func ExecInheritedDirectory(argv []string) (bool, error) {
	if len(argv) >= 2 && argv[1] == cleanExecHiddenArgument {
		if len(argv) < 3 || !filepath.IsAbs(argv[2]) || filepath.Clean(argv[2]) != argv[2] {
			return true, fmt.Errorf("clean exec: invalid provider executable")
		}
		return true, execWithSanitizedDescriptors(argv[2], argv[2:])
	}
	if len(argv) < 4 || (argv[1] != fdExecHiddenArgument && argv[1] != fdExecNativeHomeHiddenArgument) {
		return false, nil
	}
	protectedNativeHome := argv[1] == fdExecNativeHomeHiddenArgument
	if protectedNativeHome && len(argv) < 8 {
		return true, fmt.Errorf("fd exec: invalid native home authority")
	}
	fd, err := strconv.Atoi(argv[2])
	if err != nil || fd < 3 || strconv.Itoa(fd) != argv[2] {
		return true, fmt.Errorf("fd exec: invalid inherited directory descriptor")
	}
	executable := argv[3]
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return true, fmt.Errorf("fd exec: provider executable must be canonical and absolute")
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(fd, &directoryStat); err != nil {
		return true, fmt.Errorf("fd exec: inspect inherited directory: %w", err)
	}
	if directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return true, fmt.Errorf("fd exec: inherited descriptor is not a directory")
	}
	if err := unix.Fchdir(fd); err != nil {
		return true, fmt.Errorf("fd exec: change directory: %w", err)
	}
	cwdFD, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, fmt.Errorf("fd exec: inspect current directory: %w", err)
	}
	var cwdStat unix.Stat_t
	statErr := unix.Fstat(cwdFD, &cwdStat)
	closeErr := unix.Close(cwdFD)
	if statErr != nil || closeErr != nil || cwdStat.Dev != directoryStat.Dev || cwdStat.Ino != directoryStat.Ino {
		return true, fmt.Errorf("fd exec: current directory identity mismatch")
	}
	providerOffset := 4
	if protectedNativeHome {
		providerOffset = 8
	}
	providerArgv := append([]string{executable}, argv[providerOffset:]...)
	if protectedNativeHome {
		if err := verifyNativeHome(argv[4:8]); err != nil {
			return true, err
		}
	}
	return true, execWithSanitizedDescriptors(executable, providerArgv)
}

func execWithSanitizedDescriptors(executable string, argv []string) error {
	if err := markInheritedDescriptorsCloseOnExec(); err != nil {
		return err
	}
	return syscall.Exec(executable, argv, os.Environ())
}

// Run only in the dedicated launch child. Changing descriptor flags here
// leaves the caller's flags untouched. Marking rather than closing also keeps
// the Go runtime's own descriptors usable until exec replaces the image.
func markInheritedDescriptorsCloseOnExec() error {
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return fmt.Errorf("provider exec: enumerate inherited descriptors: %w", err)
	}
	defer directory.Close()
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			fd, err := strconv.Atoi(name)
			if err != nil || fd < 0 || strconv.Itoa(fd) != name {
				return fmt.Errorf("provider exec: invalid inherited descriptor entry")
			}
			if fd < 3 {
				continue
			}
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if errors.Is(err, unix.EBADF) {
				continue
			}
			if err != nil {
				return fmt.Errorf("provider exec: inspect inherited descriptor: %w", err)
			}
			if flags&unix.FD_CLOEXEC == 0 {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil && !errors.Is(err, unix.EBADF) {
					return fmt.Errorf("provider exec: protect inherited descriptor: %w", err)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("provider exec: read inherited descriptors: %w", readErr)
		}
	}
}

func verifyNativeHome(argv []string) error {
	if len(argv) != 4 || !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] {
		return fmt.Errorf("fd exec: invalid native home authority")
	}
	device, err := strconv.ParseUint(argv[1], 10, 64)
	if err != nil || strconv.FormatUint(device, 10) != argv[1] || device == 0 {
		return fmt.Errorf("fd exec: invalid native home authority")
	}
	inode, err := strconv.ParseUint(argv[2], 10, 64)
	if err != nil || strconv.FormatUint(inode, 10) != argv[2] || inode == 0 {
		return fmt.Errorf("fd exec: invalid native home authority")
	}
	uid, err := strconv.ParseUint(argv[3], 10, 32)
	if err != nil || strconv.FormatUint(uid, 10) != argv[3] || uint32(uid) != uint32(unix.Geteuid()) {
		return fmt.Errorf("fd exec: native home identity mismatch")
	}
	homeFD, err := unix.Open(argv[0], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("fd exec: native home unavailable")
	}
	defer unix.Close(homeFD)
	var stat unix.Stat_t
	if err := unix.Fstat(homeFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(stat.Dev) != device || stat.Ino != inode || stat.Uid != uint32(uid) {
		return fmt.Errorf("fd exec: native home identity mismatch")
	}
	return nil
}
