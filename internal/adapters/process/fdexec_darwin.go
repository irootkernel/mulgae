//go:build darwin && arm64

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	fdExecHiddenArgument           = "__mulgae_fdexec_v1"
	fdExecNativeHomeHiddenArgument = "__mulgae_fdexec_native_home_v1"
)

// ExecInheritedDirectory recognizes Mulgae's private descriptor-bound launch
// mode. A recognized request never returns successfully: it changes to the
// inherited directory and immediately replaces itself with the provider.
func ExecInheritedDirectory(argv []string) (bool, error) {
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
	unix.CloseOnExec(fd)
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
	return true, syscall.Exec(executable, providerArgv, os.Environ())
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
