//go:build darwin

package workspace

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// descriptorDetached proves that the acquired directory was unlinked without
// relying on Darwin/APFS directory link counts, which remain non-zero while an
// unlinked directory descriptor is open.
func descriptorDetached(fd int, expectedDevice uint64, expectedInode uint64) error {
	var descriptor unix.Stat_t
	if err := unix.Fstat(fd, &descriptor); err != nil {
		return err
	}
	if uint64(descriptor.Dev) != expectedDevice || descriptor.Ino != expectedInode || descriptor.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errIdentityDrift
	}

	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		uintptr(fd),
		uintptr(unix.F_GETPATH),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return errno
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) {
		return errIdentityDrift
	}

	var named unix.Stat_t
	if err := unix.Lstat(string(buffer[:end]), &named); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if uint64(named.Dev) == expectedDevice && named.Ino == expectedInode {
		return errIdentityDrift
	}
	return nil
}
