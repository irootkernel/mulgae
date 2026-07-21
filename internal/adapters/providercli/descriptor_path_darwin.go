//go:build darwin

package providercli

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// verifyDescriptorDetached proves that the acquired directory descriptor still
// names the expected object while no filesystem path returned for that object
// resolves to the same identity. Darwin/APFS does not reliably reduce Nlink on
// an open, unlinked directory, so link counts cannot provide this proof.
func verifyDescriptorDetached(fd int, expectedDevice int32, expectedInode uint64) error {
	var descriptor unix.Stat_t
	if err := unix.Fstat(fd, &descriptor); err != nil {
		return fmt.Errorf("inspect detached descriptor: %w", err)
	}
	if descriptor.Dev != expectedDevice || descriptor.Ino != expectedInode || descriptor.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("detached descriptor identity drift")
	}

	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		uintptr(fd),
		uintptr(unix.F_GETPATH),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return fmt.Errorf("inspect detached descriptor path: %w", errno)
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) {
		return fmt.Errorf("inspect detached descriptor path: invalid path")
	}

	var named unix.Stat_t
	if err := unix.Lstat(string(buffer[:end]), &named); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect detached descriptor path: %w", err)
	}
	if named.Dev == expectedDevice && named.Ino == expectedInode {
		return fmt.Errorf("descriptor remains linked")
	}
	return nil
}
