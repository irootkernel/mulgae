//go:build darwin && arm64

package filesystem

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	privateDirectoryMode = 0o700
	privateFileMode      = 0o600
)

type privateDirectoryIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	mode   uint32
}

func privateDirectoryIdentityForFD(fd int) (privateDirectoryIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return privateDirectoryIdentity{}, fmt.Errorf("stat private directory identity: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return privateDirectoryIdentity{}, fmt.Errorf("private directory identity is not a directory")
	}
	return privateDirectoryIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), uid: stat.Uid, mode: uint32(stat.Mode & 0o7777)}, nil
}

func revalidatePrivateDirectory(
	root ports.AnchoredRoot,
	components []string,
	expected privateDirectoryIdentity,
	operations secureWriterOperations,
) error {
	reopenedFD, err := walkPrivateDirectoryWithOperations(root, components, false, operations)
	if err != nil {
		return err
	}
	actual, identityErr := privateDirectoryIdentityForFD(reopenedFD)
	closeErr := unix.Close(reopenedFD)
	if identityErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close private directory revalidation: %w", closeErr)
	}
	if actual != expected {
		return fmt.Errorf("private directory namespace changed")
	}
	return nil
}

func openAnchoredRoot(root ports.AnchoredRoot) (int, error) {
	if !root.Valid() {
		return -1, fmt.Errorf("open anchored root: invalid root")
	}

	fd, err := unix.Open(root.String(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open anchored root: %w", err)
	}
	if err := verifyAnchoredDirectory(fd); err != nil {
		closeFD(fd)
		return -1, fmt.Errorf("open anchored root: %w", err)
	}
	return fd, nil
}

func walkPrivateDirectory(root ports.AnchoredRoot, components []string, create bool) (int, error) {
	return walkPrivateDirectoryWithOperations(root, components, create, defaultSecureWriterOperations())
}

func walkPrivateDirectoryWithOperations(root ports.AnchoredRoot, components []string, create bool, operations secureWriterOperations) (int, error) {
	fd, err := openAnchoredRoot(root)
	operations = operations.withDefaults()
	if err != nil {
		return -1, err
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, 0) {
			closeFD(fd)
			return -1, fmt.Errorf("walk private directory: invalid component")
		}

		created := false
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			mkdirErr := unix.Mkdirat(fd, component, privateDirectoryMode)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				closeFD(fd)
				return -1, fmt.Errorf("create private directory: %w", mkdirErr)
			}
			if mkdirErr == nil {
				created = true
				if syncErr := operations.fsync(fd); syncErr != nil {
					closeFD(fd)
					return -1, fmt.Errorf("sync private directory parent: %w", syncErr)
				}
			}
			next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			closeFD(fd)
			return -1, fmt.Errorf("open private directory component: %w", openErr)
		}
		if verifyErr := verifyPrivateDirectory(next); verifyErr != nil {
			closeFD(next)
			closeFD(fd)
			return -1, fmt.Errorf("open private directory component: %w", verifyErr)
		}
		if create && !created {
			if syncErr := operations.fsync(fd); syncErr != nil {
				closeFD(next)
				closeFD(fd)
				return -1, fmt.Errorf("sync private directory parent: %w", syncErr)
			}
		}
		closeFD(fd)
		fd = next
	}
	return fd, nil
}

func verifyAnchoredDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat anchored directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("anchor is not a directory")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("anchored directory is not owned by the current user")
	}
	mode := stat.Mode & 0o7777
	if mode != 0o700 && mode != 0o750 && mode != 0o755 {
		return fmt.Errorf("anchored directory mode is not allowed")
	}
	return nil
}

func verifyPrivateDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("not a directory")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("directory is not owned by the current user")
	}
	if stat.Mode&0o7777 != privateDirectoryMode {
		return fmt.Errorf("directory mode is not 0700")
	}
	return nil
}

func verifyPrivateRegularFile(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat temporary file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("temporary node is not a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("temporary file is not owned by the current user")
	}
	if stat.Mode&0o7777 != privateFileMode {
		return fmt.Errorf("temporary file mode is not 0600")
	}
	return nil
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
