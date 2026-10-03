//go:build darwin && arm64

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const seatbeltExecutable = "/usr/bin/sandbox-exec"

// liveBoundaryArgv adds the fixed platform launcher without changing provider
// identity or introducing a shell. The kernel policy is independent of the
// provider's planning mode and protocol permission gate.
func liveBoundaryArgv(ctx context.Context, request ports.ProcessRequest) (string, []string, error) {
	boundary, guarded := request.LiveReadOnlyBoundary()
	if !guarded {
		return request.Executable(), request.Argv(), nil
	}
	admissionContext, cancel := context.WithTimeout(ctx, request.Timeout())
	defer cancel()
	var profile strings.Builder
	profile.WriteString("(version 1)\n(allow default)\n")
	if err := validateLiveBoundaryDirectory(boundary.WritableRoot().String()); err != nil {
		return "", nil, fmt.Errorf("process runner: live writable namespace admission: %w", err)
	}
	profile.WriteString("(deny file-write* file-link (require-all (require-not (subpath " + strconv.Quote(boundary.WritableRoot().String()) + "))")
	if root, present := boundary.RuntimeTempRoot(); present {
		if err := validateLiveBoundaryDirectory(root.String()); err != nil {
			return "", nil, fmt.Errorf("process runner: live runtime directory admission: %w", err)
		}
		profile.WriteString(" (require-not (subpath " + strconv.Quote(root.String()) + "))")
		profile.WriteString(" (require-not (literal \"/dev/null\"))))\n")
		profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(root.String()) + "))\n")
	} else {
		profile.WriteString(" (require-not (literal \"/dev/null\"))))\n")
	}
	ancestors := map[string]bool{}
	for _, group := range []struct {
		roots      []ports.AnchoredRoot
		operations string
	}{
		{boundary.ReadOnlyRoots(), "file-write* file-link"},
		{boundary.CredentialRoots(), "file-read* file-write* file-link"},
	} {
		for _, root := range group.roots {
			path := root.String()
			if err := validateLiveBoundaryDirectory(path); err != nil {
				return "", nil, fmt.Errorf("process runner: live boundary admission: %w", err)
			}
			profile.WriteString("(deny " + group.operations + " (subpath " + strconv.Quote(path) + "))\n")
			profile.WriteString("(deny network-outbound (remote unix-socket (subpath " + strconv.Quote(path) + ")))\n")
			for parent := path; parent != "/"; parent = filepath.Dir(parent) {
				if !ancestors[parent] {
					profile.WriteString("(deny file-write-unlink (literal " + strconv.Quote(parent) + "))\n")
					ancestors[parent] = true
				}
			}
		}
	}
	aliasRoots := append(boundary.CredentialRoots(), boundary.WritableRoot())
	if root, present := boundary.RuntimeTempRoot(); present {
		aliasRoots = append(aliasRoots, root)
	}
	for _, root := range aliasRoots {
		if err := validateLiveRootFileLinks(admissionContext, root.String()); err != nil {
			return "", nil, fmt.Errorf("process runner: live file alias admission: %w", err)
		}
	}
	argv := append([]string{seatbeltExecutable, "-p", profile.String(), request.Executable()}, request.Argv()[1:]...)
	return seatbeltExecutable, argv, nil
}

// Admit each path through descriptors: aliases and symlinked ancestors cannot
// silently leave the named protection behind.
func validateLiveBoundaryDirectory(path string) error {
	fd, err := openLiveBoundaryDirectory(path)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func openLiveBoundaryDirectory(path string) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		_ = unix.Close(fd)
		fd = next
	}
	if err := descriptorPathMatches(fd, path); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Seatbelt path rules do not deny an already existing hardlink outside a
// protected tree. Reject multiply linked credential or writable-root files
// before any spawn; global link denial prevents importing an outside alias.
// Inspect metadata through directory descriptors; never follow links or read
// file contents. Cancellation and the request deadline bound traversal.
func validateLiveRootFileLinks(ctx context.Context, path string) error {
	fd, err := openLiveBoundaryDirectory(path)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	return inspectLiveRootDirectory(ctx, directory, path)
}

func inspectLiveRootDirectory(ctx context.Context, directory *os.File, path string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := directory.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return err
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFREG:
				if stat.Nlink != 1 {
					return fmt.Errorf("credential or writable-root file has a hardlink alias")
				}
			case unix.S_IFDIR:
				fd, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					return err
				}
				childPath := filepath.Join(path, entry.Name())
				child := os.NewFile(uintptr(fd), childPath)
				var retained unix.Stat_t
				err = unix.Fstat(fd, &retained)
				if err == nil && (retained.Dev != stat.Dev || retained.Ino != stat.Ino || retained.Btim != stat.Btim) {
					err = fmt.Errorf("live alias-admission directory changed")
				}
				if err == nil {
					err = inspectLiveRootDirectory(ctx, child, childPath)
				}
				closeErr := child.Close()
				if err := errors.Join(err, closeErr); err != nil {
					return err
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return descriptorPathMatches(int(directory.Fd()), path)
		}
	}
}

func descriptorPathMatches(fd int, path string) error {
	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return errno
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) || string(buffer[:end]) != path {
		return fmt.Errorf("protected directory is not descriptor-canonical")
	}
	return nil
}

func validateNeutralLaunchDirectory(fd int, path string) error {
	if err := descriptorPathMatches(fd, path); err != nil {
		return err
	}
	var retained, named unix.Stat_t
	if err := unix.Fstat(fd, &retained); err != nil {
		return err
	}
	if err := unix.Lstat(path, &named); err != nil {
		return err
	}
	if retained.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&unix.S_IFMT != unix.S_IFDIR || retained.Dev != named.Dev || retained.Ino != named.Ino || retained.Btim != named.Btim {
		return fmt.Errorf("neutral launch directory identity changed")
	}
	return nil
}
