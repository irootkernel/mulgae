//go:build darwin && arm64

package gittarget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/ports"
)

// ProjectBindingObserver observes local Git anchors without executing Git or
// reading its configuration. It owns no mutable configuration or provider state.
type ProjectBindingObserver struct{}

func (ProjectBindingObserver) ObserveProjectBinding(ctx context.Context, root ports.AnchoredRoot) (ports.ProjectBindingLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !root.Valid() {
		return nil, fmt.Errorf("project binding: invalid root")
	}
	lease, err := openProjectBinding(root.String())
	if err != nil {
		return nil, err
	}
	if err := lease.Revalidate(ctx); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

type projectBindingLease struct {
	mu          sync.Mutex
	requested   string
	directories canonicalGitDirectorySet
	observation ports.ProjectBindingObservation
	closed      bool
}

func openProjectBinding(requested string) (*projectBindingLease, error) {
	canonical, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return nil, err
	}
	directories, err := openCanonicalGitDirectorySet(canonical)
	if err != nil {
		return nil, err
	}
	if err := validateBindingPointers(directories); err != nil {
		return nil, joinCanonicalConstructionCleanup(err, "close binding descriptors", directories.source.close)
	}
	observation, err := observeBindingDirectories(directories)
	if err == nil {
		err = directories.source.verify()
	}
	if err != nil {
		return nil, joinCanonicalConstructionCleanup(err, "close binding descriptors", directories.source.close)
	}
	return &projectBindingLease{requested: requested, directories: directories, observation: observation}, nil
}

func observeBindingDirectories(directories canonicalGitDirectorySet) (ports.ProjectBindingObservation, error) {
	var observation ports.ProjectBindingObservation
	anchors := []*canonicalMetadataDirectory{directories.source.directories[0], directories.worktree, directories.common}
	roots := []*ports.AnchoredRoot{&observation.Root, &observation.GitDirectory, &observation.CommonDirectory}
	identities := []*ports.ProjectDirectoryIdentity{&observation.RootIdentity, &observation.GitIdentity, &observation.CommonIdentity}
	for i, anchor := range anchors {
		var stat unix.Stat_t
		if err := unix.Fstat(int(anchor.file.Fd()), &stat); err != nil {
			return observation, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
			return observation, fmt.Errorf("project binding: unsafe directory")
		}
		root, err := bindingDescriptorRoot(anchor.file, stat)
		if err != nil {
			return observation, err
		}
		*roots[i] = root
		*identities[i] = ports.ProjectDirectoryIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, BirthSeconds: stat.Btim.Sec, BirthNanoseconds: stat.Btim.Nsec}
	}
	return observation, nil
}

func (lease *projectBindingLease) Observation() ports.ProjectBindingObservation {
	return lease.observation
}

func (lease *projectBindingLease) Revalidate(ctx context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease.closed {
		return fmt.Errorf("project binding: closed lease")
	}
	held, err := observeBindingDirectories(lease.directories)
	if err != nil {
		return err
	}
	if held != lease.observation {
		return fmt.Errorf("project binding: descriptor changed")
	}
	current, err := openProjectBinding(lease.requested)
	if err != nil {
		return err
	}
	closeErr := current.Close()
	if current.observation != lease.observation {
		return fmt.Errorf("project binding: directory changed")
	}
	if closeErr != nil {
		return closeErr
	}
	return ctx.Err()
}

func (lease *projectBindingLease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	lease.closed = true
	return lease.directories.source.close()
}

func validateBindingPointers(directories canonicalGitDirectorySet) error {
	for _, entry := range []struct {
		directory *canonicalMetadataDirectory
		name      string
	}{
		{directories.source.directories[0], ".git"}, {directories.worktree, "commondir"},
	} {
		var stat unix.Stat_t
		err := unix.Fstatat(int(entry.directory.file.Fd()), entry.name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if entry.name == "commondir" && err == unix.ENOENT {
			continue
		}
		if err != nil {
			return err
		}
		if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
			return fmt.Errorf("project binding: unsafe Git metadata")
		}
		if entry.name == ".git" && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			continue
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
			return fmt.Errorf("project binding: unsafe Git pointer")
		}
	}
	return nil
}

// F_GETPATH supplies the filesystem spelling, including case and Unicode aliases.
// EvalSymlinks alone preserves the caller's spelling on case-insensitive APFS.
func bindingDescriptorRoot(file *os.File, expected unix.Stat_t) (ports.AnchoredRoot, error) {
	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		file.Fd(), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return ports.AnchoredRoot{}, errno
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) {
		return ports.AnchoredRoot{}, fmt.Errorf("project binding: invalid descriptor path")
	}
	root, err := ports.NewAnchoredRoot(string(buffer[:end]))
	if err != nil {
		return ports.AnchoredRoot{}, err
	}
	var named unix.Stat_t
	if err := unix.Lstat(root.String(), &named); err != nil {
		return ports.AnchoredRoot{}, err
	}
	if named.Mode&unix.S_IFMT != unix.S_IFDIR || named.Dev != expected.Dev || named.Ino != expected.Ino || named.Btim != expected.Btim {
		return ports.AnchoredRoot{}, fmt.Errorf("project binding: descriptor path changed")
	}
	return root, nil
}
