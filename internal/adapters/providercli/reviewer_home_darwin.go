//go:build darwin && arm64

package providercli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

type reviewerHome struct {
	mu          sync.Mutex
	root        ports.AnchoredRoot
	directories []*os.File
	identities  []unix.Stat_t
	paths       []string
	guideFile   *os.File
	guideStat   unix.Stat_t
	guide       []byte
	closed      bool
}

var _ ports.ReviewerHome = (*reviewerHome)(nil)

// OpenReviewerHome uses an explicitly admitted operator home. New files belong
// only to its neutral .mulgae/home directory; existing guide bytes are preserved.
func OpenReviewerHome(operatorHome ports.AnchoredRoot, defaultGuide []byte) (ports.ReviewerHome, error) {
	if !operatorHome.Valid() || operatorHome.String() == "/" || !utf8.Valid(defaultGuide) || strings.IndexByte(string(defaultGuide), 0) >= 0 {
		return nil, fmt.Errorf("reviewer home: invalid home or default guide")
	}
	home := &reviewerHome{}
	failed := true
	defer func() {
		if failed {
			_ = home.Close()
		}
	}()
	parent, err := openAbsoluteDirectory(operatorHome.String())
	if err != nil {
		return nil, fmt.Errorf("reviewer home: open operator directory: %w", err)
	}
	home.directories = append(home.directories, parent)
	var operatorStat unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &operatorStat); err != nil || operatorStat.Uid != uint32(os.Geteuid()) || operatorStat.Mode&0022 != 0 {
		return nil, fmt.Errorf("reviewer home: unsafe operator directory")
	}
	for _, component := range []string{".mulgae", "home"} {
		if err := unix.Mkdirat(int(parent.Fd()), component, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("reviewer home: create directory: %w", err)
		}
		directory, err := openDirectoryAt(parent, component)
		if err != nil {
			return nil, fmt.Errorf("reviewer home: open directory: %w", err)
		}
		home.directories = append(home.directories, directory)
		var stat unix.Stat_t
		if err := unix.Fstat(int(directory.Fd()), &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
			return nil, fmt.Errorf("reviewer home: unsafe directory ownership or permissions")
		}
		if err := parent.Sync(); err != nil {
			return nil, fmt.Errorf("reviewer home: sync parent: %w", err)
		}
		parent = directory
	}
	if err := createReviewerGuide(parent, defaultGuide); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), "AGENTS.md", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("reviewer home: open guide: %w", err)
	}
	home.guideFile = os.NewFile(uintptr(fd), "reviewer-guide")
	if err := unix.Fstat(fd, &home.guideStat); err != nil || !safeReviewerGuide(home.guideStat) {
		return nil, fmt.Errorf("reviewer home: unsafe guide")
	}
	home.guide, err = io.ReadAll(home.guideFile)
	if err != nil || !utf8.Valid(home.guide) || strings.IndexByte(string(home.guide), 0) >= 0 {
		return nil, fmt.Errorf("reviewer home: unreadable guide")
	}
	for _, directory := range home.directories {
		var stat unix.Stat_t
		if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
			return nil, err
		}
		path, err := reviewerDescriptorPath(directory)
		if err != nil {
			return nil, err
		}
		home.identities = append(home.identities, stat)
		home.paths = append(home.paths, path)
	}
	home.root, err = ports.NewAnchoredRoot(home.paths[len(home.paths)-1])
	if err != nil {
		return nil, err
	}
	if err := home.Revalidate(); err != nil {
		return nil, err
	}
	failed = false
	return home, nil
}

// Publish a fully written file with renameatx_np's no-overwrite semantics. Concurrent
// creators see the complete winner, never a partially written AGENTS.md.
func createReviewerGuide(directory *os.File, guide []byte) error {
	var existing unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), "AGENTS.md", &existing, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if !safeReviewerGuide(existing) {
			return fmt.Errorf("reviewer home: unsafe existing guide")
		}
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("reviewer home: inspect guide: %w", err)
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := ".AGENTS-" + hex.EncodeToString(token[:])
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("reviewer home: create guide candidate: %w", err)
	}
	file := os.NewFile(uintptr(fd), "reviewer-guide-candidate")
	defer func() { _ = unix.Unlinkat(int(directory.Fd()), name, 0) }()
	count, writeErr := file.Write(guide)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil || count != len(guide) {
		return fmt.Errorf("reviewer home: write guide candidate: %w", err)
	}
	err = unix.RenameatxNp(int(directory.Fd()), name, int(directory.Fd()), "AGENTS.md", unix.RENAME_EXCL)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("reviewer home: publish guide: %w", err)
	}
	if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("reviewer home: remove guide candidate: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("reviewer home: sync guide: %w", err)
	}
	return nil
}

func safeReviewerGuide(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && stat.Uid == uint32(os.Geteuid()) && stat.Mode&0022 == 0
}

func (home *reviewerHome) Root() ports.AnchoredRoot { return home.root }
func (home *reviewerHome) Guide() []byte            { return append([]byte(nil), home.guide...) }

func (home *reviewerHome) Revalidate() error {
	home.mu.Lock()
	defer home.mu.Unlock()
	return home.revalidate()
}

func (home *reviewerHome) revalidate() error {
	if home.closed || home.guideFile == nil {
		return fmt.Errorf("reviewer home: closed authority")
	}
	for i, directory := range home.directories {
		path, err := reviewerDescriptorPath(directory)
		if err != nil || path != home.paths[i] {
			return fmt.Errorf("reviewer home: relocated directory")
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil || !sameReviewerIdentity(stat, home.identities[i]) || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("reviewer home: replaced directory")
		}
		if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
			return fmt.Errorf("reviewer home: unsafe directory permissions")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(home.directories[len(home.directories)-1].Fd()), "AGENTS.md", &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || !safeReviewerGuide(stat) || !sameReviewerIdentity(stat, home.guideStat) || stat.Size != home.guideStat.Size || stat.Mtim != home.guideStat.Mtim || stat.Ctim != home.guideStat.Ctim {
		return fmt.Errorf("reviewer home: changed guide")
	}
	return nil
}

func sameReviewerIdentity(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Btim == expected.Btim
}

func (home *reviewerHome) DuplicateLaunchDirectory() (*os.File, error) {
	home.mu.Lock()
	defer home.mu.Unlock()
	if err := home.revalidate(); err != nil {
		return nil, err
	}
	fd, err := unix.Dup(int(home.directories[len(home.directories)-1].Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), home.root.String()), nil
}

func (home *reviewerHome) Close() error {
	home.mu.Lock()
	defer home.mu.Unlock()
	if home.closed {
		return nil
	}
	home.closed = true
	var err error
	if home.guideFile != nil {
		err = home.guideFile.Close()
	}
	for i := len(home.directories) - 1; i >= 0; i-- {
		err = errors.Join(err, home.directories[i].Close())
	}
	return err
}

func reviewerDescriptorPath(file *os.File) (string, error) {
	buffer := make([]byte, 4096)
	_, _, errno := unix.Syscall(
		unix.SYS_FCNTL, //nolint:staticcheck // Darwin exposes F_GETPATH only through fcntl(2).
		file.Fd(), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return "", errno
	}
	end := 0
	for end < len(buffer) && buffer[end] != 0 {
		end++
	}
	if end == 0 || end == len(buffer) {
		return "", fmt.Errorf("reviewer home: invalid descriptor path")
	}
	path := string(buffer[:end])
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("reviewer home: noncanonical descriptor path")
	}
	return path, nil
}
