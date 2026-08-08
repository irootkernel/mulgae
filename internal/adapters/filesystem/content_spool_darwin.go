//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

// ContentSpooler stores one reopenable artifact per private temporary directory.
type ContentSpooler struct{}

var _ ports.ContentSpooler = ContentSpooler{}

// NewContentSpooler returns the Darwin file-backed content spooler.
func NewContentSpooler() ContentSpooler { return ContentSpooler{} }

// Spool copies source through EOF without imposing a product byte limit.
func (ContentSpooler) Spool(ctx context.Context, request ports.ContentSpoolRequest) (ports.ContentLease, error) {
	if ctx == nil {
		return nil, fmt.Errorf("content spool: nil context")
	}
	if request.Source() == nil || request.MediaType() == "" {
		return nil, fmt.Errorf("content spool: invalid request")
	}
	root, err := os.MkdirTemp("", "mulgae-content-")
	if err != nil {
		return nil, fmt.Errorf("content spool: create private directory: %w", err)
	}
	cleanup := func(cause error) (ports.ContentLease, error) {
		return nil, errors.Join(cause, os.RemoveAll(root))
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return cleanup(fmt.Errorf("content spool: secure private directory: %w", err))
	}
	path := filepath.Join(root, "content")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return cleanup(fmt.Errorf("content spool: create content file: %w", err))
	}
	remove := func(cause error) (ports.ContentLease, error) {
		return cleanup(errors.Join(cause, file.Close()))
	}

	hash := sha256.New()
	buffer := make([]byte, streamBufferSize)
	var length int64
	for {
		if err := ctx.Err(); err != nil {
			zeroBytes(buffer)
			return remove(fmt.Errorf("content spool: %w", err))
		}
		n, readErr := request.Source().Read(buffer)
		if n < 0 || n > len(buffer) {
			zeroBytes(buffer)
			return remove(fmt.Errorf("content spool: source returned an invalid byte count"))
		}
		if n > 0 {
			if _, err := hash.Write(buffer[:n]); err != nil {
				zeroBytes(buffer)
				return remove(fmt.Errorf("content spool: hash content: %w", err))
			}
			if _, err := file.Write(buffer[:n]); err != nil {
				zeroBytes(buffer)
				return remove(fmt.Errorf("content spool: write content: %w", err))
			}
			length += int64(n)
			zeroBytes(buffer[:n])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			zeroBytes(buffer)
			return remove(fmt.Errorf("content spool: read source: %w", readErr))
		}
		if n == 0 {
			zeroBytes(buffer)
			return remove(fmt.Errorf("content spool: source made no progress"))
		}
	}
	zeroBytes(buffer)
	if err := ctx.Err(); err != nil {
		return remove(fmt.Errorf("content spool: %w", err))
	}
	if err := file.Sync(); err != nil {
		return remove(fmt.Errorf("content spool: sync content: %w", err))
	}
	identity, err := contentFileIdentity(file)
	if err != nil {
		return remove(fmt.Errorf("content spool: identify content: %w", err))
	}
	if err := file.Close(); err != nil {
		return cleanup(fmt.Errorf("content spool: close content: %w", err))
	}
	contentIdentity, err := ports.NewContentIdentity(
		"sha256:"+hex.EncodeToString(hash.Sum(nil)), length, request.MediaType(),
	)
	if err != nil {
		return cleanup(fmt.Errorf("content spool: construct identity: %w", err))
	}
	return &fileContentLease{
		root: root, path: path, fileIdentity: identity, contentIdentity: contentIdentity,
	}, nil
}

type fileContentIdentity struct {
	device uint64
	inode  uint64
}

type fileContentLease struct {
	mu              sync.Mutex
	root            string
	path            string
	fileIdentity    fileContentIdentity
	contentIdentity ports.ContentIdentity
	closed          bool
}

func (lease *fileContentLease) Identity() ports.ContentIdentity {
	if lease == nil {
		return ports.ContentIdentity{}
	}
	return lease.contentIdentity
}

func (lease *fileContentLease) Open(ctx context.Context) (io.ReadCloser, error) {
	if lease == nil || ctx == nil {
		return nil, fmt.Errorf("content lease: invalid open request")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("content lease: %w", err)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil, fmt.Errorf("content lease: already closed")
	}
	fd, err := unix.Open(lease.path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("content lease: open: %w", err)
	}
	file := os.NewFile(uintptr(fd), "mulgae-content")
	identity, err := contentFileIdentity(file)
	if err != nil || identity != lease.fileIdentity {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("identity changed")
		}
		return nil, fmt.Errorf("content lease: verify: %w", err)
	}
	return file, nil
}

func (lease *fileContentLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return nil
	}
	file, err := os.Open(lease.path)
	if err != nil {
		return fmt.Errorf("content lease: open for cleanup: %w", err)
	}
	identity, identityErr := contentFileIdentity(file)
	closeErr := file.Close()
	if identityErr != nil || identity != lease.fileIdentity {
		if identityErr == nil {
			identityErr = fmt.Errorf("identity changed")
		}
		return errors.Join(fmt.Errorf("content lease: refuse cleanup: %w", identityErr), closeErr)
	}
	if err := os.Remove(lease.path); err != nil {
		return errors.Join(fmt.Errorf("content lease: remove content: %w", err), closeErr)
	}
	if err := os.Remove(lease.root); err != nil {
		return errors.Join(fmt.Errorf("content lease: remove private directory: %w", err), closeErr)
	}
	lease.closed = true
	return closeErr
}

func contentFileIdentity(file *os.File) (fileContentIdentity, error) {
	if file == nil {
		return fileContentIdentity{}, fmt.Errorf("nil content file")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileContentIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 {
		return fileContentIdentity{}, fmt.Errorf("content is not a private regular file")
	}
	return fileContentIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}
