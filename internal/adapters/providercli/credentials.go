package providercli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

const maxProjectedCredentialBytes int64 = 16 << 20

type credentialSeed struct {
	sourcePath      string
	sourceInfo      os.FileInfo
	destination     string
	destinationInfo os.FileInfo
	destinationFile *os.File
	sourceSHA256    string
	sourceSize      int64
	sourceMode      os.FileMode
	destinationSize int64
	authority       ports.CredentialSourceAuthority
}

func (lease *namespaceLease) ProjectCredential(ctx context.Context, request ports.CredentialProjectionRequest) (ports.CredentialProjectionReceipt, error) {
	source := request.Source()
	if source == nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: invalid source")
	}
	defer source.Close()
	if ctx == nil || ctx.Err() != nil || lease == nil || request.ProviderInstance() != lease.instance || request.Generation() != lease.generation {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: invalid request")
	}
	destination, ok := credentialDestination(request.Destination())
	if !ok || request.Size() > maxProjectedCredentialBytes {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: invalid request")
	}

	lease.terminalMu.Lock()
	defer lease.terminalMu.Unlock()
	if lease.drained {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: lease is closed")
	}
	lease.seedMu.Lock()
	defer lease.seedMu.Unlock()
	if _, exists := lease.seeds[request.Destination()]; exists {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: duplicate destination")
	}

	sourceInfo, err := safeDeclaredSource(request.SourcePath(), source, request.Size(), request.Mode())
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: unsafe source")
	}
	bytes, digest, err := readDeclaredSource(source, request.Size())
	if err != nil || digest != request.SHA256() {
		zeroBytes(bytes)
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: source integrity mismatch")
	}
	defer zeroBytes(bytes)
	destinationBytes := bytes
	if _, err := safeDeclaredSource(request.SourcePath(), source, request.Size(), request.Mode()); err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: source drift")
	}
	if err := ctx.Err(); err != nil {
		return ports.CredentialProjectionReceipt{}, err
	}

	parent, name, err := lease.openCredentialParent(destination)
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: namespace drift")
	}
	defer parent.Close()
	fileFD, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: create destination")
	}
	file := os.NewFile(uintptr(fileFD), "projected credential")
	created := true
	defer func() {
		if created {
			_ = file.Close()
			_ = unix.Unlinkat(int(parent.Fd()), name, 0)
			_ = parent.Sync()
		}
	}()
	if count, err := file.Write(destinationBytes); err != nil || count != len(destinationBytes) || file.Sync() != nil || file.Close() != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: write destination")
	}
	if err := parent.Sync(); err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: write destination")
	}
	entry, err := credentialEntryStat(parent, name)
	if err != nil || entry.Mode&unix.S_IFMT != unix.S_IFREG || entry.Mode&0777 != 0600 || entry.Size != int64(len(destinationBytes)) {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	destinationFD, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	destinationFile := os.NewFile(uintptr(destinationFD), "projected credential retained descriptor")
	openedInfo, openErr := destinationFile.Stat()
	var openedStat unix.Stat_t
	statErr := unix.Fstat(destinationFD, &openedStat)
	if openErr != nil || statErr != nil || !sameCredentialStat(entry, openedStat) {
		_ = destinationFile.Close()
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	created = false
	lease.seeds[request.Destination()] = credentialSeed{
		sourcePath: request.SourcePath(), sourceInfo: sourceInfo,
		destination: destination, destinationInfo: openedInfo, destinationFile: destinationFile,
		sourceSHA256: request.SHA256(), sourceSize: request.Size(), sourceMode: request.Mode(),
		destinationSize: int64(len(destinationBytes)),
		authority:       request.SourceAuthority(),
	}
	return ports.NewCredentialProjectionReceipt(request.Destination())
}

func credentialDestination(destination ports.CredentialProjectionDestination) (string, bool) {
	switch destination {
	case ports.CredentialProjectionGrokAuth:
		return "home/.grok/auth.json", true
	case ports.CredentialProjectionCodexAuth:
		return "home/.codex/auth.json", true
	default:
		return "", false
	}
}

func (lease *namespaceLease) openCredentialParent(destination string) (*os.File, string, error) {
	if lease == nil || lease.rootDirectory == nil || destination == "" || filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return nil, "", fmt.Errorf("namespace drift")
	}
	rootInfo, err := lease.rootDirectory.Stat()
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0077 != 0 || !os.SameFile(lease.rootInfo, rootInfo) {
		return nil, "", fmt.Errorf("namespace drift")
	}
	relative := filepath.Dir(destination)
	current := ""
	currentFD := int(lease.rootDirectory.Fd())
	var directory *os.File
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		expected, ok := lease.directoryInfo[current]
		if !ok {
			if directory != nil {
				_ = directory.Close()
			}
			return nil, "", fmt.Errorf("unknown credential directory")
		}
		fd, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			if directory != nil {
				_ = directory.Close()
			}
			return nil, "", fmt.Errorf("namespace drift")
		}
		next := os.NewFile(uintptr(fd), "credential parent directory")
		info, statErr := next.Stat()
		if statErr != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !os.SameFile(expected, info) {
			_ = next.Close()
			if directory != nil {
				_ = directory.Close()
			}
			return nil, "", fmt.Errorf("namespace drift")
		}
		if directory != nil {
			_ = directory.Close()
		}
		directory = next
		currentFD = fd
	}
	if directory == nil {
		return nil, "", fmt.Errorf("unknown credential directory")
	}
	if hook := lease.afterCredentialParentOpenHook; hook != nil {
		hook(lease, destination)
	}
	return directory, filepath.Base(destination), nil
}

func credentialEntryStat(parent *os.File, name string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if parent == nil || name == "" || name == "." || name == ".." {
		return stat, fmt.Errorf("invalid credential entry")
	}
	return stat, unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
}

func sameCredentialStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func safeDeclaredSource(path string, source *os.File, size int64, mode os.FileMode) (os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe source")
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) || info.Size() != size || info.Mode().Perm() != mode.Perm() {
		return nil, fmt.Errorf("source drift")
	}
	return info, nil
}

func readDeclaredSource(source *os.File, size int64) ([]byte, string, error) {
	if size > maxProjectedCredentialBytes {
		return nil, "", fmt.Errorf("source too large")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	bytes := make([]byte, size)
	if _, err := io.ReadFull(source, bytes); err != nil {
		zeroBytes(bytes)
		return nil, "", err
	}
	var extra [1]byte
	if count, err := source.Read(extra[:]); err != io.EOF || count != 0 {
		zeroBytes(bytes)
		return nil, "", fmt.Errorf("source size drift")
	}
	digest := sha256.Sum256(bytes)
	return bytes, fmt.Sprintf("%x", digest), nil
}

func (lease *namespaceLease) validateSeeds() error {
	lease.seedMu.RLock()
	defer lease.seedMu.RUnlock()
	for _, seed := range lease.seeds {
		var sourceErr error
		if seed.authority != nil {
			sourceErr = seed.authority.ValidateCredentialSource(seed.sourceSize, seed.sourceMode, seed.sourceSHA256)
		} else {
			source, err := os.OpenFile(seed.sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				sourceErr = err
			} else {
				info, checkErr := safeDeclaredSource(seed.sourcePath, source, seed.sourceSize, seed.sourceMode)
				if checkErr == nil && !os.SameFile(seed.sourceInfo, info) {
					checkErr = fmt.Errorf("source identity drift")
				}
				if checkErr == nil {
					bytes, digest, readErr := readDeclaredSource(source, seed.sourceSize)
					zeroBytes(bytes)
					if readErr != nil || digest != seed.sourceSHA256 {
						checkErr = fmt.Errorf("source integrity drift")
					}
				}
				sourceErr = checkErr
				_ = source.Close()
			}
		}
		if sourceErr != nil {
			return fmt.Errorf("credential seed drift")
		}
		parent, name, parentErr := lease.openCredentialParent(seed.destination)
		if parentErr != nil {
			return fmt.Errorf("credential seed drift")
		}
		entry, err := credentialEntryStat(parent, name)
		if err != nil || entry.Mode&unix.S_IFMT != unix.S_IFREG || entry.Mode&0777 != 0600 || entry.Size < 0 || entry.Size > maxProjectedCredentialBytes {
			_ = parent.Close()
			return fmt.Errorf("credential seed drift")
		}
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = parent.Close()
			return fmt.Errorf("credential seed drift")
		}
		destinationFile := os.NewFile(uintptr(fd), "validated credential")
		var openedStat unix.Stat_t
		openErr := unix.Fstat(fd, &openedStat)
		closeErr := destinationFile.Close()
		parentCloseErr := parent.Close()
		if openErr != nil || closeErr != nil || parentCloseErr != nil || !sameCredentialStat(entry, openedStat) {
			return fmt.Errorf("credential seed drift")
		}
	}
	return nil
}

func (lease *namespaceLease) zeroAndUnlinkSeeds() error {
	lease.seedMu.Lock()
	defer lease.seedMu.Unlock()
	var cleanupErrors []error
	destinations := make([]ports.CredentialProjectionDestination, 0, len(lease.seeds))
	for destination := range lease.seeds {
		destinations = append(destinations, destination)
	}
	sort.Slice(destinations, func(left, right int) bool { return destinations[left] < destinations[right] })
	for _, destination := range destinations {
		seed := lease.seeds[destination]
		if seed.destinationFile != nil {
			info, err := seed.destinationFile.Stat()
			if err != nil || !os.SameFile(seed.destinationInfo, info) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: retained descriptor drift"))
			} else {
				wipeSize := max(seed.destinationSize, info.Size())
				if err := zeroCredentialFile(seed.destinationFile, wipeSize); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: wipe retained descriptor: %w", err))
				}
			}
			closeErr := seed.destinationFile.Close()
			seed.destinationFile = nil
			lease.seeds[destination] = seed
			if closeErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: close retained descriptor: %w", closeErr))
			}
		}
		parent, name, parentErr := lease.openCredentialParent(seed.destination)
		if parentErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: destination directory: %w", parentErr))
			delete(lease.seeds, destination)
			continue
		}
		info, err := credentialEntryStat(parent, name)
		if err == nil {
			isRegular := info.Mode&unix.S_IFMT == unix.S_IFREG && info.Size >= 0 && info.Size <= maxProjectedCredentialBytes
			isOriginal := credentialFileInfoMatchesStat(seed.destinationInfo, info)
			if isRegular && !isOriginal {
				currentFD, openErr := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if openErr != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: open replacement: %w", openErr))
				} else {
					current := os.NewFile(uintptr(currentFD), "credential replacement")
					replacementSize, safeErr := lease.safeCredentialReplacement(current, info)
					if safeErr != nil {
						cleanupErrors = append(cleanupErrors, safeErr)
					} else if wipeErr := zeroCredentialFile(current, replacementSize); wipeErr != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: wipe replacement: %w", wipeErr))
					}
					if closeErr := current.Close(); closeErr != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: close replacement: %w", closeErr))
					}
				}
			}
			if isRegular {
				currentInfo, statErr := credentialEntryStat(parent, name)
				if statErr == nil && sameCredentialStat(info, currentInfo) {
					if removeErr := unix.Unlinkat(int(parent.Fd()), name, 0); removeErr != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: unlink destination: %w", removeErr))
					} else if syncErr := parent.Sync(); syncErr != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: sync destination directory: %w", syncErr))
					}
				} else if statErr == nil || !errors.Is(statErr, unix.ENOENT) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: replacement drift"))
				}
			}
		} else if !errors.Is(err, unix.ENOENT) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: inspect destination: %w", err))
		}
		if closeErr := parent.Close(); closeErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("credential cleanup: close destination directory: %w", closeErr))
		}
		delete(lease.seeds, destination)
	}
	return errors.Join(cleanupErrors...)
}

func (lease *namespaceLease) safeCredentialReplacement(file *os.File, pathInfo unix.Stat_t) (int64, error) {
	if lease == nil || file == nil || lease.rootDirectory == nil {
		return 0, fmt.Errorf("credential cleanup: invalid replacement")
	}
	var replacement unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &replacement); err != nil {
		return 0, fmt.Errorf("credential cleanup: inspect replacement: %w", err)
	}
	if !sameCredentialStat(pathInfo, replacement) {
		return 0, fmt.Errorf("credential cleanup: replacement drift")
	}
	var root unix.Stat_t
	if err := unix.Fstat(int(lease.rootDirectory.Fd()), &root); err != nil {
		return 0, fmt.Errorf("credential cleanup: inspect namespace root: %w", err)
	}
	if replacement.Mode&unix.S_IFMT != unix.S_IFREG || replacement.Size < 0 || replacement.Size > maxProjectedCredentialBytes ||
		replacement.Nlink != 1 || replacement.Dev != root.Dev || replacement.Uid != root.Uid {
		return 0, fmt.Errorf("credential cleanup: unsafe replacement")
	}
	return replacement.Size, nil
}

func zeroCredentialFile(file *os.File, size int64) error {
	if file == nil || size < 0 || size > maxProjectedCredentialBytes {
		return fmt.Errorf("unsafe credential file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zeros := make([]byte, 32*1024)
	defer zeroBytes(zeros)
	for remaining := size; remaining > 0; {
		count := int64(len(zeros))
		if remaining < count {
			count = remaining
		}
		if _, err := file.Write(zeros[:count]); err != nil {
			return err
		}
		remaining -= count
	}
	return file.Sync()
}

func credentialFileInfoMatchesStat(info os.FileInfo, stat unix.Stat_t) bool {
	if info == nil {
		return false
	}
	system, ok := info.Sys().(*syscall.Stat_t)
	return ok && system.Dev == stat.Dev && system.Ino == stat.Ino && system.Mode&unix.S_IFMT == stat.Mode&unix.S_IFMT
}

func zeroBytes(bytes []byte) {
	for index := range bytes {
		bytes[index] = 0
	}
}
