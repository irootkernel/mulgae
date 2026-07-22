package providercli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const maxProjectedCredentialBytes int64 = 16 << 20

type credentialSeed struct {
	sourcePath      string
	sourceInfo      os.FileInfo
	destination     string
	destinationInfo os.FileInfo
	destinationFile *os.File
	sha256          string
	size            int64
	mode            os.FileMode
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
	if _, err := safeDeclaredSource(request.SourcePath(), source, request.Size(), request.Mode()); err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: source drift")
	}
	if err := ctx.Err(); err != nil {
		return ports.CredentialProjectionReceipt{}, err
	}

	parent, err := lease.validateCredentialDirectory(destination)
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: namespace drift")
	}
	path := filepath.Join(parent, filepath.Base(destination))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: create destination")
	}
	created := true
	defer func() {
		if created {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if count, err := file.Write(bytes); err != nil || count != len(bytes) || file.Sync() != nil || file.Close() != nil {
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: write destination")
	}
	created = false
	if err := syncCredentialDirectory(parent); err != nil {
		_ = os.Remove(path)
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: write destination")
	}
	destinationInfo, err := os.Lstat(path)
	if err != nil || !destinationInfo.Mode().IsRegular() || destinationInfo.Mode().Perm() != 0600 || destinationInfo.Size() != request.Size() {
		_ = os.Remove(path)
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	destinationFile, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = os.Remove(path)
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	openedInfo, openErr := destinationFile.Stat()
	if openErr != nil || !os.SameFile(destinationInfo, openedInfo) {
		_ = destinationFile.Close()
		_ = os.Remove(path)
		return ports.CredentialProjectionReceipt{}, fmt.Errorf("credential projection: destination drift")
	}
	lease.seeds[request.Destination()] = credentialSeed{sourcePath: request.SourcePath(), sourceInfo: sourceInfo, destination: destination, destinationInfo: destinationInfo, destinationFile: destinationFile, sha256: request.SHA256(), size: request.Size(), mode: request.Mode(), authority: request.SourceAuthority()}
	return ports.NewCredentialProjectionReceipt(request.Destination())
}

func credentialDestination(destination ports.CredentialProjectionDestination) (string, bool) {
	switch destination {
	case ports.CredentialProjectionKimiConfig:
		return "home/.kimi-code/config.toml", true
	case ports.CredentialProjectionKimiCredentials:
		return "home/.kimi-code/credentials/kimi-code.json", true
	case ports.CredentialProjectionZCodeConfig:
		return "home/.zcode/cli/config.json", true
	default:
		return "", false
	}
}

func (lease *namespaceLease) validateCredentialDirectory(destination string) (string, error) {
	rootInfo, err := os.Lstat(lease.root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm()&0077 != 0 || !os.SameFile(lease.rootInfo, rootInfo) {
		return "", fmt.Errorf("namespace drift")
	}
	relative := filepath.Dir(destination)
	current := ""
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		expected, ok := lease.directoryInfo[current]
		if !ok {
			return "", fmt.Errorf("unknown credential directory")
		}
		info, err := os.Lstat(filepath.Join(lease.root, current))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0077 != 0 || !os.SameFile(expected, info) {
			return "", fmt.Errorf("namespace drift")
		}
	}
	return filepath.Join(lease.root, relative), nil
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
			sourceErr = seed.authority.ValidateCredentialSource(seed.size, seed.mode, seed.sha256)
		} else {
			source, err := os.OpenFile(seed.sourcePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				sourceErr = err
			} else {
				info, checkErr := safeDeclaredSource(seed.sourcePath, source, seed.size, seed.mode)
				if checkErr == nil && !os.SameFile(seed.sourceInfo, info) {
					checkErr = fmt.Errorf("source identity drift")
				}
				if checkErr == nil {
					bytes, digest, readErr := readDeclaredSource(source, seed.size)
					zeroBytes(bytes)
					if readErr != nil || digest != seed.sha256 {
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
		parent, parentErr := lease.validateCredentialDirectory(seed.destination)
		if parentErr != nil {
			return fmt.Errorf("credential seed drift")
		}
		path := filepath.Join(parent, filepath.Base(seed.destination))
		destinationInfo, err := os.Lstat(path)
		if err != nil || !destinationInfo.Mode().IsRegular() || destinationInfo.Mode().Perm() != 0600 || destinationInfo.Size() > maxProjectedCredentialBytes {
			return fmt.Errorf("credential seed drift")
		}
		destinationFile, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("credential seed drift")
		}
		openedInfo, openErr := destinationFile.Stat()
		closeErr := destinationFile.Close()
		if openErr != nil || closeErr != nil || !os.SameFile(destinationInfo, openedInfo) {
			return fmt.Errorf("credential seed drift")
		}
	}
	return nil
}

func (lease *namespaceLease) zeroAndUnlinkSeeds() error {
	lease.seedMu.Lock()
	defer lease.seedMu.Unlock()
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
				return fmt.Errorf("credential cleanup failed")
			}
			wipeSize := seed.size
			if info.Size() > wipeSize {
				wipeSize = info.Size()
			}
			if wipeSize > maxProjectedCredentialBytes {
				return fmt.Errorf("credential cleanup failed")
			}
			if _, err := seed.destinationFile.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("credential cleanup failed")
			}
			zeros := make([]byte, 32*1024)
			for remaining := wipeSize; remaining > 0; {
				count := int64(len(zeros))
				if remaining < count {
					count = remaining
				}
				if _, err := seed.destinationFile.Write(zeros[:count]); err != nil {
					zeroBytes(zeros)
					return fmt.Errorf("credential cleanup failed")
				}
				remaining -= count
			}
			zeroBytes(zeros)
			syncErr := seed.destinationFile.Sync()
			closeErr := seed.destinationFile.Close()
			seed.destinationFile = nil
			lease.seeds[destination] = seed
			if syncErr != nil || closeErr != nil {
				return fmt.Errorf("credential cleanup failed")
			}
		}
		parent, parentErr := lease.validateCredentialDirectory(seed.destination)
		if parentErr != nil {
			return fmt.Errorf("credential cleanup failed")
		}
		path := filepath.Join(parent, filepath.Base(seed.destination))
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && os.SameFile(seed.destinationInfo, info) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("credential cleanup failed")
			}
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("credential cleanup failed")
		}
		delete(lease.seeds, destination)
	}
	return nil
}

func syncCredentialDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func zeroBytes(bytes []byte) {
	for index := range bytes {
		bytes[index] = 0
	}
}
