//go:build darwin && arm64

// Package filesystem provides Darwin filesystem adapters for ports.
package filesystem

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const streamBufferSize = 32 * 1024

var (
	// ErrSecretDetected reports that the scanner rejected the stream before install.
	ErrSecretDetected = errors.New("secure write rejected detected secret")
	// ErrMaxBytesExceeded reports that the source exceeded the request cap.
	ErrMaxBytesExceeded = errors.New("secure write exceeded maximum bytes")
	// ErrSourceRead reports a source read that cannot safely be persisted.
	ErrSourceRead = errors.New("secure write source read failed")
	// ErrContextCancelled aliases the standard cancellation sentinel so reducers
	// do not mistake this compatibility marker for an independent artifact error.
	ErrContextCancelled = context.Canceled
)

// TemporaryCleanupError reports that removal of a temporary file could not be
// proven durably.
type TemporaryCleanupError struct {
	cause         error
	temporaryFD   int
	temporaryName string
}

func (err *TemporaryCleanupError) Error() string {
	return fmt.Sprintf("secure write temporary cleanup could not be proven: %v", err.cause)
}

// Unwrap returns the close, unlink, or directory-sync failure that prevented a
// durable temporary-file purge. The error retains the post-attempt temporary
// descriptor and name state so failed cleanup is not silently retried.
func (err *TemporaryCleanupError) Unwrap() error {
	return err.cause
}

// InstalledButUndurableError reports an installation whose durable namespace or
// post-install observation cannot be proven. A zero receipt means no installed
// bytes remain authoritative.
type InstalledButUndurableError struct {
	receipt ports.SecureWriteReceipt
	cause   error
}

func (err *InstalledButUndurableError) Error() string {
	return fmt.Sprintf("secure write installed but post-effect durability is uncertain: %v", err.cause)
}

// Unwrap returns the post-install durability or cleanup failure.
func (err *InstalledButUndurableError) Unwrap() error {
	return err.cause
}

// Receipt returns the verified installed receipt, or zero when the installed
// path or bytes could not be proven.
func (err *InstalledButUndurableError) Receipt() ports.SecureWriteReceipt {
	return err.receipt
}

type secureWriterOperations struct {
	fsync         func(int) error
	write         func(int, []byte) (int, error)
	close         func(int) error
	unlinkat      func(int, string, int) error
	renameatxNp   func(int, string, int, string, uint32) error
	afterEOF      func()
	beforeInstall func(int, string)
}
type secureFileIdentity struct {
	device uint64
	inode  uint64
}

func defaultSecureWriterOperations() secureWriterOperations {
	return secureWriterOperations{
		fsync:       unix.Fsync,
		write:       unix.Write,
		close:       unix.Close,
		unlinkat:    unix.Unlinkat,
		renameatxNp: unix.RenameatxNp,
	}
}

func (operations secureWriterOperations) withDefaults() secureWriterOperations {
	defaults := defaultSecureWriterOperations()
	if operations.fsync == nil {
		operations.fsync = defaults.fsync
	}
	if operations.write == nil {
		operations.write = defaults.write
	}
	if operations.close == nil {
		operations.close = defaults.close
	}
	if operations.unlinkat == nil {
		operations.unlinkat = defaults.unlinkat
	}
	if operations.renameatxNp == nil {
		operations.renameatxNp = defaults.renameatxNp
	}
	return operations
}

var errAbortCallbackPanicked = errors.New("secure write abort callback panicked")

// SecureWriter installs only clean bounded streams beneath an approved root.
type SecureWriter struct {
	operations secureWriterOperations
}

var _ ports.SecureFileWriter = (*SecureWriter)(nil)

// NewSecureWriter returns a writer with the fixed Darwin secure-write policy.
func NewSecureWriter() *SecureWriter {
	return &SecureWriter{operations: defaultSecureWriterOperations()}
}

func (writer *SecureWriter) operationSet() secureWriterOperations {
	return writer.operations.withDefaults()
}

// EnsurePrivateDir creates a 0700 directory path beneath root without following
// symlinks and syncs each parent before advancing. Create-mode retries sync
// existing components so a prior parent-sync failure is reproven.
func (writer *SecureWriter) EnsurePrivateDir(root ports.AnchoredRoot, directory ports.SafeRelativePath) error {
	if !root.Valid() || !directory.Valid() {
		return fmt.Errorf("ensure private directory: invalid root or directory")
	}
	fd, err := walkPrivateDirectoryWithOperations(root, strings.Split(directory.String(), "/"), true, writer.operationSet())
	if err != nil {
		return fmt.Errorf("ensure private directory: %w", err)
	}
	closeFD(fd)
	return nil
}

// Write scans a bounded source stream before atomically creating it once without
// replacing an existing destination.
func (writer *SecureWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	if ctx == nil {
		return ports.SecureWriteReceipt{}, nil, fmt.Errorf("secure write: nil context")
	}
	if !request.Root().Valid() || !request.Destination().Valid() || request.Source() == nil || request.MaxBytes() <= 0 || request.Channel() == "" || len(request.SourceIDs()) == 0 || request.Abort() == nil {
		return ports.SecureWriteReceipt{}, nil, fmt.Errorf("secure write: invalid request")
	}

	operations := writer.operationSet()

	buffer := make([]byte, streamBufferSize)
	var scanner credentialScanner
	defer func() {
		zeroBytes(buffer)
		scanner.Reset()
	}()

	parents, name, err := splitDestination(request.Destination())
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, err
	}
	directoryFD, err := walkPrivateDirectoryWithOperations(request.Root(), parents, true, operations)
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, fmt.Errorf("secure write destination directory: %w", err)
	}
	defer closeFD(directoryFD)
	directoryIdentity, err := privateDirectoryIdentityForFD(directoryFD)
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, fmt.Errorf("secure write destination directory: %w", err)
	}

	temporaryFD, temporaryName, err := createPrivateTempFile(operations, directoryFD)
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, err
	}
	cleanupBeforeReturn := func(cause error) error {
		return errors.Join(cause, purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName))
	}

	drop := func(detector string) (*ports.DropMetadata, error) {
		metadata, metadataErr := ports.NewDropMetadata(request.Channel(), detector, 1, request.SourceIDs())
		if metadataErr != nil {
			return nil, fmt.Errorf("secure write drop metadata: %w", metadataErr)
		}
		return &metadata, nil
	}
	reject := func(detector string, cause error) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
		cleanupErr := purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName)
		metadata, metadataErr := drop(detector)
		abortErr := invokeAbort(request.Abort(), cause)
		if metadataErr != nil {
			return ports.SecureWriteReceipt{}, nil, errors.Join(cause, cleanupErr, metadataErr, abortErr)
		}
		return ports.SecureWriteReceipt{}, metadata, errors.Join(cause, cleanupErr, abortErr)
	}
	cancel := func(cause error) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
		cleanupErr := purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName)
		abortErr := invokeAbort(request.Abort(), cause)
		return ports.SecureWriteReceipt{}, nil, errors.Join(cause, ErrContextCancelled, cleanupErr, abortErr)
	}

	hash := sha256.New()
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return cancel(err)
		}

		readSize := int64(len(buffer))
		remaining := request.MaxBytes() - size
		if remaining < readSize {
			readSize = remaining + 1
		}
		readN, readErr := request.Source().Read(buffer[:readSize])
		if readN < 0 || readN > int(readSize) {
			return reject("source_read_error", ErrSourceRead)
		}
		if err := ctx.Err(); err != nil {
			zeroBytes(buffer[:readN])
			return cancel(err)
		}
		if int64(readN) > remaining {
			zeroBytes(buffer[:readN])
			return reject("maximum_bytes_exceeded", ErrMaxBytesExceeded)
		}
		if readN > 0 {
			match, found := scanner.Scan(buffer[:readN])
			if found {
				zeroBytes(buffer[:readN])
				return reject(match.detector, ErrSecretDetected)
			}
			hash.Write(buffer[:readN])
			if writeErr := writeAll(temporaryFD, buffer[:readN]); writeErr != nil {
				zeroBytes(buffer[:readN])
				return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(fmt.Errorf("secure write temporary file: %w", writeErr))
			}
			size += int64(readN)
			zeroBytes(buffer[:readN])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return reject("source_read_error", ErrSourceRead)
		}
		if readN == 0 {
			return reject("source_read_error", ErrSourceRead)
		}
	}
	if operations.afterEOF != nil {
		operations.afterEOF()
	}
	if err := ctx.Err(); err != nil {
		return cancel(err)
	}

	sum := hash.Sum(nil)
	defer zeroBytes(sum)
	receipt, err := ports.NewSecureWriteReceipt(
		request.Root(),
		request.Destination(),
		"sha256:"+hex.EncodeToString(sum),
		size,
		request.Channel(),
		request.SourceIDs(),
	)
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(fmt.Errorf("secure write receipt: %w", err))
	}
	if err := operations.fsync(temporaryFD); err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(fmt.Errorf("secure write sync temporary file: %w", err))
	}
	temporaryIdentity, err := secureFileIdentityForFD(temporaryFD)
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(fmt.Errorf("secure write identify temporary file: %w", err))
	}
	if err := revalidatePrivateDirectory(request.Root(), parents, directoryIdentity, operations); err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(
			fmt.Errorf("secure write destination directory changed before install: %w", err),
		)
	}
	if operations.beforeInstall != nil {
		operations.beforeInstall(directoryFD, temporaryName)
	}
	if err := validateSecureFileAt(directoryFD, temporaryName, temporaryIdentity); err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(
			fmt.Errorf("secure write temporary file changed before install: %w", err),
		)
	}
	if err := ctx.Err(); err != nil {
		return cancel(err)
	}
	if err := operations.renameatxNp(directoryFD, temporaryName, directoryFD, name, unix.RENAME_EXCL); err != nil {
		return ports.SecureWriteReceipt{}, nil, cleanupBeforeReturn(fmt.Errorf("secure write install: %w", err))
	}
	temporaryName = ""
	discardInstalled := func(cause error) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
		if cleanupErr := removeInstalledFile(operations, directoryFD, name, temporaryIdentity); cleanupErr != nil {
			cause = errors.Join(cause, cleanupErr)
		}
		if cleanupErr := purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName); cleanupErr != nil {
			cause = errors.Join(cause, cleanupErr)
		}
		return ports.SecureWriteReceipt{}, nil, &InstalledButUndurableError{cause: cause}
	}
	if err := verifyInstalledFileAt(directoryFD, name, temporaryIdentity, sum, size); err != nil {
		return discardInstalled(fmt.Errorf("secure write verify installed file: %w", err))
	}
	if err := operations.close(temporaryFD); err != nil {
		return discardInstalled(fmt.Errorf("secure write close installed temporary file: %w", err))
	}
	temporaryFD = -1
	if err := revalidatePrivateDirectory(request.Root(), parents, directoryIdentity, operations); err != nil {
		return discardInstalled(fmt.Errorf("secure write destination directory changed after install: %w", err))
	}
	if syncErr := operations.fsync(directoryFD); syncErr != nil {
		cause := fmt.Errorf("secure write sync directory: %w", syncErr)
		if revalidationErr := revalidatePrivateDirectory(request.Root(), parents, directoryIdentity, operations); revalidationErr != nil {
			return discardInstalled(errors.Join(cause, fmt.Errorf("secure write destination directory changed after sync: %w", revalidationErr)))
		}
		if verificationErr := verifyInstalledFileAt(directoryFD, name, temporaryIdentity, sum, size); verificationErr != nil {
			return discardInstalled(errors.Join(cause, fmt.Errorf("secure write verify installed file after sync: %w", verificationErr)))
		}
		return receipt, nil, &InstalledButUndurableError{
			receipt: receipt,
			cause:   cause,
		}
	}
	if err := revalidatePrivateDirectory(request.Root(), parents, directoryIdentity, operations); err != nil {
		return discardInstalled(fmt.Errorf("secure write destination directory changed after sync: %w", err))
	}
	if err := verifyInstalledFileAt(directoryFD, name, temporaryIdentity, sum, size); err != nil {
		return discardInstalled(fmt.Errorf("secure write verify installed file after sync: %w", err))
	}
	return receipt, nil, nil
}

func wrapSecureWriteCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("secure write %s: %w", operation, err)
}
func invokeAbort(abort func(error), cause error) (callbackErr error) {
	defer func() {
		if recover() != nil {
			callbackErr = errAbortCallbackPanicked
		}
	}()
	abort(cause)
	return nil
}

func splitDestination(destination ports.SafeRelativePath) ([]string, string, error) {
	if !destination.Valid() {
		return nil, "", fmt.Errorf("secure write destination: invalid path")
	}
	components := strings.Split(destination.String(), "/")
	if len(components) == 0 || components[len(components)-1] == "" {
		return nil, "", fmt.Errorf("secure write destination: invalid final component")
	}
	return components[:len(components)-1], components[len(components)-1], nil
}

func createPrivateTempFile(operations secureWriterOperations, directoryFD int) (int, string, error) {
	operations = operations.withDefaults()
	var random [16]byte
	defer zeroBytes(random[:])
	for attempts := 0; attempts < 128; attempts++ {
		if _, err := rand.Read(random[:]); err != nil {
			return -1, "", fmt.Errorf("secure write temporary name: %w", err)
		}
		name := ".securewriter-" + hex.EncodeToString(random[:]) + ".tmp"
		fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, privateFileMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return -1, "", fmt.Errorf("secure write create temporary file: %w", err)
		}
		if err := verifyPrivateRegularFile(fd); err != nil {
			temporaryFD, temporaryName := fd, name
			cause := fmt.Errorf("secure write create temporary file: %w", err)
			if cleanupErr := purgeTemporaryFile(operations, directoryFD, &temporaryFD, &temporaryName); cleanupErr != nil {
				return -1, "", errors.Join(cause, cleanupErr)
			}
			return -1, "", cause
		}
		return fd, name, nil
	}
	return -1, "", fmt.Errorf("secure write create temporary file: exhausted random names")
}

func purgeTemporaryFile(operations secureWriterOperations, directoryFD int, temporaryFD *int, temporaryName *string) error {
	operations = operations.withDefaults()
	var cleanupErrors []error
	if *temporaryName != "" {
		canUnlink := true
		if *temporaryFD >= 0 {
			temporaryIdentity, identityErr := secureFileIdentityForFD(*temporaryFD)
			if identityErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("identify temporary file before cleanup: %w", identityErr))
				canUnlink = false
			} else if identityErr := validateSecureFileAt(directoryFD, *temporaryName, temporaryIdentity); identityErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("verify temporary file before cleanup: %w", identityErr))
				canUnlink = false
			}
		}
		if canUnlink {
			if err := operations.unlinkat(directoryFD, *temporaryName, 0); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("unlink temporary file: %w", err))
			} else {
				*temporaryName = ""
			}
		}
	}
	if *temporaryFD >= 0 {
		if err := operations.close(*temporaryFD); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close temporary file: %w", err))
		} else {
			*temporaryFD = -1
		}
	}
	if err := operations.fsync(directoryFD); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("sync temporary directory: %w", err))
	}
	if len(cleanupErrors) == 0 {
		return nil
	}
	return &TemporaryCleanupError{
		cause:         errors.Join(cleanupErrors...),
		temporaryFD:   *temporaryFD,
		temporaryName: *temporaryName,
	}
}

func secureFileIdentityForFD(fd int) (secureFileIdentity, error) {
	if err := verifyPrivateRegularFile(fd); err != nil {
		return secureFileIdentity{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return secureFileIdentity{}, fmt.Errorf("stat private file: %w", err)
	}
	return secureFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validateSecureFileAt(directoryFD int, name string, expected secureFileIdentity) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat installed file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("installed file is not regular")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != privateFileMode {
		return errors.New("installed file owner or mode changed")
	}
	if actual := (secureFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}); actual != expected {
		return errors.New("installed file identity changed")
	}
	return nil
}
func verifyInstalledFileAt(
	directoryFD int,
	name string,
	expected secureFileIdentity,
	expectedSum []byte,
	expectedSize int64,
) error {
	if expectedSize < 0 {
		return errors.New("installed file expected size is negative")
	}
	if err := validateSecureFileAt(directoryFD, name, expected); err != nil {
		return err
	}

	installedFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open installed file: %w", err)
	}
	defer closeFD(installedFD)

	installedIdentity, err := secureFileIdentityForFD(installedFD)
	if err != nil {
		return fmt.Errorf("identify installed file: %w", err)
	}
	if installedIdentity != expected {
		return errors.New("installed file identity changed")
	}

	buffer := make([]byte, streamBufferSize)
	defer zeroBytes(buffer)
	hash := sha256.New()
	var size int64
	for {
		count, readErr := unix.Read(installedFD, buffer)
		if count < 0 || count > len(buffer) {
			return errors.New("invalid installed file read count")
		}
		if count > 0 {
			if int64(count) > expectedSize-size {
				zeroBytes(buffer[:count])
				return errors.New("installed file exceeds expected size")
			}
			size += int64(count)
			if _, err := hash.Write(buffer[:count]); err != nil {
				zeroBytes(buffer[:count])
				return fmt.Errorf("hash installed file: %w", err)
			}
			zeroBytes(buffer[:count])
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("read installed file: %w", readErr)
		}
		if count == 0 {
			break
		}
	}
	if size != expectedSize {
		return errors.New("installed file size changed")
	}
	actualSum := hash.Sum(nil)
	defer zeroBytes(actualSum)
	if subtle.ConstantTimeCompare(actualSum, expectedSum) != 1 {
		return errors.New("installed file bytes changed")
	}
	if err := validateSecureFileAt(directoryFD, name, expected); err != nil {
		return err
	}
	return nil
}

func removeInstalledFile(
	operations secureWriterOperations,
	directoryFD int,
	name string,
	expected secureFileIdentity,
) error {
	if err := validateSecureFileAt(directoryFD, name, expected); err != nil {
		return fmt.Errorf("secure write verify installed file before cleanup: %w", err)
	}
	if err := operations.unlinkat(directoryFD, name, 0); err != nil {
		return wrapSecureWriteCleanupError("remove misdirected installed file", err)
	}
	if err := operations.fsync(directoryFD); err != nil {
		return wrapSecureWriteCleanupError("sync misdirected installed file removal", err)
	}
	return nil
}

func writeAll(fd int, data []byte) error {
	return writeAllWith(fd, data, unix.Write)
}

func writeAllWith(fd int, data []byte, write func(int, []byte) (int, error)) error {
	for len(data) > 0 {
		count, err := write(fd, data)
		if count < 0 || count > len(data) {
			return fmt.Errorf("invalid write count")
		}
		if count > 0 {
			data = data[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
