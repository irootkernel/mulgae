//go:build darwin

package providercli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// stagedOutputFilename is the single base name a staged_file provider
// invocation may write. Mulgae owns the name: provider output never selects it.
const stagedOutputFilename = "role-report.md"

// stagedOutputMaxBytes bounds the untrusted staged file. It must never exceed
// the application role-report bound (maxRoleReportBytes, internal/app/review/
// role_report.go): bytes this adapter accepts must remain acceptable to the
// role-report boundary that consumes them.
const stagedOutputMaxBytes = 8 << 20

// maxStagedOutputDirectoryName bounds the per-invocation directory name.
const maxStagedOutputDirectoryName = 96

// stagedOutputIdentity is the exact descriptor identity of the per-invocation
// staging directory recorded at creation. Validation and cleanup compare
// against these values instead of re-resolving the staging path.
type stagedOutputIdentity struct {
	device int32
	inode  uint64
	mode   uint16
	uid    uint32
}

// stagedOutputLease owns one per-invocation staging directory for its complete
// lifetime. It retains the directory descriptor opened at creation plus the
// parent descriptor that names it, so no later step resolves the staging path
// through a namespace the provider process can write.
type stagedOutputLease struct {
	parentDirectory *os.File
	directory       *os.File
	identity        stagedOutputIdentity
	// ownerUID is the effective UID Mulgae requires to own the staging
	// directory and the staged file. It is recorded once at creation so
	// validation compares against the identity that created the lease.
	ownerUID uint32
	path     string
	name     string
	filename string
	// released records a completed cleanup. The later wiring attempts cleanup
	// on every path, so a repeated call must be a no-op success.
	released bool
	// pendingDescriptors retains descriptors whose close failed so a later
	// cleanup retries them instead of leaking them silently.
	pendingDescriptors []*os.File
}

// createStagedOutputDirectory creates one fresh per-invocation staging
// directory beneath parent and retains its descriptor identity. parent is
// created with owner-only permissions when absent, but the per-invocation
// directory itself must not already exist: a colliding or stale directory could
// carry entries written by an earlier, unrelated provider process.
func createStagedOutputDirectory(parent string, invocationDir string) (*stagedOutputLease, error) {
	if !validCanonicalAbsolute(parent) || parent == string(filepath.Separator) {
		return nil, stagedOutputViolation("invalid staging parent")
	}
	if !validStagedOutputDirectoryName(invocationDir) {
		return nil, stagedOutputViolation("invalid staging directory name")
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, stagedOutputViolation("create staging parent: %w", err)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stagedOutputViolation("open staging parent: %w", err)
	}
	parentDirectory := os.NewFile(uintptr(parentFD), "provider staged output parent")
	if err := unix.Mkdirat(parentFD, invocationDir, 0700); err != nil {
		return nil, stagedOutputCreationFailure(
			parentDirectory, nil, "", stagedOutputViolation("create staging directory: %w", err),
		)
	}
	directoryFD, err := unix.Openat(parentFD, invocationDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stagedOutputCreationFailure(
			parentDirectory, nil, invocationDir, stagedOutputViolation("open staging directory: %w", err),
		)
	}
	lease := &stagedOutputLease{
		parentDirectory: parentDirectory,
		directory:       os.NewFile(uintptr(directoryFD), "provider staged output directory"),
		ownerUID:        uint32(unix.Geteuid()),
		path:            filepath.Join(parent, invocationDir),
		name:            invocationDir,
		filename:        stagedOutputFilename,
	}
	if err := lease.recordIdentity(); err != nil {
		return nil, stagedOutputCreationFailure(parentDirectory, lease.directory, invocationDir, err)
	}
	return lease, nil
}

// recordIdentity pins the created directory through its own descriptor. A fresh
// staging directory must be owner-only, owned by the creating identity, and
// empty: anything else means the directory Mulgae opened is not the directory
// Mulgae just created.
func (lease *stagedOutputLease) recordIdentity() error {
	var identity unix.Stat_t
	if err := unix.Fstat(int(lease.directory.Fd()), &identity); err != nil {
		return stagedOutputViolation("inspect staging directory: %w", err)
	}
	if identity.Mode&unix.S_IFMT != unix.S_IFDIR {
		return stagedOutputViolation("staging directory is not a directory")
	}
	if identity.Mode&0077 != 0 {
		return stagedOutputViolation("staging directory permits non-owner access")
	}
	if identity.Uid != lease.ownerUID {
		return stagedOutputViolation("staging directory is owned by another user")
	}
	names, err := lease.entryNames()
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return stagedOutputViolation("fresh staging directory is not empty")
	}
	lease.identity = stagedOutputIdentity{
		device: identity.Dev, inode: identity.Ino, mode: identity.Mode, uid: identity.Uid,
	}
	return nil
}

// Destination returns the exact absolute path Mulgae instructs the provider to
// write. It is the only staging value that leaves the adapter, and it is never
// carried by a receipt.
func (lease *stagedOutputLease) Destination() (ports.StagedOutputDestination, error) {
	if lease == nil || lease.directory == nil || lease.released {
		return ports.StagedOutputDestination{}, stagedOutputViolation("staged output lease is not open")
	}
	destination, err := ports.NewStagedOutputDestination(lease.path, lease.filename)
	if err != nil {
		return ports.StagedOutputDestination{}, stagedOutputViolation("staged output destination: %w", err)
	}
	return destination, nil
}

// Validate reads back the single file the provider was allowed to stage and
// returns its exact bytes with their path-free receipt. It must be called only
// after the provider process has fully terminated: a live process can still
// mutate the staging directory, so an earlier call proves nothing about the
// bytes it returns. The bytes remain untrusted provider output.
func (lease *stagedOutputLease) Validate() ([]byte, ports.StagedOutputReceipt, error) {
	if lease == nil || lease.directory == nil || lease.released {
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged output lease is not open")
	}
	directoryFD := int(lease.directory.Fd())
	if err := lease.verifyDirectoryIdentity(directoryFD); err != nil {
		return nil, ports.StagedOutputReceipt{}, err
	}
	if err := lease.verifyStagedEntries(); err != nil {
		return nil, ports.StagedOutputReceipt{}, err
	}
	// O_NONBLOCK keeps a provider-planted FIFO or device node from blocking the
	// adapter inside open(2); the file type is rejected immediately afterwards.
	fileFD, err := unix.Openat(
		directoryFD, lease.filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return nil, ports.StagedOutputReceipt{}, stagedOutputFileMissing("open staged file: %w", err)
		case errors.Is(err, unix.ELOOP):
			return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file is a symbolic link: %w", err)
		default:
			return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("open staged file: %w", err)
		}
	}
	content, receipt, err := lease.readStagedFile(fileFD)
	if closeErr := unix.Close(fileFD); closeErr != nil && err == nil {
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("close staged file: %w", closeErr)
	}
	if err != nil {
		return nil, ports.StagedOutputReceipt{}, err
	}
	return content, receipt, nil
}

// verifyDirectoryIdentity proves the retained descriptor still names the exact
// directory recorded at creation and still excludes every non-owner.
func (lease *stagedOutputLease) verifyDirectoryIdentity(directoryFD int) error {
	var identity unix.Stat_t
	if err := unix.Fstat(directoryFD, &identity); err != nil {
		return stagedOutputViolation("inspect staging directory: %w", err)
	}
	if identity.Dev != lease.identity.device || identity.Ino != lease.identity.inode ||
		identity.Mode != lease.identity.mode || identity.Uid != lease.identity.uid {
		return stagedOutputViolation("staging directory identity drift")
	}
	if identity.Mode&0077 != 0 {
		return stagedOutputViolation("staging directory permits non-owner access")
	}
	return nil
}

// verifyStagedEntries requires exactly the one entry Mulgae named. An empty
// staging directory is an ordinary missing report; anything else present is a
// provider that wrote outside the single file it was granted.
func (lease *stagedOutputLease) verifyStagedEntries() error {
	names, err := lease.entryNames()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return stagedOutputFileMissing("provider staged no output file")
	}
	if len(names) > 1 {
		return stagedOutputViolation("staging directory holds %d entries", len(names))
	}
	// The unexpected name is provider-controlled and stays out of diagnostics.
	if names[0] != lease.filename {
		return stagedOutputViolation("staging directory holds an unexpected entry")
	}
	return nil
}

// readStagedFile validates the opened descriptor and reads exactly the bytes it
// reported. Every rule is descriptor-bound: the staged path is never consulted
// again once the file is open.
func (lease *stagedOutputLease) readStagedFile(fileFD int) ([]byte, ports.StagedOutputReceipt, error) {
	var staged unix.Stat_t
	if err := unix.Fstat(fileFD, &staged); err != nil {
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("inspect staged file: %w", err)
	}
	switch {
	case staged.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file is not a regular file")
	case staged.Nlink != 1:
		// A second link means the accepted inode is also reachable, and
		// mutable, from a name Mulgae never authorized.
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file has %d links", staged.Nlink)
	case staged.Dev != lease.identity.device:
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file is on another device")
	case staged.Uid != lease.ownerUID:
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file is owned by another user")
	case staged.Mode&0022 != 0:
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file permits non-owner writes")
	case staged.Size == 0:
		return nil, ports.StagedOutputReceipt{}, stagedOutputFileInvalid("staged file is empty")
	case staged.Size > stagedOutputMaxBytes:
		return nil, ports.StagedOutputReceipt{}, stagedOutputFileInvalid(
			"staged file exceeds %d bytes", int64(stagedOutputMaxBytes),
		)
	}

	content := make([]byte, staged.Size)
	if err := readStagedOutputBytes(fileFD, content); err != nil {
		return nil, ports.StagedOutputReceipt{}, err
	}
	var current unix.Stat_t
	if err := unix.Fstat(fileFD, &current); err != nil {
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("re-inspect staged file: %w", err)
	}
	if current.Dev != staged.Dev || current.Ino != staged.Ino || current.Size != staged.Size {
		return nil, ports.StagedOutputReceipt{}, stagedOutputViolation("staged file changed while it was read")
	}
	if err := validateStagedOutputContent(content); err != nil {
		return nil, ports.StagedOutputReceipt{}, err
	}
	digest := sha256.Sum256(content)
	receipt, err := ports.NewStagedOutputReceipt("sha256:"+hex.EncodeToString(digest[:]), int64(len(content)))
	if err != nil {
		return nil, ports.StagedOutputReceipt{}, stagedOutputFileInvalid("staged output receipt: %w", err)
	}
	return content, receipt, nil
}

// readStagedOutputBytes reads exactly len(content) bytes through the descriptor
// that was identity-checked and then proves the file holds no more. A short
// read means the file shrank, an extra byte means it grew: either way the bytes
// are not the bytes that were measured.
func readStagedOutputBytes(fileFD int, content []byte) error {
	for offset := 0; offset < len(content); {
		read, err := unix.Pread(fileFD, content[offset:], int64(offset))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return stagedOutputViolation("read staged file: %w", err)
		}
		if read == 0 {
			return stagedOutputViolation("staged file is shorter than its recorded size")
		}
		offset += read
	}
	var extra [1]byte
	read, err := unix.Pread(fileFD, extra[:], int64(len(content)))
	if err != nil {
		return stagedOutputViolation("read staged file: %w", err)
	}
	if read != 0 {
		return stagedOutputViolation("staged file grew while it was read")
	}
	return nil
}

// validateStagedOutputContent applies the content rules Mulgae requires of an
// untrusted staged Markdown body before any consumer observes it.
func validateStagedOutputContent(content []byte) error {
	if bytes.IndexByte(content, 0) >= 0 {
		return stagedOutputFileInvalid("staged file contains a NUL byte")
	}
	if !utf8.Valid(content) {
		return stagedOutputFileInvalid("staged file is not valid UTF-8")
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return stagedOutputFileInvalid("staged file contains only whitespace")
	}
	return nil
}

// Cleanup removes the staging directory and releases its descriptors. The later
// wiring attempts it on every path, so a completed cleanup is a no-op success
// on repeat. A failure keeps the lease intact, descriptors included, so a retry
// still owns the exact identity it must remove.
func (lease *stagedOutputLease) Cleanup() error {
	if lease == nil {
		return stagedOutputCleanupFailure("invalid staged output lease")
	}
	if lease.released {
		return nil
	}
	if lease.directory == nil || lease.parentDirectory == nil {
		return stagedOutputCleanupFailure("staged output lease retains no descriptors")
	}
	directoryFD, parentFD := int(lease.directory.Fd()), int(lease.parentDirectory.Fd())
	if err := lease.verifyDirectoryIdentity(directoryFD); err != nil {
		return stagedOutputCleanupFailure("refuse to remove a drifted staging directory: %w", err)
	}
	names, err := lease.entryNames()
	if err != nil {
		return stagedOutputCleanupFailure("list staging directory: %w", err)
	}
	for _, name := range names {
		// Staging may hold at most the one staged file. Anything else - a
		// subdirectory in particular - fails closed rather than authorizing
		// this lease to delete a tree Mulgae never created.
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return stagedOutputCleanupFailure("remove staged entry: %w", err)
		}
	}
	if err := namespaceEntryMatches(parentFD, lease.name, lease.identity.device, lease.identity.inode); err != nil {
		return stagedOutputCleanupFailure("staging directory identity drift: %w", err)
	}
	if err := unix.Unlinkat(parentFD, lease.name, unix.AT_REMOVEDIR); err != nil {
		return stagedOutputCleanupFailure("remove staging directory: %w", err)
	}
	if err := verifyDescriptorDetached(directoryFD, lease.identity.device, lease.identity.inode); err != nil {
		return stagedOutputCleanupFailure("staging directory remains linked: %w", err)
	}
	if err := lease.closeDescriptors(); err != nil {
		return err
	}
	lease.released = true
	return nil
}

// entryNames lists the staging directory through the retained descriptor. The
// staging path is never re-resolved, so a replaced directory entry cannot
// redirect the listing to another directory.
func (lease *stagedOutputLease) entryNames() ([]string, error) {
	names, pending, err := namespaceDirectoryNames(int(lease.directory.Fd()))
	if pending != nil {
		lease.pendingDescriptors = append(lease.pendingDescriptors, pending)
	}
	if err != nil {
		return nil, stagedOutputViolation("list staging directory: %w", err)
	}
	entries := make([]string, 0, len(names))
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		entries = append(entries, name)
	}
	return entries, nil
}

func (lease *stagedOutputLease) closeDescriptors() error {
	var errs []error
	for index := len(lease.pendingDescriptors) - 1; index >= 0; index-- {
		if err := lease.pendingDescriptors[index].Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staging scan descriptor: %w", err))
			continue
		}
		lease.pendingDescriptors = append(lease.pendingDescriptors[:index], lease.pendingDescriptors[index+1:]...)
	}
	if lease.directory != nil {
		if err := lease.directory.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staging directory descriptor: %w", err))
		} else {
			lease.directory = nil
		}
	}
	if lease.parentDirectory != nil {
		if err := lease.parentDirectory.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staging parent descriptor: %w", err))
		} else {
			lease.parentDirectory = nil
		}
	}
	if len(errs) != 0 {
		return stagedOutputCleanupFailure("release staging descriptors: %w", errors.Join(errs...))
	}
	return nil
}

// stagedOutputCreationFailure rolls back a staging directory that could never
// be handed to a caller. The construction cause stays outermost, so the later
// wiring classifies the refusal rather than the rollback.
func stagedOutputCreationFailure(parent, directory *os.File, name string, cause error) error {
	var errs []error
	if directory != nil {
		if err := directory.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staging directory descriptor: %w", err))
		}
	}
	if parent != nil {
		if name != "" {
			if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
				errs = append(errs, fmt.Errorf("remove staging directory: %w", err))
			}
		}
		if err := parent.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close staging parent descriptor: %w", err))
		}
	}
	if len(errs) == 0 {
		return cause
	}
	return errors.Join(cause, errors.Join(errs...))
}

// validStagedOutputDirectoryName accepts exactly one safe, traversal-free base
// name for the per-invocation staging directory.
func validStagedOutputDirectoryName(value string) bool {
	if value == "" || len(value) > maxStagedOutputDirectoryName || value[0] == '.' {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// stagedOutputViolation reports a staging boundary breach: the provider wrote
// something Mulgae never authorized, or the staging identity moved underneath
// the retained descriptor.
func stagedOutputViolation(format string, args ...any) error {
	return newProviderOutputFailure(
		domain.DiagnosticCauseProviderOutputStagingViolation, fmt.Errorf("provider staged output: "+format, args...),
	)
}

// stagedOutputFileMissing reports the ordinary operational outcome of a
// provider that staged no file at all.
func stagedOutputFileMissing(format string, args ...any) error {
	return newProviderOutputFailure(
		domain.DiagnosticCauseProviderOutputFileMissing, fmt.Errorf("provider staged output: "+format, args...),
	)
}

// stagedOutputFileInvalid reports a staged file that exists inside the
// authorized boundary but cannot be a role report body.
func stagedOutputFileInvalid(format string, args ...any) error {
	return newProviderOutputFailure(
		domain.DiagnosticCauseProviderOutputFileInvalid, fmt.Errorf("provider staged output: "+format, args...),
	)
}

// stagedOutputCleanupFailure reports staging that could not be proven removed.
func stagedOutputCleanupFailure(format string, args ...any) error {
	return newProviderOutputFailure(
		domain.DiagnosticCauseProviderOutputStagingCleanupFailed,
		fmt.Errorf("provider staged output: "+format, args...),
	)
}
