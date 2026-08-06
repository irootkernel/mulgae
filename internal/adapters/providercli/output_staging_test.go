//go:build darwin

package providercli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/irootkernel/mulgae/internal/domain"
)

// stagedOutputLeaseFixture creates one fresh staging lease beneath a private
// test root and returns the lease together with that root. Cleanup is attempted
// for every case, exactly as the later wiring attempts it on every path.
func stagedOutputLeaseFixture(t *testing.T) (*stagedOutputLease, string) {
	t.Helper()
	root := t.TempDir()
	lease, err := createStagedOutputDirectory(filepath.Join(root, "staging"), "invocation-0000")
	if err != nil {
		t.Fatalf("createStagedOutputDirectory() error = %v", err)
	}
	t.Cleanup(func() { _ = lease.Cleanup() })
	return lease, root
}

// stagedOutputDestinationPath returns the exact absolute path the provider is
// instructed to write, taken from the port contract rather than rebuilt here.
func stagedOutputDestinationPath(t *testing.T, lease *stagedOutputLease) string {
	t.Helper()
	destination, err := lease.Destination()
	if err != nil {
		t.Fatalf("Destination() error = %v", err)
	}
	return destination.AbsolutePath()
}

// writeStagedOutputTestFile stages content at the destination path with an
// exact mode, independent of the process umask.
func writeStagedOutputTestFile(t *testing.T, lease *stagedOutputLease, content []byte, mode os.FileMode) string {
	t.Helper()
	path := stagedOutputDestinationPath(t, lease)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write staged file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod staged file: %v", err)
	}
	return path
}

func requireStagedOutputRejection(t *testing.T, err error, want domain.RuntimeDiagnosticCause) {
	t.Helper()
	if err == nil {
		t.Fatal("staged output validation accepted rejected input")
	}
	requireProviderDiagnosticCause(t, err, want)
}

func TestStagedOutputAcceptsBoundedMarkdownWithDigest(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	content := []byte("# Role report\n\nOne bounded finding.\n")
	writeStagedOutputTestFile(t, lease, content, 0600)

	staged, receipt, err := lease.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !bytes.Equal(staged, content) {
		t.Fatalf("Validate() bytes = %q, want %q", staged, content)
	}
	digest := sha256.Sum256(content)
	if !receipt.Valid() || receipt.SHA256() != "sha256:"+hex.EncodeToString(digest[:]) ||
		receipt.ByteLength() != int64(len(content)) {
		t.Fatalf("receipt = %q/%d, want %q/%d",
			receipt.SHA256(), receipt.ByteLength(), "sha256:"+hex.EncodeToString(digest[:]), len(content))
	}

	if err := lease.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Lstat(lease.path); !os.IsNotExist(err) {
		t.Fatalf("staging directory survived cleanup: %v", err)
	}
}

func TestStagedOutputRejectsSymlinkTarget(t *testing.T) {
	lease, root := stagedOutputLeaseFixture(t)
	target := filepath.Join(root, "outside.md")
	if err := os.WriteFile(target, []byte("# outside the staging boundary\n"), 0600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, stagedOutputDestinationPath(t, lease)); err != nil {
		t.Fatalf("stage symlink: %v", err)
	}

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsHardLinkSubstitution(t *testing.T) {
	lease, root := stagedOutputLeaseFixture(t)
	source := filepath.Join(root, "source.md")
	if err := os.WriteFile(source, []byte("# reachable from another name\n"), 0600); err != nil {
		t.Fatalf("write hard link source: %v", err)
	}
	if err := os.Link(source, stagedOutputDestinationPath(t, lease)); err != nil {
		t.Fatalf("stage hard link: %v", err)
	}

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsNonRegularFile(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	if err := unix.Mkfifo(stagedOutputDestinationPath(t, lease), 0600); err != nil {
		t.Fatalf("stage fifo: %v", err)
	}

	// A blocking open on a provider-planted fifo would stall the adapter, so
	// the rejection must arrive without a writer ever appearing.
	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsExtraStagedEntries(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0600)
	if err := os.WriteFile(filepath.Join(lease.path, "notes.md"), []byte("# extra\n"), 0600); err != nil {
		t.Fatalf("write extra staged entry: %v", err)
	}

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsDirectoryIdentityDrift(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0600)

	// Renaming the staging directory is not the drift a retained descriptor can
	// observe: a rename leaves the descriptor bound to the very same inode, so
	// the lease keeps listing exactly the directory it created and the entry it
	// validates is unchanged. Metadata mutation of that inode is the drift the
	// recorded identity does detect, and 0750 also re-opens the directory to a
	// group that Mulgae never granted staging access.
	if err := os.Chmod(lease.path, 0750); err != nil {
		t.Fatalf("chmod staging directory: %v", err)
	}

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsGroupWritableFileMode(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0664)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsForeignOwner(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0600)

	// A test process cannot give a file away to another user, so the owner the
	// lease requires is moved instead: the staged file is then owned by an
	// identity Mulgae does not accept. The recorded directory identity is left
	// untouched, so the file owner rule is the rule under test.
	lease.ownerUID = uint32(unix.Geteuid()) + 1

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)
}

func TestStagedOutputRejectsInvalidUTF8(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte{0xff, 0xfe}, 0600)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileInvalid)
}

func TestStagedOutputRejectsNULByte(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("a\x00b"), 0600)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileInvalid)
}

func TestStagedOutputRejectsWhitespaceOnlyContent(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte(" \n\t\n"), 0600)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileInvalid)
}

func TestStagedOutputRejectsOversizeContent(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	path := stagedOutputDestinationPath(t, lease)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatalf("create oversize staged file: %v", err)
	}
	// Sparse: the size bound is decided before a single byte is read.
	if err := file.Truncate(stagedOutputMaxBytes + 1); err != nil {
		_ = file.Close()
		t.Fatalf("grow oversize staged file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversize staged file: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatalf("chmod oversize staged file: %v", err)
	}

	_, _, err = lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileInvalid)
}

func TestStagedOutputRejectsEmptyFile(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, nil, 0600)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileInvalid)
}

func TestStagedOutputReportsMissingFile(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)

	_, _, err := lease.Validate()
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputFileMissing)
}

func TestStagedOutputRejectsReusedInvocationDirectory(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "staging")
	lease, err := createStagedOutputDirectory(parent, "invocation-0000")
	if err != nil {
		t.Fatalf("createStagedOutputDirectory() error = %v", err)
	}
	t.Cleanup(func() { _ = lease.Cleanup() })
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0600)

	reused, err := createStagedOutputDirectory(parent, "invocation-0000")
	if err == nil {
		_ = reused.Cleanup()
		t.Fatal("createStagedOutputDirectory() reused an existing staging directory")
	}
	requireStagedOutputRejection(t, err, domain.DiagnosticCauseProviderOutputStagingViolation)

	// The refused create must never disturb the live lease that already owns
	// this directory.
	if _, _, err := lease.Validate(); err != nil {
		t.Fatalf("live lease after refused reuse: %v", err)
	}
}

func TestStagedOutputCleanupRemovesDirectoryAndReportsFailure(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, lease, []byte("# Role report\n"), 0600)
	if err := lease.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Lstat(lease.path); !os.IsNotExist(err) {
		t.Fatalf("staging directory survived cleanup: %v", err)
	}
	if err := lease.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}

	blocked, _ := stagedOutputLeaseFixture(t)
	writeStagedOutputTestFile(t, blocked, []byte("# Role report\n"), 0600)
	// A subdirectory is not an entry this lease may remove: unlinkat refuses a
	// directory, and the lease never recurses into a tree Mulgae did not create.
	if err := os.MkdirAll(filepath.Join(blocked.path, "planted", "nested"), 0700); err != nil {
		t.Fatalf("plant staging subdirectory: %v", err)
	}

	err := blocked.Cleanup()
	if err == nil {
		t.Fatal("Cleanup() removed an unauthorized staging subdirectory")
	}
	requireProviderDiagnosticCause(t, err, domain.DiagnosticCauseProviderOutputStagingCleanupFailed)
	if _, statErr := os.Lstat(blocked.path); statErr != nil {
		t.Fatalf("failed cleanup discarded the staging directory: %v", statErr)
	}
}

func TestStagedOutputLeaseDestinationMatchesPortsContract(t *testing.T) {
	lease, _ := stagedOutputLeaseFixture(t)
	destination, err := lease.Destination()
	if err != nil {
		t.Fatalf("Destination() error = %v", err)
	}
	if !destination.Valid() {
		t.Fatalf("destination = %#v is not valid", destination)
	}
	if destination.Directory() != lease.path || destination.Filename() != stagedOutputFilename {
		t.Fatalf("destination = %q/%q, want %q/%q",
			destination.Directory(), destination.Filename(), lease.path, stagedOutputFilename)
	}
	absolute := destination.AbsolutePath()
	if !filepath.IsAbs(absolute) || !strings.HasSuffix(absolute, string(filepath.Separator)+stagedOutputFilename) {
		t.Fatalf("AbsolutePath() = %q", absolute)
	}

	if err := lease.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := lease.Destination(); err == nil {
		t.Fatal("Destination() served a released lease")
	}
}
