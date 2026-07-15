//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

func TestSecureWriteReceiptBindsLineageDefensively(t *testing.T) {
	root := mustRoot(t, "/tmp/kar")
	sourceIDs := []string{"provider:stdout"}
	receipt, err := ports.NewSecureWriteReceipt(
		root,
		mustRelativePath(t, "nested/artifact.json"),
		"sha256:"+strings.Repeat("a", 64),
		42,
		"provider_stdout",
		sourceIDs,
	)
	if err != nil {
		t.Fatalf("NewSecureWriteReceipt() error = %v", err)
	}
	if receipt.Root() != root {
		t.Fatalf("receipt root = %q, want %q", receipt.Root(), root)
	}
	sourceIDs[0] = "mutated"

	if receipt.Channel() != "provider_stdout" {
		t.Fatalf("receipt channel = %q, want provider_stdout", receipt.Channel())
	}
	gotSourceIDs := receipt.SourceIDs()
	if len(gotSourceIDs) != 1 || gotSourceIDs[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs = %q, want provider:stdout", gotSourceIDs)
	}
	gotSourceIDs[0] = "mutated-again"
	if got := receipt.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs after caller mutation = %q, want provider:stdout", got)
	}
	if _, err := ports.NewSecureWriteReceipt(
		root,
		mustRelativePath(t, "nested/artifact.json"),
		"sha256:"+strings.Repeat("a", 64),
		42,
		"",
		nil,
	); err == nil {
		t.Fatal("NewSecureWriteReceipt() accepted empty channel and source IDs")
	}
	if _, err := ports.NewSecureWriteReceipt(
		root,
		mustRelativePath(t, "nested/artifact.json"),
		"sha256:"+strings.Repeat("a", 64),
		42,
		"provider_stdout",
		nil,
	); err == nil {
		t.Fatal("NewSecureWriteReceipt() accepted empty source IDs")
	}
}

func TestSecureWriterWritesPrivateFileWithReceipt(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	var aborts int
	data := []byte("clean bounded content\n")
	request := secureWriteRequest(t, root, "nested/artifact.json", strings.NewReader(string(data)), 1024, func(error) { aborts++ })

	receipt, drop, err := writer.Write(context.Background(), request)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if receipt.Root() != mustRoot(t, root) || receipt.Destination() != mustRelativePath(t, "nested/artifact.json") {
		t.Fatalf("receipt target = %q/%q", receipt.Root(), receipt.Destination())
	}
	if drop != nil {
		t.Fatalf("Write() drop = %#v, want nil", drop)
	}
	if aborts != 0 {
		t.Fatalf("Abort calls = %d, want 0", aborts)
	}
	if receipt.ByteLength() != int64(len(data)) {
		t.Fatalf("receipt byte length = %d, want %d", receipt.ByteLength(), len(data))
	}
	sum := sha256.Sum256(data)
	if want := fmt.Sprintf("sha256:%x", sum); receipt.SHA256() != want {
		t.Fatalf("receipt SHA256 = %q, want %q", receipt.SHA256(), want)
	}
	if receipt.Channel() != "provider_stdout" {
		t.Fatalf("receipt channel = %q, want provider_stdout", receipt.Channel())
	}
	receiptSourceIDs := receipt.SourceIDs()
	if len(receiptSourceIDs) != 1 || receiptSourceIDs[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs = %q, want provider:stdout", receiptSourceIDs)
	}
	receiptSourceIDs[0] = "mutated"
	if got := receipt.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs after caller mutation = %q, want provider:stdout", got)
	}
	assertPrivateRegularFile(t, filepath.Join(root, "nested", "artifact.json"))
	assertPrivateDirectory(t, filepath.Join(root, "nested"))
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterRejectsExistingDestinationWithoutReplacement(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "nested")); err != nil {
		t.Fatalf("EnsurePrivateDir() error = %v", err)
	}
	destination := filepath.Join(root, "nested", "artifact.json")
	if err := os.WriteFile(destination, []byte("original"), privateFileMode); err != nil {
		t.Fatal(err)
	}

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/artifact.json", strings.NewReader("replacement"), 1024, func(error) { t.Fatal("Abort called") }))
	if err == nil {
		t.Fatal("Write() succeeded for an existing destination")
	}
	if drop != nil {
		t.Fatalf("Write() drop = %#v, want nil", drop)
	}
	if !zeroReceipt(receipt) {
		t.Fatalf("Write() receipt = %#v, want zero receipt", receipt)
	}
	content, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "original" {
		t.Fatalf("existing content = %q, want original", content)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestInstalledButUndurableErrorExposesInstalledReceipt(t *testing.T) {
	root := mustRoot(t, "/tmp/kar")
	receipt, err := ports.NewSecureWriteReceipt(
		root,
		mustRelativePath(t, "nested/artifact.json"),
		"sha256:"+strings.Repeat("a", 64),
		42,
		"provider_stdout",
		[]string{"provider:stdout"},
	)
	if err != nil {
		t.Fatalf("NewSecureWriteReceipt() error = %v", err)
	}
	syncErr := errors.New("directory sync failed")
	writeErr := error(&InstalledButUndurableError{receipt: receipt, cause: syncErr})

	var undurable *InstalledButUndurableError
	if !errors.As(writeErr, &undurable) {
		t.Fatalf("Write() error = %v, want InstalledButUndurableError", writeErr)
	}
	if !errors.Is(writeErr, syncErr) {
		t.Fatalf("Write() error = %v, want directory sync error", writeErr)
	}
	installed := undurable.Receipt()
	if installed.Root() != root ||
		installed.Destination() != receipt.Destination() ||
		installed.SHA256() != receipt.SHA256() ||
		installed.ByteLength() != receipt.ByteLength() ||
		installed.Channel() != receipt.Channel() {
		t.Fatalf("installed receipt = %#v, want receipt observation", installed)
	}
	if got := installed.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("installed receipt source IDs = %q, want provider:stdout", got)
	}
}

func TestSecureWriterRejectsInvalidPortPaths(t *testing.T) {
	for _, value := range []string{"/absolute", "../escape", "nested/../escape", ".", ".."} {
		if _, err := ports.NewSafeRelativePath(value); err == nil {
			t.Fatalf("NewSafeRelativePath(%q) succeeded", value)
		}
	}
}

func TestSecureWriterRejectsSymlinkAndNonRegularComponents(t *testing.T) {
	root := privateTempRoot(t)
	outside := privateTempRoot(t)
	writer := NewSecureWriter()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	_, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "linked/artifact", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") }))
	if err == nil {
		t.Fatal("Write() succeeded through a symlink component")
	}
	if drop != nil {
		t.Fatalf("Write() drop = %#v, want nil", drop)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "artifact")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside artifact stat error = %v, want not exist", statErr)
	}

	if err := unix.Mkfifo(filepath.Join(root, "fifo"), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "fifo/child")); err == nil {
		t.Fatal("EnsurePrivateDir() succeeded through a non-directory node")
	}
	if err := os.Mkdir(filepath.Join(root, "unsafe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "unsafe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "unsafe/artifact", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") })); err == nil || drop != nil {
		t.Fatalf("Write() through unsafe directory = (drop %#v, error %v), want non-drop error", drop, err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "unsafe", "artifact")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe artifact stat error = %v, want not exist", statErr)
	}
}

func TestSecureWriterRejectsExistingFinalSymlink(t *testing.T) {
	root := privateTempRoot(t)
	outside := privateTempRoot(t)
	writer := NewSecureWriter()
	if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "nested")); err != nil {
		t.Fatalf("EnsurePrivateDir() error = %v", err)
	}
	outsideFile := filepath.Join(outside, "target")
	if err := os.WriteFile(outsideFile, []byte("outside"), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "nested", "artifact")); err != nil {
		t.Fatal(err)
	}

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/artifact", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") }))
	if err == nil {
		t.Fatal("Write() succeeded for a final symlink")
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("Write() returned drop/receipt for final symlink: %#v, %#v", drop, receipt)
	}
	content, readErr := os.ReadFile(outsideFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "outside" {
		t.Fatalf("symlink target content = %q, want outside", content)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterDropsCrossChunkSecretAndCleansTemporaryFile(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	var aborts int
	request := secureWriteRequest(t, root, "nested/blocked", &chunkReader{chunks: [][]byte{[]byte("before pass"), []byte("word=value after")}}, 1024, func(error) { aborts++ })

	receipt, drop, err := writer.Write(context.Background(), request)
	if !errors.Is(err, ErrSecretDetected) {
		t.Fatalf("Write() error = %v, want ErrSecretDetected", err)
	}
	assertBlockedWrite(t, receipt, drop, "credential_assignment", aborts)
	if _, statErr := os.Stat(filepath.Join(root, "nested", "blocked")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("blocked destination stat error = %v, want not exist", statErr)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterDropsOverflowAndReadOrContextErrorsOnce(t *testing.T) {
	tests := []struct {
		name     string
		source   io.Reader
		maxBytes int64
		context  func() (context.Context, context.CancelFunc)
		detector string
		wantErr  error
	}{
		{
			name:     "overflow",
			source:   strings.NewReader("12345"),
			maxBytes: 4,
			context:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			detector: "maximum_bytes_exceeded",
			wantErr:  ErrMaxBytesExceeded,
		},
		{
			name:     "source read error",
			source:   errorReader{},
			maxBytes: 1024,
			context:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			detector: "source_read_error",
			wantErr:  ErrSourceRead,
		},
		{
			name:     "cancelled context",
			source:   strings.NewReader("clean"),
			maxBytes: 1024,
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			detector: "context_cancelled",
			wantErr:  ErrContextCancelled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := privateTempRoot(t)
			writer := NewSecureWriter()
			ctx, cancel := test.context()
			defer cancel()
			var aborts int
			receipt, drop, err := writer.Write(ctx, secureWriteRequest(t, root, "nested/blocked", test.source, test.maxBytes, func(error) { aborts++ }))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Write() error = %v, want %v", err, test.wantErr)
			}
			assertBlockedWrite(t, receipt, drop, test.detector, aborts)
			if _, statErr := os.Stat(filepath.Join(root, "nested", "blocked")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("blocked destination stat error = %v, want not exist", statErr)
			}
			assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
		})
	}
}
func TestEnsurePrivateDirSyncsEveryNewParentBeforeAdvance(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	syncErr := errors.New("parent sync failed")
	syncCalls := 0
	operations := writer.operationSet()
	operations.fsync = func(int) error {
		syncCalls++
		return syncErr
	}
	writer.operations = operations

	err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "one/two"))
	if !errors.Is(err, syncErr) {
		t.Fatalf("EnsurePrivateDir() error = %v, want parent sync error", err)
	}
	if syncCalls != 1 {
		t.Fatalf("parent sync calls = %d, want 1", syncCalls)
	}
	assertPrivateDirectory(t, filepath.Join(root, "one"))
	if _, statErr := os.Stat(filepath.Join(root, "one", "two")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("advanced after unsynced parent: %v", statErr)
	}
}

func TestSecureWriterTempSyncFailurePurgesOnce(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	tempSyncErr := errors.New("temporary sync failed")
	syncCalls := 0
	operations := writer.operationSet()
	operations.fsync = func(fd int) error {
		syncCalls++
		if syncCalls == 1 {
			return tempSyncErr
		}
		return unix.Fsync(fd)
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/sync-failure", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") }))
	if !errors.Is(err, tempSyncErr) {
		t.Fatalf("Write() error = %v, want temporary sync error", err)
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("Write() result = (receipt %#v, drop %#v), want zero receipt and nil drop", receipt, drop)
	}
	if syncCalls != 2 {
		t.Fatalf("sync calls = %d, want temporary and cleanup sync", syncCalls)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterTempCloseFailureUsesOneCleanupAttempt(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	closeErr := errors.New("temporary close failed")
	closeCalls := 0
	operations := writer.operationSet()
	operations.close = func(fd int) error {
		closeCalls++
		if closeCalls == 1 {
			return closeErr
		}
		return unix.Close(fd)
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/close-failure", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") }))
	if !errors.Is(err, closeErr) {
		t.Fatalf("Write() error = %v, want temporary close error", err)
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("Write() result = (receipt %#v, drop %#v), want zero receipt and nil drop", receipt, drop)
	}
	if closeCalls != 2 {
		t.Fatalf("close calls = %d, want install close and one cleanup close", closeCalls)
	}
	var cleanupErr *TemporaryCleanupError
	if errors.As(err, &cleanupErr) {
		t.Fatalf("Write() error = %v, want cleanup proven", err)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterCleanupFailureRetainsFailedCloseState(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	closeErr := errors.New("cleanup close failed")
	closeCalls := 0
	operations := writer.operationSet()
	operations.close = func(int) error {
		closeCalls++
		return closeErr
	}
	writer.operations = operations

	aborts := 0
	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/blocked", strings.NewReader("password=value"), 1024, func(error) { aborts++ }))
	if !errors.Is(err, ErrSecretDetected) || !errors.Is(err, closeErr) {
		t.Fatalf("Write() error = %v, want rejection and cleanup close errors", err)
	}
	assertBlockedWrite(t, receipt, drop, "credential_assignment", aborts)
	var cleanupErr *TemporaryCleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("Write() error = %v, want TemporaryCleanupError", err)
	}
	if cleanupErr.temporaryFD < 0 || cleanupErr.temporaryName != "" {
		t.Fatalf("cleanup state = (fd %d, name %q), want failed fd and unlinked name", cleanupErr.temporaryFD, cleanupErr.temporaryName)
	}
	if closeCalls != 1 {
		t.Fatalf("cleanup close calls = %d, want 1", closeCalls)
	}
	if err := unix.Close(cleanupErr.temporaryFD); err != nil {
		t.Fatalf("close retained temporary fd: %v", err)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterUnlinkFailureIsNotRetried(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	unlinkErr := errors.New("cleanup unlink failed")
	unlinkCalls := 0
	operations := writer.operationSet()
	operations.unlinkat = func(int, string, int) error {
		unlinkCalls++
		return unlinkErr
	}
	writer.operations = operations

	aborts := 0
	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/blocked", strings.NewReader("password=value"), 1024, func(error) { aborts++ }))
	if !errors.Is(err, ErrSecretDetected) || !errors.Is(err, unlinkErr) {
		t.Fatalf("Write() error = %v, want rejection and cleanup unlink errors", err)
	}
	assertBlockedWrite(t, receipt, drop, "credential_assignment", aborts)
	var cleanupErr *TemporaryCleanupError
	if !errors.As(err, &cleanupErr) || cleanupErr.temporaryName == "" {
		t.Fatalf("Write() cleanup error = %#v, want retained temporary name", cleanupErr)
	}
	if unlinkCalls != 1 {
		t.Fatalf("unlink calls = %d, want one cleanup attempt", unlinkCalls)
	}
	if err := os.Remove(filepath.Join(root, "nested", cleanupErr.temporaryName)); err != nil {
		t.Fatalf("remove retained temporary file: %v", err)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterCleanupSyncFailureIsTyped(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	syncErr := errors.New("cleanup directory sync failed")
	syncCalls := 0
	operations := writer.operationSet()
	operations.fsync = func(int) error {
		syncCalls++
		return syncErr
	}
	writer.operations = operations

	aborts := 0
	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/blocked", strings.NewReader("password=value"), 1024, func(error) { aborts++ }))
	if !errors.Is(err, ErrSecretDetected) || !errors.Is(err, syncErr) {
		t.Fatalf("Write() error = %v, want rejection and cleanup sync errors", err)
	}
	assertBlockedWrite(t, receipt, drop, "credential_assignment", aborts)
	var cleanupErr *TemporaryCleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("Write() error = %v, want TemporaryCleanupError", err)
	}
	if cleanupErr.temporaryFD != -1 || cleanupErr.temporaryName != "" {
		t.Fatalf("cleanup state = (fd %d, name %q), want removed temporary file", cleanupErr.temporaryFD, cleanupErr.temporaryName)
	}
	if syncCalls != 1 {
		t.Fatalf("cleanup sync calls = %d, want 1", syncCalls)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterRenameFailureDoesNotRetryOrInstall(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	renameErr := errors.New("rename failed")
	renameCalls := 0
	operations := writer.operationSet()
	operations.renameatxNp = func(int, string, int, string, uint32) error {
		renameCalls++
		return renameErr
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/rename-failure", strings.NewReader("clean"), 1024, func(error) { t.Fatal("Abort called") }))
	if !errors.Is(err, renameErr) {
		t.Fatalf("Write() error = %v, want rename error", err)
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("Write() result = (receipt %#v, drop %#v), want zero receipt and nil drop", receipt, drop)
	}
	if renameCalls != 1 {
		t.Fatalf("rename calls = %d, want one", renameCalls)
	}
	if _, statErr := os.Stat(filepath.Join(root, "nested", "rename-failure")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rename failure installed destination: %v", statErr)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterPostRenameSyncFailureReturnsExactInstalledReceipt(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	data := []byte("clean installed bytes")
	postRenameSyncErr := errors.New("post-rename sync failed")
	syncCalls := 0
	renameCalls := 0
	operations := writer.operationSet()
	operations.fsync = func(fd int) error {
		syncCalls++
		if syncCalls == 2 {
			return postRenameSyncErr
		}
		return unix.Fsync(fd)
	}
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		renameCalls++
		return unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/installed", strings.NewReader(string(data)), 1024, func(error) { t.Fatal("Abort called") }))
	if !errors.Is(err, postRenameSyncErr) {
		t.Fatalf("Write() error = %v, want post-rename sync error", err)
	}
	if drop != nil {
		t.Fatalf("Write() drop = %#v, want nil", drop)
	}
	var undurable *InstalledButUndurableError
	if !errors.As(err, &undurable) {
		t.Fatalf("Write() error = %v, want InstalledButUndurableError", err)
	}
	assertReceiptLineage(t, receipt, root, "nested/installed", data)
	assertReceiptLineage(t, undurable.Receipt(), root, "nested/installed", data)
	if syncCalls != 2 || renameCalls != 1 {
		t.Fatalf("transition calls = (sync %d, rename %d), want (2, 1)", syncCalls, renameCalls)
	}
	installed, readErr := os.ReadFile(filepath.Join(root, "nested", "installed"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(installed) != string(data) {
		t.Fatalf("installed bytes = %q, want %q", installed, data)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterAbortPanicCannotBypassCleanup(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	aborts := 0
	receipt, drop, err := writer.Write(context.Background(), secureWriteRequest(t, root, "nested/blocked", strings.NewReader("password=value"), 1024, func(error) {
		aborts++
		panic("abort failed")
	}))
	if !errors.Is(err, ErrSecretDetected) || !errors.Is(err, errAbortCallbackPanicked) {
		t.Fatalf("Write() error = %v, want rejection and abort panic errors", err)
	}
	assertBlockedWrite(t, receipt, drop, "credential_assignment", aborts)
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterNoReplaceRaceInstallsExactlyOneSource(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	start := make(chan struct{})
	type result struct {
		source  string
		receipt ports.SecureWriteReceipt
		drop    *ports.DropMetadata
		err     error
	}
	results := make(chan result, 2)
	var group sync.WaitGroup
	for _, source := range []string{"first", "second"} {
		request := secureWriteRequest(t, root, "nested/race", strings.NewReader(source), 1024, func(error) {})
		group.Add(1)
		go func(source string, request ports.SecureWriteRequest) {
			defer group.Done()
			<-start
			receipt, drop, err := writer.Write(context.Background(), request)
			results <- result{source: source, receipt: receipt, drop: drop, err: err}
		}(source, request)
	}
	close(start)
	group.Wait()
	close(results)

	var winner result
	var loser result
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
			winner = result
			continue
		}
		loser = result
	}
	if successes != 1 {
		t.Fatalf("successful writes = %d, want 1", successes)
	}
	if winner.drop != nil {
		t.Fatalf("winner drop = %#v, want nil", winner.drop)
	}
	if winner.receipt.Root() != mustRoot(t, root) ||
		winner.receipt.Destination() != mustRelativePath(t, "nested/race") ||
		winner.receipt.Channel() != "provider_stdout" ||
		winner.receipt.ByteLength() != int64(len(winner.source)) {
		t.Fatalf("winner receipt = %#v", winner.receipt)
	}
	winnerSum := sha256.Sum256([]byte(winner.source))
	if winner.receipt.SHA256() != fmt.Sprintf("sha256:%x", winnerSum) {
		t.Fatalf("winner receipt SHA256 = %q", winner.receipt.SHA256())
	}
	if got := winner.receipt.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("winner receipt source IDs = %q", got)
	}
	if loser.err == nil || loser.drop != nil || !zeroReceipt(loser.receipt) {
		t.Fatalf("loser result = (receipt %#v, drop %#v, error %v), want zero receipt, nil drop, error", loser.receipt, loser.drop, loser.err)
	}
	content, err := os.ReadFile(filepath.Join(root, "nested", "race"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != winner.source {
		t.Fatalf("installed content = %q, want winner %q", content, winner.source)
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
}

func TestSecureWriterRejectsSymlinkRootAndExistingNonRegularDestinations(t *testing.T) {
	target := privateTempRoot(t)
	parent := t.TempDir()
	symlinkRoot := filepath.Join(parent, "linked-root")
	if err := os.Symlink(target, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	writer := NewSecureWriter()
	receipt, drop, err := writer.Write(
		context.Background(),
		secureWriteRequest(t, symlinkRoot, "artifact", strings.NewReader("clean"), 1024, func(error) {}),
	)
	if err == nil || drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("symlink-root result = (receipt %#v, drop %#v, error %v), want zero receipt, nil drop, error", receipt, drop, err)
	}

	writer, root := secureWriterWithPrivateNestedDir(t)
	for _, testCase := range []struct {
		name   string
		create func(string) error
		check  func(os.FileInfo) bool
	}{
		{
			name:   "directory",
			create: func(path string) error { return os.Mkdir(path, privateDirectoryMode) },
			check:  func(info os.FileInfo) bool { return info.IsDir() },
		},
		{
			name:   "fifo",
			create: func(path string) error { return unix.Mkfifo(path, privateFileMode) },
			check:  func(info os.FileInfo) bool { return info.Mode()&os.ModeNamedPipe != 0 },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			destination := filepath.Join(root, "nested", testCase.name)
			if err := testCase.create(destination); err != nil {
				t.Fatal(err)
			}
			receipt, drop, err := writer.Write(
				context.Background(),
				secureWriteRequest(t, root, "nested/"+testCase.name, strings.NewReader("clean"), 1024, func(error) {}),
			)
			if err == nil || drop != nil || !zeroReceipt(receipt) {
				t.Fatalf("nonregular destination result = (receipt %#v, drop %#v, error %v)", receipt, drop, err)
			}
			info, statErr := os.Lstat(destination)
			if statErr != nil || !testCase.check(info) {
				t.Fatalf("destination changed: info %#v error %v", info, statErr)
			}
			assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
		})
	}
}

func TestSecureWriterRemovesInstallWhenDestinationDirectoryNamespaceChanges(t *testing.T) {
	writer, root := secureWriterWithPrivateNestedDir(t)
	replacement := filepath.Join(root, "replacement")
	detached := filepath.Join(root, "detached")
	if err := os.Mkdir(replacement, privateDirectoryMode); err != nil {
		t.Fatal(err)
	}
	operations := writer.operationSet()
	renameCalls := 0
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		renameCalls++
		if err := os.Rename(filepath.Join(root, "nested"), detached); err != nil {
			return err
		}
		if err := os.Rename(replacement, filepath.Join(root, "nested")); err != nil {
			return err
		}
		return unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(
		context.Background(),
		secureWriteRequest(t, root, "nested/artifact", strings.NewReader("clean"), 1024, func(error) {}),
	)
	if err == nil || !strings.Contains(err.Error(), "destination directory changed after install") {
		t.Fatalf("namespace-swap error = %v", err)
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("namespace-swap result = (receipt %#v, drop %#v), want zero receipt and nil drop", receipt, drop)
	}
	if renameCalls != 1 {
		t.Fatalf("rename calls = %d, want 1", renameCalls)
	}
	for _, path := range []string{
		filepath.Join(root, "nested", "artifact"),
		filepath.Join(detached, "artifact"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("misdirected artifact remains at %q: %v", path, statErr)
		}
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
	assertNoSecureWriterTemps(t, detached)
}
func TestSecureWriterRemovesInstallWhenAnchoredRootNamespaceChanges(t *testing.T) {
	base := privateTempRoot(t)
	root := filepath.Join(base, "root")
	replacement := filepath.Join(base, "replacement")
	detached := filepath.Join(base, "detached")
	for _, directory := range []string{root, replacement} {
		if err := os.MkdirAll(filepath.Join(directory, "nested"), privateDirectoryMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, privateDirectoryMode); err != nil {
			t.Fatal(err)
		}
	}

	writer := NewSecureWriter()
	operations := writer.operationSet()
	renameCalls := 0
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		renameCalls++
		if err := os.Rename(root, detached); err != nil {
			return err
		}
		if err := os.Rename(replacement, root); err != nil {
			return err
		}
		return unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	writer.operations = operations

	receipt, drop, err := writer.Write(
		context.Background(),
		secureWriteRequest(t, root, "nested/artifact", strings.NewReader("clean"), 1024, func(error) {}),
	)
	if err == nil || !strings.Contains(err.Error(), "destination directory changed after install") {
		t.Fatalf("root namespace-swap error = %v", err)
	}
	if drop != nil || !zeroReceipt(receipt) {
		t.Fatalf("root namespace-swap result = (receipt %#v, drop %#v), want zero receipt and nil drop", receipt, drop)
	}
	if renameCalls != 1 {
		t.Fatalf("rename calls = %d, want 1", renameCalls)
	}
	for _, path := range []string{
		filepath.Join(root, "nested", "artifact"),
		filepath.Join(detached, "nested", "artifact"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("misdirected artifact remains at %q: %v", path, statErr)
		}
	}
	assertNoSecureWriterTemps(t, filepath.Join(root, "nested"))
	assertNoSecureWriterTemps(t, filepath.Join(detached, "nested"))
}
func secureWriterWithPrivateNestedDir(t *testing.T) (*SecureWriter, string) {
	t.Helper()

	root := privateTempRoot(t)
	writer := NewSecureWriter()
	if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "nested")); err != nil {
		t.Fatalf("EnsurePrivateDir() error = %v", err)
	}
	return writer, root
}
func secureWriteRequest(t *testing.T, root, destination string, source io.Reader, maxBytes int64, abort func(error)) ports.SecureWriteRequest {
	t.Helper()
	request, err := ports.NewSecureWriteRequest(mustRoot(t, root), mustRelativePath(t, destination), "provider_stdout", source, maxBytes, []string{"provider:stdout"}, abort)
	if err != nil {
		t.Fatalf("NewSecureWriteRequest() error = %v", err)
	}
	return request
}

func privateTempRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, privateDirectoryMode); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustRoot(t *testing.T, value string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(value)
	if err != nil {
		t.Fatalf("NewAnchoredRoot(%q) error = %v", value, err)
	}
	return root
}

func mustRelativePath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatalf("NewSafeRelativePath(%q) error = %v", value, err)
	}
	return path
}

func assertBlockedWrite(t *testing.T, receipt ports.SecureWriteReceipt, drop *ports.DropMetadata, detector string, aborts int) {
	t.Helper()
	if !zeroReceipt(receipt) {
		t.Fatalf("blocked receipt = %#v, want zero receipt", receipt)
	}
	if drop == nil {
		t.Fatal("blocked write drop = nil")
	}
	if drop.Channel() != "provider_stdout" || drop.Detector() != detector || drop.Count() != 1 {
		t.Fatalf("drop = (%q, %q, %d), want provider_stdout, %s, 1", drop.Channel(), drop.Detector(), drop.Count(), detector)
	}
	if got := drop.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("drop source IDs = %q, want provider:stdout", got)
	}
	if aborts != 1 {
		t.Fatalf("Abort calls = %d, want 1", aborts)
	}
}

func zeroReceipt(receipt ports.SecureWriteReceipt) bool {
	return !receipt.Root().Valid() &&
		!receipt.Destination().Valid() &&
		receipt.SHA256() == "" &&
		receipt.ByteLength() == 0 &&
		receipt.Channel() == "" &&
		len(receipt.SourceIDs()) == 0
}

func assertReceiptLineage(t *testing.T, receipt ports.SecureWriteReceipt, root, destination string, data []byte) {
	t.Helper()

	sum := sha256.Sum256(data)
	if receipt.Root() != mustRoot(t, root) ||
		receipt.Destination() != mustRelativePath(t, destination) ||
		receipt.SHA256() != fmt.Sprintf("sha256:%x", sum) ||
		receipt.ByteLength() != int64(len(data)) ||
		receipt.Channel() != "provider_stdout" {
		t.Fatalf("receipt = %#v, want exact root and accepted-byte lineage", receipt)
	}
	if sourceIDs := receipt.SourceIDs(); len(sourceIDs) != 1 || sourceIDs[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs = %q, want provider:stdout", sourceIDs)
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode {
		t.Fatalf("file mode = %v, want regular 0600", info.Mode())
	}
}

func assertPrivateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != privateDirectoryMode {
		t.Fatalf("directory mode = %v, want directory 0700", info.Mode())
	}
}

func assertNoSecureWriterTemps(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".securewriter-") {
			t.Fatalf("temporary file remains: %q", entry.Name())
		}
	}
}

type chunkReader struct {
	chunks [][]byte
}

func (reader *chunkReader) Read(destination []byte) (int, error) {
	if len(reader.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := reader.chunks[0]
	reader.chunks = reader.chunks[1:]
	return copy(destination, chunk), nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("source failed")
}
