//go:build darwin && arm64

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestInstallConfigRejectsTemporaryByteMutationBeforeInstall(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".kar"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	operations := writer.operationSet()
	operations.beforeInstall = func(directoryFD int, name string) {
		overwriteSecureWriterFile(t, directoryFD, name, []byte("version: 2\n"))
	}
	writer.operations = operations

	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.InstallConfig(context.Background(), root, prepared, []byte("version: 1\n"))
	if err == nil || receipt.Installed() {
		t.Fatalf("InstallConfig() = (%#v, %v), want rejected preinstall", receipt, err)
	}
	var installErr *ports.ConfigInstallError
	if !errors.As(err, &installErr) || installErr.Stage() != ports.ConfigInstallStagePreinstall || installErr.DestinationState() != ports.ConfigDestinationAbsent {
		t.Fatalf("InstallConfig() error = %v, want preinstall/absent", err)
	}
	if _, statErr := os.Lstat(filepath.Join(rootPath, ".kar", "config.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mutated config destination exists: %v", statErr)
	}
}

func TestInstallConfigClassifiesCancellationWithConcurrentDestinationAsCollision(t *testing.T) {
	rootPath := configInstallTestRoot(t)
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	operations := writer.operationSet()
	defaultWrite := operations.write
	created := false
	operations.write = func(fd int, data []byte) (int, error) {
		written, writeErr := defaultWrite(fd, data)
		if writeErr == nil && !created {
			created = true
			if err := os.WriteFile(filepath.Join(rootPath, ".kar", "config.yaml"), []byte("external\n"), 0o600); err != nil {
				return written, err
			}
			cancel()
		}
		return written, writeErr
	}
	writer.operations = operations
	receipt, installErr := writer.InstallConfig(ctx, root, prepared, []byte("version: 1\n"))
	var typed *ports.ConfigInstallError
	if installErr == nil || receipt.Installed() || !errors.As(installErr, &typed) || typed.Stage() != ports.ConfigInstallStageCollision || typed.DestinationState() != ports.ConfigDestinationPresent {
		t.Fatalf("InstallConfig() = (%#v, %v), want collision/present", receipt, installErr)
	}
	contents, readErr := os.ReadFile(filepath.Join(rootPath, ".kar", "config.yaml"))
	if readErr != nil || string(contents) != "external\n" {
		t.Fatalf("concurrent destination changed: %q, %v", contents, readErr)
	}
	entries, readErr := os.ReadDir(filepath.Join(rootPath, ".kar"))
	if readErr != nil || len(entries) != 1 || entries[0].Name() != "config.yaml" {
		t.Fatalf("owned temporary was not cleaned: %#v, %v", entries, readErr)
	}
}

func TestInstallConfigRejectsPreparedDirectorySubstitutionBeforeTempCreation(t *testing.T) {
	rootPath := configInstallTestRoot(t)
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rootPath, ".kar"), filepath.Join(rootPath, ".kar-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".kar"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".kar", "config.yaml"), []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.InstallConfig(context.Background(), root, prepared, []byte("version: 1\n"))
	if err == nil || receipt.Installed() {
		t.Fatalf("InstallConfig() = (%#v, %v), want identity rejection", receipt, err)
	}
	var installErr *ports.ConfigInstallError
	if !errors.As(err, &installErr) || installErr.Stage() != ports.ConfigInstallStagePreparedIdentity {
		t.Fatalf("InstallConfig() error = %v, want prepared-identity rejection", err)
	}
	if installErr.DestinationState() != ports.ConfigDestinationPresent {
		t.Fatalf("InstallConfig() destination = %s, want present", installErr.DestinationState())
	}
	contents, readErr := os.ReadFile(filepath.Join(rootPath, ".kar", "config.yaml"))
	if readErr != nil || string(contents) != "replacement\n" {
		t.Fatalf("replacement config changed: %q, %v", contents, readErr)
	}
}

func TestInstallConfigShortWriteCleansOwnedTemporary(t *testing.T) {
	rootPath := configInstallTestRoot(t)
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	operations := writer.operationSet()
	operations.write = func(int, []byte) (int, error) { return 0, nil }
	writer.operations = operations
	receipt, err := writer.InstallConfig(context.Background(), root, prepared, []byte("version: 1\n"))
	if err == nil || receipt.Installed() {
		t.Fatalf("InstallConfig() = (%#v, %v), want short-write rejection", receipt, err)
	}
	entries, readErr := os.ReadDir(filepath.Join(rootPath, ".kar"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("temporary cleanup = entries %#v err %v", entries, readErr)
	}
}

func TestPrepareConfigDirectoryRetryReprovesVisibleDirectory(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	operations := writer.operationSet()
	operations.fsync = func(int) error { return errors.New("injected root sync") }
	writer.operations = operations
	first, firstErr := writer.PrepareConfigDirectory(context.Background(), root)
	if firstErr == nil || !first.CreatedByInvocation() {
		t.Fatalf("first PrepareConfigDirectory() = (%#v, %v)", first, firstErr)
	}
	second, secondErr := writer.PrepareConfigDirectory(context.Background(), root)
	if secondErr == nil || second.CreatedByInvocation() {
		t.Fatalf("second PrepareConfigDirectory() = (%#v, %v)", second, secondErr)
	}
	writer.operations = defaultSecureWriterOperations()
	third, thirdErr := writer.PrepareConfigDirectory(context.Background(), root)
	if thirdErr != nil || third.CreatedByInvocation() {
		t.Fatalf("retry PrepareConfigDirectory() = (%#v, %v)", third, thirdErr)
	}
}

func TestPrepareConfigDirectoryRootSyncReportsConcurrentDestination(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T) string
		created bool
	}{
		{
			name: "created private directory",
			prepare: func(t *testing.T) string {
				rootPath, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rootPath, 0o700); err != nil {
					t.Fatal(err)
				}
				return rootPath
			},
			created: true,
		},
		{
			name:    "existing private directory",
			prepare: configInstallTestRoot,
			created: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := test.prepare(t)
			root := mustRoot(t, rootPath)
			writer := NewSecureWriter()
			operations := writer.operationSet()
			operations.fsync = func(int) error {
				if err := os.WriteFile(filepath.Join(rootPath, ".kar", "config.yaml"), []byte("external\n"), 0o600); err != nil {
					return err
				}
				return errors.New("injected root sync")
			}
			writer.operations = operations

			receipt, prepareErr := writer.PrepareConfigDirectory(context.Background(), root)
			var typed *ports.ConfigInstallError
			if prepareErr == nil || !errors.As(prepareErr, &typed) {
				t.Fatalf("PrepareConfigDirectory() = (%#v, %v), want typed root-sync failure", receipt, prepareErr)
			}
			if receipt.CreatedByInvocation() != test.created || typed.Stage() != ports.ConfigInstallStageRootSync || typed.DestinationState() != ports.ConfigDestinationPresent {
				t.Fatalf("PrepareConfigDirectory() = (%#v, %v), want created=%t root-sync/present", receipt, prepareErr, test.created)
			}
			contents, err := os.ReadFile(filepath.Join(rootPath, ".kar", "config.yaml"))
			if err != nil || string(contents) != "external\n" {
				t.Fatalf("concurrent destination = %q, %v", contents, err)
			}
		})
	}
}

func TestInstallConfigRetainsInstalledBytesWhenDirectorySyncFails(t *testing.T) {
	rootPath := configInstallTestRoot(t)
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	operations := writer.operationSet()
	fsyncCalls := 0
	operations.fsync = func(fd int) error {
		fsyncCalls++
		if fsyncCalls == 2 {
			return errors.New("injected directory sync")
		}
		return defaultSecureWriterOperations().fsync(fd)
	}
	writer.operations = operations
	receipt, installErr := writer.InstallConfig(context.Background(), root, prepared, []byte("version: 1\n"))
	var typed *ports.ConfigInstallError
	if installErr == nil || !receipt.Installed() || !errors.As(installErr, &typed) || typed.Stage() != ports.ConfigInstallStageDirectorySync {
		t.Fatalf("InstallConfig() = (%#v, %v), want installed directory-sync failure", receipt, installErr)
	}
	contents, readErr := os.ReadFile(filepath.Join(rootPath, ".kar", "config.yaml"))
	if readErr != nil || string(contents) != "version: 1\n" {
		t.Fatalf("retained config = %q err %v", contents, readErr)
	}
}

func TestInstallConfigReportsNamespaceLossAsInstalledNotObserved(t *testing.T) {
	rootPath := configInstallTestRoot(t)
	root := mustRoot(t, rootPath)
	writer := NewSecureWriter()
	prepared, err := writer.PrepareConfigDirectory(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	operations := writer.operationSet()
	fsyncCalls := 0
	operations.fsync = func(fd int) error {
		fsyncCalls++
		if fsyncCalls == 2 {
			if err := os.Rename(filepath.Join(rootPath, ".kar"), filepath.Join(rootPath, ".kar-installed")); err != nil {
				return err
			}
			if err := os.Mkdir(filepath.Join(rootPath, ".kar"), 0o700); err != nil {
				return err
			}
		}
		return defaultSecureWriterOperations().fsync(fd)
	}
	writer.operations = operations
	receipt, installErr := writer.InstallConfig(context.Background(), root, prepared, []byte("version: 1\n"))
	var typed *ports.ConfigInstallError
	if installErr == nil || !receipt.Installed() || !errors.As(installErr, &typed) ||
		typed.Stage() != ports.ConfigInstallStageFinalReattestation || typed.DestinationState() != ports.ConfigDestinationNotObserved {
		t.Fatalf("InstallConfig() = (%#v, %v), want installed final-reattestation/not-observed failure", receipt, installErr)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, ".kar", "config.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("visible replacement contains config: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(rootPath, ".kar-installed", "config.yaml"))
	if err != nil || string(contents) != "version: 1\n" {
		t.Fatalf("installed bytes were not retained: %q, %v", contents, err)
	}
}

func configInstallTestRoot(t *testing.T) string {
	t.Helper()
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".kar"), 0o700); err != nil {
		t.Fatal(err)
	}
	return rootPath
}
