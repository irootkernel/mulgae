//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	appexport "github.com/irootkernel/mulgae/internal/app/export"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
)

func TestExportInstallerInstallsPairWithExactReceiptsAndAdoptsIdenticalRetry(t *testing.T) {
	root := privateTempRoot(t)
	installer, err := NewExportInstaller(NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	request := exportInstallerRequest(t, root, "exports/bundle.tar", "exports/manifest.json", []byte("bundle bytes\n"))

	first, err := installer.Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	assertExportInstallResult(t, first, request)
	assertPrivateDirectory(t, filepath.Join(root, "exports"))
	assertPrivateRegularFile(t, filepath.Join(root, "exports", "bundle.tar"))
	assertPrivateRegularFile(t, filepath.Join(root, "exports", "manifest.json"))
	assertExportJournalAbsent(t, root, request)

	second, err := installer.Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() retry error = %v", err)
	}
	assertExportInstallResult(t, second, request)
	if !bytes.Equal(first.ManifestBytes, second.ManifestBytes) || first.BundleReceipt.SHA256() != second.BundleReceipt.SHA256() || first.ManifestReceipt.SHA256() != second.ManifestReceipt.SHA256() {
		t.Fatal("identical retry did not adopt the exact installed pair")
	}
}

func TestExportInstallerRejectsMismatchedExistingBundleWithoutReplacement(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	installer, err := NewExportInstaller(writer)
	if err != nil {
		t.Fatal(err)
	}
	request := exportInstallerRequest(t, root, "exports/bundle.tar", "exports/manifest.json", []byte("expected bundle\n"))
	writeExportInstallerTestFile(t, writer, root, request.BundlePath, []byte("different bundle\n"), "export_bundle", request.SourceIDs)

	result, err := installer.Install(context.Background(), request)
	if err == nil {
		t.Fatal("Install() succeeded with a mismatched existing bundle")
	}
	if !zeroReceipt(result.BundleReceipt) || !zeroReceipt(result.ManifestReceipt) || result.ManifestBytes != nil {
		t.Fatalf("Install() result = %#v, want no partial success", result)
	}
	got, readErr := os.ReadFile(filepath.Join(root, "exports", "bundle.tar"))
	if readErr != nil || !bytes.Equal(got, []byte("different bundle\n")) {
		t.Fatalf("existing bundle = %q, read error = %v", got, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "exports", "manifest.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("manifest stat error = %v, want not exist", statErr)
	}
	assertExportJournalPresent(t, root, request)
}

func TestExportInstallerRejectsEscapingAndNonRegularDestinationsWithoutPartialSuccess(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, root, outside string, writer *SecureWriter, request appexport.ExportInstallRequest)
	}{
		{
			name: "final symlink",
			setup: func(t *testing.T, root, outside string, writer *SecureWriter, request appexport.ExportInstallRequest) {
				t.Helper()
				if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "exports")); err != nil {
					t.Fatal(err)
				}
				outsideFile := filepath.Join(outside, "bundle.tar")
				if err := os.WriteFile(outsideFile, []byte("outside"), privateFileMode); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideFile, filepath.Join(root, request.BundlePath.String())); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "ancestor symlink",
			setup: func(t *testing.T, root, outside string, writer *SecureWriter, request appexport.ExportInstallRequest) {
				t.Helper()
				if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non regular final destination",
			setup: func(t *testing.T, root, outside string, writer *SecureWriter, request appexport.ExportInstallRequest) {
				t.Helper()
				if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "exports")); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filepath.Join(root, request.BundlePath.String()), privateFileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := privateTempRoot(t)
			outside := privateTempRoot(t)
			writer := NewSecureWriter()
			installer, err := NewExportInstaller(writer)
			if err != nil {
				t.Fatal(err)
			}
			bundlePath := "exports/bundle.tar"
			if test.name == "ancestor symlink" {
				bundlePath = "escape/bundle.tar"
			}
			request := exportInstallerRequest(t, root, bundlePath, "manifests/manifest.json", []byte("bundle bytes\n"))
			test.setup(t, root, outside, writer, request)

			result, err := installer.Install(context.Background(), request)
			if err == nil {
				t.Fatal("Install() succeeded for unsafe destination")
			}
			if !zeroReceipt(result.BundleReceipt) || !zeroReceipt(result.ManifestReceipt) || result.ManifestBytes != nil {
				t.Fatalf("Install() result = %#v, want no partial success", result)
			}
			assertExportJournalPresent(t, root, request)
			switch test.name {
			case "ancestor symlink":
				entries, readErr := os.ReadDir(outside)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("outside entries = %v, read error = %v", entries, readErr)
				}
			case "final symlink":
				got, readErr := os.ReadFile(filepath.Join(outside, "bundle.tar"))
				if readErr != nil || !bytes.Equal(got, []byte("outside")) {
					t.Fatalf("outside bundle = %q, read error = %v", got, readErr)
				}
			}
		})
	}
}

func TestExportInstallerRecoversAfterWriterInterruptions(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*SecureWriter)
		want   func(t *testing.T, root string, request appexport.ExportInstallRequest)
	}{
		{
			name: "after durable journal",
			inject: func(writer *SecureWriter) {
				operations := writer.operationSet()
				rename := operations.renameatxNp
				operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
					if newName == "bundle.tar" {
						return errors.New("injected bundle install interruption")
					}
					return rename(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
				}
				writer.operations = operations
			},
			want: func(t *testing.T, root string, request appexport.ExportInstallRequest) {
				t.Helper()
				if _, err := os.Lstat(filepath.Join(root, request.BundlePath.String())); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("bundle stat error = %v, want not exist", err)
				}
			},
		},
		{
			name: "after bundle installation",
			inject: func(writer *SecureWriter) {
				injectExportInstallerPostInstallSyncFailure(writer, "bundle.tar")
			},
			want: func(t *testing.T, root string, request appexport.ExportInstallRequest) {
				t.Helper()
				got, err := os.ReadFile(filepath.Join(root, request.BundlePath.String()))
				if err != nil || !bytes.Equal(got, request.Bundle) {
					t.Fatalf("installed bundle = %q, read error = %v", got, err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := privateTempRoot(t)
			writer := NewSecureWriter()
			test.inject(writer)
			installer, err := NewExportInstaller(writer)
			if err != nil {
				t.Fatal(err)
			}
			request := exportInstallerRequest(t, root, "exports/bundle.tar", "exports/manifest.json", []byte("bundle bytes\n"))

			result, err := installer.Install(context.Background(), request)
			if err == nil {
				t.Fatal("Install() succeeded through injected interruption")
			}
			if !zeroReceipt(result.BundleReceipt) || !zeroReceipt(result.ManifestReceipt) || result.ManifestBytes != nil {
				t.Fatalf("Install() result = %#v, want no partial success", result)
			}
			assertExportJournalPresent(t, root, request)
			test.want(t, root, request)

			restarted, restartErr := NewExportInstaller(NewSecureWriter())
			if restartErr != nil {
				t.Fatal(restartErr)
			}
			result, err = restarted.Install(context.Background(), request)
			if err != nil {
				t.Fatalf("Install() restart recovery error = %v", err)
			}
			assertExportInstallResult(t, result, request)
			assertExportJournalAbsent(t, root, request)
		})
	}
}
func TestExportInstallerReadoptsPostRenameFilesOnlyAfterDirectorySync(t *testing.T) {
	for _, test := range []struct {
		name         string
		bundlePath   string
		manifestPath string
		targetName   func(t *testing.T, request appexport.ExportInstallRequest) string
		targetPath   func(t *testing.T, request appexport.ExportInstallRequest) ports.SafeRelativePath
	}{
		{
			name:         "journal",
			bundlePath:   "bundles/bundle.tar",
			manifestPath: "manifests/manifest.json",
			targetName: func(t *testing.T, request appexport.ExportInstallRequest) string {
				return filepath.Base(exportInstallerJournalPath(t, request).String())
			},
			targetPath: exportInstallerJournalPath,
		},
		{
			name:         "bundle in separate directory",
			bundlePath:   "bundles/bundle.tar",
			manifestPath: "manifests/manifest.json",
			targetName: func(_ *testing.T, request appexport.ExportInstallRequest) string {
				return filepath.Base(request.BundlePath.String())
			},
			targetPath: func(_ *testing.T, request appexport.ExportInstallRequest) ports.SafeRelativePath {
				return request.BundlePath
			},
		},
		{
			name:         "manifest in separate directory",
			bundlePath:   "bundles/bundle.tar",
			manifestPath: "manifests/manifest.json",
			targetName: func(_ *testing.T, request appexport.ExportInstallRequest) string {
				return filepath.Base(request.ManifestPath.String())
			},
			targetPath: func(_ *testing.T, request appexport.ExportInstallRequest) ports.SafeRelativePath {
				return request.ManifestPath
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := privateTempRoot(t)
			writer := NewSecureWriter()
			request := exportInstallerRequest(t, root, test.bundlePath, test.manifestPath, []byte("bundle bytes\n"))
			directorySyncs := injectExportInstallerPostRenameDirectorySyncFailure(writer, test.targetName(t, request))
			installer, err := NewExportInstaller(writer)
			if err != nil {
				t.Fatal(err)
			}

			result, err := installer.Install(context.Background(), request)
			if err == nil {
				t.Fatal("Install() succeeded through post-rename directory sync failure")
			}
			if !zeroReceipt(result.BundleReceipt) || !zeroReceipt(result.ManifestReceipt) || result.ManifestBytes != nil {
				t.Fatalf("Install() result = %#v, want no partial success", result)
			}
			assertPrivateRegularFile(t, filepath.Join(root, test.targetPath(t, request).String()))

			result, err = installer.Install(context.Background(), request)
			if err != nil {
				t.Fatalf("Install() retry error = %v", err)
			}
			if directorySyncs() < 2 {
				t.Fatalf("directory syncs after rename = %d, want retry adoption to sync the existing target", directorySyncs())
			}
			assertExportInstallResult(t, result, request)
			assertExportJournalAbsent(t, root, request)
		})
	}
}

func injectExportInstallerPostRenameDirectorySyncFailure(writer *SecureWriter, targetName string) func() int {
	operations := writer.operationSet()
	rename := operations.renameatxNp
	renamed := false
	syncs := 0
	failed := false
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		if err := rename(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if newName == targetName {
			renamed = true
		}
		return nil
	}
	operations.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if renamed && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			syncs++
			if !failed {
				failed = true
				return errors.New("injected post-rename directory sync failure")
			}
		}
		return unix.Fsync(fd)
	}
	writer.operations = operations
	return func() int { return syncs }
}

func injectExportInstallerPostInstallSyncFailure(writer *SecureWriter, targetName string) {
	operations := writer.operationSet()
	rename := operations.renameatxNp
	installed := false
	failed := false
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		if err := rename(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if newName == targetName {
			installed = true
		}
		return nil
	}
	operations.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if installed && !failed && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			failed = true
			return errors.New("injected directory sync failure")
		}
		return unix.Fsync(fd)
	}
	writer.operations = operations
}
func TestExportInstallerRecoversDurableJournalAndBundleOnlyState(t *testing.T) {
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	installer, err := NewExportInstaller(writer)
	if err != nil {
		t.Fatal(err)
	}
	request := exportInstallerRequest(t, root, "exports/bundle.tar", "exports/manifest.json", []byte("bundle bytes\n"))
	journalPath := exportInstallerJournalPath(t, request)
	journalBytes, marshalErr := json.Marshal(exportJournal{request.BundlePath.String(), request.ManifestPath.String(), exportDigest(request.Bundle), int64(len(request.Bundle))})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	writeExportInstallerTestFile(t, writer, root, journalPath, journalBytes, "export_install_journal", request.SourceIDs)
	assertExportJournalPresent(t, root, request)

	result, err := installer.Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() recovery from journal error = %v", err)
	}
	assertExportInstallResult(t, result, request)
	assertExportJournalAbsent(t, root, request)

	// This recreates the durable state left after bundle installation but before
	// manifest installation, as a restarted process would observe it.
	writeExportInstallerTestFile(t, writer, root, journalPath, journalBytes, "export_install_journal", request.SourceIDs)
	if err := os.Remove(filepath.Join(root, request.ManifestPath.String())); err != nil {
		t.Fatal(err)
	}
	assertExportJournalPresent(t, root, request)
	result, err = installer.Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() recovery from bundle-only state error = %v", err)
	}
	assertExportInstallResult(t, result, request)
	assertExportJournalAbsent(t, root, request)
}

func TestExportInstallerRetainsJournalUntilBothMembersVerify(t *testing.T) {
	root := privateTempRoot(t)
	outside := privateTempRoot(t)
	writer := NewSecureWriter()
	installer, err := NewExportInstaller(writer)
	if err != nil {
		t.Fatal(err)
	}
	request := exportInstallerRequest(t, root, "exports/bundle.tar", "exports/manifest.json", []byte("bundle bytes\n"))
	if err := writer.EnsurePrivateDir(mustRoot(t, root), mustRelativePath(t, "exports")); err != nil {
		t.Fatal(err)
	}
	outsideManifest := filepath.Join(outside, "manifest.json")
	if err := os.WriteFile(outsideManifest, []byte("outside"), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideManifest, filepath.Join(root, request.ManifestPath.String())); err != nil {
		t.Fatal(err)
	}

	result, err := installer.Install(context.Background(), request)
	if err == nil {
		t.Fatal("Install() succeeded with an unsafe manifest destination")
	}
	if !zeroReceipt(result.BundleReceipt) || !zeroReceipt(result.ManifestReceipt) || result.ManifestBytes != nil {
		t.Fatalf("Install() result = %#v, want no partial success", result)
	}
	assertExportJournalPresent(t, root, request)
	gotBundle, readErr := os.ReadFile(filepath.Join(root, request.BundlePath.String()))
	if readErr != nil || !bytes.Equal(gotBundle, request.Bundle) {
		t.Fatalf("installed bundle = %q, read error = %v", gotBundle, readErr)
	}
	gotOutsideManifest, outsideReadErr := os.ReadFile(outsideManifest)
	if outsideReadErr != nil || !bytes.Equal(gotOutsideManifest, []byte("outside")) {
		t.Fatalf("outside manifest = %q, read error = %v", gotOutsideManifest, outsideReadErr)
	}
	if err := os.Remove(filepath.Join(root, request.ManifestPath.String())); err != nil {
		t.Fatal(err)
	}

	result, err = installer.Install(context.Background(), request)
	if err != nil {
		t.Fatalf("Install() retry error = %v", err)
	}
	assertExportInstallResult(t, result, request)
	assertExportJournalAbsent(t, root, request)
}

func exportInstallerRequest(t *testing.T, root, bundlePath, manifestPath string, bundle []byte) appexport.ExportInstallRequest {
	t.Helper()
	return appexport.ExportInstallRequest{
		Root:         mustRoot(t, root),
		BundlePath:   mustRelativePath(t, bundlePath),
		ManifestPath: mustRelativePath(t, manifestPath),
		Bundle:       append([]byte(nil), bundle...),
		SourceIDs:    []string{"export:test"},
		MaxBytes:     1 << 20,
		ManifestForBundleReceipt: func(receipt ports.SecureWriteReceipt) ([]byte, error) {
			return []byte(fmt.Sprintf("bundle_sha256=%s\nbundle_bytes=%d\n", receipt.SHA256(), receipt.ByteLength())), nil
		},
	}
}

func writeExportInstallerTestFile(t *testing.T, writer *SecureWriter, root string, path ports.SafeRelativePath, data []byte, channel string, sourceIDs []string) {
	t.Helper()
	request, err := ports.NewSecureWriteRequest(mustRoot(t, root), path, channel, bytes.NewReader(data), 1<<20, sourceIDs, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, drop, err := writer.Write(context.Background(), request); err != nil || drop != nil {
		t.Fatalf("Write(%s) = (drop %#v, error %v)", path, drop, err)
	}
}

func assertExportInstallResult(t *testing.T, result appexport.ExportInstallResult, request appexport.ExportInstallRequest) {
	t.Helper()
	manifest, err := request.ManifestForBundleReceipt(result.BundleReceipt)
	if err != nil {
		t.Fatal(err)
	}
	assertExportInstallerReceipt(t, result.BundleReceipt, request.Root, request.BundlePath, request.Bundle, "export_bundle", request.SourceIDs)
	assertExportInstallerReceipt(t, result.ManifestReceipt, request.Root, request.ManifestPath, manifest, "export_manifest", request.SourceIDs)
	if !bytes.Equal(result.ManifestBytes, manifest) {
		t.Fatalf("manifest bytes = %q, want %q", result.ManifestBytes, manifest)
	}
	for _, member := range []struct {
		path string
		want []byte
	}{{request.BundlePath.String(), request.Bundle}, {request.ManifestPath.String(), manifest}} {
		got, readErr := os.ReadFile(filepath.Join(request.Root.String(), member.path))
		if readErr != nil || !bytes.Equal(got, member.want) {
			t.Fatalf("installed %s = %q, read error = %v", member.path, got, readErr)
		}
	}
}

func assertExportInstallerReceipt(t *testing.T, receipt ports.SecureWriteReceipt, root ports.AnchoredRoot, path ports.SafeRelativePath, data []byte, channel string, sourceIDs []string) {
	t.Helper()
	sum := sha256.Sum256(data)
	if receipt.Root() != root || receipt.Destination() != path || receipt.SHA256() != fmt.Sprintf("sha256:%x", sum) || receipt.ByteLength() != int64(len(data)) || receipt.Channel() != channel || !equalExportInstallerStrings(receipt.SourceIDs(), sourceIDs) {
		t.Fatalf("receipt = %#v, want exact receipt for %s", receipt, path)
	}
}

func exportInstallerJournalPath(t *testing.T, request appexport.ExportInstallRequest) ports.SafeRelativePath {
	t.Helper()
	return mustRelativePath(t, exportInstallDirectory+"/"+exportInstallKey(request)+".json")
}

func assertExportJournalPresent(t *testing.T, root string, request appexport.ExportInstallRequest) {
	t.Helper()
	path := filepath.Join(root, exportInstallerJournalPath(t, request).String())
	assertPrivateRegularFile(t, path)
}

func assertExportJournalAbsent(t *testing.T, root string, request appexport.ExportInstallRequest) {
	t.Helper()
	path := filepath.Join(root, exportInstallerJournalPath(t, request).String())
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal stat error = %v, want not exist", err)
	}
}

func equalExportInstallerStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
