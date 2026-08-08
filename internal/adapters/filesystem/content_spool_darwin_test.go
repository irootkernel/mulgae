//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestContentSpoolerStreamsReopenableContent(t *testing.T) {
	data := bytes.Repeat([]byte("streamed-content\n"), 1<<16)
	request, err := ports.NewContentSpoolRequest(bytes.NewReader(data), "text/markdown")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewContentSpooler().Spool(context.Background(), request)
	if err != nil {
		t.Fatalf("Spool() error = %v", err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	sum := sha256.Sum256(data)
	if got, want := lease.Identity().SHA256(), "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("SHA256() = %q, want %q", got, want)
	}
	if got := lease.Identity().ByteLength(); got != int64(len(data)) {
		t.Fatalf("ByteLength() = %d, want %d", got, len(data))
	}
	for attempt := 0; attempt < 2; attempt++ {
		reader, err := lease.Open(context.Background())
		if err != nil {
			t.Fatalf("Open() attempt %d error = %v", attempt, err)
		}
		got, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil || closeErr != nil || !bytes.Equal(got, data) {
			t.Fatalf("read attempt %d: bytes=%d readErr=%v closeErr=%v", attempt, len(got), err, closeErr)
		}
	}
}

func TestContentSpoolerCancellationCleansTemporaryContent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, _ := ports.NewContentSpoolRequest(bytes.NewReader([]byte("content")), "text/plain")
	if lease, err := NewContentSpooler().Spool(ctx, request); err == nil || lease != nil {
		t.Fatalf("cancelled spool = %#v, error = %v", lease, err)
	}
}

func TestContentLeaseRefusesDriftedCleanup(t *testing.T) {
	request, _ := ports.NewContentSpoolRequest(bytes.NewReader([]byte("content")), "text/plain")
	artifact, err := NewContentSpooler().Spool(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	lease := artifact.(*fileContentLease)
	original := lease.path + ".original"
	if err := os.Rename(lease.path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lease.path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err == nil {
		t.Fatal("drifted content was removed")
	}
	if _, err := os.Stat(lease.path); err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if err := os.RemoveAll(lease.root); err != nil {
		t.Fatal(err)
	}
}

func TestSecureWriterInstallsExactContentArtifact(t *testing.T) {
	data := bytes.Repeat([]byte("exact-content\n"), 1<<15)
	spoolRequest, _ := ports.NewContentSpoolRequest(bytes.NewReader(data), "text/markdown")
	lease, err := NewContentSpooler().Spool(context.Background(), spoolRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	rootPath := t.TempDir()
	root, _ := ports.NewAnchoredRoot(rootPath)
	destination, _ := ports.NewSafeRelativePath("reports/logic.md")
	request, err := ports.NewContentInstallRequest(root, destination, "role_report", lease, []string{"role:logic"})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewSecureWriter().InstallContent(context.Background(), request)
	if err != nil {
		t.Fatalf("InstallContent() error = %v", err)
	}
	if receipt.SHA256() != lease.Identity().SHA256() || receipt.ByteLength() != int64(len(data)) {
		t.Fatalf("receipt = %#v, identity = %#v", receipt, lease.Identity())
	}
	got, err := os.ReadFile(rootPath + "/reports/logic.md")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("installed bytes = %d, error = %v", len(got), err)
	}
}

type identityOverridingArtifact struct {
	ports.ContentArtifact
	identity ports.ContentIdentity
}

func (artifact identityOverridingArtifact) Identity() ports.ContentIdentity { return artifact.identity }

type closeFailingArtifact struct {
	identity ports.ContentIdentity
	data     []byte
}

func (artifact closeFailingArtifact) Identity() ports.ContentIdentity { return artifact.identity }
func (artifact closeFailingArtifact) Open(context.Context) (io.ReadCloser, error) {
	return closeFailingReader{Reader: bytes.NewReader(artifact.data)}, nil
}

type closeFailingReader struct{ io.Reader }

func (closeFailingReader) Close() error { return errors.New("close failed") }

func TestSecureWriterRejectsContentIdentityDriftBeforeInstall(t *testing.T) {
	spoolRequest, _ := ports.NewContentSpoolRequest(bytes.NewReader([]byte("actual")), "text/plain")
	lease, err := NewContentSpooler().Spool(context.Background(), spoolRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()
	wrong, _ := ports.NewContentIdentity("sha256:"+string(bytes.Repeat([]byte{'b'}, 64)), 6, "text/plain")
	artifact := identityOverridingArtifact{ContentArtifact: lease, identity: wrong}
	rootPath := t.TempDir()
	root, _ := ports.NewAnchoredRoot(rootPath)
	destination, _ := ports.NewSafeRelativePath("reports/logic.md")
	request, _ := ports.NewContentInstallRequest(root, destination, "role_report", artifact, []string{"role:logic"})
	if _, err := NewSecureWriter().InstallContent(context.Background(), request); !errors.Is(err, ErrContentIdentityMismatch) {
		t.Fatalf("InstallContent() error = %v, want identity mismatch", err)
	}
	if _, err := os.Stat(rootPath + "/reports/logic.md"); !os.IsNotExist(err) {
		t.Fatalf("drifted content was installed: %v", err)
	}
}

func TestSecureWriterReturnsReceiptWhenInstalledArtifactReaderCloseFails(t *testing.T) {
	data := []byte("durable")
	sum := sha256.Sum256(data)
	identity, _ := ports.NewContentIdentity("sha256:"+hex.EncodeToString(sum[:]), int64(len(data)), "text/plain")
	rootPath := t.TempDir()
	root, _ := ports.NewAnchoredRoot(rootPath)
	destination, _ := ports.NewSafeRelativePath("reports/logic.md")
	request, _ := ports.NewContentInstallRequest(
		root, destination, "role_report", closeFailingArtifact{identity: identity, data: data}, []string{"role:logic"},
	)
	receipt, err := NewSecureWriter().InstallContent(context.Background(), request)
	if err == nil || receipt.SHA256() != identity.SHA256() {
		t.Fatalf("InstallContent() receipt = %#v, error = %v", receipt, err)
	}
	got, readErr := os.ReadFile(rootPath + "/reports/logic.md")
	if readErr != nil || !bytes.Equal(got, data) {
		t.Fatalf("installed bytes = %q, error = %v", got, readErr)
	}
}
