package ports

import (
	"bytes"
	"context"
	"io"
	"testing"
)

type contentArtifactStub struct{ identity ContentIdentity }

func (artifact contentArtifactStub) Identity() ContentIdentity { return artifact.identity }
func (contentArtifactStub) Open(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func TestContentContracts(t *testing.T) {
	identity, err := NewContentIdentity("sha256:"+string(bytes.Repeat([]byte{'a'}, 64)), 0, "application/octet-stream")
	if err != nil || !identity.Valid() || identity.ByteLength() != 0 || identity.MediaType() != "application/octet-stream" {
		t.Fatalf("content identity = %#v, error = %v", identity, err)
	}
	if _, err := NewContentIdentity("sha256:bad", 0, "application/octet-stream"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if _, err := NewContentIdentity(identity.SHA256(), -1, "application/octet-stream"); err == nil {
		t.Fatal("negative length accepted")
	}

	spool, err := NewContentSpoolRequest(bytes.NewReader(nil), "text/markdown")
	if err != nil || spool.Source() == nil || spool.MediaType() != "text/markdown" {
		t.Fatalf("spool request = %#v, error = %v", spool, err)
	}
	if _, err := NewContentSpoolRequest(nil, "text/markdown"); err == nil {
		t.Fatal("nil spool source accepted")
	}

	root, _ := NewAnchoredRoot("/tmp")
	destination, _ := NewSafeRelativePath("role-reports/logic.md")
	install, err := NewContentInstallRequest(root, destination, "role_report", contentArtifactStub{identity}, []string{"role:logic"})
	if err != nil || install.Artifact().Identity() != identity || install.SourceIDs()[0] != "role:logic" {
		t.Fatalf("install request = %#v, error = %v", install, err)
	}
	sources := install.SourceIDs()
	sources[0] = "mutated"
	if install.SourceIDs()[0] != "role:logic" {
		t.Fatal("install source IDs were mutable")
	}
}
