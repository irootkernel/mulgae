package config

import (
	"github.com/irootkernel/mulgae/internal/ports"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalConfigSourceReadsConfigV2PairAndDetectsDrift(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin source")
	}
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	data, localData, _ := EncodeSplit(validConfig())
	path := filepath.Join(rootPath, ".mulgae", "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), localData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae.yaml"), []byte("legacy: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	source, err := NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	got, identity, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !identity.Valid() || identity.SHA256() == "" {
		t.Fatal("local source mismatch")
	}
	if err := os.WriteFile(path, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.Revalidate(); err == nil {
		t.Fatal("drift accepted")
	}
}

func TestLocalConfigSourceRejectsUnsafeModesAndAllowsExplicitAbsence(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin source")
	}
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	root, _ := ports.NewAnchoredRoot(rootPath)
	source, err := NewLocalConfigSource(root, true)
	if err != nil || source.Present() {
		t.Fatalf("absence=%v present=%t", err, source != nil && source.Present())
	}
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalConfigSource(root, true); err == nil {
		t.Fatal("unsafe .mulgae accepted")
	}
}

func TestLocalConfigSourceAdmitsTrackedProjectOnlyCheckout(t *testing.T) {
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o755)
	project, _, err := EncodeSplit(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), project, 0o644); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	source, err := NewLocalConfigSource(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if source.Present() || !source.ProjectPresent() {
		t.Fatalf("source complete=%t project=%t", source.Present(), source.ProjectPresent())
	}
}
