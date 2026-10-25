//go:build darwin && arm64

package publication

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/ports"
)

func copiedFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative] = raw
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCompositeSupportBundleRejectsReboundCopies(t *testing.T) {
	bundle := retainedHistoricalFixture(t, "composite-copied-v1").bundle
	if err := validateCompositeBundleSemantics(bundle); err != nil {
		t.Fatal(err)
	}
	for i, artifact := range bundle.excerpts {
		if filepath.Base(artifact.Path().String()) != "composite.json" {
			continue
		}
		var doc compositesupport.Document
		if err := json.Unmarshal(artifact.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		doc.Sources[0].ProviderIdentities = []string{"different-provider"}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := ports.NewImmutablePublicationArtifact(artifact.Path(), sha256Identifier(raw), raw)
		if err != nil {
			t.Fatal(err)
		}
		bundle.excerpts[i] = replacement
		if err := validateCompositeBundleSemantics(bundle); err == nil {
			t.Fatal("bundle accepted changed support without immutable index binding")
		}
		return
	}
	t.Fatal("new support metadata absent")
}
