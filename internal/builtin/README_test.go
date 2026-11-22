package builtin

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

// TestCatalogDocumentationContract exercises the public ports.ContractCatalog
// semantics documented by Catalog: callers filter List results by kind and own
// every byte slice returned by Read.
func TestCatalogDocumentationContract(t *testing.T) {
	t.Parallel()

	var catalog ports.ContractCatalog = NewCatalog()
	metadata, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var help ports.AssetMetadata
	for _, asset := range metadata {
		if asset.Kind() == ports.AssetKindHelp {
			help = asset
			break
		}
	}
	if !help.ID().Valid() {
		t.Fatal("List did not return a valid help asset for client-side kind filtering")
	}
	if help.Source().String() == "" || help.MediaType() == "" {
		t.Fatal("help metadata omitted its source or media type")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := catalog.Read(ctx, help.ID()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read with cancelled context error = %v, want context.Canceled", err)
	}
}

// TestSchemaIndexCoversEveryEmbeddedSchema pins the schemas README as a
// complete index: every embedded schema has a row whose example exists, and
// the current-version sentence names the actual maxima.
func TestSchemaIndexCoversEveryEmbeddedSchema(t *testing.T) {
	schemaPaths, err := fs.Glob(embeddedAssets, "assets/schemas/*.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(schemaPaths) == 0 {
		t.Fatal("no embedded schemas found")
	}
	readme, err := embeddedAssets.ReadFile("assets/schemas/README.md")
	if err != nil {
		t.Fatal(err)
	}
	index := string(readme)
	for _, schemaPath := range schemaPaths {
		base := strings.TrimSuffix(filepath.Base(schemaPath), ".schema.json")
		row := "| `" + base + "` |"
		if !strings.Contains(index, row) {
			t.Errorf("schema index omits %s", base)
			continue
		}
		rowStart := strings.Index(index, row)
		lineEnd := strings.Index(index[rowStart:], "\n")
		if lineEnd < 0 {
			t.Fatalf("schema row for %s is unterminated", base)
		}
		line := index[rowStart : rowStart+lineEnd]
		segment := strings.Split(line, "|")
		if len(segment) < 4 {
			t.Fatalf("schema row for %s is malformed: %q", base, line)
		}
		example := strings.Trim(strings.TrimSpace(segment[2]), "`")
		// The embedded filesystem rejects ".." segments, so the row's
		// schemas-relative reference is resolved against the asset root.
		resolved := "assets/" + strings.TrimPrefix(example, "../")
		if _, err := embeddedAssets.ReadFile(resolved); err != nil {
			t.Errorf("schema row for %s references a missing example %q", base, example)
		}
	}
	if !strings.Contains(index, "Current commands emit v24") || !strings.Contains(index, "doctor emits v8") || !strings.Contains(index, "provider heartbeat emits v5") || !strings.Contains(index, "preflight emits v12") {
		t.Error("schema index current-version sentence does not name command v24, doctor v8, heartbeat v5, and preflight v12")
	}
}
