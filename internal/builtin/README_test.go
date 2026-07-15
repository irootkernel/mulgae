package builtin

import (
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
