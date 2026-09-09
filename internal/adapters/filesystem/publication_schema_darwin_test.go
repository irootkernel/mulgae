//go:build darwin && arm64

package filesystem

import (
	"context"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

type schemaSelectionValidator struct{ selected ports.AssetID }

func (validator *schemaSelectionValidator) Validate(_ context.Context, schema ports.AssetID, _ []byte) error {
	validator.selected = schema
	return nil
}

func TestPublicationSchemaSelectionPreservesArtifactFamily(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	validator := &schemaSelectionValidator{}
	fixture.store.validator = validator
	recovery, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-run-recovery.v1.schema.json")
	for _, test := range []struct {
		name      string
		requested ports.AssetID
		version   string
		want      ports.AssetID
	}{
		{"recovery rejects manifest", recovery, "mulgae-run-manifest.v2", recovery},
		{"recovery rejects final", recovery, "mulgae-review-artifact.v2", recovery},
		{"manifest rejects final", fixture.store.manifestSchema, "mulgae-review-artifact.v2", fixture.store.manifestSchema},
		{"final rejects manifest", fixture.store.finalSchema, "mulgae-run-manifest.v2", fixture.store.finalSchema},
		{"manifest accepts composite", fixture.store.manifestSchema, "mulgae-composite-run-manifest.v1", fixture.store.compositeManifestSchema},
		{"final accepts composite", fixture.store.finalSchema, "mulgae-composite-review-artifact.v1", fixture.store.compositeFinalSchema},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := fixture.store.validatePublicationSchema(context.Background(), test.requested, []byte(fmt.Sprintf(`{"schema_version":%q}`, test.version))); err != nil {
				t.Fatal(err)
			}
			if validator.selected != test.want {
				t.Fatalf("selected %v, want %v", validator.selected, test.want)
			}
		})
	}
}
