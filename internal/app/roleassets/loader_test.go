package roleassets_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/roleassets"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	rolecatalog "github.com/irootkernel/mulgae/internal/roles"
)

// rootDocumentPath is the human-authored authority this package projects.
const rootDocumentPath = "../../../assets/roles.yaml"

type failingCatalog struct {
	inner ports.ContractCatalog
	err   error
	kind  string
}

func (catalog failingCatalog) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if catalog.err != nil {
		return ports.AssetMetadata{}, nil, catalog.err
	}
	metadata, raw, err := catalog.inner.Read(ctx, id)
	if err != nil {
		return metadata, raw, err
	}
	if catalog.kind != "" {
		source, parseErr := ports.NewSafeRelativePath("help/config.md")
		if parseErr != nil {
			return ports.AssetMetadata{}, nil, parseErr
		}
		mistyped, parseErr := ports.NewAssetMetadata(metadata.ID(), metadata.Kind(), source, catalog.kind, metadata.SHA256(), metadata.ByteLength())
		if parseErr != nil {
			return ports.AssetMetadata{}, nil, parseErr
		}
		return mistyped, raw, nil
	}
	return metadata, raw, nil
}

func (catalog failingCatalog) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	return catalog.inner.List(ctx)
}

func TestLoadReturnsEveryFixedRoleInOrder(t *testing.T) {
	t.Parallel()

	definitions, err := roleassets.Load(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatalf("load role assets: %v", err)
	}
	if len(definitions) != len(domain.FixedRoleOrder()) {
		t.Fatalf("definition count = %d, want %d", len(definitions), len(domain.FixedRoleOrder()))
	}
	for index, role := range domain.FixedRoleOrder() {
		if definitions[index].ID != string(role) {
			t.Fatalf("definition %d = %q, want %q", index, definitions[index].ID, role)
		}
		if definitions[index].SystemPrompt == "" {
			t.Fatalf("role %q has no system prompt", role)
		}
	}
}

func TestLoadFailsClosedOnUnreadableOrMistypedAsset(t *testing.T) {
	t.Parallel()

	for name, catalog := range map[string]ports.ContractCatalog{
		"nil catalog":    nil,
		"read error":     failingCatalog{inner: builtin.NewCatalog(), err: errors.New("unavailable")},
		"mistyped asset": failingCatalog{inner: builtin.NewCatalog(), kind: "text/markdown"},
		"empty catalog":  emptyCatalog{},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := roleassets.Load(context.Background(), catalog); err == nil {
				t.Fatal("load succeeded, want rejection")
			}
		})
	}
}

type emptyCatalog struct{}

func (emptyCatalog) Read(context.Context, ports.AssetID) (ports.AssetMetadata, []byte, error) {
	return ports.AssetMetadata{}, nil, errors.New("asset not found")
}
func (emptyCatalog) List(context.Context) ([]ports.AssetMetadata, error) { return nil, nil }

// TestDefaultsMirrorTheRootRoleDocument is the proof that assets/roles.yaml is
// the authority. No provider order is spelled in Go here: the expectation is
// read straight from the human-authored file on disk.
func TestDefaultsMirrorTheRootRoleDocument(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(rootDocumentPath)
	if err != nil {
		t.Fatalf("read root role document: %v", err)
	}
	authored, err := rolecatalog.ParseCatalog(raw)
	if err != nil {
		t.Fatalf("parse root role document: %v", err)
	}
	definitions, err := roleassets.Load(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatalf("load role assets: %v", err)
	}
	defaults, err := roleassets.Defaults(definitions)
	if err != nil {
		t.Fatalf("project role defaults: %v", err)
	}
	for _, definition := range authored {
		role := domain.Role(definition.ID)
		entry, exists := defaults.Role(role)
		if !exists {
			t.Fatalf("defaults omit role %q", role)
		}
		if strings.Join(entry.ProviderPreferences, ",") != strings.Join(definition.ProviderPreferences, ",") {
			t.Fatalf("role %q preferences = %v, want the authored %v", role, entry.ProviderPreferences, definition.ProviderPreferences)
		}
		if definition.DefaultInputs == nil {
			if entry.ArtistTaskPath != "" || len(entry.ArtistDesignSpecGlobs) != 0 {
				t.Fatalf("role %q carries artist inputs it does not declare", role)
			}
			continue
		}
		if entry.ArtistTaskPath != definition.DefaultInputs.TaskPath {
			t.Fatalf("role %q task path = %q, want the authored %q", role, entry.ArtistTaskPath, definition.DefaultInputs.TaskPath)
		}
		if strings.Join(entry.ArtistDesignSpecGlobs, ",") != strings.Join(definition.DefaultInputs.DesignSpecGlobs, ",") {
			t.Fatalf("role %q globs = %v, want the authored %v", role, entry.ArtistDesignSpecGlobs, definition.DefaultInputs.DesignSpecGlobs)
		}
	}
}

func TestDefaultsRejectsIncompleteDefinitions(t *testing.T) {
	t.Parallel()

	definitions, err := roleassets.Load(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatalf("load role assets: %v", err)
	}
	if _, err := roleassets.Defaults(definitions[:len(definitions)-1]); err == nil {
		t.Fatal("defaults accepted an incomplete role set")
	}
	duplicated := append(append([]rolecatalog.Definition(nil), definitions...), definitions[0])
	if _, err := roleassets.Defaults(duplicated); err == nil {
		t.Fatal("defaults accepted a duplicate role")
	}
}
