// Package roleassets is the single application-layer reader of the build-owned
// role catalog document. Every consumer of the role documents goes through Load,
// so one read and one whole-catalog validation govern them all.
//
// The document is a generation-time authority only. Defaults projects it onto
// the values mulgae init writes into a new project configuration; nothing here
// participates in resolving an already configured value.
package roleassets

import (
	"context"
	"fmt"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	rolecatalog "github.com/irootkernel/mulgae/internal/roles"
)

// documentSource is the catalog source of the build-owned role document.
const documentSource = "roles.yaml"

// Load returns the fixed role definitions in domain.FixedRoleOrder() order,
// after parsing and whole-catalog validation.
func Load(ctx context.Context, catalog ports.ContractCatalog) ([]rolecatalog.Definition, error) {
	if catalog == nil {
		return nil, fmt.Errorf("role assets: catalog is required")
	}
	assetID, err := ports.ParseAssetID("sot:" + documentSource)
	if err != nil {
		return nil, fmt.Errorf("role assets: asset ID: %w", err)
	}
	metadata, raw, err := catalog.Read(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("role assets: read %q: %w", documentSource, err)
	}
	if metadata.Source().String() != documentSource || metadata.MediaType() != "application/yaml" {
		return nil, fmt.Errorf("role assets: unexpected metadata for %q", documentSource)
	}
	definitions, err := rolecatalog.ParseCatalog(raw)
	if err != nil {
		return nil, fmt.Errorf("role assets: parse %q: %w", documentSource, err)
	}
	return definitions, nil
}

// Defaults projects loaded definitions onto init's build-owned role defaults.
func Defaults(definitions []rolecatalog.Definition) (appconfig.RoleDefaults, error) {
	entries := make(map[domain.Role]appconfig.RoleDefault, len(definitions))
	for _, definition := range definitions {
		role := domain.Role(definition.ID)
		if !role.Valid() {
			return appconfig.RoleDefaults{}, fmt.Errorf("role assets: invalid role %q", definition.ID)
		}
		if _, duplicate := entries[role]; duplicate {
			return appconfig.RoleDefaults{}, fmt.Errorf("role assets: duplicate role %q", role)
		}
		entry := appconfig.RoleDefault{ProviderPreferences: append([]string(nil), definition.ProviderPreferences...)}
		if definition.DefaultInputs != nil {
			entry.ArtistTaskPath = definition.DefaultInputs.TaskPath
			entry.ArtistDesignSpecGlobs = append([]string(nil), definition.DefaultInputs.DesignSpecGlobs...)
		}
		entries[role] = entry
	}
	return appconfig.NewRoleDefaults(entries)
}
