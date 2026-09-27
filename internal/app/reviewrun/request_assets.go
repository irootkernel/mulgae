package reviewrun

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// These describe the existing public preflight transmission contract. Native
// provider permissions remain owned by their protocol adapters.
const PreflightPermissionMode = "not_applicable"
const PreflightTargetChannel = "prompt"

// PlannedRequestAssets binds only assets selected by ordinary execution.
func PlannedRequestAssets(ctx context.Context, catalog ports.ContractCatalog, templates review.TemplateSet, roles []domain.Role, extraction bool) ([]RequestAsset, []RequestContract, error) {
	layers := []prompt.TrustedLayer{templates.Common(), templates.ReviewRun(), templates.JSONOutput(), templates.Repair()}
	if extraction {
		layers = append(layers, templates.Extract())
	}
	for _, role := range roles {
		layer, ok := templates.RoleTemplate(role)
		if !ok {
			return nil, nil, fmt.Errorf("request assets: selected role missing")
		}
		layers = append(layers, layer)
	}
	assets := make([]RequestAsset, 0, len(layers)+5)
	contracts := make([]RequestContract, 0, len(layers)+5)
	for _, layer := range layers {
		if layer.ID() == "" {
			return nil, nil, fmt.Errorf("request assets: selected prompt missing")
		}
		assets = append(assets, RequestAsset{Name: layer.ID(), SHA256: identitySHA256(layer.Bytes())})
		contracts = append(contracts, RequestContract{Name: layer.ID(), Version: layer.Version()})
	}
	for _, name := range []string{validation.ProviderReviewWireSchemaID, validation.ProviderReviewSchemaID,
		"https://mulgae.local/schemas/mulgae-repair-patch.v1.schema.json",
		"https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json",
		"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json"} {
		id, err := ports.ParseAssetID(name)
		if err != nil {
			return nil, nil, err
		}
		metadata, raw, err := catalog.Read(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		var schema struct {
			Properties struct {
				SchemaVersion struct {
					Const string `json:"const"`
				} `json:"schema_version"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil || schema.Properties.SchemaVersion.Const == "" {
			return nil, nil, fmt.Errorf("request assets: schema version missing")
		}
		assets = append(assets, RequestAsset{Name: name, SHA256: metadata.SHA256()})
		contracts = append(contracts, RequestContract{Name: name, Version: schema.Properties.SchemaVersion.Const})
	}
	return assets, contracts, nil
}
