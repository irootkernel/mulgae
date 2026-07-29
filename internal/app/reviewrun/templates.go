package reviewrun

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	rolecatalog "github.com/irootkernel/mulgae/internal/roles"
)

type templateDescriptor struct {
	id      string
	source  string
	layer   string
	version string
	role    domain.Role
}

var rootReviewTemplateDescriptors = [...]templateDescriptor{
	{id: "sot:prompts/root-review/common.v2.txt", source: "prompts/root-review/common.v2.txt", layer: "builtin:review/common", version: "2"},
	{id: "sot:prompts/root-review/run-review.v2.txt", source: "prompts/root-review/run-review.v2.txt", layer: "builtin:run/review", version: "2"},
	{id: "sot:prompts/root-review/output-provider-review-wire.v3.txt", source: "prompts/root-review/output-provider-review-wire.v3.txt", layer: "builtin:output/provider-review-wire", version: "3"},
	{id: "sot:prompts/root-review/repair-provider-review.v3.txt", source: "prompts/root-review/repair-provider-review.v3.txt", layer: "builtin:repair/provider-review", version: "3"},
}

// LoadDefaultTemplateSet loads the fixed root-review prompt contract from the
// supplied immutable contract catalog.
func LoadDefaultTemplateSet(ctx context.Context, catalog ports.ContractCatalog) (review.TemplateSet, error) {
	if ctx == nil || catalog == nil {
		return review.TemplateSet{}, fmt.Errorf("review templates: nil context or catalog")
	}
	var common, run, output, repair prompt.TrustedLayer
	roles := make(map[domain.Role]prompt.TrustedLayer, len(domain.FixedRoleOrder()))
	for _, descriptor := range rootReviewTemplateDescriptors {
		assetID, err := ports.ParseAssetID(descriptor.id)
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: descriptor %q: %w", descriptor.id, err)
		}
		metadata, raw, err := catalog.Read(ctx, assetID)
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: read %q: %w", descriptor.id, err)
		}
		if metadata.ID().String() != descriptor.id || metadata.Source().String() != descriptor.source || metadata.MediaType() != "text/plain" {
			return review.TemplateSet{}, fmt.Errorf("review templates: unexpected metadata for %q", descriptor.id)
		}
		if len(raw) == 0 || !utf8.Valid(raw) || raw[len(raw)-1] == '\n' {
			return review.TemplateSet{}, fmt.Errorf("review templates: invalid content for %q", descriptor.id)
		}
		for _, value := range raw {
			if value == '\r' || value == 0 {
				return review.TemplateSet{}, fmt.Errorf("review templates: invalid content for %q", descriptor.id)
			}
		}
		layer, err := prompt.NewTrustedLayer(descriptor.layer, descriptor.version, raw)
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: layer %q: %w", descriptor.id, err)
		}
		switch descriptor.role {
		case domain.Role(""):
			switch descriptor.layer {
			case "builtin:review/common":
				common = layer
			case "builtin:run/review":
				run = layer
			case "builtin:output/provider-review-wire":
				output = layer
			case "builtin:repair/provider-review":
				repair = layer
			}
		default:
			roles[descriptor.role] = layer
		}
	}
	definitions := make([]rolecatalog.Definition, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		source := "roles/" + string(role) + ".yaml"
		assetID, err := ports.ParseAssetID("sot:" + source)
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: role %q asset ID: %w", role, err)
		}
		metadata, raw, err := catalog.Read(ctx, assetID)
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: read role %q: %w", role, err)
		}
		if metadata.Source().String() != source || metadata.MediaType() != "application/yaml" {
			return review.TemplateSet{}, fmt.Errorf("review templates: unexpected role metadata for %q", role)
		}
		definition, err := rolecatalog.Parse(raw)
		if err != nil || definition.ID != string(role) {
			return review.TemplateSet{}, fmt.Errorf("review templates: invalid role document %q: %w", role, err)
		}
		definitions = append(definitions, definition)
		layer, err := prompt.NewTrustedLayer("builtin:roles/"+string(role), "3", []byte(definition.SystemPrompt))
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: role layer %q: %w", role, err)
		}
		roles[role] = layer
	}
	if err := rolecatalog.ValidateCatalog(definitions); err != nil {
		return review.TemplateSet{}, fmt.Errorf("review templates: role catalog: %w", err)
	}
	return review.NewTemplateSet(common, run, output, repair, roles)
}
