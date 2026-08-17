package reviewrun

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/roleassets"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type templateDescriptor struct {
	id      string
	source  string
	layer   string
	version string
	role    domain.Role
}

var rootReviewTemplateDescriptors = [...]templateDescriptor{
	{id: "sot:prompts/root-review/common.v1.txt", source: "prompts/root-review/common.v1.txt", layer: "builtin:review/common", version: "1"},
	{id: "sot:prompts/root-review/run-review.v1.txt", source: "prompts/root-review/run-review.v1.txt", layer: "builtin:run/review", version: "1"},
	{id: "sot:prompts/root-review/output-provider-review-wire.v1.txt", source: "prompts/root-review/output-provider-review-wire.v1.txt", layer: "builtin:output/provider-review-wire", version: "1"},
	{id: "sot:prompts/root-review/repair-provider-review.v1.txt", source: "prompts/root-review/repair-provider-review.v1.txt", layer: "builtin:repair/provider-review", version: "1"},
	{id: "sot:prompts/root-review/extract-provider-review.v1.txt", source: "prompts/root-review/extract-provider-review.v1.txt", layer: "builtin:extract/provider-review", version: "1"},
}

// LoadDefaultTemplateSet loads the fixed root-review prompt contract from the
// supplied immutable contract catalog.
func LoadDefaultTemplateSet(ctx context.Context, catalog ports.ContractCatalog) (review.TemplateSet, error) {
	if ctx == nil || catalog == nil {
		return review.TemplateSet{}, fmt.Errorf("review templates: nil context or catalog")
	}
	var common, run, output, repair, extract prompt.TrustedLayer
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
			case "builtin:extract/provider-review":
				extract = layer
			}
		default:
			roles[descriptor.role] = layer
		}
	}
	definitions, err := roleassets.Load(ctx, catalog)
	if err != nil {
		return review.TemplateSet{}, fmt.Errorf("review templates: %w", err)
	}
	for _, definition := range definitions {
		role := domain.Role(definition.ID)
		layer, err := prompt.NewTrustedLayer("builtin:roles/"+definition.ID, "1", []byte(definition.SystemPrompt))
		if err != nil {
			return review.TemplateSet{}, fmt.Errorf("review templates: role layer %q: %w", role, err)
		}
		roles[role] = layer
	}
	return review.NewTemplateSet(common, run, output, repair, extract, roles)
}
