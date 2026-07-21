package reviewrun

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type templateDescriptor struct {
	id     string
	source string
	layer  string
	role   domain.Role
}

var rootReviewTemplateDescriptors = [...]templateDescriptor{
	{id: "sot:prompts/root-review/common.v2.txt", source: "prompts/root-review/common.v2.txt", layer: "builtin:review/common"},
	{id: "sot:prompts/root-review/run-review.v2.txt", source: "prompts/root-review/run-review.v2.txt", layer: "builtin:run/review"},
	{id: "sot:prompts/root-review/roles/logic.v2.txt", source: "prompts/root-review/roles/logic.v2.txt", layer: "builtin:roles/logic", role: domain.RoleLogic},
	{id: "sot:prompts/root-review/roles/security.v2.txt", source: "prompts/root-review/roles/security.v2.txt", layer: "builtin:roles/security", role: domain.RoleSecurity},
	{id: "sot:prompts/root-review/roles/maintainability.v2.txt", source: "prompts/root-review/roles/maintainability.v2.txt", layer: "builtin:roles/maintainability", role: domain.RoleMaintainability},
	{id: "sot:prompts/root-review/roles/product.v2.txt", source: "prompts/root-review/roles/product.v2.txt", layer: "builtin:roles/product", role: domain.RoleProduct},
	{id: "sot:prompts/root-review/roles/documentation.v2.txt", source: "prompts/root-review/roles/documentation.v2.txt", layer: "builtin:roles/documentation", role: domain.RoleDocumentation},
	{id: "sot:prompts/root-review/roles/testing.v2.txt", source: "prompts/root-review/roles/testing.v2.txt", layer: "builtin:roles/testing", role: domain.RoleTesting},
	{id: "sot:prompts/root-review/output-provider-review-wire.v2.txt", source: "prompts/root-review/output-provider-review-wire.v2.txt", layer: "builtin:output/provider-review-wire"},
	{id: "sot:prompts/root-review/repair-provider-review.v2.txt", source: "prompts/root-review/repair-provider-review.v2.txt", layer: "builtin:repair/provider-review"},
}

// LoadDefaultTemplateSet loads the fixed root-review prompt contract from the
// supplied immutable contract catalog.
func LoadDefaultTemplateSet(ctx context.Context, catalog ports.ContractCatalog) (review.TemplateSet, error) {
	if ctx == nil || catalog == nil {
		return review.TemplateSet{}, fmt.Errorf("review templates: nil context or catalog")
	}
	var common, run, output, repair prompt.TrustedLayer
	roles := make(map[domain.Role]prompt.TrustedLayer, 6)
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
		layer, err := prompt.NewTrustedLayer(descriptor.layer, "2", raw)
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
	return review.NewTemplateSet(common, run, output, repair, roles)
}
