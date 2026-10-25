// Package review owns assignments, concurrent coordination, provider runtime,
// and accepted review results.
package review

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Assignment is a trusted, immutable role selection. Required is always true
// for the logic required floor, independent of the supplied flag.
type Assignment struct {
	role             domain.Role
	required         bool
	providerInstance string
	primaryRoute     ports.ProviderRoute
}

// NewScheduledAssignment constructs one trusted role assignment binding the
// role to exactly one provider route.
func NewScheduledAssignment(
	role domain.Role,
	required bool,
	primary ports.ProviderRoute,
) (Assignment, error) {
	task, err := domain.NewRoleTask(role, required, primary.ProviderInstance())
	if err != nil {
		return Assignment{}, err
	}
	if !primary.Valid() {
		return Assignment{}, fmt.Errorf("review assignment: invalid primary provider route")
	}
	return newScheduledAssignment(task, primary), nil
}

func newScheduledAssignment(task domain.RoleTask, primary ports.ProviderRoute) Assignment {
	return Assignment{
		role:             task.Role(),
		required:         task.Required(),
		providerInstance: task.PrimaryProvider(),
		primaryRoute:     primary,
	}
}

// Role returns the coordinator-selected role.
func (assignment Assignment) Role() domain.Role { return assignment.role }

// Required reports whether the role is part of this run's required coverage.
func (assignment Assignment) Required() bool { return assignment.required }

// ProviderInstance returns the trusted primary provider instance selected for the role.
func (assignment Assignment) ProviderInstance() string { return assignment.providerInstance }

// PrimaryRoute returns the trusted primary provider route.
func (assignment Assignment) PrimaryRoute() ports.ProviderRoute { return assignment.primaryRoute }

// TemplateSet holds the trusted prompt layers required to compose a role
// packet. It owns defensive copies of all layer bytes and exposes copies.
type TemplateSet struct {
	common     promptLayer
	reviewRun  promptLayer
	jsonOutput promptLayer
	repair     promptLayer
	extract    promptLayer
	roleLayers map[domain.Role]promptLayer
}

// promptLayer keeps result.go independent of prompt construction details while
// preserving the immutable prompt.TrustedLayer value at the package boundary.
type promptLayer struct {
	id      string
	version string
	bytes   []byte
}

// NewTemplateSet validates and defensively copies the common, review-run,
// JSON-output, repair, extraction, and role-specific trusted layers.
func NewTemplateSet(common, reviewRun, jsonOutput, repair, extract prompt.TrustedLayer, roleSpecific map[domain.Role]prompt.TrustedLayer) (TemplateSet, error) {
	copiedCommon, err := copyPromptLayer(common)
	if err != nil {
		return TemplateSet{}, err
	}
	copiedReviewRun, err := copyPromptLayer(reviewRun)
	if err != nil {
		return TemplateSet{}, err
	}
	copiedJSONOutput, err := copyPromptLayer(jsonOutput)
	if err != nil {
		return TemplateSet{}, err
	}
	copiedRepair, err := copyPromptLayer(repair)
	if err != nil {
		return TemplateSet{}, err
	}
	copiedExtract, err := copyPromptLayer(extract)
	if err != nil {
		return TemplateSet{}, err
	}
	if len(roleSpecific) == 0 {
		return TemplateSet{}, fmt.Errorf("review templates: at least one role-specific layer is required")
	}
	roleLayers := make(map[domain.Role]promptLayer, len(roleSpecific))
	for role, layer := range roleSpecific {
		if !role.Valid() {
			return TemplateSet{}, fmt.Errorf("review templates: invalid role %q", role)
		}
		copied, err := copyPromptLayer(layer)
		if err != nil {
			return TemplateSet{}, fmt.Errorf("review templates: role %q: %w", role, err)
		}
		roleLayers[role] = copied
	}
	return TemplateSet{
		common:     copiedCommon,
		reviewRun:  copiedReviewRun,
		jsonOutput: copiedJSONOutput,
		repair:     copiedRepair,
		extract:    copiedExtract,
		roleLayers: roleLayers,
	}, nil
}

// Common returns a caller-owned copy of the common trusted layer.
func (templates TemplateSet) Common() prompt.TrustedLayer { return templates.common.trustedLayer() }

// ReviewRun returns a caller-owned copy of the review-run trusted layer.
func (templates TemplateSet) ReviewRun() prompt.TrustedLayer {
	return templates.reviewRun.trustedLayer()
}

// JSONOutput returns a caller-owned copy of the JSON-output trusted layer.
func (templates TemplateSet) JSONOutput() prompt.TrustedLayer {
	return templates.jsonOutput.trustedLayer()
}

// Repair returns a caller-owned copy of the repair trusted layer.
func (templates TemplateSet) Repair() prompt.TrustedLayer { return templates.repair.trustedLayer() }

// Extract returns a caller-owned copy of the structured extraction trusted layer.
func (templates TemplateSet) Extract() prompt.TrustedLayer { return templates.extract.trustedLayer() }

// ComposeRootReview composes the fixed-order trusted template for role.
func (templates TemplateSet) ComposeRootReview(role domain.Role, objective *prompt.Objective) (prompt.TrustedTemplate, error) {
	roleLayer, ok := templates.RoleTemplate(role)
	if !ok {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: missing role %q", role)
	}
	layers := []prompt.TrustedLayer{templates.Common(), templates.ReviewRun(), roleLayer}
	if objective != nil {
		if err := objective.Lint().Err(); err != nil {
			return prompt.TrustedTemplate{}, fmt.Errorf("review templates: objective: %w", err)
		}
		layer, err := prompt.NewTrustedLayer("review:objective", "1", objective.Bytes())
		if err != nil {
			return prompt.TrustedTemplate{}, fmt.Errorf("review templates: objective: %w", err)
		}
		layers = append(layers, layer)
	}
	layers = append(layers, templates.JSONOutput())
	return prompt.ComposeTrustedTemplate("builtin:template/root-review/"+string(role), "1", layers...)
}

// ComposeRootReviewRepair appends the frozen repair contract and canonical plan
// to the original trusted template without promoting prior provider output.
func (templates TemplateSet) ComposeRootReviewRepair(original prompt.TrustedTemplate, plan validation.RepairPlan) (prompt.TrustedTemplate, error) {
	baseLayers, err := trustedLayersForRepair(original)
	if err != nil {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: repair base: %w", err)
	}
	paths := plan.AllowedPaths()
	sort.Strings(paths)
	lines := []string{
		"Mulgae ROOT REVIEW REPAIR PLAN/1",
		"original_output_sha256:" + plan.OriginalSHA256(),
		"mode:" + string(plan.Mode()),
		"allowed_paths_count:" + strconv.Itoa(len(paths)),
	}
	for _, path := range paths {
		lines = append(lines, "allowed_path:"+path)
	}
	planLayer, err := prompt.NewTrustedLayer("review:repair-plan", "1", []byte(strings.Join(lines, "\n")))
	if err != nil {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: repair plan: %w", err)
	}
	if !validRootReviewTemplateID(original.ID()) {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: invalid root-review template %q", original.ID())
	}
	layers := append(baseLayers, templates.Repair(), planLayer)
	return prompt.ComposeTrustedTemplate(
		original.ID()+"/repair",
		"1",
		layers...,
	)
}

// ComposeRootReviewExtraction appends the frozen structured extraction contract
// to the original trusted template. The accepted role report never becomes a
// trusted layer: it travels as an untrusted prior-report frame in the packet.
func (templates TemplateSet) ComposeRootReviewExtraction(original prompt.TrustedTemplate) (prompt.TrustedTemplate, error) {
	baseLayers, err := trustedLayersForRepair(original)
	if err != nil {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: extraction base: %w", err)
	}
	if !validRootReviewTemplateID(original.ID()) {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: invalid root-review template %q", original.ID())
	}
	layers := append(baseLayers, templates.Extract())
	return prompt.ComposeTrustedTemplate(
		original.ID()+"/extract",
		"1",
		layers...,
	)
}

func validRootReviewTemplateID(id string) bool {
	role, found := strings.CutPrefix(id, "builtin:template/root-review/")
	if !found {
		role, found = strings.CutPrefix(id, "builtin:template/live-review/")
	}
	return found && domain.Role(role).Valid()
}

// OutputDestinationTrustedLayerID is the fixed identity of the Mulgae-owned
// staged output destination layer. It is always the last trusted layer of a
// staged_file launch template, so consumers can recognize it by identity.
const OutputDestinationTrustedLayerID = "review:output-destination"

const outputDestinationTrustedLayerVersion = "1"

// ComposeRootReviewOutputDestination appends the Mulgae-owned output destination
// contract as the last trusted layer of original. The destination is chosen by
// the adapter locator for exactly one launch, so separate launches of one
// attempt carry different absolute paths. Provider output never
// participates in the layer.
func ComposeRootReviewOutputDestination(
	original prompt.TrustedTemplate,
	destination ports.StagedOutputDestination,
) (prompt.TrustedTemplate, error) {
	baseLayers, err := trustedLayersForRepair(original)
	if err != nil {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: output destination base: %w", err)
	}
	destinationLayer, err := OutputDestinationTrustedLayer(destination)
	if err != nil {
		return prompt.TrustedTemplate{}, err
	}
	if original.ID() == "" {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: output destination base template has no identity")
	}
	return prompt.ComposeTrustedTemplate(
		original.ID()+"/output-destination",
		outputDestinationTrustedLayerVersion,
		append(baseLayers, destinationLayer)...,
	)
}

// RebindRootReviewOutputDestination replaces the final Mulgae-owned staged
// output layer while preserving every preceding trusted layer and the template
// identity. It rejects templates that were not already staged so exact replay
// cannot introduce a transport contract absent from the source attempt.
func RebindRootReviewOutputDestination(
	original prompt.TrustedTemplate,
	destination ports.StagedOutputDestination,
) (prompt.TrustedTemplate, error) {
	layers, err := trustedLayersForRepair(original)
	if err != nil {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: rebind output destination base: %w", err)
	}
	if len(layers) == 0 || layers[len(layers)-1].ID() != OutputDestinationTrustedLayerID {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: source template has no final output destination layer")
	}
	destinationLayer, err := OutputDestinationTrustedLayer(destination)
	if err != nil {
		return prompt.TrustedTemplate{}, err
	}
	layers[len(layers)-1] = destinationLayer
	return prompt.ComposeTrustedTemplate(original.ID(), original.Version(), layers...)
}

// OutputDestinationTrustedLayer builds the exact trusted layer that instructs a
// provider to write its complete role report to the one staged file Mulgae
// granted it. Callers that resolve a destination and callers that verify one
// must derive the layer from this single constructor.
func OutputDestinationTrustedLayer(destination ports.StagedOutputDestination) (prompt.TrustedLayer, error) {
	if !destination.Valid() {
		return prompt.TrustedLayer{}, fmt.Errorf("review templates: invalid staged output destination")
	}
	lines := []string{
		"Mulgae ROOT REVIEW OUTPUT DESTINATION/1",
		"Write your complete final Markdown role report to this exact absolute file path, creating that one file only:",
		destination.AbsolutePath(),
		"Write nothing else there, create no other file or directory, and do not create links.",
		"That directory is outside the review workspace and is not listed in ._mulgae_workspace_manifest.json; do not read, search, or reason about it as review content.",
		"This contract supersedes any earlier instruction to return the report on standard output. Standard output is ignored for acceptance.",
	}
	layer, err := prompt.NewTrustedLayer(
		OutputDestinationTrustedLayerID, outputDestinationTrustedLayerVersion, []byte(strings.Join(lines, "\n")),
	)
	if err != nil {
		return prompt.TrustedLayer{}, fmt.Errorf("review templates: output destination layer: %w", err)
	}
	return layer, nil
}

func trustedLayersForRepair(original prompt.TrustedTemplate) ([]prompt.TrustedLayer, error) {
	manifest := original.TrustedLayerManifest()
	if len(manifest) == 0 {
		layer, err := prompt.NewTrustedLayer("review:original-template", "1", original.Bytes())
		if err != nil {
			return nil, err
		}
		return []prompt.TrustedLayer{layer}, nil
	}
	content := original.Bytes()
	layers := make([]prompt.TrustedLayer, 0, len(manifest))
	offset := 0
	for index, provenance := range manifest {
		end := offset + provenance.ByteLength()
		if end > len(content) {
			return nil, fmt.Errorf("trusted layer %d extends beyond template bytes", provenance.Ordinal())
		}
		layer, err := prompt.NewTrustedLayer(provenance.ID(), provenance.Version(), content[offset:end])
		if err != nil {
			return nil, err
		}
		if layer.SHA256() != provenance.SHA256() {
			return nil, fmt.Errorf("trusted layer %d SHA-256 does not match template bytes", provenance.Ordinal())
		}
		layers = append(layers, layer)
		offset = end
		if index < len(manifest)-1 {
			if offset+2 > len(content) || !bytes.Equal(content[offset:offset+2], []byte("\n\n")) {
				return nil, fmt.Errorf("trusted layer %d separator does not match composed template", provenance.Ordinal())
			}
			offset += 2
		}
	}
	if offset != len(content) {
		return nil, fmt.Errorf("trusted layer manifest does not cover template bytes")
	}
	return layers, nil
}

// RoleTemplate returns a caller-owned copy of a role-specific trusted layer.
func (templates TemplateSet) RoleTemplate(role domain.Role) (prompt.TrustedLayer, bool) {
	layer, ok := templates.roleLayers[role]
	if !ok {
		return prompt.TrustedLayer{}, false
	}
	return layer.trustedLayer(), true
}

// RoleTemplates returns a caller-owned map and caller-owned layer values.
func (templates TemplateSet) RoleTemplates() map[domain.Role]prompt.TrustedLayer {
	copied := make(map[domain.Role]prompt.TrustedLayer, len(templates.roleLayers))
	for role, layer := range templates.roleLayers {
		copied[role] = layer.trustedLayer()
	}
	return copied
}

func copyPromptLayer(layer prompt.TrustedLayer) (promptLayer, error) {
	copied, err := prompt.NewTrustedLayer(layer.ID(), layer.Version(), layer.Bytes())
	if err != nil {
		return promptLayer{}, err
	}
	return promptLayer{id: copied.ID(), version: copied.Version(), bytes: copied.Bytes()}, nil
}

func (layer promptLayer) trustedLayer() prompt.TrustedLayer {
	trusted, _ := prompt.NewTrustedLayer(layer.id, layer.version, layer.bytes)
	return trusted
}
