// Package review coordinates one deterministic, in-memory review run.
package review

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/evidence"
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
	fallbackRoute    ports.ProviderRoute
	hasFallback      bool
}

const legacyConcurrencyKey = "legacy"

// NewAssignment constructs a legacy trusted role assignment without fallback
// authority. All legacy assignments share the fixed legacy concurrency lane.
func NewAssignment(role domain.Role, required bool, providerInstance string) (Assignment, error) {
	task, err := domain.NewRoleTask(role, required, providerInstance, nil)
	if err != nil {
		return Assignment{}, err
	}
	key, err := ports.ParseConcurrencyKey(legacyConcurrencyKey)
	if err != nil {
		return Assignment{}, fmt.Errorf("review assignment: legacy concurrency key: %w", err)
	}
	primary, err := ports.NewProviderRoute(task.PrimaryProvider(), key)
	if err != nil {
		return Assignment{}, err
	}
	return newScheduledAssignment(task, primary, nil), nil
}

// NewScheduledAssignment constructs one trusted role assignment with a primary
// route and an optional fallback route on a distinct concurrency lane.
func NewScheduledAssignment(
	role domain.Role,
	required bool,
	primary ports.ProviderRoute,
	fallback *ports.ProviderRoute,
) (Assignment, error) {
	var fallbackProvider *string
	if fallback != nil {
		provider := fallback.ProviderInstance()
		fallbackProvider = &provider
	}
	task, err := domain.NewRoleTask(role, required, primary.ProviderInstance(), fallbackProvider)
	if err != nil {
		return Assignment{}, err
	}
	if !primary.Valid() {
		return Assignment{}, fmt.Errorf("review assignment: invalid primary provider route")
	}
	if fallback == nil {
		return newScheduledAssignment(task, primary, nil), nil
	}
	if !fallback.Valid() {
		return Assignment{}, fmt.Errorf("review assignment: invalid fallback provider route")
	}
	if fallback.ProviderInstance() == primary.ProviderInstance() {
		return Assignment{}, fmt.Errorf("review assignment: fallback provider instance must differ from primary")
	}
	if fallback.ConcurrencyKey().String() == primary.ConcurrencyKey().String() {
		return Assignment{}, fmt.Errorf("review assignment: fallback concurrency key must differ from primary")
	}
	return newScheduledAssignment(task, primary, fallback), nil
}

func newScheduledAssignment(
	task domain.RoleTask,
	primary ports.ProviderRoute,
	fallback *ports.ProviderRoute,
) Assignment {
	assignment := Assignment{
		role:             task.Role(),
		required:         task.Required(),
		providerInstance: task.PrimaryProvider(),
		primaryRoute:     primary,
	}
	if fallback != nil {
		assignment.fallbackRoute = *fallback
		assignment.hasFallback = true
	}
	return assignment
}

// Role returns the coordinator-selected role.
func (assignment Assignment) Role() domain.Role { return assignment.role }

// Required reports whether the role is part of this run's required coverage.
func (assignment Assignment) Required() bool { return assignment.required }

// ProviderInstance returns the trusted primary provider instance selected for the role.
func (assignment Assignment) ProviderInstance() string { return assignment.providerInstance }

// PrimaryRoute returns the trusted primary provider route.
func (assignment Assignment) PrimaryRoute() ports.ProviderRoute { return assignment.primaryRoute }

// HasFallback reports whether the assignment has a configured fallback route.
func (assignment Assignment) HasFallback() bool { return assignment.hasFallback }

// FallbackRoute returns a caller-owned fallback route when configured.
func (assignment Assignment) FallbackRoute() (ports.ProviderRoute, bool) {
	return assignment.fallbackRoute, assignment.hasFallback
}

// TemplateSet holds the trusted prompt layers required to compose a role
// packet. It owns defensive copies of all layer bytes and exposes copies.
type TemplateSet struct {
	common     promptLayer
	reviewRun  promptLayer
	jsonOutput promptLayer
	repair     promptLayer
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
// JSON-output, repair, and role-specific trusted layers.
func NewTemplateSet(common, reviewRun, jsonOutput, repair prompt.TrustedLayer, roleSpecific map[domain.Role]prompt.TrustedLayer) (TemplateSet, error) {
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
	role := strings.TrimPrefix(original.ID(), "builtin:template/root-review/")
	if role == original.ID() || !domain.Role(role).Valid() {
		return prompt.TrustedTemplate{}, fmt.Errorf("review templates: invalid root-review template %q", original.ID())
	}
	layers := append(baseLayers, templates.Repair(), planLayer)
	return prompt.ComposeTrustedTemplate(
		"builtin:template/root-review/"+role+"/repair",
		"1",
		layers...,
	)
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

// PromptWireIdentity records the exact source and execution identities of one
// compiled provider packet. It contains no provider output.
type PromptWireIdentity struct {
	purpose               ports.ProviderInvocationPurpose
	sourceInvocationID    string
	executionInvocationID string
	completeStdinSHA256   string
	stdinByteLength       int
}

// Purpose returns whether this was an initial or repair invocation.
func (identity PromptWireIdentity) Purpose() ports.ProviderInvocationPurpose { return identity.purpose }

// SourceInvocationID returns the source identity framed in the packet.
func (identity PromptWireIdentity) SourceInvocationID() string { return identity.sourceInvocationID }

// ExecutionInvocationID returns the process execution identity for the packet.
func (identity PromptWireIdentity) ExecutionInvocationID() string {
	return identity.executionInvocationID
}

// CompleteStdinSHA256 returns the exact complete-stdin wire identity.
func (identity PromptWireIdentity) CompleteStdinSHA256() string { return identity.completeStdinSHA256 }

// StdinByteLength returns the exact number of bytes in the provider packet.
func (identity PromptWireIdentity) StdinByteLength() int { return identity.stdinByteLength }

// RoleExecution is an immutable record of one selected role. An unstarted
// role has no attempt identity or prompt identities.
type RoleExecution struct {
	role         domain.Role
	state        domain.RoleTaskState
	attemptID    domain.AttemptID
	hasAttempt   bool
	attemptState domain.AttemptState
	repaired     bool
	promptWires  []PromptWireIdentity
}

// Role returns the selected role.
func (execution RoleExecution) Role() domain.Role { return execution.role }

// State returns the terminal role-task state.
func (execution RoleExecution) State() domain.RoleTaskState { return execution.state }

// AttemptID returns the coordinator-issued attempt ID when the role started.
func (execution RoleExecution) AttemptID() (domain.AttemptID, bool) {
	return execution.attemptID, execution.hasAttempt
}

// AttemptState returns the terminal attempt state when the role started.
func (execution RoleExecution) AttemptState() (domain.AttemptState, bool) {
	return execution.attemptState, execution.hasAttempt
}

// Repaired reports whether a repair response was accepted for this role.
func (execution RoleExecution) Repaired() bool { return execution.repaired }

// PromptWireIdentities returns caller-owned identity records in invocation
// order. The values contain no mutable bytes.
func (execution RoleExecution) PromptWireIdentities() []PromptWireIdentity {
	return append([]PromptWireIdentity(nil), execution.promptWires...)
}

// ResultFindingEvidence binds one final global finding ID to its exact
// verifier-owned receipt group. The validation proof remains private so
// callers cannot substitute a different finding for the receipts.
type ResultFindingEvidence struct {
	findingID string
	finding   domain.Finding
	proof     VerifiedFindingEvidence
}

func newResultFindingEvidence(finding domain.Finding, proof VerifiedFindingEvidence) ResultFindingEvidence {
	return ResultFindingEvidence{
		findingID: finding.ID(),
		finding:   finding,
		proof:     cloneVerifiedFindingEvidence([]VerifiedFindingEvidence{proof})[0],
	}
}

// FindingID returns the final global finding ID.
func (group ResultFindingEvidence) FindingID() string { return group.findingID }

// Finding returns the final global finding associated with the receipts.
func (group ResultFindingEvidence) Finding() domain.Finding { return group.finding }

// MatchesFinding reports whether finding is the exact final finding associated
// with this verifier-owned receipt group.
func (group ResultFindingEvidence) MatchesFinding(finding domain.Finding) bool {
	return group.findingID == finding.ID() && group.finding == finding
}

// Receipts returns caller-owned verifier receipt values in validation claim order.
func (group ResultFindingEvidence) Receipts() []evidence.CurrentReceipt {
	return group.proof.Receipts()
}

func cloneResultFindingEvidence(source []ResultFindingEvidence) []ResultFindingEvidence {
	copied := make([]ResultFindingEvidence, len(source))
	for index, group := range source {
		copied[index] = newResultFindingEvidence(group.finding, group.proof)
	}
	return copied
}

// Result is an immutable review-service snapshot. It intentionally exposes no
// mutable domain.Run, provider output, publication authority, or filesystem
// receipt.
type Result struct {
	sessionID      domain.SessionID
	runID          domain.RunID
	runState       domain.RunState
	findings       []domain.Finding
	evidence       []ResultFindingEvidence
	outcomes       domain.OutcomeAxes
	roleExecutions []RoleExecution
}

// SessionID returns the immutable review session ID.
func (result Result) SessionID() domain.SessionID { return result.sessionID }

// RunID returns the immutable review run ID.
func (result Result) RunID() domain.RunID { return result.runID }

// RunState returns the terminal state of the in-memory run.
func (result Result) RunState() domain.RunState { return result.runState }

// Findings returns a caller-owned ordered finding slice.
func (result Result) Findings() []domain.Finding {
	return append([]domain.Finding(nil), result.findings...)
}

// Evidence returns defensive verifier receipt-group copies in final finding
// order.
func (result Result) Evidence() []ResultFindingEvidence {
	return cloneResultFindingEvidence(result.evidence)
}

// Outcomes returns the four system-owned outcome axes.
func (result Result) Outcomes() domain.OutcomeAxes { return result.outcomes }

// OutcomeAxes is an explicit alias for Outcomes.
func (result Result) OutcomeAxes() domain.OutcomeAxes { return result.outcomes }

// RoleExecutions returns caller-owned terminal role execution records.
func (result Result) RoleExecutions() []RoleExecution {
	return cloneRoleExecutions(result.roleExecutions)
}

func cloneRoleExecutions(source []RoleExecution) []RoleExecution {
	copied := make([]RoleExecution, len(source))
	for index, execution := range source {
		copied[index] = execution
		copied[index].promptWires = append([]PromptWireIdentity(nil), execution.promptWires...)
	}
	return copied
}

// FallbackScheduled is always false for this sequential vertical slice.
func (Result) FallbackScheduled() bool { return false }
