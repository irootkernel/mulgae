// Package config resolves already-strict configuration models without performing
// parsing, filesystem access, or provider readiness checks.
package config

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// FieldSource identifies the layer that contributes an effective policy value.
type FieldSource string

const (
	SourceBuiltin FieldSource = "builtin"
	SourceGlobal  FieldSource = "global"
	SourceProject FieldSource = "project"
)
const (
	builtinRoleMaxInvocations     = 4
	builtinRunMaxInvocations      = 24
	builtinRunTotalOutputCapBytes = 64 << 20
)

// WorkspaceAccess is ordered from most restrictive to least restrictive.
type WorkspaceAccess string

const (
	WorkspaceNone             WorkspaceAccess = "none"
	WorkspaceReadonlySnapshot WorkspaceAccess = "readonly_snapshot"
	WorkspaceProject          WorkspaceAccess = "project"
)

// Valid reports whether access is a member of the fixed workspace lattice.
func (access WorkspaceAccess) Valid() bool { return access.Rank() >= 0 }

// Rank returns the workspace lattice rank. Lower ranks are more restrictive.
func (access WorkspaceAccess) Rank() int {
	switch access {
	case WorkspaceNone:
		return 0
	case WorkspaceReadonlySnapshot:
		return 1
	case WorkspaceProject:
		return 2
	default:
		return -1
	}
}

// Intersect returns the more restrictive access mode. It rejects values outside
// the fixed workspace lattice.
func (access WorkspaceAccess) Intersect(other WorkspaceAccess) (WorkspaceAccess, error) {
	if !access.Valid() || !other.Valid() {
		return "", fmt.Errorf("invalid workspace access intersection %q and %q", access, other)
	}
	if access.Rank() <= other.Rank() {
		return access, nil
	}
	return other, nil
}

// FixedSeverityOrder returns the severity lattice from strongest threshold to
// weakest threshold. A threshold includes its severity and every later member.
func FixedSeverityOrder() []domain.Severity {
	return []domain.Severity{
		domain.SeverityInfo,
		domain.SeverityLow,
		domain.SeverityMedium,
		domain.SeverityHigh,
		domain.SeverityCritical,
		domain.SeverityBlocker,
	}
}
func builtinSeverityThreshold() []domain.Severity {
	return []domain.Severity{
		domain.SeverityHigh,
		domain.SeverityCritical,
		domain.SeverityBlocker,
	}
}

// ReductionDiagnostic describes a policy violation found while reducing typed
// configuration models. Source locations are unavailable because parsing has
// already completed before this package is called.
type ReductionDiagnostic struct {
	Layer   adapterconfig.Layer
	Path    string
	Code    string
	Message string
}

// ReductionError rejects a configuration layer without exposing a partial
// result. Diagnostics returns a defensive copy in deterministic field order.
type ReductionError struct {
	diagnostics []ReductionDiagnostic
}

func (err *ReductionError) Error() string {
	if err == nil || len(err.diagnostics) == 0 {
		return "configuration reduction rejected"
	}

	parts := make([]string, 0, len(err.diagnostics))
	for _, diagnostic := range err.diagnostics {
		parts = append(parts, fmt.Sprintf("%s %s [%s] %s", diagnostic.Layer, diagnostic.Path, diagnostic.Code, diagnostic.Message))
	}
	return "configuration reduction rejected: " + strings.Join(parts, "; ")
}

// Diagnostics returns a copy of the reduction diagnostics.
func (err *ReductionError) Diagnostics() []ReductionDiagnostic {
	if err == nil {
		return nil
	}
	return append([]ReductionDiagnostic(nil), err.diagnostics...)
}

// AsReductionError returns the typed reduction error, including when wrapped.
func AsReductionError(err error) (*ReductionError, bool) {
	var reductionError *ReductionError
	if !errors.As(err, &reductionError) {
		return nil, false
	}
	return reductionError, true
}

// ProvenanceEntry records every contributing source for one effective field.
// Sources are ordered from the built-in baseline through the project proposal.
type ProvenanceEntry struct {
	Field   string
	Sources []FieldSource
}

// FieldProvenance is an immutable, deterministic field-to-source view.
type FieldProvenance struct {
	entries []ProvenanceEntry
}

// Entries returns a defensive copy sorted by field name.
func (provenance FieldProvenance) Entries() []ProvenanceEntry {
	entries := make([]ProvenanceEntry, len(provenance.entries))
	for index, entry := range provenance.entries {
		entries[index] = ProvenanceEntry{
			Field:   entry.Field,
			Sources: append([]FieldSource(nil), entry.Sources...),
		}
	}
	return entries
}

// Sources returns the contributing layers for field.
func (provenance FieldProvenance) Sources(field string) []FieldSource {
	for _, entry := range provenance.entries {
		if entry.Field == field {
			return append([]FieldSource(nil), entry.Sources...)
		}
	}
	return nil
}

// Source returns the most specific contributing layer for field.
func (provenance FieldProvenance) Source(field string) (FieldSource, bool) {
	sources := provenance.Sources(field)
	if len(sources) == 0 {
		return "", false
	}
	return sources[len(sources)-1], true
}

// ResolvedRole is the immutable effective configuration for one fixed role.
type ResolvedRole struct {
	enabled bool
	guide   string
}

// Enabled reports whether the role is enabled by the effective policy.
func (role ResolvedRole) Enabled() bool { return role.enabled }

// Guide returns the effective trusted guide reference.
func (role ResolvedRole) Guide() string { return role.guide }

// ResolvedConfig is the immutable B -> G -> P reduction result. Accessors
// return values or defensive copies so callers cannot mutate resolved policy.
type ResolvedConfig struct {
	global                 adapterconfig.GlobalConfig
	project                adapterconfig.ProjectMetadata
	hasProject             bool
	roles                  map[domain.Role]ResolvedRole
	requiredRoles          []domain.Role
	workspaceAccess        WorkspaceAccess
	requestChangesOn       []domain.Severity
	requireVerifiedFor     []domain.Severity
	roleMaxInvocations     int
	runMaxInvocations      int
	runTotalOutputCapBytes int64
	ciFailOnSeverity       []domain.Severity
	degradedReviewFails    bool
	provenance             FieldProvenance
}

// Runtime returns a defensive copy of the global runtime policy. Its sensitive
// path values are intentionally omitted by Redact.
func (resolved ResolvedConfig) Runtime() adapterconfig.RuntimeConfig {
	return cloneRuntime(resolved.global.Runtime)
}

// Providers returns defensive copies of globally owned provider definitions.
// The reducer never selects a provider or changes its readiness status.
func (resolved ResolvedConfig) Providers() map[string]adapterconfig.ProviderConfig {
	return cloneProviders(resolved.global.Providers)
}

// Provider returns a defensive copy of one globally owned provider definition.
func (resolved ResolvedConfig) Provider(id string) (adapterconfig.ProviderConfig, bool) {
	provider, exists := resolved.global.Providers[id]
	if !exists {
		return adapterconfig.ProviderConfig{}, false
	}
	return cloneProvider(provider), true
}

// Project returns the trusted-base project metadata when a project proposal was
// accepted.
func (resolved ResolvedConfig) Project() (adapterconfig.ProjectMetadata, bool) {
	return resolved.project, resolved.hasProject
}

// Role returns the effective configuration of one fixed role.
func (resolved ResolvedConfig) Role(role domain.Role) (ResolvedRole, bool) {
	resolvedRole, exists := resolved.roles[role]
	return resolvedRole, exists
}

// RequiredRoles returns the effective required-role set in domain.FixedRoleOrder.
func (resolved ResolvedConfig) RequiredRoles() []domain.Role {
	return append([]domain.Role(nil), resolved.requiredRoles...)
}

// WorkspaceAccess returns the effective workspace access intersection.
func (resolved ResolvedConfig) WorkspaceAccess() WorkspaceAccess { return resolved.workspaceAccess }

// RequestChangesOn returns the canonical effective request-changes closure.
func (resolved ResolvedConfig) RequestChangesOn() []domain.Severity {
	return append([]domain.Severity(nil), resolved.requestChangesOn...)
}

// RequireVerifiedFor returns the canonical effective evidence requirement set.
func (resolved ResolvedConfig) RequireVerifiedFor() []domain.Severity {
	return append([]domain.Severity(nil), resolved.requireVerifiedFor...)
}

// RoleMaxInvocations returns the effective per-role invocation ceiling.
func (resolved ResolvedConfig) RoleMaxInvocations() int { return resolved.roleMaxInvocations }

// RunMaxInvocations returns the effective per-run invocation ceiling.
func (resolved ResolvedConfig) RunMaxInvocations() int { return resolved.runMaxInvocations }

// RunTotalOutputCapBytes returns the exact effective parsed output cap.
func (resolved ResolvedConfig) RunTotalOutputCapBytes() int64 { return resolved.runTotalOutputCapBytes }

// CIFailOnSeverity returns the canonical effective CI failure closure.
func (resolved ResolvedConfig) CIFailOnSeverity() []domain.Severity {
	return append([]domain.Severity(nil), resolved.ciFailOnSeverity...)
}

// DegradedReviewFails reports the effective OR-combined CI enforcement policy.
func (resolved ResolvedConfig) DegradedReviewFails() bool { return resolved.degradedReviewFails }

// Provenance returns a defensive copy of the source provenance.
func (resolved ResolvedConfig) Provenance() FieldProvenance {
	return FieldProvenance{entries: resolved.provenance.Entries()}
}

// ParseOutputCap parses the strict IEC byte-size syntax accepted by the typed
// configuration model. Values must be positive, exact KiB/MiB/GiB quantities
// no larger than one GiB.
func ParseOutputCap(value string) (int64, error) {
	var multiplier int64
	amountText := ""
	switch {
	case strings.HasSuffix(value, "KiB"):
		amountText, multiplier = strings.TrimSuffix(value, "KiB"), 1<<10
	case strings.HasSuffix(value, "MiB"):
		amountText, multiplier = strings.TrimSuffix(value, "MiB"), 1<<20
	case strings.HasSuffix(value, "GiB"):
		amountText, multiplier = strings.TrimSuffix(value, "GiB"), 1<<30
	default:
		return 0, fmt.Errorf("output cap must use a positive KiB, MiB, or GiB quantity")
	}
	if amountText == "" || len(amountText) > 9 || amountText[0] == '0' {
		return 0, fmt.Errorf("output cap must use a bounded positive quantity")
	}
	for _, character := range amountText {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("output cap quantity must be decimal digits")
		}
	}
	amount, err := strconv.ParseInt(amountText, 10, 64)
	if err != nil || amount <= 0 || amount > (1<<30)/multiplier {
		return 0, fmt.Errorf("output cap exceeds one GiB")
	}
	return amount * multiplier, nil
}

// ResolveConfiguration atomically reduces an already strictly parsed global
// configuration and optional trusted-base project proposal. It never parses
// YAML, reads files, invokes providers, or accepts CLI policy overrides.
func ResolveConfiguration(global adapterconfig.GlobalConfig, project *adapterconfig.ProjectConfig) (ResolvedConfig, error) {
	state := newReductionState(global)
	state.validateGlobal()
	state.validateRequiredRoles(state.required, adapterconfig.LayerGlobal, "$.trust.required_roles")
	if project != nil {
		state.applyProject(*project)
	}
	// Global requirements were checked before P. Recheck only requirements
	// introduced by P after all project role proposals have been applied.
	state.validateRequiredRoles(state.projectAddedRequired, adapterconfig.LayerProject, "$.review.required_roles")
	if len(state.diagnostics) != 0 {
		return ResolvedConfig{}, &ReductionError{diagnostics: state.diagnostics}
	}
	return state.freeze(), nil
}

// Resolve is a concise alias for ResolveConfiguration.
func Resolve(global adapterconfig.GlobalConfig, project *adapterconfig.ProjectConfig) (ResolvedConfig, error) {
	return ResolveConfiguration(global, project)
}

type reductionState struct {
	global                 adapterconfig.GlobalConfig
	project                adapterconfig.ProjectMetadata
	hasProject             bool
	roles                  map[domain.Role]ResolvedRole
	required               map[domain.Role]struct{}
	projectAddedRequired   map[domain.Role]struct{}
	workspaceAccess        WorkspaceAccess
	requestChangesOn       []domain.Severity
	requireVerifiedFor     []domain.Severity
	roleMaxInvocations     int
	runMaxInvocations      int
	runTotalOutputCapBytes int64
	ciFailOnSeverity       []domain.Severity
	degradedReviewFails    bool
	provenance             map[string][]FieldSource
	diagnostics            []ReductionDiagnostic
}

func newReductionState(global adapterconfig.GlobalConfig) *reductionState {
	state := &reductionState{
		global:               cloneGlobal(global),
		roles:                make(map[domain.Role]ResolvedRole, len(domain.FixedRoleOrder())),
		required:             make(map[domain.Role]struct{}, len(domain.FixedRoleOrder())),
		projectAddedRequired: make(map[domain.Role]struct{}, len(domain.FixedRoleOrder())),
		// WorkspaceNone is the built-in default. Global policy deliberately
		// establishes the workspace ceiling and may expand that default; project
		// proposals only intersect the established global ceiling.
		workspaceAccess:        WorkspaceNone,
		requestChangesOn:       builtinSeverityThreshold(),
		requireVerifiedFor:     builtinSeverityThreshold(),
		roleMaxInvocations:     builtinRoleMaxInvocations,
		runMaxInvocations:      builtinRunMaxInvocations,
		runTotalOutputCapBytes: builtinRunTotalOutputCapBytes,
		ciFailOnSeverity:       builtinSeverityThreshold(),
		degradedReviewFails:    true,
		provenance:             make(map[string][]FieldSource),
	}

	for _, role := range domain.FixedRoleOrder() {
		state.roles[role] = ResolvedRole{
			enabled: role.RequiredFloor(),
			guide:   builtinRoleGuide(role),
		}
		state.setProvenance("policy.roles."+string(role)+".enabled", SourceBuiltin)
		if role.RequiredFloor() {
			state.required[role] = struct{}{}
		}
		state.setProvenance("policy.roles."+string(role)+".required", SourceBuiltin)
	}
	state.setProvenance("policy.required_roles", SourceBuiltin)
	state.setProvenance("policy.workspace_access", SourceBuiltin)
	state.setProvenance("policy.request_changes_on", SourceBuiltin)
	state.setProvenance("policy.require_verified_for", SourceBuiltin)
	state.setProvenance("policy.role_max_invocations", SourceBuiltin)
	state.setProvenance("policy.run_max_invocations", SourceBuiltin)
	state.setProvenance("policy.run_total_output_cap_bytes", SourceBuiltin)
	state.setProvenance("policy.ci_fail_on_severity", SourceBuiltin)
	state.setProvenance("policy.degraded_review_fails", SourceBuiltin)

	for id := range state.global.Providers {
		for _, field := range []string{"id", "driver", "status", "optional", "concurrency_key"} {
			state.setProvenance("providers."+id+"."+field, SourceGlobal)
		}
	}
	return state
}

func (state *reductionState) validateGlobal() {
	state.validateGlobalSecurityPolicy()
	state.validateProviders()

	globalAccess := WorkspaceAccess(state.global.Execution.WorkspaceAccess)
	if !globalAccess.Valid() {
		state.add(adapterconfig.LayerGlobal, "$.execution.workspace_access", "invalid_workspace_access", "workspace access is outside the fixed lattice")
	} else {
		// The global layer intentionally may expand the built-in WorkspaceNone
		// default; only project proposals are limited to an intersection.
		state.workspaceAccess = globalAccess
		state.appendProvenance("policy.workspace_access", SourceGlobal)
	}

	for _, role := range domain.FixedRoleOrder() {
		current := state.roles[role]
		current.enabled = globalRoleEnabled(state.global.Roles, role)
		state.roles[role] = current
		state.appendProvenance("policy.roles."+string(role)+".enabled", SourceGlobal)
		if role.RequiredFloor() && !current.enabled {
			state.add(adapterconfig.LayerGlobal, "$.roles."+string(role)+".enabled", "required_floor_disabled", "logic and security are fixed enabled roles")
		}
	}

	globalRequired := state.canonicalRoles(state.global.Trust.RequiredRoles, adapterconfig.LayerGlobal, "$.trust.required_roles")
	for _, role := range domain.FixedRoleOrder() {
		state.appendProvenance("policy.roles."+string(role)+".required", SourceGlobal)
		if role.RequiredFloor() {
			if _, exists := globalRequired[role]; !exists {
				state.add(adapterconfig.LayerGlobal, "$.trust.required_roles", "required_floor_missing", "logic and security must be explicitly required by global policy")
			}
		}
	}
	state.appendProvenance("policy.required_roles", SourceGlobal)
	for role := range globalRequired {
		state.required[role] = struct{}{}
	}

	globalRequestChanges := state.canonicalSeverityClosure(state.global.Review.RequestChangesOn, adapterconfig.LayerGlobal, "$.review.request_changes_on")
	if len(globalRequestChanges) != 0 {
		if severityRank(globalRequestChanges[0]) > severityRank(domain.SeverityHigh) {
			state.add(adapterconfig.LayerGlobal, "$.review.request_changes_on", "weakening_threshold", "global request-changes threshold must be no weaker than high")
		} else {
			state.requestChangesOn = globalRequestChanges
			state.appendProvenance("policy.request_changes_on", SourceGlobal)
		}
	}

	globalEvidence := state.canonicalSeveritySet(state.global.Validation.Evidence.RequireVerifiedFor, adapterconfig.LayerGlobal, "$.validation.evidence.require_verified_for")
	if len(globalEvidence) == 0 {
		state.add(adapterconfig.LayerGlobal, "$.validation.evidence.require_verified_for", "invalid_threshold", "global verified-evidence policy must include high, critical, and blocker")
	} else if !containsAllSeverities(globalEvidence, builtinSeverityThreshold()) {
		state.add(adapterconfig.LayerGlobal, "$.validation.evidence.require_verified_for", "weakening_threshold", "global verified-evidence policy must include high, critical, and blocker")
	} else {
		state.requireVerifiedFor = globalEvidence
		state.appendProvenance("policy.require_verified_for", SourceGlobal)
	}

	if state.global.Resources.RoleMaxInvocations <= 0 {
		state.add(adapterconfig.LayerGlobal, "$.resources.role_max_invocations", "invalid_limit", "role invocation limit must be positive")
	} else if state.global.Resources.RoleMaxInvocations > builtinRoleMaxInvocations {
		state.add(adapterconfig.LayerGlobal, "$.resources.role_max_invocations", "weakening_limit", "global role invocation limit may not exceed the built-in ceiling")
	} else {
		state.roleMaxInvocations = state.global.Resources.RoleMaxInvocations
		state.appendProvenance("policy.role_max_invocations", SourceGlobal)
	}
	if state.global.Resources.RunMaxInvocations <= 0 {
		state.add(adapterconfig.LayerGlobal, "$.resources.run_max_invocations", "invalid_limit", "run invocation limit must be positive")
	} else if state.global.Resources.RunMaxInvocations > builtinRunMaxInvocations {
		state.add(adapterconfig.LayerGlobal, "$.resources.run_max_invocations", "weakening_limit", "global run invocation limit may not exceed the built-in ceiling")
	} else {
		state.runMaxInvocations = state.global.Resources.RunMaxInvocations
		state.appendProvenance("policy.run_max_invocations", SourceGlobal)
	}
	capBytes, err := ParseOutputCap(state.global.Resources.RunTotalOutputCap)
	if err != nil {
		state.add(adapterconfig.LayerGlobal, "$.resources.run_total_output_cap", "invalid_limit", err.Error())
	} else if capBytes > builtinRunTotalOutputCapBytes {
		state.add(adapterconfig.LayerGlobal, "$.resources.run_total_output_cap", "weakening_limit", "global output cap may not exceed the built-in ceiling")
	} else {
		state.runTotalOutputCapBytes = capBytes
		state.appendProvenance("policy.run_total_output_cap_bytes", SourceGlobal)
	}

	globalCIFailure := state.canonicalSeverityClosure(state.global.CI.FailOnSeverity, adapterconfig.LayerGlobal, "$.ci.fail_on_severity")
	if len(globalCIFailure) != 0 {
		if severityRank(globalCIFailure[0]) > severityRank(domain.SeverityHigh) {
			state.add(adapterconfig.LayerGlobal, "$.ci.fail_on_severity", "weakening_threshold", "global CI failure threshold must be no weaker than high")
		} else {
			state.ciFailOnSeverity = globalCIFailure
			state.appendProvenance("policy.ci_fail_on_severity", SourceGlobal)
		}
	}
	if !state.global.CI.DegradedReviewFails {
		state.add(adapterconfig.LayerGlobal, "$.ci.degraded_review_fails", "weakening_value", "global CI policy must fail degraded reviews")
	} else {
		state.appendProvenance("policy.degraded_review_fails", SourceGlobal)
	}
}

func (state *reductionState) validateGlobalSecurityPolicy() {
	if !state.global.Validation.RejectUnknownFields {
		state.add(adapterconfig.LayerGlobal, "$.validation.reject_unknown_fields", "strict_validation_required", "global validation must reject unknown fields")
	}
	if !state.global.Validation.RejectEmptyStrings {
		state.add(adapterconfig.LayerGlobal, "$.validation.reject_empty_strings", "strict_validation_required", "global validation must reject empty strings")
	}
	if !state.global.Validation.RejectPlaceholderValues {
		state.add(adapterconfig.LayerGlobal, "$.validation.reject_placeholder_values", "strict_validation_required", "global validation must reject placeholder values")
	}
	if !state.global.Safety.RedactSecrets {
		state.add(adapterconfig.LayerGlobal, "$.safety.redact_secrets", "safety_policy_required", "global safety policy must redact secrets")
	}
	if state.global.Safety.SecretOutputPolicy != "block" {
		state.add(adapterconfig.LayerGlobal, "$.safety.secret_output_policy", "safety_policy_required", "global safety policy must block secret output")
	}
	if !state.global.Safety.MutationDetection {
		state.add(adapterconfig.LayerGlobal, "$.safety.mutation_detection", "safety_policy_required", "global safety policy must detect mutation")
	}
	if state.global.Trust.ProjectConfig != "trusted_base_only" {
		state.add(adapterconfig.LayerGlobal, "$.trust.project_config", "unsupported_project_config", "global project configuration must be limited to trusted-base proposals")
	}
	if state.global.Trust.ProjectPromptOverrides {
		state.add(adapterconfig.LayerGlobal, "$.trust.project_prompt_overrides", "unsupported_project_prompt_override", "project prompt overrides are not supported")
	}
	if state.global.Trust.ProjectPromptSource != "target_base" {
		state.add(adapterconfig.LayerGlobal, "$.trust.project_prompt_source", "unsupported_project_prompt_override", "project prompt source must remain target_base")
	}
	if state.global.Trust.AllowProjectProviderCommands {
		state.add(adapterconfig.LayerGlobal, "$.trust.allow_project_provider_commands", "project_executable_prohibited", "project provider commands are prohibited")
	}
	if state.global.Trust.AllowProjectShell {
		state.add(adapterconfig.LayerGlobal, "$.trust.allow_project_shell", "project_shell_prohibited", "project shell execution is prohibited")
	}
}

func (state *reductionState) validateProviders() {
	ids := make([]string, 0, len(state.global.Providers))
	for id := range state.global.Providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		provider := state.global.Providers[id]
		path := "$.providers." + id
		if !validProviderInstanceID(id) {
			state.add(adapterconfig.LayerGlobal, path, "invalid_provider", "provider ID must match [a-z][a-z0-9._-]{0,63}")
		}
		if !validConcurrencyKey(provider.ConcurrencyKey) {
			state.add(adapterconfig.LayerGlobal, path+".concurrency_key", "invalid_concurrency_key", "concurrency key must be canonical ASCII-lower and match [a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
		}
		switch provider.Driver {
		case "kimi", "zcode", "agy", "codex", "claude":
		default:
			state.add(adapterconfig.LayerGlobal, path+".driver", "invalid_provider", "provider driver is not supported")
		}
		optionalDefinition := provider.Optional != nil && *provider.Optional
		if provider.Status != "unverified" && !(optionalDefinition && provider.Status == "") {
			state.add(adapterconfig.LayerGlobal, path+".status", "provider_readiness_promotion", "configuration cannot promote provider readiness")
		}
		if !optionalDefinition && provider.Status == "" {
			state.add(adapterconfig.LayerGlobal, path+".status", "provider_status_required", "intended provider status must remain unverified")
		}
		if provider.Driver == "codex" || provider.Driver == "claude" {
			if provider.Optional == nil || !*provider.Optional {
				state.add(adapterconfig.LayerGlobal, path+".optional", "optional_provider_required", "codex and claude providers must be explicitly optional")
			}
		}
	}
}

func (state *reductionState) applyProject(project adapterconfig.ProjectConfig) {
	state.hasProject = true
	state.project = project.Project
	if !project.TrustedBase {
		state.add(adapterconfig.LayerProject, "$.trusted_base", "trusted_base_required", "project proposal must be read from a trusted base")
	}

	if project.Execution != nil && project.Execution.WorkspaceAccess != nil {
		projectAccess := WorkspaceAccess(*project.Execution.WorkspaceAccess)
		if !projectAccess.Valid() {
			state.add(adapterconfig.LayerProject, "$.execution.workspace_access", "invalid_workspace_access", "workspace access is outside the fixed lattice")
		} else if state.workspaceAccess.Valid() {
			if projectAccess.Rank() > state.workspaceAccess.Rank() {
				state.add(adapterconfig.LayerProject, "$.execution.workspace_access", "weakening_workspace", "project workspace access may only intersect or reduce global access")
			} else {
				intersection, _ := state.workspaceAccess.Intersect(projectAccess)
				state.workspaceAccess = intersection
				state.appendProvenance("policy.workspace_access", SourceProject)
			}
		}
	}

	if project.Review != nil {
		if project.Review.RequiredRoles != nil {
			state.appendProvenance("policy.required_roles", SourceProject)
			for role := range state.canonicalRoles(*project.Review.RequiredRoles, adapterconfig.LayerProject, "$.review.required_roles") {
				if _, alreadyRequired := state.required[role]; !alreadyRequired {
					state.projectAddedRequired[role] = struct{}{}
				}
				state.required[role] = struct{}{}
				state.appendProvenance("policy.roles."+string(role)+".required", SourceProject)
			}
		}
		if project.Review.RequestChangesOn != nil {
			projectClosure := state.canonicalSeverityClosure(*project.Review.RequestChangesOn, adapterconfig.LayerProject, "$.review.request_changes_on")
			if len(projectClosure) != 0 && len(state.requestChangesOn) != 0 {
				if severityRank(projectClosure[0]) > severityRank(state.requestChangesOn[0]) {
					state.add(adapterconfig.LayerProject, "$.review.request_changes_on", "weakening_threshold", "project request-changes threshold must be at least as strict as global policy")
				} else {
					state.requestChangesOn = projectClosure
					state.appendProvenance("policy.request_changes_on", SourceProject)
				}
			}
		}
	}

	state.applyProjectRoles(project.Roles)

	if project.Validation != nil && project.Validation.Evidence != nil && project.Validation.Evidence.RequireVerifiedFor != nil {
		projectSet := state.canonicalSeveritySet(*project.Validation.Evidence.RequireVerifiedFor, adapterconfig.LayerProject, "$.validation.evidence.require_verified_for")
		for _, severity := range projectSet {
			if !containsSeverity(state.requireVerifiedFor, severity) {
				state.requireVerifiedFor = append(state.requireVerifiedFor, severity)
			}
		}
		state.requireVerifiedFor = sortSeverities(state.requireVerifiedFor)
		state.appendProvenance("policy.require_verified_for", SourceProject)
	}

	if project.Resources != nil {
		if project.Resources.RoleMaxInvocations != nil {
			value := *project.Resources.RoleMaxInvocations
			if value <= 0 {
				state.add(adapterconfig.LayerProject, "$.resources.role_max_invocations", "invalid_limit", "role invocation limit must be positive")
			} else if value > state.roleMaxInvocations {
				state.add(adapterconfig.LayerProject, "$.resources.role_max_invocations", "weakening_limit", "project role invocation limit may only decrease")
			} else {
				state.roleMaxInvocations = value
				state.appendProvenance("policy.role_max_invocations", SourceProject)
			}
		}
		if project.Resources.RunMaxInvocations != nil {
			value := *project.Resources.RunMaxInvocations
			if value <= 0 {
				state.add(adapterconfig.LayerProject, "$.resources.run_max_invocations", "invalid_limit", "run invocation limit must be positive")
			} else if value > state.runMaxInvocations {
				state.add(adapterconfig.LayerProject, "$.resources.run_max_invocations", "weakening_limit", "project run invocation limit may only decrease")
			} else {
				state.runMaxInvocations = value
				state.appendProvenance("policy.run_max_invocations", SourceProject)
			}
		}
		if project.Resources.RunTotalOutputCap != nil {
			value, err := ParseOutputCap(*project.Resources.RunTotalOutputCap)
			if err != nil {
				state.add(adapterconfig.LayerProject, "$.resources.run_total_output_cap", "invalid_limit", err.Error())
			} else if value > state.runTotalOutputCapBytes {
				state.add(adapterconfig.LayerProject, "$.resources.run_total_output_cap", "weakening_limit", "project output cap may only decrease")
			} else {
				state.runTotalOutputCapBytes = value
				state.appendProvenance("policy.run_total_output_cap_bytes", SourceProject)
			}
		}
	}

	if project.CI != nil {
		if project.CI.FailOnSeverity != nil {
			projectClosure := state.canonicalSeverityClosure(*project.CI.FailOnSeverity, adapterconfig.LayerProject, "$.ci.fail_on_severity")
			if len(projectClosure) != 0 && len(state.ciFailOnSeverity) != 0 {
				if severityRank(projectClosure[0]) > severityRank(state.ciFailOnSeverity[0]) {
					state.add(adapterconfig.LayerProject, "$.ci.fail_on_severity", "weakening_threshold", "project CI failure threshold must be at least as strict as global policy")
				} else {
					state.ciFailOnSeverity = projectClosure
					state.appendProvenance("policy.ci_fail_on_severity", SourceProject)
				}
			}
		}
		if project.CI.DegradedReviewFails != nil {
			if !*project.CI.DegradedReviewFails {
				state.add(adapterconfig.LayerProject, "$.ci.degraded_review_fails", "weakening_value", "project CI enforcement may only be set to true")
			} else {
				state.appendProvenance("policy.degraded_review_fails", SourceProject)
			}
		}
	}
}

func (state *reductionState) applyProjectRoles(roles *adapterconfig.ProjectRolesConfig) {
	if roles == nil {
		return
	}
	for _, entry := range []struct {
		role     domain.Role
		proposal *adapterconfig.ProjectRoleConfig
	}{
		{domain.RoleLogic, roles.Logic},
		{domain.RoleSecurity, roles.Security},
		{domain.RoleMaintainability, roles.Maintainability},
		{domain.RoleProduct, roles.Product},
		{domain.RoleDocumentation, roles.Documentation},
		{domain.RoleTesting, roles.Testing},
	} {
		if entry.proposal == nil {
			continue
		}
		path := "$.roles." + string(entry.role)
		current := state.roles[entry.role]
		if entry.proposal.Enabled != nil {
			if !*entry.proposal.Enabled {
				state.add(adapterconfig.LayerProject, path+".enabled", "weakening_value", "project roles may not be disabled")
			} else {
				current.enabled = true
				state.appendProvenance("policy.roles."+string(entry.role)+".enabled", SourceProject)
			}
		}
		if entry.proposal.Guide != nil && *entry.proposal.Guide != builtinRoleGuide(entry.role) {
			state.add(adapterconfig.LayerProject, path+".guide", "unsupported_guide_override", "project role guides may only restate the built-in guide")
		}
		state.roles[entry.role] = current
	}
}

func (state *reductionState) validateRequiredRoles(requiredRoles map[domain.Role]struct{}, layer adapterconfig.Layer, path string) {
	for _, role := range domain.FixedRoleOrder() {
		if _, required := requiredRoles[role]; !required {
			continue
		}
		if state.roles[role].enabled {
			continue
		}
		state.add(layer, path, "required_role_disabled", "required roles must be enabled")
	}
}

func (state *reductionState) canonicalRoles(values []string, layer adapterconfig.Layer, path string) map[domain.Role]struct{} {
	roles := make(map[domain.Role]struct{}, len(values))
	for index, value := range values {
		role := domain.Role(value)
		entryPath := fmt.Sprintf("%s[%d]", path, index)
		if !role.Valid() {
			state.add(layer, entryPath, "invalid_role", "role is not in the fixed role set")
			continue
		}
		if _, exists := roles[role]; exists {
			state.add(layer, entryPath, "duplicate_value", "role must not be duplicated")
			continue
		}
		roles[role] = struct{}{}
	}
	return roles
}

func (state *reductionState) canonicalSeveritySet(values []string, layer adapterconfig.Layer, path string) []domain.Severity {
	severities := make([]domain.Severity, 0, len(values))
	seen := make(map[domain.Severity]struct{}, len(values))
	for index, value := range values {
		severity := domain.Severity(value)
		entryPath := fmt.Sprintf("%s[%d]", path, index)
		if !severity.Valid() {
			state.add(layer, entryPath, "invalid_severity", "severity is outside the fixed severity lattice")
			continue
		}
		if _, exists := seen[severity]; exists {
			state.add(layer, entryPath, "duplicate_value", "severity must not be duplicated")
			continue
		}
		seen[severity] = struct{}{}
		severities = append(severities, severity)
	}
	return sortSeverities(severities)
}

func (state *reductionState) canonicalSeverityClosure(values []string, layer adapterconfig.Layer, path string) []domain.Severity {
	severities := state.canonicalSeveritySet(values, layer, path)
	if len(severities) == 0 {
		state.add(layer, path, "invalid_threshold", "severity threshold must be a nonempty canonical upward closure")
		return nil
	}
	thresholdRank := severityRank(severities[0])
	expected := FixedSeverityOrder()[thresholdRank:]
	if len(values) != len(expected) {
		state.add(layer, path, "non_canonical_closure", "severity list must include every severity at or above its threshold")
		return nil
	}
	for index := range expected {
		if values[index] != string(expected[index]) {
			state.add(layer, path, "non_canonical_closure", "severity list must be in fixed severity order")
			return nil
		}
	}
	return expected
}

func (state *reductionState) add(layer adapterconfig.Layer, path, code, message string) {
	state.diagnostics = append(state.diagnostics, ReductionDiagnostic{
		Layer:   layer,
		Path:    path,
		Code:    code,
		Message: message,
	})
}

func (state *reductionState) setProvenance(field string, sources ...FieldSource) {
	state.provenance[field] = nil
	for _, source := range sources {
		state.appendProvenance(field, source)
	}
}

func (state *reductionState) appendProvenance(field string, source FieldSource) {
	for _, existing := range state.provenance[field] {
		if existing == source {
			return
		}
	}
	state.provenance[field] = append(state.provenance[field], source)
}

func (state *reductionState) freeze() ResolvedConfig {
	requiredRoles := make([]domain.Role, 0, len(state.required))
	for _, role := range domain.FixedRoleOrder() {
		if _, required := state.required[role]; required {
			requiredRoles = append(requiredRoles, role)
		}
	}

	roles := make(map[domain.Role]ResolvedRole, len(state.roles))
	for role, resolvedRole := range state.roles {
		roles[role] = resolvedRole
	}

	fields := make([]string, 0, len(state.provenance))
	for field := range state.provenance {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	entries := make([]ProvenanceEntry, 0, len(fields))
	for _, field := range fields {
		entries = append(entries, ProvenanceEntry{
			Field:   field,
			Sources: append([]FieldSource(nil), state.provenance[field]...),
		})
	}

	return ResolvedConfig{
		global:                 cloneGlobal(state.global),
		project:                state.project,
		hasProject:             state.hasProject,
		roles:                  roles,
		requiredRoles:          requiredRoles,
		workspaceAccess:        state.workspaceAccess,
		requestChangesOn:       append([]domain.Severity(nil), state.requestChangesOn...),
		requireVerifiedFor:     append([]domain.Severity(nil), state.requireVerifiedFor...),
		roleMaxInvocations:     state.roleMaxInvocations,
		runMaxInvocations:      state.runMaxInvocations,
		runTotalOutputCapBytes: state.runTotalOutputCapBytes,
		ciFailOnSeverity:       append([]domain.Severity(nil), state.ciFailOnSeverity...),
		degradedReviewFails:    state.degradedReviewFails,
		provenance:             FieldProvenance{entries: entries},
	}
}

func globalRoleEnabled(roles adapterconfig.RolesConfig, role domain.Role) bool {
	switch role {
	case domain.RoleLogic:
		return roles.Logic.Enabled
	case domain.RoleSecurity:
		return roles.Security.Enabled
	case domain.RoleMaintainability:
		return roles.Maintainability.Enabled
	case domain.RoleProduct:
		return roles.Product.Enabled
	case domain.RoleDocumentation:
		return roles.Documentation.Enabled
	case domain.RoleTesting:
		return roles.Testing.Enabled
	default:
		return false
	}
}

func builtinRoleGuide(role domain.Role) string {
	return "builtin:roles/" + string(role) + "@1"
}

func validProviderInstanceID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
func validConcurrencyKey(value string) bool {
	if len(value) == 0 || len(value) > 64 || !asciiAlphaNumeric(value[0]) || !asciiAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')
}

func containsSeverity(severities []domain.Severity, target domain.Severity) bool {
	for _, severity := range severities {
		if severity == target {
			return true
		}
	}
	return false
}
func containsAllSeverities(values, required []domain.Severity) bool {
	for _, severity := range required {
		if !containsSeverity(values, severity) {
			return false
		}
	}
	return true
}

func sortSeverities(severities []domain.Severity) []domain.Severity {
	sorted := append([]domain.Severity(nil), severities...)
	sort.Slice(sorted, func(left, right int) bool {
		return severityRank(sorted[left]) < severityRank(sorted[right])
	})
	return sorted
}

func severityRank(severity domain.Severity) int { return severity.Rank() }

func cloneGlobal(input adapterconfig.GlobalConfig) adapterconfig.GlobalConfig {
	output := input
	output.Runtime = cloneRuntime(input.Runtime)
	output.Providers = cloneProviders(input.Providers)
	output.Review.RequestChangesOn = append([]string(nil), input.Review.RequestChangesOn...)
	output.Validation.Evidence.RequireVerifiedFor = append([]string(nil), input.Validation.Evidence.RequireVerifiedFor...)
	output.Trust.RequiredRoles = append([]string(nil), input.Trust.RequiredRoles...)
	output.CI.FailOnSeverity = append([]string(nil), input.CI.FailOnSeverity...)
	return output
}

func cloneRuntime(input adapterconfig.RuntimeConfig) adapterconfig.RuntimeConfig {
	output := input
	output.Path.Prepend = append([]string(nil), input.Path.Prepend...)
	output.Path.Append = append([]string(nil), input.Path.Append...)
	output.EnvAllowlist = append([]string(nil), input.EnvAllowlist...)
	return output
}

func cloneProviders(input adapterconfig.ProvidersConfig) map[string]adapterconfig.ProviderConfig {
	if input == nil {
		return nil
	}
	output := make(map[string]adapterconfig.ProviderConfig, len(input))
	for id, provider := range input {
		output[id] = cloneProvider(provider)
	}
	return output
}

func cloneProvider(input adapterconfig.ProviderConfig) adapterconfig.ProviderConfig {
	output := input
	output.Args = append([]string(nil), input.Args...)
	if input.Optional != nil {
		optional := *input.Optional
		output.Optional = &optional
	}
	return output
}
