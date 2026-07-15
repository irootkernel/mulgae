package config

import (
	"sort"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// RedactedConfig is a deterministic JSON/YAML-safe projection of resolved
// policy. It deliberately contains no runtime paths, provider command details,
// provider arguments, guides, project paths, or secret-like values.
type RedactedConfig struct {
	Providers  []RedactedProvider   `json:"providers" yaml:"providers"`
	Policy     RedactedPolicy       `json:"policy" yaml:"policy"`
	Provenance []RedactedProvenance `json:"provenance" yaml:"provenance"`
}

// RedactedProvider retains only non-executable provider identity and policy
// state. Optional is false when the global definition omitted the field.
type RedactedProvider struct {
	ID             string `json:"id" yaml:"id"`
	Driver         string `json:"driver" yaml:"driver"`
	Status         string `json:"status" yaml:"status"`
	Optional       bool   `json:"optional" yaml:"optional"`
	ConcurrencyKey string `json:"concurrency_key" yaml:"concurrency_key"`
}

// RedactedPolicy contains the effective trust-reduced policy fields that are
// safe to persist with a run artifact.
type RedactedPolicy struct {
	Roles                  []RedactedRole    `json:"roles" yaml:"roles"`
	RequiredRoles          []domain.Role     `json:"required_roles" yaml:"required_roles"`
	WorkspaceAccess        WorkspaceAccess   `json:"workspace_access" yaml:"workspace_access"`
	RequestChangesOn       []domain.Severity `json:"request_changes_on" yaml:"request_changes_on"`
	RequireVerifiedFor     []domain.Severity `json:"require_verified_for" yaml:"require_verified_for"`
	RoleMaxInvocations     int               `json:"role_max_invocations" yaml:"role_max_invocations"`
	RunMaxInvocations      int               `json:"run_max_invocations" yaml:"run_max_invocations"`
	RunTotalOutputCapBytes int64             `json:"run_total_output_cap_bytes" yaml:"run_total_output_cap_bytes"`
	CIFailOnSeverity       []domain.Severity `json:"ci_fail_on_severity" yaml:"ci_fail_on_severity"`
	DegradedReviewFails    bool              `json:"degraded_review_fails" yaml:"degraded_review_fails"`
}

// RedactedRole is the safe role policy projection. Guide references are omitted
// because they are non-policy prompt assets.
type RedactedRole struct {
	Role     domain.Role `json:"role" yaml:"role"`
	Enabled  bool        `json:"enabled" yaml:"enabled"`
	Required bool        `json:"required" yaml:"required"`
}

// RedactedProvenance records policy source layers without exposing raw
// configuration paths or values.
type RedactedProvenance struct {
	Field   string        `json:"field" yaml:"field"`
	Sources []FieldSource `json:"sources" yaml:"sources"`
}

// Redact builds a deterministic, safe persistence view. Its slices are newly
// allocated and may be freely marshaled or changed without mutating resolved
// policy.
func Redact(resolved ResolvedConfig) RedactedConfig {
	providers := resolved.Providers()
	providerIDs := make([]string, 0, len(providers))
	for id := range providers {
		providerIDs = append(providerIDs, id)
	}
	sort.Strings(providerIDs)

	redactedProviders := make([]RedactedProvider, 0, len(providerIDs))
	for _, id := range providerIDs {
		provider := providers[id]
		optional := provider.Optional != nil && *provider.Optional
		redactedProviders = append(redactedProviders, RedactedProvider{
			ID:             id,
			Driver:         provider.Driver,
			Status:         provider.Status,
			Optional:       optional,
			ConcurrencyKey: provider.ConcurrencyKey,
		})
	}

	required := make(map[domain.Role]struct{}, len(resolved.RequiredRoles()))
	for _, role := range resolved.RequiredRoles() {
		required[role] = struct{}{}
	}
	roles := make([]RedactedRole, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		resolvedRole, exists := resolved.Role(role)
		if !exists {
			continue
		}
		_, isRequired := required[role]
		roles = append(roles, RedactedRole{
			Role:     role,
			Enabled:  resolvedRole.Enabled(),
			Required: isRequired,
		})
	}

	provenanceEntries := resolved.Provenance().Entries()
	provenance := make([]RedactedProvenance, 0, len(provenanceEntries))
	for _, entry := range provenanceEntries {
		if !safeProvenanceField(entry.Field) {
			continue
		}
		provenance = append(provenance, RedactedProvenance{
			Field:   entry.Field,
			Sources: append([]FieldSource(nil), entry.Sources...),
		})
	}

	return RedactedConfig{
		Providers: redactedProviders,
		Policy: RedactedPolicy{
			Roles:                  roles,
			RequiredRoles:          resolved.RequiredRoles(),
			WorkspaceAccess:        resolved.WorkspaceAccess(),
			RequestChangesOn:       resolved.RequestChangesOn(),
			RequireVerifiedFor:     resolved.RequireVerifiedFor(),
			RoleMaxInvocations:     resolved.RoleMaxInvocations(),
			RunMaxInvocations:      resolved.RunMaxInvocations(),
			RunTotalOutputCapBytes: resolved.RunTotalOutputCapBytes(),
			CIFailOnSeverity:       resolved.CIFailOnSeverity(),
			DegradedReviewFails:    resolved.DegradedReviewFails(),
		},
		Provenance: provenance,
	}
}

// Redacted returns the deterministic safe persistence view for this result.
func (resolved ResolvedConfig) Redacted() RedactedConfig {
	return Redact(resolved)
}

func safeProvenanceField(field string) bool {
	switch field {
	case "policy.required_roles",
		"policy.workspace_access",
		"policy.request_changes_on",
		"policy.require_verified_for",
		"policy.role_max_invocations",
		"policy.run_max_invocations",
		"policy.run_total_output_cap_bytes",
		"policy.ci_fail_on_severity",
		"policy.degraded_review_fails":
		return true
	}

	if strings.HasPrefix(field, "policy.roles.") {
		parts := strings.Split(field, ".")
		return len(parts) == 4 &&
			domain.Role(parts[2]).Valid() &&
			(parts[3] == "enabled" || parts[3] == "required")
	}

	if !strings.HasPrefix(field, "providers.") {
		return false
	}
	remainder := strings.TrimPrefix(field, "providers.")
	separator := strings.LastIndex(remainder, ".")
	if separator <= 0 || !validProviderInstanceID(remainder[:separator]) {
		return false
	}
	switch remainder[separator+1:] {
	case "id", "driver", "status", "optional", "concurrency_key":
		return true
	default:
		return false
	}
}
