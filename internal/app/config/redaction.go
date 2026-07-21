package config

import "github.com/irootkernel/kkachi-agent-review/internal/domain"

type RedactedConfig struct {
	ConfiguredProviderIDs []string       `json:"configured_provider_ids" yaml:"configured_provider_ids"`
	Policy                RedactedPolicy `json:"policy" yaml:"policy"`
}
type RedactedPolicy struct {
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

func Redact(resolved ResolvedConfig) RedactedConfig {
	return RedactedConfig{ConfiguredProviderIDs: resolved.raw.Providers.Families(), Policy: RedactedPolicy{RequiredRoles: resolved.RequiredRoles(), WorkspaceAccess: resolved.WorkspaceAccess(), RequestChangesOn: resolved.RequestChangesOn(), RequireVerifiedFor: resolved.RequireVerifiedFor(), RoleMaxInvocations: resolved.RoleMaxInvocations(), RunMaxInvocations: resolved.RunMaxInvocations(), RunTotalOutputCapBytes: resolved.RunTotalOutputCapBytes(), CIFailOnSeverity: resolved.CIFailOnSeverity(), DegradedReviewFails: resolved.DegradedReviewFails()}}
}
func (resolved ResolvedConfig) Redacted() RedactedConfig { return Redact(resolved) }
