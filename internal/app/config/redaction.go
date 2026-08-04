package config

import "github.com/irootkernel/mulgae/internal/domain"

type RedactedConfig struct {
	ConfiguredProviderIDs []string       `json:"configured_provider_ids" yaml:"configured_provider_ids"`
	Policy                RedactedPolicy `json:"policy" yaml:"policy"`
}
type RedactedPolicy struct {
	RoleAssignments        []RedactedRoleAssignment  `json:"role_assignments" yaml:"role_assignments"`
	ProviderTimeouts       []RedactedProviderTimeout `json:"provider_timeouts" yaml:"provider_timeouts"`
	AGYPermissionMode      string                    `json:"agy_permission_mode,omitempty" yaml:"agy_permission_mode,omitempty"`
	Warnings               []string                  `json:"warnings" yaml:"warnings"`
	RequiredRoles          []domain.Role             `json:"required_roles" yaml:"required_roles"`
	WorkspaceAccess        WorkspaceAccess           `json:"workspace_access" yaml:"workspace_access"`
	RequestChangesOn       []domain.Severity         `json:"request_changes_on" yaml:"request_changes_on"`
	RequireVerifiedFor     []domain.Severity         `json:"require_verified_for" yaml:"require_verified_for"`
	RoleMaxInvocations     int                       `json:"role_max_invocations" yaml:"role_max_invocations"`
	RunMaxInvocations      int                       `json:"run_max_invocations" yaml:"run_max_invocations"`
	RunTotalOutputCapBytes int64                     `json:"run_total_output_cap_bytes" yaml:"run_total_output_cap_bytes"`
	CIFailOnSeverity       []domain.Severity         `json:"ci_fail_on_severity" yaml:"ci_fail_on_severity"`
	DegradedReviewFails    bool                      `json:"degraded_review_fails" yaml:"degraded_review_fails"`
}
type RedactedProviderTimeout struct {
	Family  string `json:"family" yaml:"family"`
	Timeout string `json:"timeout" yaml:"timeout"`
}
type RedactedRoleAssignment struct {
	Role             domain.Role `json:"role" yaml:"role"`
	PrimaryProvider  string      `json:"primary_provider" yaml:"primary_provider"`
	FallbackProvider *string     `json:"fallback_provider" yaml:"fallback_provider"`
}

func Redact(resolved ResolvedConfig) RedactedConfig {
	assignments := make([]RedactedRoleAssignment, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		resolvedRole, ok := resolved.Role(role)
		if !ok {
			continue
		}
		var fallback *string
		if value, present := resolvedRole.FallbackProvider(); present {
			copy := value
			fallback = &copy
		}
		assignments = append(assignments, RedactedRoleAssignment{Role: role, PrimaryProvider: resolvedRole.PrimaryProvider(), FallbackProvider: fallback})
	}
	timeouts := make([]RedactedProviderTimeout, 0, resolved.raw.Providers.Count())
	for _, family := range resolved.raw.Providers.Families() {
		if timeout, ok := resolved.ProviderTimeout(family); ok {
			timeouts = append(timeouts, RedactedProviderTimeout{Family: family, Timeout: ProviderTimeoutText(timeout)})
		}
	}
	agyPermissionMode := ""
	warnings := []string{}
	if resolved.raw.Providers.AGY != nil {
		agyPermissionMode = resolved.raw.Providers.AGY.PermissionMode
		if agyPermissionMode == SafeAGYPermissionMode {
			warnings = append(warnings, "AGY safe permission mode is opt-in; headless tool requests may be denied")
		}
	}
	return RedactedConfig{ConfiguredProviderIDs: resolved.raw.Providers.Families(), Policy: RedactedPolicy{RoleAssignments: assignments, ProviderTimeouts: timeouts, AGYPermissionMode: agyPermissionMode, Warnings: warnings, RequiredRoles: resolved.RequiredRoles(), WorkspaceAccess: resolved.WorkspaceAccess(), RequestChangesOn: resolved.RequestChangesOn(), RequireVerifiedFor: resolved.RequireVerifiedFor(), RoleMaxInvocations: resolved.RoleMaxInvocations(), RunMaxInvocations: resolved.RunMaxInvocations(), RunTotalOutputCapBytes: resolved.RunTotalOutputCapBytes(), CIFailOnSeverity: resolved.CIFailOnSeverity(), DegradedReviewFails: resolved.DegradedReviewFails()}}
}
func (resolved ResolvedConfig) Redacted() RedactedConfig { return Redact(resolved) }
