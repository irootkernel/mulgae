// Package config admits one project-local configuration and projects the fixed
// runtime policy consumed by review composition.
package config

import (
	"fmt"
	"github.com/irootkernel/mulgae/internal/domain"
	"time"
)

type WorkspaceAccess string

const (
	WorkspaceNone             WorkspaceAccess = "none"
	WorkspaceReadonlySnapshot WorkspaceAccess = "readonly_snapshot"
)

func (access WorkspaceAccess) Valid() bool {
	return access == WorkspaceNone || access == WorkspaceReadonlySnapshot
}

type ResolvedRole struct {
	enabled          bool
	primaryProvider  string
	fallbackProvider string
}

func (role ResolvedRole) Enabled() bool           { return role.enabled }
func (role ResolvedRole) PrimaryProvider() string { return role.primaryProvider }
func (role ResolvedRole) FallbackProvider() (string, bool) {
	return role.fallbackProvider, role.fallbackProvider != ""
}

type RuntimePolicy struct{ MaxActiveLanes int }

type ResolvedConfig struct {
	raw                    Config
	roles                  map[domain.Role]ResolvedRole
	requiredRoles          []domain.Role
	requestChangesOn       []domain.Severity
	requireVerifiedFor     []domain.Severity
	ciFailOnSeverity       []domain.Severity
	runTotalOutputCapBytes int64
	providerTimeouts       map[string]time.Duration
}

func ResolveConfiguration(raw Config) (ResolvedConfig, error) {
	capBytes, err := RunTotalOutputCapBytes(raw)
	if err != nil {
		return ResolvedConfig{}, fmt.Errorf("resolve configuration: output cap: %w", err)
	}
	providerTimeouts := make(map[string]time.Duration, raw.Providers.Count())
	for _, family := range raw.Providers.Families() {
		timeout, timeoutErr := ParseProviderTimeout(configuredProviderTimeout(raw.Providers, family))
		if timeoutErr != nil {
			return ResolvedConfig{}, fmt.Errorf("resolve configuration: %s timeout: %w", family, timeoutErr)
		}
		providerTimeouts[family] = timeout
	}
	roles := make(map[domain.Role]ResolvedRole, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		configured := configuredRole(raw.Roles, role)
		roles[role] = ResolvedRole{enabled: configured.Enabled, primaryProvider: configured.PrimaryProvider, fallbackProvider: configured.FallbackProvider}
	}
	return ResolvedConfig{
		raw: cloneConfig(raw), roles: roles,
		requiredRoles:          parseRoles(raw.Review.RequiredRoles),
		requestChangesOn:       parseSeverities(raw.Review.RequestChangesOn),
		requireVerifiedFor:     parseSeverities(raw.Validation.Evidence.RequireVerifiedFor),
		ciFailOnSeverity:       parseSeverities(raw.CI.FailOnSeverity),
		runTotalOutputCapBytes: capBytes,
		providerTimeouts:       providerTimeouts,
	}, nil
}

func configuredProviderTimeout(providers ProvidersConfig, family string) string {
	switch family {
	case "kimi":
		if providers.Kimi != nil {
			return providers.Kimi.Timeout
		}
	case "zcode":
		if providers.ZCode != nil {
			return providers.ZCode.Timeout
		}
	case "agy":
		if providers.AGY != nil {
			return providers.AGY.Timeout
		}
	}
	return ""
}

func configuredRole(roles RolesConfig, role domain.Role) RoleConfig {
	switch role {
	case domain.RoleLogic:
		return roles.Logic
	case domain.RoleSecurity:
		return roles.Security
	case domain.RoleMaintainability:
		return roles.Maintainability
	case domain.RoleProduct:
		return roles.Product
	case domain.RoleDocumentation:
		return roles.Documentation
	case domain.RoleTesting:
		return roles.Testing
	case domain.RoleArtist:
		return roles.Artist
	default:
		return RoleConfig{}
	}
}

func (resolved ResolvedConfig) Raw() Config { return cloneConfig(resolved.raw) }
func (resolved ResolvedConfig) Runtime() RuntimePolicy {
	return RuntimePolicy{MaxActiveLanes: resolved.raw.Resources.MaxActiveLanes}
}
func (resolved ResolvedConfig) Providers() ProvidersConfig {
	return cloneConfig(resolved.raw).Providers
}

// ProviderTimeout returns the effective timeout for a configured provider
// family. The boolean is false for an absent or unknown family.
func (resolved ResolvedConfig) ProviderTimeout(family string) (time.Duration, bool) {
	timeout, ok := resolved.providerTimeouts[family]
	return timeout, ok
}
func (resolved ResolvedConfig) Role(role domain.Role) (ResolvedRole, bool) {
	value, ok := resolved.roles[role]
	return value, ok
}
func (resolved ResolvedConfig) RequiredRoles() []domain.Role {
	return append([]domain.Role(nil), resolved.requiredRoles...)
}
func (resolved ResolvedConfig) WorkspaceAccess() WorkspaceAccess {
	return WorkspaceAccess(resolved.raw.Execution.WorkspaceAccess)
}
func (resolved ResolvedConfig) RequestChangesOn() []domain.Severity {
	return append([]domain.Severity(nil), resolved.requestChangesOn...)
}
func (resolved ResolvedConfig) RequireVerifiedFor() []domain.Severity {
	return append([]domain.Severity(nil), resolved.requireVerifiedFor...)
}
func (resolved ResolvedConfig) RoleMaxInvocations() int {
	return resolved.raw.Resources.RoleMaxInvocations
}
func (resolved ResolvedConfig) RunMaxInvocations() int {
	return resolved.raw.Resources.RunMaxInvocations
}
func (resolved ResolvedConfig) RunTotalOutputCapBytes() int64 { return resolved.runTotalOutputCapBytes }
func (resolved ResolvedConfig) CIFailOnSeverity() []domain.Severity {
	return append([]domain.Severity(nil), resolved.ciFailOnSeverity...)
}
func (resolved ResolvedConfig) DegradedReviewFails() bool { return resolved.raw.CI.DegradedReviewFails }

func parseRoles(values []string) []domain.Role {
	result := make([]domain.Role, len(values))
	for index, value := range values {
		result[index] = domain.Role(value)
	}
	return result
}
func parseSeverities(values []string) []domain.Severity {
	result := make([]domain.Severity, len(values))
	for index, value := range values {
		result[index] = domain.Severity(value)
	}
	return result
}

func cloneConfig(value Config) Config {
	copyValue := value
	if value.Providers.Kimi != nil {
		provider := *value.Providers.Kimi
		copyValue.Providers.Kimi = &provider
	}
	if value.Providers.ZCode != nil {
		provider := *value.Providers.ZCode
		copyValue.Providers.ZCode = &provider
	}
	if value.Providers.AGY != nil {
		provider := *value.Providers.AGY
		copyValue.Providers.AGY = &provider
	}
	copyValue.Review.RequiredRoles = append([]string(nil), value.Review.RequiredRoles...)
	copyValue.Review.RequestChangesOn = append([]string(nil), value.Review.RequestChangesOn...)
	copyValue.Validation.Evidence.RequireVerifiedFor = append([]string(nil), value.Validation.Evidence.RequireVerifiedFor...)
	copyValue.CI.FailOnSeverity = append([]string(nil), value.CI.FailOnSeverity...)
	if value.Roles.Artist.Inputs != nil {
		inputs := *value.Roles.Artist.Inputs
		inputs.DesignSpecGlobs = append([]string(nil), value.Roles.Artist.Inputs.DesignSpecGlobs...)
		copyValue.Roles.Artist.Inputs = &inputs
	}
	return copyValue
}
