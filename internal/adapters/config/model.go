package config

import (
	"time"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
)

type Config = appconfig.Config
type ProjectConfig = appconfig.ProjectConfig
type NativeUserConfig = appconfig.NativeUserConfig
type ProvidersConfig = appconfig.ProvidersConfig
type KimiProviderConfig = appconfig.KimiProviderConfig
type ZCodeProviderConfig = appconfig.ZCodeProviderConfig
type AGYProviderConfig = appconfig.AGYProviderConfig
type CodexProviderConfig = appconfig.CodexProviderConfig
type CodexCredentialHomeConfig = appconfig.CodexCredentialHomeConfig
type ExecutionConfig = appconfig.ExecutionConfig
type RolesConfig = appconfig.RolesConfig
type RoleConfig = appconfig.RoleConfig
type ArtistInputsConfig = appconfig.ArtistInputsConfig
type RoleDefaults = appconfig.RoleDefaults
type RoleDefault = appconfig.RoleDefault
type ReviewConfig = appconfig.ReviewConfig
type ValidationConfig = appconfig.ValidationConfig
type EvidenceConfig = appconfig.EvidenceConfig
type RepairConfig = appconfig.RepairConfig
type ExtractionConfig = appconfig.ExtractionConfig
type ResourcesConfig = appconfig.ResourcesConfig
type CIConfig = appconfig.CIConfig

const (
	ConfigVersion             = appconfig.ConfigVersion
	DefaultKimiModel          = appconfig.DefaultKimiModel
	DefaultAGYPermissionMode  = appconfig.DefaultAGYPermissionMode
	SafeAGYPermissionMode     = appconfig.SafeAGYPermissionMode
	HeadlessAGYPermissionMode = appconfig.HeadlessAGYPermissionMode
	DefaultProviderTimeout    = appconfig.DefaultProviderTimeout
	MinimumProviderTimeout    = appconfig.MinimumProviderTimeout
	MaximumProviderTimeout    = appconfig.MaximumProviderTimeout
	ConfigRelativePath        = appconfig.ConfigRelativePath
	LocalConfigRelativePath   = appconfig.LocalConfigRelativePath
	MaximumConfigBytes        = appconfig.MaximumConfigBytes
	ProjectKindNonUI          = appconfig.ProjectKindNonUI
	ProjectKindUI             = appconfig.ProjectKindUI
)

func DefaultKimiDataHome(nativeHome string) string { return appconfig.DefaultKimiDataHome(nativeHome) }
func ParseProviderTimeout(value string) (time.Duration, error) {
	return appconfig.ParseProviderTimeout(value)
}
func ProviderTimeoutText(timeout time.Duration) string { return appconfig.ProviderTimeoutText(timeout) }
func CanonicalRolesConfig(defaults RoleDefaults, families []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfig(defaults, families)
}
func CanonicalRolesConfigForSelection(defaults RoleDefaults, families, roles []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfigForSelection(defaults, families, roles)
}
func CanonicalRolesConfigForUI(defaults RoleDefaults, families []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfigForUI(defaults, families)
}
