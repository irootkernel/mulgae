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
type ExecutionConfig = appconfig.ExecutionConfig
type RolesConfig = appconfig.RolesConfig
type RoleConfig = appconfig.RoleConfig
type ArtistInputsConfig = appconfig.ArtistInputsConfig
type ReviewConfig = appconfig.ReviewConfig
type ValidationConfig = appconfig.ValidationConfig
type EvidenceConfig = appconfig.EvidenceConfig
type RepairConfig = appconfig.RepairConfig
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
	MaximumConfigBytes        = appconfig.MaximumConfigBytes
	ProjectKindNonUI          = appconfig.ProjectKindNonUI
	ProjectKindUI             = appconfig.ProjectKindUI
	DefaultArtistBriefPath    = appconfig.DefaultArtistBriefPath
)

var DefaultArtistDesignSpecGlobs = append([]string(nil), appconfig.DefaultArtistDesignSpecGlobs...)

func DefaultKimiDataHome(nativeHome string) string { return appconfig.DefaultKimiDataHome(nativeHome) }
func ParseProviderTimeout(value string) (time.Duration, error) {
	return appconfig.ParseProviderTimeout(value)
}
func ProviderTimeoutText(timeout time.Duration) string { return appconfig.ProviderTimeoutText(timeout) }
func CanonicalRolesConfig(families []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfig(families)
}
func CanonicalRolesConfigForSelection(families, roles []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfigForSelection(families, roles)
}
func CanonicalRolesConfigForUI(families []string) (RolesConfig, error) {
	return appconfig.CanonicalRolesConfigForUI(families)
}
