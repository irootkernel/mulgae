package config

import appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"

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
type ReviewConfig = appconfig.ReviewConfig
type ValidationConfig = appconfig.ValidationConfig
type EvidenceConfig = appconfig.EvidenceConfig
type RepairConfig = appconfig.RepairConfig
type ResourcesConfig = appconfig.ResourcesConfig
type CIConfig = appconfig.CIConfig

const (
	DefaultKimiModel         = appconfig.DefaultKimiModel
	DefaultAGYPermissionMode = appconfig.DefaultAGYPermissionMode
	ConfigRelativePath       = appconfig.ConfigRelativePath
	MaximumConfigBytes       = appconfig.MaximumConfigBytes
)

func DefaultKimiDataHome(nativeHome string) string { return appconfig.DefaultKimiDataHome(nativeHome) }
