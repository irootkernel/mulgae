package config

// GlobalConfig is the complete global trusted-base proposal. The YAML schema
// verifies required policy sections and leaves before this value is decoded.
type GlobalConfig struct {
	Version    int              `yaml:"version"`
	Runtime    RuntimeConfig    `yaml:"runtime"`
	Execution  ExecutionConfig  `yaml:"execution"`
	Providers  ProvidersConfig  `yaml:"providers"`
	Roles      RolesConfig      `yaml:"roles"`
	Review     ReviewConfig     `yaml:"review"`
	Validation ValidationConfig `yaml:"validation"`
	Trust      TrustConfig      `yaml:"trust"`
	Resources  ResourcesConfig  `yaml:"resources"`
	CI         CIConfig         `yaml:"ci"`
	Artifacts  ArtifactsConfig  `yaml:"artifacts"`
	Safety     SafetyConfig     `yaml:"safety"`
}

// RuntimeConfig controls only the inherited process environment. It never
// carries environment values, which keeps configuration free of secrets.
type RuntimeConfig struct {
	Home           string            `yaml:"home"`
	Path           RuntimePathConfig `yaml:"path"`
	EnvAllowlist   []string          `yaml:"env_allowlist"`
	MaxActiveLanes int               `yaml:"max_active_lanes"`
}

type RuntimePathConfig struct {
	Inherit bool     `yaml:"inherit"`
	Prepend []string `yaml:"prepend"`
	Append  []string `yaml:"append"`
}

type ExecutionConfig struct {
	Strategy             string `yaml:"strategy"`
	WorkspaceAccess      string `yaml:"workspace_access"`
	CrossProcessLaneLock bool   `yaml:"cross_process_lane_lock"`
}

// ProvidersConfig is keyed by stable provider instance ID. Provider commands
// are global-only and cannot appear in a project proposal.
type ProvidersConfig map[string]ProviderConfig

type ProviderConfig struct {
	Driver         string   `yaml:"driver"`
	Status         string   `yaml:"status"`
	Optional       *bool    `yaml:"optional"`
	Bin            string   `yaml:"bin"`
	Args           []string `yaml:"args"`
	ConcurrencyKey string   `yaml:"concurrency_key"`
	TimeoutSec     int      `yaml:"timeout_sec"`
	MaxStdoutBytes int      `yaml:"max_stdout_bytes"`
	MaxStderrBytes int      `yaml:"max_stderr_bytes"`
}

// RolesConfig names the six fixed review roles. Global entries are complete;
// project entries use ProjectRolesConfig so omission remains observable.
type RolesConfig struct {
	Logic           RoleConfig `yaml:"logic"`
	Security        RoleConfig `yaml:"security"`
	Maintainability RoleConfig `yaml:"maintainability"`
	Product         RoleConfig `yaml:"product"`
	Documentation   RoleConfig `yaml:"documentation"`
	Testing         RoleConfig `yaml:"testing"`
}

type RoleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type ReviewConfig struct {
	RequestChangesOn []string `yaml:"request_changes_on"`
}

type ValidationConfig struct {
	RejectUnknownFields     bool           `yaml:"reject_unknown_fields"`
	RejectEmptyStrings      bool           `yaml:"reject_empty_strings"`
	RejectPlaceholderValues bool           `yaml:"reject_placeholder_values"`
	Evidence                EvidenceConfig `yaml:"evidence"`
	Repair                  RepairConfig   `yaml:"repair"`
}

type EvidenceConfig struct {
	RequireVerifiedFor []string `yaml:"require_verified_for"`
}

type RepairConfig struct {
	Enabled      bool `yaml:"enabled"`
	MaxAttempts  int  `yaml:"max_attempts"`
	SameProvider bool `yaml:"same_provider"`
}

type TrustConfig struct {
	RequiredRoles                []string `yaml:"required_roles"`
	ProjectConfig                string   `yaml:"project_config"`
	ProjectPromptOverrides       bool     `yaml:"project_prompt_overrides"`
	ProjectPromptSource          string   `yaml:"project_prompt_source"`
	AllowProjectProviderCommands bool     `yaml:"allow_project_provider_commands"`
	AllowProjectShell            bool     `yaml:"allow_project_shell"`
}

type ResourcesConfig struct {
	PrimaryRepairAttempts  int    `yaml:"primary_repair_attempts"`
	FallbackRepairAttempts int    `yaml:"fallback_repair_attempts"`
	RoleMaxInvocations     int    `yaml:"role_max_invocations"`
	RunMaxInvocations      int    `yaml:"run_max_invocations"`
	RunTotalOutputCap      string `yaml:"run_total_output_cap"`
}

type CIConfig struct {
	FailOnSeverity      []string `yaml:"fail_on_severity"`
	DegradedReviewFails bool     `yaml:"degraded_review_fails"`
}

type ArtifactsConfig struct {
	Root              string `yaml:"root"`
	DirectoryMode     string `yaml:"directory_mode"`
	FileMode          string `yaml:"file_mode"`
	PreserveRawOutput bool   `yaml:"preserve_raw_output"`
}

type SafetyConfig struct {
	RedactSecrets      bool   `yaml:"redact_secrets"`
	SecretOutputPolicy string `yaml:"secret_output_policy"`
	MutationDetection  bool   `yaml:"mutation_detection"`
}

// ProjectConfig is a trusted-base strengthening proposal. Every optional
// setting is a pointer so the trust reducer can distinguish omission from an
// explicit value. Its structure deliberately excludes providers, commands,
// shell, arbitrary environment, templates, and weakening-only controls.
type ProjectConfig struct {
	Version     int                      `yaml:"version"`
	TrustedBase bool                     `yaml:"trusted_base"`
	Project     ProjectMetadata          `yaml:"project"`
	Execution   *ProjectExecutionConfig  `yaml:"execution"`
	Review      *ProjectReviewConfig     `yaml:"review"`
	Roles       *ProjectRolesConfig      `yaml:"roles"`
	Validation  *ProjectValidationConfig `yaml:"validation"`
	Resources   *ProjectResourcesConfig  `yaml:"resources"`
	CI          *ProjectCIConfig         `yaml:"ci"`
}

type ProjectMetadata struct {
	Name    string `yaml:"name"`
	Root    string `yaml:"root"`
	Context string `yaml:"context"`
}

type ProjectExecutionConfig struct {
	WorkspaceAccess *string `yaml:"workspace_access"`
}

type ProjectReviewConfig struct {
	RequiredRoles    *[]string `yaml:"required_roles"`
	RequestChangesOn *[]string `yaml:"request_changes_on"`
}

type ProjectRolesConfig struct {
	Logic           *ProjectRoleConfig `yaml:"logic"`
	Security        *ProjectRoleConfig `yaml:"security"`
	Maintainability *ProjectRoleConfig `yaml:"maintainability"`
	Product         *ProjectRoleConfig `yaml:"product"`
	Documentation   *ProjectRoleConfig `yaml:"documentation"`
	Testing         *ProjectRoleConfig `yaml:"testing"`
}

type ProjectRoleConfig struct {
	Enabled *bool   `yaml:"enabled"`
	Guide   *string `yaml:"guide"`
}

type ProjectValidationConfig struct {
	Evidence *ProjectEvidenceConfig `yaml:"evidence"`
}

type ProjectEvidenceConfig struct {
	RequireVerifiedFor *[]string `yaml:"require_verified_for"`
}

type ProjectResourcesConfig struct {
	RoleMaxInvocations *int    `yaml:"role_max_invocations"`
	RunMaxInvocations  *int    `yaml:"run_max_invocations"`
	RunTotalOutputCap  *string `yaml:"run_total_output_cap"`
}

type ProjectCIConfig struct {
	FailOnSeverity      *[]string `yaml:"fail_on_severity"`
	DegradedReviewFails *bool     `yaml:"degraded_review_fails"`
}
