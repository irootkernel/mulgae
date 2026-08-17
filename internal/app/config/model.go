package config

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

// Config is the admitted effective value merged from Config v3's project and
// machine-local authorities.
type Config struct {
	Version    int              `yaml:"version" json:"version"`
	Project    ProjectConfig    `yaml:"project" json:"project"`
	NativeUser NativeUserConfig `yaml:"native_user" json:"native_user"`
	Providers  ProvidersConfig  `yaml:"providers" json:"providers"`
	Execution  ExecutionConfig  `yaml:"execution" json:"execution"`
	Roles      RolesConfig      `yaml:"roles" json:"roles"`
	Review     ReviewConfig     `yaml:"review" json:"review"`
	Validation ValidationConfig `yaml:"validation" json:"validation"`
	Resources  ResourcesConfig  `yaml:"resources" json:"resources"`
	CI         CIConfig         `yaml:"ci" json:"ci"`
}

type ProjectConfig struct {
	Name    string `yaml:"name" json:"name"`
	Context string `yaml:"context,omitempty" json:"context,omitempty"`
	Kind    string `yaml:"kind,omitempty" json:"kind,omitempty"`
}
type NativeUserConfig struct {
	Home string `yaml:"home" json:"home"`
}
type ProvidersConfig struct {
	Kimi  *KimiProviderConfig  `yaml:"kimi,omitempty" json:"kimi,omitempty"`
	ZCode *ZCodeProviderConfig `yaml:"zcode,omitempty" json:"zcode,omitempty"`
	AGY   *AGYProviderConfig   `yaml:"agy,omitempty" json:"agy,omitempty"`
	Codex *CodexProviderConfig `yaml:"codex,omitempty" json:"codex,omitempty"`
}
type KimiProviderConfig struct {
	Executable string `yaml:"executable" json:"executable"`
	Model      string `yaml:"model,omitempty" json:"model"`
	DataHome   string `yaml:"data_home,omitempty" json:"data_home"`
	Timeout    string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}
type ZCodeProviderConfig struct {
	NodeExecutable string `yaml:"node_executable" json:"node_executable"`
	Launcher       string `yaml:"launcher" json:"launcher"`
	Timeout        string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}
type AGYProviderConfig struct {
	Executable             string `yaml:"executable" json:"executable"`
	PermissionMode         string `yaml:"permission_mode,omitempty" json:"permission_mode"`
	Timeout                string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	PermissionModeExplicit bool   `yaml:"-" json:"-"`
}
type CodexProviderConfig struct {
	Executable               string                      `yaml:"executable" json:"executable"`
	DefaultCredentialProfile string                      `yaml:"default_credential_profile,omitempty" json:"default_credential_profile,omitempty"`
	CredentialHomes          []CodexCredentialHomeConfig `yaml:"credential_homes,omitempty" json:"credential_homes,omitempty"`
	Model                    string                      `yaml:"model,omitempty" json:"model,omitempty"`
	ReasoningEffort          string                      `yaml:"reasoning_effort,omitempty" json:"reasoning_effort,omitempty"`
	Timeout                  string                      `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}
type CodexCredentialHomeConfig struct {
	Profile string `yaml:"profile" json:"profile"`
	Home    string `yaml:"home" json:"home"`
}

func (provider CodexProviderConfig) CredentialHome(profile string) (string, bool) {
	for _, entry := range provider.CredentialHomes {
		if entry.Profile == profile {
			return entry.Home, true
		}
	}
	return "", false
}

type ExecutionConfig struct {
	WorkspaceAccess string `yaml:"workspace_access" json:"workspace_access"`
}
type RolesConfig struct {
	Logic           RoleConfig `yaml:"logic" json:"logic"`
	Security        RoleConfig `yaml:"security" json:"security"`
	Maintainability RoleConfig `yaml:"maintainability" json:"maintainability"`
	Product         RoleConfig `yaml:"product" json:"product"`
	Documentation   RoleConfig `yaml:"documentation" json:"documentation"`
	Testing         RoleConfig `yaml:"testing" json:"testing"`
	Artist          RoleConfig `yaml:"artist,omitempty" json:"artist,omitempty"`
}
type RoleConfig struct {
	Enabled           bool                `yaml:"enabled" json:"enabled"`
	PrimaryProvider   string              `yaml:"primary_provider" json:"primary_provider"`
	CredentialProfile string              `yaml:"credential_profile,omitempty" json:"credential_profile,omitempty"`
	Inputs            *ArtistInputsConfig `yaml:"inputs,omitempty" json:"inputs,omitempty"`
}
type ArtistInputsConfig struct {
	TaskPath        string   `yaml:"task_path" json:"task_path"`
	DesignSpecGlobs []string `yaml:"design_spec_globs" json:"design_spec_globs"`
}
type ReviewConfig struct {
	RequiredRoles    []string `yaml:"required_roles" json:"required_roles"`
	RequestChangesOn []string `yaml:"request_changes_on" json:"request_changes_on"`
}
type ValidationConfig struct {
	Evidence   EvidenceConfig   `yaml:"evidence" json:"evidence"`
	Repair     RepairConfig     `yaml:"repair" json:"repair"`
	Extraction ExtractionConfig `yaml:"extraction" json:"extraction"`
}
type EvidenceConfig struct {
	RequireVerifiedFor []string `yaml:"require_verified_for" json:"require_verified_for"`
}
type RepairConfig struct {
	Enabled      bool `yaml:"enabled" json:"enabled"`
	MaxAttempts  int  `yaml:"max_attempts" json:"max_attempts"`
	SameProvider bool `yaml:"same_provider" json:"same_provider"`
}

// ExtractionConfig enables the Mulgae-owned structured extraction trailer. It
// consumes the same single second invocation retry and repair compete for, so
// enabling it never widens a role path.
type ExtractionConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}
type ResourcesConfig struct {
	MaxActiveLanes        int `yaml:"max_active_lanes" json:"max_active_lanes"`
	PrimaryRepairAttempts int `yaml:"primary_repair_attempts" json:"primary_repair_attempts"`
	RoleMaxInvocations    int `yaml:"role_max_invocations" json:"role_max_invocations"`
	RunMaxInvocations     int `yaml:"run_max_invocations" json:"run_max_invocations"`
}
type CIConfig struct {
	FailOnSeverity      []string `yaml:"fail_on_severity" json:"fail_on_severity"`
	DegradedReviewFails bool     `yaml:"degraded_review_fails" json:"degraded_review_fails"`
}

const (
	ConfigVersion    = 3
	DefaultKimiModel = "kimi-code/kimi-for-coding"
	// DefaultAGYPermissionMode keeps AGY headless reviews inside Mulgae's
	// read-oriented permission boundary. The immutable snapshot and --sandbox
	// remain the workspace authority; write/shell requests stay soft-denied.
	// Explicit permission_mode: "dangerously-skip-permissions" remains opt-in.
	DefaultAGYPermissionMode  = "safe"
	SafeAGYPermissionMode     = "safe"
	HeadlessAGYPermissionMode = "dangerously-skip-permissions"
	DefaultProviderTimeout    = 60 * time.Minute
	MinimumProviderTimeout    = time.Minute
	MaximumProviderTimeout    = 60 * time.Minute
	ConfigRelativePath        = ".mulgae/config.yaml"
	LocalConfigRelativePath   = ".mulgae/local.yaml"
	MaximumConfigBytes        = 1 << 20
	ProjectKindNonUI          = "non_ui"
	ProjectKindUI             = "ui"
)

// ParseProviderTimeout resolves an optional Config v3 provider timeout. An
// omitted value uses the fixed 60-minute default, which is also the admitted
// maximum; explicit values are bounded inclusively between one and sixty
// minutes, so a project may only shorten a provider window.
func ParseProviderTimeout(value string) (time.Duration, error) {
	if value == "" {
		return DefaultProviderTimeout, nil
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout < MinimumProviderTimeout || timeout > MaximumProviderTimeout {
		return 0, fmt.Errorf("provider timeout must be a duration from %s through %s", canonicalProviderTimeout(MinimumProviderTimeout), canonicalProviderTimeout(MaximumProviderTimeout))
	}
	return timeout, nil
}

// ProviderTimeoutText returns the stable Config v3 spelling for a valid
// provider timeout. Whole-minute values use the concise "30m" form.
func ProviderTimeoutText(timeout time.Duration) string {
	return canonicalProviderTimeout(timeout)
}

func canonicalProviderTimeout(timeout time.Duration) string {
	if timeout%time.Minute == 0 {
		return strconv.FormatInt(int64(timeout/time.Minute), 10) + "m"
	}
	return timeout.String()
}

// Ordered returns the role configurations in canonical role order.
func (roles RolesConfig) Ordered() []RoleConfig {
	return []RoleConfig{roles.Logic, roles.Security, roles.Maintainability, roles.Product, roles.Documentation, roles.Testing, roles.Artist}
}

// HasFamily reports whether a provider family is explicitly configured.
func (providers ProvidersConfig) HasFamily(family string) bool {
	for _, configured := range providers.Families() {
		if configured == family {
			return true
		}
	}
	return false
}

// CanonicalRolesConfig derives init's deterministic role assignments from the
// build-owned role defaults and the selected provider subset. Persisted configs
// remain explicit; runtime never calls this function to invent an assignment.
func CanonicalRolesConfig(defaults RoleDefaults, families []string) (RolesConfig, error) {
	return CanonicalRolesConfigForSelection(defaults, families, coreRoleIDs())
}

func CanonicalRolesConfigForUI(defaults RoleDefaults, families []string) (RolesConfig, error) {
	return CanonicalRolesConfigForSelection(defaults, families, fixedRoleIDs())
}

func fixedRoleIDs() []string {
	roles := make([]string, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		roles = append(roles, string(role))
	}
	return roles
}

func coreRoleIDs() []string {
	roles := make([]string, 0, len(domain.CoreRoleOrder()))
	for _, role := range domain.CoreRoleOrder() {
		roles = append(roles, string(role))
	}
	return roles
}

// CanonicalRolesConfigForSelection derives the deterministic assignments for
// every Config v3 role while enabling only the canonical project role set.
// Logic forms the project-level floor, not a per-run selection.
//
// Each role resolves independently from its own build-owned preference order, so
// editing one role's defaults never moves another role's assignment.
func CanonicalRolesConfigForSelection(defaults RoleDefaults, families, selectedRoles []string) (RolesConfig, error) {
	if !defaults.Valid() {
		return RolesConfig{}, fmt.Errorf("canonical role assignments: role defaults are required")
	}
	configured := make(map[string]struct{}, len(families))
	lastOrdinal := -1
	for _, family := range families {
		ordinal := -1
		for index, candidate := range []string{"kimi", "zcode", "agy", "codex"} {
			if family == candidate {
				ordinal = index
				break
			}
		}
		if ordinal <= lastOrdinal {
			return RolesConfig{}, fmt.Errorf("canonical role assignments: provider families are invalid")
		}
		configured[family] = struct{}{}
		lastOrdinal = ordinal
	}
	if len(configured) == 0 {
		return RolesConfig{}, fmt.Errorf("canonical role assignments: provider families are required")
	}
	fixedRoles := fixedRoleIDs()
	enabled := make(map[string]bool, len(selectedRoles))
	lastRole := -1
	for _, selected := range selectedRoles {
		ordinal := -1
		for index, role := range fixedRoles {
			if selected == role {
				ordinal = index
				break
			}
		}
		if ordinal <= lastRole {
			return RolesConfig{}, fmt.Errorf("canonical role assignments: selected roles are invalid")
		}
		enabled[selected] = true
		lastRole = ordinal
	}
	if !enabled["logic"] {
		return RolesConfig{}, fmt.Errorf("canonical role assignments: logic is required")
	}
	// assign resolves one role against its own build-owned preference order. The
	// first configured family becomes the role's provider. Later preferences are
	// not recorded: a role runs on exactly one provider, and choosing a different
	// one after a failure is the operator's call, not a preconfigured route.
	assign := func(role domain.Role) (RoleConfig, RoleDefault, error) {
		preference, exists := defaults.Role(role)
		if !exists {
			return RoleConfig{}, RoleDefault{}, fmt.Errorf("canonical role assignments: no default for %q", role)
		}
		for _, family := range preference.ProviderPreferences {
			if _, ok := configured[family]; ok {
				return RoleConfig{PrimaryProvider: family}, preference, nil
			}
		}
		return RoleConfig{}, preference, nil
	}
	core := make(map[domain.Role]RoleConfig, len(domain.CoreRoleOrder()))
	for _, role := range domain.CoreRoleOrder() {
		assignment, _, err := assign(role)
		if err != nil {
			return RolesConfig{}, err
		}
		if assignment.PrimaryProvider == "" {
			return RolesConfig{}, fmt.Errorf("canonical role assignments: %q has no configured provider", role)
		}
		assignment.Enabled = enabled[string(role)]
		core[role] = assignment
	}
	var artist RoleConfig
	if enabled[string(domain.RoleArtist)] {
		assignment, preference, err := assign(domain.RoleArtist)
		if err != nil {
			return RolesConfig{}, err
		}
		if assignment.PrimaryProvider == "" {
			return RolesConfig{}, fmt.Errorf("canonical role assignments: artist requires agy, zcode, or codex")
		}
		artist = assignment
		artist.Enabled = true
		artist.Inputs = &ArtistInputsConfig{
			TaskPath:        preference.ArtistTaskPath,
			DesignSpecGlobs: append([]string(nil), preference.ArtistDesignSpecGlobs...),
		}
	}
	return RolesConfig{
		Logic:           core[domain.RoleLogic],
		Security:        core[domain.RoleSecurity],
		Maintainability: core[domain.RoleMaintainability],
		Product:         core[domain.RoleProduct],
		Documentation:   core[domain.RoleDocumentation],
		Testing:         core[domain.RoleTesting],
		Artist:          artist,
	}, nil
}

func DefaultKimiDataHome(nativeHome string) string { return nativeHome + "/.kimi-code" }
func (providers ProvidersConfig) Families() []string {
	result := make([]string, 0, 4)
	if providers.Kimi != nil {
		result = append(result, "kimi")
	}
	if providers.ZCode != nil {
		result = append(result, "zcode")
	}
	if providers.AGY != nil {
		result = append(result, "agy")
	}
	if providers.Codex != nil {
		result = append(result, "codex")
	}
	return result
}
func (providers ProvidersConfig) Count() int { return len(providers.Families()) }

type ReasonCode string

const (
	ReasonYAMLInvalid             ReasonCode = "config_yaml_invalid"
	ReasonSizeInvalid             ReasonCode = "config_size_invalid"
	ReasonProviderTimeoutInvalid  ReasonCode = "config_provider_timeout_invalid"
	ReasonProviderIdentityInvalid ReasonCode = "config_provider_identity_invalid"
	ReasonRoleMappingInvalid      ReasonCode = "config_role_mapping_invalid"
	ReasonCredentialKeyDetected   ReasonCode = "config_credential_key_detected"
	ReasonCredentialValueDetected ReasonCode = "config_credential_value_detected"
)

type AdmissionError struct{ reason ReasonCode }

func NewAdmissionError(reason ReasonCode) error { return &AdmissionError{reason: reason} }
func (err *AdmissionError) Error() string {
	if err == nil || err.reason == "" {
		return "configuration rejected"
	}
	return fmt.Sprintf("configuration rejected: %s", err.reason)
}
func (err *AdmissionError) Reason() ReasonCode {
	if err == nil {
		return ""
	}
	return err.reason
}
func AsAdmissionError(err error) (*AdmissionError, bool) {
	var target *AdmissionError
	return target, errors.As(err, &target)
}

// Codec keeps serialization mechanics outside the application layer.
type Codec interface {
	Decode([]byte) (Config, error)
	EncodeCanonical(Config) ([]byte, error)
}

// SplitCodec owns the disk projection and merge rules for Config v3's paired
// authorities.
type SplitCodec interface {
	Codec
	DecodeSplit([]byte, []byte) (Config, error)
	EncodeSplit(Config) ([]byte, []byte, error)
	ProjectProviderIDs([]byte) ([]string, error)
	MergeProjectConfig([]byte, Config) (Config, error)
}
