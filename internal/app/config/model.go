package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config is the sole project-local Mulgae configuration authority.
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
	Enabled          bool                `yaml:"enabled" json:"enabled"`
	PrimaryProvider  string              `yaml:"primary_provider" json:"primary_provider"`
	FallbackProvider string              `yaml:"fallback_provider,omitempty" json:"fallback_provider,omitempty"`
	Inputs           *ArtistInputsConfig `yaml:"inputs,omitempty" json:"inputs,omitempty"`
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
	Evidence EvidenceConfig `yaml:"evidence" json:"evidence"`
	Repair   RepairConfig   `yaml:"repair" json:"repair"`
}
type EvidenceConfig struct {
	RequireVerifiedFor []string `yaml:"require_verified_for" json:"require_verified_for"`
}
type RepairConfig struct {
	Enabled      bool `yaml:"enabled" json:"enabled"`
	MaxAttempts  int  `yaml:"max_attempts" json:"max_attempts"`
	SameProvider bool `yaml:"same_provider" json:"same_provider"`
}
type ResourcesConfig struct {
	MaxActiveLanes         int    `yaml:"max_active_lanes" json:"max_active_lanes"`
	PrimaryRepairAttempts  int    `yaml:"primary_repair_attempts" json:"primary_repair_attempts"`
	FallbackRepairAttempts int    `yaml:"fallback_repair_attempts" json:"fallback_repair_attempts"`
	RoleMaxInvocations     int    `yaml:"role_max_invocations" json:"role_max_invocations"`
	RunMaxInvocations      int    `yaml:"run_max_invocations" json:"run_max_invocations"`
	RunTotalOutputCap      string `yaml:"run_total_output_cap" json:"run_total_output_cap"`
}
type CIConfig struct {
	FailOnSeverity      []string `yaml:"fail_on_severity" json:"fail_on_severity"`
	DegradedReviewFails bool     `yaml:"degraded_review_fails" json:"degraded_review_fails"`
}

const (
	ConfigVersion    = 1
	DefaultKimiModel = "kimi-code/kimi-for-coding"
	// DefaultAGYPermissionMode keeps AGY headless reviews inside Mulgae's
	// read-oriented permission boundary. The bounded snapshot and --sandbox
	// remain the workspace authority; write/shell requests stay soft-denied.
	// Explicit permission_mode: "dangerously-skip-permissions" remains opt-in.
	DefaultAGYPermissionMode  = "safe"
	SafeAGYPermissionMode     = "safe"
	HeadlessAGYPermissionMode = "dangerously-skip-permissions"
	DefaultProviderTimeout    = 15 * time.Minute
	MinimumProviderTimeout    = time.Minute
	MaximumProviderTimeout    = 60 * time.Minute
	ConfigRelativePath        = ".mulgae/config.yaml"
	MaximumConfigBytes        = 1 << 20
	ProjectKindNonUI          = "non_ui"
	ProjectKindUI             = "ui"
	DefaultArtistBriefPath    = "ux-ui-info.md"
)

// ParseProviderTimeout resolves an optional Config v1 provider timeout. An
// omitted value uses the fixed 15-minute default; admitted explicit values are
// bounded inclusively between one and sixty minutes.
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

// ProviderTimeoutText returns the stable Config v1 spelling for a valid
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

var DefaultArtistDesignSpecGlobs = []string{
	"design-specs/**/*.png",
	"design-specs/**/*.jpg",
	"design-specs/**/*.jpeg",
	"design-specs/**/*.webp",
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
// selected provider subset. Persisted configs remain explicit; runtime never
// calls this function to invent an assignment.
func CanonicalRolesConfig(families []string) (RolesConfig, error) {
	return CanonicalRolesConfigForSelection(families, []string{"logic", "security", "maintainability", "product", "documentation", "testing"})
}

func CanonicalRolesConfigForUI(families []string) (RolesConfig, error) {
	return CanonicalRolesConfigForSelection(families, []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"})
}

// CanonicalRolesConfigForSelection derives the deterministic assignments for
// every Config v1 role while enabling only the canonical project role set.
// Logic forms the project-level floor, not a per-run selection.
func CanonicalRolesConfigForSelection(families, selectedRoles []string) (RolesConfig, error) {
	configured := make(map[string]struct{}, len(families))
	lastOrdinal := -1
	for _, family := range families {
		ordinal := -1
		for index, candidate := range []string{"kimi", "zcode", "agy"} {
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
	fixedRoles := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
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
	selectRole := func(preferences []string) RoleConfig {
		selected := make([]string, 0, 2)
		for _, family := range preferences {
			if _, ok := configured[family]; ok {
				selected = append(selected, family)
				if len(selected) == 2 {
					break
				}
			}
		}
		role := RoleConfig{PrimaryProvider: selected[0]}
		if len(selected) == 2 {
			role.FallbackProvider = selected[1]
		}
		return role
	}
	selectOptionalRole := func(preferences []string) RoleConfig {
		selected := make([]string, 0, 2)
		for _, family := range preferences {
			if _, ok := configured[family]; ok {
				selected = append(selected, family)
			}
		}
		if len(selected) == 0 {
			return RoleConfig{}
		}
		role := RoleConfig{PrimaryProvider: selected[0]}
		if len(selected) > 1 {
			role.FallbackProvider = selected[1]
		}
		return role
	}
	logic := selectRole([]string{"kimi", "zcode", "agy"})
	documentation := selectRole([]string{"agy", "zcode", "kimi"})
	other := selectRole([]string{"zcode", "agy", "kimi"})
	logic.Enabled = enabled["logic"]
	security := other
	security.Enabled = enabled["security"]
	maintainability := other
	maintainability.Enabled = enabled["maintainability"]
	product := other
	product.Enabled = enabled["product"]
	documentation.Enabled = enabled["documentation"]
	testing := other
	testing.Enabled = enabled["testing"]
	var artist RoleConfig
	if enabled["artist"] {
		artist = selectOptionalRole([]string{"agy", "zcode"})
		if artist.PrimaryProvider == "" {
			return RolesConfig{}, fmt.Errorf("canonical role assignments: artist requires agy or zcode")
		}
		artist.Enabled = true
		artist.Inputs = &ArtistInputsConfig{TaskPath: DefaultArtistBriefPath, DesignSpecGlobs: append([]string(nil), DefaultArtistDesignSpecGlobs...)}
	}
	return RolesConfig{Logic: logic, Security: security, Maintainability: maintainability, Product: product, Documentation: documentation, Testing: testing, Artist: artist}, nil
}

func DefaultKimiDataHome(nativeHome string) string { return nativeHome + "/.kimi-code" }
func (providers ProvidersConfig) Families() []string {
	result := make([]string, 0, 3)
	if providers.Kimi != nil {
		result = append(result, "kimi")
	}
	if providers.ZCode != nil {
		result = append(result, "zcode")
	}
	if providers.AGY != nil {
		result = append(result, "agy")
	}
	return result
}
func (providers ProvidersConfig) Count() int { return len(providers.Families()) }

func RunTotalOutputCapBytes(config Config) (int64, error) {
	value := config.Resources.RunTotalOutputCap
	units := map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
	for suffix, multiplier := range units {
		if !strings.HasSuffix(value, suffix) {
			continue
		}
		amount, err := strconv.ParseInt(strings.TrimSuffix(value, suffix), 10, 64)
		if err != nil || amount <= 0 || amount > (1<<30)/multiplier {
			return 0, fmt.Errorf("output cap")
		}
		return amount * multiplier, nil
	}
	return 0, fmt.Errorf("output cap")
}

type ReasonCode string

const (
	ReasonYAMLInvalid             ReasonCode = "config_yaml_invalid"
	ReasonSizeInvalid             ReasonCode = "config_size_invalid"
	ReasonProviderTimeoutInvalid  ReasonCode = "config_provider_timeout_invalid"
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
