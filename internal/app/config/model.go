package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Config is the sole project-local KAR configuration authority.
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
}
type ZCodeProviderConfig struct {
	NodeExecutable string `yaml:"node_executable" json:"node_executable"`
	Launcher       string `yaml:"launcher" json:"launcher"`
}
type AGYProviderConfig struct {
	Executable     string `yaml:"executable" json:"executable"`
	PermissionMode string `yaml:"permission_mode,omitempty" json:"permission_mode"`
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
}
type RoleConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
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
	DefaultKimiModel         = "kimi-code/k3"
	DefaultAGYPermissionMode = "safe"
	ConfigRelativePath       = ".kar/config.yaml"
	MaximumConfigBytes       = 1 << 20
)

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
