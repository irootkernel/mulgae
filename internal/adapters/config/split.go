package config

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type projectConfig struct {
	Version    int                    `yaml:"version"`
	Project    ProjectConfig          `yaml:"project"`
	Providers  projectProvidersConfig `yaml:"providers"`
	Execution  ExecutionConfig        `yaml:"execution"`
	Roles      RolesConfig            `yaml:"roles"`
	Review     ReviewConfig           `yaml:"review"`
	Validation ValidationConfig       `yaml:"validation"`
	Resources  ResourcesConfig        `yaml:"resources"`
	CI         CIConfig               `yaml:"ci"`
}

type projectProvidersConfig struct {
	Kimi  *projectKimiConfig  `yaml:"kimi,omitempty"`
	ZCode *projectZCodeConfig `yaml:"zcode,omitempty"`
	AGY   *projectAGYConfig   `yaml:"agy,omitempty"`
}

type projectKimiConfig struct {
	Model   string `yaml:"model,omitempty"`
	Timeout string `yaml:"timeout,omitempty"`
}

type projectZCodeConfig struct {
	Timeout string `yaml:"timeout,omitempty"`
}

type projectAGYConfig struct {
	PermissionMode string `yaml:"permission_mode,omitempty"`
	Timeout        string `yaml:"timeout,omitempty"`
}

type machineConfig struct {
	Version    int                    `yaml:"version"`
	NativeUser NativeUserConfig       `yaml:"native_user"`
	Providers  machineProvidersConfig `yaml:"providers"`
}

type machineProvidersConfig struct {
	Kimi  *machineKimiConfig  `yaml:"kimi,omitempty"`
	ZCode *machineZCodeConfig `yaml:"zcode,omitempty"`
	AGY   *machineAGYConfig   `yaml:"agy,omitempty"`
}

type machineKimiConfig struct {
	Executable string `yaml:"executable"`
	DataHome   string `yaml:"data_home,omitempty"`
}

type machineZCodeConfig struct {
	NodeExecutable string `yaml:"node_executable"`
	Launcher       string `yaml:"launcher"`
}

type machineAGYConfig struct {
	Executable string `yaml:"executable"`
}

func DecodeSplit(projectData, localData []byte) (Config, error) {
	projectRoot, err := admittedConfigDocument(projectData)
	if err != nil {
		return Config{}, err
	}
	if _, err := admittedConfigDocument(localData); err != nil {
		return Config{}, err
	}
	var project projectConfig
	if err := decodeKnown(projectData, &project); err != nil {
		return Config{}, err
	}
	var local machineConfig
	if err := decodeKnown(localData, &local); err != nil {
		return Config{}, err
	}
	if project.Version != ConfigVersion || local.Version != ConfigVersion {
		return Config{}, reject(ReasonYAMLInvalid)
	}
	config, err := mergeSplit(project, local)
	if err != nil {
		return Config{}, reject(ReasonYAMLInvalid)
	}
	if config.Providers.AGY != nil {
		config.Providers.AGY.PermissionModeExplicit = mappingHasPath(projectRoot, "providers", "agy", "permission_mode")
	}
	if err := validate(&config); err != nil {
		if errors.Is(err, errProviderTimeoutInvalid) {
			return Config{}, reject(ReasonProviderTimeoutInvalid)
		}
		return Config{}, reject(ReasonYAMLInvalid)
	}
	return config, nil
}

func ProjectProviderIDs(projectData []byte) ([]string, error) {
	if _, err := admittedConfigDocument(projectData); err != nil {
		return nil, err
	}
	var project projectConfig
	if err := decodeKnown(projectData, &project); err != nil || project.Version != ConfigVersion {
		return nil, reject(ReasonYAMLInvalid)
	}
	var families []string
	if project.Providers.Kimi != nil {
		families = append(families, "kimi")
	}
	if project.Providers.ZCode != nil {
		families = append(families, "zcode")
	}
	if project.Providers.AGY != nil {
		families = append(families, "agy")
	}
	if len(families) == 0 {
		return nil, reject(ReasonYAMLInvalid)
	}
	return families, nil
}

func MergeProjectConfig(projectData []byte, localCandidate Config) (Config, error) {
	return DecodeSplit(projectData, encodeMachineConfig(localCandidate))
}

func admittedConfigDocument(data []byte) (*yaml.Node, error) {
	root, err := parseBoundedDocument(data)
	if err != nil {
		return nil, err
	}
	if reason := scanCredentials(root); reason != "" {
		return nil, reject(reason)
	}
	if !strictScalarGrammar(root) {
		return nil, reject(ReasonYAMLInvalid)
	}
	return root, nil
}

func decodeKnown(data []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return reject(ReasonYAMLInvalid)
	}
	return nil
}

func mergeSplit(project projectConfig, local machineConfig) (Config, error) {
	config := Config{
		Version: project.Version, Project: project.Project, NativeUser: local.NativeUser,
		Execution: project.Execution, Roles: project.Roles, Review: project.Review,
		Validation: project.Validation, Resources: project.Resources, CI: project.CI,
	}
	if (project.Providers.Kimi == nil) != (local.Providers.Kimi == nil) ||
		(project.Providers.ZCode == nil) != (local.Providers.ZCode == nil) ||
		(project.Providers.AGY == nil) != (local.Providers.AGY == nil) {
		return Config{}, fmt.Errorf("provider sets differ")
	}
	if project.Providers.Kimi != nil {
		config.Providers.Kimi = &KimiProviderConfig{Executable: local.Providers.Kimi.Executable, Model: project.Providers.Kimi.Model, DataHome: local.Providers.Kimi.DataHome, Timeout: project.Providers.Kimi.Timeout}
	}
	if project.Providers.ZCode != nil {
		config.Providers.ZCode = &ZCodeProviderConfig{NodeExecutable: local.Providers.ZCode.NodeExecutable, Launcher: local.Providers.ZCode.Launcher, Timeout: project.Providers.ZCode.Timeout}
	}
	if project.Providers.AGY != nil {
		config.Providers.AGY = &AGYProviderConfig{Executable: local.Providers.AGY.Executable, PermissionMode: project.Providers.AGY.PermissionMode, Timeout: project.Providers.AGY.Timeout}
	}
	return config, nil
}

func EncodeSplit(config Config) ([]byte, []byte, error) {
	if err := validate(&config); err != nil {
		return nil, nil, err
	}
	project := encodeProjectConfig(config)
	local := encodeMachineConfig(config)
	if _, err := DecodeSplit(project, local); err != nil {
		return nil, nil, fmt.Errorf("canonical split config did not round trip: %w", err)
	}
	return project, local, nil
}

func encodeProjectConfig(config Config) []byte {
	q := strconv.Quote
	var out strings.Builder
	out.WriteString("version: " + strconv.Itoa(ConfigVersion) + "\nproject:\n  name: " + q(config.Project.Name) + "\n")
	if config.Project.Context != "" {
		out.WriteString("  context: " + q(config.Project.Context) + "\n")
	}
	if config.Project.Kind == ProjectKindUI {
		out.WriteString("  kind: \"ui\"\n")
	}
	out.WriteString("providers:\n")
	if provider := config.Providers.Kimi; provider != nil {
		out.WriteString("  kimi:")
		if provider.Model == DefaultKimiModel && provider.Timeout == ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString(" {}\n")
		} else {
			out.WriteString("\n")
			if provider.Model != DefaultKimiModel {
				out.WriteString("    model: " + q(provider.Model) + "\n")
			}
			if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
				out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
			}
		}
	}
	if provider := config.Providers.ZCode; provider != nil {
		out.WriteString("  zcode:")
		if provider.Timeout == ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString(" {}\n")
		} else {
			out.WriteString("\n    timeout: " + q(provider.Timeout) + "\n")
		}
	}
	if provider := config.Providers.AGY; provider != nil {
		out.WriteString("  agy:")
		if provider.PermissionMode == DefaultAGYPermissionMode && !provider.PermissionModeExplicit && provider.Timeout == ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString(" {}\n")
		} else {
			out.WriteString("\n")
			if provider.PermissionMode != DefaultAGYPermissionMode || provider.PermissionModeExplicit {
				out.WriteString("    permission_mode: " + q(provider.PermissionMode) + "\n")
			}
			if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
				out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
			}
		}
	}
	appendPolicyYAML(&out, config)
	return []byte(out.String())
}

func appendPolicyYAML(out *strings.Builder, config Config) {
	q := strconv.Quote
	out.WriteString("execution:\n  workspace_access: " + q(config.Execution.WorkspaceAccess) + "\nroles:\n")
	for index, role := range fixedRoles {
		configured := config.Roles.Ordered()[index]
		if role == "artist" && !configured.Enabled {
			continue
		}
		if role == "artist" {
			out.WriteString("  artist:\n    enabled: true\n    primary_provider: " + q(configured.PrimaryProvider) + "\n")
			out.WriteString("    inputs:\n      task_path: " + q(configured.Inputs.TaskPath) + "\n      design_spec_globs: " + quotedList(configured.Inputs.DesignSpecGlobs) + "\n")
			continue
		}
		out.WriteString("  " + role + ": {enabled: " + strconv.FormatBool(configured.Enabled) + ", primary_provider: " + q(configured.PrimaryProvider) + "}\n")
	}
	out.WriteString("review:\n  required_roles: " + quotedList(config.Review.RequiredRoles) + "\n  request_changes_on: " + quotedList(config.Review.RequestChangesOn) + "\n")
	out.WriteString("validation:\n  evidence:\n    require_verified_for: " + quotedList(config.Validation.Evidence.RequireVerifiedFor) + "\n  repair:\n    enabled: " + strconv.FormatBool(config.Validation.Repair.Enabled) + "\n    max_attempts: " + strconv.Itoa(config.Validation.Repair.MaxAttempts) + "\n    same_provider: " + strconv.FormatBool(config.Validation.Repair.SameProvider) + "\n")
	out.WriteString("resources:\n  max_active_lanes: " + strconv.Itoa(config.Resources.MaxActiveLanes) + "\n  primary_repair_attempts: " + strconv.Itoa(config.Resources.PrimaryRepairAttempts) + "\n  role_max_invocations: " + strconv.Itoa(config.Resources.RoleMaxInvocations) + "\n  run_max_invocations: " + strconv.Itoa(config.Resources.RunMaxInvocations) + "\n  run_total_output_cap: " + q(config.Resources.RunTotalOutputCap) + "\n")
	out.WriteString("ci:\n  fail_on_severity: " + quotedList(config.CI.FailOnSeverity) + "\n  degraded_review_fails: " + strconv.FormatBool(config.CI.DegradedReviewFails) + "\n")
}

func encodeMachineConfig(config Config) []byte {
	q := strconv.Quote
	var out strings.Builder
	out.WriteString("version: " + strconv.Itoa(ConfigVersion) + "\nnative_user:\n  home: " + q(config.NativeUser.Home) + "\nproviders:\n")
	if provider := config.Providers.Kimi; provider != nil {
		out.WriteString("  kimi:\n    executable: " + q(provider.Executable) + "\n")
		if provider.DataHome != DefaultKimiDataHome(config.NativeUser.Home) {
			out.WriteString("    data_home: " + q(provider.DataHome) + "\n")
		}
	}
	if provider := config.Providers.ZCode; provider != nil {
		out.WriteString("  zcode:\n    node_executable: " + q(provider.NodeExecutable) + "\n    launcher: " + q(provider.Launcher) + "\n")
	}
	if provider := config.Providers.AGY; provider != nil {
		out.WriteString("  agy:\n    executable: " + q(provider.Executable) + "\n")
	}
	return []byte(out.String())
}
