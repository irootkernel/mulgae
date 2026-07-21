package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type ResolveRequest struct {
	Source ports.ConfigSource
}

type ProvenanceRow struct {
	Field       string `json:"field"`
	Source      string `json:"source"`
	Disposition string `json:"disposition"`
	ValueClass  string `json:"value_class"`
}

type Resolution struct {
	config     ResolvedConfig
	sha256     string
	canonical  []byte
	provenance []ProvenanceRow
	source     ports.ConfigSource
}

func (resolution Resolution) Config() ResolvedConfig { return resolution.config }
func (resolution Resolution) SHA256() string         { return resolution.sha256 }
func (resolution Resolution) URI() string            { return ConfigRelativePath }
func (resolution Resolution) CanonicalYAML() []byte {
	return append([]byte(nil), resolution.canonical...)
}
func (resolution Resolution) Provenance() []ProvenanceRow {
	return append([]ProvenanceRow(nil), resolution.provenance...)
}
func (resolution Resolution) Revalidate() error {
	if resolution.source == nil {
		return fmt.Errorf("configuration resolution has no source")
	}
	return resolution.source.Revalidate()
}
func (resolution Resolution) RedactedJSON() []byte {
	data, _ := json.Marshal(Redact(resolution.config))
	return data
}

type Service struct{ codec Codec }

func NewService(codec Codec) *Service { return &Service{codec: codec} }

func (service *Service) Resolve(ctx context.Context, request ResolveRequest) (Resolution, error) {
	if ctx == nil || service == nil || service.codec == nil || request.Source == nil {
		return Resolution{}, fmt.Errorf("resolve configuration: invalid request")
	}
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	source := request.Source
	data, observation, err := source.Read()
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve configuration: read: %w", err)
	}
	decoded, err := service.codec.Decode(data)
	if err != nil {
		return Resolution{}, err
	}
	canonical, err := service.codec.EncodeCanonical(decoded)
	if err != nil || !bytes.Equal(data, canonical) {
		return Resolution{}, fmt.Errorf("resolve configuration: non-canonical local configuration")
	}
	resolved, err := ResolveConfiguration(decoded)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{config: resolved, sha256: observation.SHA256(), canonical: canonical, provenance: provenanceRows(decoded), source: source}, nil
}

func provenanceRows(config Config) []ProvenanceRow {
	fields := []string{
		"version", "project.name", "project.root", "project.context", "native_user.home",
		"providers.kimi.configured", "providers.kimi.executable", "providers.kimi.model", "providers.kimi.data_home",
		"providers.zcode.configured", "providers.zcode.node_executable", "providers.zcode.launcher",
		"providers.agy.configured", "providers.agy.executable", "providers.agy.permission_mode",
		"execution.workspace_access", "roles.logic.enabled", "roles.security.enabled", "roles.maintainability.enabled", "roles.product.enabled", "roles.documentation.enabled", "roles.testing.enabled",
		"review.required_roles", "review.request_changes_on", "validation.evidence.require_verified_for", "validation.repair.enabled", "validation.repair.max_attempts", "validation.repair.same_provider",
		"resources.max_active_lanes", "resources.primary_repair_attempts", "resources.fallback_repair_attempts", "resources.role_max_invocations", "resources.run_max_invocations", "resources.run_total_output_cap", "ci.fail_on_severity", "ci.degraded_review_fails",
		"execution.strategy", "execution.cross_process_lane_lock", "runtime.path_policy", "runtime.environment_policy", "provider.timeout_sec", "provider.max_stdout_bytes", "provider.max_stderr_bytes", "artifacts.root", "artifacts.directory_mode", "artifacts.file_mode", "safety.redact_secrets", "safety.secret_output_policy", "safety.mutation_detection",
	}
	rows := make([]ProvenanceRow, 0, len(fields))
	for _, field := range fields {
		source, disposition, class := "local", "configured", "policy"
		if field == "project.root" || len(field) >= 10 && (field[:10] == "execution." && field != "execution.workspace_access") || len(field) >= 8 && field[:8] == "runtime." || len(field) >= 9 && field[:9] == "provider." || len(field) >= 10 && field[:10] == "artifacts." || len(field) >= 7 && field[:7] == "safety." {
			source, disposition, class = "code", "fixed", "invariant"
		}
		if field == "project.context" && config.Project.Context == "" || field == "providers.kimi.configured" && config.Providers.Kimi == nil || field == "providers.zcode.configured" && config.Providers.ZCode == nil || field == "providers.agy.configured" && config.Providers.AGY == nil {
			disposition = "absent"
		}
		if field == "providers.kimi.model" && config.Providers.Kimi != nil && config.Providers.Kimi.Model == DefaultKimiModel || field == "providers.kimi.data_home" && config.Providers.Kimi != nil && config.Providers.Kimi.DataHome == DefaultKimiDataHome(config.NativeUser.Home) || field == "providers.agy.permission_mode" && config.Providers.AGY != nil && config.Providers.AGY.PermissionMode == DefaultAGYPermissionMode {
			source, disposition = "default", "defaulted"
		}
		rows = append(rows, ProvenanceRow{Field: field, Source: source, Disposition: disposition, ValueClass: class})
	}
	return rows
}
