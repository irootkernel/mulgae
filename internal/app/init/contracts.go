package init

//go:generate go run generate_contract.go

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// DiscoverySourceFieldSpec defines one exact family-specific init discovery
// source field and its closed wire values.
type DiscoverySourceFieldSpec struct {
	JSONName string
	Values   []string
}

// DiscoverySourceSpec defines one branch of the init discovery discriminated union.
type DiscoverySourceSpec struct {
	Family string
	Fields []DiscoverySourceFieldSpec
}

// DiscoverySourceSpecs returns a caller-owned copy of the command-owned source contract.
func DiscoverySourceSpecs() []DiscoverySourceSpec {
	specs := []DiscoverySourceSpec{
		{Family: "kimi", Fields: []DiscoverySourceFieldSpec{
			{JSONName: "executable_source", Values: []string{"override", "startup_path", "not_discovered", "not_selected"}},
			{JSONName: "model_source", Values: []string{"override", "default_k3", "not_selected"}},
			{JSONName: "data_home_source", Values: []string{"override", "startup_environment", "native_home_default", "not_selected"}},
		}},
		{Family: "zcode", Fields: []DiscoverySourceFieldSpec{
			{JSONName: "node_executable_source", Values: []string{"override", "startup_path", "not_discovered", "not_selected"}},
			{JSONName: "launcher_source", Values: []string{"override", "bundled", "not_discovered", "not_selected"}},
		}},
		{Family: "agy", Fields: []DiscoverySourceFieldSpec{
			{JSONName: "executable_source", Values: []string{"override", "startup_path", "not_discovered", "not_selected"}},
			{JSONName: "native_home_source", Values: []string{"os_account", "verified_equal_input", "not_selected"}},
			// headless_default remains admitted for command-result v1 readers even
			// though new init results emit safe_default.
			{JSONName: "permission_mode_source", Values: []string{"explicit", "headless_default", "safe_default", "not_selected"}},
		}},
		{Family: "codex", Fields: []DiscoverySourceFieldSpec{
			{JSONName: "executable_source", Values: []string{"override", "startup_path", "not_discovered", "not_selected"}},
			{JSONName: "model_source", Values: []string{"override", "provider_default", "not_selected"}},
			{JSONName: "reasoning_effort_source", Values: []string{"override", "provider_default", "not_selected"}},
		}},
	}
	for index := range specs {
		specs[index].Fields = append([]DiscoverySourceFieldSpec(nil), specs[index].Fields...)
		for field := range specs[index].Fields {
			specs[index].Fields[field].Values = append([]string(nil), specs[index].Fields[field].Values...)
		}
	}
	return specs
}

// PrevalidatedOutcome is one exact result and optional failure envelope that
// may be selected after filesystem mutation.
type PrevalidatedOutcome struct {
	Result  InitializeProjectResult
	Failure *Failure
}

// Validate requires an exact row from the command-owned post-mutation outcome
// table. Result.Validate owns the result projection itself; this method also
// binds the failure class, code, message, and retryability to that projection.
func (outcome PrevalidatedOutcome) Validate() error {
	if err := outcome.Result.Validate(); err != nil {
		return err
	}
	for _, spec := range MutationOutcomeSpecs() {
		if spec.Kind != outcome.Result.Kind || spec.WriteState != outcome.Result.WriteState || spec.Committed != outcome.Result.Committed || spec.Destination != outcome.Result.DestinationState {
			continue
		}
		if spec.Code == "" {
			if outcome.Failure == nil {
				return nil
			}
			continue
		}
		if outcome.Failure != nil && outcome.Failure.Class() == spec.Class && outcome.Failure.Code() == spec.Code && outcome.Failure.Message() == spec.Message && outcome.Failure.Retryable() == spec.Retryable {
			return nil
		}
	}
	return fmt.Errorf("init outcome: result and failure do not match the post-mutation contract")
}

// ResultPrevalidator validates every exact result/failure envelope that can be
// selected after filesystem mutation.
type ResultPrevalidator interface {
	PrevalidateInitOutcome(context.Context, PrevalidatedOutcome) error
}

// ResultPrevalidatorFunc adapts a function to ResultPrevalidator.
type ResultPrevalidatorFunc func(context.Context, PrevalidatedOutcome) error

func (function ResultPrevalidatorFunc) PrevalidateInitOutcome(ctx context.Context, outcome PrevalidatedOutcome) error {
	return function(ctx, outcome)
}

// Validate enforces the command-owned semantic relationship between the init
// result projections. JSON Schema additionally validates their wire shape.
func (result InitializeProjectResult) Validate() error {
	if result.ConfigURI != ".mulgae/config.yaml" || !canonicalFamilyIDs(result.SelectedProviderIDs) || !canonicalFamilyIDs(result.CandidateProviderIDs) || !canonicalFamilyIDs(result.ConfiguredProviderIDs) || !canonicalRoleIDs(result.ConfiguredRoleIDs) {
		return fmt.Errorf("init result: invalid identity projection")
	}
	if len(result.ConfiguredProviderIDs) == 0 {
		if result.ConfigSHA256 != "" {
			return fmt.Errorf("init result: unconfigured result has a digest")
		}
	} else if !slices.Equal(result.ConfiguredProviderIDs, result.CandidateProviderIDs) || result.ConfigSHA256 == "" || len(result.Discovery) != len(familyOrder) {
		return fmt.Errorf("init result: admitted config projection is inconsistent")
	}
	if result.ConfigSHA256 != "" && !validSHA256(result.ConfigSHA256) {
		return fmt.Errorf("init result: invalid config digest")
	}
	if len(result.Discovery) != 0 && len(result.Discovery) != len(familyOrder) {
		return fmt.Errorf("init result: invalid discovery cardinality")
	}
	if len(result.Discovery) != 0 {
		auto := len(result.SelectedProviderIDs) == 0
		for index, family := range familyOrder {
			row := result.Discovery[index]
			autoSelected := auto && (family == "zcode" || family == "agy")
			if row.Family != family || row.Status == "" || !validDiscoverySources(row) || row.Selected != (autoSelected || contains(result.SelectedProviderIDs, family)) || row.Candidate != contains(result.CandidateProviderIDs, family) || row.Configured != contains(result.ConfiguredProviderIDs, family) {
				return fmt.Errorf("init result: inconsistent discovery row")
			}
			switch row.Status {
			case "not_selected":
				if row.Selected || row.Candidate || row.Configured {
					return fmt.Errorf("init result: invalid unselected discovery row")
				}
			case "unavailable":
				if !row.Selected || row.Candidate || row.Configured {
					return fmt.Errorf("init result: invalid unavailable discovery row")
				}
			case "candidate":
				if !row.Selected || !row.Candidate {
					return fmt.Errorf("init result: invalid candidate discovery row")
				}
			default:
				return fmt.Errorf("init result: invalid discovery status")
			}
		}
	}
	if result.Committed {
		if result.Kind != "initialized" || result.WriteState != "committed" || result.DestinationState != ports.ConfigDestinationPresent || result.ConfigSHA256 == "" || len(result.ConfiguredProviderIDs) == 0 || len(result.Discovery) != len(familyOrder) {
			return fmt.Errorf("init result: invalid committed projection")
		}
		return nil
	}
	if result.Kind != "initialization_failed" {
		return fmt.Errorf("init result: noncommitted result is not a failure")
	}
	switch result.WriteState {
	case "not_attempted":
		if result.DestinationState == ports.ConfigDestinationPresent {
			return fmt.Errorf("init result: unattempted destination is present")
		}
	case "existing_untouched":
		if result.DestinationState != ports.ConfigDestinationPresent {
			return fmt.Errorf("init result: existing destination is not present")
		}
	case "not_committed":
		if result.DestinationState == ports.ConfigDestinationPresent || len(result.ConfiguredProviderIDs) == 0 {
			return fmt.Errorf("init result: invalid preinstall projection")
		}
	case "project_committed_local_missing":
		if result.DestinationState != ports.ConfigDestinationPresent || len(result.ConfiguredProviderIDs) == 0 {
			return fmt.Errorf("init result: invalid partial bundle projection")
		}
	case "private_dir_created_unconfirmed", "private_dir_existing_unconfirmed":
		if len(result.ConfiguredProviderIDs) == 0 {
			return fmt.Errorf("init result: invalid root-barrier projection")
		}
	case "installed_unconfirmed":
		if result.DestinationState == ports.ConfigDestinationAbsent || len(result.ConfiguredProviderIDs) == 0 {
			return fmt.Errorf("init result: invalid installed projection")
		}
	default:
		return fmt.Errorf("init result: invalid write state")
	}
	return nil
}

func canonicalRoleIDs(values []string) bool {
	if len(values) < 1 || len(values) > len(domain.FixedRoleOrder()) {
		return false
	}
	roles := []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	last := -1
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		ordinal := -1
		for index, role := range roles {
			if value == role {
				ordinal = index
				break
			}
		}
		if ordinal <= last {
			return false
		}
		seen[value], last = true, ordinal
	}
	return seen["logic"]
}

func validDiscoverySources(row DiscoveryRow) bool {
	fields := map[string]string{
		"executable_source":       row.ExecutableSource,
		"model_source":            row.ModelSource,
		"data_home_source":        row.DataHomeSource,
		"node_executable_source":  row.NodeExecutableSource,
		"launcher_source":         row.LauncherSource,
		"native_home_source":      row.NativeHomeSource,
		"permission_mode_source":  row.PermissionModeSource,
		"reasoning_effort_source": row.ReasoningEffortSource,
	}
	var selected *DiscoverySourceSpec
	for _, spec := range DiscoverySourceSpecs() {
		if spec.Family == row.Family {
			copy := spec
			selected = &copy
			break
		}
	}
	if selected == nil {
		return false
	}
	expected := make(map[string]struct{}, len(selected.Fields))
	for _, field := range selected.Fields {
		expected[field.JSONName] = struct{}{}
		if !slices.Contains(field.Values, fields[field.JSONName]) {
			return false
		}
	}
	for name, value := range fields {
		_, belongs := expected[name]
		if belongs != (value != "") {
			return false
		}
	}
	if !row.Selected {
		for name := range expected {
			if fields[name] != "not_selected" {
				return false
			}
		}
	} else {
		for name := range expected {
			if fields[name] == "not_selected" {
				return false
			}
		}
	}
	return true
}

func canonicalFamilyIDs(ids []string) bool {
	position := -1
	for _, id := range ids {
		found := -1
		for index, family := range familyOrder {
			if id == family {
				found = index
				break
			}
		}
		if found <= position {
			return false
		}
		position = found
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == 32
}

func cloneInitResult(result InitializeProjectResult) InitializeProjectResult {
	encoded, _ := json.Marshal(result)
	var cloned InitializeProjectResult
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}

// NewObservedFailureResult constructs the truthful pre-discovery projection
// used when the command boundary has observed the config destination before it
// can establish the native account identity.
func NewObservedFailureResult(selection Selection, destination ports.ConfigDestinationState) (InitializeProjectResult, error) {
	result := baseResult(InitializeProjectRequest{})
	selected, err := validateSelection(selection, Overrides{})
	if err != nil {
		return result, err
	}
	result.SelectedProviderIDs = selected
	result.DestinationState = destination
	switch destination {
	case ports.ConfigDestinationPresent:
		result.WriteState = "existing_untouched"
	case ports.ConfigDestinationAbsent, ports.ConfigDestinationNotObserved:
		result.WriteState = "not_attempted"
	default:
		return result, fmt.Errorf("init result: invalid destination observation")
	}
	if err := result.Validate(); err != nil {
		return InitializeProjectResult{}, err
	}
	return result, nil
}

// NewRejectedRequestResult constructs the only truthful result projection for
// an init request rejected before a contract-valid selection can be frozen.
func NewRejectedRequestResult() InitializeProjectResult {
	return baseResult(InitializeProjectRequest{})
}
