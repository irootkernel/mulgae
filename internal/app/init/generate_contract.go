//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	appinit "github.com/irootkernel/mulgae/internal/app/init"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	specs := appinit.MutationOutcomeSpecs()
	discoverySpecs := appinit.DiscoverySourceSpecs()
	if err := validateSpecs(specs); err != nil {
		return err
	}
	golden, err := json.MarshalIndent(specs, "", "  ")
	if err != nil {
		return err
	}
	golden = append(golden, '\n')
	if err := writeIfChanged(filepath.Join(root, "internal", "app", "init", "testdata", "mutation-outcomes.v1.json"), golden); err != nil {
		return err
	}
	assets := filepath.Join(root, "internal", "builtin", "assets")
	if err := replaceSchemaMatrix(filepath.Join(assets, "schemas", "mulgae-command-result.v1.schema.json"), specs); err != nil {
		return err
	}
	if err := replaceSchemaOutcomeContract(filepath.Join(assets, "schemas", "mulgae-command-result.v1.schema.json"), specs); err != nil {
		return err
	}
	if err := replaceSchemaDiscoveryContract(filepath.Join(assets, "schemas", "mulgae-command-result.v1.schema.json"), discoverySpecs); err != nil {
		return err
	}
	return nil
}

func repositoryRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("init contract generator: caller unavailable")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	if err != nil {
		return "", err
	}
	return root, nil
}

func validateSpecs(specs []appinit.MutationOutcomeSpec) error {
	seen := make(map[string]struct{}, len(specs))
	successes, deliveryFailures := 0, 0
	for _, spec := range specs {
		key := strings.Join([]string{spec.Kind, spec.WriteState, string(spec.Destination), string(spec.Class), spec.Code}, "\x00")
		if _, ok := seen[key]; ok {
			return fmt.Errorf("init contract generator: duplicate outcome %q", key)
		}
		seen[key] = struct{}{}
		if spec.Code == "" {
			if !spec.Committed || spec.Class != "" || spec.Message != "" || spec.Retryable || spec.DeliveryOnly {
				return fmt.Errorf("init contract generator: invalid successful outcome %q", key)
			}
			successes++
			continue
		}
		if spec.Class == "" || spec.Message == "" {
			return fmt.Errorf("init contract generator: incomplete failure outcome %q", key)
		}
		if spec.Committed != spec.DeliveryOnly {
			return fmt.Errorf("init contract generator: invalid committed failure outcome %q", key)
		}
		if spec.DeliveryOnly && (spec.Kind != "initialized" || spec.WriteState != "committed" || spec.Destination != ports.ConfigDestinationPresent || spec.Code != "init_result_delivery_failed" || spec.Class != domain.FailureArtifact || spec.Message != "The init result could not be delivered after commit." || !spec.Retryable) {
			return fmt.Errorf("init contract generator: invalid delivery outcome %q", key)
		}
		if spec.DeliveryOnly {
			deliveryFailures++
		}
	}
	if successes != 1 || deliveryFailures != 1 {
		return fmt.Errorf("init contract generator: success/delivery cardinality = %d/%d, want 1/1", successes, deliveryFailures)
	}
	for _, state := range []string{"committed", "existing_untouched", "not_committed", "private_dir_created_unconfirmed", "private_dir_existing_unconfirmed", "installed_unconfirmed"} {
		found := false
		for _, spec := range specs {
			found = found || spec.WriteState == state
		}
		if !found {
			return fmt.Errorf("init contract generator: missing state %q", state)
		}
	}
	return nil
}

func replaceSchemaOutcomeContract(filename string, specs []appinit.MutationOutcomeSpec) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	startNeedle := []byte(`    "init_mutation_outcome": {`)
	endNeedle := []byte(`    "requests": {`)
	start := bytes.Index(data, startNeedle)
	end := bytes.Index(data, endNeedle)
	if start < 0 || end <= start || bytes.Index(data[start+1:], startNeedle) >= 0 || bytes.Index(data[end+1:], endNeedle) >= 0 {
		return fmt.Errorf("init contract generator: outcome schema anchors are missing or ambiguous")
	}
	replacement, err := renderSchemaOutcomeContract(specs)
	if err != nil {
		return err
	}
	updated := append(append(append([]byte(nil), data[:start]...), replacement...), data[end:]...)
	if !json.Valid(updated) {
		return fmt.Errorf("init contract generator: generated outcome schema is invalid JSON")
	}
	return writeIfChanged(filename, updated)
}

func renderSchemaOutcomeContract(specs []appinit.MutationOutcomeSpec) ([]byte, error) {
	branches := make([]any, 0, len(specs))
	for _, spec := range specs {
		exit := exitForClass(spec.Class)
		exitKind := exitKindForClass(spec.Class)
		reasons := map[string]any{"maxItems": 0}
		if spec.Code != "" {
			reasons = map[string]any{
				"minItems": 1,
				"maxItems": 1,
				"prefixItems": []any{map[string]any{
					"properties": map[string]any{
						"artifact_uri": map[string]any{"const": nil},
						"category":     map[string]any{"const": categoryForClass(spec.Class)},
						"code":         map[string]any{"const": spec.Code},
						"message":      map[string]any{"const": spec.Message},
						"retryable":    map[string]any{"const": spec.Retryable},
					}},
				},
			}
		}
		branches = append(branches, map[string]any{
			"properties": map[string]any{
				"exit": map[string]any{"properties": map[string]any{
					"code": map[string]any{"const": exit},
					"kind": map[string]any{"const": exitKind},
				}},
				"reasons": reasons,
				"result": map[string]any{"properties": map[string]any{
					"committed":         map[string]any{"const": spec.Committed},
					"destination_state": map[string]any{"const": spec.Destination},
					"kind":              map[string]any{"const": spec.Kind},
					"write_state":       map[string]any{"const": spec.WriteState},
				}},
			},
		})
	}
	contract, err := json.MarshalIndent(map[string]any{"oneOf": branches}, "    ", "  ")
	if err != nil {
		return nil, err
	}
	result := append([]byte(`    "init_mutation_outcome": `), contract...)
	result = append(result, ',', '\n')
	return result, nil
}

func replaceSchemaMatrix(filename string, specs []appinit.MutationOutcomeSpec) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	startNeedle := []byte(`          { "properties": { "kind": { "const": "initialized" }, "write_state": { "const": "committed" }`)
	endNeedle := []byte(`          { "properties": { "kind": { "const": "initialization_failed" }, "write_state": { "const": "installed_unconfirmed" }`)
	start := bytes.Index(data, startNeedle)
	endStart := bytes.Index(data, endNeedle)
	if start < 0 || endStart < start || bytes.Index(data[start+1:], startNeedle) >= 0 || bytes.Index(data[endStart+1:], endNeedle) >= 0 {
		return fmt.Errorf("init contract generator: schema anchors are missing or ambiguous")
	}
	end := bytes.IndexByte(data[endStart:], '\n')
	if end < 0 {
		return fmt.Errorf("init contract generator: schema end anchor is unterminated")
	}
	end += endStart + 1
	replacement := []byte(renderSchemaBranches(specs))
	updated := append(append(append([]byte(nil), data[:start]...), replacement...), data[end:]...)
	if !json.Valid(updated) {
		return fmt.Errorf("init contract generator: generated schema is invalid JSON")
	}
	return writeIfChanged(filename, updated)
}

func renderSchemaBranches(specs []appinit.MutationOutcomeSpec) string {
	destinations := destinationsByState(specs)
	lines := []string{
		`          { "properties": { "kind": { "const": "initialized" }, "write_state": { "const": "committed" }, "committed": { "const": true }, "destination_state": { "const": "present" }, "config_sha256": { "$ref": "#/$defs/sha256" }, "candidate_provider_ids": { "minItems": 1 }, "configured_provider_ids": { "minItems": 1 }, "discovery": { "minItems": 3 } } },`,
		`          { "properties": { "kind": { "const": "initialization_failed" }, "write_state": { "const": "not_attempted" }, "committed": { "const": false }, "destination_state": { "enum": ["absent", "not_observed"] } }, "oneOf": [`,
		`            { "properties": { "config_sha256": { "const": "" }, "configured_provider_ids": { "maxItems": 0 } } },`,
		`            { "properties": { "config_sha256": { "$ref": "#/$defs/sha256" }, "candidate_provider_ids": { "minItems": 1 }, "configured_provider_ids": { "minItems": 1 }, "discovery": { "minItems": 3 } } }`,
		`          ] },`,
		`          { "properties": { "kind": { "const": "initialization_failed" }, "write_state": { "const": "existing_untouched" }, "committed": { "const": false }, "destination_state": { "const": "present" } }, "oneOf": [`,
		`            { "properties": { "config_sha256": { "const": "" }, "candidate_provider_ids": { "maxItems": 0 }, "configured_provider_ids": { "maxItems": 0 }, "discovery": { "maxItems": 0 } } },`,
		`            { "properties": { "config_sha256": { "$ref": "#/$defs/sha256" }, "candidate_provider_ids": { "minItems": 1 }, "configured_provider_ids": { "minItems": 1 }, "discovery": { "minItems": 3 } } }`,
		`          ] },`,
	}
	states := []string{"not_committed", "private_dir_created_unconfirmed", "private_dir_existing_unconfirmed", "installed_unconfirmed"}
	for index, state := range states {
		comma := ","
		if index == len(states)-1 {
			comma = ""
		}
		lines = append(lines, fmt.Sprintf(`          { "properties": { "kind": { "const": "initialization_failed" }, "write_state": { "const": %q }, "committed": { "const": false }, "destination_state": { "enum": %s }, "config_sha256": { "$ref": "#/$defs/sha256" }, "candidate_provider_ids": { "minItems": 1 }, "configured_provider_ids": { "minItems": 1 }, "discovery": { "minItems": 3 } } }%s`, state, jsonStrings(destinations[state]), comma))
	}
	return strings.Join(lines, "\n") + "\n"
}

func destinationsByState(specs []appinit.MutationOutcomeSpec) map[string][]string {
	order := map[ports.ConfigDestinationState]int{ports.ConfigDestinationPresent: 0, ports.ConfigDestinationAbsent: 1, ports.ConfigDestinationNotObserved: 2}
	sets := make(map[string]map[string]struct{})
	for _, spec := range specs {
		if sets[spec.WriteState] == nil {
			sets[spec.WriteState] = make(map[string]struct{})
		}
		sets[spec.WriteState][string(spec.Destination)] = struct{}{}
	}
	result := make(map[string][]string, len(sets))
	for state, set := range sets {
		for destination := range set {
			result[state] = append(result[state], destination)
		}
		sort.Slice(result[state], func(i, j int) bool {
			return order[ports.ConfigDestinationState(result[state][i])] < order[ports.ConfigDestinationState(result[state][j])]
		})
	}
	return result
}

func jsonStrings(values []string) string {
	data, _ := json.Marshal(values)
	return string(data)
}

func replaceSchemaDiscoveryContract(filename string, specs []appinit.DiscoverySourceSpec) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	startNeedle := []byte(`    "init_discovery_kimi": {`)
	start := bytes.Index(data, startNeedle)
	if start < 0 {
		startNeedle = []byte(`    "init_discovery": {`)
		start = bytes.Index(data, startNeedle)
	}
	endNeedle := []byte(`    "path": {`)
	end := bytes.Index(data, endNeedle)
	if start < 0 || end <= start || bytes.Index(data[start+1:], startNeedle) >= 0 || bytes.Index(data[end+1:], endNeedle) >= 0 {
		return fmt.Errorf("init contract generator: discovery schema anchors are missing or ambiguous")
	}
	replacement := renderSchemaDiscoveryContract(specs)
	updated := append(append(append([]byte(nil), data[:start]...), replacement...), data[end:]...)
	if !json.Valid(updated) {
		return fmt.Errorf("init contract generator: generated discovery schema is invalid JSON")
	}
	return writeIfChanged(filename, updated)
}

func renderSchemaDiscoveryContract(specs []appinit.DiscoverySourceSpec) []byte {
	var output strings.Builder
	for _, spec := range specs {
		required := []string{"family", "selected", "candidate", "configured", "status"}
		for _, field := range spec.Fields {
			required = append(required, field.JSONName)
		}
		fmt.Fprintf(&output, "    %q: {\n", "init_discovery_"+spec.Family)
		output.WriteString("      \"type\": \"object\",\n      \"additionalProperties\": false,\n")
		fmt.Fprintf(&output, "      \"required\": %s,\n", jsonStrings(required))
		output.WriteString("      \"properties\": {\n")
		fmt.Fprintf(&output, "        \"family\": { \"const\": %q },\n", spec.Family)
		output.WriteString("        \"selected\": { \"type\": \"boolean\" },\n")
		output.WriteString("        \"candidate\": { \"type\": \"boolean\" },\n")
		output.WriteString("        \"configured\": { \"type\": \"boolean\" },\n")
		output.WriteString("        \"status\": { \"enum\": [\"not_selected\", \"unavailable\", \"candidate\"] },\n")
		output.WriteString("        \"reason\": { \"type\": \"string\", \"minLength\": 1, \"maxLength\": 1024, \"pattern\": \"^[^\\\\u0000\\\\r\\\\n]+$\" },\n")
		for index, field := range spec.Fields {
			comma := ","
			if index == len(spec.Fields)-1 {
				comma = ""
			}
			fmt.Fprintf(&output, "        %q: { \"enum\": %s }%s\n", field.JSONName, jsonStrings(field.Values), comma)
		}
		output.WriteString("      }\n    },\n")
	}
	return []byte(output.String())
}

func categoryForClass(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "configuration"
	case domain.FailureArtifact:
		return "artifact"
	case domain.FailureSecurityPolicy:
		return "security"
	case domain.FailureInternal:
		return "internal"
	default:
		return "readiness"
	}
}

func exitKindForClass(class domain.FailureClass) string {
	switch class {
	case domain.FailureConfiguration:
		return "usage"
	case domain.FailureArtifact:
		return "artifact"
	case domain.FailureSecurityPolicy:
		return "security"
	case domain.FailureInternal:
		return "internal"
	default:
		return "success"
	}
}

func exitForClass(class domain.FailureClass) int {
	switch class {
	case domain.FailureConfiguration:
		return 2
	case domain.FailureProviderUnavailable:
		return 4
	case domain.FailureArtifact:
		return 7
	case domain.FailureSecurityPolicy:
		return 8
	case domain.FailureInternal:
		return 10
	default:
		return 0
	}
}

func writeIfChanged(filename string, data []byte) error {
	current, err := os.ReadFile(filename)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0o644)
}
