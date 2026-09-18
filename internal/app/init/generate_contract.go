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
	commandSchema := filepath.Join(assets, "schemas", "mulgae-command-result.v11.schema.json")
	if err := seedCommandSchema(assets, commandSchema); err != nil {
		return err
	}
	for _, update := range []func(string) error{
		func(filename string) error { return replaceSchemaMatrix(filename, specs) },
		func(filename string) error { return replaceSchemaOutcomeContract(filename, specs) },
		func(filename string) error { return replaceSchemaDiscoveryContract(filename, discoverySpecs) },
		replaceSchemaProviderContract,
		replaceSchemaZCodeAppBundleContract,
	} {
		if err := update(commandSchema); err != nil {
			return err
		}
	}
	if err := sanitizeCommandJSON(commandSchema); err != nil {
		return err
	}
	if err := addCommandDoctorApplicationCompatibility(commandSchema, true); err != nil {
		return err
	}
	return writeCommandExample(assets)
}

func seedCommandSchema(assets, target string) error {
	source := filepath.Join(assets, "schemas", "mulgae-command-result.v9.schema.json")
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	contents = bytes.ReplaceAll(contents, []byte("mulgae-command-result.v9"), []byte("mulgae-command-result.v11"))
	contents = bytes.ReplaceAll(contents, []byte("Mulgae Command Result v9"), []byte("Mulgae Command Result v11"))
	return writeIfChanged(target, contents)
}

func writeCommandExample(assets string) error {
	source := filepath.Join(assets, "examples", "command-result.v9.valid.json")
	target := filepath.Join(assets, "examples", "command-result.v11.valid.json")
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	contents = bytes.ReplaceAll(contents, []byte("mulgae-command-result.v9"), []byte("mulgae-command-result.v11"))
	if err := writeIfChanged(target, contents); err != nil {
		return err
	}
	return addCommandDoctorApplicationCompatibility(target, false)
}

func addCommandDoctorApplicationCompatibility(filename string, schema bool) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			if schema {
				if properties, ok := typed["properties"].(map[string]any); ok && properties["cli_compatible"] != nil && properties["binary_available"] != nil {
					properties["application_compatible"] = map[string]any{"$ref": "#/$defs/doctor/$defs/cli_compatibility"}
					if required, ok := typed["required"].([]any); ok {
						typed["required"] = append(required, "application_compatible")
					}
				}
			} else if family, ok := typed["family"].(string); ok {
				if _, ok := typed["cli_compatible"].(map[string]any); ok {
					compatibility := map[string]any{"status": "not_applicable", "observed_version": "", "eligibility": "not_evaluated", "compatibility": "not_observed", "minimum_version": "", "verified_latest": "", "reason_code": ""}
					if family == "zcode" && typed["configured"] == true {
						compatibility = map[string]any{"status": "verified", "observed_version": "3.12.3", "eligibility": "eligible", "compatibility": "verified", "minimum_version": "3.12.3", "verified_latest": "3.12.3", "reason_code": "zcode_application_version_supported"}
						typed["reason"] = "zcode_application_version_supported"
					}
					typed["application_compatible"] = compatibility
				}
			}
			for _, child := range typed {
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(document)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeIfChanged(filename, append(encoded, '\n'))
}

func replaceSchemaZCodeAppBundleContract(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	old := []byte(`              "zcode_node_executable": { "$ref": "#/$defs/path" }, "zcode_launcher": { "$ref": "#/$defs/path" },`)
	replacement := []byte(`              "zcode_app_bundle": { "$ref": "#/$defs/path" },`)
	if bytes.Count(data, old) != 1 {
		return fmt.Errorf("init contract generator: zcode app-bundle schema anchor is missing or ambiguous")
	}
	updated := bytes.Replace(data, old, replacement, 1)
	if !json.Valid(updated) {
		return fmt.Errorf("init contract generator: generated zcode app-bundle schema is invalid JSON")
	}
	return writeIfChanged(filename, updated)
}

func sanitizeCommandJSON(filename string) error {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document any
	if err := json.Unmarshal(contents, &document); err != nil {
		return err
	}
	document = sanitizeCommandValue(document)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeIfChanged(filename, append(encoded, '\n'))
}

func sanitizeCommandValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "kimi") || strings.Contains(lower, "agy") {
				continue
			}
			result[key] = sanitizeCommandValue(child)
		}
		before, beforeOK := typed["prefixItems"].([]any)
		after, afterOK := result["prefixItems"].([]any)
		if beforeOK && afterOK && len(before) != len(after) {
			if minimum, ok := typed["minItems"].(float64); ok && int(minimum) == len(before) {
				result["minItems"] = float64(len(after))
			}
			if maximum, ok := typed["maxItems"].(float64); ok && int(maximum) == len(before) {
				result["maxItems"] = float64(len(after))
			}
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			if text, ok := child.(string); ok && (text == "kimi" || text == "agy" || text == "agy_permission_mode") {
				continue
			}
			if directRetiredProviderBranch(child) {
				continue
			}
			result = append(result, sanitizeCommandValue(child))
		}
		return result
	case string:
		for old, next := range map[string]string{
			"mulgae-doctor-result.v3":             "mulgae-doctor-result.v5",
			"mulgae-provider-heartbeat-result.v2": "mulgae-provider-heartbeat-result.v3",
			"mulgae-review-preflight.v4":          "mulgae-review-preflight.v5",
			"(?:kimi|zcode|agy|grok|codex)":       "(?:zcode|grok|codex)",
		} {
			typed = strings.ReplaceAll(typed, old, next)
		}
		return typed
	default:
		return value
	}
}

func directRetiredProviderBranch(value any) bool {
	typed, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if reference, ok := typed["$ref"].(string); ok {
		return strings.Contains(reference, "init_discovery_kimi") || strings.Contains(reference, "init_discovery_agy")
	}
	constant, ok := typed["const"].(string)
	return ok && (constant == "kimi" || constant == "agy")
}

func replaceSchemaProviderContract(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	startNeedle := []byte(`    "canonical_provider_ids": {`)
	endNeedle := []byte(`    "canonical_role_ids": {`)
	start, end := bytes.Index(data, startNeedle), bytes.Index(data, endNeedle)
	if start < 0 || end <= start {
		return fmt.Errorf("init contract generator: provider schema anchors are missing")
	}
	families := []string{"zcode", "grok", "codex"}
	branches := make([]any, 0, 1<<len(families))
	for mask := 0; mask < 1<<len(families); mask++ {
		selected := make([]any, 0, len(families))
		for index, family := range families {
			if mask&(1<<index) != 0 {
				selected = append(selected, map[string]any{"const": family})
			}
		}
		if len(selected) == 0 {
			branches = append(branches, map[string]any{"maxItems": 0})
			continue
		}
		branches = append(branches, map[string]any{"minItems": len(selected), "maxItems": len(selected), "prefixItems": selected, "items": false})
	}
	encoded, err := json.MarshalIndent(map[string]any{"type": "array", "oneOf": branches}, "    ", "  ")
	if err != nil {
		return err
	}
	replacement := append([]byte(`    "canonical_provider_ids": `), encoded...)
	replacement = append(replacement, ',', '\n')
	updated := append(append(append([]byte(nil), data[:start]...), replacement...), data[end:]...)
	if !json.Valid(updated) {
		return fmt.Errorf("init contract generator: generated provider schema is invalid JSON")
	}
	return writeIfChanged(filename, updated)
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
	for _, state := range []string{"committed", "existing_untouched", "not_committed", "project_committed_local_missing", "private_dir_created_unconfirmed", "private_dir_existing_unconfirmed", "installed_unconfirmed"} {
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
	// The init outcome block is generated independently. Review preflight owns
	// the following definitions, so stop at its stable first definition instead
	// of consuming every definition up to requests.
	endNeedle := []byte(`    "review_preflight_duration": {`)
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
	states := []string{"not_committed", "project_committed_local_missing", "private_dir_created_unconfirmed", "private_dir_existing_unconfirmed", "installed_unconfirmed"}
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
