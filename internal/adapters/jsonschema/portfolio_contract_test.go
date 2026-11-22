package jsonschema

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCurrentProviderEvidenceBaseAdmitsEveryPublishedFamily(t *testing.T) {
	t.Parallel()

	document := readAssetJSON(t, "schemas/mulgae-provider-contract-evidence.v4.schema.json").(map[string]any)
	definitions := document["$defs"].(map[string]any)
	providerBase := definitions["provider_base"].(map[string]any)
	properties := providerBase["properties"].(map[string]any)
	family := properties["family"].(map[string]any)
	got := family["enum"].([]any)
	want := []any{"zcode", "grok", "codex", "cursor"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("provider base families = %v, want %v", got, want)
	}
}

func TestCurrentInitZCodeModelPatternRejectsTrailingSlash(t *testing.T) {
	document := readAssetJSON(t, "schemas/mulgae-command-result.v14.schema.json").(map[string]any)
	definitions := document["$defs"].(map[string]any)
	requests := definitions["requests"].(map[string]any)
	accepted := requests["init_accepted"].(map[string]any)
	properties := accepted["properties"].(map[string]any)
	overrides := properties["overrides"].(map[string]any)["properties"].(map[string]any)
	pattern := overrides["zcode_model"].(map[string]any)["pattern"].(string)
	regexp, err := compileECMARegexp(pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"account:zai-individual-coding-plan/GLM-5.3", true},
		{"account:zai-individual-coding-plan/GLM-5.3/variant", true},
		{"account:zai-individual-coding-plan/GLM-5.3/", false},
	} {
		if got := regexp.MatchString(test.value); got != test.want {
			t.Fatalf("zcode_model pattern matches %q = %t, want %t", test.value, got, test.want)
		}
	}
}

func TestCurrentPreflightContractsRejectRetiredPermissionModes(t *testing.T) {
	t.Parallel()

	for _, relative := range []string{
		"schemas/mulgae-review-preflight.v5.schema.json",
		"schemas/mulgae-command-result.v12.schema.json",
		"schemas/mulgae-command-result.v13.schema.json",
		"schemas/mulgae-command-result.v14.schema.json",
	} {
		document := readAssetJSON(t, relative)
		modes := collectPermissionModeEnums(document)
		if len(modes) != 1 || !reflect.DeepEqual(modes[0], []any{"not_applicable"}) {
			t.Fatalf("%s permission modes = %v, want [[not_applicable]]", relative, modes)
		}
	}

	validator := newBuiltinValidator(t)
	schemaID := mustAssetID(t, "https://mulgae.local/schemas/mulgae-review-preflight.v5.schema.json")
	example := readAssetJSON(t, "examples/review-preflight.v5.valid.json").(map[string]any)
	transmissions := example["transmissions"].([]any)
	transmissions[0].(map[string]any)["permission_mode"] = "safe"
	raw, err := json.Marshal(example)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), schemaID, raw); err == nil {
		t.Fatal("review-preflight v5 accepted retired permission mode safe")
	}
}

func collectPermissionModeEnums(value any) [][]any {
	var result [][]any
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "permission_mode" {
					if property, ok := child.(map[string]any); ok {
						if values, ok := property["enum"].([]any); ok {
							result = append(result, values)
						}
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return result
}

func TestCursorRetirementContractsRejectCursorWhilePredecessorsAcceptIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	validator := newBuiltinValidator(t)

	// Heartbeat v5 rejects cursor while frozen v4 still accepts it.
	hb := readAssetJSON(t, "examples/provider-heartbeat-result.v5.valid.json").(map[string]any)
	hb["provider_id"] = "cursor"
	raw, err := json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(ctx, mustAssetID(t, "https://mulgae.local/schemas/mulgae-provider-heartbeat-result.v5.schema.json"), raw); err == nil {
		t.Fatal("heartbeat v5 accepted retired provider cursor")
	}
	hb["schema_version"] = "mulgae-provider-heartbeat-result.v4"
	raw, err = json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(ctx, mustAssetID(t, "https://mulgae.local/schemas/mulgae-provider-heartbeat-result.v4.schema.json"), raw); err != nil {
		t.Fatalf("frozen heartbeat v4 rejected historical cursor: %v", err)
	}

	// Review preflight v12 rejects cursor while frozen v11 still accepts it.
	pf := readAssetJSON(t, "examples/review-preflight.v12.valid.json").(map[string]any)
	pf["transmissions"].([]any)[0].(map[string]any)["provider_family"] = "cursor"
	raw, err = json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(ctx, mustAssetID(t, "https://mulgae.local/schemas/mulgae-review-preflight.v12.schema.json"), raw); err == nil {
		t.Fatal("review-preflight v12 accepted retired provider_family cursor")
	}
	pf["schema_version"] = "mulgae-review-preflight.v11"
	raw, err = json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(ctx, mustAssetID(t, "https://mulgae.local/schemas/mulgae-review-preflight.v11.schema.json"), raw); err != nil {
		t.Fatalf("frozen review-preflight v11 rejected historical cursor: %v", err)
	}

	// Doctor v8 enforces four-family inventory and rejects cursor in configured_provider_ids.
	doc := readAssetJSON(t, "examples/doctor-result.v8.valid.json").(map[string]any)
	doc["configured_provider_ids"] = []any{"cursor"}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(ctx, mustAssetID(t, "https://mulgae.local/schemas/mulgae-doctor-result.v8.schema.json"), raw); err == nil {
		t.Fatal("doctor v8 accepted retired configured_provider_ids cursor")
	}

	// Command result v24 rejects cursor_executable override and cursor provider selection.
	cmd := readAssetJSON(t, "schemas/mulgae-command-result.v24.schema.json").(map[string]any)
	defs := cmd["$defs"].(map[string]any)
	if _, exists := defs["init_discovery_cursor"]; exists {
		t.Fatal("command-result v24 still defines init_discovery_cursor")
	}
	overrides := defs["requests"].(map[string]any)["init_accepted"].(map[string]any)["properties"].(map[string]any)["overrides"].(map[string]any)["properties"].(map[string]any)
	if _, exists := overrides["cursor_executable"]; exists {
		t.Fatal("command-result v24 still defines cursor_executable override")
	}
}
