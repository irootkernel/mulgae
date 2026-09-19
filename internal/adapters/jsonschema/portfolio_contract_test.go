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
	want := []any{"zcode", "grok", "codex"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("provider base families = %v, want %v", got, want)
	}
}

func TestCurrentPreflightContractsRejectRetiredPermissionModes(t *testing.T) {
	t.Parallel()

	for _, relative := range []string{
		"schemas/mulgae-review-preflight.v5.schema.json",
		"schemas/mulgae-command-result.v11.schema.json",
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
