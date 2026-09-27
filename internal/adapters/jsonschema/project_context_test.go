package jsonschema

import (
	"context"
	"encoding/json"
	"testing"
)

func TestProjectContextContractRejectsUnsupportedOrPrivateFields(t *testing.T) {
	validator := newBuiltinValidator(t)
	current := mustAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v14.schema.json")
	for _, mutation := range []string{"", "future_capability", "private_path", "missing_binding", "unknown_capability", "failed_identity"} {
		t.Run(mutation, func(t *testing.T) {
			doc := readAssetJSON(t, "examples/command-result.v14.valid.json").(map[string]any)
			result := doc["result"].(map[string]any)
			capabilities := result["capabilities"].(map[string]any)
			switch mutation {
			case "future_capability":
				capabilities["execution_guard"] = "v1"
			case "private_path":
				result["project_root"] = "/private/root"
			case "missing_binding":
				result["project_binding"] = nil
			case "unknown_capability":
				capabilities["new_feature"] = "v1"
			case "failed_identity":
				doc["exit"] = map[string]any{"code": 8, "kind": "security"}
				doc["reasons"] = []any{map[string]any{"category": "security", "code": "security_policy_violation", "message": "Project binding unavailable.", "retryable": false, "artifact_uri": nil}}
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			err = validator.Validate(context.Background(), current, raw)
			if (err == nil) != (mutation == "") {
				t.Fatalf("contract acceptance for %s: %v", mutation, err)
			}
			if mutation == "" {
				doc["schema_version"] = "mulgae-command-result.v13"
				raw, _ = json.Marshal(doc)
				old := mustAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v13.schema.json")
				if err := validator.Validate(context.Background(), old, raw); err == nil {
					t.Fatal("historical contract silently accepted context")
				}
			}
		})
	}
}
