package jsonschema

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPreflightV6RejectsIncompleteAdmissionReceipts(t *testing.T) {
	validator := newBuiltinValidator(t)
	schema := mustAssetID(t, "https://mulgae.local/schemas/mulgae-review-preflight.v6.schema.json")
	for _, mutation := range []string{"", "missing_receipt", "missing_capture", "bad_digest", "missing_component", "private_path", "unknown_capability"} {
		t.Run(mutation, func(t *testing.T) {
			document := readAssetJSON(t, "examples/review-preflight.v6.valid.json").(map[string]any)
			receipt := document["request_receipt"].(map[string]any)
			switch mutation {
			case "missing_receipt":
				document["request_receipt"] = nil
			case "missing_capture":
				document["capture_identity"] = ""
			case "bad_digest":
				receipt["request_digest"] = "invalid"
			case "missing_component":
				delete(receipt["components"].(map[string]any), "policy")
			case "private_path":
				document["project_root"] = "/private/fixture"
			case "unknown_capability":
				document["capabilities"].(map[string]any)["execution_guard"] = "v2"
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			err = validator.Validate(context.Background(), schema, raw)
			if (err == nil) != (mutation == "") {
				t.Fatalf("acceptance %s: %v", mutation, err)
			}
		})
	}
}
