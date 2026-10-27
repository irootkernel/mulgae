package validation_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestRequirementsSchemasRejectProviderOwnedIdentityAndUnsupportedVerdicts(t *testing.T) {
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../builtin/assets/examples/provider-requirements.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ports.ParseAssetID("https://mulgae.local/schemas/mulgae-provider-requirements.v1.schema.json")
	if err := validator.Validate(context.Background(), id, raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"owner_role", "origin", "evaluated_count", "input_sha256", "provider_instance", "verification"} {
		t.Run(key, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			value["assessments"].([]any)[0].(map[string]any)[key] = "provider-owned"
			bad, _ := json.Marshal(value)
			if err := validator.Validate(context.Background(), id, bad); err == nil {
				t.Fatal("provider assigned a trusted field")
			}
		})
	}
	for _, verdict := range []string{"met", "partially_met", "unmet", "unverified", "approved"} {
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		row := value["assessments"].([]any)[0].(map[string]any)
		row["verdict"] = verdict
		if verdict == "unverified" {
			row["reason"] = "insufficient_evidence"
		}
		body, _ := json.Marshal(value)
		if err := validator.Validate(context.Background(), id, body); (err == nil) != (verdict != "approved") {
			t.Fatalf("verdict %s acceptance: %v", verdict, err)
		}
	}
}
