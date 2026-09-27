package jsonschema

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCompositeSupportReceiptKindsAndAvailability(t *testing.T) {
	validator := newBuiltinValidator(t)
	schema := mustAssetID(t, "https://mulgae.local/schemas/mulgae-composite-support.v1.schema.json")
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"published source lacks receipt", func(doc map[string]any) { compositeSource(doc, 0)["final_sha256"] = "" }},
		{"published source lacks epoch", func(doc map[string]any) { compositeSource(doc, 0)["epoch"] = 0 }},
		{"recovery source fabricates review", func(doc map[string]any) { compositeSource(doc, 1)["review_id"] = compositeSource(doc, 0)["review_id"] }},
		{"recovery source fabricates receipt", func(doc map[string]any) {
			compositeSource(doc, 1)["final_sha256"] = compositeSource(doc, 0)["final_sha256"]
		}},
		{"recovery source fabricates epoch", func(doc map[string]any) { compositeSource(doc, 1)["epoch"] = 1 }},
		{"portable source exposes project binding", func(doc map[string]any) {
			compositeSource(doc, 0)["project_binding"] = compositeSource(doc, 0)["target_sha256"]
		}},
		{"verified capture lacks identity", func(doc map[string]any) { compositeSource(doc, 0)["capture_identity"] = "" }},
		{"unavailable capture claims identity", func(doc map[string]any) {
			compositeSource(doc, 1)["capture_identity"] = compositeSource(doc, 0)["capture_identity"]
		}},
		{"provider provenance absent", func(doc map[string]any) { compositeSource(doc, 0)["provider_identities"] = []any{} }},
		{"provider provenance duplicated", func(doc map[string]any) {
			compositeSource(doc, 0)["provider_identities"] = []any{"zcode-logic", "zcode-logic"}
		}},
		{"verified evidence lacks content digest", func(doc map[string]any) { compositeEvidence(doc)["content_sha256"] = "" }},
		{"unavailable evidence claims content digest", func(doc map[string]any) { compositeEvidence(doc)["availability"] = "evidence_unavailable" }},
		{"evidence index outside public range", func(doc map[string]any) { compositeEvidence(doc)["index"] = 20 }},
		{"unavailable evidence has invalid side", func(doc map[string]any) {
			e := compositeEvidence(doc)
			e["availability"] = "evidence_unavailable"
			e["content_sha256"] = ""
			e["side"] = "unknown"
		}},
		{"source finding has invalid identity", func(doc map[string]any) { doc["findings"].([]any)[0].(map[string]any)["source_finding_id"] = "F1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := readAssetJSON(t, "examples/composite-support.v1.valid.json").(map[string]any)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(context.Background(), schema, raw); err != nil {
				t.Fatalf("valid fixture: %v", err)
			}
			test.mutate(doc)
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(context.Background(), schema, raw); err == nil {
				t.Fatal("invalid composite support accepted")
			}
		})
	}
	t.Run("unavailable evidence preserves claim without copied bytes", func(t *testing.T) {
		doc := readAssetJSON(t, "examples/composite-support.v1.valid.json").(map[string]any)
		e := compositeEvidence(doc)
		e["availability"], e["content_sha256"] = "evidence_unavailable", ""
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := validator.Validate(context.Background(), schema, raw); err != nil {
			t.Fatal(err)
		}
	})
}

func compositeSource(doc map[string]any, index int) map[string]any {
	return doc["sources"].([]any)[index].(map[string]any)
}

func compositeEvidence(doc map[string]any) map[string]any {
	return doc["findings"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)
}

func TestCompositeEvidenceCapabilityVersionsRemainDistinct(t *testing.T) {
	validator := newBuiltinValidator(t)
	for _, test := range []struct {
		name, schema, example, version string
		current                        bool
	}{
		{"current command", "mulgae-command-result.v18", "command-result.v15.valid.json", "mulgae-command-result.v18", true},
		{"retained command", "mulgae-command-result.v17", "command-result.v15.valid.json", "mulgae-command-result.v17", false},
		{"current preflight", "mulgae-review-preflight.v7", "review-preflight.v7.valid.json", "mulgae-review-preflight.v7", true},
		{"retained preflight", "mulgae-review-preflight.v6", "review-preflight.v6.valid.json", "mulgae-review-preflight.v6", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := readAssetJSON(t, "examples/"+test.example).(map[string]any)
			doc["schema_version"] = test.version
			owner := doc
			if result, ok := doc["result"]; ok {
				owner = result.(map[string]any)
			}
			capabilities := owner["capabilities"].(map[string]any)
			for _, version := range []string{"", "v1", "v2"} {
				capabilities["composite_evidence"] = version
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				err = validator.Validate(context.Background(), mustAssetID(t, "https://mulgae.local/schemas/"+test.schema+".schema.json"), raw)
				wantValid := version == "" || version == "v1" && test.current
				if (err == nil) != wantValid {
					t.Fatalf("%s acceptance = %v, want %v: %v", version, err == nil, wantValid, err)
				}
			}
		})
	}
}
