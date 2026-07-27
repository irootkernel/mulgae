package validation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type followupSchemaFunc func(context.Context, ports.AssetID, []byte) error

func (fn followupSchemaFunc) Validate(ctx context.Context, id ports.AssetID, raw []byte) error {
	return fn(ctx, id, raw)
}

func TestFollowupValidatorInjectsTrustedEvidenceForEveryResolution(t *testing.T) {
	for _, resolution := range []string{"resolved", "partially_resolved", "still_open", "unclear"} {
		t.Run(resolution, func(t *testing.T) {
			validator := followupTestValidator(t, followupSchemaFunc(func(_ context.Context, _ ports.AssetID, raw []byte) error {
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					return err
				}
				evidence := value["evidence"].([]any)[0].(map[string]any)
				if evidence["source"].(map[string]any)["finding_id"] != "F001" || evidence["current"].(map[string]any)["verification"] != "claimed" {
					return errors.New("trusted evidence was not injected")
				}
				return nil
			}))
			raw := []byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"summary","resolution":"` + resolution + `","rationale":"rationale","evidence":[{"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[]}`)
			result, err := validator.Validate(context.Background(), raw, followupTestScope(t))
			if err != nil || string(result.Resolution()) != resolution {
				t.Fatalf("Validate() = %q, %v", result.Resolution(), err)
			}
			provider := result.ProviderRaw()
			provider[0] = '!'
			normalized := result.NormalizedRaw()
			normalized[0] = '!'
			if string(result.ProviderRaw()) != string(raw) || result.NormalizedRaw()[0] == '!' {
				t.Fatal("validated output did not defensively copy bytes")
			}
		})
	}
}

func TestFollowupValidatorFailsClosed(t *testing.T) {
	validator := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return nil }))
	valid := []byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"summary","resolution":"resolved","rationale":"rationale","evidence":[{"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[]}`)
	cases := [][]byte{
		[]byte(`{`),
		[]byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"summary","resolution":"resolved","rationale":"rationale","evidence":[{"source":{},"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[]}`),
		[]byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"summary","resolution":"resolved","rationale":"rationale","evidence":[{"current":{"target_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[],"provider":"spoof"}`),
		[]byte(`{"schema_version":"kar-provider-followup-output.v2","summary":"summary","resolution":"resolved","rationale":"rationale","evidence":[{"current":{"path":"a.go","line_start":2,"line_end":1,"side":"head","quote":"x"}}],"new_findings":[],"limitations":[]}`),
	}
	for _, raw := range cases {
		if _, err := validator.Validate(context.Background(), raw, followupTestScope(t)); err == nil {
			t.Fatalf("Validate(%s) unexpectedly succeeded", raw)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validator.Validate(cancelled, valid, followupTestScope(t)); err == nil {
		t.Fatal("cancelled validation succeeded")
	}
	schemaFailure := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return errors.New("schema failure") }))
	if _, err := schemaFailure.Validate(context.Background(), valid, followupTestScope(t)); err == nil {
		t.Fatal("schema failure succeeded")
	}
}

func TestFollowupValidatorRepairAuthorityIsStructuralOnly(t *testing.T) {
	valid := followupTestDocument("resolved", "The issue was removed by the current change.")
	schema := followupSchemaFunc(func(_ context.Context, _ ports.AssetID, raw []byte) error {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return err
		}
		if _, ok := document["summary"]; !ok {
			return errors.New("summary is required")
		}
		return nil
	})
	validator := followupTestValidator(t, schema)

	if _, repairable, err := validator.ValidateWithRepairAuthority(context.Background(), []byte("not json"), followupTestScope(t)); err == nil || !repairable {
		t.Fatalf("invalid JSON repairable=%t err=%v", repairable, err)
	}
	missing := followupTestDocument("resolved", "The issue was removed by the current change.")
	delete(missing, "summary")
	if _, repairable, err := validator.ValidateWithRepairAuthority(context.Background(), followupTestJSON(t, missing), followupTestScope(t)); err == nil || !repairable {
		t.Fatalf("missing provider field repairable=%t err=%v", repairable, err)
	}
	forbidden := followupTestDocument("resolved", "The issue was removed by the current change.")
	forbidden["session_id"] = "provider-owned"
	if _, repairable, err := validator.ValidateWithRepairAuthority(context.Background(), followupTestJSON(t, forbidden), followupTestScope(t)); err == nil || repairable {
		t.Fatalf("trust violation repairable=%t err=%v", repairable, err)
	}
	contradiction := followupTestDocument("resolved", "The issue remains in the current target.")
	if _, repairable, err := validator.ValidateWithRepairAuthority(context.Background(), followupTestJSON(t, contradiction), followupTestScope(t)); err == nil || repairable {
		t.Fatalf("semantic contradiction repairable=%t err=%v", repairable, err)
	}
	if _, repairable, err := validator.ValidateWithRepairAuthority(context.Background(), followupTestJSON(t, valid), followupTestScope(t)); err != nil || repairable {
		t.Fatalf("valid document repairable=%t err=%v", repairable, err)
	}
}

func TestFollowupValidatorRejectsMeaninglessProviderText(t *testing.T) {
	validator := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return nil }))
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"summary", func(document map[string]any) { document["summary"] = " tbd " }},
		{"rationale", func(document map[string]any) { document["rationale"] = "TODO" }},
		{"evidence quote", func(document map[string]any) {
			document["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "unknown"
		}},
		{"limitation", func(document map[string]any) { document["limitations"] = []any{"none"} }},
		{"new finding title", func(document map[string]any) {
			document["new_findings"] = []any{followupTestFinding("-")}
		}},
		{"new finding description", func(document map[string]any) {
			finding := followupTestFinding("New finding")
			finding["description"] = "n/a"
			document["new_findings"] = []any{finding}
		}},
		{"new finding recommendation", func(document map[string]any) {
			finding := followupTestFinding("New finding")
			finding["recommendation"] = "TBD"
			document["new_findings"] = []any{finding}
		}},
		{"new finding evidence quote", func(document map[string]any) {
			finding := followupTestFinding("New finding")
			finding["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = " "
			document["new_findings"] = []any{finding}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := followupTestDocument("resolved", "The issue was removed by the current change.")
			test.mutate(document)
			if _, err := validator.Validate(context.Background(), followupTestJSON(t, document), followupTestScope(t)); err == nil {
				t.Fatal("Validate() unexpectedly accepted meaningless text")
			}
		})
	}
}

func TestFollowupValidatorRejectsResolvedContradictions(t *testing.T) {
	validator := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return nil }))
	for _, rationale := range []string{
		"The issue remains in the current target.",
		"The ISSUE, IS STILL PRESENT after inspection.",
		"The issue-still-exists.",
		"This is still open.",
		"The finding is not resolved.",
		"It is still unresolved.",
		"The finding remains unresolved.",
	} {
		t.Run(rationale, func(t *testing.T) {
			document := followupTestDocument("resolved", rationale)
			if _, err := validator.Validate(context.Background(), followupTestJSON(t, document), followupTestScope(t)); err == nil {
				t.Fatal("Validate() unexpectedly accepted a resolved contradiction")
			}
		})
	}
}

func TestFollowupValidatorAcceptsNonContradictoryRationale(t *testing.T) {
	validator := followupTestValidator(t, followupSchemaFunc(func(context.Context, ports.AssetID, []byte) error { return nil }))
	cases := []map[string]any{
		followupTestDocument("resolved", "The issue no longer remains after applying the fix."),
		followupTestDocument("still_open", "The issue remains in the current target."),
	}
	for _, document := range cases {
		if _, err := validator.Validate(context.Background(), followupTestJSON(t, document), followupTestScope(t)); err != nil {
			t.Fatalf("Validate() rejected valid rationale: %v", err)
		}
	}
}

func followupTestDocument(resolution, rationale string) map[string]any {
	return map[string]any{
		"schema_version": "kar-provider-followup-output.v2",
		"summary":        "The finding was checked against the current target.",
		"resolution":     resolution,
		"rationale":      rationale,
		"evidence": []any{map[string]any{"current": map[string]any{
			"path": "a.go", "line_start": 1, "line_end": 1, "side": "head", "quote": "return nil",
		}}},
		"new_findings": []any{},
		"limitations":  []any{},
	}
}

func followupTestFinding(title string) map[string]any {
	return map[string]any{
		"severity":       "medium",
		"title":          title,
		"description":    "The current target introduces a separate defect.",
		"evidence":       []any{map[string]any{"current": map[string]any{"path": "b.go", "line_start": 2, "line_end": 2, "side": "head", "quote": "panic(err)"}}},
		"recommendation": "Handle the error before returning.",
		"confidence":     0.9,
	}
}

func followupTestJSON(t *testing.T, document map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func followupTestValidator(t *testing.T, schema SchemaValidator) *FollowupValidator {
	t.Helper()
	id, err := ports.ParseAssetID(ProviderFollowupSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewFollowupValidator(schema, id)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}
func followupTestScope(t *testing.T) FollowupValidationScope {
	t.Helper()
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	review, err := domain.ParseReviewID("019f596a-cfe5-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return FollowupValidationScope{SessionID: session, SourceRunID: run, ReviewID: review, FindingID: "F001", SourceTargetSHA256: digest, SourceExcerptSHA256: digest, CurrentTargetSHA256: digest, Role: domain.RoleLogic, ProviderInstance: "test.provider"}
}
