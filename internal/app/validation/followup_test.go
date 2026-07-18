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
