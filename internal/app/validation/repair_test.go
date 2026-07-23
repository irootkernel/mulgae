package validation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestApplyRepairCandidateReturnsTypedRepairPlanCause(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	_, _, err := validator.ApplyRepairCandidate(
		context.Background(), validProviderReview(), []byte(`{"schema_version":"kar-repair-patch.v1","repairs":[]}`), testScope(), RepairPlan{},
	)
	if err == nil {
		t.Fatal("invalid repair plan was accepted")
	}
	if cause, ok := RuntimeCause(err); !ok || cause != domain.DiagnosticCauseCandidateRepairPlanInvalid {
		t.Fatalf("repair plan cause = %q, present = %t", cause, ok)
	}
}

func marshalRepairPatch(t *testing.T, repairs []map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema_version": "kar-repair-patch.v1",
		"repairs":        repairs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestApplyRepairFillsOnlyAnAllowedMissingProviderValue(t *testing.T) {
	schema := &recordingSchemaValidator{}
	validator := testReviewValidator(t, schema)
	original := providerReviewWith(t, func(document map[string]any) {
		finding := document["findings"].([]any)[0].(map[string]any)
		finding["recommendation"] = nil
	})
	_, plan, err := validator.Validate(context.Background(), original, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/findings/0/recommendation" {
		t.Fatalf("classification: err=%v plan=%#v", err, plan)
	}
	patched := marshalRepairPatch(t, []map[string]any{{
		"path":  "/findings/0/recommendation",
		"value": "Treat a valid finding as a successful role result.",
	}})
	review, err := validator.ApplyRepair(context.Background(), original, patched, testScope(), *plan)
	if err != nil {
		t.Fatal(err)
	}
	if !review.Repaired() || string(review.OriginalRaw()) != string(original) || string(review.RepairedRaw()) != string(patched) || len(review.Findings()) != 1 {
		t.Fatalf("repaired review = %#v", review)
	}
	repaired := review.RepairedRaw()
	repaired[0] = '!'
	if string(review.RepairedRaw()) != string(patched) {
		t.Fatal("RepairedRaw leaked mutable storage")
	}
	if len(schema.calls) != 5 || schema.calls[0].id.String() != ProviderReviewWireSchemaID || schema.calls[1].id.String() != ProviderReviewSchemaID || schema.calls[2].id.String() != repairPatchSchemaID || schema.calls[3].id.String() != ProviderReviewWireSchemaID || schema.calls[4].id.String() != ProviderReviewSchemaID {
		t.Fatalf("schema calls = %#v", schema.calls)
	}
}

func TestApplyRepairReformatRevalidatesReplacementWithoutPatch(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	original := []byte("```json\nnot-json\n```")
	_, plan, err := validator.Validate(context.Background(), original, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeReformatOnly {
		t.Fatalf("classification: err=%v plan=%#v", err, plan)
	}
	review, err := validator.ApplyRepair(context.Background(), original, validProviderReview(), testScope(), *plan)
	if err != nil {
		t.Fatal(err)
	}
	if !review.Repaired() || len(review.Findings()) != 1 {
		t.Fatalf("reformatted review = %#v", review)
	}
}

func TestApplyExactEvidenceRepairMayReplaceOnlySelectedQuote(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	original := validProviderReview()
	path := "/findings/0/evidence/0/current/quote"
	plan, err := NewExactEvidenceRepairPlan(original, []string{path})
	if err != nil || plan.Mode() != RepairModeExactEvidence || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != path {
		t.Fatalf("exact evidence plan = %#v, err=%v", plan, err)
	}
	patch := marshalRepairPatch(t, []map[string]any{{"path": path, "value": "exact target line\n"}})
	review, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan)
	if err != nil {
		t.Fatal(err)
	}
	claims := review.EvidenceClaims()
	if len(claims) != 1 || len(claims[0].Claims()) != 1 || string(claims[0].Claims()[0].QuoteBytes()) != "exact target line\n" {
		t.Fatalf("repaired evidence claims = %#v", claims)
	}
	if _, err := NewExactEvidenceRepairPlan(original, []string{"/findings/0/title"}); err == nil {
		t.Fatal("non-evidence path received exact evidence repair authority")
	}
	missing := marshalRepairPatch(t, []map[string]any{{"path": path, "value": "exact target line\n"}})
	twoPaths, err := NewExactEvidenceRepairPlan(original, []string{path, "/findings/0/evidence/1/current/quote"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.ApplyRepair(context.Background(), original, missing, testScope(), *twoPaths); err == nil {
		t.Fatal("partial exact evidence repair was accepted")
	}
}

func TestApplyRepairRejectsOverwriteOrUnapprovedOrStructuralChanges(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	original := validProviderReview()

	for _, path := range []string{
		"/summary",
		"/findings/0/title",
		"/findings/0/severity",
		"/findings/0/evidence/0/current/path",
	} {
		plan := newRepairPlan(RepairModeFillMissingFields, original, []string{path})
		patch := marshalRepairPatch(t, []map[string]any{{"path": path, "value": "replacement"}})
		if _, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan); err == nil {
			t.Fatalf("meaningful path %q was overwritten", path)
		}
	}

	missingRecommendation := providerReviewWith(t, func(document map[string]any) {
		finding := document["findings"].([]any)[0].(map[string]any)
		finding["recommendation"] = nil
	})
	_, plan, err := validator.Validate(context.Background(), missingRecommendation, testScope())
	if err == nil || plan == nil {
		t.Fatalf("missing recommendation classification: err=%v plan=%#v", err, plan)
	}
	unapproved := marshalRepairPatch(t, []map[string]any{{"path": "/findings", "value": []any{}}})
	if _, err := validator.ApplyRepair(context.Background(), missingRecommendation, unapproved, testScope(), *plan); err == nil {
		t.Fatal("unapproved finding-array replacement was accepted")
	}
	duplicate := marshalRepairPatch(t, []map[string]any{
		{"path": "/findings/0/recommendation", "value": "One."},
		{"path": "/findings/0/recommendation", "value": "Two."},
	})
	if _, err := validator.ApplyRepair(context.Background(), missingRecommendation, duplicate, testScope(), *plan); err == nil {
		t.Fatal("duplicate repair paths were accepted")
	}
	if _, err := validator.ApplyRepair(context.Background(), append([]byte(nil), missingRecommendation...), marshalRepairPatch(t, []map[string]any{{"path": "/findings/0/recommendation", "value": "One."}}), testScope(), *plan); err != nil {
		t.Fatalf("same bytes should remain bound to repair plan: %v", err)
	}
	changedOriginal := append([]byte(nil), missingRecommendation...)
	changedOriginal[0] = ' '
	if _, err := validator.ApplyRepair(context.Background(), changedOriginal, marshalRepairPatch(t, []map[string]any{{"path": "/findings/0/recommendation", "value": "One."}}), testScope(), *plan); err == nil {
		t.Fatal("changed original bytes were accepted")
	}
}

func TestRepairPlanAndPointerParserRejectAmbiguousInputs(t *testing.T) {
	for _, pointer := range []string{"", "summary", "/", "/findings/~2/title"} {
		if _, err := parseJSONPointer(pointer); err == nil {
			t.Fatalf("pointer %q accepted", pointer)
		}
	}
	if index, err := parseArrayIndex("0", 1); err != nil || index != 0 {
		t.Fatalf("canonical array index: index=%d err=%v", index, err)
	}
	for _, index := range []string{"+0", "+1", "-0", "00", "01", "1", strings.Repeat("9", 1000)} {
		if _, err := parseArrayIndex(index, 1); err == nil {
			t.Fatalf("array index %q accepted", index)
		}
	}

	document := map[string]any{"limitations": []any{nil}}
	for _, pointer := range []string{"/limitations/+0", "/limitations/-0", "/limitations/00", "/limitations/~30", "/limitations/0~1"} {
		if err := setRepairValue(document, pointer, "replacement", false); err == nil {
			t.Fatalf("array pointer %q accepted", pointer)
		}
	}

	plan := newRepairPlan(RepairModeFillMissingFields, []byte("original"), []string{"/summary"})
	if len(plan.OriginalSHA256()) != 64 {
		t.Fatalf("repair plan digest = %q", plan.OriginalSHA256())
	}
}

func TestApplyRepairPreservesFindingCardinalityAndNormalizesOrder(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	original := providerReviewWith(t, func(document map[string]any) {
		high := document["findings"].([]any)[0]
		document["summary"] = "TBD"
		document["findings"] = []any{
			map[string]any{
				"severity":       "low",
				"title":          "Lower severity finding",
				"description":    "The lower severity finding remains in the review.",
				"recommendation": "Keep the low severity finding.",
				"confidence":     "high",
				"evidence": []any{map[string]any{"current": map[string]any{
					"path": "internal/app/low.go", "line_start": 4, "line_end": 4, "side": "head", "quote": "low finding",
				}}},
			},
			high,
		}
	})
	_, plan, err := validator.Validate(context.Background(), original, testScope())
	if err == nil || plan == nil || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/summary" {
		t.Fatalf("classification: err=%v plan=%#v", err, plan)
	}

	patch := marshalRepairPatch(t, []map[string]any{{
		"path":  "/summary",
		"value": "Two findings were identified.",
	}})
	review, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan)
	if err != nil {
		t.Fatal(err)
	}
	findings := review.Findings()
	if !review.Repaired() || len(findings) != 2 || findings[0].Severity() != domain.SeverityHigh || findings[0].ID() != "F001" || findings[1].Severity() != domain.SeverityLow || findings[1].ID() != "F002" {
		t.Fatalf("repaired findings = %#v", findings)
	}
}

func TestRejectSeverityDowngrade(t *testing.T) {
	repaired := map[string]any{
		"findings": []any{map[string]any{"severity": "low"}},
	}
	if err := rejectSeverityDowngrade([]domain.Severity{domain.SeverityHigh}, repaired); err == nil {
		t.Fatal("severity downgrade was accepted")
	}
}

func TestApplyRepairRejectsInjectedSystemOwnedCurrentFields(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		field string
		value any
	}{
		{name: "target", field: "target_sha256", value: "sha256:" + strings.Repeat("b", 64)},
		{name: "verification", field: "verification", value: "claimed"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			validator := testReviewValidator(t, &recordingSchemaValidator{})
			original := providerReviewWith(t, func(document map[string]any) {
				finding := document["findings"].([]any)[0].(map[string]any)
				evidence := finding["evidence"].([]any)[0].(map[string]any)
				evidence["current"] = nil
			})
			_, plan, err := validator.Validate(context.Background(), original, testScope())
			if err == nil || plan == nil || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/findings/0/evidence/0/current" {
				t.Fatalf("classification: err=%v plan=%#v", err, plan)
			}

			current := map[string]any{
				"path": "internal/app/coordinator.go", "line_start": 12, "line_end": 14, "side": "head", "quote": "queueFallback(task)",
			}
			current[testCase.field] = testCase.value
			patch := marshalRepairPatch(t, []map[string]any{{
				"path":  "/findings/0/evidence/0/current",
				"value": current,
			}})
			if _, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan); err == nil {
				t.Fatalf("system-owned %s injection was accepted", testCase.field)
			}
		})
	}
}
