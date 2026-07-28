package validation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type schemaCall struct {
	id  ports.AssetID
	raw []byte
}

type recordingSchemaValidator struct {
	calls []schemaCall
	err   error
}

func (validator *recordingSchemaValidator) Validate(_ context.Context, id ports.AssetID, raw []byte) error {
	validator.calls = append(validator.calls, schemaCall{id: id, raw: append([]byte(nil), raw...)})
	return validator.err
}

type documentSchemaError struct {
	cause error
}

func (err documentSchemaError) Error() string {
	return "provider document violates schema"
}

func (err documentSchemaError) Unwrap() error {
	return err.cause
}

func (documentSchemaError) DocumentViolation() bool {
	return true
}

func testReviewValidator(t *testing.T, schemaValidator SchemaValidator) *ReviewValidator {
	t.Helper()
	id, err := ports.ParseAssetID(ProviderReviewSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewReviewValidator(schemaValidator, id)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func testScope() ReviewValidationScope {
	return ReviewValidationScope{
		TargetSHA256:     strings.Repeat("a", 64),
		Role:             domain.RoleSecurity,
		ProviderInstance: "fake/security",
	}
}

func validProviderReview() []byte {
	return []byte(`{
		"schema_version":"kar-provider-review-output.v3",
		"summary":"A high severity issue was found.",
		"completeness":"complete",
		"limitations":[],
		"findings":[{
			"severity":"high",
			"title":"Fallback after valid review",
			"description":"The coordinator queues a fallback after it has accepted a valid finding.",
			"evidence":[{"current":{"path":"internal/app/coordinator.go","line_start":12,"line_end":14,"side":"head","quote":"queueFallback(task)"}}],
			"recommendation":"Queue fallback only for invalid provider output.",
			"confidence":"high"
		}]
	}`)
}

func providerReviewWith(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(validProviderReview(), &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestValidateReviewCompleteness(t *testing.T) {
	tooMany := make([]string, 21)
	for index := range tooMany {
		tooMany[index] = "limitation " + strconv.Itoa(index)
	}
	tooLong := strings.Repeat("界", 2001)

	invalid := []struct {
		name         string
		completeness string
		limitations  []string
	}{
		{name: "invalid completeness", completeness: "partial"},
		{name: "placeholder n a", completeness: "incomplete", limitations: []string{" N/A "}},
		{name: "placeholder tbd", completeness: "incomplete", limitations: []string{"\tTbD\n"}},
		{name: "placeholder todo", completeness: "incomplete", limitations: []string{" TODO "}},
		{name: "placeholder unknown", completeness: "incomplete", limitations: []string{" UnKnOwN "}},
		{name: "placeholder none", completeness: "incomplete", limitations: []string{" none "}},
		{name: "placeholder dash", completeness: "incomplete", limitations: []string{" - "}},
		{name: "duplicate", completeness: "complete", limitations: []string{"The test fixture was excluded.", "The test fixture was excluded."}},
		{name: "count limit", completeness: "complete", limitations: tooMany},
		{name: "rune limit", completeness: "complete", limitations: []string{tooLong}},
		{name: "material unreadable", completeness: "complete", limitations: []string{"The material scope was unreadable."}},
		{name: "material files unread", completeness: "complete", limitations: []string{"Material files could not be read."}},
		{name: "material files inaccessible", completeness: "complete", limitations: []string{"Material files could not be accessed."}},
		{name: "material scope uninspected", completeness: "complete", limitations: []string{"The target scope could not be inspected."}},
		{name: "material files unreviewed", completeness: "complete", limitations: []string{"Material files could not be reviewed."}},
		{name: "material files unloaded", completeness: "complete", limitations: []string{"Material files could not be loaded."}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReviewCompleteness(test.completeness, test.limitations); err == nil {
				t.Fatal("ValidateReviewCompleteness() error = nil")
			}
		})
	}

	valid := []struct {
		name         string
		completeness string
		limitations  []string
	}{
		{name: "complete informational limitation", completeness: "complete", limitations: []string{"Generated fixtures were outside the requested review scope."}},
		{name: "complete missing caller context", completeness: "complete", limitations: []string{"The review target is the captured diff only; caller context for ReadReport and the deployment trust boundary that determine whether name is attacker-controlled are not present, so exploitability depends on those assumptions even though the validation regression is present in the code."}},
		{name: "complete review target excludes callers", completeness: "complete", limitations: []string{"The review target does not include callers, so the degree of attacker control cannot be confirmed from the target alone."}},
		{name: "complete review target caller context unavailable", completeness: "complete", limitations: []string{"Callers of the exported function are not present in the review target, so exploitability cannot be confirmed from the target alone."}},
		{name: "complete unavailable test execution", completeness: "complete", limitations: []string{"Could not execute the Go toolchain or any test suite: the review workspace forbids command execution, and the snapshot contains no test files to invoke."}},
		{name: "incomplete meaningful limitation", completeness: "incomplete", limitations: []string{"Generated fixtures were outside the requested review scope."}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReviewCompleteness(test.completeness, test.limitations); err != nil {
				t.Fatalf("ValidateReviewCompleteness() error = %v", err)
			}
		})
	}
}

func TestReviewValidatorRejectsCompleteMaterialAccessLimitations(t *testing.T) {
	for _, limitation := range []string{
		"The material scope was unreadable.",
		"Material files could not be read.",
		"Material files could not be accessed.",
		"The target scope could not be inspected.",
		"Material files could not be reviewed.",
		"Material files were not reviewed.",
		"The provider could not review the target files.",
		"Material files could not be loaded.",
	} {
		t.Run(limitation, func(t *testing.T) {
			validator := testReviewValidator(t, &recordingSchemaValidator{})
			raw := providerReviewWith(t, func(document map[string]any) {
				document["limitations"] = []any{limitation}
			})
			_, plan, err := validator.Validate(context.Background(), raw, testScope())
			if err == nil || plan != nil || !errorChainContains(err, "complete review cannot state that material scope was unreadable") {
				t.Fatalf("limitation fixture %q did not return the expected typed rejection", limitation)
			}
		})
	}
}

func TestReviewValidatorInjectsTrustedIdentityAndNormalizesFindings(t *testing.T) {
	schema := &recordingSchemaValidator{}
	validator := testReviewValidator(t, schema)
	review, plan, err := validator.Validate(context.Background(), validProviderReview(), testScope())
	if err != nil {
		t.Fatal(err)
	}
	if plan != nil {
		t.Fatalf("repair plan = %#v, want nil", plan)
	}
	if len(schema.calls) != 2 || schema.calls[0].id.String() != ProviderReviewWireSchemaID || schema.calls[1].id.String() != ProviderReviewSchemaID {
		t.Fatalf("schema calls = %#v", schema.calls)
	}
	candidate, err := decodeJSONObject(schema.calls[1].raw, "candidate")
	if err != nil {
		t.Fatal(err)
	}
	finding := candidate["findings"].([]any)[0].(map[string]any)
	current := finding["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
	if current["target_sha256"] != "sha256:"+strings.Repeat("a", 64) || current["verification"] != "claimed" {
		t.Fatalf("injected current = %#v", current)
	}
	if _, exists := finding["source"]; exists {
		t.Fatalf("root review unexpectedly has source: %#v", finding)
	}
	findings := review.Findings()
	if len(findings) != 1 || findings[0].ID() != "F001" || findings[0].Role() != domain.RoleSecurity || findings[0].ProviderInstance() != "fake/security" || findings[0].EvidenceState() != domain.EvidenceUnverified {
		t.Fatalf("normalized finding = %#v", findings)
	}
	original := review.OriginalRaw()
	original[0] = '!'
	if string(review.OriginalRaw()) != string(validProviderReview()) {
		t.Fatal("OriginalRaw leaked mutable storage")
	}
}

func TestReviewValidatorRequiresCapturedVisualIdentityForArtistFindings(t *testing.T) {
	const path = "design-specs/home.png"
	const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	raw := providerReviewWith(t, func(document map[string]any) {
		evidence := document["findings"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)
		evidence["visual"] = map[string]any{
			"path": path, "sha256": digest,
			"bbox": map[string]any{"x": 0, "y": 12, "width": 44, "height": 20},
		}
	})
	scope := testScope()
	scope.Role = domain.RoleArtist
	scope.VisualAssets = map[string]string{path: digest}
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	validated, plan, err := validator.Validate(context.Background(), raw, scope)
	if err != nil || plan != nil {
		t.Fatalf("captured visual identity rejected: plan=%v err=%v", plan, err)
	}
	visuals := validated.EvidenceClaims()[0].VisualReferences()
	if len(visuals) != 1 || visuals[0].Path().String() != path || visuals[0].SHA256() != digest ||
		visuals[0].X() != 0 || visuals[0].Y() != 12 || visuals[0].Width() != 44 || visuals[0].Height() != 20 ||
		visuals[0].Verification() != "verified" {
		t.Fatalf("verified visual reference was not retained: %#v", visuals)
	}
	scope.VisualAssets[path] = "sha256:" + strings.Repeat("c", 64)
	if _, _, err := validator.Validate(context.Background(), raw, scope); err == nil || !strings.Contains(err.Error(), "candidate_validation_failed") {
		t.Fatalf("mismatched visual identity was accepted: %v", err)
	}
}
func TestReviewValidatorCorrelatesEvidenceClaimsAfterFindingOrdering(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		first := document["findings"].([]any)[0].(map[string]any)
		first["severity"] = "low"
		first["title"] = "Later finding"
		first["description"] = "This finding sorts after the critical finding."
		first["recommendation"] = "Address the later finding."
		first["evidence"] = []any{map[string]any{"current": map[string]any{
			"path": "internal/app/zeta.go", "line_start": 20, "line_end": 20, "side": "head", "quote": "later quote",
		}}}
		document["findings"] = []any{
			first,
			map[string]any{
				"severity":       "critical",
				"title":          "Earlier finding",
				"description":    "This finding sorts before the low finding.",
				"recommendation": "Address the earlier finding.",
				"confidence":     "high",
				"evidence": []any{map[string]any{"current": map[string]any{
					"path": "internal/app/alpha.go", "line_start": 3, "line_end": 4, "side": "base", "quote": "earlier quote",
				}}},
			},
		}
	})

	review, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err != nil || plan != nil {
		t.Fatalf("validation: review=%#v plan=%#v err=%v", review, plan, err)
	}
	findings, evidenceGroups := review.Findings(), review.EvidenceClaims()
	if len(findings) != 2 || len(evidenceGroups) != 2 {
		t.Fatalf("findings=%#v evidence groups=%#v", findings, evidenceGroups)
	}
	if findings[0].ID() != "F001" || findings[0].Title() != "Earlier finding" {
		t.Fatalf("ordered findings = %#v", findings)
	}
	if evidenceGroups[0].FindingID() != findings[0].ID() {
		t.Fatalf("first evidence group ID = %q, want %q", evidenceGroups[0].FindingID(), findings[0].ID())
	}
	if got := evidenceGroups[0].Finding(); got != findings[0] || !evidenceGroups[0].MatchesFinding(findings[0]) {
		t.Fatalf("first evidence group finding proof = %#v, want %#v", got, findings[0])
	}
	claims := evidenceGroups[0].Claims()
	if len(claims) != 1 || string(claims[0].QuoteBytes()) != "earlier quote" {
		t.Fatalf("first evidence claims = %#v", claims)
	}
	if got, want := claims[0].TargetSHA256(), "sha256:"+strings.Repeat("a", 64); got != want {
		t.Fatalf("claim target SHA-256 = %q, want %q", got, want)
	}
	if got := claims[0].Side(); got != CurrentEvidenceSideBase || !claims[0].Path().Valid() {
		t.Fatalf("claim side/path = %q/%#v", got, claims[0].Path())
	}
	for _, method := range []string{"Verification", "VerificationState", "SetVerification", "SetVerificationState"} {
		if _, exists := reflect.TypeOf(CurrentEvidenceClaim{}).MethodByName(method); exists {
			t.Fatalf("CurrentEvidenceClaim exposes verification authority through %s", method)
		}
	}
}

func TestReviewValidatorEvidenceClaimsUseNormalizedOrderAndDefensiveCopies(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		finding := document["findings"].([]any)[0].(map[string]any)
		finding["evidence"] = []any{
			map[string]any{"current": map[string]any{
				"path": "internal/app/zeta.go", "line_start": 2, "line_end": 2, "side": "base", "quote": "zeta base quote\n",
			}},
			map[string]any{"current": map[string]any{
				"path": "internal/app/alpha.go", "line_start": 10, "line_end": 10, "side": "worktree", "quote": "alpha ten quote\n",
			}},
			map[string]any{"current": map[string]any{
				"path": "internal/app/alpha.go", "line_start": 2, "line_end": 10, "side": "head", "quote": "alpha two through ten quote\n",
			}},
			map[string]any{"current": map[string]any{
				"path": "internal/app/alpha.go", "line_start": 2, "line_end": 2, "side": "base", "quote": "alpha two quote\n",
			}},
		}
	})

	review, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err != nil || plan != nil {
		t.Fatalf("validation: review=%#v plan=%#v err=%v", review, plan, err)
	}
	groups := review.EvidenceClaims()
	if len(groups) != 1 {
		t.Fatalf("evidence groups = %#v", groups)
	}
	claims := groups[0].Claims()
	wantClaims := []struct {
		path      string
		lineStart int
		lineEnd   int
		side      CurrentEvidenceSide
		quote     string
	}{
		{path: "internal/app/alpha.go", lineStart: 2, lineEnd: 2, side: CurrentEvidenceSideBase, quote: "alpha two quote\n"},
		{path: "internal/app/alpha.go", lineStart: 2, lineEnd: 10, side: CurrentEvidenceSideHead, quote: "alpha two through ten quote\n"},
		{path: "internal/app/alpha.go", lineStart: 10, lineEnd: 10, side: CurrentEvidenceSideWorktree, quote: "alpha ten quote\n"},
		{path: "internal/app/zeta.go", lineStart: 2, lineEnd: 2, side: CurrentEvidenceSideBase, quote: "zeta base quote\n"},
	}
	if len(claims) != len(wantClaims) {
		t.Fatalf("claim count = %d, want %d", len(claims), len(wantClaims))
	}
	for index, want := range wantClaims {
		claim := claims[index]
		if claim.Path().String() != want.path || claim.LineStart() != want.lineStart || claim.LineEnd() != want.lineEnd || claim.Side() != want.side || string(claim.QuoteBytes()) != want.quote {
			t.Errorf("claim %d = %#v, want path=%q line=%d-%d side=%q quote=%q", index, claim, want.path, want.lineStart, want.lineEnd, want.side, want.quote)
		}
	}

	quote := claims[0].QuoteBytes()
	quote[0] = 'X'
	claims[0] = CurrentEvidenceClaim{}
	groups[0] = FindingEvidenceClaims{}
	freshGroups := review.EvidenceClaims()
	freshClaims := freshGroups[0].Claims()
	if freshGroups[0].FindingID() == "" ||
		!freshGroups[0].MatchesFinding(review.Findings()[0]) ||
		string(freshClaims[0].QuoteBytes()) != "alpha two quote\n" {
		t.Fatalf("EvidenceClaims leaked mutable storage: %#v", freshGroups)
	}
}
func TestFindingEvidenceClaimsFailClosedOnProofIDOrClaimDisagreement(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	review, plan, err := validator.Validate(context.Background(), validProviderReview(), testScope())
	if err != nil || plan != nil {
		t.Fatalf("validation: review=%#v plan=%#v err=%v", review, plan, err)
	}
	finding := review.Findings()[0]
	group := review.EvidenceClaims()[0]
	claims := group.Claims()
	trustedTarget := claims[0].TargetSHA256()

	if _, err := newFindingEvidenceClaims(finding, claims, make([]VerifiedVisualReference, len(claims)), trustedTarget); err != nil {
		t.Fatalf("newFindingEvidenceClaims() error = %v", err)
	}
	claims[0].targetSHA256 = "sha256:" + strings.Repeat("b", 64)
	if _, err := newFindingEvidenceClaims(finding, claims, make([]VerifiedVisualReference, len(claims)), trustedTarget); err == nil {
		t.Fatal("newFindingEvidenceClaims() accepted a mismatched target claim")
	}

	claims = group.Claims()
	claims[0].quote = []byte("changed quote")
	if _, err := newFindingEvidenceClaims(finding, claims, make([]VerifiedVisualReference, len(claims)), trustedTarget); err == nil {
		t.Fatal("newFindingEvidenceClaims() accepted a mismatched quote claim")
	}

	group.findingID = "F002"
	if group.MatchesFinding(finding) {
		t.Fatal("MatchesFinding() accepted a mismatched proof ID")
	}
}

func TestReviewValidatorRepairUpdatesEvidenceClaims(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	original := providerReviewWith(t, func(document map[string]any) {
		finding := document["findings"].([]any)[0].(map[string]any)
		current := finding["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
		current["quote"] = "TBD"
	})
	_, plan, err := validator.Validate(context.Background(), original, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields {
		t.Fatalf("classification: plan=%#v err=%v", plan, err)
	}
	patch := marshalRepairPatch(t, []map[string]any{{
		"path":  "/findings/0/evidence/0/current/quote",
		"value": "repaired exact quote\n",
	}})
	review, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan)
	if err != nil {
		t.Fatal(err)
	}
	groups := review.EvidenceClaims()
	if !review.Repaired() || len(groups) != 1 || string(groups[0].Claims()[0].QuoteBytes()) != "repaired exact quote\n" {
		t.Fatalf("repaired review claims = %#v", groups)
	}
	if string(review.OriginalRaw()) != string(original) || string(review.RepairedRaw()) != string(patch) {
		t.Fatalf("repair raw lineage changed: original=%q repaired=%q", review.OriginalRaw(), review.RepairedRaw())
	}
}

func TestNormalizeFindingsRejectsEvidenceCorrelationCollision(t *testing.T) {
	evidence := providerEvidence{
		path:      "internal/app/collision.go",
		lineStart: 1,
		lineEnd:   1,
		side:      "head",
		quote:     "collision quote",
	}
	finding := providerFinding{
		severity:       domain.SeverityHigh,
		title:          "Collision",
		description:    "Two identical normalized findings cannot be correlated safely.",
		recommendation: "Remove the duplicate finding.",
		confidence:     domain.ConfidenceHigh,
		evidence:       []providerEvidence{evidence},
	}
	_, _, err := normalizeFindings(
		[]providerFinding{finding, finding},
		testScope(),
		"sha256:"+strings.Repeat("a", 64),
	)
	if err == nil || !strings.Contains(err.Error(), "correlation collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestReviewValidatorRejectsStrictJSONAndOwnershipViolations(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	for _, raw := range [][]byte{
		nil,
		[]byte(`null`),
		[]byte(`[]`),
		[]byte("```json\n{}\n```"),
		[]byte(`{} {}`),
		[]byte{'{', 0xff, '}'},
		[]byte(`{"summary":"first","summary":"second"}`),
		[]byte(`{"summary":"value"} trailing`),
		[]byte(`{"summary":"\ud800"}`),
	} {
		_, plan, err := validator.Validate(context.Background(), raw, testScope())
		if err == nil || plan == nil || plan.Mode() != RepairModeReformatOnly {
			t.Fatalf("raw %q: err=%v plan=%#v, want reformat-only error", raw, err, plan)
		}
	}

	systemOwned := providerReviewWith(t, func(document map[string]any) {
		document["session_id"] = "s_00000000-0000-7000-8000-000000000000"
	})
	if _, plan, err := validator.Validate(context.Background(), systemOwned, testScope()); err == nil || plan != nil {
		t.Fatal("system-owned input was accepted")
	} else if cause, ok := RuntimeCause(err); !ok || cause != domain.DiagnosticCauseObservationMismatch {
		t.Fatalf("system-owned cause = %q, present = %t", cause, ok)
	}
	providerTarget := providerReviewWith(t, func(document map[string]any) {
		finding := document["findings"].([]any)[0].(map[string]any)
		current := finding["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
		current["target_sha256"] = "sha256:" + strings.Repeat("b", 64)
	})
	if _, plan, err := validator.Validate(context.Background(), providerTarget, testScope()); err == nil || plan != nil {
		t.Fatal("provider target identity was accepted")
	} else if cause, ok := RuntimeCause(err); !ok || cause != domain.DiagnosticCauseObservationMismatch {
		t.Fatalf("provider target cause = %q, present = %t", cause, ok)
	}
}

func TestReviewValidatorClassifiesOnlyMissingOrInvalidProviderValuesForRepair(t *testing.T) {
	schema := &recordingSchemaValidator{}
	validator := testReviewValidator(t, schema)
	placeholder := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = " TBD "
	})
	_, plan, err := validator.Validate(context.Background(), placeholder, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/summary" {
		t.Fatalf("placeholder: err=%v plan=%#v", err, plan)
	}
	contradiction := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "No findings were identified."
	})
	if _, plan, err := validator.Validate(context.Background(), contradiction, testScope()); err == nil || plan != nil {
		t.Fatalf("contradiction: err=%v plan=%#v", err, plan)
	}
	invalidEnum := providerReviewWith(t, func(document map[string]any) {
		document["completeness"] = "probably"
	})
	_, plan, err = validator.Validate(context.Background(), invalidEnum, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/completeness" {
		t.Fatalf("invalid enum: err=%v plan=%#v", err, plan)
	}

	schema.err = errors.New("schema rejected")
	if _, plan, err := validator.Validate(context.Background(), validProviderReview(), testScope()); err == nil || plan != nil {
		t.Fatalf("unclassified schema error: err=%v plan=%#v", err, plan)
	}
}

func TestReviewValidatorAcceptsValidNegativeReview(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "No findings were identified in the reviewed scope."
		document["findings"] = []any{}
	})
	review, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err != nil || plan != nil || len(review.Findings()) != 0 || review.Repaired() {
		t.Fatalf("negative review: review=%#v plan=%#v err=%v", review, plan, err)
	}
}

func TestReviewValidatorOnlyRepairsDocumentViolations(t *testing.T) {
	operationalCause := errors.New("schema compiler unavailable")
	schema := &recordingSchemaValidator{err: operationalCause}
	validator := testReviewValidator(t, schema)
	placeholder := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "TBD"
	})

	_, plan, err := validator.Validate(context.Background(), placeholder, testScope())
	if err == nil || plan != nil || !errors.Is(err, operationalCause) {
		t.Fatalf("operational schema failure: err=%v plan=%#v", err, plan)
	}

	documentCause := errors.New("review field has wrong type")
	schema.err = documentSchemaError{cause: documentCause}
	_, plan, err = validator.Validate(context.Background(), placeholder, testScope())
	if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields || !errors.Is(err, documentCause) {
		t.Fatalf("document schema failure: err=%v plan=%#v", err, plan)
	}

	contradiction := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "No findings were identified."
	})
	_, plan, err = validator.Validate(context.Background(), contradiction, testScope())
	if err == nil || plan != nil || !errors.Is(err, documentCause) || !errorChainContains(err, "summary claims no findings") {
		t.Fatal("schema and semantic failures did not retain their typed causes")
	}
}

func TestReviewValidatorRepairsIncompleteLimitationElements(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		value any
	}{
		{name: "placeholder", value: " TBD "},
		{name: "number", value: 7},
		{name: "boolean", value: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			validator := testReviewValidator(t, &recordingSchemaValidator{})
			original := providerReviewWith(t, func(document map[string]any) {
				document["completeness"] = "incomplete"
				document["limitations"] = []any{testCase.value}
			})

			_, plan, err := validator.Validate(context.Background(), original, testScope())
			if err == nil || plan == nil || plan.Mode() != RepairModeFillMissingFields || len(plan.AllowedPaths()) != 1 || plan.AllowedPaths()[0] != "/limitations/0" {
				t.Fatalf("classification: err=%v plan=%#v", err, plan)
			}

			patch := marshalRepairPatch(t, []map[string]any{{
				"path":  "/limitations/0",
				"value": "The provider could not inspect generated configuration.",
			}})
			review, err := validator.ApplyRepair(context.Background(), original, patch, testScope(), *plan)
			if err != nil {
				t.Fatal(err)
			}
			if got := review.Limitations(); len(got) != 1 || got[0] != "The provider could not inspect generated configuration." {
				t.Fatalf("limitations = %#v", got)
			}
		})
	}

	validator := testReviewValidator(t, &recordingSchemaValidator{})
	empty := providerReviewWith(t, func(document map[string]any) {
		document["completeness"] = "incomplete"
		document["limitations"] = []any{}
	})
	if _, plan, err := validator.Validate(context.Background(), empty, testScope()); err == nil || plan != nil {
		t.Fatalf("empty incomplete limitations: err=%v plan=%#v", err, plan)
	}
}

func TestReviewValidatorRejectsUnfulfillableRepairPlan(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		delete(document, "summary")
		finding := document["findings"].([]any)[0].(map[string]any)
		evidence := make([]any, 20)
		for index := range evidence {
			evidence[index] = map[string]any{"current": map[string]any{}}
		}
		finding["evidence"] = evidence
	})

	_, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err == nil || plan != nil || !errorChainContains(err, "repair requires 101 paths") {
		t.Fatal("unfulfillable repair did not retain its typed cause")
	}
}

func TestReviewValidatorRejectsWhitespaceAndCaseDuplicateFindings(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		first := document["findings"].([]any)[0].(map[string]any)
		first["evidence"] = []any{
			map[string]any{"current": map[string]any{
				"path": "internal/app/alpha.go", "line_start": 12, "line_end": 14, "side": "head", "quote": "first quote",
			}},
			map[string]any{"current": map[string]any{
				"path": "internal/app/beta.go", "line_start": 20, "line_end": 22, "side": "head", "quote": "second quote",
			}},
		}

		secondRaw, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		var second map[string]any
		if err := json.Unmarshal(secondRaw, &second); err != nil {
			t.Fatal(err)
		}
		second["title"] = "  FALLBACK  AFTER VALID REVIEW  "
		second["description"] = "  THE COORDINATOR QUEUES A FALLBACK AFTER IT HAS ACCEPTED A VALID FINDING. "
		second["recommendation"] = "  QUEUE FALLBACK ONLY FOR INVALID PROVIDER OUTPUT.  "
		evidence := second["evidence"].([]any)
		for _, value := range evidence {
			current := value.(map[string]any)["current"].(map[string]any)
			current["quote"] = strings.ToUpper("  " + current["quote"].(string) + "  ")
		}
		second["evidence"] = []any{evidence[1], evidence[0]}
		document["findings"] = []any{first, second}
	})

	if _, plan, err := validator.Validate(context.Background(), raw, testScope()); err == nil || plan != nil || !errorChainContains(err, "duplicate normalized finding content") {
		t.Fatal("duplicate findings did not retain their typed cause")
	}
}

func errorChainContains(err error, fragment string) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), fragment) {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, nested := range joined.Unwrap() {
			if errorChainContains(nested, fragment) {
				return true
			}
		}
		return false
	}
	return errorChainContains(errors.Unwrap(err), fragment)
}

func TestReviewValidatorKeepsCaseDistinctPathsAndQualifiedSummaries(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "No issues in package A; one vulnerability remains in package B."
		first := document["findings"].([]any)[0].(map[string]any)
		secondRaw, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		var second map[string]any
		if err := json.Unmarshal(secondRaw, &second); err != nil {
			t.Fatal(err)
		}
		firstCurrent := first["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
		secondCurrent := second["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)
		firstCurrent["path"] = "internal/app/Review.go"
		secondCurrent["path"] = "internal/app/review.go"
		document["findings"] = []any{first, second}
	})

	review, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err != nil || plan != nil || len(review.Findings()) != 2 {
		t.Fatalf("case-distinct qualified review: findings=%#v plan=%#v err=%v", review.Findings(), plan, err)
	}
}

func TestReviewValidationReturnsDefensiveCopies(t *testing.T) {
	validator := testReviewValidator(t, &recordingSchemaValidator{})
	raw := providerReviewWith(t, func(document map[string]any) {
		document["limitations"] = []any{"The provider could not inspect generated configuration."}
	})
	review, plan, err := validator.Validate(context.Background(), raw, testScope())
	if err != nil || plan != nil {
		t.Fatalf("validation: review=%#v plan=%#v err=%v", review, plan, err)
	}
	limitations := review.Limitations()
	limitations[0] = "mutated"
	if got := review.Limitations(); got[0] != "The provider could not inspect generated configuration." {
		t.Fatalf("Limitations leaked mutable storage: %#v", got)
	}

	placeholder := providerReviewWith(t, func(document map[string]any) {
		document["summary"] = "TBD"
	})
	_, plan, err = validator.Validate(context.Background(), placeholder, testScope())
	if err == nil || plan == nil {
		t.Fatalf("classification: err=%v plan=%#v", err, plan)
	}
	paths := plan.AllowedPaths()
	paths[0] = "/findings"
	if got := plan.AllowedPaths(); len(got) != 1 || got[0] != "/summary" {
		t.Fatalf("AllowedPaths leaked mutable storage: %#v", got)
	}
}
