package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type assessmentReader struct {
	ports.LiveSourceReader
	target ports.LiveSourceTarget
	reads  int
	err    error
}

func (r *assessmentReader) Target() ports.LiveSourceTarget { return r.target }
func (r *assessmentReader) Read(_ context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	r.reads++
	if r.err != nil {
		return ports.LiveSourceFile{}, r.err
	}
	if side != domain.LiveSourceIndex || path.String() != "reader.go" {
		return ports.LiveSourceFile{}, ports.NewLiveSourceError(ports.LiveSourceInvalid, fmt.Errorf("not selected"))
	}
	return ports.NewLiveSourceFile(path, []byte("readIndex(path)\n"), "text/plain")
}
func assessmentFixture(t *testing.T) (RequirementsInput, *assessmentReader, evidence.LiveSourceIdentity, *evidence.Verifier) {
	t.Helper()
	raw := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"A","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"B","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"},{"id":"C","text":"description","acceptance_criteria":["criterion"],"owner_role":"logic"}]}`)
	input, err := DecodeRequirementsInput(raw, []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	oid, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	p, _ := ports.NewSafeRelativePath("reader.go")
	target, err := ports.NewLiveSourceTarget(selector, oid, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "modified", Before: p, After: p}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &assessmentReader{target: target}
	identity, _ := evidence.NewLiveSourceIdentity(target)
	verifier, _ := evidence.NewLiveVerifier(reader)
	return input, reader, identity, verifier
}
func assessmentRow(id, verdict string) map[string]any {
	reason := ""
	if verdict == "unverified" {
		reason = "insufficient_evidence"
	}
	return map[string]any{"requirement_id": id, "verdict": verdict, "rationale": "The admitted index demonstrates this judgment.", "evidence": []any{map[string]any{"current": map[string]any{"path": "reader.go", "side": "index", "line_start": 1, "line_end": 1, "quote": "readIndex(path)\n"}}}, "examined_scope": "Selected reader.go index", "limitations": []any{"No execution proof."}, "reason": reason}
}
func assessmentSection(rows ...map[string]any) []byte {
	raw, _ := json.Marshal(map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": rows})
	return raw
}

func TestRequirementsProviderDecodingVerifiesEveryVerdictAndCounts(t *testing.T) {
	input, reader, identity, verifier := assessmentFixture(t)
	for _, verdict := range []string{"met", "partially_met", "unmet", "unverified"} {
		t.Run(verdict, func(t *testing.T) {
			row := assessmentRow("A", verdict)
			if verdict == "unmet" {
				row["evidence"] = []any{}
			}
			answers, err := DecodeProviderRequirements(context.Background(), assessmentSection(row, assessmentRow("B", "unverified")), input.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", input.SHA256())
			if err != nil {
				t.Fatal(err)
			}
			result, err := NormalizeRequirements(input, answers, nil, identity.SHA256(), false)
			if err != nil {
				t.Fatal(err)
			}
			selected, evaluated, known := result.Evaluation().Counts()
			if !known || selected != 3 || evaluated != 2 || result.Evaluation().Assessments()[2].Reason() != domain.AssessmentAnswerOmitted {
				t.Fatal("dishonest normalization")
			}
			if result.Evaluation().Assessments()[0].Verdict() != domain.RequirementVerdict(verdict) || result.Evaluation().Assessments()[1].Origin() != domain.AssessmentProvider {
				t.Fatal("provider answer changed")
			}
		})
	}
	if reader.reads == 0 {
		t.Fatal("did not verify source")
	}
}
func TestRequirementsProviderRejectsInvalidOwningSectionsAndProtectedFields(t *testing.T) {
	input, reader, identity, verifier := assessmentFixture(t)
	cases := []struct {
		name      string
		mutate    func(map[string]any)
		protected bool
	}{
		{"foreign", func(r map[string]any) { r["requirement_id"] = "foreign" }, false},
		{"wrong side", func(r map[string]any) {
			r["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["side"] = "worktree"
		}, false},
		{"false quote", func(r map[string]any) {
			r["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["quote"] = "worktree bytes\n"
		}, false},
		{"input is not proof", func(r map[string]any) {
			r["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["path"] = "requirements.json"
		}, false},
		{"no support", func(r map[string]any) { r["evidence"] = []any{} }, false},
		{"absence without limitations", func(r map[string]any) { r["verdict"] = "unmet"; r["evidence"] = []any{}; r["limitations"] = []any{} }, false},
		{"unknown verdict", func(r map[string]any) { r["verdict"] = "passed" }, false},
		{"NUL", func(r map[string]any) { r["rationale"] = "bad\x00" }, false},
		{"reason type", func(r map[string]any) { r["reason"] = false }, false},
		{"scope array", func(r map[string]any) { r["examined_scope"] = []any{"reader.go"} }, false},
		{"owner injection", func(r map[string]any) { r["owner_role"] = "logic" }, true},
		{"verification injection", func(r map[string]any) {
			r["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["verification"] = "verified"
		}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			row := assessmentRow("A", "met")
			test.mutate(row)
			_, err := DecodeProviderRequirements(context.Background(), assessmentSection(row), input.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", input.SHA256())
			if err == nil {
				t.Fatal("invalid section accepted")
			}
			cause, ok := RuntimeCause(err)
			if test.protected && (!ok || cause != domain.DiagnosticCauseProviderOwnershipViolation) {
				t.Fatalf("ownership attack lost protected identity: %v", err)
			}
		})
	}
	for _, rows := range [][]map[string]any{{assessmentRow("A", "met"), assessmentRow("A", "met")}, {assessmentRow("A", "met")}} {
		role := domain.RoleLogic
		if len(rows) == 1 {
			role = domain.RoleSecurity
		}
		if _, err := DecodeProviderRequirements(context.Background(), assessmentSection(rows...), input.Requirements(), role, identity, verifier, nil, "requirements.json", input.SHA256()); err == nil {
			t.Fatal("duplicate/wrong owner accepted")
		}
	}
	reader.err = ports.NewLiveSourceError(ports.LiveSourceUnsafe, errors.New("protected source changed"))
	_, err := DecodeProviderRequirements(context.Background(), assessmentSection(assessmentRow("A", "met")), input.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", input.SHA256())
	sourceErr, ok := RequirementsSourceFailure(err)
	var typed *ports.LiveSourceError
	if !ok || !errors.As(sourceErr, &typed) || typed.Code() != ports.LiveSourceUnsafe {
		t.Fatal("source failure lost its typed cause")
	}
}
func TestRequirementsProviderContentIsUnboundedAndWholeJSONIsStrict(t *testing.T) {
	input, _, identity, verifier := assessmentFixture(t)
	row := assessmentRow("A", "unverified")
	row["rationale"] = strings.Repeat("r", 9<<20)
	row["limitations"] = []any{strings.Repeat("l", 9<<20)}
	raw := assessmentSection(row)
	answers, err := DecodeProviderRequirements(context.Background(), raw, input.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", input.SHA256())
	if err != nil || len(answers) != 1 || len(answers[0].Content()) <= 18<<20 {
		t.Fatalf("content ceiling: %v", err)
	}
	for _, raw := range [][]byte{[]byte(`{"requirements":{},`), []byte(`{"requirements":{},"requirements":{}}`), []byte("{\"summary\":\"\xff\"}"), []byte(`{"summary":"\ud800"}`)} {
		if _, _, _, err := SplitRequirementsResponse(raw); err == nil {
			t.Fatal("invalid whole response yielded a section")
		}
	}
}

func TestRequirementsProviderVisualEvidenceKeepsRoleAndSourceSide(t *testing.T) {
	_, _, identity, verifier := assessmentFixture(t)
	selected, _ := domain.NewRequirement("A", "Design", []string{"criterion"}, domain.RoleArtist)
	row := assessmentRow("A", "met")
	digest := "sha256:" + strings.Repeat("a", 64)
	row["evidence"].([]any)[0].(map[string]any)["visual"] = map[string]any{"path": "design.png", "sha256": digest, "bbox": map[string]any{"x": 0, "y": 0, "width": 1, "height": 1}}
	for _, test := range []struct {
		name   string
		images map[string]string
		valid  bool
	}{
		{"selected index", map[string]string{"index\x00design.png": digest}, true}, {"wrong source side", map[string]string{"head\x00design.png": digest}, false}, {"missing image", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			answers, err := DecodeProviderRequirements(context.Background(), assessmentSection(row), []domain.Requirement{selected}, domain.RoleArtist, identity, verifier, test.images, "requirements.json", "sha256:"+strings.Repeat("b", 64))
			if (err == nil) != test.valid {
				t.Fatalf("visual source admission: %v", err)
			}
			if test.valid && len(answers) != 1 {
				t.Fatal("verified visual answer lost")
			}
		})
	}
}

func TestRequirementsProviderClosedKeyOwnershipAndPrecedence(t *testing.T) {
	input, _, identity, verifier := assessmentFixture(t)
	artistReq, err := domain.NewRequirement("A", "Design", []string{"criterion"}, domain.RoleArtist)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	visualImages := map[string]string{"index\x00design.png": digest}

	makeVisualRow := func() map[string]any {
		row := assessmentRow("A", "met")
		row["evidence"].([]any)[0].(map[string]any)["visual"] = map[string]any{
			"path":   "design.png",
			"sha256": digest,
			"bbox":   map[string]any{"x": 0, "y": 0, "width": 1, "height": 1},
		}
		return row
	}
	decodeSection := func(section map[string]any, role domain.Role) error {
		raw, marshalErr := json.Marshal(section)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		reqs := input.Requirements()
		images := map[string]string(nil)
		if role == domain.RoleArtist {
			reqs = []domain.Requirement{artistReq}
			images = visualImages
		}
		_, decodeErr := DecodeProviderRequirements(context.Background(), raw, reqs, role, identity, verifier, images, "requirements.json", input.SHA256())
		return decodeErr
	}

	t.Run("ordinary unknown keys are bounded non-security failures across all five objects", func(t *testing.T) {
		locations := []struct {
			name   string
			role   domain.Role
			mutate func(section map[string]any, key string)
		}{
			{"requirements", domain.RoleLogic, func(s map[string]any, k string) { s[k] = "extra" }},
			{"assessment", domain.RoleLogic, func(s map[string]any, k string) {
				s["assessments"].([]any)[0].(map[string]any)[k] = "extra"
			}},
			{"evidence", domain.RoleLogic, func(s map[string]any, k string) {
				s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)[k] = "extra"
			}},
			{"current", domain.RoleLogic, func(s map[string]any, k string) {
				s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)[k] = "extra"
			}},
			{"visual", domain.RoleArtist, func(s map[string]any, k string) {
				s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["visual"].(map[string]any)[k] = "extra"
			}},
		}
		for _, loc := range locations {
			for _, key := range []string{"notes", "confidence_score", "schema_version", ""} {
				if loc.name == "requirements" && key == "schema_version" {
					continue // schema_version is an allowed key on requirements section
				}
				row := assessmentRow("A", "met")
				if loc.role == domain.RoleArtist {
					row = makeVisualRow()
				}
				section := map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{row}}
				loc.mutate(section, key)
				decodeErr := decodeSection(section, loc.role)
				if decodeErr == nil {
					t.Fatalf("%s unknown key %q was accepted", loc.name, key)
				}
				cause, ok := RuntimeCause(decodeErr)
				if !ok || cause != domain.DiagnosticCauseCandidateValidationFailed {
					t.Fatalf("%s unknown key %q cause = (%q, %t), want candidate_validation_failed (err=%v)", loc.name, key, cause, ok, decodeErr)
				}
			}
		}
	})

	t.Run("every closed protected key across all five objects fails with provider_ownership_violation", func(t *testing.T) {
		protectedSets := []struct {
			name   string
			role   domain.Role
			keys   []string
			mutate func(section map[string]any, key string)
		}{
			{
				name: "requirements",
				role: domain.RoleLogic,
				keys: []string{"owner", "owner_role", "origin", "counts", "selected_count", "evaluated_count", "availability", "input_path", "input_sha256", "input_digest", "input_byte_length", "verification", "publication_status", "review_id", "run_id", "session_id", "attempt_id", "invocation_id", "execution_invocation_id", "source_identity_sha256", "target_sha256"},
				mutate: func(s map[string]any, k string) {
					s[k] = "forged"
				},
			},
			{
				name: "assessment",
				role: domain.RoleLogic,
				keys: []string{"owner", "owner_role", "origin", "counts", "input_digest", "input_sha256", "verification", "publication_status", "review_id", "run_id", "session_id", "attempt_id", "invocation_id", "execution_invocation_id", "source_identity_sha256", "target_sha256", "content_path", "content_sha256", "content_byte_length"},
				mutate: func(s map[string]any, k string) {
					s["assessments"].([]any)[0].(map[string]any)[k] = "forged"
				},
			},
			{
				name: "evidence",
				role: domain.RoleLogic,
				keys: []string{"verification", "owner", "owner_role", "origin", "source_identity_sha256", "target_sha256", "current_excerpt_sha256", "excerpt_sha256"},
				mutate: func(s map[string]any, k string) {
					s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)[k] = "forged"
				},
			},
			{
				name: "current",
				role: domain.RoleLogic,
				keys: []string{"verification", "source_identity_sha256", "target_sha256", "current_excerpt_sha256", "excerpt_sha256", "owner", "owner_role", "origin", "review_id", "run_id", "session_id", "attempt_id"},
				mutate: func(s map[string]any, k string) {
					s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)[k] = "forged"
				},
			},
			{
				name: "visual",
				role: domain.RoleArtist,
				keys: []string{"verification", "owner", "owner_role", "origin", "source_identity_sha256", "target_sha256"},
				mutate: func(s map[string]any, k string) {
					s["assessments"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["visual"].(map[string]any)[k] = "forged"
				},
			},
		}
		for _, set := range protectedSets {
			for _, key := range set.keys {
				row := assessmentRow("A", "met")
				if set.role == domain.RoleArtist {
					row = makeVisualRow()
				}
				section := map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{row}}
				set.mutate(section, key)
				decodeErr := decodeSection(section, set.role)
				if decodeErr == nil {
					t.Fatalf("%s protected key %q was accepted", set.name, key)
				}
				cause, ok := RuntimeCause(decodeErr)
				if !ok || cause != domain.DiagnosticCauseProviderOwnershipViolation {
					t.Fatalf("%s protected key %q cause = (%q, %t), want provider_ownership_violation (err=%v)", set.name, key, cause, ok, decodeErr)
				}
			}
		}
	})

	t.Run("mixed protected and ordinary unknown keys deterministically prioritize protected keys", func(t *testing.T) {
		for i := 0; i < 64; i++ {
			row := assessmentRow("A", "met")
			row["aaa_unknown"] = "ordinary"
			row["000_unknown"] = "ordinary"
			row["zzz_unknown"] = "ordinary"
			row["verification"] = "verified"
			row["attempt_id"] = "a_forged"
			section := map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{row}}
			decodeErr := decodeSection(section, domain.RoleLogic)
			cause, ok := RuntimeCause(decodeErr)
			if !ok || cause != domain.DiagnosticCauseProviderOwnershipViolation {
				t.Fatalf("iteration %d: mixed keys cause = (%q, %t), want provider_ownership_violation", i, cause, ok)
			}
			var ownership *ownershipViolation
			if !errors.As(decodeErr, &ownership) || !strings.Contains(ownership.Unwrap().Error(), "assessment.attempt_id") {
				t.Fatalf("iteration %d: expected lexicographically smallest protected key assessment.attempt_id, got %v", i, decodeErr)
			}
		}
	})

	t.Run("outer unknown key or earlier invalid row cannot mask nested or later protected keys", func(t *testing.T) {
		// Case 1: outer ordinary unknown key + nested assessment protected key.
		rowWithProtected := assessmentRow("A", "met")
		rowWithProtected["owner_role"] = "logic"
		outerUnknown := map[string]any{
			"schema_version": "mulgae-provider-requirements.v1",
			"notes":          "ordinary unknown outer key",
			"assessments":    []any{rowWithProtected},
		}
		errOuter := decodeSection(outerUnknown, domain.RoleLogic)
		if cause, ok := RuntimeCause(errOuter); !ok || cause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("outer unknown + nested protected cause = (%q, %t), want provider_ownership_violation (err=%v)", cause, ok, errOuter)
		}

		// Case 2: earlier row has ordinary unknown key AND invalid verdict, later row has nested current.verification.
		badFirst := assessmentRow("A", "invalid_verdict")
		badFirst["extra_note"] = "ordinary unknown"
		secondProtected := assessmentRow("A", "met")
		secondProtected["evidence"].([]any)[0].(map[string]any)["current"].(map[string]any)["verification"] = "verified"
		laterProtected := map[string]any{
			"schema_version": "mulgae-provider-requirements.v1",
			"assessments":    []any{badFirst, secondProtected},
		}
		errLater := decodeSection(laterProtected, domain.RoleLogic)
		if cause, ok := RuntimeCause(errLater); !ok || cause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("earlier invalid + later protected cause = (%q, %t), want provider_ownership_violation (err=%v)", cause, ok, errLater)
		}
	})

	t.Run("visual sha256 remains allowed and verified", func(t *testing.T) {
		section := map[string]any{"schema_version": "mulgae-provider-requirements.v1", "assessments": []any{makeVisualRow()}}
		if decodeErr := decodeSection(section, domain.RoleArtist); decodeErr != nil {
			t.Fatalf("valid visual.sha256 rejected: %v", decodeErr)
		}
	})

	t.Run("SplitRequirementsResponse wraps decode and version errors with typed causes", func(t *testing.T) {
		_, _, _, decodeErr := SplitRequirementsResponse([]byte(`{"schema_version":"mulgae-provider-review-output.v3","requirements":{`))
		if cause, ok := RuntimeCause(decodeErr); !ok || cause != domain.DiagnosticCauseOutputDecodeFailed {
			t.Fatalf("malformed split cause = (%q, %t), want provider_output_decode_failed", cause, ok)
		}
		_, _, present, versionErr := SplitRequirementsResponse([]byte(`{"schema_version":"mulgae-provider-review-output.v1","requirements":{}}`))
		if !present {
			t.Fatal("wrong version lost present flag")
		}
		if cause, ok := RuntimeCause(versionErr); !ok || cause != domain.DiagnosticCauseCandidateValidationFailed {
			t.Fatalf("wrong version split cause = (%q, %t), want candidate_validation_failed", cause, ok)
		}
	})

	t.Run("repair patch requireOnlyKeys remains strict ownership protection", func(t *testing.T) {
		patchErr := requireOnlyKeys(map[string]any{"schema_version": "mulgae-repair-patch.v1", "repairs": []any{}, "extra_note": true}, "repair patch", "schema_version", "repairs")
		wrapped := wrapRuntimeError(patchErr, domain.DiagnosticCauseCandidateRepairPlanInvalid)
		if cause, ok := RuntimeCause(wrapped); !ok || cause != domain.DiagnosticCauseProviderOwnershipViolation {
			t.Fatalf("repair.go requireOnlyKeys cause = (%q, %t), want provider_ownership_violation", cause, ok)
		}
	})
}
