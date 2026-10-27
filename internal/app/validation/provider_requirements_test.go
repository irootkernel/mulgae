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
			if test.protected && (!ok || cause != domain.DiagnosticCauseObservationMismatch) {
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
