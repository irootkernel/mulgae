package validation

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func requirementContentExample(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../builtin/assets/examples/requirement-content.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRequirementContentPreservesUnboundedProseOutsideMetadata(t *testing.T) {
	item, _ := domain.NewRequirement("RCI-001", "description", []string{"criterion"}, domain.RoleLogic)
	assessment, _ := domain.NewRequirementAssessment(item, domain.RequirementUnverified, domain.AssessmentDerived, domain.AssessmentNoChangeTarget)
	var content RequirementContent
	if err := json.Unmarshal(requirementContentExample(t), &content); err != nil {
		t.Fatal(err)
	}
	content.Rationale = strings.Repeat("Assessment rationale. ", 450000)
	content.Limitations = []string{strings.Repeat("An explicit limitation. ", 400000)}
	raw, err := json.Marshal(content)
	if err != nil || len(raw) <= 8<<20 {
		t.Fatal("large content fixture misses envelope ceiling")
	}
	decoded, err := DecodeRequirementContent(raw, assessment, "")
	if err != nil || decoded.Rationale != content.Rationale || decoded.Limitations[0] != content.Limitations[0] {
		t.Fatalf("prose content was bounded or lost: %v", err)
	}
	for _, mutate := range []func(*RequirementContent){
		func(value *RequirementContent) { value.RequirementID = "foreign" },
		func(value *RequirementContent) { value.Rationale = " " },
		func(value *RequirementContent) { value.Limitations = []string{"bad\x00text"} },
		func(value *RequirementContent) { value.ExaminedScope = "invented by a placeholder" },
	} {
		var value RequirementContent
		if err := json.Unmarshal(requirementContentExample(t), &value); err != nil {
			t.Fatal(err)
		}
		mutate(&value)
		raw, _ := json.Marshal(value)
		if _, err := DecodeRequirementContent(raw, assessment, ""); err == nil {
			t.Fatal("invalid normalized content accepted")
		}
	}
}

func TestRequirementContentRequiresEvidenceOrHonestExaminedScope(t *testing.T) {
	item, _ := domain.NewRequirement("RCI-001", "description", []string{"criterion"}, domain.RoleLogic)
	identity := "sha256:" + strings.Repeat("a", 64)
	content := RequirementContent{SchemaVersion: RequirementContentVersion, RequirementID: item.ID(), Rationale: "The selected implementation supports this obligation.", Evidence: []RequirementContentEvidence{}, Limitations: []string{}}
	met, _ := domain.NewRequirementAssessment(item, domain.RequirementMet, domain.AssessmentProvider, domain.AssessmentReasonNone)
	raw, _ := json.Marshal(content)
	if _, err := DecodeRequirementContent(raw, met, identity); err == nil {
		t.Fatal("requirement text alone established met")
	}
	content.Evidence = []RequirementContentEvidence{{Current: RequirementCurrentEvidence{SourceIdentitySHA256: identity, CurrentExcerptSHA256: identity, Side: CurrentEvidenceSideIndex, Path: "reader.go", LineStart: 12, LineEnd: 12, Quote: "readIndex(path)", Verification: "verified"}}}
	raw, _ = json.Marshal(content)
	if _, err := DecodeRequirementContent(raw, met, identity); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RequirementContent){
		func(value *RequirementContent) {
			value.Evidence[0].Current.SourceIdentitySHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		func(value *RequirementContent) { value.Evidence[0].Current.Path = "../outside" },
		func(value *RequirementContent) { value.Evidence[0].Current.LineEnd = 1 },
		func(value *RequirementContent) { value.Evidence[0].Current.Verification = "claimed" },
		func(value *RequirementContent) {
			value.Evidence[0].Current.CurrentExcerptSHA256 = strings.Repeat("a", 64)
		},
		func(value *RequirementContent) { value.Evidence[0].Current.Path = strings.Repeat("a", 4097) },
	} {
		var value RequirementContent
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		mutate(&value)
		bad, _ := json.Marshal(value)
		if _, err := DecodeRequirementContent(bad, met, identity); err == nil {
			t.Fatal("invalid evidence binding accepted")
		}
	}
	unmet, _ := domain.NewRequirementAssessment(item, domain.RequirementUnmet, domain.AssessmentProvider, domain.AssessmentReasonNone)
	content.Evidence = []RequirementContentEvidence{}
	raw, _ = json.Marshal(content)
	if _, err := DecodeRequirementContent(raw, unmet, identity); err == nil {
		t.Fatal("absence claim without examined scope accepted")
	}
	content.ExaminedScope, content.Limitations = "reader.go in the selected index", []string{"Only the selected file was examined."}
	raw, _ = json.Marshal(content)
	if _, err := DecodeRequirementContent(raw, unmet, identity); err != nil {
		t.Fatal(err)
	}
}
