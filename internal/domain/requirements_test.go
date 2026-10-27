package domain

import (
	"fmt"
	"strings"
	"testing"
)

func requirementFixture(t *testing.T, id string, role Role) Requirement {
	t.Helper()
	item, err := NewRequirement(id, "Preserve the selected source.", []string{"Use the selected source side."}, role)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestRequirementConstructorRejectsInvalidUTF8Prose(t *testing.T) {
	for _, test := range []struct {
		name      string
		text      string
		criterion string
	}{
		{"description", string([]byte{0xff}), "Preserve source identity."},
		{"criterion", "Preserve source identity.", string([]byte{0xc3, 0x28})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRequirement("Unicode", test.text, []string{test.criterion}, RoleLogic); err == nil {
				t.Fatal("constructor accepted invalid UTF-8 prose")
			}
		})
	}
	const text = "Preserve café output 🌊."
	const criterion = "Keep naïve Unicode text."
	item, err := NewRequirement("Unicode", text, []string{criterion}, RoleLogic)
	if err != nil || !item.Valid() || item.Text() != text || item.AcceptanceCriteria()[0] != criterion {
		t.Fatalf("valid Unicode prose changed or was rejected: %v", err)
	}
	if err := ValidateRequirements([]Requirement{item}, []Role{RoleLogic}); err != nil {
		t.Fatal(err)
	}
}

func TestRequirementsValidateIdentityOwnershipAndBounds(t *testing.T) {
	logic := requirementFixture(t, "RCI-001", RoleLogic)
	for _, test := range []struct {
		name  string
		items []Requirement
		roles []Role
	}{
		{"empty", nil, []Role{RoleLogic}},
		{"duplicate", []Requirement{logic, logic}, []Role{RoleLogic}},
		{"unselected", []Requirement{logic}, []Role{RoleSecurity}},
		{"unknown selected role", []Requirement{logic}, []Role{"unknown"}},
		{"duplicate selected role", []Requirement{logic}, []Role{RoleLogic, RoleLogic}},
		{"zero value", []Requirement{{}}, []Role{RoleLogic}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRequirements(test.items, test.roles); err == nil {
				t.Fatal("invalid selected set accepted")
			}
		})
	}
	items := make([]Requirement, MaxRequirements)
	for index := range items {
		items[index] = requirementFixture(t, fmt.Sprintf("R_%d", index), RoleLogic)
	}
	if err := ValidateRequirements(items, []Role{RoleLogic}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(append(items, requirementFixture(t, "overflow", RoleLogic)), []Role{RoleLogic}); err == nil {
		t.Fatal("overfull set accepted")
	}
	for _, id := range []string{"", "1id", "has.dot", "이름", strings.Repeat("a", 65)} {
		if _, err := NewRequirement(id, "description", []string{"criterion"}, RoleLogic); err == nil {
			t.Fatalf("invalid ID %q accepted", id)
		}
	}
	for _, criteria := range [][]string{nil, {" "}, {"bad\x00criterion"}, make([]string, MaxAcceptanceCriteria+1)} {
		if _, err := NewRequirement("valid", "description", criteria, RoleLogic); err == nil {
			t.Fatal("invalid criteria accepted")
		}
	}
	caseSensitive := []Requirement{requirementFixture(t, "Requirement", RoleLogic), requirementFixture(t, "requirement", RoleLogic)}
	if err := ValidateRequirements(caseSensitive, []Role{RoleLogic}); err != nil {
		t.Fatal("case-sensitive IDs were conflated")
	}
	criteria := []string{"criterion"}
	item, _ := NewRequirement("owned", "description", criteria, RoleLogic)
	criteria[0] = "mutated"
	copyOfCriteria := item.AcceptanceCriteria()
	copyOfCriteria[0] = "mutated again"
	if item.AcceptanceCriteria()[0] != "criterion" {
		t.Fatal("requirement does not own criterion bytes")
	}
}

func TestRequirementEvaluationCountsResponsesWithoutInventingCoverage(t *testing.T) {
	items := []Requirement{requirementFixture(t, "met", RoleLogic), requirementFixture(t, "unknown", RoleLogic), requirementFixture(t, "omitted", RoleSecurity)}
	met, _ := NewRequirementAssessment(items[0], RequirementMet, AssessmentProvider, AssessmentReasonNone)
	unknown, _ := NewRequirementAssessment(items[1], RequirementUnverified, AssessmentProvider, AssessmentInsufficientEvidence)
	omitted, _ := NewRequirementAssessment(items[2], RequirementUnverified, AssessmentDerived, AssessmentAnswerOmitted)
	rows := []RequirementAssessment{met, unknown, omitted}
	evaluation, err := NewRequirementEvaluation(AssessmentEvaluated, items, rows)
	if err != nil {
		t.Fatal(err)
	}
	selected, evaluated, known := evaluation.Counts()
	if selected != 3 || evaluated != 2 || !known {
		t.Fatalf("counts = %d, %d, %v", selected, evaluated, known)
	}
	rows[0] = omitted
	copyOfRows := evaluation.Assessments()
	copyOfRows[0] = omitted
	if evaluation.Assessments()[0] != met {
		t.Fatal("evaluation does not own rows")
	}
	if _, err := NewRequirementEvaluation(AssessmentEvaluated, items, []RequirementAssessment{met}); err == nil {
		t.Fatal("missing normalized rows accepted")
	}
	if _, err := NewRequirementEvaluation(AssessmentEvaluated, items, []RequirementAssessment{met, omitted, unknown}); err == nil {
		t.Fatal("wrong-owner/reordered rows accepted")
	}
	for _, verdict := range []RequirementVerdict{RequirementMet, RequirementPartiallyMet, RequirementUnmet, RequirementUnverified} {
		reason := AssessmentReasonNone
		if verdict == RequirementUnverified {
			reason = AssessmentInsufficientEvidence
		}
		if _, err := NewRequirementAssessment(items[0], verdict, AssessmentProvider, reason); err != nil {
			t.Fatalf("provider verdict %q rejected: %v", verdict, err)
		}
		if verdict != RequirementUnverified {
			if _, err := NewRequirementAssessment(items[0], verdict, AssessmentDerived, AssessmentAnswerOmitted); err == nil {
				t.Fatal("derived row fabricated a provider verdict")
			}
		}
	}
	for _, reason := range []AssessmentReason{AssessmentExtractionDisabled, AssessmentExtractionAllowanceSpent, AssessmentAnswerOmitted, AssessmentInvalidContent, AssessmentNoChangeTarget} {
		if _, err := NewRequirementAssessment(items[0], RequirementUnverified, AssessmentDerived, reason); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRequirementEvaluationNoChangeAndHistoricalAbsenceStayDistinct(t *testing.T) {
	item := requirementFixture(t, "selected", RoleLogic)
	row, _ := NewRequirementAssessment(item, RequirementUnverified, AssessmentDerived, AssessmentNoChangeTarget)
	noChange, err := NewRequirementEvaluation(AssessmentNotRun, []Requirement{item}, []RequirementAssessment{row})
	if err != nil {
		t.Fatal(err)
	}
	selected, evaluated, known := noChange.Counts()
	if selected != 1 || evaluated != 0 || !known {
		t.Fatal("no-change accounting invents evaluation")
	}
	if _, err := NewRequirementEvaluation(AssessmentEvaluated, []Requirement{item}, []RequirementAssessment{row}); err == nil {
		t.Fatal("no-change placeholder accepted as ordinary evaluation")
	}
	provider, _ := NewRequirementAssessment(item, RequirementUnverified, AssessmentProvider, AssessmentInsufficientEvidence)
	if _, err := NewRequirementEvaluation(AssessmentNotRun, []Requirement{item}, []RequirementAssessment{provider}); err == nil {
		t.Fatal("no-change result invented provider execution")
	}
	for _, availability := range []AssessmentAvailability{AssessmentNotRequested, AssessmentUnavailable} {
		evaluation, err := NewRequirementEvaluation(availability, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, known := evaluation.Counts()
		if known != (availability == AssessmentNotRequested) {
			t.Fatal("unknown historical count was filled with zero")
		}
		if _, err := NewRequirementEvaluation(availability, []Requirement{item}, []RequirementAssessment{row}); err == nil {
			t.Fatal("absent support manufactured rows")
		}
	}
}
