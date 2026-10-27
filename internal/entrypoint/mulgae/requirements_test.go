package mulgae

import (
	"encoding/json"
	"testing"
)

func TestRequirementsPreflightAcceptsOptionalInputAlongsideObjective(t *testing.T) {
	invocation, err := Parse([]string{"review", "--stage", "--preflight", "--requirements", "requirements.json", "--objective", "Preserve behavior."}, testProjectRoot, testRequestID)
	if err != nil {
		t.Fatalf("requirements preflight rejected: %v", err)
	}
	raw, _ := invocation.RequestJSON()
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request["requirements_path"] != "requirements.json" || request["objective"] != "Preserve behavior." {
		t.Fatalf("optional input changed objective or path: %s", raw)
	}
}

func TestRequirementsPreflightRejectsContradictorySummaryMetadata(t *testing.T) {
	for name, mutate := range map[string]func(*RequirementsPreflightSummary){
		"count":               func(s *RequirementsPreflightSummary) { s.SelectedCount++ },
		"identity":            func(s *RequirementsPreflightSummary) { s.Items[0].RequirementID = "not valid" },
		"owner":               func(s *RequirementsPreflightSummary) { s.Items[0].OwnerRole = "unknown" },
		"execution":           func(s *RequirementsPreflightSummary) { s.ExecutionAvailable = true },
		"assessment":          func(s *RequirementsPreflightSummary) { s.EvaluationStatus = "evaluated" },
		"predicted allowance": func(s *RequirementsPreflightSummary) { s.ExtractionPolicy = "extraction_allowance_consumed" },
	} {
		t.Run(name, func(t *testing.T) {
			result := loadReviewPreflightExample(t)
			mutate(result.Requirements)
			if err := result.Validate(); err == nil {
				t.Fatal("contradictory preflight summary accepted")
			}
		})
	}
}
