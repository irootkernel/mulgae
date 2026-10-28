package mulgae

import (
	"fmt"
	"regexp"

	"github.com/irootkernel/mulgae/internal/domain"
)

// RequirementsPreflightSummary is bounded admission metadata. It is neither
// a published assessment nor a content lock, and contains no requirement prose.
type RequirementsPreflightSummary struct {
	InputSHA256        string                      `json:"input_sha256"`
	SelectedCount      int                         `json:"selected_count"`
	Items              []RequirementsPreflightItem `json:"items"`
	EvaluationStatus   string                      `json:"evaluation_status"`
	ExtractionPolicy   string                      `json:"extraction_policy"`
	SourceLimit        string                      `json:"source_limit"`
	ExecutionAvailable bool                        `json:"execution_available"`
}

type RequirementsPreflightItem struct {
	RequirementID string      `json:"requirement_id"`
	OwnerRole     domain.Role `json:"owner_role"`
}

var preflightRequirementID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func NewRequirementsPreflightSummary(digest string, requirements []domain.Requirement, extraction, executionAvailable bool) (*RequirementsPreflightSummary, error) {
	result := &RequirementsPreflightSummary{ExecutionAvailable: executionAvailable, InputSHA256: digest, SelectedCount: len(requirements), Items: make([]RequirementsPreflightItem, len(requirements)), EvaluationStatus: "not_run", ExtractionPolicy: "disabled", SourceLimit: "selected_target_only"}
	if extraction {
		result.ExtractionPolicy = "enabled"
	}
	for index, requirement := range requirements {
		if !requirement.Valid() {
			return nil, fmt.Errorf("requirements preflight: invalid admitted item")
		}
		result.Items[index] = RequirementsPreflightItem{RequirementID: requirement.ID(), OwnerRole: requirement.OwnerRole()}
	}
	return result, result.Validate()
}

func (summary RequirementsPreflightSummary) Validate() error {
	if !preflightSHA256(summary.InputSHA256) || summary.SelectedCount < 1 || summary.SelectedCount > domain.MaxRequirements || len(summary.Items) != summary.SelectedCount || summary.EvaluationStatus != "not_run" || summary.SourceLimit != "selected_target_only" || summary.ExtractionPolicy != "enabled" && summary.ExtractionPolicy != "disabled" {
		return fmt.Errorf("requirements preflight: invalid summary")
	}
	seen := make(map[string]bool, len(summary.Items))
	for _, item := range summary.Items {
		if !preflightRequirementID.MatchString(item.RequirementID) || !item.OwnerRole.Valid() || seen[item.RequirementID] {
			return fmt.Errorf("requirements preflight: invalid assignment")
		}
		seen[item.RequirementID] = true
	}
	return nil
}
