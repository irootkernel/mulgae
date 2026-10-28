package publication

import (
	"context"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	RequirementsSupportVersion = validation.RequirementsSupportVersion
	RequirementsSupportPath    = validation.RequirementsSupportPath
	RequirementsInputPath      = validation.RequirementsInputPath
	RequirementsSupportSchema  = validation.RequirementsSupportSchema
)

type RequirementContentReference = validation.RequirementContentReference

type requirementsSupportWire struct {
	SchemaVersion   string                        `json:"schema_version"`
	InputPath       string                        `json:"input_path"`
	InputSHA256     string                        `json:"input_sha256"`
	InputByteLength int64                         `json:"input_byte_length"`
	Availability    domain.AssessmentAvailability `json:"availability"`
	SelectedCount   int                           `json:"selected_count"`
	EvaluatedCount  int                           `json:"evaluated_count"`
	Items           []requirementSupportItemWire  `json:"items"`
}

type requirementSupportItemWire struct {
	RequirementID     string                    `json:"requirement_id"`
	OwnerRole         domain.Role               `json:"owner_role"`
	Verdict           domain.RequirementVerdict `json:"verdict"`
	Origin            domain.AssessmentOrigin   `json:"origin"`
	Reason            domain.AssessmentReason   `json:"reason"`
	ContentPath       string                    `json:"content_path"`
	ContentSHA256     string                    `json:"content_sha256"`
	ContentByteLength int64                     `json:"content_byte_length"`
}

// DecodeRequirementsSupport validates bounded metadata against admitted input
// and selected-source no-change state. It performs no storage or publication.
// Callers must also verify every referenced content body and its source claims.
func DecodeRequirementsSupport(ctx context.Context, validator SchemaValidator, raw, input []byte, requirements []domain.Requirement, noChange bool) (domain.RequirementEvaluation, []RequirementContentReference, error) {
	return validation.DecodeRequirementsSupport(ctx, validator, raw, input, requirements, noChange)
}

func decodeRequirementsSupport(raw, input []byte, requirements []domain.Requirement, noChange bool) (domain.RequirementEvaluation, []RequirementContentReference, error) {
	return validation.DecodeRequirementsSupportMetadata(raw, input, requirements, noChange)
}
