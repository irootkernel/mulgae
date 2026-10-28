package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	RequirementsSupportVersion = "mulgae-requirements-support.v1"
	RequirementsSupportPath    = "requirements/support.json"
	RequirementsInputPath      = "requirements/input.json"
	RequirementsSupportSchema  = "https://mulgae.local/schemas/mulgae-requirements-support.v1.schema.json"
)

// RequirementContentReference binds an ordinal item path to its complete
// unbounded content. It does not assert that the source evidence was verified.
type RequirementContentReference struct {
	path       string
	sha256     string
	byteLength int64
}

func (reference RequirementContentReference) Path() string      { return reference.path }
func (reference RequirementContentReference) SHA256() string    { return reference.sha256 }
func (reference RequirementContentReference) ByteLength() int64 { return reference.byteLength }

func (reference RequirementContentReference) Matches(raw []byte) bool {
	return reference.byteLength == int64(len(raw)) && reference.sha256 == requirementsSupportSHA256(raw)
}

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
	if ctx == nil || nilSchemaValidator(validator) {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: missing validation scope")
	}
	id, err := ports.ParseAssetID(RequirementsSupportSchema)
	if err != nil {
		return domain.RequirementEvaluation{}, nil, err
	}
	if err := validator.Validate(ctx, id, raw); err != nil {
		return domain.RequirementEvaluation{}, nil, err
	}
	return DecodeRequirementsSupportMetadata(raw, input, requirements, noChange)
}

// DecodeRequirementsSupportMetadata checks a previously bounded metadata object.
// Storage owners retain schema admission and exact artifact/hash verification.
func DecodeRequirementsSupportMetadata(raw, input []byte, requirements []domain.Requirement, noChange bool) (domain.RequirementEvaluation, []RequirementContentReference, error) {
	var err error
	var support requirementsSupportWire
	object, strictErr := decodeJSONObject(raw, "requirements support")
	if strictErr != nil || !requirementObjectFields(object, "schema_version", "input_path", "input_sha256", "input_byte_length", "availability", "selected_count", "evaluated_count", "items") {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: invalid metadata fields")
	}
	items, ok := object["items"].([]any)
	if !ok {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: invalid items")
	}
	for _, value := range items {
		item, ok := value.(map[string]any)
		if !ok || !requirementObjectFields(item, "requirement_id", "owner_role", "verdict", "origin", "reason", "content_path", "content_sha256", "content_byte_length") {
			return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: invalid item fields")
		}
	}
	if err := json.Unmarshal(raw, &support); err != nil || support.SchemaVersion != RequirementsSupportVersion || support.InputPath != RequirementsInputPath || support.InputByteLength != int64(len(input)) || support.InputSHA256 != requirementsSupportSHA256(input) || len(support.Items) != len(requirements) {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: input or selected-set mismatch")
	}
	if noChange != (support.Availability == domain.AssessmentNotRun) {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: selected-source evaluation mismatch")
	}
	assessments := make([]domain.RequirementAssessment, len(requirements))
	references := make([]RequirementContentReference, len(requirements))
	for index, requirement := range requirements {
		row := support.Items[index]
		contentDigest, digestErr := canonicalTargetSHA256(row.ContentSHA256)
		if row.RequirementID != requirement.ID() || row.OwnerRole != requirement.OwnerRole() || row.ContentPath != fmt.Sprintf("requirements/items/%03d.json", index) || digestErr != nil || contentDigest != row.ContentSHA256 || row.ContentByteLength < 1 {
			return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: item identity or content binding mismatch")
		}
		assessments[index], err = domain.NewRequirementAssessment(requirement, row.Verdict, row.Origin, row.Reason)
		if err != nil {
			return domain.RequirementEvaluation{}, nil, err
		}
		references[index] = RequirementContentReference{path: row.ContentPath, sha256: row.ContentSHA256, byteLength: row.ContentByteLength}
	}
	evaluation, err := domain.NewRequirementEvaluation(support.Availability, requirements, assessments)
	selected, evaluated, known := evaluation.Counts()
	if err != nil || !known || selected != support.SelectedCount || evaluated != support.EvaluatedCount {
		return domain.RequirementEvaluation{}, nil, fmt.Errorf("requirements support: inconsistent response counts")
	}
	return evaluation, references, nil
}

func requirementsSupportSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
