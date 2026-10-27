package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

const RequirementsInputVersion = "mulgae-requirements-input.v1"

// RequirementsInput retains exact admitted invocation bytes. Filesystem
// admission and production wiring are separate from this strict byte decoder.
type RequirementsInput struct {
	raw          []byte
	sha256       string
	requirements []domain.Requirement
}

func (input RequirementsInput) Bytes() []byte  { return append([]byte(nil), input.raw...) }
func (input RequirementsInput) SHA256() string { return input.sha256 }
func (input RequirementsInput) Requirements() []domain.Requirement {
	return append([]domain.Requirement(nil), input.requirements...)
}

// DecodeRequirementsInput applies metadata limits, never a requirement-prose
// byte ceiling. Callers must provide the already resolved selected roles.
func DecodeRequirementsInput(raw []byte, selected []domain.Role) (RequirementsInput, error) {
	object, err := decodeJSONObject(raw, "requirements input")
	if err != nil {
		return RequirementsInput{}, fmt.Errorf("requirements input: invalid JSON")
	}
	if len(object) != 2 || object["schema_version"] != RequirementsInputVersion {
		return RequirementsInput{}, fmt.Errorf("requirements input: invalid fields or version")
	}
	rows, ok := object["requirements"].([]any)
	if !ok || len(rows) < 1 || len(rows) > domain.MaxRequirements {
		return RequirementsInput{}, fmt.Errorf("requirements input: invalid item count")
	}
	requirements := make([]domain.Requirement, len(rows))
	for index, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || len(row) != 4 {
			return RequirementsInput{}, fmt.Errorf("requirements input: invalid item fields")
		}
		id, idOK := row["id"].(string)
		text, textOK := row["text"].(string)
		owner, ownerOK := row["owner_role"].(string)
		criteria, criteriaOK := requirementCriteria(row["acceptance_criteria"])
		if !idOK || !textOK || !ownerOK || !criteriaOK {
			return RequirementsInput{}, fmt.Errorf("requirements input: invalid item types")
		}
		requirements[index], err = domain.NewRequirement(id, text, criteria, domain.Role(owner))
		if err != nil {
			return RequirementsInput{}, fmt.Errorf("requirements input: invalid item")
		}
	}
	if err := domain.ValidateRequirements(requirements, selected); err != nil {
		return RequirementsInput{}, fmt.Errorf("requirements input: duplicate ID or invalid owner")
	}
	sum := sha256.Sum256(raw)
	return RequirementsInput{raw: append([]byte(nil), raw...), sha256: "sha256:" + hex.EncodeToString(sum[:]), requirements: requirements}, nil
}

func requirementCriteria(value any) ([]string, bool) {
	rows, ok := value.([]any)
	if !ok || len(rows) < 1 || len(rows) > domain.MaxAcceptanceCriteria {
		return nil, false
	}
	criteria := make([]string, len(rows))
	for index, value := range rows {
		criteria[index], ok = value.(string)
		if !ok {
			return nil, false
		}
	}
	return criteria, true
}

// ValidateRequirementAssessmentAssignments admits a role's answered IDs only.
// Omitted IDs are allowed here; normalization must supply their derived rows.
func ValidateRequirementAssessmentAssignments(requirements []domain.Requirement, owner domain.Role, answeredIDs []string) error {
	if !owner.Valid() || len(answeredIDs) > domain.MaxRequirements {
		return fmt.Errorf("requirements assessment: invalid owner or answer count")
	}
	assigned := make(map[string]domain.Role, len(requirements))
	for _, requirement := range requirements {
		if !requirement.Valid() || assigned[requirement.ID()] != "" {
			return fmt.Errorf("requirements assessment: invalid admitted set")
		}
		assigned[requirement.ID()] = requirement.OwnerRole()
	}
	seen := make(map[string]bool, len(answeredIDs))
	for _, id := range answeredIDs {
		if assigned[id] != owner || seen[id] {
			return fmt.Errorf("requirements assessment: duplicate, foreign or wrong-owner ID")
		}
		seen[id] = true
	}
	return nil
}
