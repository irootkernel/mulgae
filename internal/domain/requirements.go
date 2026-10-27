package domain

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxRequirements       = 100
	MaxAcceptanceCriteria = 32
)

var requirementIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// Requirement is an immutable invocation obligation, not source evidence.
type Requirement struct {
	id       string
	text     string
	criteria []string
	owner    Role
}

func NewRequirement(id, text string, criteria []string, owner Role) (Requirement, error) {
	if !requirementIDPattern.MatchString(id) || !requirementText(text) || !owner.Valid() || len(criteria) < 1 || len(criteria) > MaxAcceptanceCriteria {
		return Requirement{}, fmt.Errorf("requirement: invalid identity, text, criteria or owner")
	}
	for _, criterion := range criteria {
		if !requirementText(criterion) {
			return Requirement{}, fmt.Errorf("requirement: invalid criterion text")
		}
	}
	return Requirement{id: id, text: text, criteria: append([]string(nil), criteria...), owner: owner}, nil
}

func requirementText(value string) bool {
	return strings.ToValidUTF8(value, "") == value && strings.TrimSpace(value) != "" && !strings.ContainsRune(value, 0)
}

func (requirement Requirement) ID() string   { return requirement.id }
func (requirement Requirement) Text() string { return requirement.text }
func (requirement Requirement) AcceptanceCriteria() []string {
	return append([]string(nil), requirement.criteria...)
}
func (requirement Requirement) OwnerRole() Role { return requirement.owner }
func (requirement Requirement) Valid() bool {
	_, err := NewRequirement(requirement.id, requirement.text, requirement.criteria, requirement.owner)
	return err == nil
}

// ValidateRequirements checks the complete selected set without inventing roles.
func ValidateRequirements(requirements []Requirement, selected []Role) error {
	if len(requirements) < 1 || len(requirements) > MaxRequirements {
		return fmt.Errorf("requirements: item count must be between 1 and 100")
	}
	roles := make(map[Role]bool, len(selected))
	for _, role := range selected {
		if !role.Valid() || roles[role] {
			return fmt.Errorf("requirements: invalid selected roles")
		}
		roles[role] = true
	}
	seen := make(map[string]bool, len(requirements))
	for _, requirement := range requirements {
		if !requirement.Valid() || seen[requirement.ID()] || !roles[requirement.OwnerRole()] {
			return fmt.Errorf("requirements: invalid item, duplicate ID or unselected owner")
		}
		seen[requirement.ID()] = true
	}
	return nil
}

type RequirementVerdict string

const (
	RequirementMet          RequirementVerdict = "met"
	RequirementPartiallyMet RequirementVerdict = "partially_met"
	RequirementUnmet        RequirementVerdict = "unmet"
	RequirementUnverified   RequirementVerdict = "unverified"
)

func (verdict RequirementVerdict) Valid() bool {
	return oneOf(string(verdict), string(RequirementMet), string(RequirementPartiallyMet), string(RequirementUnmet), string(RequirementUnverified))
}

type AssessmentOrigin string

const (
	AssessmentProvider AssessmentOrigin = "provider"
	AssessmentDerived  AssessmentOrigin = "mulgae_derived"
)

type AssessmentReason string

const (
	AssessmentReasonNone               AssessmentReason = ""
	AssessmentInsufficientEvidence     AssessmentReason = "insufficient_evidence"
	AssessmentExtractionDisabled       AssessmentReason = "extraction_disabled"
	AssessmentExtractionAllowanceSpent AssessmentReason = "extraction_allowance_consumed"
	AssessmentAnswerOmitted            AssessmentReason = "answer_omitted"
	AssessmentInvalidContent           AssessmentReason = "invalid_assessment"
	AssessmentNoChangeTarget           AssessmentReason = "no_change_target"
)

// RequirementAssessment records trusted identity and response accounting. Its
// rationale and verified source material remain with validation/publication.
type RequirementAssessment struct {
	requirementID string
	owner         Role
	verdict       RequirementVerdict
	origin        AssessmentOrigin
	reason        AssessmentReason
}

func NewRequirementAssessment(requirement Requirement, verdict RequirementVerdict, origin AssessmentOrigin, reason AssessmentReason) (RequirementAssessment, error) {
	valid := requirement.Valid() && verdict.Valid()
	switch origin {
	case AssessmentProvider:
		valid = valid && (verdict == RequirementUnverified && reason == AssessmentInsufficientEvidence || verdict != RequirementUnverified && reason == AssessmentReasonNone)
	case AssessmentDerived:
		valid = valid && verdict == RequirementUnverified && oneOf(string(reason), string(AssessmentExtractionDisabled), string(AssessmentExtractionAllowanceSpent), string(AssessmentAnswerOmitted), string(AssessmentInvalidContent), string(AssessmentNoChangeTarget))
	default:
		valid = false
	}
	if !valid {
		return RequirementAssessment{}, fmt.Errorf("requirement assessment: inconsistent identity, verdict, origin or reason")
	}
	return RequirementAssessment{requirementID: requirement.ID(), owner: requirement.OwnerRole(), verdict: verdict, origin: origin, reason: reason}, nil
}

func (assessment RequirementAssessment) RequirementID() string       { return assessment.requirementID }
func (assessment RequirementAssessment) OwnerRole() Role             { return assessment.owner }
func (assessment RequirementAssessment) Verdict() RequirementVerdict { return assessment.verdict }
func (assessment RequirementAssessment) Origin() AssessmentOrigin    { return assessment.origin }
func (assessment RequirementAssessment) Reason() AssessmentReason    { return assessment.reason }

type AssessmentAvailability string

const (
	AssessmentNotRequested AssessmentAvailability = "not_requested"
	AssessmentUnavailable  AssessmentAvailability = "unavailable"
	AssessmentNotRun       AssessmentAvailability = "not_run"
	AssessmentEvaluated    AssessmentAvailability = "evaluated"
)

// RequirementEvaluation keeps unknown historical counts separate from zero.
type RequirementEvaluation struct {
	availability AssessmentAvailability
	selected     int
	evaluated    int
	assessments  []RequirementAssessment
}

func NewRequirementEvaluation(availability AssessmentAvailability, requirements []Requirement, assessments []RequirementAssessment) (RequirementEvaluation, error) {
	result := RequirementEvaluation{availability: availability, selected: len(requirements)}
	if availability == AssessmentNotRequested || availability == AssessmentUnavailable {
		if len(requirements) != 0 || len(assessments) != 0 {
			return RequirementEvaluation{}, fmt.Errorf("requirement evaluation: absent capability cannot contain rows")
		}
		return result, nil
	}
	if availability != AssessmentNotRun && availability != AssessmentEvaluated || len(requirements) < 1 || len(requirements) > MaxRequirements || len(requirements) != len(assessments) {
		return RequirementEvaluation{}, fmt.Errorf("requirement evaluation: incomplete selected set")
	}
	seen := make(map[string]bool, len(requirements))
	for index, requirement := range requirements {
		assessment := assessments[index]
		canonical, err := NewRequirementAssessment(requirement, assessment.Verdict(), assessment.Origin(), assessment.Reason())
		if err != nil || canonical != assessment || seen[requirement.ID()] {
			return RequirementEvaluation{}, fmt.Errorf("requirement evaluation: duplicate, missing or wrong-owner assessment")
		}
		seen[requirement.ID()] = true
		if availability == AssessmentNotRun && (assessment.Origin() != AssessmentDerived || assessment.Reason() != AssessmentNoChangeTarget) || availability == AssessmentEvaluated && assessment.Reason() == AssessmentNoChangeTarget {
			return RequirementEvaluation{}, fmt.Errorf("requirement evaluation: inconsistent no-change state")
		}
		if assessment.Origin() == AssessmentProvider {
			result.evaluated++
		}
	}
	result.assessments = append([]RequirementAssessment(nil), assessments...)
	return result, nil
}

func (evaluation RequirementEvaluation) Availability() AssessmentAvailability {
	return evaluation.availability
}
func (evaluation RequirementEvaluation) Counts() (selected, evaluated int, known bool) {
	return evaluation.selected, evaluation.evaluated, evaluation.availability != AssessmentUnavailable
}
func (evaluation RequirementEvaluation) Assessments() []RequirementAssessment {
	return append([]RequirementAssessment(nil), evaluation.assessments...)
}
