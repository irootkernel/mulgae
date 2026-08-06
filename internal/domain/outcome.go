package domain

import "fmt"

type ContentVerdict string

const (
	ContentNoFindings      ContentVerdict = "no_findings"
	ContentFindingsPresent ContentVerdict = "findings_present"
	ContentRequestChanges  ContentVerdict = "request_changes"
	// ContentReportsOnly means Mulgae published role reports without claiming a
	// structured finding set was extracted for the run.
	ContentReportsOnly ContentVerdict = "reports_only"
)

func (value ContentVerdict) Valid() bool {
	return oneOf(string(value), string(ContentNoFindings), string(ContentFindingsPresent), string(ContentRequestChanges), string(ContentReportsOnly))
}

// StructuredExtractionStatus is Mulgae-owned coverage of structured finding
// extraction across selected roles. It is independent of provider degraded
// failure and of role-report delivery.
type StructuredExtractionStatus string

const (
	StructuredExtractionStructured  StructuredExtractionStatus = "structured"
	StructuredExtractionMixed       StructuredExtractionStatus = "mixed"
	StructuredExtractionReportsOnly StructuredExtractionStatus = "reports_only"
)

func (value StructuredExtractionStatus) Valid() bool {
	return oneOf(string(value), string(StructuredExtractionStructured), string(StructuredExtractionMixed), string(StructuredExtractionReportsOnly))
}

// ComputeStructuredExtractionStatus derives Mulgae-owned structured-extraction
// coverage across selected role summaries.
func ComputeStructuredExtractionStatus(results []RoleResultSummary) StructuredExtractionStatus {
	structured := 0
	reportsOnly := 0
	for _, result := range results {
		if !result.Selected || !result.Valid {
			continue
		}
		if result.ReportsOnly {
			reportsOnly++
		} else {
			structured++
		}
	}
	switch {
	case structured > 0 && reportsOnly > 0:
		return StructuredExtractionMixed
	case reportsOnly > 0:
		return StructuredExtractionReportsOnly
	default:
		return StructuredExtractionStructured
	}
}

type CoverageStatus string

const (
	CoverageComplete   CoverageStatus = "complete"
	CoverageDegraded   CoverageStatus = "degraded"
	CoverageIncomplete CoverageStatus = "incomplete"
)

func (value CoverageStatus) Valid() bool {
	return oneOf(string(value), string(CoverageComplete), string(CoverageDegraded), string(CoverageIncomplete))
}

type CIDecision string

const (
	CIPass CIDecision = "pass"
	CIFail CIDecision = "fail"
)

func (value CIDecision) Valid() bool { return value == CIPass || value == CIFail }

type RoleResultSummary struct {
	Role     Role
	Selected bool
	Required bool
	Valid    bool
	Degraded bool
	// ReportsOnly is true when the role delivered a Mulgae-owned free-form
	// report without a validated structured finding document.
	ReportsOnly bool
}

type CIPolicy struct {
	RequestChangesFails   bool
	DegradedReviewFails   bool
	IncompleteReviewFails bool
}

func DefaultCIPolicy() CIPolicy {
	return CIPolicy{RequestChangesFails: true, DegradedReviewFails: true, IncompleteReviewFails: true}
}

type OutcomeAxes struct {
	content     ContentVerdict
	coverage    CoverageStatus
	publication PublicationStatus
	ci          CIDecision
}

func ComputeOutcomeAxes(findings []Finding, results []RoleResultSummary, threshold Severity, publication PublicationStatus, policy *CIPolicy) (OutcomeAxes, error) {
	if threshold == "" {
		threshold = SeverityHigh
	}
	if !threshold.Valid() {
		return OutcomeAxes{}, fmt.Errorf("outcome: invalid request-changes threshold %q", threshold)
	}
	if !publication.Valid() {
		return OutcomeAxes{}, fmt.Errorf("outcome: invalid publication status %q", publication)
	}
	coverage, err := computeCoverage(results)
	if err != nil {
		return OutcomeAxes{}, err
	}
	for index, finding := range findings {
		if err := finding.Validate(); err != nil {
			return OutcomeAxes{}, fmt.Errorf("outcome: finding %d: %w", index, err)
		}
	}
	content := ContentNoFindings
	if len(findings) > 0 {
		content = ContentFindingsPresent
		for _, finding := range findings {
			if finding.Severity().Rank() >= threshold.Rank() {
				content = ContentRequestChanges
			}
		}
	} else {
		for _, result := range results {
			if result.Selected && result.Valid && result.ReportsOnly {
				content = ContentReportsOnly
				break
			}
		}
	}
	resolvedPolicy := DefaultCIPolicy()
	if policy != nil {
		resolvedPolicy = *policy
	}
	ci := CIPass
	if content == ContentRequestChanges && resolvedPolicy.RequestChangesFails ||
		coverage == CoverageDegraded && resolvedPolicy.DegradedReviewFails ||
		coverage == CoverageIncomplete && resolvedPolicy.IncompleteReviewFails {
		ci = CIFail
	}
	return OutcomeAxes{content: content, coverage: coverage, publication: publication, ci: ci}, nil
}

func computeCoverage(results []RoleResultSummary) (CoverageStatus, error) {
	byRole := make(map[Role]RoleResultSummary, len(results))
	for _, result := range results {
		if !result.Role.Valid() {
			return "", fmt.Errorf("coverage: invalid role %q", result.Role)
		}
		if _, duplicate := byRole[result.Role]; duplicate {
			return "", fmt.Errorf("coverage: duplicate role %q", result.Role)
		}
		byRole[result.Role] = result
	}
	degraded := false
	for _, role := range FixedRoleOrder() {
		result, exists := byRole[role]
		if !exists {
			continue
		}
		required := result.Required || role == RoleLogic
		if required && (!result.Selected || !result.Valid) {
			return CoverageIncomplete, nil
		}
		if result.Selected && !result.Valid {
			return CoverageIncomplete, nil
		}
		if result.Selected && result.Degraded {
			degraded = true
		}
	}
	if degraded {
		return CoverageDegraded, nil
	}
	return CoverageComplete, nil
}

func (axes OutcomeAxes) ContentVerdict() ContentVerdict       { return axes.content }
func (axes OutcomeAxes) CoverageStatus() CoverageStatus       { return axes.coverage }
func (axes OutcomeAxes) PublicationStatus() PublicationStatus { return axes.publication }
func (axes OutcomeAxes) CIDecision() CIDecision               { return axes.ci }
