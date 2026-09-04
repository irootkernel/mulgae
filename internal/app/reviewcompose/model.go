// Package reviewcompose admits exact committed recovery results and computes a
// deterministic composite review without invoking providers or reading a live target.
package reviewcompose

import (
	"context"

	"github.com/irootkernel/mulgae/internal/domain"
)

// SourceReader returns independently verified, immutable P2 review projections.
type SourceReader interface {
	ReadCompositionSource(context.Context, domain.RunID) (Source, error)
}

// Request identifies one incomplete root and every explicitly selected recovery.
type Request struct {
	RootRunID    domain.RunID
	RecoveryRuns []domain.RunID
}

// Source is the bounded application projection of one verified committed review.
type Source struct {
	SessionID        domain.SessionID
	RunID            domain.RunID
	ReviewID         domain.ReviewID
	RunType          domain.RunType
	TargetSHA256     string
	Coverage         domain.CoverageStatus
	Threshold        domain.Severity
	Roles            []Role
	RoleReports      []RoleReport
	Attempts         []Attempt
	Findings         []SourceFinding
	SourceRunID      domain.RunID
	SourceReviewID   domain.ReviewID
	SourceAttemptID  domain.AttemptID
	HasSource        bool
	HasSourceAttempt bool
}

// Attempt is one verified source attempt used to prove exact failed lineage.
type Attempt struct {
	AttemptID        domain.AttemptID
	Role             domain.Role
	ProviderInstance string
	State            domain.AttemptState
}

// Role is one verified role outcome from a committed source.
type Role struct {
	Name             domain.Role
	Required         bool
	Outcome          string
	AttemptID        domain.AttemptID
	HasAttempt       bool
	ProviderInstance string
	FindingIDs       []string
	ReportsOnly      bool
}

// RoleReport identifies one integrity-checked committed role report.
type RoleReport struct {
	Role             domain.Role
	AttemptID        domain.AttemptID
	ProviderInstance string
	Path             string
	SHA256           string
	ByteLength       int
	ContentType      string
}

// SourceFinding preserves safe content and exact source-local provenance.
type SourceFinding struct {
	ID               string
	Fingerprint      string
	Role             domain.Role
	ProviderInstance string
	Severity         domain.Severity
	Title            string
	Description      string
	Recommendation   string
	Confidence       domain.Confidence
	Lifecycle        domain.FindingLifecycle
}

// Result is the deterministic, publication-ready application result.
type Result struct {
	Fingerprint      domain.CompositionFingerprint
	RootRunID        domain.RunID
	RootReviewID     domain.ReviewID
	SessionID        domain.SessionID
	TargetSHA256     string
	Threshold        domain.Severity
	Sources          []SelectedSource
	Roles            []CompositeRole
	Findings         []Finding
	ContentVerdict   domain.ContentVerdict
	CoverageStatus   domain.CoverageStatus
	ExtractionStatus domain.StructuredExtractionStatus
	CIDecision       domain.CIDecision
	CIReasonCodes    []string
}

// SelectedSource binds one effective role to its exact accepted source.
type SelectedSource struct {
	Kind       string
	Role       domain.Role
	RunID      domain.RunID
	ReviewID   domain.ReviewID
	AttemptID  domain.AttemptID
	RoleReport RoleReport
}

// CompositeRole is one complete effective role outcome.
type CompositeRole struct {
	Role             domain.Role
	Required         bool
	Outcome          string
	AttemptID        domain.AttemptID
	ProviderInstance string
	FindingIDs       []string
	ReportsOnly      bool
	SourceRunID      domain.RunID
	SourceReviewID   domain.ReviewID
}

// Finding is one newly identified composite finding with source-local provenance.
type Finding struct {
	ID               string
	Fingerprint      string
	Role             domain.Role
	ProviderInstance string
	Severity         domain.Severity
	Title            string
	Description      string
	Recommendation   string
	Confidence       domain.Confidence
	Lifecycle        domain.FindingLifecycle
	SourceRunID      domain.RunID
	SourceReviewID   domain.ReviewID
	SourceAttemptID  domain.AttemptID
	SourceFindingID  string
}

// Failure carries the stable public reason code for a rejected composition.
type Failure struct {
	reason string
	detail string
	cause  error
}

func fail(reason, detail string, cause error) error {
	if detail == "" {
		detail = "composition rejected"
	}
	return &Failure{reason: reason, detail: detail, cause: cause}
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "composition failure"
	}
	return failure.reason + ": " + failure.detail
}

func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// ReasonCode returns the stable machine-readable composition reason.
func (failure *Failure) ReasonCode() string {
	if failure == nil {
		return ""
	}
	return failure.reason
}
