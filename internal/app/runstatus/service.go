// Package runstatus acquires publication-first run status without transport
// projection or filesystem access.
package runstatus

import (
	"context"
	"errors"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RoleReportURI is one verified project-relative role-report identity.
type RoleReportURI struct {
	Role string
	URI  string
}

// PublicationStatus contains the safe query fields used by status transports.
// Final artifacts, axes and role reports require independently verified P2
// support. Transports retain their field-presence and projection validation.
type PublicationStatus struct {
	FailedRunRecovery    recovery.Status
	SessionID            string
	RunID                string
	RunState             domain.RunState
	HasRunState          bool
	PublicationState     domain.PublicationStatus
	RecoveryAction       domain.RecoveryAction
	FinalArtifactURI     string
	HasFinalArtifact     bool
	ContentVerdict       domain.ContentVerdict
	CoverageStatus       domain.CoverageStatus
	CIDecision           domain.CIDecision
	HasAxes              bool
	RoleReportURIs       []RoleReportURI
	DiagnosticSummary    ports.RuntimeDiagnosticSummary
	HasDiagnosticSummary bool
}

// PublicationQuery supplies only run resolution and safe status reads.
type PublicationQuery interface {
	ResolveRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error)
	ReadRunStatus(context.Context, ports.PublicationRun) (PublicationStatus, error)
}

// Kind distinguishes publication, diagnostic-only and unavailable acquisition.
type Kind uint8

const (
	Publication Kind = iota
	Diagnostic
	Unavailable
)

// Phase identifies where acquisition failed, for transport-specific wrapping.
type Phase uint8

const (
	Resolve Phase = iota
	ResolveScope
	PublicationRead
	DiagnosticRead
	SessionDiagnosticRead
)

var ErrInvalidScope = errors.New("run status resolution returned an invalid scope")

// Result retains the resolved scope and the original error's phase. A missing
// diagnostic after missing publication returns Unavailable and the original
// publication error. Diagnostic state eligibility belongs to the transport.
type Result struct {
	Kind       Kind
	Phase      Phase
	Run        ports.PublicationRun
	Status     PublicationStatus
	Diagnostic ports.RuntimeDiagnosticRunStatus
}

// Service owns acquisition policy through narrow query capabilities. A nil
// diagnostic query disables fallback and enrichment for the CLI's optional group.
type Service struct {
	publication PublicationQuery
	diagnostics ports.RuntimeDiagnosticQuery
}

func New(publication PublicationQuery, diagnostics ports.RuntimeDiagnosticQuery) *Service {
	return &Service{publication: publication, diagnostics: diagnostics}
}

// Read preserves original query errors; it adds no operational failure wrapper.
func (service *Service) Read(ctx context.Context, root ports.AnchoredRoot, runID domain.RunID) (Result, error) {
	run, err := service.publication.ResolveRun(ctx, root, runID)
	if err != nil {
		result := Result{Phase: Resolve}
		if !SolelyWraps(err, ports.ErrPublicationRunNotFound) || service.diagnostics == nil {
			return result, err
		}
		status, diagnosticErr := service.diagnostics.ReadRunStatus(ctx, root, runID)
		if diagnosticErr != nil {
			if SolelyWraps(diagnosticErr, ports.ErrRuntimeDiagnosticRunNotFound) {
				result.Kind = Unavailable
				return result, err
			}
			result.Phase = DiagnosticRead
			return result, diagnosticErr
		}
		return Result{Kind: Diagnostic, Diagnostic: status}, nil
	}
	if !run.Valid() || run.Root() != root || run.RunID() != runID {
		return Result{Phase: ResolveScope}, ErrInvalidScope
	}
	status, err := service.publication.ReadRunStatus(ctx, run)
	result := Result{Kind: Publication, Phase: PublicationRead, Run: run, Status: status}
	if err != nil {
		return result, err
	}
	if status.PublicationState == domain.PublicationCommitted && service.diagnostics != nil {
		// Supplementary diagnostics cannot revoke independently verified P2.
		diagnostic, diagnosticErr := service.diagnostics.ReadSessionRunStatus(ctx, root, run.SessionID(), run.RunID())
		if diagnosticErr == nil && diagnostic.SessionID() == run.SessionID() && diagnostic.RunID() == run.RunID() {
			if summary, ok := diagnostic.DiagnosticSummary(); ok && summary.Component() == "coordination" {
				result.Status.DiagnosticSummary, result.Status.HasDiagnosticSummary = summary, true
			}
		}
	}
	if status.PublicationState != domain.PublicationCommitted && service.diagnostics != nil {
		diagnostic, err := service.diagnostics.ReadSessionRunStatus(ctx, root, run.SessionID(), run.RunID())
		if err != nil {
			if !SolelyWraps(err, ports.ErrRuntimeDiagnosticRunNotFound) {
				result.Phase = SessionDiagnosticRead
				return result, err
			}
		} else if summary, ok := diagnostic.DiagnosticSummary(); ok {
			result.Status.DiagnosticSummary, result.Status.HasDiagnosticSummary = summary, true
		}
	}
	return result, nil
}

// SolelyWraps accepts a complete cause tree containing only target leaves.
// Ordinary and typed single wrappers, single-child joins and missing-only joins
// remain eligible; every non-target sibling makes the tree mixed.
func SolelyWraps(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			matched := false
			for _, child := range joined.Unwrap() {
				if child == nil {
					continue
				}
				if !SolelyWraps(child, target) {
					return false
				}
				matched = true
			}
			return matched
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}
