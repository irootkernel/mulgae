package reviewcompose

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/domain"
)

type mutationPublisher interface {
	Publish(context.Context, Result) (publication.PublicationResult, error)
}

// MutationService owns the complete provider-free composition mutation. Both
// public transports call this same use case so admission, publication, and
// retry reconciliation cannot drift.
type MutationService struct {
	composer  *Service
	publisher mutationPublisher
}

func NewMutationService(composer *Service, publisher *Publisher) (*MutationService, error) {
	if composer == nil || publisher == nil {
		return nil, fmt.Errorf("review composition mutation: composer and publisher are required")
	}
	return &MutationService{composer: composer, publisher: publisher}, nil
}

// PublishedResult is the immutable transport-neutral result of one exact
// composition request.
type PublishedResult struct {
	sessionID         domain.SessionID
	runID             domain.RunID
	reviewID          domain.ReviewID
	rootRunID         domain.RunID
	recoveryRunIDs    []domain.RunID
	targetSHA256      string
	recoveredRoles    []domain.Role
	roleReportURIs    []RoleReportURI
	coverage          domain.CoverageStatus
	content           domain.ContentVerdict
	extraction        domain.StructuredExtractionStatus
	ci                domain.CIDecision
	publication       domain.PublicationStatus
	recoveryAction    domain.RecoveryAction
	terminalExit      domain.OperationalExitDecision
	reconciliation    domain.CompositionState
	runManifestURI    string
	reviewArtifactURI string
}

// PublishedResultInput contains the trusted P2 fields required to construct a
// transport-neutral composite result.
type PublishedResultInput struct {
	SessionID                  domain.SessionID
	RunID                      domain.RunID
	ReviewID                   domain.ReviewID
	RootRunID                  domain.RunID
	RecoveryRunIDs             []domain.RunID
	TargetSHA256               string
	RecoveredRoles             []domain.Role
	RoleReportURIs             []RoleReportURI
	Coverage                   domain.CoverageStatus
	Content                    domain.ContentVerdict
	StructuredExtractionStatus domain.StructuredExtractionStatus
	CIDecision                 domain.CIDecision
	PublicationStatus          domain.PublicationStatus
	RecoveryAction             domain.RecoveryAction
	TerminalExit               domain.OperationalExitDecision
	ReconciliationState        domain.CompositionState
	RunManifestURI             string
	ReviewArtifactURI          string
}

// RoleReportURI is one project-relative report copied into the composite run.
type RoleReportURI struct {
	Role domain.Role `json:"role"`
	URI  string      `json:"uri"`
}

// NewPublishedResult validates and defensively copies a trusted P2 result.
func NewPublishedResult(input PublishedResultInput) (PublishedResult, error) {
	result := PublishedResult{
		sessionID: input.SessionID, runID: input.RunID, reviewID: input.ReviewID,
		rootRunID: input.RootRunID, recoveryRunIDs: append([]domain.RunID(nil), input.RecoveryRunIDs...),
		targetSHA256: input.TargetSHA256, recoveredRoles: append([]domain.Role(nil), input.RecoveredRoles...),
		roleReportURIs: append([]RoleReportURI(nil), input.RoleReportURIs...), coverage: input.Coverage,
		content: input.Content, extraction: input.StructuredExtractionStatus, ci: input.CIDecision,
		publication: input.PublicationStatus, recoveryAction: input.RecoveryAction, terminalExit: input.TerminalExit,
		reconciliation: input.ReconciliationState, runManifestURI: input.RunManifestURI, reviewArtifactURI: input.ReviewArtifactURI,
	}
	if err := result.validate(); err != nil {
		return PublishedResult{}, fmt.Errorf("published composite result: %w", err)
	}
	return result, nil
}

// NewReconciliationFailure preserves the deterministic identity of a
// published composite when a later transport projection cannot complete.
func NewReconciliationFailure(result PublishedResult, detail string, cause error) error {
	if detail == "" {
		detail = "published composite requires exact reconciliation"
	}
	return failWithIdentity(domain.CompositePublicationIncomplete, detail, cause, result.SessionID(), result.RunID())
}

func (service *MutationService) ComposeReview(ctx context.Context, request Request) (PublishedResult, error) {
	if service == nil || service.composer == nil || service.publisher == nil {
		return PublishedResult{}, fail(domain.CompositeValidationFailed, "composition mutation is unavailable", nil)
	}
	composed, err := service.composer.Compose(ctx, request)
	if err != nil {
		return PublishedResult{}, err
	}
	runID, err := composed.Fingerprint.RunID()
	if err != nil {
		return PublishedResult{}, fail(domain.CompositeValidationFailed, "composition identity is invalid", err)
	}
	published, err := service.publisher.Publish(ctx, composed)
	if err != nil {
		var failure *Failure
		if !errors.As(err, &failure) || failure.ReasonCode() != domain.CompositePublicationIncomplete {
			return PublishedResult{}, err
		}
		return PublishedResult{}, failWithIdentity(domain.CompositePublicationIncomplete, "composite publication requires exact reconciliation", err, composed.SessionID, runID)
	}
	decision := published.Decision()
	final, hasFinal := published.Final()
	snapshot, hasSnapshot := published.Snapshot()
	terminalExit, hasTerminalExit := published.TerminalExit()
	if !hasFinal || !hasSnapshot || !hasTerminalExit || decision.Status() != domain.PublicationCommitted ||
		decision.Authority() != domain.PublicationAuthorityP2 || final != snapshot.Final().Identity() {
		return PublishedResult{}, failWithIdentity(domain.CompositePublicationIncomplete, "composite publication did not reconcile to P2", nil, composed.SessionID, runID)
	}
	reconciliation := domain.CompositionReconciled
	if _, issued := published.IssuedReviewID(); issued {
		reconciliation = domain.CompositionCreated
	}
	recovered := make([]domain.Role, 0, len(composed.Sources))
	recoveryRunIDs := make([]domain.RunID, 0, len(composed.Sources))
	for _, source := range composed.Sources {
		if source.Kind == "recovery" {
			recovered = append(recovered, source.Role)
			recoveryRunIDs = append(recoveryRunIDs, source.RunID)
		}
	}
	projectedReports, err := publication.ProjectRoleReportURIs(published)
	if err != nil {
		return PublishedResult{}, failWithIdentity(domain.CompositePublicationIncomplete, "published composite role report projection is invalid", err, composed.SessionID, runID)
	}
	reports := make([]RoleReportURI, 0, len(projectedReports))
	for _, report := range projectedReports {
		role := domain.Role(report.Role)
		if !role.Valid() {
			return PublishedResult{}, failWithIdentity(domain.CompositePublicationIncomplete, "published composite role report projection is invalid", nil, composed.SessionID, runID)
		}
		reports = append(reports, RoleReportURI{Role: role, URI: report.URI})
	}
	result, err := NewPublishedResult(PublishedResultInput{
		SessionID: composed.SessionID, RunID: runID, ReviewID: final.ReviewID(), RootRunID: request.RootRunID,
		RecoveryRunIDs: recoveryRunIDs, TargetSHA256: composed.TargetSHA256, RecoveredRoles: recovered,
		RoleReportURIs: reports, Coverage: composed.CoverageStatus, Content: composed.ContentVerdict,
		StructuredExtractionStatus: composed.ExtractionStatus, CIDecision: composed.CIDecision,
		PublicationStatus: decision.Status(), RecoveryAction: decision.Action(), TerminalExit: terminalExit,
		ReconciliationState: reconciliation, RunManifestURI: ".mulgae/" + snapshot.Manifest().Path().String(),
		ReviewArtifactURI: ".mulgae/" + final.Path().String(),
	})
	if err != nil {
		return PublishedResult{}, failWithIdentity(domain.CompositePublicationIncomplete, "published composite projection is invalid", err, composed.SessionID, runID)
	}
	return result, nil
}

func (result PublishedResult) validate() error {
	if _, err := domain.ParseSessionID(result.sessionID.String()); err != nil {
		return err
	}
	if _, err := domain.ParseRunID(result.rootRunID.String()); err != nil || len(result.recoveryRunIDs) == 0 || len(result.recoveryRunIDs) > len(domain.FixedRoleOrder()) || len(result.recoveredRoles) != len(result.recoveryRunIDs) {
		return fmt.Errorf("published composite selection is invalid")
	}
	seenRuns := map[string]struct{}{result.rootRunID.String(): {}}
	for _, recoveryRunID := range result.recoveryRunIDs {
		if _, err := domain.ParseRunID(recoveryRunID.String()); err != nil {
			return fmt.Errorf("published composite recovery identity is invalid")
		}
		if _, duplicate := seenRuns[recoveryRunID.String()]; duplicate {
			return fmt.Errorf("published composite recovery identity is duplicated")
		}
		seenRuns[recoveryRunID.String()] = struct{}{}
	}
	if _, err := domain.ParseRunID(result.runID.String()); err != nil {
		return err
	}
	if _, err := domain.ParseReviewID(result.reviewID.String()); err != nil {
		return err
	}
	exitInput, err := domain.NewOperationalExitInput(result.terminalExit.Reasons())
	if err != nil {
		return fmt.Errorf("published composite terminal exit is invalid: %w", err)
	}
	reducedExit, err := domain.ReduceOperationalExit(exitInput)
	if err != nil || reducedExit.Code() != result.terminalExit.Code() {
		return fmt.Errorf("published composite terminal exit is inconsistent")
	}
	if result.ci == domain.CIPass && result.terminalExit.Code() != domain.ExitCommittedPass ||
		result.ci == domain.CIFail && result.terminalExit.Code() != domain.ExitCommittedCIRejected {
		return fmt.Errorf("published composite CI decision and terminal exit are inconsistent")
	}
	seenRoles := make(map[domain.Role]struct{}, len(result.roleReportURIs))
	for _, report := range result.roleReportURIs {
		if !report.Role.Valid() || report.URI != ".mulgae/"+result.sessionID.String()+"/"+result.runID.String()+"/role-reports/"+string(report.Role)+".md" {
			return fmt.Errorf("published composite role report is invalid")
		}
		if _, duplicate := seenRoles[report.Role]; duplicate {
			return fmt.Errorf("published composite role report is duplicated")
		}
		seenRoles[report.Role] = struct{}{}
	}
	seenRecovered := make(map[domain.Role]struct{}, len(result.recoveredRoles))
	for _, role := range result.recoveredRoles {
		if !role.Valid() {
			return fmt.Errorf("published composite recovery role is invalid")
		}
		if _, duplicate := seenRecovered[role]; duplicate {
			return fmt.Errorf("published composite recovery role is duplicated")
		}
		if _, reported := seenRoles[role]; !reported {
			return fmt.Errorf("published composite recovery role has no report")
		}
		seenRecovered[role] = struct{}{}
	}
	if !validDigest(result.targetSHA256) || len(result.recoveredRoles) == 0 || result.coverage != domain.CoverageComplete ||
		!result.content.Valid() || !result.extraction.Valid() || !result.ci.Valid() {
		return fmt.Errorf("published composite outcome is inconsistent")
	}
	if result.publication != domain.PublicationCommitted || result.recoveryAction != domain.RecoveryActionReconstructCompletedStatus ||
		(result.reconciliation != domain.CompositionCreated && result.reconciliation != domain.CompositionReconciled) {
		return fmt.Errorf("published composite authority is inconsistent")
	}
	if result.runManifestURI != ".mulgae/"+result.sessionID.String()+"/"+result.runID.String()+"/manifest.json" ||
		result.reviewArtifactURI != ".mulgae/"+result.sessionID.String()+"/"+result.runID.String()+"/review_"+result.reviewID.String()+".json" ||
		len(result.roleReportURIs) == 0 {
		return fmt.Errorf("published composite artifact identity is inconsistent")
	}
	return nil
}

func (result PublishedResult) SessionID() domain.SessionID { return result.sessionID }
func (result PublishedResult) RunID() domain.RunID         { return result.runID }
func (result PublishedResult) ReviewID() domain.ReviewID   { return result.reviewID }
func (result PublishedResult) RootRunID() domain.RunID     { return result.rootRunID }
func (result PublishedResult) RecoveryRunIDs() []domain.RunID {
	return append([]domain.RunID(nil), result.recoveryRunIDs...)
}
func (result PublishedResult) TargetSHA256() string { return result.targetSHA256 }
func (result PublishedResult) RecoveredRoles() []domain.Role {
	return append([]domain.Role(nil), result.recoveredRoles...)
}
func (result PublishedResult) RoleReportURIs() []RoleReportURI {
	return append([]RoleReportURI(nil), result.roleReportURIs...)
}
func (result PublishedResult) CoverageStatus() domain.CoverageStatus { return result.coverage }
func (result PublishedResult) ContentVerdict() domain.ContentVerdict { return result.content }
func (result PublishedResult) StructuredExtractionStatus() domain.StructuredExtractionStatus {
	return result.extraction
}
func (result PublishedResult) CIDecision() domain.CIDecision               { return result.ci }
func (result PublishedResult) PublicationStatus() domain.PublicationStatus { return result.publication }
func (result PublishedResult) RecoveryAction() domain.RecoveryAction       { return result.recoveryAction }
func (result PublishedResult) TerminalExit() domain.OperationalExitDecision {
	return result.terminalExit
}
func (result PublishedResult) ReconciliationState() domain.CompositionState {
	return result.reconciliation
}
func (result PublishedResult) RunManifestURI() string    { return result.runManifestURI }
func (result PublishedResult) ReviewArtifactURI() string { return result.reviewArtifactURI }
