package reviewcompose

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Publisher materializes a composed result through publication's shared atomic
// P0/P1/P2 state machine.
type Publisher struct {
	root        ports.AnchoredRoot
	publication *publication.Service
}

func NewPublisher(root ports.AnchoredRoot, service *publication.Service) (*Publisher, error) {
	if !root.Valid() || service == nil {
		return nil, fmt.Errorf("review composition publisher: root and publication service are required")
	}
	return &Publisher{root: root, publication: service}, nil
}

func (publisher *Publisher) Publish(ctx context.Context, result Result) (publication.PublicationResult, error) {
	if publisher == nil || publisher.publication == nil || !publisher.root.Valid() {
		return publication.PublicationResult{}, fail(domain.CompositeValidationFailed, "publisher is unavailable", nil)
	}
	runID, err := result.Fingerprint.RunID()
	if err != nil {
		return publication.PublicationResult{}, fail(domain.CompositeValidationFailed, "composition identity is invalid", err)
	}
	input := publication.CompositeCandidateInput{SessionID: result.SessionID, RunID: runID, Fingerprint: result.Fingerprint, RootRunID: result.RootRunID, RootReviewID: result.RootReviewID, RootRecoveryManifestSHA256: result.RootRecoveryManifestSHA256, Target: result.TargetIdentity, TargetBytes: result.TargetBytes, CapturedArchive: result.CapturedArchive, Threshold: result.Threshold, ContentVerdict: result.ContentVerdict, CoverageStatus: result.CoverageStatus, ExtractionStatus: result.ExtractionStatus, CIDecision: result.CIDecision, CIReasonCodes: result.CIReasonCodes}
	for _, source := range result.Sources {
		if source.Support != nil {
			input.SourceSupport = append(input.SourceSupport, compositesupport.Clone(*source.Support))
		}
		input.Sources = append(input.Sources, publication.CompositeSourceInput{Kind: source.Kind, Role: source.Role, RunID: source.RunID, ReviewID: source.ReviewID, RecoveryManifestSHA256: source.RecoveryManifestSHA256, AttemptID: source.AttemptID, RoleReportSHA256: source.RoleReport.SHA256})
		input.RoleReports = append(input.RoleReports, publication.CompositeRoleReportInput{Role: source.Role, AttemptID: source.AttemptID, ProviderInstance: source.RoleReport.ProviderInstance, SHA256: source.RoleReport.SHA256, Bytes: source.RoleReport.Bytes, SourceRunID: source.RunID})
	}
	for _, role := range result.Roles {
		input.Roles = append(input.Roles, publication.CompositeRoleInput{Role: role.Role, Required: role.Required, Outcome: role.Outcome, AttemptID: role.AttemptID, ProviderInstance: role.ProviderInstance, ValidFindingIDs: role.FindingIDs, SourceRunID: role.SourceRunID, SourceReviewID: role.SourceReviewID, SourceRecoveryManifestSHA256: role.SourceRecoveryManifestSHA256, ReportsOnly: role.ReportsOnly})
	}
	for _, finding := range result.Findings {
		input.Findings = append(input.Findings, publication.CompositeFindingInput{ID: finding.ID, Fingerprint: finding.Fingerprint, Role: finding.Role, Severity: finding.Severity, Title: finding.Title, Description: finding.Description, Recommendation: finding.Recommendation, Confidence: finding.Confidence, Lifecycle: finding.Lifecycle, SourceRunID: finding.SourceRunID, SourceReviewID: finding.SourceReviewID, SourceRecoveryManifestSHA256: finding.SourceRecoveryManifestSHA256, SourceAttemptID: finding.SourceAttemptID, SourceFindingID: finding.SourceFindingID})
	}
	candidate, err := publication.PrepareCompositeCandidate(input)
	if err != nil {
		return publication.PublicationResult{}, fail(domain.CompositeValidationFailed, "composite publication candidate is invalid", err)
	}
	published, err := publisher.publication.PublishCompositeNext(ctx, publisher.root, candidate)
	if err != nil {
		return publication.PublicationResult{}, fail(domain.CompositePublicationIncomplete, "composite publication did not reach P2", err)
	}
	return published, nil
}
