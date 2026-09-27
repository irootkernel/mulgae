package reviewcompose

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// QueryReader adapts the shared exact-run query authority to composition.
type QueryReader struct {
	root    ports.AnchoredRoot
	queries *query.Service
}

func NewQueryReader(root ports.AnchoredRoot, queries *query.Service) (*QueryReader, error) {
	if !root.Valid() || queries == nil {
		return nil, fmt.Errorf("review composition query reader: root and query service are required")
	}
	return &QueryReader{root: root, queries: queries}, nil
}

func (reader *QueryReader) ReadCompositionSource(ctx context.Context, runID domain.RunID) (Source, error) {
	if reader == nil || reader.queries == nil || !reader.root.Valid() {
		return Source{}, fmt.Errorf("review composition query reader is unavailable")
	}
	run, err := reader.queries.ResolveRun(ctx, reader.root, runID)
	if err != nil {
		return Source{}, err
	}
	snapshot, recoveryErr := reader.queries.ReadFailedRunRecovery(ctx, run)
	if recoveryErr == nil {
		source, err := sourceFromRecovery(snapshot)
		if err != nil {
			return Source{}, err
		}
		providers, err := reader.queries.ReadRecoveryCompositionProviders(ctx, run)
		if err != nil {
			return Source{}, err
		}
		source.Support.Source.ProviderIdentities = providers
		confirmed, err := reader.queries.ReadFailedRunRecovery(ctx, run)
		if err != nil {
			return Source{}, err
		}
		reference, err := confirmed.Reference()
		if err != nil || reference.RecoveryManifestSHA256() != source.RecoveryManifestSHA256 {
			return Source{}, fmt.Errorf("recovery source changed while material was captured")
		}
		return source, nil
	}
	if !errors.Is(recoveryErr, recovery.ErrUnavailable) {
		return Source{}, recoveryErr
	}
	review, err := reader.queries.ReadCommittedForComposition(ctx, run)
	if err != nil {
		return Source{}, err
	}
	target, err := reader.queries.ReadRuntimeTarget(ctx, run)
	if err != nil {
		return Source{}, err
	}
	source, err := sourceFromCommitted(review)
	if err != nil {
		return Source{}, err
	}
	source.TargetIdentity = target.Identity()
	source.TargetBytes = target.Bytes()
	source.CapturedArchive = target.CapturedArchive()
	for index, item := range review.RoleReports() {
		content, readErr := reader.queries.ReadCommittedRoleReport(ctx, run, item)
		if readErr != nil {
			return Source{}, readErr
		}
		source.RoleReports[index].Bytes = content
	}
	support, err := reader.queries.ReadCompositionSupport(ctx, run)
	if err != nil {
		return Source{}, err
	}
	source.Support = &support
	confirmed, err := reader.queries.ReadCommitted(ctx, run)
	if err != nil || confirmed.ReviewID() != review.ReviewID() || confirmed.FinalSHA256() != review.FinalSHA256() || confirmed.ManifestSHA256() != review.ManifestSHA256() || confirmed.Epoch() != review.Epoch() {
		return Source{}, fmt.Errorf("composition source changed while material was captured")
	}
	return source, nil
}

func sourceFromCommitted(review query.CommittedReview) (Source, error) {
	source := Source{
		SessionID: review.SessionID(), RunID: review.RunID(), ReviewID: review.ReviewID(),
		RunType: review.RunType(), TargetSHA256: review.TargetSHA256(), Coverage: review.CoverageStatus(),
		Threshold: review.RequestChangesThreshold(),
	}
	lineage := review.Lineage()
	if sourceRunID, ok := lineage.SourceRunID(); ok {
		source.SourceRunID, source.HasSource = sourceRunID, true
		sourceReviewID, present := lineage.SourceReviewID()
		recoveryHash, hasRecovery := lineage.SourceRecoveryManifestSHA256()
		if present == hasRecovery {
			return Source{}, fmt.Errorf("committed source lineage has ambiguous identity")
		}
		source.SourceReviewID = sourceReviewID
		source.SourceRecoveryManifestSHA256 = recoveryHash
	}
	if sourceAttemptID, ok := lineage.SourceAttemptID(); ok {
		source.SourceAttemptID, source.HasSourceAttempt = sourceAttemptID, true
	}
	for _, item := range review.Roles() {
		attemptID, hasAttempt := item.AttemptID()
		provider, _ := item.ProviderInstance()
		source.Roles = append(source.Roles, Role{
			Name: item.Name(), Required: item.Required(), Outcome: item.Outcome(),
			AttemptID: attemptID, HasAttempt: hasAttempt, ProviderInstance: provider,
			FindingIDs: item.ValidFindingIDs(), ReportsOnly: item.ReportsOnly(),
		})
	}
	for _, item := range review.RoleReports() {
		role := domain.Role(item.Role())
		attemptID, err := domain.ParseAttemptID(item.AttemptID())
		if err != nil || !role.Valid() {
			return Source{}, fmt.Errorf("committed role report identity is invalid")
		}
		source.RoleReports = append(source.RoleReports, RoleReport{
			Role: role, AttemptID: attemptID, ProviderInstance: item.ProviderInstance(),
			Path: item.Path(), SHA256: item.SHA256(), ByteLength: item.ByteLength(), ContentType: item.ContentType(),
		})
	}
	for _, item := range review.Attempts() {
		source.Attempts = append(source.Attempts, Attempt{
			AttemptID: item.AttemptID(), Role: item.Role(), ProviderInstance: item.ProviderInstance(), State: item.State(),
		})
	}
	for _, item := range review.Findings() {
		source.Findings = append(source.Findings, SourceFinding{
			ID: item.ID(), Fingerprint: item.Fingerprint(), Role: item.Role(), ProviderInstance: item.ProviderInstance(),
			Severity: item.Severity(), Title: item.Title(), Description: item.Description(),
			Recommendation: item.Recommendation(), Confidence: item.Confidence(), Lifecycle: item.Lifecycle(),
		})
	}
	return source, nil
}
