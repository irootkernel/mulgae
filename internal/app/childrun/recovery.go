package childrun

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// BindRecoveryCleanup transfers the caller's one-shot cleanup boundary for a
// failed rerun. The callback must return the actual terminal release receipt.
func (executor *Executor) BindRecoveryCleanup(snapshotSHA256 string, cleanup func(context.Context, domain.RunID) (ports.WorkspaceTerminalReceipt, error)) error {
	if executor == nil || cleanup == nil || executor.recoveryCleanup != nil || snapshotSHA256 == "" {
		return fmt.Errorf("child recovery: invalid cleanup authority")
	}
	executor.recoveryCleanup = cleanup
	executor.recoverySnapshotSHA256 = snapshotSHA256
	return nil
}
func replayPublicationContext(child rerun.ChildReplay, parent, source domain.RunID) (publication.RunPublicationContext, error) {
	mode := publication.ReplayMode(child.Mode)
	if child.SourceRecoveryManifestSHA256 != "" {
		if child.SourceReviewID.String() != "" {
			return publication.RunPublicationContext{}, fmt.Errorf("child recovery: ambiguous source identity")
		}
		reference, err := domain.NewRecoverySourceReference(source, child.SourceRecoveryManifestSHA256)
		if err != nil {
			return publication.RunPublicationContext{}, err
		}
		return publication.NewRecoveryRerunPublicationContext(parent, reference, child.SourceAttemptID, mode)
	}
	return publication.NewChildPublicationContext(domain.RunTypeRerun, parent, source, child.SourceReviewID, &child.SourceAttemptID, nil, &mode)
}
func (executor *Executor) preserveFailedReplay(ctx context.Context, result review.CoordinatorResult, target domain.TargetIdentity, lineage publication.RunPublicationContext) error {
	if executor.recoveryCleanup == nil {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_unavailable")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cancelled: %w", err)
	}
	initial := executor.runtime.DrainInitialInputsForRun(result.RunID())
	prepared, err := publication.PrepareFailedRunRecovery(ctx, result, target, executor.config.SeverityThreshold, executor.recoverySnapshotSHA256, lineage, initial)
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_inputs_invalid: %w", err)
	}
	receipt, err := executor.recoveryCleanup(ctx, result.RunID())
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_storage_failed: %w", err)
	}
	if _, err := executor.publisher.PersistFailedRunRecovery(ctx, executor.artifactRoot, prepared, receipt); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_storage_failed: %w", err)
	}
	return nil
}
