package reviewrun

import (
	"context"
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// FailedRunRecoveryRetentionTimeout is the cooperative whole-retention budget
// shared by failed-run preparation, cleanup, diagnostics, and persistence.
const FailedRunRecoveryRetentionTimeout = 10 * time.Minute

// DetachedFailedRunRecoveryContext starts the shared retention budget. Caller
// cancellation is detached; the deadline is not refreshed per stage.
func DetachedFailedRunRecoveryContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), FailedRunRecoveryRetentionTimeout)
}

func (service *Service) preserveFailedRun(ctx context.Context, root ports.AnchoredRoot, cleanup *ReviewRunCleanup, result review.CoordinatorResult, target domain.TargetIdentity, threshold domain.Severity, initial []review.RuntimeArtifactInventory) error {
	committer, ok := service.dependencies.Publication.(publication.FailedRunRecoveryCommitter)
	if !ok {
		return fmt.Errorf("recovery unavailable: recovery_store_unavailable")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cancelled: %w", err)
	}
	lease := cleanup.WorkspaceLease()
	snapshot, err := publication.PrepareFailedRunRecovery(ctx, result, target, threshold, lease.WorkspaceSnapshotIdentity().ManifestSHA256(), publication.RunPublicationContext{}, initial)
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_inputs_invalid: %w", err)
	}
	// Failure remains authoritative. Bounded detached cleanup can establish a
	// replay source, but cannot convert this run into a published or successful review.
	if err := cleanup.observeRetention(ctx, domain.DiagnosticNamespaceDrainStarted, "provider_namespace", "drain"); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_diagnostics_failed: %w", err)
	}
	terminal, err := DrainRunAuthorityTerminalForRetention(ctx, cleanup.ProviderOwner())
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_failed: %w", err)
	}
	cleanup.setProviderTerminal(terminal.ProviderRunTerminalReceipt())
	if err := cleanup.observeRetention(ctx, domain.DiagnosticNamespaceDrained, "provider_namespace", "drain"); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_diagnostics_failed: %w", err)
	}
	completion, err := ports.NewWorkspaceCompletionEvidence(lease.WorkspaceSnapshotIdentity(), result.RunID().String(), cleanup.ProviderTerminalReceipt())
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_failed: %w", err)
	}
	if err := cleanup.observeRetention(ctx, domain.DiagnosticWorkspaceCleanupStarted, "workspace", "cleanup"); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_diagnostics_failed: %w", err)
	}
	receipt, err := lease.Release(completion)
	if err != nil {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_failed: %w", err)
	}
	if !workspaceReceiptMatchesCompletion(receipt, completion) {
		return fmt.Errorf("recovery unavailable: recovery_cleanup_receipt_invalid")
	}
	cleanup.setWorkspaceDrained()
	if err := cleanup.observeRetention(ctx, domain.DiagnosticWorkspaceCleanupCompleted, "workspace", "cleanup"); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_diagnostics_failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_storage_failed: %w", err)
	}
	if _, err := committer.PersistFailedRunRecovery(ctx, root, snapshot, receipt); err != nil {
		return fmt.Errorf("recovery unavailable: recovery_storage_failed: %w", err)
	}
	return nil
}
