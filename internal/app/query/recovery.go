package query

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ReadFailedRunRecovery is separate from every final-review query. An absent
// manifest may lead a caller to a P2 source; a corrupt recovery never may.
func (service *Service) ReadFailedRunRecovery(ctx context.Context, run ports.PublicationRun) (recovery.Snapshot, error) {
	if err := service.preflight(ctx, "query.read_recovery"); err != nil {
		return recovery.Snapshot{}, err
	}
	snapshot, err := recovery.Read(ctx, service.store, service.validator, run, service.maxReadBytes)
	if err != nil {
		return recovery.Snapshot{}, err
	}
	observed, err := service.observe(ctx, run, "query.read_recovery")
	if err != nil {
		return recovery.Snapshot{}, err
	}
	if observed.decision.Status() != domain.PublicationNotPublished {
		return recovery.Snapshot{}, fmt.Errorf("recovery conflicts with publication state")
	}
	retired, err := service.recoveryArtifactRetired(ctx, run, snapshot, make(map[string]struct{}))
	if err != nil {
		return recovery.Snapshot{}, err
	}
	if retired {
		return recovery.Snapshot{}, typedFailure("query.read_recovery", domain.FailureArtifact, retiredProviderArtifactReason, nil)
	}
	if err := service.verifyRecoveryReplay(ctx, run, snapshot); err != nil {
		return recovery.Snapshot{}, dependencyFailure(ctx, "query.read_recovery", domain.FailureArtifact, "exact recovery lineage is invalid", err)
	}
	return snapshot, nil
}

func (service *Service) readRecoveryStatus(ctx context.Context, run ports.PublicationRun) (recovery.Status, domain.RunState, error) {
	snapshot, err := service.ReadFailedRunRecovery(ctx, run)
	if errors.Is(err, recovery.ErrUnavailable) {
		return recovery.UnavailableStatus("source_not_retained"), "", nil
	}
	if err != nil {
		return recovery.Status{}, "", err
	}
	return snapshot.Status(), snapshot.Document().RunState, nil
}

func (status RunStatus) FailedRunRecovery() recovery.Status {
	result := status.failedRunRecovery
	result.AcceptedRoles = slices.Clone(result.AcceptedRoles)
	result.RetryAttempts = slices.Clone(result.RetryAttempts)
	for _, field := range []**string{&result.SourceKind, &result.RunID, &result.ManifestSHA256, &result.UnavailableReason} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	return result
}
