package mulgae

import (
	"context"
	"errors"

	appclean "github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/domain"
)

// NewRetentionService adapts the cleanup application service to the command boundary.
func NewRetentionService(service *appclean.Service) RetentionService {
	if service == nil {
		return nil
	}
	return retentionAdapter{service: service}
}

type retentionAdapter struct{ service *appclean.Service }

func (adapter retentionAdapter) CleanRuns(ctx context.Context, request RetentionRequest) (RetentionResult, error) {
	result, err := adapter.service.Run(ctx, appclean.Request{
		OlderThanDays: request.OlderThanDays,
		All:           request.All,
		DryRun:        request.DryRun,
	})
	if err != nil {
		return RetentionResult{}, classifyCleanFailure(err)
	}
	return RetentionResult{
		DryRun:           result.DryRun,
		AffectedRunCount: result.AffectedRunCount,
		AffectedBytes:    result.AffectedBytes,
	}, nil
}

func classifyCleanFailure(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var failure *appclean.Failure
	if !errors.As(err, &failure) {
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup operation failed", err)
	}
	switch failure.Kind {
	case appclean.FailureStalePlan:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup plan is stale", err)
	case appclean.FailureInvalidSnapshot, appclean.FailureInvalidGraph, appclean.FailureInvalidPath:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup state is unavailable or invalid", err)
	case appclean.FailureTombstone:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup tombstone operation failed", err)
	default:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup operation failed", err)
	}
}
