package mulgae

import (
	"context"
	"errors"
	"strings"

	appclean "github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/domain"
)

// NewRetentionService adapts the cleanup application service to the command
// retention boundary without introducing provider authority or policy defaults.
func NewRetentionService(service *appclean.Service) RetentionService {
	if service == nil {
		return nil
	}
	return retentionAdapter{service: service}
}

type retentionAdapter struct{ service *appclean.Service }

func (adapter retentionAdapter) PlanAndApplyRetention(ctx context.Context, request RetentionRequest) (RetentionResult, error) {
	mode, err := cleanMode(request.Mode)
	if err != nil {
		return RetentionResult{}, err
	}
	expected := ""
	if request.ExpectedPlanSHA256 != nil {
		expected = *request.ExpectedPlanSHA256
	}
	result, err := adapter.service.Run(ctx, appclean.Request{Mode: mode, ExpectedPlanSHA256: expected})
	if err != nil {
		return RetentionResult{}, classifyCleanFailure(err)
	}
	return RetentionResult{
		Mode:         request.Mode,
		CleanPlanURI: cleanPlanURI(result.Plan.PlanHash),
		PlanSHA256:   result.Plan.PlanHash,
		Applied:      request.Mode == CleanModeApply,
		ExplainRows:  append([]string(nil), result.ExplainRows...),
	}, nil
}

func cleanMode(mode CleanMode) (appclean.Mode, error) {
	switch mode {
	case CleanModePlan:
		return appclean.ModeDryRun, nil
	case CleanModeExplain:
		return appclean.ModeExplain, nil
	case CleanModeApply:
		return appclean.ModeApply, nil
	default:
		return "", typedHandlerFailure("cli.clean", domain.FailureConfiguration, "unsupported clean mode", nil)
	}
}

func cleanPlanURI(hash string) string {
	return "store/clean/plans/" + strings.TrimPrefix(hash, "sha256:") + ".json"
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
		return typedHandlerFailure("cli.clean", domain.FailureConfiguration, "cleanup authority or snapshot is invalid", err)
	case appclean.FailureTombstone:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup tombstone operation failed", err)
	default:
		return typedHandlerFailure("cli.clean", domain.FailureArtifact, "cleanup operation failed", err)
	}
}
