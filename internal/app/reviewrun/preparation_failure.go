package reviewrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ReviewPreparationStage is one closed step after planning has been admitted
// and before the coordinator durably records run_started.
type ReviewPreparationStage string

const (
	ReviewPreparationPromptSource          ReviewPreparationStage = "prompt_source"
	ReviewPreparationProviderRuntime       ReviewPreparationStage = "provider_runtime"
	ReviewPreparationProviderOutputStaging ReviewPreparationStage = "provider_output_staging"
	ReviewPreparationCoordinator           ReviewPreparationStage = "coordinator"
	ReviewPreparationCoordinatorAdmission  ReviewPreparationStage = "coordinator_admission"
	ReviewPreparationRootRun               ReviewPreparationStage = "root_run"
)

func (stage ReviewPreparationStage) Valid() bool {
	return stage.diagnosticCause().Valid()
}

func (stage ReviewPreparationStage) diagnosticCause() domain.RuntimeDiagnosticCause {
	switch stage {
	case ReviewPreparationPromptSource:
		return domain.DiagnosticCauseReviewPromptSourcePreparationFailed
	case ReviewPreparationProviderRuntime:
		return domain.DiagnosticCauseReviewProviderRuntimePreparationFailed
	case ReviewPreparationProviderOutputStaging:
		return domain.DiagnosticCauseReviewProviderOutputStagingPreparationFailed
	case ReviewPreparationCoordinator:
		return domain.DiagnosticCauseReviewCoordinatorPreparationFailed
	case ReviewPreparationCoordinatorAdmission:
		return domain.DiagnosticCauseReviewCoordinatorAdmissionPreparationFailed
	case ReviewPreparationRootRun:
		return domain.DiagnosticCauseReviewRootRunPreparationFailed
	default:
		return ""
	}
}

type reviewPreparationFailure struct {
	stage ReviewPreparationStage
	cause error
}

type invalidReviewPreparationFailure struct {
	cause error
}

func (failure *invalidReviewPreparationFailure) Error() string {
	return "review preparation failure: invalid classification"
}

func (failure *invalidReviewPreparationFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// NewReviewPreparationFailure constructs a redaction-safe classified failure.
// The causal error remains available for in-process classification but is never
// included in Error, public diagnostics, or runtime diagnostic fields.
func NewReviewPreparationFailure(stage ReviewPreparationStage, cause error) error {
	if cause == nil {
		return errors.New("review preparation failure: invalid classification")
	}
	if !stage.Valid() {
		return &invalidReviewPreparationFailure{cause: cause}
	}
	return &reviewPreparationFailure{stage: stage, cause: cause}
}

func (failure *reviewPreparationFailure) Error() string {
	if failure == nil || !failure.stage.Valid() {
		return "review preparation failed"
	}
	return fmt.Sprintf("review preparation %s failed", failure.stage)
}

func (failure *reviewPreparationFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// ReviewPreparationFailureFromError returns the closed public-safe details of
// one preparation failure without exposing its causal error.
func ReviewPreparationFailureFromError(err error) (ReviewPreparationStage, domain.RuntimeDiagnosticCause, bool) {
	var failure *reviewPreparationFailure
	if !errors.As(err, &failure) || failure == nil || !failure.stage.Valid() {
		return "", "", false
	}
	var typed *domain.Failure
	if errors.As(failure.cause, &typed) || errors.Is(failure.cause, context.Canceled) || errors.Is(failure.cause, context.DeadlineExceeded) ||
		runtimeDiagnosticPersistenceFailure(err) {
		return "", "", false
	}
	cause := failure.stage.diagnosticCause()
	return failure.stage, cause, cause.Valid()
}
