package reviewrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RequestAdmission derives the plan and receipt from the captured input and the
// already admitted configuration. It has no provider or publication authority.
type RequestAdmission interface {
	Admit(context.Context, Request, CapturedRunInput, domain.ProjectBinding) (AdmittedRequest, error)
}

type AdmittedRequest struct {
	Receipt RequestReceipt
	Plan    ExecutionPlan
}

func guardFailure(reason error) error {
	failure, err := domain.NewFailure("review.admission", domain.FailureConfiguration, reason.Error(), reason)
	if err != nil {
		return fmt.Errorf("review admission: %w", reason)
	}
	return failure
}

func observedProjectBinding(lease ports.ProjectBindingLease) (domain.ProjectBinding, error) {
	observation := lease.Observation()
	return NewProjectBinding(observation.Root, observation.GitDirectory, observation.CommonDirectory, observation.RootIdentity, observation.GitIdentity, observation.CommonIdentity)
}

func projectAdmissionFailure(cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	failure, err := domain.NewFailure("review.project_binding", domain.FailureSecurityPolicy, "project binding unavailable or changed", cause)
	if err != nil {
		return cause
	}
	return failure
}
