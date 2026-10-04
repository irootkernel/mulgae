package reviewrun

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func guardFailure(reason error) error {
	failure, err := domain.NewFailure("review.admission", domain.FailureConfiguration, reason.Error(), reason)
	if err != nil {
		return fmt.Errorf("review admission: %w", reason)
	}
	return failure
}

// LiveSourceFailureClass maps the closed source boundary codes to application
// failure policy. Native Git diagnostics and paths are never public reasons.
func LiveSourceFailureClass(code ports.LiveSourceErrorCode) (domain.FailureClass, bool) {
	switch code {
	case ports.LiveSourceUnsafe:
		return domain.FailureSecurityPolicy, true
	case ports.LiveSourceInvalid, ports.LiveSourceConflict, ports.LiveSourceRevision, ports.LiveSourceNoMergeBase, ports.LiveSourceUnsupported:
		return domain.FailureConfiguration, true
	case ports.LiveSourceUnavailable:
		return domain.FailureArtifact, true
	default:
		return "", false
	}
}

func liveSourceAdmissionFailure(cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	var source *ports.LiveSourceError
	if errors.As(cause, &source) && source != nil {
		if class, ok := LiveSourceFailureClass(source.Code()); ok {
			failure, err := domain.NewFailure("review.source", class, "live source admission failed", cause)
			if err == nil {
				return failure
			}
		}
	}
	return cause
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
