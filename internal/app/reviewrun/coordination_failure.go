package reviewrun

import (
	"context"
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type coordinationPhaseError struct {
	phase   string
	monitor bool
	err     error
}

func (e *coordinationPhaseError) Error() string { return e.err.Error() }
func (e *coordinationPhaseError) Unwrap() error { return e.err }

func withCoordinationPhase(phase string, monitor bool, err error) error {
	if err == nil {
		return nil
	}
	return &coordinationPhaseError{phase: phase, monitor: monitor, err: err}
}

func coordinationError(reason ports.ReviewCoordinationReason, operation ports.ReviewLockOperation, uncertain bool, cause error) error {
	return &ports.ReviewCoordinationError{Reason: reason, Operation: operation, Retry: ports.ReviewCoordinationRetryInspectFirst, Uncertain: uncertain, Cause: cause}
}

// Coordination failures are never provider faults. Inspect the complete cause
// tree so cancellation cannot hide an uncertain mutation or a persistence fault.
func coordinationFailure(err error, held bool) error {
	if err == nil {
		return nil
	}
	class := domain.FailureConfiguration
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		class = domain.FailureCancelled
	}
	if held {
		class = domain.FailureArtifact
	}
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if phaseErr, ok := current.(*coordinationPhaseError); ok && phaseErr.monitor {
			class = domain.FailureArtifact
		}
		if coordination, ok := current.(*ports.ReviewCoordinationError); ok && (coordination.Uncertain || coordination.Reason == ports.ReviewCoordinationReasonPersistenceRefused || coordination.Reason == ports.ReviewCoordinationReasonObservationPersistFailed) {
			class = domain.FailureArtifact
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
		} else if child, ok := current.(interface{ Unwrap() error }); ok {
			visit(child.Unwrap())
		}
	}
	visit(err)
	failure, _ := domain.NewFailure("review.coordination", class, "review coordination failed", err)
	return failure
}

func unsafeCoordinationDisposition(err error) bool {
	class := runtimeDiagnosticFailureClass(err)
	if class == domain.FailureSecurityPolicy || class == domain.FailureInternal {
		return true
	}
	var unsafe func(error) bool
	unsafe = func(current error) bool {
		if current == nil {
			return false
		}
		if fault, ok := current.(*ports.ReviewCoordinationError); ok {
			switch fault.Reason {
			case ports.ReviewCoordinationReasonProtocolIncompatible, ports.ReviewCoordinationReasonInstallationMismatch,
				ports.ReviewCoordinationReasonParentContextInvalid, ports.ReviewCoordinationReasonLockStateConflict:
				return true
			}
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				if unsafe(child) {
					return true
				}
			}
		} else if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			return unsafe(wrapped.Unwrap())
		}
		return false
	}
	return unsafe(err)
}
