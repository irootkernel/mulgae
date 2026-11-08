package reviewrun

import (
	"errors"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// CoordinationFailureReason returns only an owned bounded token. Native text,
// paths, request identities and transcripts never enter the public projection.
func CoordinationFailureReason(err error) (domain.RuntimeDiagnosticCause, bool) {
	class := runtimeDiagnosticFailureClass(err)
	if class == domain.FailureSecurityPolicy || class == domain.FailureInternal {
		return "", false
	}
	var fault *ports.ReviewCoordinationError
	if !errors.As(err, &fault) {
		return "", false
	}
	switch fault.Reason {
	case ports.ReviewCoordinationReasonLocalDrainUnverified:
		return domain.DiagnosticCauseCoordinationDrainUnverified, true
	case ports.ReviewCoordinationReasonPersistenceRefused, ports.ReviewCoordinationReasonObservationPersistFailed:
		return domain.DiagnosticCauseCoordinationPersistenceFailed, true
	case ports.ReviewCoordinationReasonHoldBudgetExceeded:
		return domain.DiagnosticCauseCoordinationHoldBudgetExceeded, true
	case ports.ReviewCoordinationReasonQueueExpired:
		return domain.DiagnosticCauseCoordinationQueueExpired, true
	case ports.ReviewCoordinationReasonContextCancelled:
		if !fault.Uncertain {
			return domain.DiagnosticCauseCoordinationCancelled, true
		}
	}
	if fault.Operation == ports.ReviewLockOperationRelease {
		return domain.DiagnosticCauseCoordinationDispositionFailed, true
	}
	if fault.Uncertain || fault.Operation == ports.ReviewLockOperationRenew || fault.Reason == ports.ReviewCoordinationReasonHoldExpired {
		return domain.DiagnosticCauseCoordinationProtectionLost, true
	}
	switch fault.Reason {
	case ports.ReviewCoordinationReasonInstallationNotSelected, ports.ReviewCoordinationReasonParentContextInvalid,
		ports.ReviewCoordinationReasonControllerUnreachable, ports.ReviewCoordinationReasonProtocolIncompatible,
		ports.ReviewCoordinationReasonInstallationMismatch, ports.ReviewCoordinationReasonCapabilityUnsupported,
		ports.ReviewCoordinationReasonResourceInvalid, ports.ReviewCoordinationReasonAcquireConflict,
		ports.ReviewCoordinationReasonAcquireInvalid, ports.ReviewCoordinationReasonAcquireOverloaded,
		ports.ReviewCoordinationReasonLockCancelled, ports.ReviewCoordinationReasonLockReleased,
		ports.ReviewCoordinationReasonLockStateConflict, ports.ReviewCoordinationReasonLockNotFound:
		return domain.DiagnosticCauseCoordinationReadinessFailed, true
	}
	return "", false
}

func coordinationDiagnosticSummary(err error) (ports.RuntimeDiagnosticSummary, bool) {
	cause, ok := CoordinationFailureReason(err)
	if !ok {
		return ports.RuntimeDiagnosticSummary{}, false
	}
	phase := "drain"
	var fault *ports.ReviewCoordinationError
	if errors.As(err, &fault) {
		switch fault.Operation {
		case ports.ReviewLockOperationHello, ports.ReviewLockOperationInspectResource:
			phase = "admission"
		case ports.ReviewLockOperationAcquire:
			phase = "acquire"
		case ports.ReviewLockOperationWait:
			phase = "wait"
		case ports.ReviewLockOperationRenew:
			phase = "renew"
		case ports.ReviewLockOperationRelease:
			phase = "release"
		case ports.ReviewLockOperationCancel:
			phase = "cancel"
		}
	}
	summary, err := ports.NewRuntimeDiagnosticSummary(ports.RuntimeDiagnosticSummaryInput{Component: "coordination", Phase: phase, InvariantID: string(cause)})
	return summary, err == nil
}
