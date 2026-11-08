package reviewrun

import (
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// CoordinationFailureReason returns only an owned bounded token. Native text,
// paths, request identities and transcripts never enter the public projection.
func CoordinationFailureReason(err error) (domain.RuntimeDiagnosticCause, bool) {
	candidate, ok := selectCoordinationCandidate(err)
	if !ok {
		return "", false
	}
	return candidate.cause, true
}

func coordinationDiagnosticSummary(err error) (ports.RuntimeDiagnosticSummary, bool) {
	candidate, ok := selectCoordinationCandidate(err)
	if !ok {
		return ports.RuntimeDiagnosticSummary{}, false
	}
	summary, err := ports.NewRuntimeDiagnosticSummary(ports.RuntimeDiagnosticSummaryInput{
		Component:   "coordination",
		Phase:       candidate.phase,
		InvariantID: string(candidate.cause),
	})
	return summary, err == nil
}

type coordinationDiagnosticCandidate struct {
	cause    domain.RuntimeDiagnosticCause
	phase    string
	priority int
}

func selectCoordinationCandidate(err error) (coordinationDiagnosticCandidate, bool) {
	class := runtimeDiagnosticFailureClass(err)
	if class == domain.FailureSecurityPolicy || class == domain.FailureInternal {
		return coordinationDiagnosticCandidate{}, false
	}
	var best coordinationDiagnosticCandidate
	var walk func(current error, enclosingPhase string, enclosingMonitor bool)
	walk = func(current error, enclosingPhase string, enclosingMonitor bool) {
		if current == nil {
			return
		}
		if phaseErr, ok := current.(*coordinationPhaseError); ok {
			if phaseErr.phase != "" {
				enclosingPhase = phaseErr.phase
			}
			if phaseErr.monitor {
				enclosingMonitor = true
			}
		}
		if fault, ok := current.(*ports.ReviewCoordinationError); ok && fault != nil {
			if candidate, ok := classifyCoordinationFault(fault, enclosingPhase, enclosingMonitor); ok && candidate.priority > best.priority {
				best = candidate
			}
			return
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				walk(child, enclosingPhase, enclosingMonitor)
			}
		} else if child, ok := current.(interface{ Unwrap() error }); ok {
			walk(child.Unwrap(), enclosingPhase, enclosingMonitor)
		}
	}
	walk(err, "", false)
	return best, best.priority > 0
}

func classifyCoordinationFault(fault *ports.ReviewCoordinationError, enclosingPhase string, enclosingMonitor bool) (coordinationDiagnosticCandidate, bool) {
	phase := enclosingPhase
	if phase == "" {
		phase = operationPhase(fault.Operation)
	}
	switch fault.Reason {
	case ports.ReviewCoordinationReasonLocalDrainUnverified:
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationDrainUnverified,
			phase:    "drain",
			priority: 60,
		}, true
	case ports.ReviewCoordinationReasonPersistenceRefused, ports.ReviewCoordinationReasonObservationPersistFailed:
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationPersistenceFailed,
			phase:    phase,
			priority: 50,
		}, true
	case ports.ReviewCoordinationReasonHoldBudgetExceeded:
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationHoldBudgetExceeded,
			phase:    phase,
			priority: 40,
		}, true
	}
	if enclosingMonitor {
		monitorPhase := enclosingPhase
		if monitorPhase == "" {
			monitorPhase = "monitor"
		}
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationProtectionLost,
			phase:    monitorPhase,
			priority: 30,
		}, true
	}
	switch fault.Reason {
	case ports.ReviewCoordinationReasonQueueExpired:
		if enclosingPhase == "admission" {
			return coordinationDiagnosticCandidate{
				cause:    domain.DiagnosticCauseCoordinationReadinessFailed,
				phase:    "admission",
				priority: 20,
			}, true
		}
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationQueueExpired,
			phase:    phase,
			priority: 20,
		}, true
	case ports.ReviewCoordinationReasonContextCancelled:
		if !fault.Uncertain {
			return coordinationDiagnosticCandidate{
				cause:    domain.DiagnosticCauseCoordinationCancelled,
				phase:    phase,
				priority: 10,
			}, true
		}
	}
	if fault.Operation == ports.ReviewLockOperationRelease {
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationDispositionFailed,
			phase:    "release",
			priority: 25,
		}, true
	}
	if fault.Uncertain || fault.Operation == ports.ReviewLockOperationRenew || (fault.Reason == ports.ReviewCoordinationReasonHoldExpired && enclosingPhase != "admission") {
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationProtectionLost,
			phase:    phase,
			priority: 30,
		}, true
	}
	switch fault.Reason {
	case ports.ReviewCoordinationReasonInstallationNotSelected, ports.ReviewCoordinationReasonParentContextInvalid,
		ports.ReviewCoordinationReasonControllerUnreachable, ports.ReviewCoordinationReasonProtocolIncompatible,
		ports.ReviewCoordinationReasonInstallationMismatch, ports.ReviewCoordinationReasonCapabilityUnsupported,
		ports.ReviewCoordinationReasonResourceInvalid, ports.ReviewCoordinationReasonAcquireConflict,
		ports.ReviewCoordinationReasonAcquireInvalid, ports.ReviewCoordinationReasonAcquireOverloaded,
		ports.ReviewCoordinationReasonLockCancelled, ports.ReviewCoordinationReasonLockReleased,
		ports.ReviewCoordinationReasonLockStateConflict, ports.ReviewCoordinationReasonLockNotFound,
		ports.ReviewCoordinationReasonHoldExpired:
		return coordinationDiagnosticCandidate{
			cause:    domain.DiagnosticCauseCoordinationReadinessFailed,
			phase:    phase,
			priority: 20,
		}, true
	}
	return coordinationDiagnosticCandidate{}, false
}

func operationPhase(op ports.ReviewLockOperation) string {
	switch op {
	case ports.ReviewLockOperationHello, ports.ReviewLockOperationInspectResource, ports.ReviewLockOperationList:
		return "admission"
	case ports.ReviewLockOperationAcquire:
		return "acquire"
	case ports.ReviewLockOperationWait:
		return "wait"
	case ports.ReviewLockOperationRenew:
		return "renew"
	case ports.ReviewLockOperationRelease:
		return "release"
	case ports.ReviewLockOperationCancel:
		return "cancel"
	default:
		return "drain"
	}
}
