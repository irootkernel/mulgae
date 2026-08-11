package review

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (execution *coordinatorExecution) emitRuntimeDiagnostics(trace CoordinatorTraceEvent) error {
	if execution == nil || execution.coordinator == nil || nilInterface(execution.coordinator.diagnostics) {
		return nil
	}
	inputs := execution.coordinatorDiagnosticInputs(trace)
	var lastSequence uint64
	for _, input := range inputs {
		draft, err := domain.NewRuntimeDiagnosticEventDraft(input)
		if err != nil {
			return coordinatorDiagnosticFailure(err)
		}
		event, err := execution.coordinator.diagnostics.Emit(context.WithoutCancel(execution.runContext), draft)
		if errors.Is(err, ports.ErrRuntimeDiagnosticEventDropped) {
			continue
		}
		if err != nil {
			return coordinatorDiagnosticFailure(err)
		}
		lastSequence = event.Sequence()
	}
	if trace.hasAttempt {
		if err := execution.replaceDiagnosticAttemptStatus(trace, lastSequence); err != nil {
			return coordinatorDiagnosticFailure(err)
		}
	}
	return nil
}

func (execution *coordinatorExecution) persistInitiatingFailure(job InvocationJob, outcome AttemptOutcome) error {
	if execution == nil || execution.coordinator == nil || nilInterface(execution.coordinator.diagnostics) || outcome.Succeeded() {
		return nil
	}
	condition, ok := outcome.Condition()
	if !ok {
		condition = AttemptConditionInternalInvariant
	}
	draft, err := domain.NewRuntimeDiagnosticEventDraft(domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticError, Component: "coordinator", Operation: "stop",
		Event: domain.DiagnosticAttemptFailed, SessionID: execution.run.SessionID(), RunID: execution.run.ID(),
		AttemptID: job.AttemptID(), Role: job.Role(), Provider: job.Route().ProviderInstance(),
		Cause: diagnosticCauseForCondition(condition), Failure: string(condition), State: string(domain.AttemptRunning), Outcome: string(condition),
	})
	if err != nil {
		return coordinatorDiagnosticFailure(err)
	}
	if _, err := execution.coordinator.diagnostics.Emit(context.WithoutCancel(execution.runContext), draft); err != nil {
		return coordinatorDiagnosticFailure(err)
	}
	return nil
}

func (execution *coordinatorExecution) coordinatorDiagnosticInputs(trace CoordinatorTraceEvent) []domain.RuntimeDiagnosticEventInput {
	base := domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticInfo, Component: "coordinator", Operation: "transition",
		SessionID: execution.run.SessionID(), RunID: execution.run.ID(), Role: trace.role,
	}
	if trace.hasAttempt {
		base.AttemptID = trace.attemptID
		base.Provider = execution.diagnosticAttemptProvider(trace.attemptID)
	}
	if trace.hasCondition {
		base.Cause = diagnosticCauseForCondition(trace.condition)
		base.Failure = string(trace.condition)
	}
	add := func(level domain.RuntimeDiagnosticLevel, code domain.RuntimeDiagnosticEventCode, state, outcome string) domain.RuntimeDiagnosticEventInput {
		input := base
		input.Level, input.Event, input.State, input.Outcome = level, code, state, outcome
		return input
	}
	switch trace.kind {
	case CoordinatorEventRunStarted:
		return []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticInfo, domain.DiagnosticRunStarted, string(domain.RunRunning), "")}
	case CoordinatorEventAttemptQueued:
		inputs := []domain.RuntimeDiagnosticEventInput{
			add(domain.RuntimeDiagnosticInfo, domain.DiagnosticRolePathScheduled, string(domain.AttemptQueued), ""),
			add(domain.RuntimeDiagnosticInfo, domain.DiagnosticAttemptCreated, string(domain.AttemptQueued), ""),
			add(domain.RuntimeDiagnosticInfo, domain.DiagnosticAttemptStarted, string(domain.AttemptRunning), ""),
		}
		return inputs
	case CoordinatorEventInvocationDispatched:
		inputs := []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticInfo, domain.DiagnosticRolePathStarted, string(domain.InvocationRunning), "")}
		if trace.purpose == domain.InvocationRepair {
			inputs = append(inputs, add(domain.RuntimeDiagnosticWarn, domain.DiagnosticRepairStarted, string(domain.AttemptRepairing), ""))
		}
		return inputs
	case CoordinatorEventRepairQueued:
		return []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticWarn, domain.DiagnosticRepairScheduled, string(domain.AttemptRepairing), "")}
	case CoordinatorEventRoleTerminal:
		state := traceAttemptState(execution, trace.attemptID)
		level, attemptEvent := domain.RuntimeDiagnosticError, domain.DiagnosticAttemptFailed
		roleEvent := domain.DiagnosticRoleExhausted
		if state == domain.AttemptSucceeded {
			level, attemptEvent, roleEvent = domain.RuntimeDiagnosticInfo, domain.DiagnosticAttemptCompleted, domain.DiagnosticRoleCompleted
		}
		inputs := []domain.RuntimeDiagnosticEventInput{add(level, attemptEvent, string(state), string(trace.condition))}
		if execution.diagnosticAttemptUsedRepair(trace.attemptID) {
			if state == domain.AttemptSucceeded {
				inputs = append(inputs, add(domain.RuntimeDiagnosticWarn, domain.DiagnosticRepairCompleted, string(state), string(trace.condition)))
			} else {
				inputs = append(inputs, add(domain.RuntimeDiagnosticError, domain.DiagnosticRepairExhausted, string(state), string(trace.condition)))
			}
		}
		if state != domain.AttemptSucceeded && execution.diagnosticRoleProviderUnusable(trace.role) {
			inputs = append(inputs, add(domain.RuntimeDiagnosticError, domain.DiagnosticProviderQuarantined, string(state), string(trace.condition)))
		}
		roleLevel := domain.RuntimeDiagnosticError
		if roleEvent == domain.DiagnosticRoleCompleted {
			roleLevel = domain.RuntimeDiagnosticInfo
		}
		inputs = append(inputs, add(roleLevel, roleEvent, "", string(trace.condition)), add(domain.RuntimeDiagnosticInfo, domain.DiagnosticRolePathCompleted, "", string(trace.condition)))
		return inputs
	case CoordinatorEventCancellationRequested:
		return []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticInfo, domain.DiagnosticRolePathCancelled, "", string(trace.condition))}
	case CoordinatorEventLanesCloseAuthorized:
		return []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticInfo, domain.DiagnosticReductionStarted, "", "")}
	case CoordinatorEventRunTerminal:
		return []domain.RuntimeDiagnosticEventInput{add(domain.RuntimeDiagnosticInfo, domain.DiagnosticReductionCompleted, string(trace.runState), "")}
	default:
		return nil
	}
}

func (execution *coordinatorExecution) diagnosticAttemptUsedRepair(id domain.AttemptID) bool {
	for _, role := range execution.roles {
		for index := range role.attempts {
			if role.attempts[index].attempt.ID() == id {
				return role.attempts[index].repairUsed
			}
		}
	}
	return false
}

// diagnosticRoleProviderUnusable reports whether this role's failure proved its
// provider unusable, so the runtime log records that the operator must fix or
// replace the provider rather than simply rerun.
func (execution *coordinatorExecution) diagnosticRoleProviderUnusable(role domain.Role) bool {
	state, ok := execution.roles[role]
	return ok && state.providerUnusable
}

func (execution *coordinatorExecution) diagnosticAttemptProvider(id domain.AttemptID) string {
	for _, role := range execution.roles {
		for index := range role.attempts {
			if role.attempts[index].attempt.ID() == id {
				return role.attempts[index].route.ProviderInstance()
			}
		}
	}
	return ""
}

func traceAttemptState(execution *coordinatorExecution, id domain.AttemptID) domain.AttemptState {
	for _, role := range execution.roles {
		for index := range role.attempts {
			if role.attempts[index].attempt.ID() == id {
				return role.attempts[index].attempt.State()
			}
		}
	}
	return domain.AttemptFailed
}

func (execution *coordinatorExecution) replaceDiagnosticAttemptStatus(trace CoordinatorTraceEvent, lastSequence uint64) error {
	now := execution.coordinator.clock.Now().UTC()
	started, ok := execution.diagnosticAttemptStarted[trace.attemptID]
	if !ok {
		started = now
		execution.diagnosticAttemptStarted[trace.attemptID] = started
	}
	state := traceAttemptState(execution, trace.attemptID)
	hasCompleted := state == domain.AttemptSucceeded || state == domain.AttemptFailed || state == domain.AttemptTimedOut || state == domain.AttemptCancelled || state == domain.AttemptBlocked
	completed := time.Time{}
	if hasCompleted {
		completed = now
	}
	selection := ports.RuntimeDiagnosticPrimary
	status, err := ports.NewRuntimeDiagnosticAttemptStatus(ports.RuntimeDiagnosticAttemptStatusInput{
		SessionID: execution.run.SessionID(), RunID: execution.run.ID(), AttemptID: trace.attemptID,
		Role: trace.role, Provider: execution.diagnosticAttemptProvider(trace.attemptID), Selection: selection,
		State: state, StartedAt: started, UpdatedAt: now, CompletedAt: completed, HasCompletedAt: hasCompleted,
		InvocationCount: execution.diagnosticAttemptInvocationCount(trace.attemptID), LastSequence: lastSequence,
		TerminalCause: diagnosticCauseForCondition(trace.condition),
	})
	if err != nil {
		return err
	}
	return execution.coordinator.diagnostics.ReplaceAttemptStatus(context.WithoutCancel(execution.runContext), status)
}

func (execution *coordinatorExecution) diagnosticAttemptInvocationCount(id domain.AttemptID) int {
	for _, role := range execution.roles {
		for index := range role.attempts {
			if role.attempts[index].attempt.ID() == id {
				return len(role.attempts[index].attempt.Invocations())
			}
		}
	}
	return 0
}

func diagnosticCauseForCondition(condition AttemptCondition) domain.RuntimeDiagnosticCause {
	switch condition {
	case AttemptConditionLoginRequired:
		return domain.DiagnosticCauseLoginRequired
	case AttemptConditionAuthentication:
		return domain.DiagnosticCauseAuthenticationFailed
	case AttemptConditionQuota:
		return domain.DiagnosticCauseQuotaExceeded
	case AttemptConditionRateLimit:
		return domain.DiagnosticCauseRateLimited
	case AttemptConditionTimeout:
		return domain.DiagnosticCauseTimedOut
	case AttemptConditionProviderTimeout:
		return domain.DiagnosticCauseTimedOut
	case AttemptConditionProviderPermissionDenied:
		return domain.DiagnosticCausePermissionDenied
	case AttemptConditionArtifactFailure:
		return domain.DiagnosticCausePersistenceFailed
	case AttemptConditionProviderOutputMissing:
		return domain.DiagnosticCauseOutputMissing
	case AttemptConditionProviderOutputDecodeFailed:
		return domain.DiagnosticCauseOutputDecodeFailed
	case AttemptConditionInvalidProviderOutput, AttemptConditionUnrepairableProviderOutput,
		AttemptConditionInvalidEvidenceClaim, AttemptConditionUnrepairableEvidence, AttemptConditionSemanticContradiction:
		return domain.DiagnosticCauseCandidateValidationFailed
	case AttemptConditionSecurityViolation, AttemptConditionMutationViolation:
		return domain.DiagnosticCauseObservationMismatch
	case AttemptConditionProviderUnavailable:
		return domain.DiagnosticCauseProviderExecutionFailed
	case AttemptConditionProviderSpawnFailed:
		return domain.DiagnosticCauseProviderSpawnFailed
	default:
		return ""
	}
}

// DiagnosticCauseForCondition projects one closed attempt condition to the
// safe runtime cause shared by review and specialized child-run diagnostics.
func DiagnosticCauseForCondition(condition AttemptCondition) domain.RuntimeDiagnosticCause {
	return diagnosticCauseForCondition(condition)
}

func coordinatorDiagnosticFailure(cause error) error {
	failure, err := domain.NewFailure("review.coordinator.diagnostics", domain.FailureArtifact, "runtime diagnostics persistence failed", cause)
	if err != nil {
		return fmt.Errorf("review coordinator: diagnostic failure: %w", err)
	}
	return failure
}
