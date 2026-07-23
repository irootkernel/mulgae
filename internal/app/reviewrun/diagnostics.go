package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type runtimeDiagnosticLifecycle struct {
	mu        sync.Mutex
	sink      ports.RuntimeDiagnosticSink
	identity  rootRunIdentity
	roles     []domain.Role
	clock     ports.Clock
	lastSeq   uint64
	finalized bool
}

func (lifecycle *runtimeDiagnosticLifecycle) ObservePublicationLifecycle(ctx context.Context, event publication.LifecycleEvent) error {
	code := domain.RuntimeDiagnosticEventCode("")
	level := domain.RuntimeDiagnosticInfo
	switch event {
	case publication.LifecyclePreparationStarted:
		code = domain.DiagnosticPublicationPreparationStarted
	case publication.LifecycleStaged:
		code = domain.DiagnosticPublicationStaged
	case publication.LifecycleInstalled:
		code = domain.DiagnosticPublicationInstalled
	case publication.LifecycleCommitted:
		code = domain.DiagnosticPublicationCommitted
	case publication.LifecycleFailed:
		code = domain.DiagnosticPublicationFailed
		level = domain.RuntimeDiagnosticError
	default:
		return diagnosticArtifactFailure("reviewrun.diagnostics.publication", fmt.Errorf("unknown publication lifecycle event %q", event))
	}
	_, err := lifecycle.emit(ctx, domain.RuntimeDiagnosticEventInput{
		Level: level, Component: "publication", Operation: "commit", Event: code,
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID,
	})
	return err
}

func (lifecycle *runtimeDiagnosticLifecycle) observeRunEvent(
	ctx context.Context,
	event domain.RuntimeDiagnosticEventCode,
	component string,
	operation string,
	role domain.Role,
) error {
	_, err := lifecycle.emit(ctx, domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticInfo, Component: component, Operation: operation, Event: event,
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID, Role: role,
	})
	return err
}

func (lifecycle *runtimeDiagnosticLifecycle) RuntimeDiagnosticSink(runID domain.RunID) (ports.RuntimeDiagnosticSink, bool) {
	if lifecycle == nil || runID != lifecycle.identity.runID || nilInterface(lifecycle.sink) {
		return nil, false
	}
	return lifecycle.sink, true
}

func (lifecycle *runtimeDiagnosticLifecycle) Sink() ports.RuntimeDiagnosticSink {
	if lifecycle == nil {
		return nil
	}
	return lifecycle.sink
}

func openRuntimeDiagnosticLifecycle(
	ctx context.Context,
	factory ports.RuntimeDiagnosticSinkFactory,
	root ports.AnchoredRoot,
	identity rootRunIdentity,
	roles []domain.Role,
	clock ports.Clock,
) (*runtimeDiagnosticLifecycle, error) {
	request, err := ports.NewRuntimeDiagnosticOpenRequest(root, identity.sessionID, identity.runID, identity.startedAt)
	if err != nil {
		return nil, diagnosticArtifactFailure("reviewrun.diagnostics.open", ports.NewRuntimeDiagnosticPersistenceError(ports.DiagnosticPersistenceOpen, ports.DiagnosticPersistenceInvalidInput, err))
	}
	sink, err := factory.Open(ctx, request)
	if err != nil || nilInterface(sink) {
		if err == nil {
			err = fmt.Errorf("diagnostic sink factory returned nil sink")
		}
		return nil, diagnosticArtifactFailure("reviewrun.diagnostics.open", ports.NewRuntimeDiagnosticPersistenceError(ports.DiagnosticPersistenceOpen, ports.DiagnosticPersistenceWriteFailure, err))
	}
	lifecycle := &runtimeDiagnosticLifecycle{sink: sink, identity: identity, roles: append([]domain.Role(nil), roles...), clock: clock}
	for _, event := range []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticCommandAccepted,
		domain.DiagnosticRuntimeOpened,
		domain.DiagnosticSessionCreated,
		domain.DiagnosticRunCreated,
	} {
		if _, err := lifecycle.emit(ctx, domain.RuntimeDiagnosticEventInput{
			Level: domain.RuntimeDiagnosticInfo, Component: "reviewrun", Operation: "lifecycle", Event: event,
			SessionID: identity.sessionID, RunID: identity.runID, State: string(domain.RunPending),
		}); err != nil {
			return nil, err
		}
	}
	return lifecycle, nil
}

func (lifecycle *runtimeDiagnosticLifecycle) emit(ctx context.Context, input domain.RuntimeDiagnosticEventInput) (domain.RuntimeDiagnosticEvent, error) {
	if lifecycle == nil || nilInterface(lifecycle.sink) {
		return domain.RuntimeDiagnosticEvent{}, diagnosticArtifactFailure("reviewrun.diagnostics.emit", fmt.Errorf("diagnostic lifecycle is unavailable"))
	}
	draft, err := domain.NewRuntimeDiagnosticEventDraft(input)
	if err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticArtifactFailure("reviewrun.diagnostics.emit", ports.NewRuntimeDiagnosticPersistenceError(ports.DiagnosticPersistenceEmit, ports.DiagnosticPersistenceInvalidInput, err))
	}
	event, err := lifecycle.sink.Emit(ctx, draft)
	if err != nil {
		return domain.RuntimeDiagnosticEvent{}, diagnosticArtifactFailure("reviewrun.diagnostics.emit", err)
	}
	lifecycle.mu.Lock()
	if event.Sequence() > lifecycle.lastSeq {
		lifecycle.lastSeq = event.Sequence()
	}
	lifecycle.mu.Unlock()
	return event, nil
}

func (lifecycle *runtimeDiagnosticLifecycle) finalize(
	parent context.Context,
	state domain.RunState,
	cause domain.RuntimeDiagnosticCause,
	result Result,
	coordinator review.CoordinatorResult,
) (ports.RuntimeDiagnosticFinalizeResult, error) {
	if lifecycle == nil || nilInterface(lifecycle.sink) {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", fmt.Errorf("diagnostic lifecycle is unavailable"))
	}
	lifecycle.mu.Lock()
	if lifecycle.finalized {
		lifecycle.mu.Unlock()
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", fmt.Errorf("diagnostic lifecycle already finalized"))
	}
	lastSequence := lifecycle.lastSeq
	lifecycle.mu.Unlock()

	now := lifecycle.clock.Now().UTC()
	if now.IsZero() || now.Before(lifecycle.identity.startedAt) {
		now = lifecycle.identity.startedAt
	}
	laneCompleted, laneFailed := 0, 0
	for _, summary := range coordinator.RoleSummaries() {
		if summary.State() == domain.RoleTaskSucceeded {
			laneCompleted++
		} else {
			laneFailed++
		}
	}
	var p2URI ports.SafeRelativePath
	if result.Snapshot().Valid() {
		var pathErr error
		p2URI, pathErr = ports.NewSafeRelativePath(".kar/" + result.Snapshot().Manifest().Path().String())
		if pathErr != nil {
			return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", pathErr)
		}
	}
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID, State: state,
		StartedAt: lifecycle.identity.startedAt, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true,
		SelectedRoles: lifecycle.roles, LaneTotal: len(lifecycle.roles), LaneCompleted: laneCompleted, LaneFailed: laneFailed,
		LastSequence: lastSequence, TerminalCause: cause, P2URI: p2URI, HasP2URI: p2URI.Valid(),
	})
	if err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", err)
	}
	request, err := ports.NewRuntimeDiagnosticFinalizeRequest(state, cause, status)
	if err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", err)
	}
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Minute)
	defer cancel()
	finalized, err := lifecycle.sink.Finalize(finalizeCtx, request)
	if err != nil {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", err)
	}
	if !finalized.URI().Valid() {
		return ports.RuntimeDiagnosticFinalizeResult{}, diagnosticArtifactFailure("reviewrun.diagnostics.finalize", fmt.Errorf("diagnostic sink returned no installed URI"))
	}
	lifecycle.mu.Lock()
	lifecycle.finalized = true
	lifecycle.lastSeq = finalized.LastSequence()
	lifecycle.mu.Unlock()
	return finalized, nil
}

func runtimeDiagnosticTerminalDecision(parent context.Context, result Result, err error) (domain.RunState, domain.RuntimeDiagnosticCause) {
	if err == nil {
		state := result.Coordinator().RunState()
		if state == domain.RunCompleted || state == domain.RunDegraded {
			return state, ""
		}
		return domain.RunCompleted, ""
	}
	if _, ok := ProviderLoginRequiredProvidersFromError(err); ok {
		return domain.RunFailed, domain.DiagnosticCauseLoginRequired
	}
	var failure *domain.Failure
	if errors.As(err, &failure) {
		switch failure.Class() {
		case domain.FailureArtifact:
			return domain.RunFailed, domain.DiagnosticCausePersistenceFailed
		case domain.FailureAuthentication:
			return domain.RunFailed, domain.DiagnosticCauseAuthenticationFailed
		case domain.FailureTimeout:
			return domain.RunFailed, domain.DiagnosticCauseTimedOut
		case domain.FailureCancelled:
			return domain.RunCancelled, ""
		}
		return domain.RunFailed, ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || parent != nil && parent.Err() != nil {
		return domain.RunCancelled, ""
	}
	return domain.RunFailed, ""
}

func diagnosticArtifactFailure(stage string, cause error) error {
	failure, err := domain.NewFailure(stage, domain.FailureArtifact, "runtime diagnostics persistence failed", cause)
	if err != nil {
		return fmt.Errorf("review run: construct diagnostic artifact failure: %w", err)
	}
	return failure
}

type RuntimeDiagnosticReferenceError struct {
	uri   ports.SafeRelativePath
	cause error
}

func (err *RuntimeDiagnosticReferenceError) Error() string {
	return "review run: terminal failure has installed runtime diagnostics"
}

func (err *RuntimeDiagnosticReferenceError) Unwrap() error { return err.cause }

func runtimeDiagnosticReferenceError(uri ports.SafeRelativePath, cause error) error {
	if cause == nil || !uri.Valid() {
		return cause
	}
	return &RuntimeDiagnosticReferenceError{uri: uri, cause: cause}
}

func RuntimeDiagnosticURIFromError(err error) (ports.SafeRelativePath, bool) {
	var referenced *RuntimeDiagnosticReferenceError
	if !errors.As(err, &referenced) || referenced == nil || !referenced.uri.Valid() {
		return ports.SafeRelativePath{}, false
	}
	return referenced.uri, true
}
