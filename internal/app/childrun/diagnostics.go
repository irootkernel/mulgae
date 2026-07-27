package childrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/reviewrun"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type childDiagnosticRegistry struct {
	mu    sync.RWMutex
	runID domain.RunID
	sink  ports.RuntimeDiagnosticSink
}

func (registry *childDiagnosticRegistry) RuntimeDiagnosticSink(runID domain.RunID) (ports.RuntimeDiagnosticSink, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.sink, registry.sink != nil && runID == registry.runID
}

func (registry *childDiagnosticRegistry) bind(runID domain.RunID, sink ports.RuntimeDiagnosticSink) error {
	if registry == nil || runID.String() == "" || sink == nil {
		return fmt.Errorf("child diagnostics: invalid sink binding")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.sink != nil {
		return fmt.Errorf("child diagnostics: sink already bound")
	}
	registry.runID, registry.sink = runID, sink
	return nil
}

type childDiagnosticLifecycle struct {
	sink      ports.RuntimeDiagnosticSink
	clock     ports.Clock
	sessionID domain.SessionID
	runID     domain.RunID
	roles     []domain.Role
	startedAt time.Time
	lastSeq   uint64
}

func openChildDiagnostics(ctx context.Context, factory ports.RuntimeDiagnosticSinkFactory, root ports.AnchoredRoot, clock ports.Clock, run domain.Run) (*childDiagnosticLifecycle, error) {
	if factory == nil {
		return nil, nil
	}
	started := clock.Now().UTC()
	request, err := ports.NewRuntimeDiagnosticOpenRequest(root, run.SessionID(), run.ID(), started)
	if err != nil {
		return nil, childDiagnosticArtifactFailure(err)
	}
	sink, err := factory.Open(ctx, request)
	if err != nil || sink == nil {
		if err == nil {
			err = fmt.Errorf("diagnostic factory returned nil sink")
		}
		return nil, childDiagnosticArtifactFailure(err)
	}
	roles := make([]domain.Role, 0, len(run.RoleTasks()))
	for _, task := range run.RoleTasks() {
		roles = append(roles, task.Role())
	}
	lifecycle := &childDiagnosticLifecycle{sink: sink, clock: clock, sessionID: run.SessionID(), runID: run.ID(), roles: roles, startedAt: started}
	for _, code := range []domain.RuntimeDiagnosticEventCode{domain.DiagnosticCommandAccepted, domain.DiagnosticRuntimeOpened, domain.DiagnosticSessionCreated, domain.DiagnosticRunCreated} {
		if err := lifecycle.emit(ctx, domain.RuntimeDiagnosticInfo, code, "childrun", "lifecycle", ""); err != nil {
			return nil, err
		}
	}
	return lifecycle, nil
}

func (lifecycle *childDiagnosticLifecycle) emit(ctx context.Context, level domain.RuntimeDiagnosticLevel, code domain.RuntimeDiagnosticEventCode, component, operation string, cause domain.RuntimeDiagnosticCause) error {
	draft, err := domain.NewRuntimeDiagnosticEventDraft(domain.RuntimeDiagnosticEventInput{Level: level, Component: component, Operation: operation, Event: code, SessionID: lifecycle.sessionID, RunID: lifecycle.runID, Cause: cause})
	if err != nil {
		return childDiagnosticArtifactFailure(err)
	}
	event, err := lifecycle.sink.Emit(context.WithoutCancel(ctx), draft)
	if err != nil {
		return childDiagnosticArtifactFailure(err)
	}
	lifecycle.lastSeq = event.Sequence()
	return nil
}

func (lifecycle *childDiagnosticLifecycle) persistObservation(ctx context.Context, observation ports.ProviderExecutionObservation, ordinal uint64) error {
	if lifecycle == nil {
		return nil
	}
	invocation := observation.Invocation()
	persist := func(stream domain.RuntimeDiagnosticStream, content []byte, maximum int64) error {
		if len(content) == 0 {
			return nil
		}
		request, err := ports.NewRuntimeDiagnosticRawRequest(invocation.AttemptID(), invocation.SourceInvocationID(), ordinal, invocation.Purpose(), stream, bytes.NewReader(content), maximum, []string{"provider:" + string(stream)}, func(error) {})
		if err != nil {
			return childDiagnosticArtifactFailure(err)
		}
		if _, err := lifecycle.sink.PersistRaw(context.WithoutCancel(ctx), request); err != nil {
			return childDiagnosticArtifactFailure(err)
		}
		return nil
	}
	if err := persist(domain.DiagnosticStdout, observation.Stdout(), observation.StdoutLimit()); err != nil {
		return err
	}
	return persist(domain.DiagnosticStderr, observation.Stderr(), observation.StderrLimit())
}

func (lifecycle *childDiagnosticLifecycle) finish(ctx context.Context, terminalErr error, p2 ports.SafeRelativePath) error {
	if lifecycle == nil {
		return terminalErr
	}
	state, cause := domain.RunCompleted, domain.RuntimeDiagnosticCause("")
	if terminalErr != nil {
		state, cause = domain.RunFailed, domain.DiagnosticCauseObservationInvalid
		var failure *domain.Failure
		if errors.As(terminalErr, &failure) {
			switch failure.Class() {
			case domain.FailureTimeout:
				cause = domain.DiagnosticCauseTimedOut
			case domain.FailureAuthentication:
				cause = domain.DiagnosticCauseAuthenticationFailed
			case domain.FailureQuota:
				cause = domain.DiagnosticCauseQuotaExceeded
			case domain.FailureRateLimit:
				cause = domain.DiagnosticCauseRateLimited
			case domain.FailureArtifact:
				cause = domain.DiagnosticCausePersistenceFailed
			}
		}
		_ = lifecycle.emit(ctx, domain.RuntimeDiagnosticError, domain.DiagnosticRunStopped, "childrun", "finalize", cause)
	} else {
		_ = lifecycle.emit(ctx, domain.RuntimeDiagnosticInfo, domain.DiagnosticRunCompleted, "childrun", "finalize", "")
	}
	_ = lifecycle.emit(ctx, domain.RuntimeDiagnosticInfo, domain.DiagnosticRuntimeClosed, "childrun", "finalize", "")
	now := lifecycle.clock.Now().UTC()
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: lifecycle.sessionID, RunID: lifecycle.runID, State: state, StartedAt: lifecycle.startedAt, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true, SelectedRoles: lifecycle.roles, LaneTotal: len(lifecycle.roles), LaneCompleted: boolCount(terminalErr == nil) * len(lifecycle.roles), LaneFailed: boolCount(terminalErr != nil) * len(lifecycle.roles), LastSequence: lifecycle.lastSeq, TerminalCause: cause, P2URI: p2, HasP2URI: p2.Valid()})
	if err != nil {
		return childDiagnosticArtifactFailure(err)
	}
	request, err := ports.NewRuntimeDiagnosticFinalizeRequest(state, cause, status)
	if err != nil {
		return childDiagnosticArtifactFailure(err)
	}
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	finalized, err := lifecycle.sink.Finalize(finalizeCtx, request)
	if err != nil || !finalized.URI().Valid() {
		if err == nil {
			err = fmt.Errorf("diagnostic sink returned no installed URI")
		}
		return childDiagnosticArtifactFailure(err)
	}
	if terminalErr != nil {
		return reviewrun.NewRuntimeDiagnosticReferenceError(finalized.URI(), terminalErr)
	}
	return nil
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func childDiagnosticArtifactFailure(cause error) error {
	failure, err := domain.NewFailure("childrun.diagnostics", domain.FailureArtifact, "runtime diagnostics persistence failed", cause)
	if err != nil {
		return fmt.Errorf("child diagnostics: %w", cause)
	}
	return failure
}
