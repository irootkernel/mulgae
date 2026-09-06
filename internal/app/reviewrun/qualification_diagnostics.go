package reviewrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type qualificationDiagnostics struct {
	mu        sync.Mutex
	lifecycle *runtimeDiagnosticLifecycle
	ids       review.IdentityGenerator
}

func qualificationDiagnosticContext(ctx context.Context, lifecycle *runtimeDiagnosticLifecycle, ids review.IdentityGenerator) context.Context {
	return ports.WithQualificationProbeObserver(ctx, &qualificationDiagnostics{lifecycle: lifecycle, ids: ids})
}

func (observer *qualificationDiagnostics) ObserveQualificationProbe(ctx context.Context, observation ports.QualificationProbeObservation) error {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	lifecycle := observer.lifecycle
	now := lifecycle.clock.Now()
	attempt, err := observer.ids.NewAttemptID(now)
	if err != nil {
		return err
	}
	invocation, err := observer.ids.NewSourceInvocationID(now)
	if err != nil {
		return err
	}
	base := domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticInfo, Event: domain.DiagnosticIOObserved,
		Component: "qualification", SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID,
		AttemptID: attempt, InvocationID: invocation, Role: observation.Role, Provider: observation.Provider,
	}
	for _, phase := range []struct {
		name           string
		stdout, stderr []byte
		process        ports.ProcessObservation
		failure        error
	}{
		{"request", observation.Packet, nil, ports.ProcessObservation{}, nil},
		{"version", observation.Version.Stdout(), observation.Version.Stderr(), observation.Version, observation.VersionError},
		{"capability", observation.Capability.Stdout(), observation.Capability.Stderr(), observation.Capability, observation.CapabilityError},
	} {
		event := base
		var processFailure *ports.ProcessExecutionError
		if errors.As(phase.failure, &processFailure) {
			if len(phase.stdout) == 0 {
				phase.stdout = processFailure.Stdout()
			}
			if len(phase.stderr) == 0 {
				phase.stderr = processFailure.Stderr()
			}
		}
		if phase.failure != nil {
			event.Cause = qualificationDiagnosticCause(phase.failure)
		}
		event.Operation = phase.name
		event.Termination = string(phase.process.Termination())
		event.ExitCode, event.HasExitCode = phase.process.ExitCode()
		if len(phase.stdout) == 0 && len(phase.stderr) == 0 {
			if _, err := lifecycle.emit(ctx, event); err != nil {
				return err
			}
		}
		for _, stream := range []struct {
			kind domain.RuntimeDiagnosticStream
			body []byte
		}{
			{domain.DiagnosticStdout, phase.stdout}, {domain.DiagnosticStderr, phase.stderr},
		} {
			if len(stream.body) == 0 {
				continue
			}
			request, err := ports.NewQualificationDiagnosticRawRequest(attempt, invocation, phase.name, stream.kind, bytes.NewReader(stream.body), int64(len(stream.body)))
			if err != nil {
				return err
			}
			result, err := lifecycle.sink.PersistRaw(ctx, request)
			if err != nil {
				var rejection *ports.RuntimeDiagnosticSecurityRejectionError
				drop, dropped := result.Drop()
				if !errors.As(err, &rejection) || !result.ValidFor(stream.kind) || !dropped || drop.Channel() != rejection.Drop().Channel() || drop.Detector() != rejection.Drop().Detector() || drop.Count() != rejection.Drop().Count() || !slices.Equal(drop.SourceIDs(), rejection.Drop().SourceIDs()) {
					return diagnosticArtifactFailure("reviewrun.diagnostics.qualification", err)
				}
				event.State = "security_dropped"
			} else {
				uri, ok := result.URI()
				if !ok || !result.ValidFor(stream.kind) {
					return fmt.Errorf("qualification diagnostic: missing raw receipt")
				}
				event.ArtifactRef = uri.String()
			}
			event.Stream, event.Length = stream.kind, int64(len(stream.body))
			if _, err := lifecycle.emit(ctx, event); err != nil {
				return err
			}
			event.ArtifactRef, event.State = "", ""
		}
	}
	base.Operation = "result"
	base.Outcome = qualificationOutcomeQualified
	if observation.Err != nil {
		base.Outcome = qualificationOutcomeRejected
		base.Cause = qualificationDiagnosticCause(observation.Err)
		base.Failure = qualificationFailureToken(observation.Err)
	}
	_, err = lifecycle.emit(ctx, base)
	return err
}

// PreparedRunDiagnostics owns the pre-execution child identity until the child
// executor takes over the same sink. It never creates publication authority.
type PreparedRunDiagnostics struct {
	lifecycle *runtimeDiagnosticLifecycle
	taken     bool
}

type preparedDiagnosticsKey struct{}

func PrepareChildRunDiagnostics(ctx context.Context, factory ports.RuntimeDiagnosticSinkFactory, root ports.AnchoredRoot, session domain.SessionID, roles []domain.Role, clock ports.Clock, ids review.IdentityGenerator) (*PreparedRunDiagnostics, context.Context, error) {
	if nilInterface(factory) || nilInterface(clock) || nilInterface(ids) {
		return nil, ctx, fmt.Errorf("child qualification diagnostics dependencies required")
	}
	now := clock.Now().UTC()
	run, err := ids.NewRunID(now)
	if err != nil {
		return nil, ctx, err
	}
	lifecycle, err := openRuntimeDiagnosticLifecycle(ctx, factory, root, rootRunIdentity{sessionID: session, runID: run, startedAt: now}, roles, clock)
	if err != nil {
		return nil, ctx, NewAllocatedRunIdentityError(session, run, err)
	}
	prepared := &PreparedRunDiagnostics{lifecycle: lifecycle}
	ctx = context.WithValue(qualificationDiagnosticContext(ctx, lifecycle, ids), preparedDiagnosticsKey{}, prepared)
	return prepared, ctx, nil
}

func (prepared *PreparedRunDiagnostics) RunID() domain.RunID {
	return prepared.lifecycle.identity.runID
}

func TakePreparedRunDiagnostics(ctx context.Context, session domain.SessionID, run domain.RunID) (ports.RuntimeDiagnosticSink, time.Time, uint64, bool, error) {
	prepared, ok := ctx.Value(preparedDiagnosticsKey{}).(*PreparedRunDiagnostics)
	if !ok {
		return nil, time.Time{}, 0, false, nil
	}
	lifecycle := prepared.lifecycle
	if prepared.taken || session != lifecycle.identity.sessionID || run != lifecycle.identity.runID {
		return nil, time.Time{}, 0, true, fmt.Errorf("child diagnostic handoff identity mismatch")
	}
	prepared.taken = true
	return lifecycle.sink, lifecycle.identity.startedAt, lifecycle.lastSeq, true, nil
}

func (prepared *PreparedRunDiagnostics) Finish(ctx context.Context, terminalErr error) error {
	if prepared.taken {
		return terminalErr
	}
	if terminalErr == nil {
		terminalErr = fmt.Errorf("child executor did not consume prepared diagnostics")
	}
	lifecycle := prepared.lifecycle
	for _, observation := range qualificationObservationsFromError(terminalErr) {
		if err := lifecycle.observeQualificationCandidate(context.WithoutCancel(ctx), observation); err != nil {
			terminalErr = errors.Join(err, terminalErr)
		}
	}
	state, cause, phase := runtimeDiagnosticTerminalDecision(ctx, Result{}, terminalErr)
	for _, code := range []domain.RuntimeDiagnosticEventCode{domain.DiagnosticRunStopped, domain.DiagnosticRuntimeClosed} {
		level := domain.RuntimeDiagnosticInfo
		if code == domain.DiagnosticRunStopped {
			level = domain.RuntimeDiagnosticError
		}
		_, err := lifecycle.emit(context.WithoutCancel(ctx), domain.RuntimeDiagnosticEventInput{Level: level, Event: code, Component: "qualification", Operation: "finalize", SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID, Cause: cause})
		if err != nil {
			terminalErr = errors.Join(err, terminalErr)
		}
	}
	final, err := lifecycle.finalize(ctx, state, cause, phase, ports.SafeRelativePath{}, review.CoordinatorResult{})
	if err != nil {
		terminalErr = errors.Join(err, terminalErr)
	} else {
		terminalErr = NewRuntimeDiagnosticReferenceError(final.URI(), terminalErr)
	}
	return NewAllocatedRunIdentityError(lifecycle.identity.sessionID, lifecycle.identity.runID, terminalErr)
}
