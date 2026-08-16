package review

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func (runtime *ProviderInvocationRuntime) emitInvocationDiagnostic(
	ctx context.Context,
	job InvocationJob,
	level domain.RuntimeDiagnosticLevel,
	code domain.RuntimeDiagnosticEventCode,
	cause domain.RuntimeDiagnosticCause,
	state, outcome, termination string,
	exitCode int,
	hasExitCode bool,
	stream domain.RuntimeDiagnosticStream,
	length int64,
) error {
	if runtime == nil || runtime.diagnostics == nil {
		return nil
	}
	sink, ok := runtime.diagnostics.RuntimeDiagnosticSink(job.RunID())
	if !ok || nilInterface(sink) {
		return errors.New("provider invocation runtime: mandatory diagnostic sink unavailable")
	}
	input := domain.RuntimeDiagnosticEventInput{
		Level: level, Component: "provider_runtime", Operation: "invoke", Event: code,
		SessionID: job.SessionID(), RunID: job.RunID(), AttemptID: job.AttemptID(),
		InvocationID: runtime.diagnosticInvocationID(job), Role: job.Role(), Provider: job.Route().ProviderInstance(),
		Cause: cause, State: state, Outcome: outcome, Termination: termination, ExitCode: exitCode, HasExitCode: hasExitCode,
	}
	if stream.Valid() && length > 0 {
		input.Stream, input.Offset, input.Length = stream, 0, length
	}
	draft, err := domain.NewRuntimeDiagnosticEventDraft(input)
	if err != nil {
		return err
	}
	event, err := sink.Emit(context.WithoutCancel(ctx), draft)
	if errors.Is(err, ports.ErrRuntimeDiagnosticEventDropped) {
		return nil
	}
	if err == nil {
		runtime.mu.Lock()
		key := captureKey{job.AttemptID(), invocationSequence(job.Purpose())}
		inventory := runtime.inventory[key]
		if event.Sequence() > inventory.diagnosticLastSequence {
			inventory.diagnosticLastSequence = event.Sequence()
			runtime.inventory[key] = inventory
		}
		runtime.mu.Unlock()
	}
	return err
}

func (runtime *ProviderInvocationRuntime) diagnosticInvocationID(job InvocationJob) string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.inventory[captureKey{job.AttemptID(), invocationSequence(job.Purpose())}].sourceInvocationID
}

func (runtime *ProviderInvocationRuntime) emitObservationDiagnostics(ctx context.Context, job InvocationJob, observation ports.ProviderExecutionObservation) error {
	process, hasProcess := observation.AvailableProcessObservation()
	cause := observation.PrimaryCause()
	if hasProcess {
		if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticSpawnRevalidated, "", string(domain.InvocationRunning), "", "", 0, false, "", 0); err != nil {
			return err
		}
		if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticProcessStarted, "", string(domain.InvocationRunning), "", "", 0, false, "", 0); err != nil {
			return err
		}
		for _, stream := range []struct {
			kind  domain.RuntimeDiagnosticStream
			bytes []byte
		}{{domain.DiagnosticStdout, observation.Stdout()}, {domain.DiagnosticStderr, observation.Stderr()}} {
			if len(stream.bytes) == 0 {
				continue
			}
			if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticIOObserved, "", "", "", "", 0, false, stream.kind, int64(len(stream.bytes))); err != nil {
				return err
			}
		}
		level, code := domain.RuntimeDiagnosticInfo, domain.DiagnosticProcessExited
		switch process.Termination() {
		case ports.ProcessTerminationTimedOut:
			level, code = domain.RuntimeDiagnosticError, domain.DiagnosticProcessTimedOut
		case ports.ProcessTerminationCancelled:
			code = domain.DiagnosticProcessCancelled
		case ports.ProcessTerminationExited:
		default:
			level, code = domain.RuntimeDiagnosticError, domain.DiagnosticProcessTerminated
		}
		exitCode, hasExitCode := observation.ExitCode()
		if err := runtime.emitInvocationDiagnostic(ctx, job, level, code, cause, "", string(observation.Status()), string(process.Termination()), exitCode, hasExitCode, "", 0); err != nil {
			return err
		}
	}
	if len(observation.Stdout()) > 0 {
		return runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputReceived, cause, "", string(observation.Status()), "", 0, false, "", 0)
	}
	return nil
}

func (runtime *ProviderInvocationRuntime) emitValidationDiagnostics(ctx context.Context, job InvocationJob, err error, repaired bool) error {
	if err == nil {
		if emitErr := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParsed, "", string(domain.ParseValid), "", "", 0, false, "", 0); emitErr != nil {
			return emitErr
		}
		state := domain.ValidationValid
		if repaired {
			state = domain.ValidationRepairedValid
		}
		if emitErr := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticValidationSucceeded, "", string(state), "", "", 0, false, "", 0); emitErr != nil {
			return emitErr
		}
		if repaired {
			return runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticWarn, domain.DiagnosticRepairCompleted, "", string(state), "", "", 0, false, "", 0)
		}
		return nil
	}
	cause, _ := validation.RuntimeCause(err)
	parseFailure := cause == domain.DiagnosticCauseOutputDecodeFailed || cause == domain.DiagnosticCauseOutputEnvelopeInvalid || cause == domain.DiagnosticCauseOutputFrameMissing
	if parseFailure {
		if emitErr := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticError, domain.DiagnosticOutputParseFailed, cause, string(domain.ParseInvalidJSON), "", "", 0, false, "", 0); emitErr != nil {
			return emitErr
		}
	} else if emitErr := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParsed, "", string(domain.ParseValid), "", "", 0, false, "", 0); emitErr != nil {
		return emitErr
	}
	if emitErr := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticError, domain.DiagnosticValidationFailed, cause, string(domain.ValidationInvalid), "", "", 0, false, "", 0); emitErr != nil {
		return emitErr
	}
	if repaired {
		return runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticError, domain.DiagnosticRepairExhausted, cause, string(domain.ValidationRepairExhausted), "", "", 0, false, "", 0)
	}
	return nil
}

func (runtime *ProviderInvocationRuntime) emitDiscardedFieldDiagnostics(ctx context.Context, job InvocationJob, paths []string) error {
	if len(paths) == 0 || runtime == nil || runtime.diagnostics == nil {
		return nil
	}
	sink, ok := runtime.diagnostics.RuntimeDiagnosticSink(job.RunID())
	if !ok || nilInterface(sink) {
		return errors.New("provider invocation runtime: mandatory diagnostic sink unavailable")
	}
	retained := append([]string(nil), paths...)
	if len(retained) > domain.MaxRuntimeDiagnosticDiscardedPaths {
		retained = retained[:domain.MaxRuntimeDiagnosticDiscardedPaths]
	}
	input := domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticWarn, Component: "provider_runtime", Operation: "validate",
		Event: domain.DiagnosticProviderFieldsDiscarded, SessionID: job.SessionID(), RunID: job.RunID(),
		AttemptID: job.AttemptID(), InvocationID: runtime.diagnosticInvocationID(job), Role: job.Role(),
		Provider: job.Route().ProviderInstance(), DiscardedPaths: retained, DiscardedPathCount: len(paths),
	}
	draft, err := domain.NewRuntimeDiagnosticEventDraft(input)
	if err != nil {
		return err
	}
	_, err = sink.Emit(context.WithoutCancel(ctx), draft)
	if errors.Is(err, ports.ErrRuntimeDiagnosticEventDropped) {
		return nil
	}
	return err
}

func (runtime *ProviderInvocationRuntime) replaceInvocationDiagnosticStatus(
	ctx context.Context,
	job InvocationJob,
	observation ports.ProviderExecutionObservation,
	parseState domain.ParseState,
	validationState domain.ValidationState,
) error {
	if runtime == nil || runtime.diagnostics == nil {
		return nil
	}
	sink, ok := runtime.diagnostics.RuntimeDiagnosticSink(job.RunID())
	if !ok || nilInterface(sink) {
		return errors.New("provider invocation runtime: mandatory diagnostic sink unavailable")
	}
	started, ended := observation.StartedAt(), observation.EndedAt()
	if started.IsZero() || ended.IsZero() || ended.Before(started) {
		return nil
	}
	state := domain.InvocationFailed
	if observation.Succeeded() {
		state = domain.InvocationSucceeded
	} else {
		switch observation.Termination() {
		case ports.ProcessTerminationTimedOut:
			state = domain.InvocationTimedOut
		case ports.ProcessTerminationCancelled:
			state = domain.InvocationCancelled
		}
	}
	runtime.mu.Lock()
	inventory := runtime.inventory[captureKey{job.AttemptID(), invocationSequence(job.Purpose())}]
	runtime.mu.Unlock()
	input := ports.RuntimeDiagnosticInvocationStatusInput{
		SessionID: job.SessionID(), RunID: job.RunID(), AttemptID: job.AttemptID(), InvocationID: inventory.sourceInvocationID,
		Ordinal: invocationSequence(job.Purpose()), Purpose: runtimePurpose(job.Purpose()), ProcessState: state,
		ParseState: parseState, ValidationState: validationState, StartedAt: started, UpdatedAt: ended, CompletedAt: ended, HasCompletedAt: true,
		Termination: string(observation.Termination()), LastSequence: inventory.diagnosticLastSequence,
	}
	if exitCode, ok := observation.ExitCode(); ok {
		input.ExitCode, input.HasExitCode = exitCode, true
	}
	if stdout, ok := inventory.DiagnosticStdout(); ok {
		input.Stdout, input.HasStdout = stdout, true
	}
	if stderr, ok := inventory.DiagnosticStderr(); ok {
		input.Stderr, input.HasStderr = stderr, true
	}
	status, err := ports.NewRuntimeDiagnosticInvocationStatus(input)
	if err != nil {
		return err
	}
	return sink.ReplaceInvocationStatus(context.WithoutCancel(ctx), status)
}

func diagnosticConditionForPersistence(err error) AttemptCondition {
	var rejection *ports.RuntimeDiagnosticSecurityRejectionError
	if errors.As(err, &rejection) {
		return AttemptConditionSecurityViolation
	}
	return AttemptConditionArtifactFailure
}

func diagnosticParseState(err error, output []byte) domain.ParseState {
	if err == nil {
		return domain.ParseValid
	}
	if len(output) == 0 {
		return domain.ParseEmptyOutput
	}
	cause, _ := validation.RuntimeCause(err)
	if cause == domain.DiagnosticCauseOutputDecodeFailed || cause == domain.DiagnosticCauseOutputEnvelopeInvalid || cause == domain.DiagnosticCauseOutputFrameMissing {
		return domain.ParseInvalidJSON
	}
	// Validate wraps decode failures as CandidateValidationFailed. Incomplete
	// structured-like JSON must still classify as invalid_json so free-form
	// repair acceptance retains the closed reports-only pair.
	if cause == domain.DiagnosticCauseCandidateValidationFailed && !json.Valid(output) {
		return domain.ParseInvalidJSON
	}
	return domain.ParseValid
}

func diagnosticObservationPointer(observation ports.ProviderExecutionObservation) *ports.ProviderExecutionObservation {
	copy := observation
	return &copy
}
