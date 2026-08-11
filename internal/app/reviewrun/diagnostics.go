package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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

func (lifecycle *runtimeDiagnosticLifecycle) ObservePublicationLifecycle(ctx context.Context, observation publication.LifecycleObservation) error {
	event := observation.Event()
	code := domain.RuntimeDiagnosticEventCode("")
	level := domain.RuntimeDiagnosticInfo
	operation := "commit"
	var cause domain.RuntimeDiagnosticCause
	var failure, mitigation string
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
		if diagnostic, ok := observation.FailureDiagnostic(); ok {
			operation = string(diagnostic.Phase())
			cause = diagnostic.Cause()
			failure = diagnostic.Failure()
			mitigation = diagnostic.Mitigation()
		}
	default:
		return diagnosticArtifactFailure("reviewrun.diagnostics.publication", fmt.Errorf("unknown publication lifecycle event %q", event))
	}
	_, err := lifecycle.emit(ctx, domain.RuntimeDiagnosticEventInput{
		Level: level, Component: "publication", Operation: operation, Event: code,
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID,
		Cause: cause, Failure: failure, Mitigation: mitigation,
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

func (lifecycle *runtimeDiagnosticLifecycle) observeQualificationCandidate(
	ctx context.Context,
	observation ProviderQualificationObservation,
) error {
	_, err := lifecycle.emit(ctx, domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticInfo, Component: "qualification", Operation: "candidate",
		Event:     domain.DiagnosticQualificationCandidateChecked,
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID,
		Provider: observation.ProviderInstance(), Cause: observation.Cause(), Failure: observation.Failure(),
		Mitigation: observation.Mitigation(), Outcome: observation.Outcome(),
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
	phase domain.RuntimeDiagnosticPhase,
	p2URI ports.SafeRelativePath,
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
	rolePathCompleted, rolePathFailed := 0, 0
	for _, summary := range coordinator.RoleSummaries() {
		if summary.State() == domain.RoleTaskSucceeded {
			rolePathCompleted++
		} else {
			rolePathFailed++
		}
	}
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: lifecycle.identity.sessionID, RunID: lifecycle.identity.runID, State: state,
		StartedAt: lifecycle.identity.startedAt, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true,
		SelectedRoles: lifecycle.roles, RolePathTotal: len(lifecycle.roles), RolePathCompleted: rolePathCompleted, RolePathFailed: rolePathFailed,
		LastSequence: lastSequence, TerminalCause: cause, TerminalPhase: phase, P2URI: p2URI, HasP2URI: p2URI.Valid(),
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

func runtimeDiagnosticP2URI(result Result, terminalErr error) (ports.SafeRelativePath, error) {
	manifest := ports.SafeRelativePath{}
	if result.Snapshot().Valid() {
		manifest = result.Snapshot().Manifest().Path()
	} else if committedManifest, ok := publication.CommittedPublicationManifestPathFromError(terminalErr); ok {
		manifest = committedManifest
	}
	if !manifest.Valid() {
		return ports.SafeRelativePath{}, nil
	}
	p2URI, err := ports.NewSafeRelativePath(".mulgae/" + manifest.String())
	if err != nil {
		return ports.SafeRelativePath{}, diagnosticArtifactFailure("reviewrun.diagnostics.p2_reference", err)
	}
	return p2URI, nil
}

func runtimeDiagnosticTerminalDecision(parent context.Context, result Result, err error) (domain.RunState, domain.RuntimeDiagnosticCause, domain.RuntimeDiagnosticPhase) {
	if err == nil {
		state := result.Coordinator().RunState()
		if state == domain.RunCompleted || state == domain.RunDegraded {
			return state, "", ""
		}
		return domain.RunCompleted, "", ""
	}
	if diagnostic, ok := publication.FailureDiagnosticFromError(err); ok {
		return domain.RunFailed, diagnostic.Cause(), diagnostic.Phase()
	}
	if _, ok := ProviderLoginRequiredProvidersFromError(err); ok {
		return domain.RunFailed, domain.DiagnosticCauseLoginRequired, ""
	}
	if cause := qualificationTerminalCause(err); cause.Valid() {
		return domain.RunFailed, cause, ""
	}
	var failure *domain.Failure
	if errors.As(err, &failure) {
		switch failure.Class() {
		case domain.FailureArtifact:
			if strings.HasPrefix(failure.Stage(), "reviewrun.diagnostics") || failure.Stage() == "publication.diagnostics" {
				return domain.RunFailed, domain.DiagnosticCausePersistenceFailed, domain.DiagnosticPhaseDiagnostics
			}
			return domain.RunFailed, "", ""
		case domain.FailureAuthentication:
			return domain.RunFailed, domain.DiagnosticCauseAuthenticationFailed, ""
		case domain.FailureTimeout:
			return domain.RunFailed, domain.DiagnosticCauseTimedOut, ""
		case domain.FailureCancelled:
			return domain.RunCancelled, "", ""
		}
		return domain.RunFailed, "", ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || parent != nil && parent.Err() != nil {
		return domain.RunCancelled, "", ""
	}
	return domain.RunFailed, "", ""
}

func qualificationTerminalCause(err error) domain.RuntimeDiagnosticCause {
	observations := qualificationObservationsFromError(err)
	var cause domain.RuntimeDiagnosticCause
	for _, observation := range observations {
		if observation.Outcome() != qualificationOutcomeRejected || !observation.Cause().Valid() {
			continue
		}
		if cause == "" {
			cause = observation.Cause()
			continue
		}
		if cause != observation.Cause() {
			return domain.DiagnosticCauseObservationInvalid
		}
	}
	if cause.Valid() {
		return cause
	}
	failures, ok := ProviderQualificationFailuresFromError(err)
	if !ok {
		return ""
	}
	for _, failure := range failures {
		if cause == "" {
			cause = failure.DiagnosticCause()
			continue
		}
		if cause != failure.DiagnosticCause() {
			return domain.DiagnosticCauseObservationInvalid
		}
	}
	return cause
}

func diagnosticArtifactFailure(stage string, cause error) error {
	failure, err := domain.NewFailure(stage, domain.FailureArtifact, "runtime diagnostics persistence failed", cause)
	if err != nil {
		return fmt.Errorf("review run: construct diagnostic artifact failure: %w", err)
	}
	return failure
}

type RuntimeDiagnosticReferenceError struct {
	uri                  ports.SafeRelativePath
	sessionID            domain.SessionID
	runID                domain.RunID
	hasAllocatedIdentity bool
	cause                error
}

// AllocatedRunIdentityError retains recovery identity without claiming that a
// diagnostic or publication artifact was installed.
type AllocatedRunIdentityError struct {
	sessionID domain.SessionID
	runID     domain.RunID
	cause     error
}

func (err *AllocatedRunIdentityError) Error() string {
	return "review run: terminal failure retains allocated run identity"
}

func (err *AllocatedRunIdentityError) Unwrap() error { return err.cause }

// NewAllocatedRunIdentityError retains an identity even when runtime
// diagnostics could not be installed or finalized.
func NewAllocatedRunIdentityError(sessionID domain.SessionID, runID domain.RunID, cause error) error {
	if cause == nil {
		return nil
	}
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return cause
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return cause
	}
	return &AllocatedRunIdentityError{sessionID: sessionID, runID: runID, cause: cause}
}

func (err *RuntimeDiagnosticReferenceError) Error() string {
	return "review run: terminal failure has installed runtime diagnostics"
}

func (err *RuntimeDiagnosticReferenceError) Unwrap() error { return err.cause }

func runtimeDiagnosticReferenceError(uri ports.SafeRelativePath, cause error) error {
	return NewRuntimeDiagnosticReferenceError(uri, cause)
}

// NewRuntimeDiagnosticReferenceError attaches an installed runtime diagnostic
// URI to a terminal error without exposing any diagnostic contents.
func NewRuntimeDiagnosticReferenceError(uri ports.SafeRelativePath, cause error) error {
	if cause == nil || !uri.Valid() {
		return cause
	}
	return &RuntimeDiagnosticReferenceError{uri: uri, cause: cause}
}

// NewRuntimeDiagnosticReferenceErrorWithIdentity attaches an installed runtime
// diagnostic URI and the already allocated run identity to a terminal error.
// Command projections use the identity for recovery without treating the
// diagnostic as publication authority.
func NewRuntimeDiagnosticReferenceErrorWithIdentity(
	uri ports.SafeRelativePath,
	sessionID domain.SessionID,
	runID domain.RunID,
	cause error,
) error {
	if cause == nil || !uri.Valid() || sessionID.String() == "" || runID.String() == "" {
		return cause
	}
	return &RuntimeDiagnosticReferenceError{
		uri: uri, sessionID: sessionID, runID: runID,
		hasAllocatedIdentity: true, cause: cause,
	}
}

// RuntimeDiagnosticIdentityFromError returns an allocated identity retained by
// a failed review after diagnostics were installed.
func RuntimeDiagnosticIdentityFromError(err error) (domain.SessionID, domain.RunID, bool) {
	var referenced *RuntimeDiagnosticReferenceError
	if errors.As(err, &referenced) && referenced != nil && referenced.hasAllocatedIdentity {
		return validRuntimeDiagnosticIdentity(referenced.sessionID, referenced.runID)
	}
	var allocated *AllocatedRunIdentityError
	if errors.As(err, &allocated) && allocated != nil {
		return validRuntimeDiagnosticIdentity(allocated.sessionID, allocated.runID)
	}
	return domain.SessionID{}, domain.RunID{}, false
}

func validRuntimeDiagnosticIdentity(sessionID domain.SessionID, runID domain.RunID) (domain.SessionID, domain.RunID, bool) {
	if _, parseErr := domain.ParseSessionID(sessionID.String()); parseErr != nil {
		return domain.SessionID{}, domain.RunID{}, false
	}
	if _, parseErr := domain.ParseRunID(runID.String()); parseErr != nil {
		return domain.SessionID{}, domain.RunID{}, false
	}
	return sessionID, runID, true
}

func RuntimeDiagnosticURIFromError(err error) (ports.SafeRelativePath, bool) {
	var referenced *RuntimeDiagnosticReferenceError
	if !errors.As(err, &referenced) || referenced == nil || !referenced.uri.Valid() {
		return ports.SafeRelativePath{}, false
	}
	return referenced.uri, true
}
