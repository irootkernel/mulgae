package ports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

const (
	RuntimeDiagnosticLogMaxBytes            int64 = 8 << 20
	RuntimeDiagnosticTailReserveBytes       int64 = 256 << 10
	RuntimeDiagnosticStatusMaxBytes         int64 = 256 << 10
	RuntimeDiagnosticRunStatusSchema              = "kar-runtime-run-status.v1"
	RuntimeDiagnosticAttemptStatusSchema          = "kar-runtime-attempt-status.v1"
	RuntimeDiagnosticInvocationStatusSchema       = "kar-runtime-invocation-status.v1"
)

var ErrRuntimeDiagnosticEventDropped = errors.New("runtime diagnostic ordinary event dropped at cap")

type RuntimeDiagnosticOpenRequest struct {
	root      AnchoredRoot
	sessionID domain.SessionID
	runID     domain.RunID
	startedAt time.Time
}

func NewRuntimeDiagnosticOpenRequest(root AnchoredRoot, sessionID domain.SessionID, runID domain.RunID, startedAt time.Time) (RuntimeDiagnosticOpenRequest, error) {
	if !root.Valid() || !validDiagnosticRunIdentity(sessionID, runID) || startedAt.IsZero() || startedAt.Location() != time.UTC {
		return RuntimeDiagnosticOpenRequest{}, fmt.Errorf("runtime diagnostic open request: invalid root, identity, or UTC start")
	}
	return RuntimeDiagnosticOpenRequest{root: root, sessionID: sessionID, runID: runID, startedAt: startedAt}, nil
}

func (request RuntimeDiagnosticOpenRequest) Root() AnchoredRoot          { return request.root }
func (request RuntimeDiagnosticOpenRequest) SessionID() domain.SessionID { return request.sessionID }
func (request RuntimeDiagnosticOpenRequest) RunID() domain.RunID         { return request.runID }
func (request RuntimeDiagnosticOpenRequest) StartedAt() time.Time        { return request.startedAt }
func (request RuntimeDiagnosticOpenRequest) RunPath() SafeRelativePath {
	value, _ := NewSafeRelativePath("diagnostics/" + request.sessionID.String() + "/" + request.runID.String())
	return value
}

type RuntimeDiagnosticSelection string

const (
	RuntimeDiagnosticPrimary  RuntimeDiagnosticSelection = "primary"
	RuntimeDiagnosticFallback RuntimeDiagnosticSelection = "fallback"
)

func (selection RuntimeDiagnosticSelection) Valid() bool {
	return selection == RuntimeDiagnosticPrimary || selection == RuntimeDiagnosticFallback
}

type RuntimeDiagnosticRunStatus struct {
	sessionID                            domain.SessionID
	runID                                domain.RunID
	state                                domain.RunState
	startedAt, updatedAt                 time.Time
	completedAt                          time.Time
	hasCompletedAt                       bool
	selectedRoles                        []domain.Role
	laneTotal, laneCompleted, laneFailed int
	lastSequence                         uint64
	terminalCause                        domain.RuntimeDiagnosticCause
	p2URI                                SafeRelativePath
	hasP2URI                             bool
	droppedEvents                        uint64
}

type RuntimeDiagnosticRunStatusInput struct {
	SessionID                            domain.SessionID
	RunID                                domain.RunID
	State                                domain.RunState
	StartedAt, UpdatedAt, CompletedAt    time.Time
	HasCompletedAt                       bool
	SelectedRoles                        []domain.Role
	LaneTotal, LaneCompleted, LaneFailed int
	LastSequence                         uint64
	TerminalCause                        domain.RuntimeDiagnosticCause
	P2URI                                SafeRelativePath
	HasP2URI                             bool
	DroppedEvents                        uint64
}

func NewRuntimeDiagnosticRunStatus(input RuntimeDiagnosticRunStatusInput) (RuntimeDiagnosticRunStatus, error) {
	if !validDiagnosticRunIdentity(input.SessionID, input.RunID) || !input.State.Valid() || !validDiagnosticTimes(input.StartedAt, input.UpdatedAt, input.CompletedAt, input.HasCompletedAt) {
		return RuntimeDiagnosticRunStatus{}, fmt.Errorf("runtime diagnostic run status: invalid identity, state, or time")
	}
	roles := append([]domain.Role(nil), input.SelectedRoles...)
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	for index, role := range roles {
		if !role.Valid() || index > 0 && roles[index-1] == role {
			return RuntimeDiagnosticRunStatus{}, fmt.Errorf("runtime diagnostic run status: invalid selected roles")
		}
	}
	if input.LaneTotal < 0 || input.LaneCompleted < 0 || input.LaneFailed < 0 || input.LaneCompleted+input.LaneFailed > input.LaneTotal {
		return RuntimeDiagnosticRunStatus{}, fmt.Errorf("runtime diagnostic run status: invalid lane counts")
	}
	if input.TerminalCause != "" && !input.TerminalCause.Valid() {
		return RuntimeDiagnosticRunStatus{}, fmt.Errorf("runtime diagnostic run status: invalid terminal cause")
	}
	if input.HasP2URI != input.P2URI.Valid() {
		return RuntimeDiagnosticRunStatus{}, fmt.Errorf("runtime diagnostic run status: inconsistent P2 URI")
	}
	return RuntimeDiagnosticRunStatus{sessionID: input.SessionID, runID: input.RunID, state: input.State, startedAt: input.StartedAt, updatedAt: input.UpdatedAt,
		completedAt: input.CompletedAt, hasCompletedAt: input.HasCompletedAt, selectedRoles: roles, laneTotal: input.LaneTotal, laneCompleted: input.LaneCompleted,
		laneFailed: input.LaneFailed, lastSequence: input.LastSequence, terminalCause: input.TerminalCause, p2URI: input.P2URI, hasP2URI: input.HasP2URI, droppedEvents: input.DroppedEvents}, nil
}

func (status RuntimeDiagnosticRunStatus) SchemaVersion() string {
	return RuntimeDiagnosticRunStatusSchema
}
func (status RuntimeDiagnosticRunStatus) SessionID() domain.SessionID { return status.sessionID }
func (status RuntimeDiagnosticRunStatus) RunID() domain.RunID         { return status.runID }
func (status RuntimeDiagnosticRunStatus) State() domain.RunState      { return status.state }
func (status RuntimeDiagnosticRunStatus) StartedAt() time.Time        { return status.startedAt }
func (status RuntimeDiagnosticRunStatus) UpdatedAt() time.Time        { return status.updatedAt }
func (status RuntimeDiagnosticRunStatus) CompletedAt() (time.Time, bool) {
	return status.completedAt, status.hasCompletedAt
}
func (status RuntimeDiagnosticRunStatus) SelectedRoles() []domain.Role {
	return append([]domain.Role(nil), status.selectedRoles...)
}
func (status RuntimeDiagnosticRunStatus) LaneCounts() (int, int, int) {
	return status.laneTotal, status.laneCompleted, status.laneFailed
}
func (status RuntimeDiagnosticRunStatus) LastSequence() uint64 { return status.lastSequence }
func (status RuntimeDiagnosticRunStatus) TerminalCause() domain.RuntimeDiagnosticCause {
	return status.terminalCause
}
func (status RuntimeDiagnosticRunStatus) P2URI() (SafeRelativePath, bool) {
	return status.p2URI, status.hasP2URI
}
func (status RuntimeDiagnosticRunStatus) DroppedEvents() uint64 { return status.droppedEvents }

type RuntimeDiagnosticAttemptStatus struct {
	sessionID                         domain.SessionID
	runID                             domain.RunID
	attemptID                         domain.AttemptID
	role                              domain.Role
	provider                          string
	selection                         RuntimeDiagnosticSelection
	state                             domain.AttemptState
	startedAt, updatedAt, completedAt time.Time
	hasCompletedAt                    bool
	invocationCount                   int
	lastSequence                      uint64
	terminalCause                     domain.RuntimeDiagnosticCause
}

type RuntimeDiagnosticAttemptStatusInput struct {
	SessionID                         domain.SessionID
	RunID                             domain.RunID
	AttemptID                         domain.AttemptID
	Role                              domain.Role
	Provider                          string
	Selection                         RuntimeDiagnosticSelection
	State                             domain.AttemptState
	StartedAt, UpdatedAt, CompletedAt time.Time
	HasCompletedAt                    bool
	InvocationCount                   int
	LastSequence                      uint64
	TerminalCause                     domain.RuntimeDiagnosticCause
}

func NewRuntimeDiagnosticAttemptStatus(input RuntimeDiagnosticAttemptStatusInput) (RuntimeDiagnosticAttemptStatus, error) {
	if !validDiagnosticRunIdentity(input.SessionID, input.RunID) || !validAttemptID(input.AttemptID) || !input.Role.Valid() || !validProviderInstanceID(input.Provider) || !input.Selection.Valid() || !input.State.Valid() || !validDiagnosticTimes(input.StartedAt, input.UpdatedAt, input.CompletedAt, input.HasCompletedAt) || input.InvocationCount < 0 || input.TerminalCause != "" && !input.TerminalCause.Valid() {
		return RuntimeDiagnosticAttemptStatus{}, fmt.Errorf("runtime diagnostic attempt status: invalid field")
	}
	return RuntimeDiagnosticAttemptStatus{sessionID: input.SessionID, runID: input.RunID, attemptID: input.AttemptID, role: input.Role, provider: input.Provider,
		selection: input.Selection, state: input.State, startedAt: input.StartedAt, updatedAt: input.UpdatedAt, completedAt: input.CompletedAt,
		hasCompletedAt: input.HasCompletedAt, invocationCount: input.InvocationCount, lastSequence: input.LastSequence, terminalCause: input.TerminalCause}, nil
}

func (status RuntimeDiagnosticAttemptStatus) SchemaVersion() string {
	return RuntimeDiagnosticAttemptStatusSchema
}
func (status RuntimeDiagnosticAttemptStatus) SessionID() domain.SessionID { return status.sessionID }
func (status RuntimeDiagnosticAttemptStatus) RunID() domain.RunID         { return status.runID }
func (status RuntimeDiagnosticAttemptStatus) AttemptID() domain.AttemptID { return status.attemptID }
func (status RuntimeDiagnosticAttemptStatus) Role() domain.Role           { return status.role }
func (status RuntimeDiagnosticAttemptStatus) Provider() string            { return status.provider }
func (status RuntimeDiagnosticAttemptStatus) Selection() RuntimeDiagnosticSelection {
	return status.selection
}
func (status RuntimeDiagnosticAttemptStatus) State() domain.AttemptState { return status.state }
func (status RuntimeDiagnosticAttemptStatus) StartedAt() time.Time       { return status.startedAt }
func (status RuntimeDiagnosticAttemptStatus) UpdatedAt() time.Time       { return status.updatedAt }
func (status RuntimeDiagnosticAttemptStatus) CompletedAt() (time.Time, bool) {
	return status.completedAt, status.hasCompletedAt
}
func (status RuntimeDiagnosticAttemptStatus) InvocationCount() int { return status.invocationCount }
func (status RuntimeDiagnosticAttemptStatus) LastSequence() uint64 { return status.lastSequence }
func (status RuntimeDiagnosticAttemptStatus) TerminalCause() domain.RuntimeDiagnosticCause {
	return status.terminalCause
}

type RuntimeDiagnosticInvocationStatus struct {
	sessionID                         domain.SessionID
	runID                             domain.RunID
	attemptID                         domain.AttemptID
	invocationID                      string
	ordinal                           uint64
	purpose                           ProviderInvocationPurpose
	processState                      domain.InvocationState
	parseState                        domain.ParseState
	validationState                   domain.ValidationState
	startedAt, updatedAt, completedAt time.Time
	hasCompletedAt                    bool
	termination                       string
	exitCode                          int
	hasExitCode                       bool
	lastSequence                      uint64
	stdout, stderr                    RuntimeDiagnosticRawResult
	hasStdout, hasStderr              bool
}

type RuntimeDiagnosticInvocationStatusInput struct {
	SessionID                         domain.SessionID
	RunID                             domain.RunID
	AttemptID                         domain.AttemptID
	InvocationID                      string
	Ordinal                           uint64
	Purpose                           ProviderInvocationPurpose
	ProcessState                      domain.InvocationState
	ParseState                        domain.ParseState
	ValidationState                   domain.ValidationState
	StartedAt, UpdatedAt, CompletedAt time.Time
	HasCompletedAt                    bool
	Termination                       string
	ExitCode                          int
	HasExitCode                       bool
	LastSequence                      uint64
	Stdout, Stderr                    RuntimeDiagnosticRawResult
	HasStdout, HasStderr              bool
}

func NewRuntimeDiagnosticInvocationStatus(input RuntimeDiagnosticInvocationStatusInput) (RuntimeDiagnosticInvocationStatus, error) {
	if !validDiagnosticRunIdentity(input.SessionID, input.RunID) || !validAttemptID(input.AttemptID) || validateProviderInvocationID(input.InvocationID, "i_") != nil || input.Ordinal == 0 || !input.Purpose.Valid() || !input.ProcessState.Valid() || !input.ParseState.Valid() || !input.ValidationState.Valid() || !validDiagnosticTimes(input.StartedAt, input.UpdatedAt, input.CompletedAt, input.HasCompletedAt) {
		return RuntimeDiagnosticInvocationStatus{}, fmt.Errorf("runtime diagnostic invocation status: invalid field")
	}
	if input.Termination != "" && validateAuditToken(input.Termination, 128) != nil {
		return RuntimeDiagnosticInvocationStatus{}, fmt.Errorf("runtime diagnostic invocation status: invalid termination")
	}
	if input.HasStdout != input.Stdout.ValidFor(domain.DiagnosticStdout) || input.HasStderr != input.Stderr.ValidFor(domain.DiagnosticStderr) {
		return RuntimeDiagnosticInvocationStatus{}, fmt.Errorf("runtime diagnostic invocation status: inconsistent stream result")
	}
	return RuntimeDiagnosticInvocationStatus{sessionID: input.SessionID, runID: input.RunID, attemptID: input.AttemptID, invocationID: input.InvocationID,
		ordinal: input.Ordinal, purpose: input.Purpose, processState: input.ProcessState, parseState: input.ParseState, validationState: input.ValidationState,
		startedAt: input.StartedAt, updatedAt: input.UpdatedAt, completedAt: input.CompletedAt, hasCompletedAt: input.HasCompletedAt,
		termination: input.Termination, exitCode: input.ExitCode, hasExitCode: input.HasExitCode, lastSequence: input.LastSequence,
		stdout: input.Stdout, stderr: input.Stderr, hasStdout: input.HasStdout, hasStderr: input.HasStderr}, nil
}

func (status RuntimeDiagnosticInvocationStatus) SchemaVersion() string {
	return RuntimeDiagnosticInvocationStatusSchema
}
func (status RuntimeDiagnosticInvocationStatus) SessionID() domain.SessionID { return status.sessionID }
func (status RuntimeDiagnosticInvocationStatus) RunID() domain.RunID         { return status.runID }
func (status RuntimeDiagnosticInvocationStatus) AttemptID() domain.AttemptID { return status.attemptID }
func (status RuntimeDiagnosticInvocationStatus) InvocationID() string        { return status.invocationID }
func (status RuntimeDiagnosticInvocationStatus) Ordinal() uint64             { return status.ordinal }
func (status RuntimeDiagnosticInvocationStatus) Purpose() ProviderInvocationPurpose {
	return status.purpose
}
func (status RuntimeDiagnosticInvocationStatus) States() (domain.InvocationState, domain.ParseState, domain.ValidationState) {
	return status.processState, status.parseState, status.validationState
}
func (status RuntimeDiagnosticInvocationStatus) StartedAt() time.Time { return status.startedAt }
func (status RuntimeDiagnosticInvocationStatus) UpdatedAt() time.Time { return status.updatedAt }
func (status RuntimeDiagnosticInvocationStatus) CompletedAt() (time.Time, bool) {
	return status.completedAt, status.hasCompletedAt
}
func (status RuntimeDiagnosticInvocationStatus) Termination() string { return status.termination }
func (status RuntimeDiagnosticInvocationStatus) ExitCode() (int, bool) {
	return status.exitCode, status.hasExitCode
}
func (status RuntimeDiagnosticInvocationStatus) LastSequence() uint64 { return status.lastSequence }
func (status RuntimeDiagnosticInvocationStatus) Stdout() (RuntimeDiagnosticRawResult, bool) {
	return status.stdout, status.hasStdout
}
func (status RuntimeDiagnosticInvocationStatus) Stderr() (RuntimeDiagnosticRawResult, bool) {
	return status.stderr, status.hasStderr
}

type RuntimeDiagnosticRawRequest struct {
	attemptID    domain.AttemptID
	invocationID string
	ordinal      uint64
	purpose      ProviderInvocationPurpose
	stream       domain.RuntimeDiagnosticStream
	source       io.Reader
	maxBytes     int64
	sourceIDs    []string
	abort        func(error)
}

func NewRuntimeDiagnosticRawRequest(attemptID domain.AttemptID, invocationID string, ordinal uint64, purpose ProviderInvocationPurpose, stream domain.RuntimeDiagnosticStream, source io.Reader, maxBytes int64, sourceIDs []string, abort func(error)) (RuntimeDiagnosticRawRequest, error) {
	if !validAttemptID(attemptID) || validateProviderInvocationID(invocationID, "i_") != nil || ordinal == 0 || !purpose.Valid() || !stream.Valid() || isNilReader(source) || maxBytes <= 0 || validateSourceIDs(sourceIDs) != nil || abort == nil {
		return RuntimeDiagnosticRawRequest{}, fmt.Errorf("runtime diagnostic raw request: invalid field")
	}
	return RuntimeDiagnosticRawRequest{attemptID: attemptID, invocationID: invocationID, ordinal: ordinal, purpose: purpose, stream: stream, source: source, maxBytes: maxBytes, sourceIDs: cloneStrings(sourceIDs), abort: abort}, nil
}

func (request RuntimeDiagnosticRawRequest) AttemptID() domain.AttemptID { return request.attemptID }
func (request RuntimeDiagnosticRawRequest) InvocationID() string        { return request.invocationID }
func (request RuntimeDiagnosticRawRequest) Ordinal() uint64             { return request.ordinal }
func (request RuntimeDiagnosticRawRequest) Purpose() ProviderInvocationPurpose {
	return request.purpose
}
func (request RuntimeDiagnosticRawRequest) Stream() domain.RuntimeDiagnosticStream {
	return request.stream
}
func (request RuntimeDiagnosticRawRequest) Source() io.Reader { return request.source }
func (request RuntimeDiagnosticRawRequest) MaxBytes() int64   { return request.maxBytes }
func (request RuntimeDiagnosticRawRequest) SourceIDs() []string {
	return cloneStrings(request.sourceIDs)
}
func (request RuntimeDiagnosticRawRequest) Abort() func(error) { return request.abort }

type RuntimeDiagnosticRawResult struct {
	stream     domain.RuntimeDiagnosticStream
	uri        SafeRelativePath
	drop       *DropMetadata
	byteLength int64
}

func NewRuntimeDiagnosticRawResult(stream domain.RuntimeDiagnosticStream, uri SafeRelativePath, drop *DropMetadata, byteLength int64) (RuntimeDiagnosticRawResult, error) {
	if !stream.Valid() || byteLength < 0 || uri.Valid() == (drop != nil) {
		return RuntimeDiagnosticRawResult{}, fmt.Errorf("runtime diagnostic raw result: require exactly one artifact URI or drop")
	}
	var copied *DropMetadata
	if drop != nil {
		value := *drop
		copied = &value
		if byteLength != 0 {
			return RuntimeDiagnosticRawResult{}, fmt.Errorf("runtime diagnostic raw result: dropped stream has bytes")
		}
	}
	return RuntimeDiagnosticRawResult{stream: stream, uri: uri, drop: copied, byteLength: byteLength}, nil
}
func (result RuntimeDiagnosticRawResult) Stream() domain.RuntimeDiagnosticStream {
	return result.stream
}
func (result RuntimeDiagnosticRawResult) URI() (SafeRelativePath, bool) {
	return result.uri, result.uri.Valid()
}
func (result RuntimeDiagnosticRawResult) Drop() (*DropMetadata, bool) {
	if result.drop == nil {
		return nil, false
	}
	copied := *result.drop
	return &copied, true
}
func (result RuntimeDiagnosticRawResult) ByteLength() int64 { return result.byteLength }
func (result RuntimeDiagnosticRawResult) ValidFor(stream domain.RuntimeDiagnosticStream) bool {
	return result.stream == stream && result.stream.Valid() && (result.uri.Valid() != (result.drop != nil)) && result.byteLength >= 0
}

type RuntimeDiagnosticFinalizeRequest struct {
	state  domain.RunState
	cause  domain.RuntimeDiagnosticCause
	status RuntimeDiagnosticRunStatus
}

func NewRuntimeDiagnosticFinalizeRequest(state domain.RunState, cause domain.RuntimeDiagnosticCause, status RuntimeDiagnosticRunStatus) (RuntimeDiagnosticFinalizeRequest, error) {
	if !state.Valid() || state == domain.RunPending || state == domain.RunRunning || cause != "" && !cause.Valid() || status.state != state || cause != status.terminalCause {
		return RuntimeDiagnosticFinalizeRequest{}, fmt.Errorf("runtime diagnostic finalize request: invalid terminal state, cause, or status")
	}
	return RuntimeDiagnosticFinalizeRequest{state: state, cause: cause, status: status}, nil
}
func (request RuntimeDiagnosticFinalizeRequest) State() domain.RunState { return request.state }
func (request RuntimeDiagnosticFinalizeRequest) Cause() domain.RuntimeDiagnosticCause {
	return request.cause
}
func (request RuntimeDiagnosticFinalizeRequest) Status() RuntimeDiagnosticRunStatus {
	return request.status
}

type RuntimeDiagnosticFinalizeResult struct {
	uri          SafeRelativePath
	lastSequence uint64
}

func NewRuntimeDiagnosticFinalizeResult(uri SafeRelativePath, lastSequence uint64) (RuntimeDiagnosticFinalizeResult, error) {
	if !uri.Valid() {
		return RuntimeDiagnosticFinalizeResult{}, fmt.Errorf("runtime diagnostic finalize result: invalid URI")
	}
	return RuntimeDiagnosticFinalizeResult{uri: uri, lastSequence: lastSequence}, nil
}
func (result RuntimeDiagnosticFinalizeResult) URI() SafeRelativePath { return result.uri }
func (result RuntimeDiagnosticFinalizeResult) LastSequence() uint64  { return result.lastSequence }

type RuntimeDiagnosticPersistenceOperation string

const (
	DiagnosticPersistenceOpen     RuntimeDiagnosticPersistenceOperation = "open"
	DiagnosticPersistenceEmit     RuntimeDiagnosticPersistenceOperation = "emit"
	DiagnosticPersistenceRaw      RuntimeDiagnosticPersistenceOperation = "raw"
	DiagnosticPersistenceStatus   RuntimeDiagnosticPersistenceOperation = "status"
	DiagnosticPersistenceFinalize RuntimeDiagnosticPersistenceOperation = "finalize"
)

type RuntimeDiagnosticPersistenceError struct {
	Operation RuntimeDiagnosticPersistenceOperation
	Reason    string
	Err       error
}

func (err *RuntimeDiagnosticPersistenceError) Error() string {
	if err == nil {
		return "runtime diagnostic persistence failure"
	}
	return fmt.Sprintf("runtime diagnostic persistence %s: %s", err.Operation, err.Reason)
}
func (err *RuntimeDiagnosticPersistenceError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

type RuntimeDiagnosticSink interface {
	Emit(context.Context, domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error)
	PersistRaw(context.Context, RuntimeDiagnosticRawRequest) (RuntimeDiagnosticRawResult, error)
	ReplaceRunStatus(context.Context, RuntimeDiagnosticRunStatus) error
	ReplaceAttemptStatus(context.Context, RuntimeDiagnosticAttemptStatus) error
	ReplaceInvocationStatus(context.Context, RuntimeDiagnosticInvocationStatus) error
	Finalize(context.Context, RuntimeDiagnosticFinalizeRequest) (RuntimeDiagnosticFinalizeResult, error)
	URI() (SafeRelativePath, bool)
}

type RuntimeDiagnosticSinkFactory interface {
	Open(context.Context, RuntimeDiagnosticOpenRequest) (RuntimeDiagnosticSink, error)
}

type inMemoryRuntimeDiagnosticSink struct {
	mu          sync.Mutex
	request     RuntimeDiagnosticOpenRequest
	now         func() time.Time
	sequence    uint64
	lastElapsed uint64
	events      []domain.RuntimeDiagnosticEvent
	raw         map[string][]byte
	finalized   bool
	installed   bool
}

func NewInMemoryRuntimeDiagnosticSink(request RuntimeDiagnosticOpenRequest) (RuntimeDiagnosticSink, error) {
	if !request.root.Valid() {
		return nil, fmt.Errorf("in-memory runtime diagnostic sink: invalid request")
	}
	return &inMemoryRuntimeDiagnosticSink{request: request, now: func() time.Time { return time.Now().UTC() }, raw: make(map[string][]byte), installed: true}, nil
}

func NewNoopRuntimeDiagnosticSink(request RuntimeDiagnosticOpenRequest) (RuntimeDiagnosticSink, error) {
	if !request.root.Valid() {
		return nil, fmt.Errorf("noop runtime diagnostic sink: invalid request")
	}
	return &inMemoryRuntimeDiagnosticSink{request: request, now: func() time.Time { return time.Now().UTC() }, raw: make(map[string][]byte)}, nil
}

func (sink *inMemoryRuntimeDiagnosticSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.RuntimeDiagnosticEvent{}, err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return domain.RuntimeDiagnosticEvent{}, errors.New("runtime diagnostic sink finalized")
	}
	input := draft.Input()
	if input.SessionID != sink.request.sessionID || input.RunID != sink.request.runID {
		return domain.RuntimeDiagnosticEvent{}, errors.New("runtime diagnostic event identity does not match sink")
	}
	now := sink.now()
	elapsed := now.Sub(sink.request.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	millis := uint64(elapsed / time.Millisecond)
	if millis < sink.lastElapsed {
		millis = sink.lastElapsed
	}
	sink.sequence++
	event, err := domain.StampRuntimeDiagnosticEvent(draft, sink.sequence, now, millis)
	if err != nil {
		sink.sequence--
		return domain.RuntimeDiagnosticEvent{}, err
	}
	sink.lastElapsed = millis
	sink.events = append(sink.events, event)
	return event, nil
}

func (sink *inMemoryRuntimeDiagnosticSink) PersistRaw(ctx context.Context, request RuntimeDiagnosticRawRequest) (RuntimeDiagnosticRawResult, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeDiagnosticRawResult{}, err
	}
	limited := io.LimitReader(request.source, request.maxBytes+1)
	bytes, err := io.ReadAll(limited)
	if err != nil {
		request.abort(err)
		return RuntimeDiagnosticRawResult{}, err
	}
	if int64(len(bytes)) > request.maxBytes {
		err = errors.New("runtime diagnostic raw stream exceeds cap")
		request.abort(err)
		drop, _ := NewDropMetadata(string(request.stream), "size_cap", 1, request.sourceIDs)
		return NewRuntimeDiagnosticRawResult(request.stream, SafeRelativePath{}, &drop, 0)
	}
	uri, _ := sink.diagnosticRawPath(request)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return RuntimeDiagnosticRawResult{}, errors.New("runtime diagnostic sink finalized")
	}
	sink.raw[uri.String()] = cloneBytes(bytes)
	return NewRuntimeDiagnosticRawResult(request.stream, uri, nil, int64(len(bytes)))
}
func (sink *inMemoryRuntimeDiagnosticSink) ReplaceRunStatus(_ context.Context, status RuntimeDiagnosticRunStatus) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return errors.New("runtime diagnostic sink finalized")
	}
	if status.sessionID != sink.request.sessionID || status.runID != sink.request.runID {
		return errors.New("runtime diagnostic run status identity does not match sink")
	}
	return nil
}
func (sink *inMemoryRuntimeDiagnosticSink) ReplaceAttemptStatus(_ context.Context, status RuntimeDiagnosticAttemptStatus) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return errors.New("runtime diagnostic sink finalized")
	}
	if status.sessionID != sink.request.sessionID || status.runID != sink.request.runID {
		return errors.New("runtime diagnostic attempt status identity does not match sink")
	}
	return nil
}
func (sink *inMemoryRuntimeDiagnosticSink) ReplaceInvocationStatus(_ context.Context, status RuntimeDiagnosticInvocationStatus) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return errors.New("runtime diagnostic sink finalized")
	}
	if status.sessionID != sink.request.sessionID || status.runID != sink.request.runID {
		return errors.New("runtime diagnostic invocation status identity does not match sink")
	}
	return nil
}
func (sink *inMemoryRuntimeDiagnosticSink) Finalize(ctx context.Context, request RuntimeDiagnosticFinalizeRequest) (RuntimeDiagnosticFinalizeResult, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeDiagnosticFinalizeResult{}, err
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.finalized {
		return RuntimeDiagnosticFinalizeResult{}, errors.New("runtime diagnostic sink already finalized")
	}
	if request.status.sessionID != sink.request.sessionID || request.status.runID != sink.request.runID {
		return RuntimeDiagnosticFinalizeResult{}, errors.New("runtime diagnostic final status identity does not match sink")
	}
	sink.finalized = true
	uri := sink.request.RunPath()
	if !sink.installed {
		return RuntimeDiagnosticFinalizeResult{}, nil
	}
	return NewRuntimeDiagnosticFinalizeResult(uri, sink.sequence)
}
func (sink *inMemoryRuntimeDiagnosticSink) URI() (SafeRelativePath, bool) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.request.RunPath(), sink.installed
}

type runtimeDiagnosticStaticFactory struct{ noop bool }

func NewInMemoryRuntimeDiagnosticSinkFactory() RuntimeDiagnosticSinkFactory {
	return runtimeDiagnosticStaticFactory{}
}
func NewNoopRuntimeDiagnosticSinkFactory() RuntimeDiagnosticSinkFactory {
	return runtimeDiagnosticStaticFactory{noop: true}
}
func (factory runtimeDiagnosticStaticFactory) Open(_ context.Context, request RuntimeDiagnosticOpenRequest) (RuntimeDiagnosticSink, error) {
	if factory.noop {
		return NewNoopRuntimeDiagnosticSink(request)
	}
	return NewInMemoryRuntimeDiagnosticSink(request)
}

func validDiagnosticRunIdentity(sessionID domain.SessionID, runID domain.RunID) bool {
	_, sessionErr := domain.ParseSessionID(sessionID.String())
	_, runErr := domain.ParseRunID(runID.String())
	return sessionErr == nil && runErr == nil
}
func validAttemptID(attemptID domain.AttemptID) bool {
	_, err := domain.ParseAttemptID(attemptID.String())
	return err == nil
}
func validDiagnosticTimes(started, updated, completed time.Time, hasCompleted bool) bool {
	if started.IsZero() || updated.IsZero() || started.Location() != time.UTC || updated.Location() != time.UTC || updated.Before(started) {
		return false
	}
	if hasCompleted {
		return !completed.IsZero() && completed.Location() == time.UTC && !completed.Before(updated)
	}
	return completed.IsZero()
}
func (sink *inMemoryRuntimeDiagnosticSink) diagnosticRawPath(request RuntimeDiagnosticRawRequest) (SafeRelativePath, error) {
	return NewSafeRelativePath(fmt.Sprintf("%s/attempts/%s/invocations/%03d-%s/%s.raw", sink.request.RunPath().String(), request.attemptID.String(), request.ordinal, request.purpose, request.stream))
}
