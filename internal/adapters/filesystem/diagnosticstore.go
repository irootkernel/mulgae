package filesystem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type DiagnosticStoreFactory struct {
	writer ports.SecureFileWriter
	clock  ports.Clock
}

func NewDiagnosticStoreFactory(writer ports.SecureFileWriter, clock ports.Clock) (*DiagnosticStoreFactory, error) {
	if nilInterface(writer) || nilInterface(clock) {
		return nil, fmt.Errorf("diagnostic store factory: nil secure writer or clock")
	}
	return &DiagnosticStoreFactory{writer: writer, clock: clock}, nil
}

type DiagnosticStore struct {
	mu             sync.Mutex
	request        ports.RuntimeDiagnosticOpenRequest
	writer         ports.SecureFileWriter
	clock          ports.Clock
	logFD          int
	logIdentity    diagnosticFileIdentity
	sequence       uint64
	lastElapsed    uint64
	logBytes       int64
	droppedEvents  uint64
	state          diagnosticStoreState
	terminalState  domain.RunState
	terminalCause  domain.RuntimeDiagnosticCause
	terminalEvent  bool
	closedEvent    bool
	terminalStatus bool
	installed      bool
	operations     diagnosticStoreOperations
}

type diagnosticStoreState uint8

const (
	diagnosticStoreOpen diagnosticStoreState = iota
	diagnosticStoreFinalizing
	diagnosticStoreFinalized
	diagnosticStorePoisoned
)

type diagnosticFileIdentity struct {
	device uint64
	inode  uint64
}

type diagnosticStoreOperations struct {
	write              func(int, []byte) (int, error)
	fsync              func(int) error
	ftruncate          func(int, int64) error
	close              func(int) error
	afterStatusInstall func()
}

var _ ports.RuntimeDiagnosticSink = (*DiagnosticStore)(nil)
var _ ports.RuntimeDiagnosticSinkFactory = (*DiagnosticStoreFactory)(nil)

type runtimeDiagnosticEventWire struct {
	SchemaVersion string                            `json:"schema_version"`
	Time          string                            `json:"time"`
	Level         domain.RuntimeDiagnosticLevel     `json:"level"`
	Message       string                            `json:"msg"`
	Sequence      uint64                            `json:"seq"`
	ElapsedMS     uint64                            `json:"elapsed_ms"`
	Component     string                            `json:"component"`
	Operation     string                            `json:"operation"`
	Event         domain.RuntimeDiagnosticEventCode `json:"event"`
	SessionID     string                            `json:"session_id"`
	RunID         string                            `json:"run_id"`
	AttemptID     string                            `json:"attempt_id,omitempty"`
	InvocationID  string                            `json:"invocation_id,omitempty"`
	Role          domain.Role                       `json:"role,omitempty"`
	Provider      string                            `json:"provider,omitempty"`
	Cause         domain.RuntimeDiagnosticCause     `json:"cause,omitempty"`
	Failure       string                            `json:"failure,omitempty"`
	Mitigation    string                            `json:"mitigation,omitempty"`
	State         string                            `json:"state,omitempty"`
	Outcome       string                            `json:"outcome,omitempty"`
	Stream        domain.RuntimeDiagnosticStream    `json:"stream,omitempty"`
	Offset        *int64                            `json:"offset,omitempty"`
	Length        *int64                            `json:"length,omitempty"`
	Termination   string                            `json:"termination,omitempty"`
	ExitCode      *int                              `json:"exit_code,omitempty"`
	ArtifactRef   string                            `json:"artifact_ref,omitempty"`
}

func encodeRuntimeDiagnosticEvent(event domain.RuntimeDiagnosticEvent) ([]byte, error) {
	input := event.Input()
	wire := runtimeDiagnosticEventWire{SchemaVersion: event.SchemaVersion(), Time: event.Time().Format(time.RFC3339Nano), Level: event.Level(), Message: event.Message(), Sequence: event.Sequence(), ElapsedMS: event.ElapsedMillis(), Component: input.Component, Operation: input.Operation, Event: input.Event, SessionID: input.SessionID.String(), RunID: input.RunID.String(), AttemptID: input.AttemptID.String(), InvocationID: input.InvocationID, Role: input.Role, Provider: input.Provider, Cause: input.Cause, Failure: input.Failure, Mitigation: input.Mitigation, State: input.State, Outcome: input.Outcome, Stream: input.Stream, Termination: input.Termination, ArtifactRef: input.ArtifactRef}
	if input.Stream.Valid() {
		offset, length := input.Offset, input.Length
		wire.Offset, wire.Length = &offset, &length
	}
	if input.HasExitCode {
		exitCode := input.ExitCode
		wire.ExitCode = &exitCode
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode runtime diagnostic event: %w", err)
	}
	return append(encoded, '\n'), nil
}

type runtimeDiagnosticRunStatusWire struct {
	SchemaVersion        string                        `json:"schema_version"`
	SessionID            string                        `json:"session_id"`
	RunID                string                        `json:"run_id"`
	State                domain.RunState               `json:"state"`
	StartedAt            string                        `json:"started_at"`
	UpdatedAt            string                        `json:"updated_at"`
	CompletedAt          string                        `json:"completed_at,omitempty"`
	SelectedRoles        []domain.Role                 `json:"selected_roles"`
	RolePathTotal        int                           `json:"role_path_total"`
	RolePathCompleted    int                           `json:"role_path_completed"`
	RolePathFailed       int                           `json:"role_path_failed"`
	LastSequence         uint64                        `json:"last_seq"`
	TerminalCause        domain.RuntimeDiagnosticCause `json:"terminal_cause,omitempty"`
	TerminalPhase        domain.RuntimeDiagnosticPhase `json:"terminal_phase,omitempty"`
	P2URI                string                        `json:"p2_uri,omitempty"`
	DroppedEvents        uint64                        `json:"dropped_events"`
	DiagnosticOnly       bool                          `json:"diagnostic_only"`
	PublicationAuthority bool                          `json:"publication_authority"`
}

func rejectLegacyDiagnosticStatus(data []byte) error {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil
	}
	if header.SchemaVersion == "mulgae-runtime-run-status.v1" ||
		bytes.Contains(data, []byte(`"lane_total"`)) ||
		bytes.Contains(data, []byte(`"lane_completed"`)) ||
		bytes.Contains(data, []byte(`"lane_failed"`)) {
		return fmt.Errorf("%w: v1 lane vocabulary", ports.ErrRuntimeDiagnosticContractUnsupported)
	}
	return nil
}

func encodeRuntimeDiagnosticRunStatus(status ports.RuntimeDiagnosticRunStatus) ([]byte, error) {
	return encodeRuntimeDiagnosticRunStatusAtSequence(status, status.LastSequence())
}

func encodeRuntimeDiagnosticRunStatusAtSequence(status ports.RuntimeDiagnosticRunStatus, lastSequence uint64) ([]byte, error) {
	return encodeRuntimeDiagnosticRunStatusAt(status, lastSequence, status.DroppedEvents())
}

func encodeRuntimeDiagnosticRunStatusAt(status ports.RuntimeDiagnosticRunStatus, lastSequence, droppedEvents uint64) ([]byte, error) {
	total, completed, failed := status.RolePathCounts()
	completedAt, hasCompletedAt := status.CompletedAt()
	p2, hasP2 := status.P2URI()
	wire := runtimeDiagnosticRunStatusWire{SchemaVersion: status.SchemaVersion(), SessionID: status.SessionID().String(), RunID: status.RunID().String(), State: status.State(), StartedAt: status.StartedAt().Format(time.RFC3339Nano), UpdatedAt: status.UpdatedAt().Format(time.RFC3339Nano), SelectedRoles: status.SelectedRoles(), RolePathTotal: total, RolePathCompleted: completed, RolePathFailed: failed, LastSequence: lastSequence, TerminalCause: status.TerminalCause(), TerminalPhase: status.TerminalPhase(), DroppedEvents: droppedEvents, DiagnosticOnly: true, PublicationAuthority: false}
	if hasCompletedAt {
		wire.CompletedAt = completedAt.Format(time.RFC3339Nano)
	}
	if hasP2 {
		wire.P2URI = p2.String()
	}
	return marshalDiagnosticStatus(wire)
}

type runtimeDiagnosticAttemptStatusWire struct {
	SchemaVersion   string                           `json:"schema_version"`
	SessionID       string                           `json:"session_id"`
	RunID           string                           `json:"run_id"`
	AttemptID       string                           `json:"attempt_id"`
	Role            domain.Role                      `json:"role"`
	Provider        string                           `json:"provider"`
	Selection       ports.RuntimeDiagnosticSelection `json:"selection"`
	State           domain.AttemptState              `json:"state"`
	StartedAt       string                           `json:"started_at"`
	UpdatedAt       string                           `json:"updated_at"`
	CompletedAt     string                           `json:"completed_at,omitempty"`
	InvocationCount int                              `json:"invocation_count"`
	LastSequence    uint64                           `json:"last_seq"`
	TerminalCause   domain.RuntimeDiagnosticCause    `json:"terminal_cause,omitempty"`
}

func encodeRuntimeDiagnosticAttemptStatus(status ports.RuntimeDiagnosticAttemptStatus) ([]byte, error) {
	completedAt, hasCompletedAt := status.CompletedAt()
	wire := runtimeDiagnosticAttemptStatusWire{SchemaVersion: status.SchemaVersion(), SessionID: status.SessionID().String(), RunID: status.RunID().String(), AttemptID: status.AttemptID().String(), Role: status.Role(), Provider: status.Provider(), Selection: status.Selection(), State: status.State(), StartedAt: status.StartedAt().Format(time.RFC3339Nano), UpdatedAt: status.UpdatedAt().Format(time.RFC3339Nano), InvocationCount: status.InvocationCount(), LastSequence: status.LastSequence(), TerminalCause: status.TerminalCause()}
	if hasCompletedAt {
		wire.CompletedAt = completedAt.Format(time.RFC3339Nano)
	}
	return marshalDiagnosticStatus(wire)
}

type runtimeDiagnosticDropWire struct {
	Channel   string   `json:"channel"`
	Detector  string   `json:"detector"`
	Count     int      `json:"count"`
	SourceIDs []string `json:"source_ids"`
}
type runtimeDiagnosticRawWire struct {
	URI        string                     `json:"uri,omitempty"`
	ByteLength int64                      `json:"byte_length"`
	Drop       *runtimeDiagnosticDropWire `json:"drop,omitempty"`
}
type runtimeDiagnosticInvocationStatusWire struct {
	SchemaVersion   string                          `json:"schema_version"`
	SessionID       string                          `json:"session_id"`
	RunID           string                          `json:"run_id"`
	AttemptID       string                          `json:"attempt_id"`
	InvocationID    string                          `json:"invocation_id"`
	Ordinal         uint64                          `json:"ordinal"`
	Purpose         ports.ProviderInvocationPurpose `json:"purpose"`
	ProcessState    domain.InvocationState          `json:"process_state"`
	ParseState      domain.ParseState               `json:"parse_state"`
	ValidationState domain.ValidationState          `json:"validation_state"`
	StartedAt       string                          `json:"started_at"`
	UpdatedAt       string                          `json:"updated_at"`
	CompletedAt     string                          `json:"completed_at,omitempty"`
	Termination     string                          `json:"termination,omitempty"`
	ExitCode        *int                            `json:"exit_code,omitempty"`
	LastSequence    uint64                          `json:"last_seq"`
	Stdout          *runtimeDiagnosticRawWire       `json:"stdout,omitempty"`
	Stderr          *runtimeDiagnosticRawWire       `json:"stderr,omitempty"`
}

func encodeRuntimeDiagnosticInvocationStatus(status ports.RuntimeDiagnosticInvocationStatus) ([]byte, error) {
	process, parse, validation := status.States()
	completedAt, hasCompletedAt := status.CompletedAt()
	exitCode, hasExitCode := status.ExitCode()
	wire := runtimeDiagnosticInvocationStatusWire{SchemaVersion: status.SchemaVersion(), SessionID: status.SessionID().String(), RunID: status.RunID().String(), AttemptID: status.AttemptID().String(), InvocationID: status.InvocationID(), Ordinal: status.Ordinal(), Purpose: status.Purpose(), ProcessState: process, ParseState: parse, ValidationState: validation, StartedAt: status.StartedAt().Format(time.RFC3339Nano), UpdatedAt: status.UpdatedAt().Format(time.RFC3339Nano), Termination: status.Termination(), LastSequence: status.LastSequence()}
	if hasCompletedAt {
		wire.CompletedAt = completedAt.Format(time.RFC3339Nano)
	}
	if hasExitCode {
		wire.ExitCode = &exitCode
	}
	if stdout, ok := status.Stdout(); ok {
		wire.Stdout = diagnosticRawWire(stdout)
	}
	if stderr, ok := status.Stderr(); ok {
		wire.Stderr = diagnosticRawWire(stderr)
	}
	return marshalDiagnosticStatus(wire)
}

func diagnosticRawWire(result ports.RuntimeDiagnosticRawResult) *runtimeDiagnosticRawWire {
	wire := &runtimeDiagnosticRawWire{ByteLength: result.ByteLength()}
	if uri, ok := result.URI(); ok {
		wire.URI = uri.String()
	}
	if drop, ok := result.Drop(); ok {
		wire.Drop = &runtimeDiagnosticDropWire{Channel: drop.Channel(), Detector: drop.Detector(), Count: drop.Count(), SourceIDs: drop.SourceIDs()}
	}
	return wire
}
func marshalDiagnosticStatus(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode runtime diagnostic status: %w", err)
	}
	if int64(len(encoded)+1) > ports.RuntimeDiagnosticStatusMaxBytes {
		return nil, fmt.Errorf("runtime diagnostic status exceeds cap")
	}
	return append(encoded, '\n'), nil
}

func diagnosticPersistenceError(operation ports.RuntimeDiagnosticPersistenceOperation, detail string, err error) error {
	reason := ports.DiagnosticPersistenceInvalidInput
	switch detail {
	case "closed", "already_finalized":
		reason = ports.DiagnosticPersistenceClosed
	case "identity_mismatch":
		reason = ports.DiagnosticPersistenceIdentityMismatch
	case "clock":
		reason = ports.DiagnosticPersistenceClockFailure
	case "encode", "encode_attempt", "encode_invocation":
		reason = ports.DiagnosticPersistenceEncodingFailure
	case "log_cap":
		reason = ports.DiagnosticPersistenceCapacityExhausted
	case "namespace_changed":
		reason = ports.DiagnosticPersistenceNamespaceChanged
	case "append", "write", "replace_attempt", "replace_invocation", "terminal_status", "initial_status":
		reason = ports.DiagnosticPersistenceWriteFailure
	case "sync", "installed_undurable", "close_log":
		reason = ports.DiagnosticPersistenceSyncFailure
	case "post_sync_verification":
		reason = ports.DiagnosticPersistenceVerificationFailed
	case "terminal_event":
		reason = ports.DiagnosticPersistenceRecoveryFailed
	case "drop_result", "installed_result", "result":
		reason = ports.DiagnosticPersistenceResultInvalid
	}
	return ports.NewRuntimeDiagnosticPersistenceError(operation, reason, err)
}

func (store *DiagnosticStore) URI() (ports.SafeRelativePath, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.request.RunPath(), store.installed
}
