package domain

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const RuntimeDiagnosticSchemaVersion = "kar-runtime-log.v1"

type RuntimeDiagnosticLevel string

const (
	RuntimeDiagnosticInfo  RuntimeDiagnosticLevel = "INFO"
	RuntimeDiagnosticWarn  RuntimeDiagnosticLevel = "WARN"
	RuntimeDiagnosticError RuntimeDiagnosticLevel = "ERROR"
)

func (level RuntimeDiagnosticLevel) Valid() bool {
	return oneOf(string(level), string(RuntimeDiagnosticInfo), string(RuntimeDiagnosticWarn), string(RuntimeDiagnosticError))
}

type RuntimeDiagnosticEventCode string

const (
	DiagnosticCommandAccepted               RuntimeDiagnosticEventCode = "command_accepted"
	DiagnosticRuntimeOpened                 RuntimeDiagnosticEventCode = "runtime_diagnostics_opened"
	DiagnosticSessionCreated                RuntimeDiagnosticEventCode = "session_created"
	DiagnosticRunCreated                    RuntimeDiagnosticEventCode = "run_created"
	DiagnosticRunStarted                    RuntimeDiagnosticEventCode = "run_started"
	DiagnosticRunCompleted                  RuntimeDiagnosticEventCode = "run_completed"
	DiagnosticRunStopped                    RuntimeDiagnosticEventCode = "run_stopped"
	DiagnosticRuntimeClosed                 RuntimeDiagnosticEventCode = "runtime_diagnostics_closed"
	DiagnosticQualificationStarted          RuntimeDiagnosticEventCode = "qualification_started"
	DiagnosticQualificationCandidateChecked RuntimeDiagnosticEventCode = "qualification_candidate_checked"
	DiagnosticQualificationSucceeded        RuntimeDiagnosticEventCode = "qualification_succeeded"
	DiagnosticQualificationRejected         RuntimeDiagnosticEventCode = "qualification_rejected"
	DiagnosticReviewPlanCreated             RuntimeDiagnosticEventCode = "review_plan_created"
	DiagnosticAssignmentResolved            RuntimeDiagnosticEventCode = "assignment_resolved"
	DiagnosticRunBudgetAccepted             RuntimeDiagnosticEventCode = "run_budget_accepted"
	DiagnosticLaneScheduled                 RuntimeDiagnosticEventCode = "lane_scheduled"
	DiagnosticLaneStarted                   RuntimeDiagnosticEventCode = "lane_started"
	DiagnosticAttemptCreated                RuntimeDiagnosticEventCode = "attempt_created"
	DiagnosticAttemptStarted                RuntimeDiagnosticEventCode = "attempt_started"
	DiagnosticAttemptCompleted              RuntimeDiagnosticEventCode = "attempt_completed"
	DiagnosticAttemptFailed                 RuntimeDiagnosticEventCode = "attempt_failed"
	DiagnosticLaneCompleted                 RuntimeDiagnosticEventCode = "lane_completed"
	DiagnosticLaneCancelled                 RuntimeDiagnosticEventCode = "lane_cancelled"
	DiagnosticInvocationPrepared            RuntimeDiagnosticEventCode = "provider_invocation_prepared"
	DiagnosticSpawnRevalidated              RuntimeDiagnosticEventCode = "provider_spawn_revalidated"
	DiagnosticProcessStarted                RuntimeDiagnosticEventCode = "provider_process_started"
	DiagnosticIOObserved                    RuntimeDiagnosticEventCode = "provider_io_observed"
	DiagnosticProcessExited                 RuntimeDiagnosticEventCode = "provider_process_exited"
	DiagnosticProcessTimedOut               RuntimeDiagnosticEventCode = "provider_process_timed_out"
	DiagnosticProcessCancelled              RuntimeDiagnosticEventCode = "provider_process_cancelled"
	DiagnosticProcessTerminated             RuntimeDiagnosticEventCode = "provider_process_terminated"
	DiagnosticOutputReceived                RuntimeDiagnosticEventCode = "provider_output_received"
	DiagnosticOutputParseStarted            RuntimeDiagnosticEventCode = "provider_output_parse_started"
	DiagnosticOutputParsed                  RuntimeDiagnosticEventCode = "provider_output_parsed"
	DiagnosticOutputParseFailed             RuntimeDiagnosticEventCode = "provider_output_parse_failed"
	DiagnosticValidationStarted             RuntimeDiagnosticEventCode = "candidate_validation_started"
	DiagnosticValidationSucceeded           RuntimeDiagnosticEventCode = "candidate_validation_succeeded"
	DiagnosticValidationFailed              RuntimeDiagnosticEventCode = "candidate_validation_failed"
	DiagnosticRepairScheduled               RuntimeDiagnosticEventCode = "repair_scheduled"
	DiagnosticRepairStarted                 RuntimeDiagnosticEventCode = "repair_started"
	DiagnosticRepairCompleted               RuntimeDiagnosticEventCode = "repair_completed"
	DiagnosticRepairExhausted               RuntimeDiagnosticEventCode = "repair_exhausted"
	DiagnosticFallbackEligible              RuntimeDiagnosticEventCode = "fallback_eligible"
	DiagnosticFallbackScheduled             RuntimeDiagnosticEventCode = "fallback_scheduled"
	DiagnosticFallbackStarted               RuntimeDiagnosticEventCode = "fallback_started"
	DiagnosticFallbackCompleted             RuntimeDiagnosticEventCode = "fallback_completed"
	DiagnosticFallbackProhibited            RuntimeDiagnosticEventCode = "fallback_prohibited"
	DiagnosticRoleCompleted                 RuntimeDiagnosticEventCode = "role_completed"
	DiagnosticRoleExhausted                 RuntimeDiagnosticEventCode = "role_exhausted"
	DiagnosticReductionStarted              RuntimeDiagnosticEventCode = "coordinator_reduction_started"
	DiagnosticReductionCompleted            RuntimeDiagnosticEventCode = "coordinator_reduction_completed"
	DiagnosticPublicationPreparationStarted RuntimeDiagnosticEventCode = "publication_preparation_started"
	DiagnosticPublicationStaged             RuntimeDiagnosticEventCode = "publication_staged"
	DiagnosticPublicationInstalled          RuntimeDiagnosticEventCode = "publication_installed"
	DiagnosticPublicationCommitted          RuntimeDiagnosticEventCode = "publication_committed"
	DiagnosticPublicationFailed             RuntimeDiagnosticEventCode = "publication_failed"
	DiagnosticNamespaceDrainStarted         RuntimeDiagnosticEventCode = "provider_namespace_drain_started"
	DiagnosticNamespaceDrained              RuntimeDiagnosticEventCode = "provider_namespace_drained"
	DiagnosticWorkspaceCleanupStarted       RuntimeDiagnosticEventCode = "workspace_cleanup_started"
	DiagnosticWorkspaceCleanupCompleted     RuntimeDiagnosticEventCode = "workspace_cleanup_completed"
)

var runtimeDiagnosticMessages = map[RuntimeDiagnosticEventCode]string{
	DiagnosticCommandAccepted: "command accepted", DiagnosticRuntimeOpened: "runtime diagnostics opened",
	DiagnosticSessionCreated: "session created", DiagnosticRunCreated: "run created", DiagnosticRunStarted: "run started",
	DiagnosticRunCompleted: "run completed", DiagnosticRunStopped: "run stopped", DiagnosticRuntimeClosed: "runtime diagnostics closed",
	DiagnosticQualificationStarted: "qualification started", DiagnosticQualificationCandidateChecked: "qualification candidate checked",
	DiagnosticQualificationSucceeded: "qualification succeeded", DiagnosticQualificationRejected: "qualification rejected",
	DiagnosticReviewPlanCreated: "review plan created", DiagnosticAssignmentResolved: "assignment resolved", DiagnosticRunBudgetAccepted: "run budget accepted",
	DiagnosticLaneScheduled: "lane scheduled", DiagnosticLaneStarted: "lane started", DiagnosticAttemptCreated: "attempt created",
	DiagnosticAttemptStarted: "attempt started", DiagnosticAttemptCompleted: "attempt completed", DiagnosticAttemptFailed: "attempt failed",
	DiagnosticLaneCompleted: "lane completed", DiagnosticLaneCancelled: "lane cancelled", DiagnosticInvocationPrepared: "provider invocation prepared",
	DiagnosticSpawnRevalidated: "provider spawn revalidated", DiagnosticProcessStarted: "provider process started", DiagnosticIOObserved: "provider I/O observed",
	DiagnosticProcessExited: "provider process exited", DiagnosticProcessTimedOut: "provider process timed out", DiagnosticProcessCancelled: "provider process cancelled",
	DiagnosticProcessTerminated: "provider process terminated", DiagnosticOutputReceived: "provider output received", DiagnosticOutputParseStarted: "provider output parse started",
	DiagnosticOutputParsed: "provider output parsed", DiagnosticOutputParseFailed: "provider output parse failed", DiagnosticValidationStarted: "candidate validation started",
	DiagnosticValidationSucceeded: "candidate validation succeeded", DiagnosticValidationFailed: "candidate validation failed", DiagnosticRepairScheduled: "repair scheduled",
	DiagnosticRepairStarted: "repair started", DiagnosticRepairCompleted: "repair completed", DiagnosticRepairExhausted: "repair exhausted",
	DiagnosticFallbackEligible: "fallback eligible", DiagnosticFallbackScheduled: "fallback scheduled", DiagnosticFallbackStarted: "fallback started",
	DiagnosticFallbackCompleted: "fallback completed", DiagnosticFallbackProhibited: "fallback prohibited", DiagnosticRoleCompleted: "role completed",
	DiagnosticRoleExhausted: "role exhausted", DiagnosticReductionStarted: "coordinator reduction started", DiagnosticReductionCompleted: "coordinator reduction completed",
	DiagnosticPublicationPreparationStarted: "publication preparation started", DiagnosticPublicationStaged: "publication staged",
	DiagnosticPublicationInstalled: "publication installed", DiagnosticPublicationCommitted: "publication committed", DiagnosticPublicationFailed: "publication failed",
	DiagnosticNamespaceDrainStarted: "provider namespace drain started", DiagnosticNamespaceDrained: "provider namespace drained",
	DiagnosticWorkspaceCleanupStarted: "workspace cleanup started", DiagnosticWorkspaceCleanupCompleted: "workspace cleanup completed",
}

func (code RuntimeDiagnosticEventCode) Valid() bool {
	_, ok := runtimeDiagnosticMessages[code]
	return ok
}
func (code RuntimeDiagnosticEventCode) SafeMessage() string { return runtimeDiagnosticMessages[code] }

type RuntimeDiagnosticCause string

const (
	DiagnosticCauseProviderSpawnFailed         RuntimeDiagnosticCause = "provider_spawn_failed"
	DiagnosticCauseProviderProcessWaitFailed   RuntimeDiagnosticCause = "provider_process_wait_failed"
	DiagnosticCauseProcessGroupCleanupFailed   RuntimeDiagnosticCause = "provider_process_group_cleanup_failed"
	DiagnosticCauseTransportVerificationFailed RuntimeDiagnosticCause = "provider_transport_verification_failed"
	DiagnosticCauseOutputFrameMissing          RuntimeDiagnosticCause = "provider_output_frame_missing"
	DiagnosticCauseOutputEnvelopeInvalid       RuntimeDiagnosticCause = "provider_output_envelope_invalid"
	DiagnosticCauseOutputDecodeFailed          RuntimeDiagnosticCause = "provider_output_decode_failed"
	DiagnosticCauseResultBindingFailed         RuntimeDiagnosticCause = "provider_result_binding_failed"
	DiagnosticCauseObservationInvalid          RuntimeDiagnosticCause = "provider_observation_invalid"
	DiagnosticCauseObservationMismatch         RuntimeDiagnosticCause = "provider_observation_mismatch"
	DiagnosticCauseCandidateValidationFailed   RuntimeDiagnosticCause = "candidate_validation_failed"
	DiagnosticCauseCandidateRepairPlanInvalid  RuntimeDiagnosticCause = "candidate_repair_plan_invalid"
	DiagnosticCauseWorkspaceRevalidationFailed RuntimeDiagnosticCause = "workspace_revalidation_failed"
	DiagnosticCausePersistenceFailed           RuntimeDiagnosticCause = "diagnostic_persistence_failed"
	DiagnosticCauseLoginRequired               RuntimeDiagnosticCause = "provider_login_required"
	DiagnosticCauseAuthenticationFailed        RuntimeDiagnosticCause = "provider_authentication_failed"
	DiagnosticCauseQuotaExceeded               RuntimeDiagnosticCause = "provider_quota_exceeded"
	DiagnosticCauseRateLimited                 RuntimeDiagnosticCause = "provider_rate_limited"
	DiagnosticCauseTimedOut                    RuntimeDiagnosticCause = "provider_timed_out"
)

func (cause RuntimeDiagnosticCause) Valid() bool {
	switch cause {
	case DiagnosticCauseProviderSpawnFailed, DiagnosticCauseProviderProcessWaitFailed, DiagnosticCauseProcessGroupCleanupFailed,
		DiagnosticCauseTransportVerificationFailed, DiagnosticCauseOutputFrameMissing, DiagnosticCauseOutputEnvelopeInvalid,
		DiagnosticCauseOutputDecodeFailed, DiagnosticCauseResultBindingFailed, DiagnosticCauseObservationInvalid,
		DiagnosticCauseObservationMismatch, DiagnosticCauseCandidateValidationFailed, DiagnosticCauseCandidateRepairPlanInvalid,
		DiagnosticCauseWorkspaceRevalidationFailed, DiagnosticCausePersistenceFailed, DiagnosticCauseLoginRequired,
		DiagnosticCauseAuthenticationFailed, DiagnosticCauseQuotaExceeded, DiagnosticCauseRateLimited, DiagnosticCauseTimedOut:
		return true
	default:
		return false
	}
}

type RuntimeDiagnosticStream string

const (
	DiagnosticStdout RuntimeDiagnosticStream = "stdout"
	DiagnosticStderr RuntimeDiagnosticStream = "stderr"
)

func (stream RuntimeDiagnosticStream) Valid() bool {
	return stream == DiagnosticStdout || stream == DiagnosticStderr
}

type RuntimeDiagnosticEventInput struct {
	Level                       RuntimeDiagnosticLevel
	Component, Operation        string
	Event                       RuntimeDiagnosticEventCode
	SessionID                   SessionID
	RunID                       RunID
	AttemptID                   AttemptID
	InvocationID                string
	Role                        Role
	Provider                    string
	Cause                       RuntimeDiagnosticCause
	Failure, Mitigation         string
	State, Outcome, Termination string
	Stream                      RuntimeDiagnosticStream
	Offset, Length              int64
	ExitCode                    int
	HasExitCode                 bool
	ArtifactRef                 string
}

type RuntimeDiagnosticEventDraft struct{ input RuntimeDiagnosticEventInput }

func NewRuntimeDiagnosticEventDraft(input RuntimeDiagnosticEventInput) (RuntimeDiagnosticEventDraft, error) {
	if !input.Level.Valid() || !input.Event.Valid() || !validDiagnosticToken(input.Component, 64) || !validDiagnosticToken(input.Operation, 64) {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid level, component, operation, or event")
	}
	if _, err := ParseSessionID(input.SessionID.String()); err != nil {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid session ID")
	}
	if _, err := ParseRunID(input.RunID.String()); err != nil {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid run ID")
	}
	if input.AttemptID.String() != "" {
		if _, err := ParseAttemptID(input.AttemptID.String()); err != nil {
			return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid attempt ID")
		}
	}
	if input.InvocationID != "" && !validDiagnosticInvocationID(input.InvocationID) {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid invocation ID")
	}
	if input.Provider != "" && !validDiagnosticProvider(input.Provider) {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid provider")
	}
	for _, value := range []string{input.Failure, input.Mitigation, input.State, input.Outcome, input.Termination} {
		if value != "" && !validDiagnosticToken(value, 128) {
			return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: unsafe optional token")
		}
	}
	if input.Role != "" && !input.Role.Valid() {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid role")
	}
	if input.Cause != "" && !input.Cause.Valid() {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid cause")
	}
	if input.Stream != "" {
		if !input.Stream.Valid() || input.Offset < 0 || input.Length <= 0 {
			return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid stream range")
		}
	} else if input.Offset != 0 || input.Length != 0 {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: stream range without stream")
	}
	if input.ArtifactRef != "" && !validDiagnosticPath(input.ArtifactRef) {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: invalid artifact reference")
	}
	if !validDiagnosticLevelForEvent(input.Level, input.Event) {
		return RuntimeDiagnosticEventDraft{}, fmt.Errorf("runtime diagnostic event: level is inconsistent with event")
	}
	return RuntimeDiagnosticEventDraft{input: input}, nil
}

func (draft RuntimeDiagnosticEventDraft) Valid() bool {
	_, err := NewRuntimeDiagnosticEventDraft(draft.input)
	return err == nil
}
func (draft RuntimeDiagnosticEventDraft) Input() RuntimeDiagnosticEventInput { return draft.input }

type RuntimeDiagnosticEvent struct {
	draft         RuntimeDiagnosticEventDraft
	sequence      uint64
	timestamp     time.Time
	elapsedMillis uint64
}

func StampRuntimeDiagnosticEvent(draft RuntimeDiagnosticEventDraft, sequence uint64, timestamp time.Time, elapsedMillis uint64) (RuntimeDiagnosticEvent, error) {
	if !draft.Valid() || sequence == 0 || timestamp.IsZero() || timestamp.Location() != time.UTC {
		return RuntimeDiagnosticEvent{}, fmt.Errorf("runtime diagnostic event: invalid draft, sequence, or UTC timestamp")
	}
	return RuntimeDiagnosticEvent{draft: draft, sequence: sequence, timestamp: timestamp, elapsedMillis: elapsedMillis}, nil
}

func (event RuntimeDiagnosticEvent) SchemaVersion() string              { return RuntimeDiagnosticSchemaVersion }
func (event RuntimeDiagnosticEvent) Sequence() uint64                   { return event.sequence }
func (event RuntimeDiagnosticEvent) Time() time.Time                    { return event.timestamp }
func (event RuntimeDiagnosticEvent) ElapsedMillis() uint64              { return event.elapsedMillis }
func (event RuntimeDiagnosticEvent) Level() RuntimeDiagnosticLevel      { return event.draft.input.Level }
func (event RuntimeDiagnosticEvent) Message() string                    { return event.draft.input.Event.SafeMessage() }
func (event RuntimeDiagnosticEvent) Code() RuntimeDiagnosticEventCode   { return event.draft.input.Event }
func (event RuntimeDiagnosticEvent) Input() RuntimeDiagnosticEventInput { return event.draft.input }

func validDiagnosticToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == ':') {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}

func validDiagnosticPath(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\\\x00\r\n") && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../")
}

func validDiagnosticInvocationID(value string) bool {
	if !strings.HasPrefix(value, "i_") {
		return false
	}
	_, err := ParseReviewID(strings.TrimPrefix(value, "i_"))
	return err == nil
}

func validDiagnosticProvider(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validDiagnosticLevelForEvent(level RuntimeDiagnosticLevel, event RuntimeDiagnosticEventCode) bool {
	switch event {
	case DiagnosticRunStopped, DiagnosticAttemptFailed, DiagnosticProcessTimedOut, DiagnosticProcessTerminated,
		DiagnosticOutputParseFailed, DiagnosticValidationFailed, DiagnosticRepairExhausted,
		DiagnosticFallbackProhibited, DiagnosticRoleExhausted, DiagnosticPublicationFailed:
		return level == RuntimeDiagnosticError
	case DiagnosticRepairScheduled, DiagnosticRepairStarted, DiagnosticRepairCompleted,
		DiagnosticFallbackEligible, DiagnosticFallbackScheduled, DiagnosticFallbackStarted, DiagnosticFallbackCompleted:
		return level == RuntimeDiagnosticWarn
	default:
		return level == RuntimeDiagnosticInfo
	}
}
