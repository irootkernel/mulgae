package domain

import (
	"errors"
	"fmt"
)

var ErrInvariant = errors.New("domain invariant violation")

type TransitionError struct {
	Domain string
	From   string
	To     string
}

func (err *TransitionError) Error() string {
	return fmt.Sprintf("%s: illegal %s transition %q -> %q", ErrInvariant, err.Domain, err.From, err.To)
}

func (err *TransitionError) Unwrap() error { return ErrInvariant }

type RunType string

const (
	RunTypeReview   RunType = "review"
	RunTypeFollowup RunType = "followup"
	RunTypeDelta    RunType = "delta"
	RunTypeRerun    RunType = "rerun"
)

func (value RunType) Valid() bool {
	return oneOf(string(value), string(RunTypeReview), string(RunTypeFollowup), string(RunTypeDelta), string(RunTypeRerun))
}

type RunState string

const (
	RunPending   RunState = "pending"
	RunRunning   RunState = "running"
	RunCompleted RunState = "completed"
	RunDegraded  RunState = "degraded"
	RunFailed    RunState = "failed"
	RunCancelled RunState = "cancelled"
)

func (value RunState) Valid() bool {
	return oneOf(string(value), string(RunPending), string(RunRunning), string(RunCompleted), string(RunDegraded), string(RunFailed), string(RunCancelled))
}

func (value RunState) CanTransition(next RunState) bool {
	switch value {
	case RunPending:
		return next == RunRunning || next == RunCancelled
	case RunRunning:
		return next == RunCompleted || next == RunDegraded || next == RunFailed || next == RunCancelled
	default:
		return false
	}
}

func (value RunState) RequireTransition(next RunState) error {
	return requireTransition("run", string(value), value.Valid(), string(next), next.Valid(), value.CanTransition(next))
}

type RoleTaskState string

const (
	RoleTaskPending         RoleTaskState = "pending"
	RoleTaskPrimaryQueued   RoleTaskState = "primary_queued"
	RoleTaskPrimaryRunning  RoleTaskState = "primary_running"
	RoleTaskFallbackQueued  RoleTaskState = "fallback_queued"
	RoleTaskFallbackRunning RoleTaskState = "fallback_running"
	RoleTaskSucceeded       RoleTaskState = "succeeded"
	RoleTaskFailed          RoleTaskState = "failed"
	RoleTaskCancelled       RoleTaskState = "cancelled"
	RoleTaskBlocked         RoleTaskState = "blocked"
)

func (value RoleTaskState) Valid() bool {
	return oneOf(string(value), string(RoleTaskPending), string(RoleTaskPrimaryQueued), string(RoleTaskPrimaryRunning), string(RoleTaskFallbackQueued), string(RoleTaskFallbackRunning), string(RoleTaskSucceeded), string(RoleTaskFailed), string(RoleTaskCancelled), string(RoleTaskBlocked))
}

func (value RoleTaskState) CanTransition(next RoleTaskState) bool {
	switch value {
	case RoleTaskPending:
		return next == RoleTaskPrimaryQueued || next == RoleTaskCancelled || next == RoleTaskBlocked
	case RoleTaskPrimaryQueued:
		return next == RoleTaskPrimaryRunning || next == RoleTaskCancelled || next == RoleTaskBlocked
	case RoleTaskPrimaryRunning:
		return next == RoleTaskSucceeded || next == RoleTaskFallbackQueued || next == RoleTaskFailed || next == RoleTaskCancelled
	case RoleTaskFallbackQueued:
		return next == RoleTaskFallbackRunning || next == RoleTaskCancelled
	case RoleTaskFallbackRunning:
		return next == RoleTaskSucceeded || next == RoleTaskFailed || next == RoleTaskCancelled
	default:
		return false
	}
}

func (value RoleTaskState) RequireTransition(next RoleTaskState) error {
	return requireTransition("role task", string(value), value.Valid(), string(next), next.Valid(), value.CanTransition(next))
}

type AttemptState string

const (
	AttemptQueued     AttemptState = "queued"
	AttemptRunning    AttemptState = "running"
	AttemptValidating AttemptState = "validating"
	AttemptRepairing  AttemptState = "repairing"
	AttemptSucceeded  AttemptState = "succeeded"
	AttemptFailed     AttemptState = "failed"
	AttemptTimedOut   AttemptState = "timed_out"
	AttemptCancelled  AttemptState = "cancelled"
	AttemptBlocked    AttemptState = "blocked"
)

func (value AttemptState) Valid() bool {
	return oneOf(string(value), string(AttemptQueued), string(AttemptRunning), string(AttemptValidating), string(AttemptRepairing), string(AttemptSucceeded), string(AttemptFailed), string(AttemptTimedOut), string(AttemptCancelled), string(AttemptBlocked))
}

func (value AttemptState) CanTransition(next AttemptState) bool {
	switch value {
	case AttemptQueued:
		return next == AttemptRunning || next == AttemptCancelled || next == AttemptBlocked
	case AttemptRunning:
		return next == AttemptValidating || next == AttemptFailed || next == AttemptTimedOut || next == AttemptCancelled || next == AttemptBlocked
	case AttemptValidating:
		return next == AttemptRepairing || next == AttemptSucceeded || next == AttemptFailed || next == AttemptCancelled || next == AttemptBlocked
	case AttemptRepairing:
		return next == AttemptValidating || next == AttemptFailed || next == AttemptTimedOut || next == AttemptCancelled || next == AttemptBlocked
	default:
		return false
	}
}

func (value AttemptState) RequireTransition(next AttemptState) error {
	return requireTransition("attempt", string(value), value.Valid(), string(next), next.Valid(), value.CanTransition(next))
}

type InvocationState string

const (
	InvocationQueued    InvocationState = "queued"
	InvocationRunning   InvocationState = "running"
	InvocationSucceeded InvocationState = "succeeded"
	InvocationFailed    InvocationState = "failed"
	InvocationTimedOut  InvocationState = "timed_out"
	InvocationCancelled InvocationState = "cancelled"
	InvocationBlocked   InvocationState = "blocked"
)

func (value InvocationState) Valid() bool {
	return oneOf(string(value), string(InvocationQueued), string(InvocationRunning), string(InvocationSucceeded), string(InvocationFailed), string(InvocationTimedOut), string(InvocationCancelled), string(InvocationBlocked))
}

func (value InvocationState) CanTransition(next InvocationState) bool {
	switch value {
	case InvocationQueued:
		return next == InvocationRunning || next == InvocationCancelled || next == InvocationBlocked
	case InvocationRunning:
		return next == InvocationSucceeded || next == InvocationFailed || next == InvocationTimedOut || next == InvocationCancelled || next == InvocationBlocked
	default:
		return false
	}
}

func (value InvocationState) RequireTransition(next InvocationState) error {
	return requireTransition("invocation", string(value), value.Valid(), string(next), next.Valid(), value.CanTransition(next))
}

type ParseState string

const (
	ParseNotStarted     ParseState = "not_started"
	ParseValid          ParseState = "valid"
	ParseInvalidJSON    ParseState = "invalid_json"
	ParseEmptyOutput    ParseState = "empty_output"
	ParseOutputTooLarge ParseState = "output_too_large"
)

func (value ParseState) Valid() bool {
	return oneOf(string(value), string(ParseNotStarted), string(ParseValid), string(ParseInvalidJSON), string(ParseEmptyOutput), string(ParseOutputTooLarge))
}

type ValidationState string

const (
	ValidationNotStarted      ValidationState = "not_started"
	ValidationValid           ValidationState = "valid"
	ValidationRepairedValid   ValidationState = "repaired_valid"
	ValidationInvalid         ValidationState = "invalid"
	ValidationRepairExhausted ValidationState = "repair_exhausted"
	ValidationInternalError   ValidationState = "internal_error"
)

func (value ValidationState) Valid() bool {
	return oneOf(string(value), string(ValidationNotStarted), string(ValidationValid), string(ValidationRepairedValid), string(ValidationInvalid), string(ValidationRepairExhausted), string(ValidationInternalError))
}

// ClassifySuccessfulAttemptExtraction classifies a successful attempt's closed
// parse/validation pair. reportsOnly is true for not_started/not_started and for
// invalid or repair_exhausted validation with parse valid, invalid_json, or
// output_too_large; false for valid/(valid|repaired_valid). ok is false for any
// other pair, including empty_output with failed structured validation — empty
// assistant content cannot yield the required nonempty report body.
func ClassifySuccessfulAttemptExtraction(parse ParseState, validation ValidationState) (reportsOnly bool, ok bool) {
	switch {
	case parse == ParseNotStarted && validation == ValidationNotStarted:
		return true, true
	case parse == ParseValid && (validation == ValidationValid || validation == ValidationRepairedValid):
		return false, true
	case validation == ValidationInvalid || validation == ValidationRepairExhausted:
		switch parse {
		case ParseValid, ParseInvalidJSON, ParseOutputTooLarge:
			return true, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

type EvidenceState string

const (
	EvidenceVerified          EvidenceState = "verified"
	EvidencePartiallyVerified EvidenceState = "partially_verified"
	EvidenceUnverified        EvidenceState = "unverified"
	EvidenceInvalidPath       EvidenceState = "invalid_path"
	EvidenceInvalidLine       EvidenceState = "invalid_line"
	EvidenceQuoteMismatch     EvidenceState = "quote_mismatch"
	EvidenceOutsideScope      EvidenceState = "outside_review_scope"
)

func (value EvidenceState) Valid() bool {
	return oneOf(string(value), string(EvidenceVerified), string(EvidencePartiallyVerified), string(EvidenceUnverified), string(EvidenceInvalidPath), string(EvidenceInvalidLine), string(EvidenceQuoteMismatch), string(EvidenceOutsideScope))
}

type PublicationStatus string

const (
	PublicationNotPublished PublicationStatus = "not_published"
	PublicationStaged       PublicationStatus = "staged"
	PublicationInstalled    PublicationStatus = "installed"
	PublicationCommitted    PublicationStatus = "committed"
	PublicationCorrupt      PublicationStatus = "corrupt"
)

func (value PublicationStatus) Valid() bool {
	return oneOf(string(value), string(PublicationNotPublished), string(PublicationStaged), string(PublicationInstalled), string(PublicationCommitted), string(PublicationCorrupt))
}

type FindingLifecycle string

const (
	FindingOpen         FindingLifecycle = "open"
	FindingAcknowledged FindingLifecycle = "acknowledged"
	FindingResolved     FindingLifecycle = "resolved"
	FindingDismissed    FindingLifecycle = "dismissed"
)

func (value FindingLifecycle) Valid() bool {
	return oneOf(string(value), string(FindingOpen), string(FindingAcknowledged), string(FindingResolved), string(FindingDismissed))
}

type FollowupResolution string

const (
	FollowupResolved          FollowupResolution = "resolved"
	FollowupPartiallyResolved FollowupResolution = "partially_resolved"
	FollowupStillOpen         FollowupResolution = "still_open"
	FollowupUnclear           FollowupResolution = "unclear"
)

func (value FollowupResolution) Valid() bool {
	return oneOf(string(value), string(FollowupResolved), string(FollowupPartiallyResolved), string(FollowupStillOpen), string(FollowupUnclear))
}

type InvocationPurpose string

const (
	InvocationInitial InvocationPurpose = "initial"
	InvocationRepair  InvocationPurpose = "repair"
)

func (value InvocationPurpose) Valid() bool {
	return value == InvocationInitial || value == InvocationRepair
}

func requireTransition(domain, from string, fromValid bool, to string, toValid, allowed bool) error {
	if !fromValid || !toValid || !allowed {
		return &TransitionError{Domain: domain, From: from, To: to}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
