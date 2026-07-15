package review

import (
	"fmt"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// CoordinatorEventKind is the closed, logical event vocabulary emitted by the
// single coordinator owner. Event order, rather than wall-clock timing, is the
// authoritative execution trace.
type CoordinatorEventKind string

const (
	CoordinatorEventRunStarted            CoordinatorEventKind = "run_started"
	CoordinatorEventAttemptQueued         CoordinatorEventKind = "attempt_queued"
	CoordinatorEventInvocationDispatched  CoordinatorEventKind = "invocation_dispatched"
	CoordinatorEventInvocationCommitted   CoordinatorEventKind = "invocation_committed"
	CoordinatorEventRepairQueued          CoordinatorEventKind = "repair_queued"
	CoordinatorEventFallbackQueued        CoordinatorEventKind = "fallback_queued"
	CoordinatorEventRoleTerminal          CoordinatorEventKind = "role_terminal"
	CoordinatorEventCancellationRequested CoordinatorEventKind = "cancellation_requested"
	CoordinatorEventLanesCloseAuthorized  CoordinatorEventKind = "lanes_close_authorized"
	CoordinatorEventRunTerminal           CoordinatorEventKind = "run_terminal"
)

// Valid reports whether kind is a coordinator-defined logical event kind.
func (kind CoordinatorEventKind) Valid() bool {
	switch kind {
	case CoordinatorEventRunStarted,
		CoordinatorEventAttemptQueued,
		CoordinatorEventInvocationDispatched,
		CoordinatorEventInvocationCommitted,
		CoordinatorEventRepairQueued,
		CoordinatorEventFallbackQueued,
		CoordinatorEventRoleTerminal,
		CoordinatorEventCancellationRequested,
		CoordinatorEventLanesCloseAuthorized,
		CoordinatorEventRunTerminal:
		return true
	default:
		return false
	}
}

// CoordinatorTraceEvent is one immutable, canonical coordinator decision. It
// intentionally excludes observed timestamps because timing has no transition
// authority.
type CoordinatorTraceEvent struct {
	ordinal      uint64
	kind         CoordinatorEventKind
	role         domain.Role
	attemptID    domain.AttemptID
	hasAttempt   bool
	attemptKind  AttemptKind
	purpose      domain.InvocationPurpose
	hasPurpose   bool
	lane         ports.ConcurrencyKey
	hasLane      bool
	condition    AttemptCondition
	hasCondition bool
	reason       string
	runState     domain.RunState
}

// Ordinal returns the canonical event order.
func (event CoordinatorTraceEvent) Ordinal() uint64 { return event.ordinal }

// Kind returns the closed logical event kind.
func (event CoordinatorTraceEvent) Kind() CoordinatorEventKind { return event.kind }

// Role returns the event role when the event is role-specific.
func (event CoordinatorTraceEvent) Role() (domain.Role, bool) {
	return event.role, event.role.Valid()
}

// AttemptID returns the coordinator-issued attempt identity when present.
func (event CoordinatorTraceEvent) AttemptID() (domain.AttemptID, bool) {
	return event.attemptID, event.hasAttempt
}

// AttemptKind returns the primary/fallback kind when an attempt is present.
func (event CoordinatorTraceEvent) AttemptKind() (AttemptKind, bool) {
	return event.attemptKind, event.hasAttempt
}

// Purpose returns the initial/repair purpose when an invocation is present.
func (event CoordinatorTraceEvent) Purpose() (domain.InvocationPurpose, bool) {
	return event.purpose, event.hasPurpose
}

// Lane returns the normalized concurrency lane when an invocation is present.
func (event CoordinatorTraceEvent) Lane() (ports.ConcurrencyKey, bool) {
	return event.lane, event.hasLane
}

// Condition returns the committed closed attempt condition when present.
func (event CoordinatorTraceEvent) Condition() (AttemptCondition, bool) {
	return event.condition, event.hasCondition
}

// Reason returns the stable policy reason when one applies.
func (event CoordinatorTraceEvent) Reason() string { return event.reason }

// RunState returns the terminal run state for run-terminal events.
func (event CoordinatorTraceEvent) RunState() (domain.RunState, bool) {
	return event.runState, event.kind == CoordinatorEventRunTerminal
}

func (event CoordinatorTraceEvent) validate() error {
	if event.ordinal == 0 || !event.kind.Valid() {
		return fmt.Errorf("review coordinator trace: invalid ordinal or event kind")
	}
	rolePresent := event.role.Valid()
	if event.role != "" && !rolePresent {
		return fmt.Errorf("review coordinator trace: invalid role")
	}
	if event.hasAttempt {
		if _, err := domain.ParseAttemptID(event.attemptID.String()); err != nil {
			return fmt.Errorf("review coordinator trace: invalid attempt ID: %w", err)
		}
		if !event.attemptKind.Valid() || !event.hasLane || !event.lane.Valid() {
			return fmt.Errorf("review coordinator trace: incomplete attempt identity")
		}
	} else if event.attemptID.String() != "" || event.attemptKind != "" || event.hasLane || event.lane.String() != "" {
		return fmt.Errorf("review coordinator trace: hidden attempt identity")
	}
	if event.hasPurpose {
		if !event.purpose.Valid() {
			return fmt.Errorf("review coordinator trace: invalid invocation purpose")
		}
	} else if event.purpose != "" {
		return fmt.Errorf("review coordinator trace: hidden invocation purpose")
	}
	if event.hasCondition {
		if !event.condition.Valid() {
			return fmt.Errorf("review coordinator trace: invalid condition")
		}
	} else if event.condition != "" {
		return fmt.Errorf("review coordinator trace: hidden condition")
	}

	var wantRole, wantAttempt, wantPurpose, wantCondition, wantReason, wantRunState bool
	switch event.kind {
	case CoordinatorEventRunStarted, CoordinatorEventLanesCloseAuthorized:
	case CoordinatorEventAttemptQueued:
		wantRole, wantAttempt = true, true
	case CoordinatorEventInvocationDispatched:
		wantRole, wantAttempt, wantPurpose = true, true, true
	case CoordinatorEventInvocationCommitted:
		wantRole, wantAttempt, wantPurpose, wantCondition = true, true, true, true
	case CoordinatorEventRepairQueued:
		wantRole, wantAttempt, wantPurpose, wantReason = true, true, true, true
	case CoordinatorEventFallbackQueued:
		wantRole, wantAttempt, wantCondition, wantReason = true, true, true, true
	case CoordinatorEventRoleTerminal:
		wantRole, wantAttempt, wantCondition, wantReason = true, event.hasAttempt, true, true
	case CoordinatorEventCancellationRequested:
		wantCondition, wantReason = true, true
	case CoordinatorEventRunTerminal:
		wantRunState = true
	}
	if rolePresent != wantRole ||
		event.hasAttempt != wantAttempt ||
		event.hasPurpose != wantPurpose ||
		event.hasCondition != wantCondition {
		return fmt.Errorf("review coordinator trace: invalid payload shape for %q", event.kind)
	}
	if wantReason {
		if !AttemptCondition(event.reason).Valid() {
			return fmt.Errorf("review coordinator trace: invalid reason for %q", event.kind)
		}
		if event.hasCondition && event.reason != string(event.condition) {
			return fmt.Errorf("review coordinator trace: reason does not match condition")
		}
	} else if event.reason != "" {
		return fmt.Errorf("review coordinator trace: unexpected reason for %q", event.kind)
	}
	if wantRunState {
		if !coordinatorTerminalRunState(event.runState) {
			return fmt.Errorf("review coordinator trace: terminal event has invalid run state")
		}
	} else if event.runState != "" {
		return fmt.Errorf("review coordinator trace: unexpected run state for %q", event.kind)
	}
	return nil
}
