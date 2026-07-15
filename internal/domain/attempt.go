package domain

import (
	"fmt"
	"strings"
)

type Invocation struct {
	sequence uint64
	purpose  InvocationPurpose
	state    InvocationState
}

func NewInvocation(sequence uint64, purpose InvocationPurpose) (Invocation, error) {
	if sequence == 0 {
		return Invocation{}, fmt.Errorf("invocation: %w: sequence must be positive", ErrInvariant)
	}
	if !purpose.Valid() {
		return Invocation{}, fmt.Errorf("invocation: %w: invalid purpose %q", ErrInvariant, purpose)
	}
	return Invocation{sequence: sequence, purpose: purpose, state: InvocationQueued}, nil
}

func (invocation Invocation) withTransition(next InvocationState) (Invocation, error) {
	if err := invocation.state.RequireTransition(next); err != nil {
		return Invocation{}, err
	}
	invocation.state = next
	return invocation, nil
}

func (invocation Invocation) Sequence() uint64           { return invocation.sequence }
func (invocation Invocation) Purpose() InvocationPurpose { return invocation.purpose }
func (invocation Invocation) State() InvocationState     { return invocation.state }

type Attempt struct {
	id               AttemptID
	state            AttemptState
	providerInstance string
	invocations      []Invocation
}

func NewAttempt(id AttemptID, providerInstance string, initial Invocation) (Attempt, error) {
	if _, err := ParseAttemptID(id.String()); err != nil {
		return Attempt{}, fmt.Errorf("attempt: %w", err)
	}
	providerInstance = strings.TrimSpace(providerInstance)
	if providerInstance == "" {
		return Attempt{}, fmt.Errorf("attempt: provider instance is required")
	}
	if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationQueued {
		return Attempt{}, fmt.Errorf("attempt: %w: first invocation must be queued initial at sequence 1", ErrInvariant)
	}
	return Attempt{id: id, state: AttemptQueued, providerInstance: providerInstance, invocations: []Invocation{initial}}, nil
}

func (attempt *Attempt) Transition(next AttemptState) error {
	if attempt == nil {
		return fmt.Errorf("attempt: %w: nil receiver", ErrInvariant)
	}
	if err := attempt.state.RequireTransition(next); err != nil {
		return err
	}

	switch next {
	case AttemptValidating:
		if attempt.state == AttemptRunning {
			if len(attempt.invocations) != 1 {
				return fmt.Errorf("attempt: %w: initial validation requires exactly one invocation", ErrInvariant)
			}
			initial := attempt.invocations[0]
			if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationSucceeded {
				return fmt.Errorf("attempt: %w: initial validation requires a succeeded initial invocation at sequence 1", ErrInvariant)
			}
			break
		}
		if len(attempt.invocations) != 2 {
			return fmt.Errorf("attempt: %w: repair validation requires exactly two invocations", ErrInvariant)
		}
		initial := attempt.invocations[0]
		repair := attempt.invocations[1]
		if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationSucceeded ||
			repair.Sequence() != 2 || repair.Purpose() != InvocationRepair || repair.State() != InvocationSucceeded {
			return fmt.Errorf("attempt: %w: repair validation requires a succeeded repair invocation at sequence 2", ErrInvariant)
		}
	case AttemptSucceeded:
		if len(attempt.invocations) == 0 || attempt.invocations[len(attempt.invocations)-1].State() != InvocationSucceeded {
			return fmt.Errorf("attempt: %w: succeeded requires the latest invocation to have succeeded", ErrInvariant)
		}
	case AttemptRepairing:
		if len(attempt.invocations) != 1 {
			return fmt.Errorf("attempt: %w: repair requires exactly one initial invocation", ErrInvariant)
		}
		initial := attempt.invocations[0]
		if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationSucceeded {
			return fmt.Errorf("attempt: %w: repair requires a succeeded initial invocation at sequence 1", ErrInvariant)
		}
	}

	attempt.state = next
	return nil
}

func (attempt *Attempt) AppendRepairInvocation(invocation Invocation) error {
	if attempt == nil {
		return fmt.Errorf("attempt: %w: nil receiver", ErrInvariant)
	}
	if len(attempt.invocations) != 1 {
		return fmt.Errorf("attempt: %w: exactly one repair invocation is allowed", ErrInvariant)
	}
	if attempt.state != AttemptRepairing {
		return fmt.Errorf("attempt: %w: repair can be appended only while repairing", ErrInvariant)
	}
	initial := attempt.invocations[0]
	if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationSucceeded {
		return fmt.Errorf("attempt: %w: repair requires a succeeded initial invocation at sequence 1", ErrInvariant)
	}
	if invocation.Sequence() != 2 || invocation.Purpose() != InvocationRepair || invocation.State() != InvocationQueued {
		return fmt.Errorf("attempt: %w: repair invocation must be queued repair at sequence 2", ErrInvariant)
	}
	attempt.invocations = append(attempt.invocations, invocation)
	return nil
}

func (attempt *Attempt) TransitionInvocation(sequence uint64, next InvocationState) error {
	if attempt == nil {
		return fmt.Errorf("attempt: %w: nil receiver", ErrInvariant)
	}
	if len(attempt.invocations) == 0 {
		return fmt.Errorf("attempt: %w: invocation aggregate is empty", ErrInvariant)
	}

	var current Invocation
	switch attempt.state {
	case AttemptRunning:
		if len(attempt.invocations) != 1 {
			return fmt.Errorf("attempt: %w: initial phase requires exactly one invocation", ErrInvariant)
		}
		current = attempt.invocations[0]
		if current.Sequence() != 1 || current.Purpose() != InvocationInitial {
			return fmt.Errorf("attempt: %w: initial phase requires the initial invocation at sequence 1", ErrInvariant)
		}
	case AttemptRepairing:
		if len(attempt.invocations) != 2 {
			return fmt.Errorf("attempt: %w: repair phase requires exactly two invocations", ErrInvariant)
		}
		initial := attempt.invocations[0]
		if initial.Sequence() != 1 || initial.Purpose() != InvocationInitial || initial.State() != InvocationSucceeded {
			return fmt.Errorf("attempt: %w: repair phase requires a succeeded initial invocation at sequence 1", ErrInvariant)
		}
		current = attempt.invocations[1]
		if current.Sequence() != 2 || current.Purpose() != InvocationRepair {
			return fmt.Errorf("attempt: %w: repair phase requires the repair invocation at sequence 2", ErrInvariant)
		}
	default:
		return fmt.Errorf("attempt: %w: invocation transition is not allowed in state %q", ErrInvariant, attempt.state)
	}
	if current.Sequence() != sequence {
		return fmt.Errorf("attempt: %w: invocation sequence %d is not current", ErrInvariant, sequence)
	}

	updated, err := current.withTransition(next)
	if err != nil {
		return err
	}
	attempt.invocations[len(attempt.invocations)-1] = updated
	return nil
}

func (attempt Attempt) ID() AttemptID            { return attempt.id }
func (attempt Attempt) State() AttemptState      { return attempt.state }
func (attempt Attempt) ProviderInstance() string { return attempt.providerInstance }
func (attempt Attempt) Invocations() []Invocation {
	return append([]Invocation(nil), attempt.invocations...)
}
