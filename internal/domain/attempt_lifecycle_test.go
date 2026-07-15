package domain

import (
	"errors"
	"reflect"
	"testing"
)

func lifecycleAttempt(t *testing.T) Attempt {
	t.Helper()

	id, err := ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewInvocation(1, InvocationInitial)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewAttempt(id, "provider", initial)
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func lifecycleInvocation(t *testing.T, sequence uint64, purpose InvocationPurpose) Invocation {
	t.Helper()

	invocation, err := NewInvocation(sequence, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func snapshotAttempt(attempt Attempt) Attempt {
	snapshot := attempt
	snapshot.invocations = append([]Invocation(nil), attempt.invocations...)
	return snapshot
}

func lifecycleRequireInvariant(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvariant) {
		t.Fatalf("error = %v, want ErrInvariant", err)
	}
}

func requireRejectedAttemptMutation(t *testing.T, attempt *Attempt, action func() error) {
	t.Helper()

	before := snapshotAttempt(*attempt)
	lifecycleRequireInvariant(t, action())
	if attempt.state != before.state {
		t.Fatalf("state changed after rejected mutation: got %q, want %q", attempt.state, before.state)
	}
	if !reflect.DeepEqual(attempt.invocations, before.invocations) {
		t.Fatalf("invocation history changed after rejected mutation: got %#v, want %#v", attempt.invocations, before.invocations)
	}
}

func advanceInitialToValidation(t *testing.T, attempt *Attempt) {
	t.Helper()

	if err := attempt.Transition(AttemptRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Transition(AttemptValidating); err != nil {
		t.Fatal(err)
	}
}

func advanceToRepairing(t *testing.T, attempt *Attempt) {
	t.Helper()

	advanceInitialToValidation(t, attempt)
	if err := attempt.Transition(AttemptRepairing); err != nil {
		t.Fatal(err)
	}
}

func TestAttemptLifecycleRequiresCanonicalInitialInvocation(t *testing.T) {
	id, err := ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	maxSequence := ^uint64(0)
	cases := []struct {
		name    string
		initial Invocation
	}{
		{
			name:    "zero sequence",
			initial: Invocation{sequence: 0, purpose: InvocationInitial, state: InvocationQueued},
		},
		{
			name:    "gap sequence",
			initial: Invocation{sequence: 2, purpose: InvocationInitial, state: InvocationQueued},
		},
		{
			name:    "max sequence",
			initial: Invocation{sequence: maxSequence, purpose: InvocationInitial, state: InvocationQueued},
		},
		{
			name:    "repair purpose",
			initial: Invocation{sequence: 1, purpose: InvocationRepair, state: InvocationQueued},
		},
		{
			name:    "running state",
			initial: Invocation{sequence: 1, purpose: InvocationInitial, state: InvocationRunning},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			before := test.initial
			attempt, err := NewAttempt(id, "provider", test.initial)
			lifecycleRequireInvariant(t, err)
			if !reflect.DeepEqual(attempt, Attempt{}) {
				t.Fatalf("rejected constructor returned attempt %#v", attempt)
			}
			if test.initial != before {
				t.Fatalf("constructor changed initial invocation: got %#v, want %#v", test.initial, before)
			}
		})
	}

	if _, err := NewInvocation(0, InvocationInitial); !errors.Is(err, ErrInvariant) {
		t.Fatalf("zero-sequence invocation error = %v, want ErrInvariant", err)
	}
	if _, err := NewInvocation(1, InvocationPurpose("unexpected")); !errors.Is(err, ErrInvariant) {
		t.Fatalf("invalid-purpose invocation error = %v, want ErrInvariant", err)
	}
}

func TestAttemptLifecycleRequiresCanonicalRepairInvocation(t *testing.T) {
	maxSequence := ^uint64(0)
	cases := []struct {
		name       string
		invocation Invocation
	}{
		{
			name:       "zero sequence",
			invocation: Invocation{sequence: 0, purpose: InvocationRepair, state: InvocationQueued},
		},
		{
			name:       "initial sequence",
			invocation: Invocation{sequence: 1, purpose: InvocationRepair, state: InvocationQueued},
		},
		{
			name:       "gap sequence",
			invocation: Invocation{sequence: 3, purpose: InvocationRepair, state: InvocationQueued},
		},
		{
			name:       "max sequence",
			invocation: Invocation{sequence: maxSequence, purpose: InvocationRepair, state: InvocationQueued},
		},
		{
			name:       "initial purpose",
			invocation: Invocation{sequence: 2, purpose: InvocationInitial, state: InvocationQueued},
		},
		{
			name:       "running state",
			invocation: Invocation{sequence: 2, purpose: InvocationRepair, state: InvocationRunning},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			attempt := lifecycleAttempt(t)
			advanceToRepairing(t, &attempt)
			requireRejectedAttemptMutation(t, &attempt, func() error {
				return attempt.AppendRepairInvocation(test.invocation)
			})
		})
	}

	attempt := lifecycleAttempt(t)
	advanceToRepairing(t, &attempt)
	repair := lifecycleInvocation(t, 2, InvocationRepair)
	if err := attempt.AppendRepairInvocation(repair); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &attempt, func() error {
		return attempt.AppendRepairInvocation(lifecycleInvocation(t, 2, InvocationRepair))
	})
}

func TestAttemptLifecycleRejectsPrematureAggregateTransitions(t *testing.T) {
	fromRunning := lifecycleAttempt(t)
	if err := fromRunning.Transition(AttemptRunning); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &fromRunning, func() error {
		return fromRunning.Transition(AttemptValidating)
	})

	fromRepairing := lifecycleAttempt(t)
	advanceToRepairing(t, &fromRepairing)
	requireRejectedAttemptMutation(t, &fromRepairing, func() error {
		return fromRepairing.Transition(AttemptValidating)
	})
	if err := fromRepairing.AppendRepairInvocation(lifecycleInvocation(t, 2, InvocationRepair)); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &fromRepairing, func() error {
		return fromRepairing.Transition(AttemptValidating)
	})

	prematureRepairCases := []struct {
		name        string
		invocations []Invocation
	}{
		{
			name: "initial not succeeded",
			invocations: []Invocation{
				{sequence: 1, purpose: InvocationInitial, state: InvocationQueued},
			},
		},
		{
			name: "repair already present",
			invocations: []Invocation{
				{sequence: 1, purpose: InvocationInitial, state: InvocationSucceeded},
				{sequence: 2, purpose: InvocationRepair, state: InvocationQueued},
			},
		},
	}
	for _, test := range prematureRepairCases {
		t.Run(test.name, func(t *testing.T) {
			attempt := lifecycleAttempt(t)
			attempt.state = AttemptValidating
			attempt.invocations = append([]Invocation(nil), test.invocations...)
			requireRejectedAttemptMutation(t, &attempt, func() error {
				return attempt.Transition(AttemptRepairing)
			})
		})
	}

	prematureSuccess := lifecycleAttempt(t)
	prematureSuccess.state = AttemptValidating
	prematureSuccess.invocations = []Invocation{
		{sequence: 1, purpose: InvocationInitial, state: InvocationSucceeded},
		{sequence: 2, purpose: InvocationRepair, state: InvocationQueued},
	}
	requireRejectedAttemptMutation(t, &prematureSuccess, func() error {
		return prematureSuccess.Transition(AttemptSucceeded)
	})
}

func TestAttemptLifecycleInitialRepairValidationSuccessPath(t *testing.T) {
	attempt := lifecycleAttempt(t)
	advanceInitialToValidation(t, &attempt)
	if err := attempt.Transition(AttemptRepairing); err != nil {
		t.Fatal(err)
	}
	if err := attempt.AppendRepairInvocation(lifecycleInvocation(t, 2, InvocationRepair)); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(2, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(2, InvocationSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Transition(AttemptValidating); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Transition(AttemptSucceeded); err != nil {
		t.Fatal(err)
	}

	if attempt.State() != AttemptSucceeded {
		t.Fatalf("state = %q, want %q", attempt.State(), AttemptSucceeded)
	}
	want := []Invocation{
		{sequence: 1, purpose: InvocationInitial, state: InvocationSucceeded},
		{sequence: 2, purpose: InvocationRepair, state: InvocationSucceeded},
	}
	if got := attempt.Invocations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("invocations = %#v, want %#v", got, want)
	}
}

func TestAttemptLifecycleRejectsWrongPhaseAndTerminalInvocationMutations(t *testing.T) {
	initialPhase := lifecycleAttempt(t)
	if err := initialPhase.Transition(AttemptRunning); err != nil {
		t.Fatal(err)
	}
	initialPhase.invocations = append(initialPhase.invocations, Invocation{sequence: 2, purpose: InvocationRepair, state: InvocationQueued})
	requireRejectedAttemptMutation(t, &initialPhase, func() error {
		return initialPhase.TransitionInvocation(2, InvocationRunning)
	})

	repairPhase := lifecycleAttempt(t)
	advanceToRepairing(t, &repairPhase)
	if err := repairPhase.AppendRepairInvocation(lifecycleInvocation(t, 2, InvocationRepair)); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &repairPhase, func() error {
		return repairPhase.TransitionInvocation(1, InvocationRunning)
	})

	terminalStates := []InvocationState{
		InvocationSucceeded,
		InvocationFailed,
		InvocationTimedOut,
		InvocationCancelled,
		InvocationBlocked,
	}
	for _, terminal := range terminalStates {
		t.Run(string(terminal), func(t *testing.T) {
			attempt := lifecycleAttempt(t)
			attempt.state = AttemptRunning
			attempt.invocations[0].state = terminal
			requireRejectedAttemptMutation(t, &attempt, func() error {
				return attempt.TransitionInvocation(1, InvocationRunning)
			})
		})
	}
}

func TestAttemptLifecycleRejectsZeroAndNilReceivers(t *testing.T) {
	validRepair := lifecycleInvocation(t, 2, InvocationRepair)
	zeroActions := []struct {
		name   string
		action func(*Attempt) error
	}{
		{
			name: "transition",
			action: func(attempt *Attempt) error {
				return attempt.Transition(AttemptRunning)
			},
		},
		{
			name: "append repair",
			action: func(attempt *Attempt) error {
				return attempt.AppendRepairInvocation(validRepair)
			},
		},
		{
			name: "transition invocation",
			action: func(attempt *Attempt) error {
				return attempt.TransitionInvocation(1, InvocationRunning)
			},
		},
	}
	for _, test := range zeroActions {
		t.Run("zero "+test.name, func(t *testing.T) {
			var attempt Attempt
			requireRejectedAttemptMutation(t, &attempt, func() error {
				return test.action(&attempt)
			})
		})
		t.Run("nil "+test.name, func(t *testing.T) {
			var attempt *Attempt
			lifecycleRequireInvariant(t, test.action(attempt))
		})
	}
}
