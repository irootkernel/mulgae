package domain

import (
	"reflect"
	"testing"
)

func TestAttemptLifecycleExtractionTrailerSuccessPath(t *testing.T) {
	attempt := lifecycleAttempt(t)
	advanceInitialToValidation(t, &attempt)
	if err := attempt.AppendExtractInvocation(lifecycleInvocation(t, 2, InvocationExtract)); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(2, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(2, InvocationSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Transition(AttemptSucceeded); err != nil {
		t.Fatal(err)
	}

	want := []Invocation{
		{sequence: 1, purpose: InvocationInitial, state: InvocationSucceeded},
		{sequence: 2, purpose: InvocationExtract, state: InvocationSucceeded},
	}
	if got := attempt.Invocations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("invocations = %#v, want %#v", got, want)
	}
}

// A failed extraction trailer must never withdraw the already accepted report.
// This is the structural guarantee that extraction cannot fail a publication
// that would otherwise succeed.
func TestAttemptLifecycleFailedExtractionTrailerStillSucceeds(t *testing.T) {
	for _, state := range []InvocationState{InvocationFailed, InvocationTimedOut, InvocationCancelled} {
		attempt := lifecycleAttempt(t)
		advanceInitialToValidation(t, &attempt)
		if err := attempt.AppendExtractInvocation(lifecycleInvocation(t, 2, InvocationExtract)); err != nil {
			t.Fatal(err)
		}
		if err := attempt.TransitionInvocation(2, InvocationRunning); err != nil {
			t.Fatal(err)
		}
		if err := attempt.TransitionInvocation(2, state); err != nil {
			t.Fatal(err)
		}
		if err := attempt.Transition(AttemptSucceeded); err != nil {
			t.Fatalf("attempt with %q extraction trailer: %v", state, err)
		}
		if attempt.State() != AttemptSucceeded {
			t.Fatalf("state = %q, want %q", attempt.State(), AttemptSucceeded)
		}
	}
}

func TestAttemptLifecycleRejectsNonTerminalExtractionTrailerOnSuccess(t *testing.T) {
	attempt := lifecycleAttempt(t)
	advanceInitialToValidation(t, &attempt)
	if err := attempt.AppendExtractInvocation(lifecycleInvocation(t, 2, InvocationExtract)); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &attempt, func() error { return attempt.Transition(AttemptSucceeded) })
	if err := attempt.TransitionInvocation(2, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &attempt, func() error { return attempt.Transition(AttemptSucceeded) })
}

func TestAttemptLifecycleRequiresCanonicalExtractionInvocation(t *testing.T) {
	cases := []struct {
		name       string
		invocation Invocation
	}{
		{"wrong sequence", lifecycleInvocation(t, 1, InvocationExtract)},
		{"wrong purpose", lifecycleInvocation(t, 2, InvocationRepair)},
		{"already running", Invocation{sequence: 2, purpose: InvocationExtract, state: InvocationRunning}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			attempt := lifecycleAttempt(t)
			advanceInitialToValidation(t, &attempt)
			requireRejectedAttemptMutation(t, &attempt, func() error {
				return attempt.AppendExtractInvocation(testCase.invocation)
			})
		})
	}
}

// Extraction consumes the same single second invocation retry and repair compete
// for, so a role that already spent that slot can never receive a trailer.
func TestAttemptLifecycleRejectsExtractionAfterSecondInvocation(t *testing.T) {
	attempt := lifecycleAttempt(t)
	advanceInitialToValidation(t, &attempt)
	if err := attempt.Transition(AttemptRepairing); err != nil {
		t.Fatal(err)
	}
	if err := attempt.AppendRepairInvocation(lifecycleInvocation(t, 2, InvocationRepair)); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &attempt, func() error {
		return attempt.AppendExtractInvocation(lifecycleInvocation(t, 3, InvocationExtract))
	})
}

func TestAttemptLifecycleRejectsExtractionOutsideValidation(t *testing.T) {
	attempt := lifecycleAttempt(t)
	if err := attempt.Transition(AttemptRunning); err != nil {
		t.Fatal(err)
	}
	requireRejectedAttemptMutation(t, &attempt, func() error {
		return attempt.AppendExtractInvocation(lifecycleInvocation(t, 2, InvocationExtract))
	})
}

func TestExtractionPurposeDoesNotCarryRoleReport(t *testing.T) {
	carriers := map[InvocationPurpose]bool{
		InvocationInitial: true,
		InvocationRetry:   true,
		InvocationRepair:  true,
		InvocationExtract: false,
	}
	for purpose, want := range carriers {
		if !purpose.Valid() {
			t.Fatalf("purpose %q must be valid", purpose)
		}
		if got := purpose.CarriesRoleReport(); got != want {
			t.Fatalf("purpose %q carries role report = %t, want %t", purpose, got, want)
		}
	}
}
