package review

import (
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCurrentReviewOwnersRejectNilAndTypedNilDependencies(t *testing.T) {
	_, receipt := coordinatorTestPlan(t)
	var err error
	receipt, err = PreflightRunBudgetWithCapacity(receipt.RoleBudgets(), receipt.Ceilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	clock := coordinatorTestClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	ids := &coordinatorTestIDs{}
	runtime := &coordinatorTestRuntime{}
	if _, err := NewCoordinator(clock, ids, runtime, 1, receipt); err != nil {
		t.Fatalf("coordinator positive control: %v", err)
	}
	for _, test := range []struct {
		name    string
		clock   ports.Clock
		ids     CoordinatorIDIssuer
		runtime InvocationRuntime
	}{
		{"clock", nil, ids, runtime}, {"typed nil clock", (*coordinatorTestClock)(nil), ids, runtime},
		{"ids", clock, nil, runtime}, {"typed nil ids", clock, (*coordinatorTestIDs)(nil), runtime},
		{"runtime", clock, ids, nil}, {"typed nil runtime", clock, ids, (*coordinatorTestRuntime)(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCoordinator(test.clock, test.ids, test.runtime, 1, receipt); err == nil {
				t.Fatal("current coordinator accepted missing dependency")
			}
		})
	}
	provider := &recordingReviewProvider{}
	source := explicitRuntimePromptSource{}
	validator := newReviewValidator(t)
	verifier := newReviewTestVerifier(t, verifiedHighFindingReader())
	if _, err := NewProviderInvocationRuntime(provider, source, validator, verifier); err != nil {
		t.Fatalf("runtime positive control: %v", err)
	}
	for _, test := range []struct {
		name      string
		provider  ports.ReviewProvider
		source    InvocationPromptSource
		validator *validation.ReviewValidator
		verifier  *evidence.Verifier
	}{
		{"provider", nil, source, validator, verifier}, {"typed nil provider", (*recordingReviewProvider)(nil), source, validator, verifier},
		{"source", provider, nil, validator, verifier}, {"typed nil source", provider, (*explicitRuntimePromptSource)(nil), validator, verifier},
		{"validator", provider, source, nil, verifier}, {"verifier", provider, source, validator, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewProviderInvocationRuntime(test.provider, test.source, test.validator, test.verifier); err == nil {
				t.Fatal("current provider runtime accepted missing dependency")
			}
		})
	}
}
