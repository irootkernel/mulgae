package review

import (
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestDecideTransitionExhaustiveMatrix(t *testing.T) {
	t.Parallel()

	for _, expectation := range policyExpectations() {
		for _, repairUsed := range []bool{false, true} {
			for _, cancellationObserved := range []bool{false, true} {
				input := TransitionInput{
					Condition:            expectation.condition,
					RepairUsed:           repairUsed,
					CancellationObserved: cancellationObserved,
				}
				decision, err := DecideTransition(input)
				if err != nil {
					t.Fatalf("DecideTransition(%+v): %v", input, err)
				}
				assertDecision(t, input, decision, expectedDecision(expectation, input))
			}
		}
	}
}

func TestValidReviewIncludingFindingsNeverSchedulesWork(t *testing.T) {
	t.Parallel()

	for _, repairUsed := range []bool{false, true} {
		decision, err := DecideTransition(TransitionInput{
			Condition:  AttemptConditionValidReview,
			RepairUsed: repairUsed,
		})
		if err != nil {
			t.Fatalf("DecideTransition(valid review): %v", err)
		}
		if decision.ScheduleRepair() || decision.CancelRun() || decision.ProviderUnusable() {
			t.Fatalf("valid review with repair=%t scheduled work or blamed the provider: %+v", repairUsed, decision)
		}
		if decision.TerminalProjection() != TerminalProjectionSucceeded || decision.TerminalClass() != "" {
			t.Fatalf("valid review projection = %q/%q", decision.TerminalProjection(), decision.TerminalClass())
		}
	}
}

func TestSecurityAndCancellationProhibitNewWork(t *testing.T) {
	t.Parallel()

	for _, condition := range []AttemptCondition{
		AttemptConditionSecurityViolation,
		AttemptConditionMutationViolation,
		AttemptConditionCancelled,
	} {
		for _, repairUsed := range []bool{false, true} {
			decision, err := DecideTransition(TransitionInput{Condition: condition, RepairUsed: repairUsed})
			if err != nil {
				t.Fatalf("DecideTransition(%q): %v", condition, err)
			}
			if !decision.CancelRun() || decision.ScheduleRepair() {
				t.Fatalf("%q decision allowed new work: %+v", condition, decision)
			}
		}
	}
}

func TestObservedCancellationRespectsPrecedence(t *testing.T) {
	t.Parallel()

	protected := map[AttemptCondition]bool{
		AttemptConditionInternalInvariant: true,
		AttemptConditionArtifactFailure:   true,
		AttemptConditionSecurityViolation: true,
		AttemptConditionMutationViolation: true,
	}
	for _, expectation := range policyExpectations() {
		input := TransitionInput{
			Condition:            expectation.condition,
			CancellationObserved: true,
		}
		decision, err := DecideTransition(input)
		if err != nil {
			t.Fatalf("DecideTransition(%q, cancelled): %v", expectation.condition, err)
		}
		assertDecision(t, input, decision, expectedDecision(expectation, input))
		if protected[expectation.condition] {
			if decision.Condition() != expectation.condition {
				t.Fatalf("%q was overwritten by cancellation as %q", expectation.condition, decision.Condition())
			}
		} else if decision.Condition() != AttemptConditionCancelled {
			t.Fatalf("%q did not yield to cancellation: %q", expectation.condition, decision.Condition())
		}
	}
}

func TestReduceAttemptConditionsExhaustivePrecedence(t *testing.T) {
	t.Parallel()

	conditions := AttemptConditions()
	for _, first := range conditions {
		for _, second := range conditions {
			got, err := ReduceAttemptConditions(first, second)
			if err != nil {
				t.Fatalf("ReduceAttemptConditions(%q, %q): %v", first, second, err)
			}
			want := first
			if expectedConditionPrecedence(second) < expectedConditionPrecedence(first) {
				want = second
			}
			if got != want {
				t.Errorf("ReduceAttemptConditions(%q, %q) = %q, want %q", first, second, got, want)
			}
		}
	}
	for _, conditions := range [][]AttemptCondition{
		nil,
		{AttemptCondition("unknown")},
		{AttemptConditionValidReview, AttemptCondition("unknown")},
	} {
		if _, err := ReduceAttemptConditions(conditions...); !errors.Is(err, domain.ErrInvariant) {
			t.Errorf("ReduceAttemptConditions(%q) error = %v, want invariant", conditions, err)
		}
	}
}

// TestSemanticContradictionFailsClosed proves a contradiction the provider
// cannot be asked to repair closes the role immediately. It is the provider's
// fault, but not proof the provider is unusable: a different diff may well pass.
func TestSemanticContradictionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, repairUsed := range []bool{false, true} {
		input := TransitionInput{Condition: AttemptConditionSemanticContradiction, RepairUsed: repairUsed}
		decision, err := DecideTransition(input)
		if err != nil {
			t.Fatalf("DecideTransition(%+v): %v", input, err)
		}
		if decision.Condition() != AttemptConditionSemanticContradiction ||
			decision.ScheduleRepair() ||
			decision.CancelRun() ||
			decision.ProviderUnusable() ||
			decision.TerminalClass() != domain.FailureInvalidOutput ||
			decision.ReasonCode() != string(AttemptConditionSemanticContradiction) ||
			!decision.Terminal() {
			t.Fatalf("semantic contradiction decision = %+v", decision)
		}
	}
}

// TestProviderUnusableIsLimitedToDeterministicFailures pins which conditions
// tell the operator the provider itself must be fixed or replaced, rather than
// that the run may simply be worth repeating.
func TestProviderUnusableIsLimitedToDeterministicFailures(t *testing.T) {
	t.Parallel()

	unusable := map[AttemptCondition]bool{
		AttemptConditionProviderUnavailable:      true,
		AttemptConditionProviderSpawnFailed:      true,
		AttemptConditionAuthentication:           true,
		AttemptConditionProviderPermissionDenied: true,
		AttemptConditionLoginRequired:            true,
		AttemptConditionQuota:                    true,
	}
	for _, condition := range AttemptConditions() {
		decision, err := DecideTransition(TransitionInput{Condition: condition})
		if err != nil {
			t.Fatalf("DecideTransition(%q): %v", condition, err)
		}
		if got, want := decision.ProviderUnusable(), unusable[condition]; got != want {
			t.Fatalf("%q ProviderUnusable() = %t, want %t", condition, got, want)
		}
		// Anything that blames the provider must carry a provider-fault class,
		// so the CLI's retryability and the report's guidance stay consistent.
		if decision.ProviderUnusable() && !decision.TerminalClass().ProviderFault() {
			t.Fatalf("%q is unusable but carries class %q", condition, decision.TerminalClass())
		}
	}
	// Transient conditions must never claim the provider is unusable.
	for _, condition := range []AttemptCondition{AttemptConditionRateLimit, AttemptConditionTimeout, AttemptConditionProviderTimeout} {
		if unusable[condition] {
			t.Fatalf("%q was marked deterministic", condition)
		}
	}
}

func TestUnknownAttemptConditionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, cancellationObserved := range []bool{false, true} {
		decision, err := DecideTransition(TransitionInput{
			Condition:            AttemptCondition("unknown"),
			CancellationObserved: cancellationObserved,
		})
		if err == nil || !errors.Is(err, domain.ErrInvariant) {
			t.Fatalf("unknown condition error = %v, want invariant", err)
		}
		if decision != (TransitionDecision{}) {
			t.Fatalf("unknown condition decision = %+v, want zero value", decision)
		}
	}
}

func TestPolicyFactsAreDefensiveAndImmutable(t *testing.T) {
	t.Parallel()

	conditions := AttemptConditions()
	if len(conditions) != len(policyExpectations()) {
		t.Fatalf("condition count = %d, want %d", len(conditions), len(policyExpectations()))
	}
	conditions[0] = AttemptCondition("unknown")
	if got := AttemptConditions()[0]; got != AttemptConditionValidReview {
		t.Fatalf("mutating returned conditions changed policy: %q", got)
	}

	input := TransitionInput{
		Condition:  AttemptConditionInvalidEvidenceClaim,
		RepairUsed: false,
	}
	decision, err := DecideTransition(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Condition = AttemptConditionSecurityViolation
	input.RepairUsed = true
	input.CancellationObserved = true

	if decision.Condition() != AttemptConditionInvalidEvidenceClaim ||
		decision.TerminalClass() != domain.FailureInvalidOutput ||
		decision.ReasonCode() != string(AttemptConditionInvalidEvidenceClaim) ||
		!decision.ScheduleRepair() ||
		decision.CancelRun() ||
		decision.TerminalProjection() != TerminalProjectionNone {
		t.Fatalf("mutating the input changed decision facts: %+v", decision)
	}
}

func TestAttemptConditionsAreExactAndExhaustivelyValidated(t *testing.T) {
	t.Parallel()

	expected := []AttemptCondition{
		AttemptConditionValidReview,
		AttemptConditionInvalidProviderOutput,
		AttemptConditionUnrepairableProviderOutput,
		AttemptConditionProviderOutputMissing,
		AttemptConditionProviderOutputDecodeFailed,
		AttemptConditionInvalidEvidenceClaim,
		AttemptConditionUnrepairableEvidence,
		AttemptConditionSemanticContradiction,
		AttemptConditionProviderUnavailable,
		AttemptConditionProviderSpawnFailed,
		AttemptConditionTimeout,
		AttemptConditionProviderTimeout,
		AttemptConditionAuthentication,
		AttemptConditionProviderPermissionDenied,
		AttemptConditionLoginRequired,
		AttemptConditionQuota,
		AttemptConditionRateLimit,
		AttemptConditionSecurityViolation,
		AttemptConditionMutationViolation,
		AttemptConditionConfigurationViolation,
		AttemptConditionArtifactFailure,
		AttemptConditionCancelled,
		AttemptConditionInternalInvariant,
	}
	actual := AttemptConditions()
	if len(actual) != len(expected) {
		t.Fatalf("condition count = %d, want %d", len(actual), len(expected))
	}
	seen := make(map[AttemptCondition]struct{}, len(actual))
	for _, condition := range actual {
		if !condition.Valid() {
			t.Fatalf("condition %q is not valid", condition)
		}
		if err := condition.Validate(); err != nil {
			t.Fatalf("condition %q validation: %v", condition, err)
		}
		if _, duplicate := seen[condition]; duplicate {
			t.Fatalf("duplicate condition %q", condition)
		}
		seen[condition] = struct{}{}
	}
	for _, condition := range expected {
		if _, found := seen[condition]; !found {
			t.Fatalf("missing condition %q", condition)
		}
	}
	if AttemptCondition("unknown").Valid() {
		t.Fatal("unknown condition acquired policy")
	}
	if err := AttemptCondition("unknown").Validate(); !errors.Is(err, domain.ErrInvariant) {
		t.Fatalf("unknown condition validation = %v, want invariant", err)
	}
}

type policyExpectation struct {
	condition     AttemptCondition
	terminalClass domain.FailureClass
	projection    TerminalProjection
	repairable    bool
	cancelsRun    bool
}

type expectedTransitionDecision struct {
	condition      AttemptCondition
	scheduleRepair bool
	cancelRun      bool
	terminalClass  domain.FailureClass
	projection     TerminalProjection
	reasonCode     string
}

func policyExpectations() []policyExpectation {
	return []policyExpectation{
		{condition: AttemptConditionValidReview, projection: TerminalProjectionSucceeded},
		{condition: AttemptConditionInvalidProviderOutput, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed, repairable: true},
		{condition: AttemptConditionUnrepairableProviderOutput, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderOutputMissing, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderOutputDecodeFailed, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed},
		{condition: AttemptConditionInvalidEvidenceClaim, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed, repairable: true},
		{condition: AttemptConditionUnrepairableEvidence, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed},
		{condition: AttemptConditionSemanticContradiction, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderUnavailable, terminalClass: domain.FailureProviderUnavailable, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderSpawnFailed, terminalClass: domain.FailureProviderUnavailable, projection: TerminalProjectionFailed},
		{condition: AttemptConditionTimeout, terminalClass: domain.FailureTimeout, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderTimeout, terminalClass: domain.FailureTimeout, projection: TerminalProjectionFailed},
		{condition: AttemptConditionAuthentication, terminalClass: domain.FailureAuthentication, projection: TerminalProjectionFailed},
		{condition: AttemptConditionProviderPermissionDenied, terminalClass: domain.FailureAuthentication, projection: TerminalProjectionFailed},
		{condition: AttemptConditionLoginRequired, terminalClass: domain.FailureAuthentication, projection: TerminalProjectionFailed},
		{condition: AttemptConditionQuota, terminalClass: domain.FailureQuota, projection: TerminalProjectionFailed},
		{condition: AttemptConditionRateLimit, terminalClass: domain.FailureRateLimit, projection: TerminalProjectionFailed},
		{condition: AttemptConditionSecurityViolation, terminalClass: domain.FailureSecurityPolicy, projection: TerminalProjectionCancelled, cancelsRun: true},
		{condition: AttemptConditionMutationViolation, terminalClass: domain.FailureSecurityPolicy, projection: TerminalProjectionCancelled, cancelsRun: true},
		{condition: AttemptConditionConfigurationViolation, terminalClass: domain.FailureConfiguration, projection: TerminalProjectionFailed},
		{condition: AttemptConditionArtifactFailure, terminalClass: domain.FailureArtifact, projection: TerminalProjectionFailed},
		{condition: AttemptConditionCancelled, terminalClass: domain.FailureCancelled, projection: TerminalProjectionCancelled, cancelsRun: true},
		{condition: AttemptConditionInternalInvariant, terminalClass: domain.FailureInternal, projection: TerminalProjectionFailed},
	}
}

func expectedDecision(expectation policyExpectation, input TransitionInput) expectedTransitionDecision {
	effectiveCondition := expectation.condition
	if input.CancellationObserved {
		effectiveCondition = expectedReducedCondition(effectiveCondition, AttemptConditionCancelled)
	}
	expectation = policyExpectationFor(effectiveCondition)

	want := expectedTransitionDecision{
		condition:     expectation.condition,
		cancelRun:     expectation.cancelsRun,
		terminalClass: expectation.terminalClass,
		projection:    expectation.projection,
		reasonCode:    string(expectation.condition),
	}
	if expectation.repairable && !input.RepairUsed {
		want.scheduleRepair = true
		want.projection = TerminalProjectionNone
	}
	return want
}

func policyExpectationFor(condition AttemptCondition) policyExpectation {
	for _, expectation := range policyExpectations() {
		if expectation.condition == condition {
			return expectation
		}
	}
	panic("missing policy expectation")
}

func expectedReducedCondition(conditions ...AttemptCondition) AttemptCondition {
	selected := conditions[0]
	for _, condition := range conditions[1:] {
		if expectedConditionPrecedence(condition) < expectedConditionPrecedence(selected) {
			selected = condition
		}
	}
	return selected
}

func expectedConditionPrecedence(condition AttemptCondition) int {
	switch condition {
	case AttemptConditionInternalInvariant:
		return 0
	case AttemptConditionArtifactFailure:
		return 1
	case AttemptConditionSecurityViolation, AttemptConditionMutationViolation:
		return 2
	case AttemptConditionCancelled:
		return 3
	case AttemptConditionConfigurationViolation:
		return 4
	case AttemptConditionLoginRequired:
		return 5
	case AttemptConditionSemanticContradiction,
		AttemptConditionUnrepairableProviderOutput,
		AttemptConditionProviderOutputMissing,
		AttemptConditionProviderOutputDecodeFailed,
		AttemptConditionUnrepairableEvidence,
		AttemptConditionInvalidEvidenceClaim,
		AttemptConditionInvalidProviderOutput:
		return 6
	case AttemptConditionAuthentication,
		AttemptConditionProviderPermissionDenied,
		AttemptConditionQuota,
		AttemptConditionRateLimit,
		AttemptConditionTimeout,
		AttemptConditionProviderTimeout,
		AttemptConditionProviderUnavailable,
		AttemptConditionProviderSpawnFailed:
		return 7
	case AttemptConditionValidReview:
		return 8
	default:
		panic("unknown attempt condition")
	}
}

func assertDecision(t *testing.T, input TransitionInput, got TransitionDecision, want expectedTransitionDecision) {
	t.Helper()
	if got.Condition() != want.condition ||
		got.ScheduleRepair() != want.scheduleRepair ||
		got.CancelRun() != want.cancelRun ||
		got.TerminalClass() != want.terminalClass ||
		got.TerminalProjection() != want.projection ||
		got.ReasonCode() != want.reasonCode {
		t.Fatalf("DecideTransition(%+v) = condition=%q repair=%t cancel=%t class=%q projection=%q reason=%q, want condition=%q repair=%t cancel=%t class=%q projection=%q reason=%q", input, got.Condition(), got.ScheduleRepair(), got.CancelRun(), got.TerminalClass(), got.TerminalProjection(), got.ReasonCode(), want.condition, want.scheduleRepair, want.cancelRun, want.terminalClass, want.projection, want.reasonCode)
	}
	if got.ScheduleRepair() == got.Terminal() {
		t.Fatalf("DecideTransition(%+v) terminal=%t does not match scheduled work", input, got.Terminal())
	}
}
