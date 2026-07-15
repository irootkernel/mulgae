package review

import (
	"errors"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestDecideTransitionExhaustiveMatrix(t *testing.T) {
	t.Parallel()

	for _, expectation := range policyExpectations() {
		for _, repairUsed := range []bool{false, true} {
			for _, fallbackConfigured := range []bool{false, true} {
				for _, fallbackEligible := range []bool{false, true} {
					for _, cancellationObserved := range []bool{false, true} {
						input := TransitionInput{
							Condition:            expectation.condition,
							RepairUsed:           repairUsed,
							FallbackConfigured:   fallbackConfigured,
							FallbackEligible:     fallbackEligible,
							CancellationObserved: cancellationObserved,
						}
						decision, err := DecideTransition(input)
						if err != nil {
							t.Fatalf("DecideTransition(%+v): %v", input, err)
						}
						want := expectedDecision(expectation, input)
						assertDecision(t, input, decision, want)
					}
				}
			}
		}
	}
}

func TestValidReviewIncludingFindingsNeverSchedulesFallback(t *testing.T) {
	t.Parallel()

	for _, repairUsed := range []bool{false, true} {
		for _, fallbackConfigured := range []bool{false, true} {
			for _, fallbackEligible := range []bool{false, true} {
				decision, err := DecideTransition(TransitionInput{
					Condition:          AttemptConditionValidReview,
					RepairUsed:         repairUsed,
					FallbackConfigured: fallbackConfigured,
					FallbackEligible:   fallbackEligible,
				})
				if err != nil {
					t.Fatalf("DecideTransition(valid review): %v", err)
				}
				if decision.ScheduleRepair() || decision.ScheduleFallback() || decision.CancelRun() {
					t.Fatalf("valid review with repair=%t configured=%t eligible=%t scheduled work: %+v", repairUsed, fallbackConfigured, fallbackEligible, decision)
				}
				if decision.TerminalProjection() != TerminalProjectionSucceeded || decision.TerminalClass() != "" {
					t.Fatalf("valid review projection = %q/%q", decision.TerminalProjection(), decision.TerminalClass())
				}
			}
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
			for _, fallbackConfigured := range []bool{false, true} {
				for _, fallbackEligible := range []bool{false, true} {
					decision, err := DecideTransition(TransitionInput{
						Condition:          condition,
						RepairUsed:         repairUsed,
						FallbackConfigured: fallbackConfigured,
						FallbackEligible:   fallbackEligible,
					})
					if err != nil {
						t.Fatalf("DecideTransition(%q): %v", condition, err)
					}
					if !decision.CancelRun() || decision.ScheduleRepair() || decision.ScheduleFallback() {
						t.Fatalf("%q decision allowed new work: %+v", condition, decision)
					}
				}
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
			FallbackConfigured:   true,
			FallbackEligible:     true,
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

func TestSemanticContradictionUsesOnlyEligibleFallback(t *testing.T) {
	t.Parallel()

	for _, repairUsed := range []bool{false, true} {
		for _, fallbackConfigured := range []bool{false, true} {
			for _, fallbackEligible := range []bool{false, true} {
				input := TransitionInput{
					Condition:          AttemptConditionSemanticContradiction,
					RepairUsed:         repairUsed,
					FallbackConfigured: fallbackConfigured,
					FallbackEligible:   fallbackEligible,
				}
				decision, err := DecideTransition(input)
				if err != nil {
					t.Fatalf("DecideTransition(%+v): %v", input, err)
				}
				wantFallback := fallbackConfigured && fallbackEligible
				if decision.Condition() != AttemptConditionSemanticContradiction ||
					decision.ScheduleRepair() ||
					decision.ScheduleFallback() != wantFallback ||
					decision.CancelRun() ||
					decision.TerminalClass() != domain.FailureInvalidOutput ||
					decision.ReasonCode() != string(AttemptConditionSemanticContradiction) ||
					decision.Terminal() == wantFallback {
					t.Fatalf("semantic contradiction decision = %+v, fallback=%t", decision, wantFallback)
				}
			}
		}
	}
}

func TestUnknownAttemptConditionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, cancellationObserved := range []bool{false, true} {
		decision, err := DecideTransition(TransitionInput{
			Condition:            AttemptCondition("unknown"),
			FallbackConfigured:   true,
			FallbackEligible:     true,
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
		Condition:          AttemptConditionInvalidEvidenceClaim,
		RepairUsed:         true,
		FallbackConfigured: true,
		FallbackEligible:   true,
	}
	decision, err := DecideTransition(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Condition = AttemptConditionSecurityViolation
	input.RepairUsed = false
	input.FallbackConfigured = false
	input.FallbackEligible = false
	input.CancellationObserved = true

	if decision.Condition() != AttemptConditionInvalidEvidenceClaim ||
		decision.TerminalClass() != domain.FailureInvalidOutput ||
		decision.ReasonCode() != string(AttemptConditionInvalidEvidenceClaim) ||
		!decision.ScheduleFallback() ||
		decision.ScheduleRepair() ||
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
		AttemptConditionInvalidEvidenceClaim,
		AttemptConditionSemanticContradiction,
		AttemptConditionProviderUnavailable,
		AttemptConditionTimeout,
		AttemptConditionAuthentication,
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
	fallbackOnly  bool
	cancelsRun    bool
}

type expectedTransitionDecision struct {
	condition        AttemptCondition
	scheduleRepair   bool
	scheduleFallback bool
	cancelRun        bool
	terminalClass    domain.FailureClass
	projection       TerminalProjection
	reasonCode       string
}

func policyExpectations() []policyExpectation {
	return []policyExpectation{
		{condition: AttemptConditionValidReview, projection: TerminalProjectionSucceeded},
		{condition: AttemptConditionInvalidProviderOutput, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed, repairable: true},
		{condition: AttemptConditionInvalidEvidenceClaim, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed, repairable: true},
		{condition: AttemptConditionSemanticContradiction, terminalClass: domain.FailureInvalidOutput, projection: TerminalProjectionFailed, fallbackOnly: true},
		{condition: AttemptConditionProviderUnavailable, terminalClass: domain.FailureProviderUnavailable, projection: TerminalProjectionFailed, fallbackOnly: true},
		{condition: AttemptConditionTimeout, terminalClass: domain.FailureTimeout, projection: TerminalProjectionFailed, fallbackOnly: true},
		{condition: AttemptConditionAuthentication, terminalClass: domain.FailureAuthentication, projection: TerminalProjectionFailed, fallbackOnly: true},
		{condition: AttemptConditionQuota, terminalClass: domain.FailureQuota, projection: TerminalProjectionFailed, fallbackOnly: true},
		{condition: AttemptConditionRateLimit, terminalClass: domain.FailureRateLimit, projection: TerminalProjectionFailed, fallbackOnly: true},
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
	fallbackUsable := input.FallbackConfigured && input.FallbackEligible
	switch {
	case expectation.repairable && !input.RepairUsed:
		want.scheduleRepair = true
		want.projection = TerminalProjectionNone
	case expectation.repairable && fallbackUsable:
		want.scheduleFallback = true
		want.projection = TerminalProjectionNone
	case expectation.fallbackOnly && fallbackUsable:
		want.scheduleFallback = true
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
	case AttemptConditionSemanticContradiction,
		AttemptConditionInvalidEvidenceClaim,
		AttemptConditionInvalidProviderOutput:
		return 5
	case AttemptConditionAuthentication,
		AttemptConditionQuota,
		AttemptConditionRateLimit,
		AttemptConditionTimeout,
		AttemptConditionProviderUnavailable:
		return 6
	case AttemptConditionValidReview:
		return 7
	default:
		panic("unknown attempt condition")
	}
}

func assertDecision(t *testing.T, input TransitionInput, got TransitionDecision, want expectedTransitionDecision) {
	t.Helper()
	if got.Condition() != want.condition ||
		got.ScheduleRepair() != want.scheduleRepair ||
		got.ScheduleFallback() != want.scheduleFallback ||
		got.CancelRun() != want.cancelRun ||
		got.TerminalClass() != want.terminalClass ||
		got.TerminalProjection() != want.projection ||
		got.ReasonCode() != want.reasonCode {
		t.Fatalf("DecideTransition(%+v) = condition=%q repair=%t fallback=%t cancel=%t class=%q projection=%q reason=%q, want condition=%q repair=%t fallback=%t cancel=%t class=%q projection=%q reason=%q", input, got.Condition(), got.ScheduleRepair(), got.ScheduleFallback(), got.CancelRun(), got.TerminalClass(), got.TerminalProjection(), got.ReasonCode(), want.condition, want.scheduleRepair, want.scheduleFallback, want.cancelRun, want.terminalClass, want.projection, want.reasonCode)
	}
	if got.ScheduleRepair() && got.ScheduleFallback() {
		t.Fatalf("DecideTransition(%+v) scheduled repair and fallback", input)
	}
	if (got.ScheduleRepair() || got.ScheduleFallback()) != !got.Terminal() {
		t.Fatalf("DecideTransition(%+v) terminal=%t does not match scheduled work", input, got.Terminal())
	}
}
