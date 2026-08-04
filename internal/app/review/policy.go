package review

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

// AttemptCondition is the closed coordinator input classification for a
// completed review attempt. Workers and adapters report facts; only the
// coordinator turns those facts into a transition decision.
type AttemptCondition string

const (
	AttemptConditionValidReview                AttemptCondition = "valid_review"
	AttemptConditionInvalidProviderOutput      AttemptCondition = "invalid_provider_output"
	AttemptConditionUnrepairableProviderOutput AttemptCondition = "unrepairable_provider_output"
	AttemptConditionInvalidEvidenceClaim       AttemptCondition = "invalid_evidence_claim"
	AttemptConditionUnrepairableEvidence       AttemptCondition = "unrepairable_evidence_claim"
	AttemptConditionSemanticContradiction      AttemptCondition = "semantic_contradiction"
	AttemptConditionProviderUnavailable        AttemptCondition = "provider_unavailable"
	AttemptConditionTimeout                    AttemptCondition = "timeout"
	AttemptConditionAuthentication             AttemptCondition = "auth"
	AttemptConditionLoginRequired              AttemptCondition = "login_required"
	AttemptConditionQuota                      AttemptCondition = "quota"
	AttemptConditionRateLimit                  AttemptCondition = "rate_limit"
	AttemptConditionSecurityViolation          AttemptCondition = "security_violation"
	AttemptConditionMutationViolation          AttemptCondition = "mutation_violation"
	AttemptConditionConfigurationViolation     AttemptCondition = "configuration_violation"
	AttemptConditionArtifactFailure            AttemptCondition = "artifact_failure"
	AttemptConditionCancelled                  AttemptCondition = "cancelled"
	AttemptConditionInternalInvariant          AttemptCondition = "internal_invariant"
	AttemptConditionProviderPermissionDenied   AttemptCondition = "provider_permission_denied"
	AttemptConditionProviderTimeout            AttemptCondition = "provider_timeout"
	AttemptConditionProviderOutputMissing      AttemptCondition = "provider_output_missing"
	AttemptConditionProviderOutputDecodeFailed AttemptCondition = "provider_output_decode_failed"
)

// TerminalProjection is the terminal role projection selected when this
// decision does not schedule more work. None means that repair or fallback was
// selected and the coordinator must await that result.
type TerminalProjection string

const (
	TerminalProjectionNone      TerminalProjection = ""
	TerminalProjectionSucceeded TerminalProjection = "succeeded"
	TerminalProjectionFailed    TerminalProjection = "failed"
	TerminalProjectionCancelled TerminalProjection = "cancelled"
)

// Valid reports whether projection is a policy-defined terminal projection.
func (projection TerminalProjection) Valid() bool {
	return projection == TerminalProjectionNone ||
		projection == TerminalProjectionSucceeded ||
		projection == TerminalProjectionFailed ||
		projection == TerminalProjectionCancelled
}

// TransitionInput contains the facts the coordinator needs to make one policy
// decision. Fallback is usable only when it is both configured and eligible.
type TransitionInput struct {
	Condition            AttemptCondition
	RepairUsed           bool
	FallbackConfigured   bool
	FallbackEligible     bool
	CancellationObserved bool
}

// TransitionDecision is an immutable coordinator-owned result. It contains no
// references and exposes its facts only through value-returning accessors.
type TransitionDecision struct {
	condition          AttemptCondition
	scheduleRepair     bool
	scheduleFallback   bool
	cancelRun          bool
	terminalClass      domain.FailureClass
	terminalProjection TerminalProjection
	reasonCode         string
}

// Condition returns the effective condition selected by closed precedence
// reduction, including an observed cancellation when it takes precedence.
func (decision TransitionDecision) Condition() AttemptCondition { return decision.condition }

// ScheduleRepair reports whether the coordinator must schedule the one allowed
// repair invocation.
func (decision TransitionDecision) ScheduleRepair() bool { return decision.scheduleRepair }

// ScheduleFallback reports whether the coordinator may schedule a configured,
// eligible fallback attempt.
func (decision TransitionDecision) ScheduleFallback() bool { return decision.scheduleFallback }

// CancelRun reports whether the coordinator must cancel the run and prevent
// further work.
func (decision TransitionDecision) CancelRun() bool { return decision.cancelRun }

// TerminalClass returns the domain failure class for the effective condition.
// It is empty only for a valid review.
func (decision TransitionDecision) TerminalClass() domain.FailureClass { return decision.terminalClass }

// TerminalProjection returns the selected terminal role projection. It is None
// while the decision schedules repair or fallback work.
func (decision TransitionDecision) TerminalProjection() TerminalProjection {
	return decision.terminalProjection
}

// Terminal reports whether the decision closes this role rather than scheduling
// repair or fallback work.
func (decision TransitionDecision) Terminal() bool {
	return decision.terminalProjection != TerminalProjectionNone
}

// ReasonCode returns the stable condition-specific reason code. In particular,
// invalid evidence claims retain invalid_evidence_claim even though their
// terminal class is invalid_provider_output.
func (decision TransitionDecision) ReasonCode() string { return decision.reasonCode }

type transitionAction uint8

const (
	transitionActionValid transitionAction = iota
	transitionActionRepairBeforeFallback
	transitionActionFallbackOnly
	transitionActionFailClosed
	transitionActionCancelRun
)

type conditionPrecedence uint8

const (
	conditionPrecedenceInternal conditionPrecedence = iota
	conditionPrecedenceArtifact
	conditionPrecedenceSecurity
	conditionPrecedenceCancellation
	conditionPrecedenceConfiguration
	conditionPrecedenceLoginRequired
	conditionPrecedenceInvalidOutput
	conditionPrecedenceProviderFailure
	conditionPrecedenceValid
)

type transitionPolicyRow struct {
	condition          AttemptCondition
	terminalClass      domain.FailureClass
	terminalProjection TerminalProjection
	action             transitionAction
	reasonCode         string
	precedence         conditionPrecedence
}

var transitionPolicyRows = [...]transitionPolicyRow{
	{
		condition:          AttemptConditionValidReview,
		precedence:         conditionPrecedenceValid,
		terminalProjection: TerminalProjectionSucceeded,
		action:             transitionActionValid,
		reasonCode:         string(AttemptConditionValidReview),
	},
	{
		condition:          AttemptConditionInvalidProviderOutput,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionRepairBeforeFallback,
		reasonCode:         string(AttemptConditionInvalidProviderOutput),
	},
	{
		condition:          AttemptConditionUnrepairableProviderOutput,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionUnrepairableProviderOutput),
	},
	{
		condition:          AttemptConditionProviderOutputMissing,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionProviderOutputMissing),
	},
	{
		condition:          AttemptConditionProviderOutputDecodeFailed,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionProviderOutputDecodeFailed),
	},
	{
		condition:          AttemptConditionInvalidEvidenceClaim,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionRepairBeforeFallback,
		reasonCode:         string(AttemptConditionInvalidEvidenceClaim),
	},
	{
		condition:          AttemptConditionUnrepairableEvidence,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionUnrepairableEvidence),
	},
	{
		condition:          AttemptConditionSemanticContradiction,
		precedence:         conditionPrecedenceInvalidOutput,
		terminalClass:      domain.FailureInvalidOutput,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionSemanticContradiction),
	},
	{
		condition:          AttemptConditionProviderUnavailable,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureProviderUnavailable,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionProviderUnavailable),
	},
	{
		condition:          AttemptConditionTimeout,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureTimeout,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionTimeout),
	},
	{
		condition:          AttemptConditionProviderTimeout,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureTimeout,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionProviderTimeout),
	},
	{
		condition:          AttemptConditionAuthentication,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureAuthentication,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionAuthentication),
	},
	{
		condition:          AttemptConditionProviderPermissionDenied,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureAuthentication,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionProviderPermissionDenied),
	},
	{
		condition:          AttemptConditionLoginRequired,
		precedence:         conditionPrecedenceLoginRequired,
		terminalClass:      domain.FailureAuthentication,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFailClosed,
		reasonCode:         string(AttemptConditionLoginRequired),
	},
	{
		condition:          AttemptConditionQuota,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureQuota,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionQuota),
	},
	{
		condition:          AttemptConditionRateLimit,
		precedence:         conditionPrecedenceProviderFailure,
		terminalClass:      domain.FailureRateLimit,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFallbackOnly,
		reasonCode:         string(AttemptConditionRateLimit),
	},
	{
		condition:          AttemptConditionSecurityViolation,
		precedence:         conditionPrecedenceSecurity,
		terminalClass:      domain.FailureSecurityPolicy,
		terminalProjection: TerminalProjectionCancelled,
		action:             transitionActionCancelRun,
		reasonCode:         string(AttemptConditionSecurityViolation),
	},
	{
		condition:          AttemptConditionMutationViolation,
		precedence:         conditionPrecedenceSecurity,
		terminalClass:      domain.FailureSecurityPolicy,
		terminalProjection: TerminalProjectionCancelled,
		action:             transitionActionCancelRun,
		reasonCode:         string(AttemptConditionMutationViolation),
	},
	{
		condition:          AttemptConditionConfigurationViolation,
		precedence:         conditionPrecedenceConfiguration,
		terminalClass:      domain.FailureConfiguration,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFailClosed,
		reasonCode:         string(AttemptConditionConfigurationViolation),
	},
	{
		condition:          AttemptConditionArtifactFailure,
		precedence:         conditionPrecedenceArtifact,
		terminalClass:      domain.FailureArtifact,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFailClosed,
		reasonCode:         string(AttemptConditionArtifactFailure),
	},
	{
		condition:          AttemptConditionCancelled,
		precedence:         conditionPrecedenceCancellation,
		terminalClass:      domain.FailureCancelled,
		terminalProjection: TerminalProjectionCancelled,
		action:             transitionActionCancelRun,
		reasonCode:         string(AttemptConditionCancelled),
	},
	{
		condition:          AttemptConditionInternalInvariant,
		precedence:         conditionPrecedenceInternal,
		terminalClass:      domain.FailureInternal,
		terminalProjection: TerminalProjectionFailed,
		action:             transitionActionFailClosed,
		reasonCode:         string(AttemptConditionInternalInvariant),
	},
}

// AttemptConditions returns the complete closed condition set in policy order.
// The returned slice is caller-owned.
func AttemptConditions() []AttemptCondition {
	conditions := make([]AttemptCondition, len(transitionPolicyRows))
	for index, row := range transitionPolicyRows {
		conditions[index] = row.condition
	}
	return conditions
}

// Valid reports whether condition is part of the closed coordinator policy.
func (condition AttemptCondition) Valid() bool {
	_, ok := lookupTransitionPolicy(condition)
	return ok
}

// Validate rejects any condition outside the closed coordinator policy.
func (condition AttemptCondition) Validate() error {
	if condition.Valid() {
		return nil
	}
	return fmt.Errorf("review transition policy: %w: unknown attempt condition %q", domain.ErrInvariant, condition)
}

// ReduceAttemptConditions returns the highest-precedence condition from the
// closed policy set. Equal-precedence conditions retain their earliest input
// order so the originating reason remains stable.
func ReduceAttemptConditions(conditions ...AttemptCondition) (AttemptCondition, error) {
	if len(conditions) == 0 {
		return "", fmt.Errorf("review transition policy: %w: no attempt conditions to reduce", domain.ErrInvariant)
	}

	selected, ok := lookupTransitionPolicy(conditions[0])
	if !ok {
		return "", conditions[0].Validate()
	}
	for _, condition := range conditions[1:] {
		candidate, ok := lookupTransitionPolicy(condition)
		if !ok {
			return "", condition.Validate()
		}
		if candidate.precedence < selected.precedence {
			selected = candidate
		}
	}
	return selected.condition, nil
}

// DecideTransition applies the closed coordinator policy to immutable attempt
// facts. It has no scheduling, provider, publication, or other side effects.
func DecideTransition(input TransitionInput) (TransitionDecision, error) {
	conditions := []AttemptCondition{input.Condition}
	if input.CancellationObserved {
		conditions = append(conditions, AttemptConditionCancelled)
	}
	condition, err := ReduceAttemptConditions(conditions...)
	if err != nil {
		return TransitionDecision{}, err
	}
	row, ok := lookupTransitionPolicy(condition)
	if !ok {
		return TransitionDecision{}, fmt.Errorf("review transition policy: %w: reduced unknown condition %q", domain.ErrInvariant, condition)
	}

	decision := TransitionDecision{
		condition:          row.condition,
		terminalClass:      row.terminalClass,
		terminalProjection: row.terminalProjection,
		reasonCode:         row.reasonCode,
	}

	switch row.action {
	case transitionActionValid, transitionActionFailClosed:
	case transitionActionRepairBeforeFallback:
		if !input.RepairUsed {
			decision.scheduleRepair = true
			decision.terminalProjection = TerminalProjectionNone
		} else if fallbackUsable(input) {
			decision.scheduleFallback = true
			decision.terminalProjection = TerminalProjectionNone
		}
	case transitionActionFallbackOnly:
		if fallbackUsable(input) {
			decision.scheduleFallback = true
			decision.terminalProjection = TerminalProjectionNone
		}
	case transitionActionCancelRun:
		decision.cancelRun = true
	default:
		return TransitionDecision{}, fmt.Errorf("review transition policy: %w: unrecognized action for condition %q", domain.ErrInvariant, row.condition)
	}

	if err := decision.validate(); err != nil {
		return TransitionDecision{}, err
	}
	return decision, nil
}

func lookupTransitionPolicy(condition AttemptCondition) (transitionPolicyRow, bool) {
	for _, row := range transitionPolicyRows {
		if row.condition == condition {
			return row, true
		}
	}
	return transitionPolicyRow{}, false
}

func fallbackUsable(input TransitionInput) bool {
	return input.FallbackConfigured && input.FallbackEligible
}

func (decision TransitionDecision) validate() error {
	if decision.scheduleRepair && decision.scheduleFallback {
		return fmt.Errorf("review transition policy: %w: repair and fallback cannot both be scheduled", domain.ErrInvariant)
	}
	if (decision.scheduleRepair || decision.scheduleFallback) && decision.terminalProjection != TerminalProjectionNone {
		return fmt.Errorf("review transition policy: %w: scheduled work cannot have a terminal projection", domain.ErrInvariant)
	}
	if decision.cancelRun && (decision.scheduleRepair || decision.scheduleFallback) {
		return fmt.Errorf("review transition policy: %w: cancelled run cannot schedule work", domain.ErrInvariant)
	}
	if !decision.terminalProjection.Valid() {
		return fmt.Errorf("review transition policy: %w: invalid terminal projection %q", domain.ErrInvariant, decision.terminalProjection)
	}
	if decision.terminalProjection == TerminalProjectionSucceeded {
		if decision.terminalClass != "" || decision.reasonCode != string(AttemptConditionValidReview) {
			return fmt.Errorf("review transition policy: %w: successful projection has failure facts", domain.ErrInvariant)
		}
		return nil
	}
	if decision.terminalClass == "" || !decision.terminalClass.Valid() {
		return fmt.Errorf("review transition policy: %w: failure projection has invalid failure class %q", domain.ErrInvariant, decision.terminalClass)
	}
	if decision.reasonCode == "" {
		return fmt.Errorf("review transition policy: %w: reason code is required", domain.ErrInvariant)
	}
	return nil
}
