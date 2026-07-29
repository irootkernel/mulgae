package domain

import (
	"fmt"
	"strings"
)

type FailureClass string

const (
	FailureProviderUnavailable FailureClass = "provider_unavailable"
	FailureInvalidOutput       FailureClass = "invalid_provider_output"
	FailureTimeout             FailureClass = "timeout"
	FailureAuthentication      FailureClass = "auth"
	FailureQuota               FailureClass = "quota"
	FailureRateLimit           FailureClass = "rate_limit"
	FailureSecurityPolicy      FailureClass = "security_policy_violation"
	FailureConfiguration       FailureClass = "configuration_violation"
	FailureArtifact            FailureClass = "artifact_failure"
	FailureInternal            FailureClass = "mulgae_internal_error"
	FailureCancelled           FailureClass = "user_cancelled"
)

func (class FailureClass) Valid() bool {
	return oneOf(string(class),
		string(FailureProviderUnavailable), string(FailureInvalidOutput), string(FailureTimeout),
		string(FailureAuthentication), string(FailureQuota), string(FailureRateLimit),
		string(FailureSecurityPolicy), string(FailureConfiguration), string(FailureArtifact),
		string(FailureInternal), string(FailureCancelled),
	)
}

// Failure is an immutable typed failure. Policy depends on Class, never on
// human-readable Reason or an underlying error string.
type Failure struct {
	stage  string
	class  FailureClass
	reason string
	cause  error
}

func NewFailure(stage string, class FailureClass, reason string, cause error) (*Failure, error) {
	if strings.TrimSpace(stage) == "" {
		return nil, fmt.Errorf("typed failure: %w: stage must be non-empty", ErrInvariant)
	}
	if !class.Valid() {
		return nil, fmt.Errorf("typed failure: %w: unknown class %q", ErrInvariant, class)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("typed failure: %w: reason must be non-empty", ErrInvariant)
	}
	return &Failure{stage: stage, class: class, reason: reason, cause: cause}, nil
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s: %s", failure.stage, failure.class, failure.reason)
}

func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *Failure) Stage() string {
	if failure == nil {
		return ""
	}
	return failure.stage
}

func (failure *Failure) Class() FailureClass {
	if failure == nil {
		return ""
	}
	return failure.class
}

func (failure *Failure) Reason() string {
	if failure == nil {
		return ""
	}
	return failure.reason
}

func (class FailureClass) RepairAllowed() bool {
	return class == FailureInvalidOutput
}

func (class FailureClass) FallbackAllowed() bool {
	switch class {
	case FailureProviderUnavailable, FailureInvalidOutput, FailureTimeout,
		FailureAuthentication, FailureQuota, FailureRateLimit:
		return true
	default:
		return false
	}
}
