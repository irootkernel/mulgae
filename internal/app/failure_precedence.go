package app

import "github.com/irootkernel/kkachi-agent-review/internal/domain"

// FailurePrecedence returns the canonical operational precedence for a failure
// class. Higher values win when independent failures are observed together.
func FailurePrecedence(class domain.FailureClass) int {
	switch class {
	case domain.FailureInternal:
		return 7
	case domain.FailureSecurityPolicy:
		return 6
	case domain.FailureArtifact:
		return 5
	case domain.FailureCancelled:
		return 4
	case domain.FailureConfiguration:
		return 3
	case domain.FailureProviderUnavailable,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit:
		return 2
	case domain.FailureInvalidOutput:
		return 1
	default:
		return 0
	}
}
