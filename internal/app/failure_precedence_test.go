package app

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestFailurePrecedenceIsExactAndClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class domain.FailureClass
		want  int
	}{
		{domain.FailureInternal, 7},
		{domain.FailureSecurityPolicy, 6},
		{domain.FailureArtifact, 5},
		{domain.FailureCancelled, 4},
		{domain.FailureConfiguration, 3},
		{domain.FailureProviderUnavailable, 2},
		{domain.FailureTimeout, 2},
		{domain.FailureAuthentication, 2},
		{domain.FailureQuota, 2},
		{domain.FailureRateLimit, 2},
		{domain.FailureInvalidOutput, 1},
		{domain.FailureClass("unknown"), 0},
	}
	for _, test := range tests {
		if got := FailurePrecedence(test.class); got != test.want {
			t.Errorf("FailurePrecedence(%q) = %d, want %d", test.class, got, test.want)
		}
	}
}
