//go:build darwin && arm64

package composition

import (
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestHeartbeatFailureClassification(t *testing.T) {
	tests := []struct {
		class      domain.FailureClass
		wantStatus string
		wantReason string
	}{
		{domain.FailureAuthentication, "authentication_failure", "authentication_required"},
		{domain.FailureTimeout, "timeout", "provider_timeout"},
		{domain.FailureInvalidOutput, "malformed_response", "heartbeat_response_malformed"},
		{domain.FailureProviderUnavailable, "provider_failure", "provider_failure"},
		{domain.FailureQuota, "provider_failure", "provider_failure"},
		{domain.FailureRateLimit, "provider_failure", "provider_failure"},
		{domain.FailureInternal, "execution_failure", "provider_execution_failed"},
	}
	for _, test := range tests {
		failure, err := domain.NewFailure("reviewrun.qualification", test.class, "heartbeat failure", errors.New("redacted"))
		if err != nil {
			t.Fatal(err)
		}
		status, reason := heartbeatFailure(failure)
		if status != test.wantStatus || reason != test.wantReason {
			t.Errorf("class %q = %q/%q, want %q/%q", test.class, status, reason, test.wantStatus, test.wantReason)
		}
	}
}

func TestHeartbeatAttemptedRemainsFalseForPreRequestVersionRejection(t *testing.T) {
	versionFailure, err := domain.NewFailure("reviewrun.qualification", domain.FailureConfiguration, "provider version is incompatible", nil)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeatLiveAttempted(versionFailure) {
		t.Fatal("version rejection was reported as a live request attempt")
	}
	capabilityFailure, err := domain.NewFailure("reviewrun.qualification", domain.FailureInvalidOutput, "capability response invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !heartbeatLiveAttempted(capabilityFailure) {
		t.Fatal("capability failure omitted the live request attempt")
	}
}
