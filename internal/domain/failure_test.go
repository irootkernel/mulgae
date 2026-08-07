package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestFailurePolicyIsClassBased(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class    FailureClass
		fallback bool
		repair   bool
	}{
		{FailureProviderUnavailable, true, false},
		{FailureInvalidOutput, true, true},
		{FailureTimeout, true, false},
		{FailureAuthentication, true, false},
		{FailureQuota, true, false},
		{FailureRateLimit, true, false},
		{FailureSecurityPolicy, false, false},
		{FailureConfiguration, false, false},
		{FailureArtifact, false, false},
		{FailureInternal, false, false},
		{FailureCancelled, false, false},
	}
	for _, test := range tests {
		if !test.class.Valid() {
			t.Errorf("%q is not a valid failure class", test.class)
		}
		if got := test.class.ProviderFault(); got != test.fallback {
			t.Errorf("%q fallback = %v, want %v", test.class, got, test.fallback)
		}
		if got := test.class.RepairAllowed(); got != test.repair {
			t.Errorf("%q repair = %v, want %v", test.class, got, test.repair)
		}
		if _, err := NewFailure("stage", test.class, "reason", nil); err != nil {
			t.Errorf("NewFailure for %q: %v", test.class, err)
		}
	}
	if FailureClass("unknown").Valid() || FailureClass("unknown").ProviderFault() || FailureClass("unknown").RepairAllowed() {
		t.Error("unknown failure class acquired policy")
	}
}

func TestFailureSupportsErrorsAsAndUnwrap(t *testing.T) {
	t.Parallel()

	cause := fmt.Errorf("transport closed")
	failure, err := NewFailure("provider.execute", FailureProviderUnavailable, "provider unavailable", cause)
	if err != nil {
		t.Fatal(err)
	}
	var typed *Failure
	if !errors.As(failure, &typed) {
		t.Fatal("errors.As did not expose typed failure")
	}
	if !errors.Is(failure, cause) {
		t.Fatal("underlying cause was not preserved")
	}
	if typed.Stage() != "provider.execute" || typed.Class() != FailureProviderUnavailable {
		t.Fatalf("typed fields = %q/%q", typed.Stage(), typed.Class())
	}
}

func TestNewFailureRejectsIncompleteClassification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		stage  string
		class  FailureClass
		reason string
	}{
		{"", FailureTimeout, "timed out"},
		{"provider", "unknown", "failed"},
		{"provider", FailureTimeout, ""},
	}
	for _, test := range cases {
		_, err := NewFailure(test.stage, test.class, test.reason, nil)
		if err == nil {
			t.Errorf("NewFailure(%q, %q, %q) succeeded", test.stage, test.class, test.reason)
			continue
		}
		if !errors.Is(err, ErrInvariant) {
			t.Errorf("NewFailure(%q, %q, %q) error = %v, want invariant", test.stage, test.class, test.reason, err)
		}
	}
}
