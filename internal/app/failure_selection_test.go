package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

type selectionEmptyJoin struct{}

func (selectionEmptyJoin) Error() string   { return "empty join" }
func (selectionEmptyJoin) Unwrap() []error { return nil }

type selectionNilWrapper struct{}

func (selectionNilWrapper) Error() string { return "nil wrapper" }
func (selectionNilWrapper) Unwrap() error { return nil }

func TestFailureSelectionCompatibility(t *testing.T) {
	// Independent literal oracle. Do not derive expected ranks from the selector.
	ranks := []struct {
		class domain.FailureClass
		rank  int
	}{
		{domain.FailureInternal, 7}, {domain.FailureSecurityPolicy, 6}, {domain.FailureArtifact, 5},
		{domain.FailureCancelled, 4}, {domain.FailureConfiguration, 3},
		{domain.FailureProviderUnavailable, 2}, {domain.FailureTimeout, 2}, {domain.FailureAuthentication, 2},
		{domain.FailureQuota, 2}, {domain.FailureRateLimit, 2}, {domain.FailureInvalidOutput, 1},
	}
	failure := func(class domain.FailureClass, cause error) *domain.Failure {
		v, err := domain.NewFailure("test.selection", class, "private cause", cause)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, mode := range []FailureSelectionMode{FailureTypedOnly, FailureCLIRawFallback} {
		for _, first := range ranks {
			for _, second := range ranks {
				a, b := failure(first.class, nil), failure(second.class, nil)
				want := a
				if second.rank > first.rank {
					want = b
				}
				got, ok := SelectFailure(errors.Join(fmt.Errorf("first: %w", a), errors.Join(b)), mode, domain.FailureInvalidOutput)
				if !ok || got.Class != want.Class() || got.Cause != want {
					t.Fatalf("mode=%d pair=%s/%s got=%+v want=%v", mode, first.class, second.class, got, want)
				}
			}
		}
	}
	raw := errors.New("raw observation")
	typed := failure(domain.FailureConfiguration, fmt.Errorf("single: %w", raw))
	joined := failure(domain.FailureConfiguration, fmt.Errorf("nested: %w", errors.Join(raw, context.Canceled)))
	cancellation := fmt.Errorf("cancelled: %w", context.Canceled)
	for _, test := range []struct {
		name    string
		err     error
		mode    FailureSelectionMode
		want    domain.FailureClass
		cause   error
		present bool
	}{
		{"nil typed", nil, FailureTypedOnly, "", nil, false},
		{"nil CLI", nil, FailureCLIRawFallback, domain.FailureArtifact, nil, true},
		{"raw typed", raw, FailureTypedOnly, "", nil, false},
		{"raw CLI", raw, FailureCLIRawFallback, domain.FailureArtifact, raw, true},
		{"typed raw suppressed", typed, FailureCLIRawFallback, domain.FailureConfiguration, typed, true},
		{"typed raw ignored", typed, FailureTypedOnly, domain.FailureConfiguration, typed, true},
		{"joined raw independent", joined, FailureCLIRawFallback, domain.FailureArtifact, raw, true},
		{"typed-only joined cancellation", joined, FailureTypedOnly, domain.FailureCancelled, context.Canceled, true},
		{"wrapped cancellation", cancellation, FailureTypedOnly, domain.FailureCancelled, context.Canceled, true},
		{"deadline", context.DeadlineExceeded, FailureCLIRawFallback, domain.FailureCancelled, context.DeadlineExceeded, true},
		{"empty join typed", selectionEmptyJoin{}, FailureTypedOnly, "", nil, false},
		{"empty join CLI", selectionEmptyJoin{}, FailureCLIRawFallback, domain.FailureArtifact, selectionEmptyJoin{}, true},
		{"nil wrapper typed", selectionNilWrapper{}, FailureTypedOnly, "", nil, false},
		{"nil wrapper CLI", selectionNilWrapper{}, FailureCLIRawFallback, domain.FailureArtifact, selectionNilWrapper{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := SelectFailure(test.err, test.mode, domain.FailureArtifact)
			if ok != test.present || got.Class != test.want || got.Cause != test.cause {
				t.Fatalf("got=%+v present=%t want=%s cause=%v present=%t", got, ok, test.want, test.cause, test.present)
			}
		})
	}
	parent := failure(domain.FailureInternal, failure(domain.FailureInternal, raw))
	got, _ := SelectFailure(parent, FailureTypedOnly, domain.FailureArtifact)
	if got.Cause != parent {
		t.Fatal("parent-first equal-rank observation lost")
	}
}
