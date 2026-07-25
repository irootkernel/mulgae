package reviewrun

import (
	"errors"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestQualificationTerminalCauseUsesExactSingleCause(t *testing.T) {
	cause, err := domain.NewFailure(
		"capability",
		domain.FailureInvalidOutput,
		"invalid output",
		currentQualifierDiagnosticError{cause: domain.DiagnosticCauseOutputDecodeFailed, err: errors.New("decode")},
	)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := NewProviderQualificationFailure("kimi-default", FamilyKimi, string(domain.FailureInvalidOutput), cause)
	if err != nil {
		t.Fatal(err)
	}
	aggregate := NewProviderQualificationFailuresError([]ProviderQualificationFailure{failure})
	if got := qualificationTerminalCause(aggregate); got != domain.DiagnosticCauseOutputDecodeFailed {
		t.Fatalf("terminal cause = %q, want %q", got, domain.DiagnosticCauseOutputDecodeFailed)
	}
}

func TestQualificationTerminalCausePreservesTransportLifecycleSubtype(t *testing.T) {
	for _, want := range []domain.RuntimeDiagnosticCause{
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
	} {
		t.Run(string(want), func(t *testing.T) {
			cause, err := domain.NewFailure(
				"capability",
				domain.FailureSecurityPolicy,
				"provider transport or lifecycle evidence mismatch",
				currentQualifierDiagnosticError{cause: want, err: errors.New("closed local detail")},
			)
			if err != nil {
				t.Fatal(err)
			}
			observation := rejectedQualificationObservation("agy-default", cause, false)
			aggregate := withQualificationObservations(cause, []ProviderQualificationObservation{observation})
			if got := qualificationTerminalCause(aggregate); got != want {
				t.Fatalf("terminal cause = %q, want %q", got, want)
			}
		})
	}
}

func TestQualificationTerminalCauseCollapsesDifferentCauses(t *testing.T) {
	newFailure := func(provider string, family Family, cause domain.RuntimeDiagnosticCause) ProviderQualificationFailure {
		t.Helper()
		typed, err := domain.NewFailure(
			"capability",
			domain.FailureInvalidOutput,
			"invalid output",
			currentQualifierDiagnosticError{cause: cause, err: errors.New("provider output")},
		)
		if err != nil {
			t.Fatal(err)
		}
		failure, err := NewProviderQualificationFailure(provider, family, string(domain.FailureInvalidOutput), typed)
		if err != nil {
			t.Fatal(err)
		}
		return failure
	}
	aggregate := NewProviderQualificationFailuresError([]ProviderQualificationFailure{
		newFailure("kimi-default", FamilyKimi, domain.DiagnosticCauseOutputFrameMissing),
		newFailure("zcode-default", FamilyZCode, domain.DiagnosticCauseOutputEnvelopeInvalid),
	})
	if got := qualificationTerminalCause(aggregate); got != domain.DiagnosticCauseObservationInvalid {
		t.Fatalf("terminal cause = %q, want %q", got, domain.DiagnosticCauseObservationInvalid)
	}
}
