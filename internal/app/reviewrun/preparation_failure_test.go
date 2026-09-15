package reviewrun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestReviewPreparationFailureClassificationIsClosedAndRedacted(t *testing.T) {
	t.Parallel()

	private := errors.New("/Users/private/.codex/auth.json")
	tests := []struct {
		stage ReviewPreparationStage
		cause domain.RuntimeDiagnosticCause
	}{
		{ReviewPreparationPromptSource, domain.DiagnosticCauseReviewPromptSourcePreparationFailed},
		{ReviewPreparationProviderRuntime, domain.DiagnosticCauseReviewProviderRuntimePreparationFailed},
		{ReviewPreparationProviderOutputStaging, domain.DiagnosticCauseReviewProviderOutputStagingPreparationFailed},
		{ReviewPreparationCoordinator, domain.DiagnosticCauseReviewCoordinatorPreparationFailed},
		{ReviewPreparationCoordinatorAdmission, domain.DiagnosticCauseReviewCoordinatorAdmissionPreparationFailed},
		{ReviewPreparationRootRun, domain.DiagnosticCauseReviewRootRunPreparationFailed},
	}
	for _, test := range tests {
		t.Run(string(test.stage), func(t *testing.T) {
			failure := NewReviewPreparationFailure(test.stage, private)
			stage, cause, ok := ReviewPreparationFailureFromError(failure)
			if !ok || stage != test.stage || cause != test.cause || !errors.Is(failure, private) {
				t.Fatalf("classification = (%q, %q, %t), err=%v", stage, cause, ok, failure)
			}
			if strings.Contains(failure.Error(), "private") || strings.Contains(failure.Error(), ".codex") {
				t.Fatalf("failure exposed causal detail: %q", failure)
			}
		})
	}

	invalid := NewReviewPreparationFailure("unknown", private)
	if _, _, ok := ReviewPreparationFailureFromError(invalid); ok {
		t.Fatal("invalid preparation classification was exposed")
	}
	if !errors.Is(invalid, private) {
		t.Fatal("invalid preparation classification discarded its cause")
	}
	if strings.Contains(invalid.Error(), "private") || strings.Contains(invalid.Error(), ".codex") {
		t.Fatalf("invalid preparation classification exposed its cause: %q", invalid)
	}
}

func TestReviewPreparationClassificationPreservesCausalTypedAndCancellationFailures(t *testing.T) {
	t.Parallel()

	typedFailures := make([]error, 0, 3)
	for _, class := range []domain.FailureClass{domain.FailureProviderUnavailable, domain.FailureArtifact, domain.FailureSecurityPolicy} {
		typed, err := domain.NewFailure("review.test", class, "typed failure", errors.New("injected"))
		if err != nil {
			t.Fatal(err)
		}
		typedFailures = append(typedFailures, typed)
	}
	for _, original := range append(typedFailures, context.Canceled, context.DeadlineExceeded) {
		classified := classifyReviewPreparationFailure(nil, nil, ReviewPreparationProviderRuntime, original)
		if !errors.Is(classified, original) {
			t.Fatalf("classified failure = %v, want original %v", classified, original)
		}
		if _, _, ok := ReviewPreparationFailureFromError(classified); ok {
			t.Fatalf("typed failure was reclassified: %v", classified)
		}
		wrapped := NewReviewPreparationFailure(ReviewPreparationProviderRuntime, original)
		if _, _, ok := ReviewPreparationFailureFromError(wrapped); ok {
			t.Fatalf("typed causal failure was reclassified: %v", wrapped)
		}
	}
}

func TestReviewPreparationClassificationIgnoresIndependentJoinedFailures(t *testing.T) {
	t.Parallel()

	preparation := NewReviewPreparationFailure(ReviewPreparationProviderRuntime, errors.New("private"))
	typed, err := domain.NewFailure("review.composition", domain.FailureArtifact, "temporary root cleanup failed", errors.New("injected"))
	if err != nil {
		t.Fatal(err)
	}
	for _, competing := range []error{
		typed,
		&terminalDrainCleanupError{cause: context.DeadlineExceeded},
	} {
		stage, cause, ok := ReviewPreparationFailureFromError(errors.Join(preparation, competing))
		if !ok || stage != ReviewPreparationProviderRuntime || cause != domain.DiagnosticCauseReviewProviderRuntimePreparationFailed {
			t.Fatalf("independent failure suppressed preparation classification: (%q, %q, %t), competing=%v", stage, cause, ok, competing)
		}
	}
}

func TestReviewPreparationClassificationDefersToDiagnosticPersistenceFailure(t *testing.T) {
	t.Parallel()

	preparation := NewReviewPreparationFailure(ReviewPreparationProviderRuntime, errors.New("private"))
	persistence := diagnosticArtifactFailure("reviewrun.diagnostics.emit", errors.New("injected"))
	if _, _, ok := ReviewPreparationFailureFromError(errors.Join(preparation, persistence)); ok {
		t.Fatal("preparation failure outranked diagnostic persistence failure")
	}
}
