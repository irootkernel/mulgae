package childrun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAcceptFollowupOutputFailsClosedOnOwnershipViolation(t *testing.T) {
	t.Parallel()

	t.Run("initial ownership violation returns security_policy_violation", func(t *testing.T) {
		t.Parallel()
		primary := followupOwnershipDocument(t, func(document map[string]any) {
			document["session_id"] = "s_00000000-0000-7000-8000-000000000000"
		})
		executor, execution, run, attemptID, scope := followupPrimaryReportFixture(t, nil, nil)
		observations := []ports.ProviderExecutionObservation{}
		runtimes := []publication.FollowupRuntimeArtifactInput{}
		drops := []childDiagnosticObservation{}
		validated, repaired, _, err := executor.acceptFollowupOutput(
			context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
			scope, primary, &observations, &runtimes, &drops,
		)
		assertFollowupOwnershipSecurityFailure(t, err, validated)
		if repaired {
			t.Fatal("initial ownership violation unexpectedly entered repair")
		}
		if len(observations) != 0 {
			t.Fatalf("ownership violation observations = %d, want 0 (no repair)", len(observations))
		}
	})

	t.Run("repair ownership violation returns security_policy_violation", func(t *testing.T) {
		t.Parallel()
		primary := followupOwnershipDocument(t, func(document map[string]any) {
			delete(document, "summary")
		})
		repairOwned := followupOwnershipDocument(t, func(document map[string]any) {
			document["provider"] = "spoof"
		})
		executor, execution, run, attemptID, scope := followupPrimaryReportFixture(t, [][]byte{repairOwned}, nil)
		observations := []ports.ProviderExecutionObservation{}
		runtimes := []publication.FollowupRuntimeArtifactInput{}
		drops := []childDiagnosticObservation{}
		validated, repaired, _, err := executor.acceptFollowupOutput(
			context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
			scope, primary, &observations, &runtimes, &drops,
		)
		assertFollowupOwnershipSecurityFailure(t, err, validated)
		if !repaired {
			t.Fatal("repair ownership path did not attempt repair before failing closed")
		}
		if len(observations) != 1 {
			t.Fatalf("repair ownership observations = %d, want 1", len(observations))
		}
	})
}

func assertFollowupOwnershipSecurityFailure(t *testing.T, err error, validated validation.ValidatedFollowup) {
	t.Helper()
	if err == nil {
		t.Fatal("ownership violation unexpectedly succeeded")
	}
	if validated.ReportsOnly() || validated.Resolution().Valid() {
		t.Fatalf("ownership violation published reportsOnly=%t resolution=%q", validated.ReportsOnly(), validated.Resolution())
	}
	failures, ok := reviewrun.ProviderExecutionFailuresFromError(err)
	if !ok || len(failures) != 1 {
		t.Fatalf("provider failures = %#v present=%t", failures, ok)
	}
	if failures[0].ReasonCode() != string(review.AttemptConditionSecurityViolation) ||
		failures[0].FailureClass() != domain.FailureSecurityPolicy {
		t.Fatalf("provider failure = reason %q class %q", failures[0].ReasonCode(), failures[0].FailureClass())
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy {
		t.Fatalf("typed failure class = %#v", failure)
	}
}

func followupOwnershipDocument(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	document := map[string]any{
		"schema_version": "mulgae-provider-followup-output.v1",
		"summary":        "F001 remains open.",
		"resolution":     "still_open",
		"rationale":      "The current target preserves the source finding.",
		"evidence": []any{map[string]any{"current": map[string]any{
			"path": "a.go", "line_start": 1, "line_end": 1, "side": "head", "quote": "return nil",
		}}},
		"new_findings": []any{},
		"limitations":  []any{},
	}
	if mutate != nil {
		mutate(document)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
