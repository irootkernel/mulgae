package childrun

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAcceptFollowupOutputDiscardsUnownedFields(t *testing.T) {
	t.Parallel()

	t.Run("initial unowned field is discarded", func(t *testing.T) {
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
		if err != nil || !reflect.DeepEqual(validated.DiscardedPaths(), []string{"/session_id"}) {
			t.Fatalf("initial projection paths=%v err=%v", validated.DiscardedPaths(), err)
		}
		if repaired {
			t.Fatal("initial ownership violation unexpectedly entered repair")
		}
		if len(observations) != 0 {
			t.Fatalf("initial projection observations = %d, want 0", len(observations))
		}
	})

	t.Run("repair unowned field is discarded", func(t *testing.T) {
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
		if err != nil || !reflect.DeepEqual(validated.DiscardedPaths(), []string{"/provider"}) {
			t.Fatalf("repair projection paths=%v err=%v", validated.DiscardedPaths(), err)
		}
		if !repaired {
			t.Fatal("repair ownership path did not attempt repair before failing closed")
		}
		if len(observations) != 1 {
			t.Fatalf("repair ownership observations = %d, want 1", len(observations))
		}
	})
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
