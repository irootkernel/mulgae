package query

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func readRecoveryExample(t *testing.T, name string, value any) {
	t.Helper()
	raw, err := os.ReadFile("../../builtin/assets/examples/" + name + ".v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCompositeExamplesShareCompleteSourceInventory(t *testing.T) {
	var final compositeFinalDTO
	var manifest compositeManifestDTO
	readRecoveryExample(t, "composite-review-artifact", &final)
	readRecoveryExample(t, "composite-run-manifest", &manifest)
	if !reflect.DeepEqual(final.ReviewComposition, manifest.ReviewComposition) {
		t.Fatal("paired composite examples disagree on their source inventory")
	}
	if err := validateCompositeSourceReferences(final, manifest); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRerunExamplesBindOneRole(t *testing.T) {
	var final finalDTO
	var manifest manifestDTO
	readRecoveryExample(t, "review-artifact", &final)
	readRecoveryExample(t, "run-manifest", &manifest)
	if len(final.RoleOutcomes) != 1 || len(manifest.SelectedRoles) != 1 || len(manifest.RequiredRoles) != 1 || len(manifest.Attempts) != 1 {
		t.Fatal("rerun examples must retain exactly one role and attempt")
	}
	roles, _, err := buildRolesForRun(final.RoleOutcomes, domain.RunTypeRerun, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifestRoleAttemptBindings(manifest.Attempts, roles); err != nil {
		t.Fatal(err)
	}
	if final.CoverageStatus != "complete" || manifest.CoverageStatus != "complete" || len(manifest.Failures) != 0 || len(final.Limitations) != 0 {
		t.Fatal("successful single-role rerun retained failed-role state")
	}
	if !reflect.DeepEqual(final.CIReasonCodes, manifest.CIReasonCodes) || !reflect.DeepEqual(final.CIReasonCodes, []string{"request_changes_threshold"}) {
		t.Fatal("rerun CI reasons do not match its findings and complete coverage")
	}
}
