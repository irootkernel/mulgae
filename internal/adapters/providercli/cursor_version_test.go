package providercli

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPlainSemverAcceptsCursorDateCommitForm(t *testing.T) {
	const installed = "2026.10.14-0f9edde"
	observation := testProcessObservation(t, []byte(installed+"\n"), nil, ports.ProcessTerminationExited, 0)
	got, err := plainSemver(FamilyCursor, observation)
	if err != nil || got != installed {
		t.Fatalf("Cursor version = %q, %v", got, err)
	}
	if !acceptedObservedVersion(FamilyCursor, installed) {
		t.Fatal("Cursor date/commit form was rejected")
	}
	for _, family := range []string{FamilyZcode, FamilyGrok, FamilyCodex} {
		if family == FamilyGrok {
			if _, err := plainSemver(family, observation); err == nil {
				t.Fatalf("%s accepted Cursor version output", family)
			}
		}
		if acceptedObservedVersion(family, "not-a-version") {
			t.Fatalf("%s accepted an invalid version", family)
		}
	}
	for _, invalid := range []string{"1.2.3", "2026.10.14", "2026.10.14-0F9EDDE", "v2026.10.14-0f9edde"} {
		candidate := testProcessObservation(t, []byte(invalid+"\n"), nil, ports.ProcessTerminationExited, 0)
		if _, err := plainSemver(FamilyCursor, candidate); err == nil {
			t.Fatalf("Cursor accepted %q", invalid)
		}
	}
	if !acceptedObservedVersion(FamilyGrok, "1.0.30") || !acceptedObservedVersion(FamilyCodex, "0.147.0") || !acceptedObservedVersion(FamilyZcode, "1.2.3") {
		t.Fatal("existing family semver acceptance changed")
	}
}
