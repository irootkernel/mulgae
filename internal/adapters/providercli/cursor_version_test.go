package providercli

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCursorProbeArgvKeepsVersionSeparateFromACP(t *testing.T) {
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinition(FamilyCursor, "cursor_logic", "", executable, "", "cursor_logic", []string{executable}, nil, "/private/var/empty", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	version, err := (NativeProbeInvocation{}).VersionArgv(definition)
	if err != nil || !reflect.DeepEqual(version, []string{executable, "--version"}) {
		t.Fatalf("version argv = %#v, %v", version, err)
	}
	fixture := nativeInvocationFixture{}
	capability, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	if err != nil || !reflect.DeepEqual(capability, []string{executable, "acp"}) {
		t.Fatalf("capability argv = %#v, %v", capability, err)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, capability); err != nil {
		t.Fatal(err)
	}
	rejected, err := NewRuntimeDefinition(FamilyCursor, "cursor_logic", "", executable, "", "cursor_logic", []string{executable, "acp"}, nil, "/private/var/empty", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (NativeProbeInvocation{}).VersionArgv(rejected); err == nil {
		t.Fatal("cursor version probe accepted an ACP base argv")
	}
}

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
