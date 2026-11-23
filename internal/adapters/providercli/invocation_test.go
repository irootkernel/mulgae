package providercli

import (
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

type nativeInvocationFixture struct {
	identity  ports.WorkspaceSnapshotIdentity
	reference string
}

func (fixture nativeInvocationFixture) Reference() string {
	if fixture.reference == "" {
		return "roadmap.md"
	}
	return fixture.reference
}
func (nativeInvocationFixture) Nonce() string  { return "nonce" }
func (nativeInvocationFixture) Link() string   { return "link" }
func (nativeInvocationFixture) Packet() []byte { return []byte("fixture-packet") }
func (fixture nativeInvocationFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (fixture nativeInvocationFixture) Validate() error { return nil }

// TestZCodeQualificationDenylistStillFullyToolDenied pins the qualification
// boundary. The review argv gained yolo mode and a Write grant for the
// staged_file transport; qualification must keep its plan-mode, fully
// tool-denied profile so the capability probe stays prompt-bound.
func TestZCodeQualificationDenylistStillFullyToolDenied(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{"/private/bin/zcode", "app-server", "--stdio"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode qualification argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate exact ZCode qualification argv: %v", err)
	}
	if reflect.DeepEqual(zcodeCapabilityProtocolDenylist, zcodeReviewProtocolDenylist) {
		t.Fatal("qualification shares the review denylist")
	}
}

func TestNativeProbeInvocationAllowsDeclaredZcodeLauncher(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")
	definition.launcher = "/private/bin/zcode-launcher"
	definition.baseArgv = []string{definition.executable, definition.launcher}

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{definition.executable, definition.launcher, "app-server", "--stdio"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode launcher argv = %#v, err = %v, want %#v", argv, err, want)
	}
}
