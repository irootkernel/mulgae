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

func TestZCodeQualificationUsesDirectCompanionArgv(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")
	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	if want := []string{definition.executable}; err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("qualification argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatal(err)
	}
	definition.baseArgv = append(definition.baseArgv, "/old/launcher")
	if _, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture); err == nil {
		t.Fatal("accepted a second launch component")
	}
}
