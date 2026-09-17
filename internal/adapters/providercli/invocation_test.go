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

func TestNativeProbeInvocationCodexUsesAppServer(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newTestProfileWithTransport(t, FamilyCodex, "codex_current", []string{"/private/bin/codex"}, transport)
	if err != nil {
		t.Fatal(err)
	}

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := appendCodexProtocolServerArgv(definition.BaseArgv(), "", "")
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("Codex argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate exact Codex argv: %v", err)
	}
	tampered := append([]string(nil), argv...)
	tampered[len(tampered)-1] = "other.schema.json"
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, tampered); err == nil {
		t.Fatal("validate accepted a different Codex launch")
	}
}

// TestZCodeQualificationDenylistStillFullyToolDenied pins the qualification
// boundary. The review argv gained yolo mode and a Write grant for the
// staged_file transport; qualification must keep its plan-mode, fully
// tool-denied profile so the capability probe stays prompt-bound.
func TestZCodeQualificationDenylistStillFullyToolDenied(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "", "")

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{"/private/bin/zcode", "app-server"}
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
	want := []string{definition.executable, definition.launcher, "app-server"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode launcher argv = %#v, err = %v, want %#v", argv, err, want)
	}
}

func nativeInvocationIdentity(t *testing.T, path string) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(path, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
