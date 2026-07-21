package providercli

import (
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
func (nativeInvocationFixture) Nonce() string { return "nonce" }
func (nativeInvocationFixture) Link() string  { return "link" }
func (fixture nativeInvocationFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (fixture nativeInvocationFixture) Validate() error { return nil }

func TestNativeProbeInvocationAgyBindsImmutableSnapshotPath(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	definition := testProfile(t, FamilyAgy, "agy_current", "agy-current", "", "")

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := append(definition.BaseArgv(), "--new-project", "--sandbox", "--dangerously-skip-permissions", "--add-dir", identity.SnapshotPath(), "--mode", "plan", "--print-timeout", "2m", "--print", "@roadmap.md")
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("AGY argv = %#v, err = %v, want %#v", argv, err, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate exact AGY argv: %v", err)
	}
	tampered := append([]string(nil), argv...)
	tampered[len(definition.BaseArgv())+3] = "/unbound"
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, tampered); err == nil {
		t.Fatal("validate accepted AGY argv with an unbound snapshot path")
	}
}

func TestNativeProbeInvocationRejectsInvalidAgySnapshotIdentity(t *testing.T) {
	definition := testProfile(t, FamilyAgy, "agy_current", "agy-current", "", "")
	for _, identity := range []ports.WorkspaceSnapshotIdentity{
		{},
	} {
		fixture := nativeInvocationFixture{identity: identity}
		if _, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture); err == nil {
			t.Fatalf("accepted invalid AGY snapshot identity %#v", identity)
		}
		if err := (NativeProbeInvocation{}).Validate(definition, fixture, nil); err == nil {
			t.Fatalf("validate accepted invalid AGY snapshot identity %#v", identity)
		}
	}
}

func TestNativeProbeInvocationKeepsKimiAndZcodeArgv(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	for family, want := range map[string][]string{
		FamilyKimi:  {"/private/bin/kimi", "--model", "kimi-code/k3", "--prompt", "@fixtures/probe.json", "--output-format", "stream-json"},
		FamilyZcode: {"/private/bin/zcode", "--mode", "plan", "--no-color", "--prompt", "@fixtures/probe.json"},
	} {
		definition := testProfile(t, family, "provider_current", "provider-current", "", "")
		argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
		if err != nil || !reflect.DeepEqual(argv, want) {
			t.Fatalf("%s argv = %#v, err = %v, want %#v", family, argv, err, want)
		}
		if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
			t.Fatalf("validate exact %s argv: %v", family, err)
		}
		tampered := append([]string(nil), argv...)
		tampered[len(definition.BaseArgv())] = "--tampered"
		if err := (NativeProbeInvocation{}).Validate(definition, fixture, tampered); err == nil {
			t.Fatalf("validate accepted tampered %s argv", family)
		}
	}
}

func TestNativeProbeInvocationVersionArgvUsesClosedFamilyBase(t *testing.T) {
	for _, family := range []string{FamilyKimi, FamilyZcode, FamilyAgy} {
		definition := testProfile(t, family, family+"_current", family+"-current", "", "")
		argv, err := (NativeProbeInvocation{}).VersionArgv(definition)
		want := append(definition.BaseArgv(), "--version")
		if err != nil || !reflect.DeepEqual(argv, want) {
			t.Fatalf("%s version argv = %#v, err = %v, want %#v", family, argv, err, want)
		}
	}
}

func TestNativeProbeInvocationAllowsDeclaredZcodeLauncher(t *testing.T) {
	fixture := nativeInvocationFixture{reference: "fixtures/probe.json"}
	definition := testProfile(t, FamilyZcode, "zcode_current", "zcode-current", "", "")
	definition.launcher = "/private/bin/zcode-launcher"
	definition.baseArgv = []string{definition.executable, definition.launcher}

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := []string{definition.executable, definition.launcher, "--mode", "plan", "--no-color", "--prompt", "@fixtures/probe.json"}
	if err != nil || !reflect.DeepEqual(argv, want) {
		t.Fatalf("ZCode launcher argv = %#v, err = %v, want %#v", argv, err, want)
	}
}

func TestNativeProbeInvocationRejectsUnrecognizedBaseArguments(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	tests := []struct {
		name   string
		family string
		args   []string
	}{
		{name: "unknown flag", family: FamilyKimi, args: []string{"--unknown"}},
		{name: "deceptive permission spelling", family: FamilyKimi, args: []string{"--permissive-mode"}},
		{name: "duplicate prompt", family: FamilyKimi, args: []string{"--prompt", "@other.json"}},
		{name: "duplicate mode", family: FamilyZcode, args: []string{"--mode", "plan"}},
		{name: "conflicting mode", family: FamilyZcode, args: []string{"--mode", "execute"}},
		{name: "duplicate sandbox", family: FamilyAgy, args: []string{"--sandbox"}},
		{name: "duplicate permission bypass", family: FamilyAgy, args: []string{"--dangerously-skip-permissions"}},
		{name: "conflicting permission bypass spelling", family: FamilyAgy, args: []string{"--dangerously-skip-permissions=true"}},
		{name: "unsupported yolo", family: FamilyKimi, args: []string{"--yolo"}},
		{name: "duplicate model", family: FamilyKimi, args: []string{"--model", "kimi-code/k3"}},
		{name: "conflicting model", family: FamilyKimi, args: []string{"--model", "kimi-code/k2"}},
		{name: "conflicting plan", family: FamilyAgy, args: []string{"--mode", "execute"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := testProfile(t, test.family, "provider_current", "provider-current", "", "")
			definition.baseArgv = append([]string{definition.executable}, test.args...)
			if _, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture); err == nil {
				t.Fatalf("accepted %s base argv %#v", test.name, definition.baseArgv)
			}
			if _, err := (NativeProbeInvocation{}).VersionArgv(definition); err == nil {
				t.Fatalf("version argv accepted %s base argv %#v", test.name, definition.baseArgv)
			}
		})
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
