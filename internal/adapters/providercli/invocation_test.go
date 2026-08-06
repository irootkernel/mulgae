package providercli

import (
	"reflect"
	"testing"
	"time"

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

func TestNativeProbeInvocationAgyBindsImmutableSnapshotPath(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	definition := testProfile(t, FamilyAgy, "agy_current", "agy-current", "", "")
	definition.timeout = 15 * time.Minute

	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	want := append(definition.BaseArgv(), "--new-project", "--sandbox", "--add-dir", identity.SnapshotPath(), "--mode", "plan", "--effort", "low", "--print-timeout", "25s", "--print", "@roadmap.md")
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

func TestAGYPrintTimeoutPreservesBoundedLifecycleGrace(t *testing.T) {
	for _, test := range []struct {
		name           string
		runtimeTimeout time.Duration
		want           time.Duration
	}{
		{name: "fifteen minutes", runtimeTimeout: 15 * time.Minute, want: 14*time.Minute + 55*time.Second},
		{name: "thirty minutes", runtimeTimeout: 30 * time.Minute, want: 29*time.Minute + 55*time.Second},
		{name: "short runtime", runtimeTimeout: 3 * time.Second, want: 1500 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := agyPrintTimeout(test.runtimeTimeout); got != test.want {
				t.Fatalf("AGY print timeout = %s, want %s", got, test.want)
			}
		})
	}
}

func TestAGYProbePrintTimeoutStaysInsideBoundedProbeDeadline(t *testing.T) {
	for _, test := range []struct {
		name           string
		runtimeTimeout time.Duration
		want           time.Duration
	}{
		{name: "production runtime timeout", runtimeTimeout: 15 * time.Minute, want: 25 * time.Second},
		{name: "long runtime timeout", runtimeTimeout: 30 * time.Minute, want: 25 * time.Second},
		{name: "bounded probe deadline", runtimeTimeout: 30 * time.Second, want: 25 * time.Second},
		{name: "short runtime timeout", runtimeTimeout: 3 * time.Second, want: 1500 * time.Millisecond},
		{name: "very short runtime timeout", runtimeTimeout: time.Second, want: 500 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := agyProbePrintTimeout(test.runtimeTimeout)
			if got != test.want {
				t.Fatalf("AGY probe print timeout = %s, want %s", got, test.want)
			}
			if bound := boundedProbeTimeout(test.runtimeTimeout); got >= bound {
				t.Fatalf("AGY probe print timeout = %s, want less than the bounded probe deadline %s", got, bound)
			}
		})
	}
}

func TestAGYReviewPrintTimeoutKeepsConfiguredRuntimeDeadline(t *testing.T) {
	transport, err := defaultRuntimeTransport(FamilyAgy, 1)
	if err != nil {
		t.Fatal(err)
	}
	argv, err := buildArgv(definition{
		family:    FamilyAgy,
		baseArgv:  []string{"/private/bin/agy"},
		transport: transport,
		timeout:   30 * time.Minute,
	}, "/private/work", []byte("review bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/private/bin/agy", "--new-project", "--sandbox", "--add-dir", "/private/work", "--mode", "plan", "--effort", "low", "--print-timeout", "29m55s", "--print", "review bytes"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("review AGY argv = %#v, want %#v", argv, want)
	}
	if got := agyPrintTimeout(30 * time.Minute); got.String() != "29m55s" {
		t.Fatalf("review AGY print timeout = %s, want 29m55s", got)
	}
}

func TestNativeProbeInvocationAgyHeadlessOptInKeepsSandboxAndSnapshot(t *testing.T) {
	identity := nativeInvocationIdentity(t, t.TempDir())
	fixture := nativeInvocationFixture{identity: identity}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newTestProfileWithTransport(
		t, FamilyAgy, "agy-headless", "agy-headless", []string{"/private/bin/agy"}, transport,
	)
	if err != nil {
		t.Fatal(err)
	}
	definition.timeout = 15 * time.Minute
	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
	if err != nil {
		t.Fatal(err)
	}
	want := append(definition.BaseArgv(), "--new-project", "--sandbox", "--dangerously-skip-permissions", "--add-dir", identity.SnapshotPath(), "--mode", "plan", "--effort", "low", "--print-timeout", "25s", "--print", "@roadmap.md")
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("headless AGY probe argv = %#v, want %#v", argv, want)
	}
	if err := (NativeProbeInvocation{}).Validate(definition, fixture, argv); err != nil {
		t.Fatalf("validate headless AGY argv: %v", err)
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
		FamilyKimi:  {"/private/bin/kimi", "--model", "kimi-code/kimi-for-coding", "--prompt", "fixture-packet", "--output-format", "stream-json"},
		FamilyZcode: {"/private/bin/zcode", "--mode", "plan", "--no-color", "--prompt", "fixture-packet", "--json", "--disallowed-tools", zcodeCapabilityDisallowedTools},
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
	want := []string{definition.executable, definition.launcher, "--mode", "plan", "--no-color", "--prompt", "fixture-packet", "--json", "--disallowed-tools", zcodeCapabilityDisallowedTools}
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
		{name: "duplicate model", family: FamilyKimi, args: []string{"--model", "kimi-code/kimi-for-coding"}},
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
