package reviewrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestCurrentQualifierCanonicalRolesRejectDuplicateAndMissingBase(t *testing.T) {
	if _, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleLogic, domain.RoleLogic}); err == nil {
		t.Fatal("duplicate role accepted")
	}
	if _, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleSecurity}); err == nil {
		t.Fatal("missing base role accepted")
	}
	roles, err := canonicalQualificationRoles(domain.RoleLogic, []domain.Role{domain.RoleTesting, domain.RoleLogic, domain.RoleSecurity})
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Role{domain.RoleLogic, domain.RoleSecurity, domain.RoleTesting}
	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("canonical roles = %v, want %v", roles, want)
		}
	}
}

func TestCurrentProbeAppReceiptsRejectsUnboundGenericAuthority(t *testing.T) {
	for _, family := range []Family{FamilyKimi, FamilyZCode} {
		t.Run(string(family), func(t *testing.T) {
			identity := Identity{Family: family, Version: "2.0.0"}
			expires := time.Now().Add(time.Minute)
			kinds := []string{"workspace", "manifest", "namespace", "environment", "transport", "native-reference", "version", "capability", "base-role", "assignment", "direct-execution-authority"}
			providerReceipts := make([]providercli.CurrentProbeReceipt, 0, len(kinds))
			for _, kind := range kinds {
				providerReceipts = append(providerReceipts, providercli.CurrentProbeReceipt{Kind: kind, ExpiresAt: expires})
			}
			if _, err := currentProbeAppReceipts(providerReceipts, identity, providercli.RuntimeDefinition{}, "", nil); err == nil {
				t.Fatal("nil direct-execution authority accepted")
			}
			providerReceipts[len(providerReceipts)-1].Kind = "security-policy"
			if _, err := currentProbeAppReceipts(providerReceipts, identity, providercli.RuntimeDefinition{}, "", nil); err == nil {
				t.Fatal("obsolete security-policy payload accepted")
			}
		})
	}
}

func TestDrainProbeFixturesRetriesAndRejectsMismatchedReceipt(t *testing.T) {
	fixture := newCurrentQualifierFixture(t, domain.RoleLogic, testCurrentQualifierWorkspaceIdentity(t), 1, false)
	if err := drainProbeFixtures([]providercli.ProbeFixtureLease{fixture}); err != nil || fixture.drains != 2 {
		t.Fatalf("retry drain = %v, calls=%d", err, fixture.drains)
	}
	fixture = newCurrentQualifierFixture(t, domain.RoleLogic, testCurrentQualifierWorkspaceIdentity(t), 0, true)
	if err := drainProbeFixtures([]providercli.ProbeFixtureLease{fixture}); err == nil || fixture.drains != 2 {
		t.Fatalf("wrong receipt drain = %v, calls=%d", err, fixture.drains)
	}
}

func TestAdmissionProbeErrorPreservesTypedFailures(t *testing.T) {
	auth, err := domain.NewFailure("capability", domain.FailureAuthentication, "authentication unavailable", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := admissionProbeError(auth); got != auth {
		t.Fatal("authentication failure was replaced")
	}
	invalid, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "bad evidence", errors.New("bad"))
	if err != nil {
		t.Fatal(err)
	}
	var got *domain.Failure
	if !errors.As(admissionProbeError(invalid), &got) || got.Stage() != "reviewrun.current.capability" || got.Class() != domain.FailureInvalidOutput {
		t.Fatalf("invalid output was not adapted for admission: %v", got)
	}
}

type currentQualifierFixture struct {
	role     domain.Role
	identity ports.WorkspaceSnapshotIdentity
	terminal ports.QualificationWorkspaceLease
	drains   int
}

func newCurrentQualifierFixture(t *testing.T, role domain.Role, identity ports.WorkspaceSnapshotIdentity, failures int, wrongReceipt bool) *currentQualifierFixture {
	t.Helper()
	fixture := &currentQualifierFixture{role: role, identity: identity}
	terminalIdentity := identity
	if wrongReceipt {
		terminalIdentity = testCurrentQualifierOtherWorkspaceIdentity()
	}
	terminal := &currentQualifierTerminalLease{identity: terminalIdentity}
	acquired, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		drain, err := binding.Bind(terminalIdentity, func(context.Context) error {
			if fixture.drains <= failures {
				return errors.New("drain failed")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		terminal.drain = drain
		return terminal, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.terminal = acquired
	return fixture
}
func newCurrentQualifierFixtureForRole(role domain.Role, identity ports.WorkspaceSnapshotIdentity) (*currentQualifierFixture, error) {
	fixture := &currentQualifierFixture{role: role, identity: identity}
	terminal := &currentQualifierTerminalLease{identity: identity}
	acquired, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		drain, err := binding.Bind(identity, func(context.Context) error {
			return nil
		})
		if err != nil {
			return nil, err
		}
		terminal.drain = drain
		return terminal, nil
	})
	if err != nil {
		return nil, err
	}
	fixture.terminal = acquired
	return fixture, nil
}

type currentQualifierTerminalLease struct {
	identity ports.WorkspaceSnapshotIdentity
	drain    ports.QualificationWorkspaceTerminalDrain
}

func (lease *currentQualifierTerminalLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (*currentQualifierTerminalLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}
func (lease *currentQualifierTerminalLease) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

func (fixture *currentQualifierFixture) Reference() string             { return "roadmap.md" }
func (fixture *currentQualifierFixture) Nonce() string                 { return "nonce" }
func (fixture *currentQualifierFixture) Link() string                  { return "linked:nonce" }
func (fixture *currentQualifierFixture) Missing() string               { return "missing:nonce" }
func (fixture *currentQualifierFixture) Denied() string                { return "denied:nonce" }
func (fixture *currentQualifierFixture) Outside() string               { return "outside:nonce" }
func (*currentQualifierFixture) Validate() error                       { return nil }
func (*currentQualifierFixture) Workspace() providercli.ProbeWorkspace { return nil }
func (*currentQualifierFixture) Packet() []byte                        { return nil }
func (*currentQualifierFixture) PacketSHA256() string                  { return "" }
func (fixture *currentQualifierFixture) Role() domain.Role             { return fixture.role }
func (fixture *currentQualifierFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fixture.identity
}
func (*currentQualifierFixture) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}
func (fixture *currentQualifierFixture) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	fixture.drains++
	return fixture.terminal.DrainTerminal(ctx)
}

func testCurrentQualifierWorkspaceIdentity(t *testing.T) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/fixture", "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "qualification", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testCurrentQualifierOtherWorkspaceIdentity() ports.WorkspaceSnapshotIdentity {
	identity, _ := ports.NewWorkspaceSnapshotIdentity("/private/other", "snapshot-fedcba9876543210fedcba9876543210", "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", "qualification", 5, 6, 7, 8)
	return identity
}

type currentQualifierProbe struct {
	requests       []providercli.CurrentProbeRequest
	dropKind       string
	duplicateKind  string
	mismatchExpiry bool
}

func (probe *currentQualifierProbe) QualifyCurrent(_ context.Context, request providercli.CurrentProbeRequest) (providercli.CurrentProbeResult, error) {
	probe.requests = append(probe.requests, request)
	receipts := make([]providercli.CurrentProbeReceipt, 0, len(currentProbeReceiptKinds)+1)
	for _, kind := range currentProbeReceiptKinds {
		if kind != probe.dropKind {
			receipts = append(receipts, providercli.CurrentProbeReceipt{Kind: kind, ExpiresAt: request.Now.Add(time.Minute)})
		}
	}
	if probe.duplicateKind != "" {
		receipts = append(receipts, providercli.CurrentProbeReceipt{Kind: probe.duplicateKind, ExpiresAt: request.Now.Add(time.Minute)})
	}
	if probe.mismatchExpiry && len(receipts) > 0 {
		receipts[len(receipts)-1].ExpiresAt = request.Now.Add(2 * time.Minute)
	}
	return providercli.CurrentProbeResult{VersionArgv: []string{"provider", "--version"}, Version: "0.23.6", Receipts: receipts}, nil
}

type currentQualifierFixtures struct {
	acquired []domain.Role
	next     int
}

func (fixtures *currentQualifierFixtures) Acquire(_ context.Context, role domain.Role) (providercli.ProbeFixtureLease, error) {
	fixtures.next++
	fixtures.acquired = append(fixtures.acquired, role)
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		fmt.Sprintf("/private/fixture-%d", fixtures.next),
		fmt.Sprintf("snapshot-%032d", fixtures.next),
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"qualification", uint64(fixtures.next), 2, 3, 4,
	)
	if err != nil {
		return nil, err
	}
	fixture, err := newCurrentQualifierFixtureForRole(role, identity)
	if err != nil {
		return nil, err
	}
	return fixture, nil
}

type currentQualifierInvocation struct{}

func (currentQualifierInvocation) VersionArgv(providercli.RuntimeDefinition) ([]string, error) {
	return []string{"provider", "--version"}, nil
}
func (currentQualifierInvocation) CapabilityArgv(providercli.RuntimeDefinition, providercli.ProbeFixture) ([]string, error) {
	return []string{"provider", "capability"}, nil
}

func (currentQualifierInvocation) Validate(providercli.RuntimeDefinition, providercli.ProbeFixture, []string) error {
	return nil
}

var currentProbeReceiptKinds = []string{
	"workspace", "manifest", "namespace", "environment", "transport", "native-reference",
	"version", "capability", "base-role", "assignment", "direct-execution-authority",
}

func TestProviderCLICurrentQualifierUsesRequestRolesWithoutAuthorityBleed(t *testing.T) {
	probe := &currentQualifierProbe{}
	fixtures := &currentQualifierFixtures{}
	qualifier, err := NewProviderCLICurrentQualifier(probe, fixtures, currentQualifierInvocation{})
	if err != nil {
		t.Fatal(err)
	}
	first := testCurrentQualificationRequest(t, []domain.Role{domain.RoleTesting, domain.RoleLogic}, domain.RoleLogic)
	if _, err := qualifier.QualifyCurrent(context.Background(), first); err == nil {
		t.Fatal("untyped fake direct-execution authority accepted")
	}
	second := testCurrentQualificationRequest(t, []domain.Role{domain.RoleSecurity}, domain.RoleSecurity)
	if _, err := qualifier.QualifyCurrent(context.Background(), second); err == nil {
		t.Fatal("untyped fake direct-execution authority accepted")
	}
	if len(probe.requests) != 2 {
		t.Fatalf("probe calls = %d", len(probe.requests))
	}
	if got := fixtureRoles(probe.requests[0]); !sameRoles(got, []domain.Role{domain.RoleLogic, domain.RoleTesting}) {
		t.Fatalf("first fixture roles = %v", got)
	}
	if got := fixtureRoles(probe.requests[1]); !sameRoles(got, []domain.Role{domain.RoleSecurity}) {
		t.Fatalf("second fixture roles = %v", got)
	}
}
func TestProviderCLICurrentQualifierRejectsIncompleteDuplicateAndMismatchedDirectEvidence(t *testing.T) {
	for _, test := range []struct {
		name  string
		probe *currentQualifierProbe
	}{
		{name: "missing", probe: &currentQualifierProbe{dropKind: "base-role"}},
		{name: "duplicate", probe: &currentQualifierProbe{duplicateKind: "assignment"}},
		{name: "mismatched authority", probe: &currentQualifierProbe{mismatchExpiry: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			qualifier, err := NewProviderCLICurrentQualifier(test.probe, &currentQualifierFixtures{}, currentQualifierInvocation{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := qualifier.QualifyCurrent(context.Background(), testCurrentQualificationRequest(t, []domain.Role{domain.RoleLogic}, domain.RoleLogic)); err == nil {
				t.Fatal("invalid direct qualification evidence accepted")
			}
		})
	}
}

func testCurrentQualificationRequest(t *testing.T, roles []domain.Role, base domain.Role) CurrentQualificationRequest {
	t.Helper()
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("current-qualifier")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		"kimi", "current-qualifier", "", "/private/bin/kimi",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"/private/bin/kimi", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		key, "kimi-default", "profile-generation", "policy-identity", []string{"/private/bin/kimi"},
		transport, nil, "/private/work", time.Second, 1024, 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	namespace := qualifierNamespace{instance: definition.Instance(), generation: "generation-1", policy: definition.RuntimeSafetyPolicyIdentity()}
	profile := DiscoveredProviderProfile{
		family: FamilyKimi, executable: definition.Executable(), launcher: definition.Launcher(),
		sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
	}
	return CurrentQualificationRequest{
		Profile: profile, Definition: definition, Namespace: namespace, RequestedRoles: append([]domain.Role(nil), roles...), BaseRole: base,
		Identity: Identity{
			Family: Family(definition.Family()), Instance: definition.Instance(), ProfileGeneration: definition.ProfileGeneration(),
			AdapterProfile: definition.ProfileID(), Version: definition.Version(), Executable: definition.Executable(),
			ExecutableSHA256: definition.ExecutableSHA256(), Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
			NamespaceLease: definition.Instance() + ":" + namespace.Generation(), NamespaceGeneration: namespace.Generation(),
		},
		Now: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC),
	}
}

func fixtureRoles(request providercli.CurrentProbeRequest) []domain.Role {
	roles := []domain.Role{request.Fixture.Role()}
	for _, fixture := range request.RoleFixtures {
		roles = append(roles, fixture.Role())
	}
	return roles
}

func sameRoles(got, want []domain.Role) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

type authorityProbeNamespace struct {
	instance, generation, policy string
	nativeHome                   ports.NativeHomeLaunchAuthority
	environment                  []ports.EnvironmentVariable
}

func (n authorityProbeNamespace) ProviderInstance() string { return n.instance }
func (n authorityProbeNamespace) Generation() string       { return n.generation }
func (n authorityProbeNamespace) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), n.environment...)
}
func (n authorityProbeNamespace) RuntimeSafetyPolicyIdentity() string { return n.policy }
func (authorityProbeNamespace) ValidateForSpawn() error               { return nil }
func (n authorityProbeNamespace) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	return n.nativeHome, n.nativeHome.Valid()
}

type authorityProbeFixture struct {
	root     ports.ValidatedWorkspaceRoot
	identity ports.WorkspaceSnapshotIdentity
}

func (authorityProbeFixture) Reference() string { return "roadmap.md" }
func (authorityProbeFixture) Nonce() string     { return "nonce" }
func (authorityProbeFixture) Link() string      { return "linked" }
func (authorityProbeFixture) Validate() error   { return nil }
func (f authorityProbeFixture) Workspace() providercli.ProbeWorkspace {
	return authorityProbeWorkspace{fixture: f}
}
func (authorityProbeFixture) Packet() []byte { return []byte("fixture") }
func (f authorityProbeFixture) PacketSHA256() string {
	sum := sha256.Sum256(f.Packet())
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (authorityProbeFixture) Role() domain.Role { return domain.RoleLogic }
func (f authorityProbeFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return f.identity
}
func (f authorityProbeFixture) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return authorityProbeGuard{fixture: f}, nil
}
func (authorityProbeFixture) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type authorityProbeWorkspace struct{ fixture authorityProbeFixture }

func (w authorityProbeWorkspace) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return w.fixture.identity
}
func (w authorityProbeWorkspace) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return w.fixture.RevalidateForExecution()
}
func (authorityProbeWorkspace) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type authorityProbeGuard struct{ fixture authorityProbeFixture }

func (g authorityProbeGuard) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return g.fixture.root }
func (g authorityProbeGuard) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return g.fixture.identity
}
func (g authorityProbeGuard) DuplicateLaunchDirectory() (*os.File, error) {
	return os.Open(g.fixture.root.Path())
}
func (authorityProbeGuard) RevalidateAfterExecution() error { return nil }
func (authorityProbeGuard) Close() error                    { return nil }

type authorityProbeVerifier struct{}

func (authorityProbeVerifier) VerifyProviderSpawn(context.Context, providercli.RuntimeDefinition) error {
	return nil
}

type authorityProbeRunner struct {
	t       *testing.T
	family  Family
	version string
	calls   int
}

func (r *authorityProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.t.Helper()
	r.calls++
	file, _, ok := request.BoundLaunchDirectory()
	if !ok {
		r.t.Fatal("current probe request was not bound to the fixture")
	}
	_ = file.Close()
	if r.calls == 1 {
		return authorityProbeObservation(r.t, []byte(r.version+"\n"), ports.ProviderPacketChannelArgvLiteral, ports.ProviderPacketIdentity{}, "", "", nil), nil
	}
	binding, ok := request.ProviderPacketBinding()
	if !ok || !binding.Valid() {
		r.t.Fatal("capability request omitted provider packet binding")
	}
	output := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	if r.family == FamilyKimi {
		output = []byte("{\"role\":\"assistant\",\"content\":\"{\\\"root\\\":\\\"nonce\\\",\\\"link\\\":\\\"linked\\\",\\\"role\\\":\\\"logic\\\"}\"}\n")
	}
	var lifecycle ports.ProcessLifecycleReceipt
	if r.family == FamilyAGY {
		policy, ok := request.PostOutputLifecycle()
		if !ok || !policy.Valid() {
			r.t.Fatal("AGY capability request omitted lifecycle policy")
		}
		frame, err := ports.NewProcessOutputFrameReceipt(policy.Framing(), output, policy.StabilityGrace())
		if err != nil {
			r.t.Fatal(err)
		}
		signal, err := ports.NewProcessSignal(15, "SIGTERM")
		if err != nil {
			r.t.Fatal(err)
		}
		signalReceipt, err := ports.NewAcceptedPostOutputProcessGroupSignalRequestReceipt(signal, binding.PacketIdentity(), frame)
		if err != nil {
			r.t.Fatal(err)
		}
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{signalReceipt}, frame)
		if err != nil {
			r.t.Fatal(err)
		}
	} else {
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, nil)
		if err != nil {
			r.t.Fatal(err)
		}
	}
	return authorityProbeObservation(r.t, output, binding.Channel(), binding.PacketIdentity(), binding.PromptFileReference(), binding.SnapshotCWD(), &lifecycle), nil
}

func authorityProbeObservation(t *testing.T, output []byte, channel ports.ProviderPacketChannel, packet ports.ProviderPacketIdentity, reference, cwd string, lifecycle *ports.ProcessLifecycleReceipt) ports.ProcessObservation {
	t.Helper()
	stdin, err := ports.NewStdinWriteReceipt(0, 0, authorityProbeStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	if !packet.Valid() {
		exitCode := 0
		observation, err := ports.NewProcessObservation(
			output, nil, &exitCode, ports.ProcessTerminationExited, stdin,
			time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	transport, err := ports.NewProviderPacketTransportReceipt(channel, packet, reference, cwd, packet, packet)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle != nil {
		observation, err := ports.NewStartedProviderProcessObservation(output, nil, ports.ProcessTerminationExited, stdin, transport, *lifecycle, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	exitCode := 0
	observation, err := ports.NewProviderProcessObservation(output, nil, &exitCode, ports.ProcessTerminationExited, stdin, transport, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func authorityProbeDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func authorityProbeStdinDigest(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func currentProbeAuthorityInput(t *testing.T, family Family, version string) QualificationInput {
	return currentProbeAuthorityInputForInstance(t, family, string(family)+"-current", version)
}

func currentProbeAuthorityInputForInstance(t *testing.T, family Family, instance, version string) QualificationInput {
	t.Helper()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	probeVersion := version
	if version == "current" {
		probeVersion = "0.23.6"
	}
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	definition, namespace := authorityProbeDefinition(t, family, instance, probeVersion, directory)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	workspace, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:"+authorityProbeDigest([]byte("workspace")), "qualification", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, workspace)
	if err != nil {
		t.Fatal(err)
	}
	fixture := authorityProbeFixture{root: root, identity: workspace}
	runner := &authorityProbeRunner{t: t, family: family, version: probeVersion}
	probe, err := providercli.NewCurrentProbe(runner, authorityProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), providercli.CurrentProbeRequest{
		Definition: definition, Namespace: namespace, Fixture: fixture, Invocation: providercli.NativeProbeInvocation{}, Now: now, TTL: time.Hour,
	})
	if err != nil {
		causes := []string{}
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			causes = append(causes, cause.Error())
		}
		t.Fatalf("current probe failed: %q", causes)
	}
	identity := Identity{
		Family: family, Instance: definition.Instance(), ProfileGeneration: definition.ProfileGeneration(), AdapterProfile: definition.ProfileID(),
		Version: probeVersion, Executable: definition.Executable(), ExecutableSHA256: definition.ExecutableSHA256(),
		Launcher: definition.Launcher(), LauncherSHA256: definition.LauncherSHA256(),
		NamespaceLease: definition.Instance() + ":" + namespace.Generation(), NamespaceGeneration: namespace.Generation(), SnapshotManifest: "manifest-1",
	}
	receipts, err := currentProbeAppReceipts(result.Receipts, identity, definition, namespace.Generation(), []domain.Role{domain.RoleLogic})
	if err != nil {
		t.Fatal(err)
	}
	input := QualificationInput{Identity: identity, Version: probeVersion, Receipts: receipts, Now: now}
	if version == probeVersion {
		return input
	}
	input.Identity.Version = version
	input.Version = version
	for index := range input.Receipts {
		input.Receipts[index].Identity.Version = version
	}
	return input
}

func authorityProbeDefinition(t *testing.T, family Family, instance, version, workingDirectory string) (providercli.RuntimeDefinition, authorityProbeNamespace) {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(instance)
	if err != nil {
		t.Fatal(err)
	}
	argvIndex := 4
	if family == FamilyZCode {
		argvIndex = 6
	} else if family == FamilyAGY {
		argvIndex = 11
	}
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, argvIndex, "@roadmap.md")
	if err != nil {
		t.Fatal(err)
	}
	policy := string(family) + "-policy"
	namespace := authorityProbeNamespace{instance: instance, generation: "generation-1", policy: policy, environment: authorityProbeEnvironment(t, family)}
	if family == FamilyAGY {
		namespace.nativeHome, err = ports.NewNativeHomeLaunchAuthority("/private/HOME", 1, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingStrictJSON, time.Second, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
			string(family), instance, version, "/private/bin/"+string(family), qualifierTestSHA, "/private/bin/"+string(family), qualifierTestSHA,
			key, string(family)+"-profile", "profile-1", policy, []string{"/private/bin/" + string(family)}, transport, lifecycle, nil, workingDirectory, 3*time.Second, 4096, 4096,
		)
		if err != nil {
			t.Fatal(err)
		}
		return definition, namespace
	}
	executable := "/private/bin/" + string(family)
	launcher := executable
	baseArgv := []string{executable}
	if family == FamilyZCode {
		executable = "/usr/bin/node"
		launcher = "/private/bin/zcode.cjs"
		baseArgv = []string{executable, launcher}
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		string(family), instance, version, executable, qualifierTestSHA, launcher, qualifierTestSHA,
		key, string(family)+"-profile", "profile-1", policy, baseArgv, transport, nil, workingDirectory, time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return definition, namespace
}
func authorityProbeEnvironment(t *testing.T, family Family) []ports.EnvironmentVariable {
	t.Helper()
	root := "/private/kar-provider-namespace"
	values := map[string]string{
		"HOME":                 filepath.Join(root, "home"),
		"XDG_CONFIG_HOME":      filepath.Join(root, "settings"),
		"XDG_DATA_HOME":        filepath.Join(root, "auth"),
		"XDG_CACHE_HOME":       filepath.Join(root, "cache"),
		"TMPDIR":               filepath.Join(root, "tmp"),
		"TMP":                  filepath.Join(root, "tmp"),
		"TEMP":                 filepath.Join(root, "tmp"),
		"KAR_PROVIDER_SCRATCH": filepath.Join(root, "scratch"),
	}
	if family == FamilyAGY {
		values["HOME"] = "/private/HOME"
	}
	names := []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "KAR_PROVIDER_SCRATCH"}
	environment := make([]ports.EnvironmentVariable, 0, len(names))
	for _, name := range names {
		variable, err := ports.NewEnvironmentVariable(name, values[name])
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, variable)
	}
	return environment
}
