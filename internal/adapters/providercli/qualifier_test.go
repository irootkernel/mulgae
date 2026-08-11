package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestClassifyProbeFailurePreservesExplicitLoginRequired(t *testing.T) {
	err := classifyProbeFailure(
		context.Background(),
		FamilyKimi,
		errors.New("provider exited"),
		[]byte(`{"code":"auth.login_required","message":"login first"}`),
	)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureAuthentication ||
		!errors.Is(err, ports.ErrProviderLoginRequired) {
		t.Fatalf("login-required probe failure = %v", err)
	}
}

func TestQualificationFamilyOutputCauseIsExact(t *testing.T) {
	for _, test := range []struct {
		name   string
		family string
		err    error
		want   domain.RuntimeDiagnosticCause
	}{
		{name: "kimi missing frame", family: FamilyKimi, err: errProviderOutputFrameMissing, want: domain.DiagnosticCauseOutputFrameMissing},
		{name: "kimi decode", family: FamilyKimi, err: errors.New("decode"), want: domain.DiagnosticCauseOutputDecodeFailed},
		{name: "zcode envelope", family: FamilyZcode, err: errInvalidZcodeEnvelope, want: domain.DiagnosticCauseOutputEnvelopeInvalid},
		{name: "agy missing frame", family: FamilyAgy, err: errProviderOutputFrameMissing, want: domain.DiagnosticCauseOutputFrameMissing},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := qualificationFamilyOutputCause(test.family, test.err); got != test.want {
				t.Fatalf("cause = %q, want %q", got, test.want)
			}
		})
	}
}

func TestQualificationProcessFailurePreservesExecutionStage(t *testing.T) {
	observation := testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 1)
	err := qualificationProcessFailure(FamilyKimi, observation, errors.New("capability probe failed"))
	var failure *providerOutputFailure
	if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCauseProviderExecutionFailed {
		t.Fatalf("qualification process failure = %#v, err=%v", failure, err)
	}
}

func TestQualificationProcessFailurePreservesExactProcessCause(t *testing.T) {
	processErr, err := ports.NewProcessExecutionError(
		domain.DiagnosticCausePromptFilePostEndFailed, "", nil, nil, errors.New("prompt identity changed"),
	)
	if err != nil {
		t.Fatal(err)
	}
	observation := testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 1)
	requireProviderDiagnosticCause(t,
		qualificationProcessFailure(FamilyAgy, observation, processErr),
		domain.DiagnosticCausePromptFilePostEndFailed,
	)
}

type currentProbeNamespace struct {
	environment []ports.EnvironmentVariable
	nativeHome  ports.NativeHomeLaunchAuthority
}

func (currentProbeNamespace) ProviderInstance() string { return "kimi_current" }
func (currentProbeNamespace) Generation() string       { return "generation" }
func (n currentProbeNamespace) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), n.environment...)
}
func (currentProbeNamespace) RuntimeSafetyPolicyIdentity() string { return "" }
func (currentProbeNamespace) ValidateForSpawn() error             { return nil }
func (n currentProbeNamespace) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	return n.nativeHome, n.nativeHome.Valid()
}

type currentProbeFixture struct {
	root     ports.ValidatedWorkspaceRoot
	identity ports.WorkspaceSnapshotIdentity
	role     domain.Role
	post     error
	closes   int
}

func (f *currentProbeFixture) Reference() string         { return "roadmap.md" }
func (f *currentProbeFixture) Nonce() string             { return "nonce" }
func (f *currentProbeFixture) Link() string              { return "linked" }
func (f *currentProbeFixture) Validate() error           { return nil }
func (f *currentProbeFixture) Workspace() ProbeWorkspace { return currentProbeWorkspace{fixture: f} }
func (f *currentProbeFixture) Packet() []byte            { return []byte("fixture") }
func (f *currentProbeFixture) PacketSHA256() string {
	sum := sha256.Sum256(f.Packet())
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (f *currentProbeFixture) Role() domain.Role {
	if f.role.Valid() {
		return f.role
	}
	return domain.RoleLogic
}
func (f *currentProbeFixture) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return f.identity
}
func (f *currentProbeFixture) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return &currentProbeGuard{fixture: f}, nil
}
func (f *currentProbeFixture) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type currentProbeWorkspace struct{ fixture *currentProbeFixture }

func (w currentProbeWorkspace) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return w.fixture.identity
}
func (w currentProbeWorkspace) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return w.fixture.RevalidateForExecution()
}
func (currentProbeWorkspace) DrainTerminal(context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return ports.QualificationWorkspaceTerminalReceipt{}, nil
}

type currentProbeGuard struct{ fixture *currentProbeFixture }

func (g *currentProbeGuard) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return g.fixture.root }
func (g *currentProbeGuard) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return g.fixture.identity
}
func (g *currentProbeGuard) DuplicateLaunchDirectory() (*os.File, error) {
	return os.Open(g.fixture.root.Path())
}
func (g *currentProbeGuard) RevalidateAfterExecution() error { return g.fixture.post }
func (g *currentProbeGuard) Close() error                    { g.fixture.closes++; return nil }

type currentProbeRunner struct {
	observations []ports.ProcessObservation
	requests     []ports.ProcessRequest
}

func (r *currentProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.requests = append(r.requests, request)
	file, _, ok := request.BoundLaunchDirectory()
	if !ok {
		return ports.ProcessObservation{}, fmt.Errorf("unbound")
	}
	_ = file.Close()
	result := r.observations[0]
	r.observations = r.observations[1:]
	return result, nil
}

func TestBoundedProbeTimeoutCapsLongProductionTimeout(t *testing.T) {
	if got := boundedProbeTimeout(30 * time.Minute); got != currentProbeTimeout {
		t.Fatalf("bounded probe timeout = %s, want %s", got, currentProbeTimeout)
	}
}

func currentProbeExitedLifecycle(t *testing.T) ports.ProcessLifecycleReceipt {
	t.Helper()
	final, err := ports.NewExitedProcessFinalTermination(0)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func currentProbeCapabilityObservation(t *testing.T, fixture *currentProbeFixture, output []byte) ports.ProcessObservation {
	return currentProbeCapabilityObservationWithStderr(t, fixture, output, nil)
}

func currentProbeCapabilityObservationWithStderr(t *testing.T, fixture *currentProbeFixture, output, stderr []byte) ports.ProcessObservation {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelArgvLiteral, packet.Identity(), "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(
		output, stderr, ports.ProcessTerminationExited, stdin, transport, currentProbeExitedLifecycle(t),
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestCurrentProbeClassifiesSuccessfulAGYPermissionDenialBeforeOutputDecode(t *testing.T) {
	directory := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	key, err := ports.ParseConcurrencyKey("agy-current-permission")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(FamilyAgy, "kimi_current", "", "/private/bin/agy", "", key, "agy-current-permission", []string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", 3*time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	runner := &agyCurrentProbeRunner{t: t, fixture: fixture, permissionDenied: true}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: definition,
		Namespace:  currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)},
		Fixture:    fixture,
		Invocation: NativeProbeInvocation{},
		Now:        time.Now().UTC(),
		TTL:        time.Minute,
	})
	if err == nil {
		t.Fatal("AGY permission denial was accepted")
	}
	requireProviderDiagnosticCause(t, err, domain.DiagnosticCausePermissionDenied)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureAuthentication {
		t.Fatalf("AGY permission failure = %v", err)
	}
}

func TestClassifyProbeFailureUsesProcessStderrWhenRunnerErrors(t *testing.T) {
	directory := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyAgy, "kimi_current", "agy-current-runner-error", "", ""))
	runner := &erroringCurrentProbeRunner{
		observation: testProcessObservation(t, nil, []byte("Error: 429 too many requests\n"), ports.ProcessTerminationExited, 1),
		err:         errors.New("provider process failed"),
	}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: definition,
		Namespace:  currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)},
		Fixture:    fixture,
		Invocation: NativeProbeInvocation{},
		Now:        time.Now().UTC(),
		TTL:        time.Minute,
	})
	if err == nil {
		t.Fatal("runner error was accepted")
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureRateLimit {
		t.Fatalf("runner error probe failure = %v", err)
	}
}

// erroringCurrentProbeRunner returns a process observation together with a
// runner error, the shape that leaves the qualification stderr unread.
type erroringCurrentProbeRunner struct {
	observation ports.ProcessObservation
	err         error
}

func (r *erroringCurrentProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	if file, _, ok := request.BoundLaunchDirectory(); ok {
		_ = file.Close()
	}
	return r.observation, r.err
}

type currentProbeVerifier struct {
	calls int
	err   error
}

func (v *currentProbeVerifier) VerifyProviderSpawn(context.Context, RuntimeDefinition) error {
	v.calls++
	return v.err
}
func currentProbeDefinitionWithExecutionIdentity(definition RuntimeDefinition) RuntimeDefinition {
	definition.executableSHA256 = "sha256:current-probe-executable"
	definition.launcher = definition.Executable()
	definition.launcherSHA256 = definition.ExecutableSHA256()
	return definition
}

func TestCurrentProbeUsesBoundDescriptorsAndStrictKimiStream(t *testing.T) {
	definition := testProfile(t, FamilyKimi, "kimi_current", "kimi-current", "", "")
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	evidence := `{"root":"nonce","link":"linked","role":"logic"}`
	runner := &currentProbeRunner{observations: []ports.ProcessObservation{testProcessObservation(t, []byte("1.2.3\n"), nil, ports.ProcessTerminationExited, 0), currentProbeCapabilityObservation(t, fixture, []byte(`{"role":"assistant","content":`+fmt.Sprintf("%q", evidence)+"}\n"))}}
	verifier := &currentProbeVerifier{}
	probe, err := NewCurrentProbe(runner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t)}, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: now, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.VersionArgv, []string{"/private/bin/kimi", "--version"}) || verifier.calls != 2 || fixture.closes != 2 {
		t.Fatalf("result=%#v calls=%d closes=%d", result, verifier.calls, fixture.closes)
	}
	wantKinds := map[string]struct{}{"workspace": {}, "manifest": {}, "namespace": {}, "environment": {}, "transport": {}, "native-reference": {}, "version": {}, "capability": {}, "base-role": {}, "assignment": {}, "direct-execution-authority": {}}
	if len(result.Receipts) != len(wantKinds) {
		t.Fatalf("receipt count = %d, want %d", len(result.Receipts), len(wantKinds))
	}
	for _, receipt := range result.Receipts {
		if _, ok := wantKinds[receipt.Kind]; !ok || !receipt.ExpiresAt.Equal(now.Add(time.Minute)) || receipt.EvidenceID == "" {
			t.Fatalf("unexpected Kimi qualification receipt: %#v", receipt)
		}
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil || !receipt.DirectExecutionAuthority.Valid() || receipt.DirectExecutionAuthority.AuthorityID() == "" ||
				receipt.DirectExecutionAuthority.ExpiresAt() != receipt.ExpiresAt {
				t.Fatalf("invalid typed Kimi direct-execution authority: %#v", receipt)
			}
			if _, ok := receipt.DirectExecutionAuthority.AGYControlAuthorityID(); ok {
				t.Fatalf("Kimi direct authority exposed AGY control authority: %#v", receipt)
			}
			if !receipt.DirectExecutionAuthority.Matches(definition, "1.2.3", "generation", []domain.Role{domain.RoleLogic}) {
				t.Fatalf("Kimi direct authority did not bind the runtime definition: %#v", receipt)
			}
		} else if receipt.DirectExecutionAuthority != nil {
			t.Fatalf("non-authority receipt carried direct-execution authority: %#v", receipt)
		}
		delete(wantKinds, receipt.Kind)
	}
	if len(wantKinds) != 0 {
		t.Fatalf("Kimi direct qualification receipts were incomplete: %v", wantKinds)
	}
	for _, request := range runner.requests {
		_, boundRoot, ok := request.BoundLaunchDirectory()
		if !ok || boundRoot != root {
			t.Fatalf("request was not fixture-bound: %#v", request)
		}
		if strings.Contains(strings.Join(request.Argv(), "\x00"), fixture.Nonce()) ||
			strings.Contains(strings.Join(request.Argv(), "\x00"), fixture.Link()) ||
			strings.Contains(string(request.Stdin()), fixture.Nonce()) ||
			strings.Contains(string(request.Stdin()), fixture.Link()) {
			t.Fatalf("probe request exposed fixture nonce: %#v", request)
		}
	}
}
func TestCurrentProbeZCodeMintsTypedDirectExecutionAuthority(t *testing.T) {
	definition := testProfile(t, FamilyZcode, "kimi_current", "zcode-current", "", "")
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	evidence := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	runner := &currentProbeRunner{observations: []ports.ProcessObservation{
		testProcessObservation(t, []byte("1.2.3\n"), nil, ports.ProcessTerminationExited, 0),
		currentProbeCapabilityObservation(t, fixture, evidence),
	}}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t)},
		Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range result.Receipts {
		if receipt.Kind == "direct-execution-authority" && receipt.DirectExecutionAuthority != nil && receipt.DirectExecutionAuthority.Valid() && receipt.DirectExecutionAuthority.AuthorityID() != "" {
			if _, ok := receipt.DirectExecutionAuthority.AGYControlAuthorityID(); ok {
				t.Fatal("ZCode direct authority exposed AGY control authority")
			}
			return
		}
	}
	t.Fatal("ZCode qualification did not mint typed direct-execution authority")
}
func TestCurrentProbeAgyBindsProviderPacketAndRequiresLifecycleEvidence(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("agy-current")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(FamilyAgy, "kimi_current", "", "/private/bin/agy", "", key, "agy-current", []string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", 3*time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	fixture := &currentProbeFixture{root: root, identity: identity}
	runner := &agyCurrentProbeRunner{t: t, fixture: fixture}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)}, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: now, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.requests) != 2 || !runner.capabilityBound || !runner.capabilityLifecycle {
		t.Fatal("AGY probe did not issue a lifecycle-bound provider packet request")
	}
	wantKinds := map[string]struct{}{"workspace": {}, "manifest": {}, "namespace": {}, "environment": {}, "transport": {}, "native-reference": {}, "version": {}, "capability": {}, "base-role": {}, "assignment": {}, "direct-execution-authority": {}}
	if len(result.Receipts) != len(wantKinds) {
		t.Fatalf("receipt count = %d, want %d", len(result.Receipts), len(wantKinds))
	}
	for _, receipt := range result.Receipts {
		if _, ok := wantKinds[receipt.Kind]; !ok || !receipt.ExpiresAt.Equal(now.Add(time.Minute)) || receipt.EvidenceID == "" {
			t.Fatalf("invalid qualification receipt: %#v", receipt)
		}
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil || !receipt.DirectExecutionAuthority.Valid() || receipt.DirectExecutionAuthority.AuthorityID() == "" ||
				receipt.DirectExecutionAuthority.ExpiresAt() != receipt.ExpiresAt {
				t.Fatalf("invalid typed AGY direct-execution authority: %#v", receipt)
			}
			if controlID, ok := receipt.DirectExecutionAuthority.AGYControlAuthorityID(); !ok || controlID == "" {
				t.Fatalf("AGY direct authority omitted control authority: %#v", receipt)
			}
		} else if receipt.DirectExecutionAuthority != nil {
			t.Fatalf("non-authority receipt carried AGY direct-execution authority: %#v", receipt)
		}
		delete(wantKinds, receipt.Kind)
	}
	if len(wantKinds) != 0 {
		t.Fatalf("qualification receipts were not exact and unique: %v", wantKinds)
	}
}

// An AGY provider that narrates its fixture bindings instead of emitting a
// terminal JSON frame still qualifies: the frame is optional metadata, and the
// bound fixture evidence carries the same authority as the framed success path.
func TestCurrentProbeAcceptsNarratedAGYCapabilityWithoutTerminalFrame(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("agy-narrated")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(FamilyAgy, "kimi_current", "", "/private/bin/agy", "", key, "agy-narrated", []string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", 3*time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	fixture := &currentProbeFixture{root: root, identity: identity}
	narrated := []byte("Readiness confirmed. root=" + fixture.Nonce() + " link=" + fixture.Link() + " role=" + string(fixture.Role()) + "\n")
	runner := &agyCurrentProbeRunner{t: t, fixture: fixture, narrated: narrated}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)}, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: now, TTL: time.Minute})
	if err != nil {
		t.Fatalf("narrated AGY capability without a terminal frame was rejected: %v", err)
	}
	if len(runner.requests) != 2 || !runner.capabilityBound || !runner.capabilityLifecycle {
		t.Fatal("AGY probe did not issue a lifecycle-bound provider packet request")
	}
	wantKinds := map[string]struct{}{"workspace": {}, "manifest": {}, "namespace": {}, "environment": {}, "transport": {}, "native-reference": {}, "version": {}, "capability": {}, "base-role": {}, "assignment": {}, "direct-execution-authority": {}}
	if len(result.Receipts) != len(wantKinds) {
		t.Fatalf("receipt count = %d, want %d", len(result.Receipts), len(wantKinds))
	}
	for _, receipt := range result.Receipts {
		if _, ok := wantKinds[receipt.Kind]; !ok || !receipt.ExpiresAt.Equal(now.Add(time.Minute)) || receipt.EvidenceID == "" {
			t.Fatalf("invalid qualification receipt: %#v", receipt)
		}
		if receipt.Kind == "direct-execution-authority" {
			if receipt.DirectExecutionAuthority == nil || !receipt.DirectExecutionAuthority.Valid() || receipt.DirectExecutionAuthority.AuthorityID() == "" ||
				receipt.DirectExecutionAuthority.ExpiresAt() != receipt.ExpiresAt {
				t.Fatalf("invalid typed AGY direct-execution authority: %#v", receipt)
			}
			if controlID, ok := receipt.DirectExecutionAuthority.AGYControlAuthorityID(); !ok || controlID == "" {
				t.Fatalf("AGY direct authority omitted control authority: %#v", receipt)
			}
		} else if receipt.DirectExecutionAuthority != nil {
			t.Fatalf("non-authority receipt carried AGY direct-execution authority: %#v", receipt)
		}
		delete(wantKinds, receipt.Kind)
	}
	if len(wantKinds) != 0 {
		t.Fatalf("qualification receipts were not exact and unique: %v", wantKinds)
	}
}

// Narrated prose that never binds the fixture nonce, link, or role proves
// nothing: transport and lifecycle evidence already passed, so rejection is an
// operational capability failure, not a security violation.
func TestCurrentProbeRejectsUnboundEvidenceAsOperationalCapabilityFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("agy-unbound-evidence")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(FamilyAgy, "kimi_current", "", "/private/bin/agy", "", key, "agy-unbound-evidence", []string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", 3*time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	fixture := &currentProbeFixture{root: root, identity: identity}
	runner := &agyCurrentProbeRunner{t: t, fixture: fixture, narrated: []byte("I could not read the fixture.\n")}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.QualifyCurrent(context.Background(), CurrentProbeRequest{Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)}, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute})
	if err == nil {
		t.Fatal("capability evidence that never bound the fixture nonce, link, or role was accepted")
	}
	requireOperationalCapabilityMismatch(t, err)
}

// Narrated stdout that is exactly the fixture prompt packet is prompt echo:
// still an operational fixture-evidence mismatch, not a security violation.
func TestCurrentProbeRejectsPromptEchoAsOperationalCapabilityFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ports.ParseConcurrencyKey("agy-prompt-echo")
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, 13, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(FamilyAgy, "kimi_current", "", "/private/bin/agy", "", key, "agy-prompt-echo", []string{"/private/bin/agy"}, transport, lifecycle, nil, "/private/work", 3*time.Second, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	definition = currentProbeDefinitionWithExecutionIdentity(definition)
	fixture := &currentProbeFixture{root: root, identity: identity}
	runner := &agyCurrentProbeRunner{t: t, fixture: fixture, narrated: fixture.Packet()}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.QualifyCurrent(context.Background(), CurrentProbeRequest{Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t), nativeHome: currentProbeNativeHome(t)}, Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute})
	if err == nil {
		t.Fatal("prompt-echo capability evidence was accepted")
	}
	requireOperationalCapabilityMismatch(t, err)
}

// requireOperationalCapabilityMismatch asserts the typed failure shape owner
// decision D1 requires for a fixture-binding rejection: an operational
// invalid-output failure at the "capability" stage carrying the observation-
// mismatch diagnostic cause, explicitly not a security-policy violation.
func requireOperationalCapabilityMismatch(t *testing.T, err error) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureInvalidOutput || failure.Stage() != "capability" {
		t.Fatalf("operational capability mismatch failure = %v", err)
	}
	if failure.Class() == domain.FailureSecurityPolicy {
		t.Fatalf("capability evidence mismatch was classified as a security failure: %v", err)
	}
	requireProviderDiagnosticCause(t, err, domain.DiagnosticCauseObservationMismatch)
}

func TestValidateProbeTransportAndLifecycleSignalSequence(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("agy-lifecycle-sequence")
	if err != nil {
		t.Fatal(err)
	}
	transportPolicy, err := NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, 13, "@fixture.md")
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePolicy, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(
		FamilyAgy, "agy_lifecycle_sequence", "", "/private/bin/agy", "", key, "agy-lifecycle-sequence",
		[]string{"/private/bin/agy"}, transportPolicy, lifecyclePolicy, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("expected packet"))
	if err != nil {
		t.Fatal(err)
	}
	otherPacket, err := ports.NewProviderPacketFromBytes([]byte("other packet"))
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"result":true}`)
	frame, err := ports.NewProcessOutputFrameReceipt(lifecyclePolicy.Framing(), output, lifecyclePolicy.StabilityGrace())
	if err != nil {
		t.Fatal(err)
	}
	otherFrame, err := ports.NewProcessOutputFrameReceipt(lifecyclePolicy.Framing(), []byte(`{"result":false}`), lifecyclePolicy.StabilityGrace())
	if err != nil {
		t.Fatal(err)
	}
	type signalSpec struct {
		reason ports.ProcessGroupSignalRequestReason
		number int
		name   string
		packet ports.ProviderPacketIdentity
		frame  ports.ProcessOutputFrameReceipt
	}
	newReceipt := func(spec signalSpec) (ports.ProcessGroupSignalRequestReceipt, error) {
		signal, signalErr := ports.NewProcessSignal(spec.number, spec.name)
		if signalErr != nil {
			return ports.ProcessGroupSignalRequestReceipt{}, signalErr
		}
		if spec.reason == ports.ProcessGroupSignalRequestPostOutput {
			return ports.NewAcceptedPostOutputProcessGroupSignalRequestReceipt(signal, spec.packet, spec.frame)
		}
		return ports.NewAcceptedPostOutputEscalationProcessGroupSignalRequestReceipt(signal, spec.packet, spec.frame)
	}
	term := signalSpec{reason: ports.ProcessGroupSignalRequestPostOutput, number: 15, name: "SIGTERM", packet: packet.Identity(), frame: frame}
	kill := signalSpec{reason: ports.ProcessGroupSignalRequestPostOutputEscalation, number: 9, name: "SIGKILL", packet: packet.Identity(), frame: frame}
	cases := []struct {
		name                  string
		signals               []signalSpec
		exitCode              int
		wantLifecycleFailure  bool
		wantValidationFailure bool
		wantCause             domain.RuntimeDiagnosticCause
	}{
		{name: "natural exit"},
		{name: "term", signals: []signalSpec{term}},
		{name: "term then kill", signals: []signalSpec{term, kill}},
		{name: "failed natural exit", exitCode: 1},
		{name: "lone kill", signals: []signalSpec{kill}, wantLifecycleFailure: true},
		{name: "reverse", signals: []signalSpec{kill, term}, wantLifecycleFailure: true},
		{name: "duplicate term", signals: []signalSpec{term, term}, wantLifecycleFailure: true},
		{name: "duplicate kill", signals: []signalSpec{kill, kill}, wantLifecycleFailure: true},
		{name: "more than two", signals: []signalSpec{term, kill, kill}, wantLifecycleFailure: true},
		{name: "term reason escalation", signals: []signalSpec{{reason: ports.ProcessGroupSignalRequestPostOutputEscalation, number: 15, name: "SIGTERM", packet: packet.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "kill reason post output", signals: []signalSpec{term, {reason: ports.ProcessGroupSignalRequestPostOutput, number: 9, name: "SIGKILL", packet: packet.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "term number mismatch", signals: []signalSpec{{reason: ports.ProcessGroupSignalRequestPostOutput, number: 9, name: "SIGTERM", packet: packet.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "kill number mismatch", signals: []signalSpec{term, {reason: ports.ProcessGroupSignalRequestPostOutputEscalation, number: 15, name: "SIGKILL", packet: packet.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "term packet mismatch", signals: []signalSpec{{reason: ports.ProcessGroupSignalRequestPostOutput, number: 15, name: "SIGTERM", packet: otherPacket.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "kill packet mismatch", signals: []signalSpec{term, {reason: ports.ProcessGroupSignalRequestPostOutputEscalation, number: 9, name: "SIGKILL", packet: otherPacket.Identity(), frame: frame}}, wantValidationFailure: true},
		{name: "frame mismatch", signals: []signalSpec{{reason: ports.ProcessGroupSignalRequestPostOutput, number: 15, name: "SIGTERM", packet: packet.Identity(), frame: otherFrame}}, wantLifecycleFailure: true},
		{name: "kill frame mismatch", signals: []signalSpec{term, {reason: ports.ProcessGroupSignalRequestPostOutputEscalation, number: 9, name: "SIGKILL", packet: packet.Identity(), frame: otherFrame}}, wantLifecycleFailure: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			requests := make([]ports.ProcessGroupSignalRequestReceipt, 0, len(test.signals))
			for _, spec := range test.signals {
				receipt, receiptErr := newReceipt(spec)
				if receiptErr != nil {
					t.Fatal(receiptErr)
				}
				requests = append(requests, receipt)
			}
			final, finalErr := ports.NewExitedProcessFinalTermination(test.exitCode)
			if finalErr != nil {
				t.Fatal(finalErr)
			}
			lifecycle, lifecycleErr := ports.NewProcessLifecycleReceipt(final, true, requests, frame)
			if test.wantLifecycleFailure {
				if lifecycleErr == nil {
					t.Fatal("invalid signal sequence produced a lifecycle receipt")
				}
				return
			}
			if lifecycleErr != nil {
				t.Fatal(lifecycleErr)
			}
			transport, transportErr := ports.NewProviderPacketTransportReceipt(
				ports.ProviderPacketChannelPromptFile, packet.Identity(), "@fixture.md", "/private/work", packet.Identity(), packet.Identity(),
			)
			if transportErr != nil {
				t.Fatal(transportErr)
			}
			stdin, stdinErr := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
			if stdinErr != nil {
				t.Fatal(stdinErr)
			}
			observation, observationErr := ports.NewStartedProviderProcessObservation(
				output, nil, ports.ProcessTerminationExited, stdin, transport, lifecycle, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
			)
			if observationErr != nil {
				t.Fatal(observationErr)
			}
			err := validateProbeTransportAndLifecycle(definition, packet, observation)
			if (err != nil) != test.wantValidationFailure {
				t.Fatalf("validateProbeTransportAndLifecycle() error = %v, want failure %t", err, test.wantValidationFailure)
			}
			if test.wantValidationFailure {
				wantCause := test.wantCause
				if wantCause == "" {
					wantCause = domain.DiagnosticCauseSignalReceiptMismatch
				}
				requireProviderDiagnosticCause(t, err, wantCause)
			}
		})
	}
	final, err := ports.NewExitedProcessFinalTermination(1)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelPromptFile, packet.Identity(), "@fixture.md", "/private/work", packet.Identity(), packet.Identity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := ports.NewStartedProviderProcessObservation(
		nil, []byte("provider authentication failed"), ports.ProcessTerminationExited,
		stdin, transport, lifecycle, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProbeTransportAndLifecycle(definition, packet, failed); err != nil {
		t.Fatalf("terminal failed launch without an output frame was masked as transport failure: %v", err)
	}

	mismatchedFrame, err := ports.NewProcessOutputFrameReceipt(lifecyclePolicy.Framing(), []byte(`{"result":false}`), lifecyclePolicy.StabilityGrace())
	if err != nil {
		t.Fatal(err)
	}
	final, err = ports.NewExitedProcessFinalTermination(0)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, nil, mismatchedFrame)
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := ports.NewStartedProviderProcessObservation(
		output, nil, ports.ProcessTerminationExited, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	requireProviderDiagnosticCause(t, validateProbeTransportAndLifecycle(definition, packet, mismatched), domain.DiagnosticCauseOutputFrameMismatch)

	lifecycle, err = ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	withoutFrame, err := ports.NewStartedProviderProcessObservation(
		output, nil, ports.ProcessTerminationExited, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProbeTransportAndLifecycle(definition, packet, withoutFrame); err != nil {
		t.Fatalf("exit-0 AGY probe without a terminal frame was rejected: %v", err)
	}
}

// A terminal JSON frame is optional metadata, so a successful AGY capability
// probe that narrated its proof without emitting one still passes transport and
// lifecycle validation; the bound fixture evidence decides acceptance later.
func TestValidateProbeTransportAllowsFramelessSuccessfulAGYProbe(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("agy-frameless-success")
	if err != nil {
		t.Fatal(err)
	}
	transportPolicy, err := NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, 13, "@fixture.md")
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePolicy, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(
		FamilyAgy, "agy_frameless_success", "", "/private/bin/agy", "", key, "agy-frameless-success",
		[]string{"/private/bin/agy"}, transportPolicy, lifecyclePolicy, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("expected packet"))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewExitedProcessFinalTermination(0)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelPromptFile, packet.Identity(), "@fixture.md", "/private/work", packet.Identity(), packet.Identity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(
		[]byte("Readiness confirmed. root=nonce link=linked role=logic\n"), nil,
		ports.ProcessTerminationExited, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Succeeded() {
		t.Fatal("frameless AGY observation was not a successful probe")
	}
	if err := validateProbeTransportAndLifecycle(definition, packet, observation); err != nil {
		t.Fatalf("exit-0 AGY probe without a terminal frame was rejected: %v", err)
	}
}

func TestValidateProbeTransportWithoutLifecycle(t *testing.T) {
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyKimi, "kimi_current", "kimi-transport", "", ""))
	packet, err := ports.NewProviderPacketFromBytes([]byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(ports.ProviderPacketChannelArgvLiteral, packet.Identity(), "", "", ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation([]byte(`{"root":"nonce","link":"linked","role":"logic"}`), nil, ports.ProcessTerminationExited, stdin, transport, currentProbeExitedLifecycle(t), time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProbeTransportAndLifecycle(definition, packet, observation); err != nil {
		t.Fatalf("valid transport without lifecycle rejected: %v", err)
	}
	requireProviderDiagnosticCause(t,
		validateProbeTransportAndLifecycle(definition, packet, testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0)),
		domain.DiagnosticCauseTransportReceiptMismatch,
	)
}

func TestValidateProbeLifecyclePreservesNonPostOutputProcessFailure(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("agy-lifecycle-timeout")
	if err != nil {
		t.Fatal(err)
	}
	transportPolicy, err := NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, 13, "@fixture.md")
	if err != nil {
		t.Fatal(err)
	}
	lifecyclePolicy, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewRuntimeDefinitionWithTransportAndPostOutputLifecycle(
		FamilyAgy, "agy_lifecycle_timeout", "", "/private/bin/agy", "", key, "agy-lifecycle-timeout",
		[]string{"/private/bin/agy"}, transportPolicy, lifecyclePolicy, nil, "/private/work", time.Second, 4096, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("expected packet"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelPromptFile, packet.Identity(), "@fixture.md", "/private/work", packet.Identity(), packet.Identity(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	kill, err := ports.NewProcessSignal(9, "SIGKILL")
	if err != nil {
		t.Fatal(err)
	}
	teardown, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(ports.ProcessGroupSignalRequestInternalTeardown, kill)
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewSignaledProcessFinalTermination(kill)
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"partial":true}`)
	frame, err := ports.NewProcessOutputFrameReceipt(lifecyclePolicy.Framing(), output, lifecyclePolicy.StabilityGrace())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		output []byte
		frame  []ports.ProcessOutputFrameReceipt
	}{
		{name: "before frame"},
		{name: "after frame", output: output, frame: []ports.ProcessOutputFrameReceipt{frame}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle, lifecycleErr := ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{teardown}, test.frame...)
			if lifecycleErr != nil {
				t.Fatal(lifecycleErr)
			}
			observation, observationErr := ports.NewStartedProviderProcessObservation(
				test.output, nil, ports.ProcessTerminationTimedOut, stdin, transport, lifecycle,
				time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
			)
			if observationErr != nil {
				t.Fatal(observationErr)
			}
			if validationErr := validateProbeTransportAndLifecycle(definition, packet, observation); validationErr != nil {
				t.Fatalf("typed process failure was relabeled as lifecycle evidence failure: %v", validationErr)
			}
			requireProviderDiagnosticCause(t, qualificationProcessFailure(FamilyAgy, observation, context.DeadlineExceeded), domain.DiagnosticCauseTimedOut)
		})
	}
}

func TestAGYPermissionDiagnosticCannotMaskInvalidTransportEvidence(t *testing.T) {
	directory := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
	if err != nil {
		t.Fatal(err)
	}
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyAgy, "kimi_current", "agy-invalid-transport", "", ""))
	observation := testProcessObservation(
		t,
		nil,
		[]byte("tool permission was denied: read_file"),
		ports.ProcessTerminationExited,
		0,
	)
	requireProviderDiagnosticCause(
		t,
		validateProbeTransportAndLifecycle(definition, packet, observation),
		domain.DiagnosticCauseTransportReceiptMismatch,
	)
}

func requireProviderDiagnosticCause(t *testing.T, err error, want domain.RuntimeDiagnosticCause) {
	t.Helper()
	if cause, ok := providerDiagnosticCause(err); !ok || cause != want {
		t.Fatalf("provider diagnostic cause = %q, present=%t, want %q; err=%v", cause, ok, want, err)
	}
}

func TestControlledProbeJSONAcceptsExactOrSingleJSONFence(t *testing.T) {
	want := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	for _, input := range [][]byte{want, []byte("```json\n" + string(want) + "\n```\n")} {
		got, err := controlledProbeJSON(input)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("controlledProbeJSON(%q) = %q, %v", input, got, err)
		}
	}
	for _, invalid := range [][]byte{[]byte("before\n" + string(want)), []byte("```\n" + string(want) + "\n```"), []byte("```json\n" + string(want) + "\n```\nafter")} {
		if _, err := controlledProbeJSON(invalid); err == nil {
			t.Fatalf("controlledProbeJSON accepted %q", invalid)
		}
	}
}

func TestCurrentProbeEnvironmentReceiptEvidenceBindsNamespaceGeneration(t *testing.T) {
	runtimeID := "sha256:runtime"
	base := currentProbeEnvironmentReceiptEvidence{
		NamespaceGeneration: "generation-a",
		Values:              []string{"HOME=/private/namespace/home", "TMPDIR=/private/namespace/tmp"},
	}
	first, err := currentProbeEvidenceID("environment", runtimeID, base)
	if err != nil {
		t.Fatal(err)
	}
	otherGeneration := base
	otherGeneration.NamespaceGeneration = "generation-b"
	second, err := currentProbeEvidenceID("environment", runtimeID, otherGeneration)
	if err != nil {
		t.Fatal(err)
	}
	otherValues := base
	otherValues.Values = []string{"HOME=/private/namespace/home", "TMPDIR=/private/namespace/other"}
	third, err := currentProbeEvidenceID("environment", runtimeID, otherValues)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first == third || second == third {
		t.Fatal("environment receipt evidence did not bind namespace generation and effective values")
	}
}

func TestCurrentProbeDoesNotMintReceiptsWhenTransportValidationFails(t *testing.T) {
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyKimi, "kimi_current", "kimi-transport-failure", "", ""))
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	runner := &currentProbeRunner{observations: []ports.ProcessObservation{
		testProcessObservation(t, []byte("1.2.3\n"), nil, ports.ProcessTerminationExited, 0),
		testProcessObservation(t, []byte(`{"role":"assistant","content":"{\"root\":\"nonce\",\"link\":\"linked\",\"role\":\"logic\"}"}`), nil, ports.ProcessTerminationExited, 0),
	}}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t)},
		Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute,
	})
	if err == nil || len(result.Receipts) != 0 {
		t.Fatalf("transport failure minted qualification receipts: result=%#v err=%v", result, err)
	}
	requireProviderDiagnosticCause(t, err, domain.DiagnosticCauseTransportReceiptMismatch)
}

func TestCurrentProbeDirectExecutionAuthorityBindsCompleteRuntimeDefinition(t *testing.T) {
	definition, receipt := currentProbeAuthorityForDefinition(t)
	if !receipt.Matches(definition, "1.2.3", "generation", []domain.Role{domain.RoleLogic}) {
		t.Fatal("authority did not match its qualified definition")
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ports.ParseConcurrencyKey("different-current-probe-lane")
	if err != nil {
		t.Fatal(err)
	}
	otherTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	indexedTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelArgvLiteral, definition.TransportArgvIndex()+1, "")
	if err != nil {
		t.Fatal(err)
	}
	referencedTransport, err := NewRuntimeTransport(ports.ProviderPacketChannelPromptFile, 0, "@other.md")
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*RuntimeDefinition){
		"instance": func(d *RuntimeDefinition) { d.instance = "other-instance" },
		"argv":     func(d *RuntimeDefinition) { d.baseArgv = append(d.baseArgv, "--other") },
		"environment": func(d *RuntimeDefinition) {
			d.environment = append(d.environment, mustEnvironment(t, "MULGAE_TEST", "other"))
		},
		"policy":              func(d *RuntimeDefinition) { d.runtimeSafetyPolicyIdentity = "other-policy" },
		"transport":           func(d *RuntimeDefinition) { d.transport = otherTransport },
		"transport-index":     func(d *RuntimeDefinition) { d.transport = indexedTransport },
		"transport-reference": func(d *RuntimeDefinition) { d.transport = referencedTransport },
		"working-directory":   func(d *RuntimeDefinition) { d.workingDirectory = "/private/other" },
		"lifecycle-present":   func(d *RuntimeDefinition) { d.hasPostOutputLifecycle = true },
		"lifecycle-policy":    func(d *RuntimeDefinition) { d.postOutputLifecycle = lifecycle; d.hasPostOutputLifecycle = true },
		"timeout":             func(d *RuntimeDefinition) { d.timeout++ },
		"max-stdout":          func(d *RuntimeDefinition) { d.maxStdoutBytes++ },
		"max-stderr":          func(d *RuntimeDefinition) { d.maxStderrBytes++ },
		"executable":          func(d *RuntimeDefinition) { d.executable = "/private/bin/other-kimi" },
		"executable-sha256":   func(d *RuntimeDefinition) { d.executableSHA256 = "sha256:other" },
		"launcher":            func(d *RuntimeDefinition) { d.launcher = "/private/bin/other-launcher" },
		"launcher-sha256":     func(d *RuntimeDefinition) { d.launcherSHA256 = "sha256:other-launcher" },
		"concurrency-key":     func(d *RuntimeDefinition) { d.concurrencyKey = otherKey },
		"workspace-authority": func(d *RuntimeDefinition) { d.requiresWorkspaceAuthority = !d.requiresWorkspaceAuthority },
		"spawn-verification":  func(d *RuntimeDefinition) { d.requiresSpawnVerification = !d.requiresSpawnVerification },
		"explicit-transport":  func(d *RuntimeDefinition) { d.productionExplicitTransport = !d.productionExplicitTransport },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := definition
			mutate(&mutated)
			if receipt.Matches(mutated, "1.2.3", "generation", []domain.Role{domain.RoleLogic}) {
				t.Fatal("authority accepted mutated runtime definition")
			}
		})
	}
}

func currentProbeAuthorityForDefinition(t *testing.T) (RuntimeDefinition, CurrentProbeDirectExecutionAuthorityReceipt) {
	t.Helper()
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyKimi, "kimi_current", "kimi-authority", "", ""))
	directory := filepath.Join(t.TempDir(), "snapshot-0123456789abcdef0123456789abcdef")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(directory, identity)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{root: root, identity: identity}
	runner := &currentProbeRunner{observations: []ports.ProcessObservation{
		testProcessObservation(t, []byte("1.2.3\n"), nil, ports.ProcessTerminationExited, 0),
		currentProbeCapabilityObservation(t, fixture, []byte(`{"role":"assistant","content":"{\"root\":\"nonce\",\"link\":\"linked\",\"role\":\"logic\"}"}`)),
	}}
	probe, err := NewCurrentProbe(runner, &currentProbeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: definition, Namespace: currentProbeNamespace{environment: currentProbeEnvironment(t)},
		Fixture: fixture, Invocation: NativeProbeInvocation{}, Now: time.Now().UTC(), TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Receipts {
		if item.Kind == "direct-execution-authority" && item.DirectExecutionAuthority != nil {
			return definition, *item.DirectExecutionAuthority
		}
	}
	t.Fatal("qualification omitted direct-execution authority")
	return RuntimeDefinition{}, CurrentProbeDirectExecutionAuthorityReceipt{}
}

type agyCurrentProbeRunner struct {
	t                   *testing.T
	fixture             *currentProbeFixture
	requests            []ports.ProcessRequest
	capabilityBound     bool
	capabilityLifecycle bool
	permissionDenied    bool
	// narrated, when set, makes the capability launch succeed with narrated
	// prose on stdout and no terminal JSON frame in its lifecycle receipt.
	narrated []byte
}

func (r *agyCurrentProbeRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.t.Helper()
	r.requests = append(r.requests, request)
	file, _, ok := request.BoundLaunchDirectory()
	if !ok {
		r.t.Fatal("request was not descriptor-bound")
	}
	if authority, ok := request.NativeHomeLaunchAuthority(); !ok || authority.Path() != "/private/home" {
		r.t.Fatal("AGY qualification spawn omitted native-home authority")
	}
	_ = file.Close()
	if len(r.requests) == 1 {
		return testProcessObservation(r.t, []byte("1.2.3\n"), nil, ports.ProcessTerminationExited, 0), nil
	}
	binding, ok := request.ProviderPacketBinding()
	lifecycle, lifecycleOK := request.PostOutputLifecycle()
	nativeReference := "@" + r.fixture.Reference()
	r.capabilityBound, r.capabilityLifecycle = ok && binding.Valid(), lifecycleOK && lifecycle.Valid()
	if !r.capabilityBound || !r.capabilityLifecycle {
		r.t.Fatal("capability request omitted packet binding or lifecycle")
	}
	if binding.Channel() != ports.ProviderPacketChannelPromptFile ||
		binding.PromptFileReference() != nativeReference ||
		binding.ArgvIndex() != 13 ||
		binding.SnapshotCWD() != r.fixture.WorkspaceSnapshotIdentity().SnapshotPath() {
		r.t.Fatal("capability request omitted the native prompt-file binding")
	}
	if binding.ArgvIndex() >= len(request.Argv()) || request.Argv()[binding.ArgvIndex()] != nativeReference {
		r.t.Fatal("native prompt-file reference is not at the bound argv index")
	}
	if r.permissionDenied {
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(final, true, nil)
		if err != nil {
			r.t.Fatal(err)
		}
		transport, err := ports.NewProviderPacketTransportReceipt(binding.Channel(), binding.PacketIdentity(), binding.PromptFileReference(), binding.SnapshotCWD(), binding.PacketIdentity(), binding.PacketIdentity())
		if err != nil {
			r.t.Fatal(err)
		}
		stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
		if err != nil {
			r.t.Fatal(err)
		}
		observation, err := ports.NewStartedProviderProcessObservation(nil, []byte("tool permission was denied: read_file"), ports.ProcessTerminationExited, stdin, transport, lifecycleReceipt, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
		if err != nil {
			r.t.Fatal(err)
		}
		return observation, nil
	}
	if len(r.narrated) > 0 {
		final, err := ports.NewExitedProcessFinalTermination(0)
		if err != nil {
			r.t.Fatal(err)
		}
		lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(final, true, nil)
		if err != nil {
			r.t.Fatal(err)
		}
		transport, err := ports.NewProviderPacketTransportReceipt(binding.Channel(), binding.PacketIdentity(), binding.PromptFileReference(), binding.SnapshotCWD(), binding.PacketIdentity(), binding.PacketIdentity())
		if err != nil {
			r.t.Fatal(err)
		}
		stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
		if err != nil {
			r.t.Fatal(err)
		}
		observation, err := ports.NewStartedProviderProcessObservation(r.narrated, nil, ports.ProcessTerminationExited, stdin, transport, lifecycleReceipt, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
		if err != nil {
			r.t.Fatal(err)
		}
		return observation, nil
	}
	output := []byte(`{"root":"nonce","link":"linked","role":"logic"}`)
	frame, err := ports.NewProcessOutputFrameReceipt(lifecycle.Framing(), output, lifecycle.StabilityGrace())
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
	lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{signalReceipt}, frame)
	if err != nil {
		r.t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(binding.Channel(), binding.PacketIdentity(), binding.PromptFileReference(), binding.SnapshotCWD(), binding.PacketIdentity(), binding.PacketIdentity())
	if err != nil {
		r.t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		r.t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(output, nil, ports.ProcessTerminationExited, stdin, transport, lifecycleReceipt, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
	if err != nil {
		r.t.Fatal(err)
	}
	return observation, nil
}
func TestVersionAtLeastHonorsAGYFloorPrereleaseAndBuildMetadata(t *testing.T) {
	for version, want := range map[string]bool{
		"1.1.3":       false,
		"1.1.4-beta":  false,
		"1.1.4":       true,
		"1.1.4+build": true,
		"1.1.5":       true,
		"1.2.0":       true,
	} {
		if got := VersionAtLeast(version, 1, 1, 4); got != want {
			t.Fatalf("VersionAtLeast(%q) = %t, want %t", version, got, want)
		}
	}
}

func TestValidateProbeEvidenceRequiresPositiveCapabilityOnly(t *testing.T) {
	fixture := &currentProbeFixture{}
	if err := validateProbeEvidence([]byte(`{"root":"nonce","link":"linked","role":"logic"}`), fixture); err != nil {
		t.Fatalf("positive capability evidence rejected: %v", err)
	}
	if err := validateProbeEvidence([]byte("Readiness confirmed with root=nonce link=linked role=logic after transport."), fixture); err != nil {
		t.Fatalf("narrated evidence rejected: %v", err)
	}
	for _, output := range [][]byte{
		[]byte(`{"root":"nonce","link":"linked"}`),
		[]byte(`{"root":"nonce","link":"linked","role":"logic","missing":"denied"}`),
		[]byte(`{"root":"nonce","link":"linked","role":"logic","command":"denied"}`),
		[]byte(fixture.Packet()),
		[]byte("only echoed the prompt without bindings"),
	} {
		if err := validateProbeEvidence(output, fixture); err == nil {
			t.Fatalf("invalid evidence accepted: %s", output)
		}
	}
}
func TestNativeProbeInvocationFamilyPolicy(t *testing.T) {
	directory := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(directory, "snapshot-0123456789abcdef0123456789abcdef", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &currentProbeFixture{identity: identity}
	for family, want := range map[string][]string{
		FamilyKimi:  {"--model", "kimi-code/kimi-for-coding", "--prompt", "fixture", "--output-format", "stream-json"},
		FamilyZcode: {"--mode", "plan", "--no-color", "--prompt", "fixture", "--json", "--disallowed-tools", zcodeCapabilityDisallowedTools},
		FamilyAgy:   {"--new-project", "--sandbox", "--add-dir", directory, "--mode", "plan", "--effort", "low", "--print-timeout", "500ms", "--print", "@roadmap.md", "--output-format", "json", "--json-schema", agyQualificationJSONSchema},
	} {
		definition := testProfile(t, family, "kimi_current", "lane", "", "")
		argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, fixture)
		if err != nil || !reflect.DeepEqual(argv[len(definition.BaseArgv()):], want) {
			t.Fatalf("%s argv=%q err=%v", family, argv, err)
		}
	}
}

func TestAgyQualificationStructuredOutputIsSeparateFromReviewContent(t *testing.T) {
	frame := []byte(`{"status":"success","response":"completed","structured_output":{"root":"nonce","link":"linked","role":"logic"}}`)
	if got := string(agyReviewResultText(frame)); got != "completed" {
		t.Fatalf("agyReviewResultText() = %q, want historical response", got)
	}
	if got := string(agyQualificationStructuredOutput(frame)); got != `{"root":"nonce","link":"linked","role":"logic"}` {
		t.Fatalf("agyQualificationStructuredOutput() = %q", got)
	}
	nested := []byte(`{"result":{"structured_output":"{\"root\":\"nonce\",\"link\":\"linked\",\"role\":\"logic\"}"}}`)
	if got := string(agyQualificationStructuredOutput(nested)); got != `{"root":"nonce","link":"linked","role":"logic"}` {
		t.Fatalf("nested agyQualificationStructuredOutput() = %q", got)
	}
}

func currentProbeNativeHome(t *testing.T) ports.NativeHomeLaunchAuthority {
	t.Helper()
	authority, err := ports.NewNativeHomeLaunchAuthority("/private/home", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
func currentProbeEnvironment(t *testing.T) []ports.EnvironmentVariable {
	t.Helper()
	return []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/private/home"), mustEnvironment(t, "XDG_CONFIG_HOME", "/private/settings"), mustEnvironment(t, "XDG_DATA_HOME", "/private/auth"), mustEnvironment(t, "XDG_CACHE_HOME", "/private/cache"), mustEnvironment(t, "TMPDIR", "/private/tmp"), mustEnvironment(t, "TMP", "/private/tmp"), mustEnvironment(t, "TEMP", "/private/tmp"), mustEnvironment(t, "MULGAE_PROVIDER_SCRATCH", "/private/scratch")}
}
func TestCurrentProbeRejectsPairwiseRoleWorkspaceReuseBeforeLaunch(t *testing.T) {
	baseIdentity, err := ports.NewWorkspaceSnapshotIdentity("fixture-root-base", "snapshot-00000000000000000000000000000000", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	sharedIdentity, err := ports.NewWorkspaceSnapshotIdentity("fixture-root-shared", "snapshot-11111111111111111111111111111111", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "policy", 5, 6, 7, 8)
	if err != nil {
		t.Fatal(err)
	}
	runner := &currentProbeRunner{}
	verifier := &currentProbeVerifier{}
	probe, err := NewCurrentProbe(runner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.QualifyCurrent(context.Background(), CurrentProbeRequest{
		Definition: testProfile(t, FamilyKimi, "kimi_current", "kimi-current", "", ""),
		Namespace:  currentProbeNamespace{environment: currentProbeEnvironment(t)},
		Fixture:    &currentProbeFixture{identity: baseIdentity, role: domain.RoleLogic},
		RoleFixtures: []ProbeFixtureLease{
			&currentProbeFixture{identity: sharedIdentity, role: domain.RoleSecurity},
			&currentProbeFixture{identity: sharedIdentity, role: domain.RoleMaintainability},
		},
		Invocation: NativeProbeInvocation{},
		Now:        time.Now().UTC(),
		TTL:        time.Minute,
	})
	if err == nil || len(runner.requests) != 0 || verifier.calls != 0 || len(result.Receipts) != 0 {
		t.Fatalf("result=%#v err=%v launches=%d verifier=%d", result, err, len(runner.requests), verifier.calls)
	}
}
