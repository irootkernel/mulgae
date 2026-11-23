package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestQualificationPreservesConfigurationFailureWithoutRetryClassification(t *testing.T) {
	failure, err := domain.NewFailure("zcode_model_selection", domain.FailureConfiguration, "selected ZCode model is unavailable", errZCodeSelectedModelUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	processed := qualificationProcessFailure(FamilyZcode, ports.ProcessObservation{}, failure)
	if processed != failure {
		t.Fatalf("qualification process failure = %v, want original configuration failure", processed)
	}
	classified := classifyProbeFailure(context.Background(), FamilyZcode, processed, []byte("provider unavailable"))
	if classified != failure {
		t.Fatalf("classified failure = %v, want original configuration failure", classified)
	}
}

func TestClassifyGrokTerminalProbeFailurePreservesQuotaAndLoginAndBlocksSecurityOverride(t *testing.T) {
	t.Run("quota balance exhausted on terminal error", func(t *testing.T) {
		observation := protocolTeardownObservationWithStderr(
			t,
			nil,
			[]byte("ERROR responses API error status=402 Payment Required error_message=Grok Build usage balance exhausted"),
		)
		driverErr := newTerminalDriverFailure(
			ports.ProviderExecutionStatusQuota,
			"provider_quota_exceeded",
			domain.DiagnosticCauseQuotaExceeded,
			"",
			errors.New("terminal program reported quota exhaustion"),
		)
		processed := qualificationProcessFailure(FamilyGrok, observation, driverErr)
		requireProviderDiagnosticCause(t, processed, domain.DiagnosticCauseQuotaExceeded)
		classified := classifyProbeFailure(context.Background(), FamilyGrok, processed, observation.Stderr(), observation.Stdout())
		var failure *domain.Failure
		if !errors.As(classified, &failure) || failure.Class() != domain.FailureQuota {
			t.Fatalf("Grok quota probe failure = %#v, want %q", failure, domain.FailureQuota)
		}
		requireProviderDiagnosticCause(t, classified, domain.DiagnosticCauseQuotaExceeded)
	})
	t.Run("login required on terminal error", func(t *testing.T) {
		observation := protocolTeardownObservationWithStderr(
			t,
			nil,
			[]byte(`{"code":"auth.login_required","message":"login first"}`),
		)
		driverErr := newTerminalDriverFailure(
			ports.ProviderExecutionStatusAuthentication,
			"provider_login_required",
			domain.DiagnosticCauseLoginRequired,
			"",
			ports.ErrProviderLoginRequired,
		)
		processed := qualificationProcessFailure(FamilyGrok, observation, driverErr)
		requireProviderDiagnosticCause(t, processed, domain.DiagnosticCauseLoginRequired)
		classified := classifyProbeFailure(context.Background(), FamilyGrok, processed, observation.Stderr(), observation.Stdout())
		var failure *domain.Failure
		if !errors.As(classified, &failure) || failure.Class() != domain.FailureAuthentication || !errors.Is(classified, ports.ErrProviderLoginRequired) {
			t.Fatalf("Grok login-required probe failure = %v", classified)
		}
		requireProviderDiagnosticCause(t, classified, domain.DiagnosticCauseLoginRequired)
	})
	t.Run("screen tokens never override security or staging failure", func(t *testing.T) {
		observation := protocolTeardownObservationWithStderr(
			t,
			[]byte(`{"code":"auth.login_required","message":"spoofed screen token"}`),
			[]byte("ERROR status=402 Payment Required usage balance exhausted"),
		)
		for _, tc := range []struct {
			name      string
			driverErr *terminalDriverFailure
			wantClass domain.FailureClass
			wantCause domain.RuntimeDiagnosticCause
		}{
			{
				name: "security violation",
				driverErr: newTerminalDriverFailure(
					ports.ProviderExecutionStatusSecurityViolation,
					"provider_output_staging_violation",
					domain.DiagnosticCauseProviderOutputStagingViolation,
					"",
					errors.New("staged output violated security boundary"),
				),
				wantClass: domain.FailureSecurityPolicy,
				wantCause: domain.DiagnosticCauseProviderOutputStagingViolation,
			},
			{
				name: "staging missing",
				driverErr: newTerminalDriverFailure(
					ports.ProviderExecutionStatusUnavailable,
					"provider_output_file_missing",
					domain.DiagnosticCauseProviderOutputFileMissing,
					"",
					errors.New("staged output missing"),
				),
				wantClass: domain.FailureInvalidOutput,
				wantCause: domain.DiagnosticCauseProviderOutputFileMissing,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				processed := qualificationProcessFailure(FamilyGrok, observation, tc.driverErr)
				requireProviderDiagnosticCause(t, processed, tc.wantCause)
				classified := classifyProbeFailure(context.Background(), FamilyGrok, processed, observation.Stderr(), observation.Stdout())
				var failure *domain.Failure
				if !errors.As(classified, &failure) || failure.Class() != tc.wantClass {
					t.Fatalf("%s classified = %v (class %v), want class %s", tc.name, classified, failure, tc.wantClass)
				}
				requireProviderDiagnosticCause(t, classified, tc.wantCause)
			})
		}
	})
}

type currentProbeNamespace struct {
	environment []ports.EnvironmentVariable
	nativeHome  ports.NativeHomeLaunchAuthority
	instance    string
}

func (namespace currentProbeNamespace) ProviderInstance() string {
	if namespace.instance != "" {
		return namespace.instance
	}
	return "zcode_current"
}
func (currentProbeNamespace) Generation() string { return "generation" }
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
	// protocol, when set, is driven by Converse so protocol-channel tests
	// exercise the real session driver against a scripted exchange.
	protocol ports.ProviderSessionExchange
}

type trackingContentLease struct {
	identity ports.ContentIdentity
	body     []byte
	closes   int
	closeErr error
}

func newTrackingContentLease(t *testing.T, body []byte) *trackingContentLease {
	t.Helper()
	digest := sha256.Sum256(body)
	identity, err := ports.NewContentIdentity("sha256:"+hex.EncodeToString(digest[:]), int64(len(body)), "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	return &trackingContentLease{identity: identity, body: append([]byte(nil), body...)}
}

func (lease *trackingContentLease) Identity() ports.ContentIdentity { return lease.identity }
func (lease *trackingContentLease) Open(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(lease.body)), nil
}
func (lease *trackingContentLease) Close() error {
	lease.closes++
	return lease.closeErr
}

func observationWithTrackingLease(t *testing.T, observation ports.ProcessObservation) (ports.ProcessObservation, *trackingContentLease) {
	t.Helper()
	lease := newTrackingContentLease(t, observation.Stdout())
	bound, err := ports.NewProcessObservationWithStdoutArtifact(observation, lease, false)
	if err != nil {
		t.Fatal(err)
	}
	return bound, lease
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

func (r *currentProbeRunner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	observation, err := r.Run(ctx, request)
	if err != nil || r.protocol == nil {
		return observation, err
	}
	if driveErr := driver.Drive(ctx, r.protocol); driveErr != nil {
		return observation, driveErr
	}
	return observation, nil
}

// scriptedProtocolExchange serves recorded server lines and records every
// client line for one ZCode Protocol conversation.
type scriptedProtocolExchange struct {
	lines  chan []byte
	sentMu sync.Mutex
	sent   [][]byte
}

func newScriptedProtocolExchange(serverLines ...string) *scriptedProtocolExchange {
	exchange := &scriptedProtocolExchange{lines: make(chan []byte, len(serverLines))}
	for _, line := range serverLines {
		exchange.lines <- []byte(line)
	}
	close(exchange.lines)
	return exchange
}

func (exchange *scriptedProtocolExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	select {
	case line, ok := <-exchange.lines:
		if !ok {
			return nil, io.EOF
		}
		return line, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (exchange *scriptedProtocolExchange) SendLine(_ context.Context, line []byte) error {
	exchange.sentMu.Lock()
	defer exchange.sentMu.Unlock()
	exchange.sent = append(exchange.sent, append([]byte(nil), line...))
	return nil
}

func (exchange *scriptedProtocolExchange) CloseInput(context.Context) error {
	return nil
}

// sentLines returns a caller-owned copy of every recorded client line.
func (exchange *scriptedProtocolExchange) sentLines(t *testing.T) [][]byte {
	t.Helper()
	exchange.sentMu.Lock()
	defer exchange.sentMu.Unlock()
	return append([][]byte(nil), exchange.sent...)
}

// zcodeProtocolScript builds one complete happy-path server script whose
// assistant message carries the given proof text.
func zcodeProtocolScript(proof string) *scriptedProtocolExchange {
	return newScriptedProtocolExchange(
		`{"id":"server-1","method":"session/requestRuntimePreferences","params":{"sessionId":"sess_script","scope":"runtime-materialization"}}`,
		`{"id":"mulgae-create","result":{"session":{"sessionId":"sess_script"}}}`,
		`{"id":"mulgae-send","result":{"accepted":true,"sessionId":"sess_script","stateRevision":1}}`,
		`{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_script"}}`,
		`{"id":"mulgae-messages","result":{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":`+strconv.Quote(proof)+`}]},{"info":{"role":"user"},"parts":[{"type":"text","text":"prompt"}]}]}}`,
		`{"id":"mulgae-close","result":{"closed":true}}`,
	)
}

func TestCapabilityResponseClassifiesNativeFailureWithoutWeakeningProof(t *testing.T) {
	fixture := &currentProbeFixture{role: domain.RoleLogic}
	for _, test := range []struct {
		name, output, stderr string
		class                domain.FailureClass
		cause                domain.RuntimeDiagnosticCause
	}{
		{"quota", "quota_exceeded", "", domain.FailureQuota, domain.DiagnosticCauseQuotaExceeded},
		{"rate limit", "rate limit exceeded", "", domain.FailureRateLimit, domain.DiagnosticCauseRateLimited},
		{"turn failure", "", "turn execution failed", domain.FailureProviderUnavailable, domain.DiagnosticCauseProviderTurnFailed},
		{"wrong proof", `{"root":"wrong","link":"linked","role":"logic"}`, "", domain.FailureInvalidOutput, domain.DiagnosticCauseObservationMismatch},
		{"valid proof", `{"root":"nonce","link":"linked","role":"logic"}`, "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := acceptCapabilityResponse(context.Background(), FamilyZcode, []byte(test.output), []byte(test.stderr), fixture)
			if test.class == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if cause, ok := providerDiagnosticCause(err); !ok || cause != test.cause {
				t.Fatalf("cause = %s, want %s", cause, test.cause)
			}
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != test.class {
				t.Fatalf("failure = %v, want %s", err, test.class)
			}
		})
	}
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

func currentProbeCapabilityProtocolObservation(t *testing.T, fixture *currentProbeFixture, output []byte) ports.ProcessObservation {
	t.Helper()
	packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelProtocol, packet.Identity(), "", "",
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
		output, nil, ports.ProcessTerminationExited, stdin, transport, currentProbeExitedLifecycle(t),
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
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
	if definition.Family() == FamilyZcode {
		definition.zcodeProviderConfig = "/private/config/zcode-builtin.json"
		definition.zcodeProviderConfigSHA256 = "sha256:" + strings.Repeat("a", 64)
		definition.applicationVersion = "3.12.3"
		definition.applicationMetadata = "/Applications/ZCode.app/Contents/Info.plist"
		definition.applicationMetadataSHA256 = "sha256:" + strings.Repeat("b", 64)
		providerConfig, _ := ports.NewEnvironmentVariable("ZCODE_BUILTIN_PROVIDER_CONFIG_FILE", definition.zcodeProviderConfig)
		definition.environment = append(definition.environment, providerConfig)
	}
	return definition
}

// Narrated prose that never binds the fixture nonce, link, or role proves
// nothing: transport and lifecycle evidence already passed, so rejection is an
// operational capability failure, not a security violation.
// Narrated stdout that is exactly the fixture prompt packet is prompt echo:
// still an operational fixture-evidence mismatch, not a security violation.
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

func TestZCodeCapabilityUsesProtocolTransport(t *testing.T) {
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newTestProfileWithTransport(t, FamilyZcode, "zcode_current", []string{"/private/bin/zcode"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes([]byte("fixture packet"))
	if err != nil {
		t.Fatal(err)
	}
	argv := appendZcodeProtocolServerArgv(definition.BaseArgv())
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest(definition.Executable(), argv, nil, "/private/work", binding, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Stdin()) != 0 || packetOccurrences(request.Argv(), string(packet.Bytes())) != 0 {
		t.Fatalf("ZCode capability packet binding = argv %q stdin %q", request.Argv(), request.Stdin())
	}
}

func TestCurrentProbeReleasesProtocolTranscript(t *testing.T) {
	root, identity := testWorkspaceRoot(t)
	fixture := &currentProbeFixture{root: root, identity: identity, role: domain.RoleLogic}
	observation, lease := observationWithTrackingLease(t, currentProbeCapabilityProtocolObservation(t, fixture, []byte("protocol transcript")))
	runner := &currentProbeRunner{observations: []ports.ProcessObservation{observation}, protocol: newScriptedProtocolExchange(
		protocolCreateResult,
		protocolSendAck,
		protocolTurnDone,
		protocolMessagesResult(`{"root":"nonce","link":"linked","role":"logic"}`),
		protocolCloseResult,
	)}
	verifier := &currentProbeVerifier{}
	probe, err := NewCurrentProbe(runner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := newTestProfileWithTransport(t, FamilyZcode, "zcode_current", []string{"/private/bin/zcode"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacketFromBytes(fixture.Packet())
	if err != nil {
		t.Fatal(err)
	}
	argv := appendZcodeProtocolServerArgv(definition.BaseArgv())
	if _, _, _, _, _, err := probe.runBound(context.Background(), definition, currentProbeNamespace{instance: "zcode_current"}, fixture, argv, nil, time.Second, &packet, ""); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatalf("protocol transcript closes = %d, want 1", lease.closes)
	}
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

func currentProbeAuthorityForDefinition(t *testing.T) (RuntimeDefinition, CurrentProbeDirectExecutionAuthorityReceipt) {
	t.Helper()
	definition := currentProbeDefinitionWithExecutionIdentity(testProfile(t, FamilyZcode, "zcode_current", "", ""))
	proof := currentProbeDirectExecutionTestProof()
	proof.Family = definition.Family()
	proof.ProviderInstance = definition.Instance()
	proof.ProviderVersion = definition.Version()
	proof.ObservedVersion = "1.2.3"
	proof.Executable = definition.Executable()
	proof.ExecutableSHA256 = definition.ExecutableSHA256()
	proof.Launcher = definition.Launcher()
	proof.LauncherSHA256 = definition.LauncherSHA256()
	proof.ZCodeProviderConfig = definition.ZCodeProviderConfig()
	proof.ZCodeProviderConfigSHA256 = definition.ZCodeProviderConfigSHA256()
	proof.ApplicationVersion = definition.ApplicationVersion()
	proof.ApplicationMetadata = definition.ApplicationMetadata()
	proof.ApplicationMetadataSHA256 = definition.ApplicationMetadataSHA256()
	proof.ProfileID = definition.ProfileID()
	proof.ProfileGeneration = definition.ProfileGeneration()
	receipt, err := newCurrentProbeDirectExecutionAuthorityReceiptForDefinition([]currentProbeDirectExecutionRoleProof{proof}, time.Now().UTC().Add(time.Minute), definition)
	if err != nil {
		t.Fatal(err)
	}
	return definition, receipt
}

func TestPlainSemverAcceptsExactGrokCLIIdentity(t *testing.T) {
	for _, valid := range []struct {
		output string
		want   string
	}{
		{"grok 1.0.89 (a1b2c3d)", "1.0.89"},
		{"grok 1.0.89 (28be5bb1bf65) [stable]", "1.0.89"},
		{"grok 1.0.89 (a1b2c3d) [beta]", "1.0.89"},
		{"grok 1.0.89 (a1b2c3d) [rc.1_test]", "1.0.89"},
		{"grok 1.0.90 (a1b2c3d) [beta]", "1.0.90"},
	} {
		observation := testProcessObservation(t, []byte(valid.output+"\n"), nil, ports.ProcessTerminationExited, 0)
		if got, err := plainSemver(FamilyGrok, observation); err != nil || got != valid.want {
			t.Fatalf("Grok version %q = %q, %v; want %q", valid.output, got, err, valid.want)
		}
	}
	for _, invalid := range []string{
		"1.0.89",
		"grok 1.0.89",
		"grok 1.0.89 (A1B2)",
		"grok 1.0.89 (a1b2c3d) []",
		"grok 1.0.89 (a1b2c3d) [bad tag]",
		"grok 1.0.89 (a1b2c3d) [stable] extra",
		"grok 1.0.89 (a1b2c3d)[stable]",
		"grok 1.0.30 (a1b2c3d)",
		"grok 1.0.40 (eb1a2256660d) [stable]",
	} {
		candidate := testProcessObservation(t, []byte(invalid+"\n"), nil, ports.ProcessTerminationExited, 0)
		if _, err := plainSemver(FamilyGrok, candidate); err == nil {
			t.Fatalf("invalid Grok version output %q was accepted", invalid)
		}
	}
}

func TestValidateProbeEvidenceRequiresPositiveCapabilityOnly(t *testing.T) {
	fixture := &currentProbeFixture{}
	if err := validateProbeEvidence([]byte(`{"root":"nonce","link":"linked","role":"logic"}`), fixture); err != nil {
		t.Fatalf("positive capability evidence rejected: %v", err)
	}
	if err := validateProbeEvidence([]byte(`{"root":"nonce","link":"linked","role":"logic","provider_note":"ignored"}`), fixture); err != nil {
		t.Fatalf("positive capability evidence with an unknown field rejected: %v", err)
	}
	if err := validateProbeEvidence([]byte("Readiness confirmed with root=nonce link=linked role=logic after transport."), fixture); err != nil {
		t.Fatalf("narrated evidence rejected: %v", err)
	}
	for _, output := range [][]byte{
		[]byte(`{"root":"nonce","link":"linked"}`),
		[]byte(`{"root":"nonce","link":"linked","role":1}`),
		[]byte(`{"root":"nonce","root":"other","link":"linked","role":"logic"}`),
		[]byte(`{"root":"nonce","link":"linked","role":"logic","nested":{"key":1,"key":2}}`),
		[]byte(`{"root":"nonce","link":"linked","role":"logic"`),
		[]byte(fixture.Packet()),
		[]byte("only echoed the prompt without bindings"),
	} {
		if err := validateProbeEvidence(output, fixture); err == nil {
			t.Fatalf("invalid evidence accepted: %s", output)
		}
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

func TestClassifyProbeFailurePreservesExplicitLoginRequired(t *testing.T) {
	err := classifyProbeFailure(
		context.Background(),
		FamilyGrok,
		errors.New("provider exited"),
		[]byte(`{"code":"auth.login_required","message":"login first"}`),
	)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureAuthentication ||
		!errors.Is(err, ports.ErrProviderLoginRequired) {
		t.Fatalf("login-required probe failure = %v", err)
	}
}

func TestClassifyProbeFailureUsesTypedProcessCauseWithoutStderr(t *testing.T) {
	for _, test := range []struct {
		cause domain.RuntimeDiagnosticCause
		class domain.FailureClass
	}{
		{domain.DiagnosticCauseTimedOut, domain.FailureTimeout},
		{domain.DiagnosticCauseRateLimited, domain.FailureRateLimit},
		{domain.DiagnosticCauseQuotaExceeded, domain.FailureQuota},
		{domain.DiagnosticCausePermissionDenied, domain.FailureAuthentication},
		{domain.DiagnosticCauseProviderExecutionFailed, domain.FailureProviderUnavailable},
	} {
		err := classifyProbeFailure(context.Background(), FamilyGrok, newProviderOutputFailure(test.cause, errors.New("provider process failed")), nil)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != test.class {
			t.Fatalf("typed cause %q projected as %#v, want %q", test.cause, failure, test.class)
		}
	}
}

func TestQualificationProcessFailurePreservesExecutionStage(t *testing.T) {
	observation := testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 1)
	err := qualificationProcessFailure(FamilyGrok, observation, errors.New("capability probe failed"))
	var failure *providerOutputFailure
	if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCauseProviderExecutionFailed {
		t.Fatalf("qualification process failure = %#v, err=%v", failure, err)
	}
}

func TestQualificationInterruptionOutranksConcurrentExchangeFailure(t *testing.T) {
	for _, test := range []struct {
		name        string
		termination ports.ProcessTermination
		want        error
		cause       domain.RuntimeDiagnosticCause
	}{
		{name: "cancelled", termination: ports.ProcessTerminationCancelled, want: context.Canceled},
		{name: "timed out", termination: ports.ProcessTerminationTimedOut, cause: domain.DiagnosticCauseTimedOut},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := qualificationInterruptionFailure(protocolInterruptedObservation(t, test.termination), ports.ErrProviderSessionExchangeClosed)
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("interruption error = %v, want %v", err, test.want)
			}
			if test.termination == ports.ProcessTerminationTimedOut && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("process-local timeout inherited enclosing deadline identity: %v", err)
			}
			if test.cause != "" {
				if cause, ok := providerDiagnosticCause(err); !ok || cause != test.cause {
					t.Fatalf("interruption cause = %q/%t, want %q", cause, ok, test.cause)
				}
			}
		})
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
		qualificationProcessFailure(FamilyGrok, observation, processErr),
		domain.DiagnosticCausePromptFilePostEndFailed,
	)
}

func TestQualificationProcessFailurePreservesZCodeProtocolCause(t *testing.T) {
	observation := testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 1)
	for _, test := range []struct {
		cause domain.RuntimeDiagnosticCause
		class domain.FailureClass
	}{
		{domain.DiagnosticCauseOutputDecodeFailed, domain.FailureInvalidOutput},
		{domain.DiagnosticCauseProviderTurnFailed, domain.FailureProviderUnavailable},
	} {
		err := qualificationProcessFailure(FamilyZcode, observation, zcodeProtocolFailure(test.cause, errors.New("zcode turn failed")))
		requireProviderDiagnosticCause(t, err, test.cause)
		classified := classifyProbeFailure(context.Background(), FamilyZcode, err, nil)
		var failure *domain.Failure
		if !errors.As(classified, &failure) || failure.Class() != test.class {
			t.Fatalf("cause %q classified as %v, want %q", test.cause, classified, test.class)
		}
	}
}

func TestPlainSemverRejectsNonBareSemverPrefixForGrok(t *testing.T) {
	observation := testProcessObservation(t, []byte("codex-cli 0.147.0\n"), nil, ports.ProcessTerminationExited, 0)
	if _, err := plainSemver(FamilyGrok, observation); err == nil {
		t.Fatal("non-bare version prefix was accepted for Grok")
	}
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
		Definition: testProfile(t, FamilyGrok, "grok_current", "", ""),
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

func TestQualificationFixtureV4EvidenceAcrossActiveProviderFamilies(t *testing.T) {
	t.Parallel()
	var schema struct {
		Type                 string         `json:"type"`
		AdditionalProperties *bool          `json:"additionalProperties"`
		Required             []string       `json:"required"`
		Properties           map[string]any `json:"properties"`
	}
	if err := json.Unmarshal([]byte(probeFixtureOutputSchema), &schema); err != nil {
		t.Fatalf("unmarshal probeFixtureOutputSchema: %v", err)
	}
	if schema.Type != "object" || schema.AdditionalProperties == nil || *schema.AdditionalProperties ||
		len(schema.Required) != 3 || len(schema.Properties) != 3 ||
		schema.Properties["root"] == nil || schema.Properties["link"] == nil || schema.Properties["role"] == nil {
		t.Fatalf("probeFixtureOutputSchema lost strict closed root/link/role schema: %s", probeFixtureOutputSchema)
	}

	nonce, err := SecureProbeNonceGenerator{}.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	link, err := SecureProbeNonceGenerator{}.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	if nonce == link {
		t.Fatal("generated identical nonces")
	}
	mismatchNonce := func(value string) string {
		if strings.HasPrefix(value, "0") {
			return "1" + value[1:]
		}
		return "0" + value[1:]
	}
	wrongNonce := mismatchNonce(nonce)
	wrongLink := mismatchNonce(link)

	role := domain.RoleSecurity
	fixture, request, err := newProbeFixture(role, nonce, link)
	if err != nil {
		t.Fatal(err)
	}
	if request.PolicyIdentity() != "current-qualification-fixture-v4" {
		t.Fatalf("fixture policy = %q, want current-qualification-fixture-v4", request.PolicyIdentity())
	}

	exactJSON := fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, nonce, link, role)
	extraFieldJSON := fmt.Sprintf(`{"root":%q,"link":%q,"role":%q,"extra":"x"}`, nonce, link, role)
	narratedOnly := fmt.Sprintf("Readiness confirmed with root=%s link=%s role=%s after transport.", nonce, link, role)

	for _, family := range []string{FamilyZcode, FamilyGrok} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			if err := acceptCapabilityResponse(context.Background(), family, []byte(exactJSON), nil, fixture); err != nil {
				t.Fatalf("%s rejected exact v4 JSON: %v", family, err)
			}

			for _, tc := range []struct {
				name   string
				output []byte
			}{
				{"exact v4 packet echo", fixture.Packet()},
				{"narrated v4 packet echo without binding", []byte("I received:\n" + string(fixture.Packet()))},
				{"nonce mismatch", []byte(fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, wrongNonce, link, role))},
				{"link mismatch", []byte(fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, nonce, wrongLink, role))},
				{"role mismatch", []byte(fmt.Sprintf(`{"root":%q,"link":%q,"role":%q}`, nonce, link, domain.RoleLogic))},
				{"duplicate JSON key same value", []byte(fmt.Sprintf(`{"root":%q,"root":%q,"link":%q,"role":%q}`, nonce, nonce, link, role))},
				{"duplicate JSON key different value", []byte(fmt.Sprintf(`{"root":%q,"root":%q,"link":%q,"role":%q}`, nonce, wrongNonce, link, role))},
			} {
				t.Run(tc.name, func(t *testing.T) {
					err := acceptCapabilityResponse(context.Background(), family, tc.output, nil, fixture)
					if err == nil {
						t.Fatalf("%s accepted %s", family, tc.name)
					}
					requireOperationalCapabilityMismatch(t, err)
				})
			}

			t.Run("extra JSON field", func(t *testing.T) {
				if err := acceptCapabilityResponse(context.Background(), family, []byte(extraFieldJSON), nil, fixture); err != nil {
					t.Fatalf("%s rejected positive-capability JSON with extra field: %v", family, err)
				}
			})

			t.Run("narrated-only output", func(t *testing.T) {
				if err := acceptCapabilityResponse(context.Background(), family, []byte(narratedOnly), nil, fixture); err != nil {
					t.Fatalf("%s rejected positive-capability narrated output: %v", family, err)
				}
			})
		})
	}
}
