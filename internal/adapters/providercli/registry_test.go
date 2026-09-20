package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestBuildArgvUsesIsolatedCodexAppServerProfile(t *testing.T) {
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := buildArgv(definition{
		family: FamilyCodex, baseArgv: []string{"/private/bin/codex"}, transport: transport,
		codexModel: "gpt-5.3-codex", codexReasoningEffort: "high", timeout: 30 * time.Minute,
	}, "/private/work", []byte("review bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/private/bin/codex", "app-server", "--strict-config",
		"--disable", "apps", "--disable", "browser_use", "--disable", "computer_use", "--disable", "hooks",
		"--disable", "image_generation", "--disable", "multi_agent", "--disable", "plugins", "--disable", "skill_search",
		"-c", `permissions.mulgae={extends=":read-only",filesystem={"~/.codex"="deny"}}`,
		"-c", `default_permissions="mulgae"`, "-c", "project_doc_max_bytes=0", "-c", "shell_environment_policy.inherit=none",
		"-c", `model="gpt-5.3-codex"`, "-c", `model_reasoning_effort="high"`,
	}
	if !equalStrings(got, want) {
		t.Fatalf("Codex argv = %q, want %q", got, want)
	}
	if occurrences := packetOccurrences(got, "review bytes"); occurrences != 0 {
		t.Fatalf("Codex argv contains protocol packet %d times", occurrences)
	}
}

func TestRegistryReleasesProtocolTranscript(t *testing.T) {
	transport, err := NewRuntimeTransport(ports.ProviderPacketChannelProtocol, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := newTestProfileWithTransport(t, FamilyCodex, "codex-logic", []string{"/private/bin/codex"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	definition := definition(profile)
	base := currentProbeCapabilityProtocolObservation(t, &currentProbeFixture{}, []byte("protocol transcript"))
	observation, lease := observationWithTrackingLease(t, base)
	runner := &observationRunner{observation: observation}
	registry := &Registry{runner: runner, namespaces: map[string]ports.ProviderNamespaceLease{}}
	packet, err := ports.NewProviderPacketFromBytes([]byte("review packet"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProviderProtocolProcessRequest(definition.executable, definition.baseArgv, nil, definition.workingDirectory, binding, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.executeProviderProcess(context.Background(), definition, packet, request, ports.ProviderInvocationInitial, nil); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatalf("protocol transcript closes = %d, want 1", lease.closes)
	}
}

// TestZCodeReviewArgvIsTheBareAppServer pins the exact review argv of the
// protocol transport: the write grant and read-only denylist travel inside the
// session conversation, never on the argv.
func TestZCodeReviewArgvIsTheBareAppServer(t *testing.T) {
	transport, err := defaultRuntimeTransport(FamilyZcode, 1)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Channel() != ports.ProviderPacketChannelProtocol || transport.ArgvIndex() != -1 {
		t.Fatalf("zcode default transport = %#v, want the protocol channel", transport)
	}
	argv, err := buildArgv(definition{
		family: FamilyZcode, baseArgv: []string{"/private/bin/zcode"}, transport: transport, timeout: 30 * time.Minute,
	}, "/private/work", []byte("review bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/private/bin/zcode", "app-server", "--stdio"}
	if !equalStrings(argv, want) {
		t.Fatalf("ZCode review argv = %q, want %q", argv, want)
	}
	if occurrences := packetOccurrences(argv, "review bytes"); occurrences != 0 {
		t.Fatalf("ZCode review argv carries %d packet occurrences, want 0", occurrences)
	}
	if _, err := runtimeTransportArgvIndex(FamilyZcode, 1); err == nil {
		t.Fatal("zcode print transport index is still admitted")
	}
}

func TestRegistryRunsSixZCodeRoleInstancesConcurrentlyInSameGuardedCWD(t *testing.T) {
	runner := newBarrierRunner()
	instances := []string{"zcode-logic", "zcode-security", "zcode-maintainability", "zcode-product", "zcode-documentation", "zcode-testing"}
	definitions := make([]definition, 0, len(instances))
	for _, instance := range instances {
		definitions = append(definitions, testDefinition(t, FamilyZcode, instance))
	}
	registry, err := newRegistry(context.Background(), runner, definitions...)
	if err != nil {
		t.Fatal(err)
	}
	root, identity := testWorkspaceRoot(t)
	var calls sync.WaitGroup
	calls.Add(len(instances))
	for _, instance := range instances {
		instance := instance
		events := []string{}
		authority := &workspaceAuthorityFake{identity: identity, guard: &workspaceGuardFake{root: root, identity: identity, events: &events}, events: &events}
		go func() {
			defer calls.Done()
			_, _ = registry.Observe(context.Background(), testWorkspaceInvocation(t, instance, authority))
		}()
	}
	for index := 0; index < len(instances); index++ {
		select {
		case <-runner.started:
		case <-time.After(time.Second):
			t.Fatal("six ZCode role instances did not enter the runner concurrently")
		}
	}
	if active := runner.activeCount(); active != len(instances) {
		t.Fatalf("active ZCode requests = %d, want %d", active, len(instances))
	}
	directories := runner.workingDirectories()
	wantDirectories := make([]string, len(instances))
	for index := range wantDirectories {
		wantDirectories[index] = root.Path()
	}
	if !reflect.DeepEqual(directories, wantDirectories) {
		t.Fatalf("ZCode working directories = %v, want shared guarded root %q", directories, root.Path())
	}
	close(runner.release)
	calls.Wait()
}
func TestClassifyProviderFailureKeepsNativeSignalAuthorityByCaller(t *testing.T) {
	tests := []struct {
		name              string
		stdout            []byte
		stderr            []byte
		allowNativeStdout bool
		wantStatus        ports.ProviderExecutionStatus
		wantDiagnostic    string
		wantCause         domain.RuntimeDiagnosticCause
	}{
		{
			name:           "review model authored stdout",
			stdout:         []byte("The review discusses rate limit handling."),
			stderr:         []byte("Error: Turn execution failed"),
			wantStatus:     ports.ProviderExecutionStatusUnavailable,
			wantDiagnostic: "provider_turn_failed",
			wantCause:      domain.DiagnosticCauseProviderTurnFailed,
		},
		{
			name:           "review model authored login marker",
			stdout:         []byte("The review discusses auth.login_required handling."),
			stderr:         []byte("Provider exited"),
			wantStatus:     ports.ProviderExecutionStatusUnavailable,
			wantDiagnostic: "provider_execution_failed",
			wantCause:      domain.DiagnosticCauseProviderExecutionFailed,
		},
		{
			name:           "review generic retry prose",
			stderr:         []byte("Please try again later.\nError: Turn execution failed"),
			wantStatus:     ports.ProviderExecutionStatusUnavailable,
			wantDiagnostic: "provider_turn_failed",
			wantCause:      domain.DiagnosticCauseProviderTurnFailed,
		},
		{
			name:           "review unrelated rate limit prose",
			stderr:         []byte("Loaded rate limit policy from configuration.\nError: Turn execution failed"),
			wantStatus:     ports.ProviderExecutionStatusUnavailable,
			wantDiagnostic: "provider_turn_failed",
			wantCause:      domain.DiagnosticCauseProviderTurnFailed,
		},
		{
			name:           "review unrelated standalone 429",
			stderr:         []byte("Elapsed 429 ms.\nError: Turn execution failed"),
			wantStatus:     ports.ProviderExecutionStatusUnavailable,
			wantDiagnostic: "provider_turn_failed",
			wantCause:      domain.DiagnosticCauseProviderTurnFailed,
		},
		{
			name:              "qualification native stdout",
			stdout:            []byte("rate_limit"),
			stderr:            []byte("Provider exited"),
			allowNativeStdout: true,
			wantStatus:        ports.ProviderExecutionStatusRateLimit,
			wantDiagnostic:    "provider_rate_limit",
			wantCause:         domain.DiagnosticCauseRateLimited,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := testProcessObservation(t, test.stdout, test.stderr, ports.ProcessTerminationExited, 1)
			classifier := classifyReviewProviderFailure
			if test.allowNativeStdout {
				classifier = classifyProviderFailure
			}
			status, diagnostic, cause := classifier(FamilyZcode, observation)
			if status != test.wantStatus || diagnostic != test.wantDiagnostic || cause != test.wantCause {
				t.Fatalf("status = %q, diagnostic = %q, cause = %q; want %q, %q, %q", status, diagnostic, cause, test.wantStatus, test.wantDiagnostic, test.wantCause)
			}
		})
	}
}

func TestNativeProviderOutcomePrefersZCodeQuotaOverRateLimitAndTurnFailure(t *testing.T) {
	for _, stderr := range [][]byte{
		[]byte("quota_exceeded\nError: Turn execution failed"),
		[]byte("quota_exceeded\nrate_limit_error\nError: Turn execution failed"),
	} {
		status, diagnostic, cause, ok := nativeProviderOutcome(FamilyZcode, nil, stderr)
		if !ok || status != ports.ProviderExecutionStatusQuota || diagnostic != "provider_quota" || cause != domain.DiagnosticCauseQuotaExceeded {
			t.Fatalf("stderr = %q: status = %q, diagnostic = %q, cause = %q, ok = %t", stderr, status, diagnostic, cause, ok)
		}
	}
}

func TestNativeProviderOutcomeRecognizesZCodeRateLimitErrorIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		marker     string
		wantStatus ports.ProviderExecutionStatus
		wantCause  domain.RuntimeDiagnosticCause
	}{
		{"colon suffix", "rate_limit_error:", ports.ProviderExecutionStatusRateLimit, domain.DiagnosticCauseRateLimited},
		{"period suffix", "rate_limit_error.", ports.ProviderExecutionStatusRateLimit, domain.DiagnosticCauseRateLimited},
		{"quoted", `"rate_limit_error"`, ports.ProviderExecutionStatusRateLimit, domain.DiagnosticCauseRateLimited},
		{"embedded identifier", "x_rate_limit_error_y", ports.ProviderExecutionStatusUnavailable, domain.DiagnosticCauseProviderTurnFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stderr := []byte(test.marker + "\nError: Turn execution failed")
			status, _, cause, ok := nativeProviderOutcome(FamilyZcode, nil, stderr)
			if !ok || status != test.wantStatus || cause != test.wantCause {
				t.Fatalf("stderr = %q: status = %q, cause = %q, ok = %t; want %q, %q", stderr, status, cause, ok, test.wantStatus, test.wantCause)
			}
		})
	}
}

type observationRunner struct {
	observation ports.ProcessObservation
	request     ports.ProcessRequest
	err         error
}

func (runner *observationRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.request = request
	return runner.observation, runner.err
}

// Converse lets the fake runner carry protocol-channel routes so zcode tests
// exercise the conversation dispatch with canned observations.
func (runner *observationRunner) Converse(_ context.Context, request ports.ProcessRequest, _ ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	runner.request = request
	return runner.observation, runner.err
}

func testProcessObservation(t *testing.T, stdout, stderr []byte, termination ports.ProcessTermination, exitCode int) ports.ProcessObservation {
	t.Helper()
	packet := []byte("review bytes")
	receipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet), testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelArgvLiteral, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Unix(0, 0).UTC()
	endedAt := time.Unix(1, 0).UTC()
	switch termination {
	case ports.ProcessTerminationStartFailed, ports.ProcessTerminationStartUnavailable,
		ports.ProcessTerminationStartConfiguration, ports.ProcessTerminationStartSecurity:
		observation, err := ports.NewProcessObservation(stdout, stderr, nil, termination, receipt, startedAt, endedAt)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	if termination == ports.ProcessTerminationExited {
		observation, err := ports.NewProviderProcessObservation(stdout, stderr, &exitCode, termination, receipt, transport, startedAt, endedAt)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	if termination == ports.ProcessTerminationSignaled {
		signal, err := ports.NewProcessSignal(15, "SIGTERM")
		if err != nil {
			t.Fatal(err)
		}
		observation, err := ports.NewProviderProcessObservation(stdout, stderr, nil, termination, receipt, transport, startedAt, endedAt, signal)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	observation, err := ports.NewProviderProcessObservation(stdout, stderr, nil, termination, receipt, transport, startedAt, endedAt)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
func packetOccurrences(argv []string, packet string) int {
	occurrences := 0
	for _, argument := range argv {
		if argument == packet {
			occurrences++
		}
	}
	return occurrences
}

func providerRuntimeCause(err error) domain.RuntimeDiagnosticCause {
	var failure *ports.ProviderRuntimeError
	if !errors.As(err, &failure) {
		return ""
	}
	return failure.Cause()
}

type workspaceAuthorityFake struct {
	identity ports.WorkspaceSnapshotIdentity
	guard    ports.WorkspaceExecutionGuard
	err      error
	events   *[]string
}

func (authority *workspaceAuthorityFake) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return authority.identity
}

func (authority *workspaceAuthorityFake) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	*authority.events = append(*authority.events, "pre")
	return authority.guard, authority.err
}

type workspaceGuardFake struct {
	root     ports.ValidatedWorkspaceRoot
	identity ports.WorkspaceSnapshotIdentity
	events   *[]string
	postErr  error
	closeErr error
}

func (guard *workspaceGuardFake) WorkspaceRoot() ports.ValidatedWorkspaceRoot { return guard.root }
func (guard *workspaceGuardFake) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return guard.identity
}
func (guard *workspaceGuardFake) DuplicateLaunchDirectory() (*os.File, error) {
	*guard.events = append(*guard.events, "duplicate")
	return os.Open(guard.root.Path())
}
func (guard *workspaceGuardFake) RevalidateAfterExecution() error {
	*guard.events = append(*guard.events, "post")
	return guard.postErr
}
func (guard *workspaceGuardFake) Close() error {
	*guard.events = append(*guard.events, "close")
	return guard.closeErr
}

type workspaceRunnerFake struct {
	request     ports.ProcessRequest
	observation ports.ProcessObservation
	err         error
	events      *[]string
	calls       int
}

func (runner *workspaceRunnerFake) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.calls++
	runner.request = request
	if runner.events != nil {
		*runner.events = append(*runner.events, "run")
	}
	if directory, _, ok := request.BoundLaunchDirectory(); ok {
		_ = directory.Close()
	}
	return runner.observation, runner.err
}

func (runner *workspaceRunnerFake) Converse(ctx context.Context, request ports.ProcessRequest, _ ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return runner.Run(ctx, request)
}

func TestRegistryObserveSecurityBoundaryOutranksConcurrentInterruption(t *testing.T) {
	for _, test := range []struct {
		name     string
		postErr  error
		closeErr error
	}{
		{name: "post-execution drift", postErr: errors.New("workspace changed")},
		{name: "guard close failure", closeErr: errors.New("guard close failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, identity := testWorkspaceRoot(t)
			events := []string{}
			guard := &workspaceGuardFake{root: root, identity: identity, events: &events, postErr: test.postErr, closeErr: test.closeErr}
			authority := &workspaceAuthorityFake{identity: identity, guard: guard, events: &events}
			runner := &workspaceRunnerFake{
				observation: protocolInterruptedObservation(t, ports.ProcessTerminationTimedOut),
				err:         ports.ErrProviderSessionExchangeClosed,
				events:      &events,
			}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
			if err != nil {
				t.Fatal(err)
			}
			observed, observeErr := registry.Observe(context.Background(), testWorkspaceInvocation(t, "grok_default", authority))
			if observeErr == nil || observed.Status() != ports.ProviderExecutionStatusSecurityViolation ||
				observed.PrimaryCause() != domain.DiagnosticCauseWorkspaceRevalidationFailed {
				t.Fatalf("security boundary result = status %q cause %q err %v", observed.Status(), observed.PrimaryCause(), observeErr)
			}
		})
	}
}

func testWorkspaceRoot(t *testing.T) (ports.ValidatedWorkspaceRoot, ports.WorkspaceSnapshotIdentity) {
	t.Helper()
	path := t.TempDir()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		path, "snapshot-0123456789abcdef0123456789abcdef", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "policy",
		1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewValidatedWorkspaceRoot(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	return root, identity
}

func testWorkspaceInvocation(t *testing.T, instance string, workspace ports.WorkspaceExecutionAuthority) ports.ProviderInvocation {
	t.Helper()
	legacy := testInvocation(t, instance)
	invocation, err := ports.NewProviderInvocationWithPacketInWorkspace(
		legacy.Role(), instance, legacy.AttemptID(), legacy.Purpose(), legacy.Packet(),
		legacy.SourceInvocationID(), legacy.ExecutionInvocationID(), workspace,
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}
func cloneRuntimeDefinition(profile RuntimeDefinition) RuntimeDefinition {
	profile.baseArgv = append([]string(nil), profile.baseArgv...)
	profile.environment = append([]ports.EnvironmentVariable(nil), profile.environment...)
	return profile
}

func TestProviderFailureProjectionKeepsTransportLifecycleSubtypesSecurityClosed(t *testing.T) {
	for _, cause := range []domain.RuntimeDiagnosticCause{
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
	} {
		status, diagnostic := providerFailureProjection(cause)
		if status != ports.ProviderExecutionStatusSecurityViolation || diagnostic != "process_security" {
			t.Fatalf("cause %q projection = (%q, %q)", cause, status, diagnostic)
		}
	}
}

func TestProviderFailureProjectionPreservesProtocolEventDecodeCause(t *testing.T) {
	status, diagnostic := providerFailureProjection(domain.DiagnosticCauseProtocolEventDecodeFailed)
	if status != ports.ProviderExecutionStatusArtifactFailure || diagnostic != "invalid_provider_output" {
		t.Fatalf("protocol event decode projection = (%q, %q)", status, diagnostic)
	}
}

type barrierRunner struct {
	started     chan struct{}
	release     chan struct{}
	mu          sync.Mutex
	active      int
	directories []string
}

func newBarrierRunner() *barrierRunner {
	return &barrierRunner{
		started: make(chan struct{}, 4),
		release: make(chan struct{}),
	}
}

func (runner *barrierRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.mu.Lock()
	runner.active++
	runner.directories = append(runner.directories, request.WorkingDirectory())
	runner.mu.Unlock()
	defer func() {
		runner.mu.Lock()
		runner.active--
		runner.mu.Unlock()
	}()
	runner.started <- struct{}{}
	<-runner.release
	if directory, _, ok := request.BoundLaunchDirectory(); ok {
		_ = directory.Close()
	}
	receipt, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	packetIdentity, err := ports.NewProviderPacketIdentity(len([]byte("review bytes")), testStdinDigest([]byte("review bytes")))
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelArgvLiteral, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	exitCode := 0
	return ports.NewProviderProcessObservation([]byte("{}"), nil, &exitCode, ports.ProcessTerminationExited, receipt, transport, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
}

// Converse carries protocol-channel routes through the same barrier so
// concurrency assertions cover the conversation dispatch.
func (runner *barrierRunner) Converse(ctx context.Context, request ports.ProcessRequest, _ ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return runner.Run(ctx, request)
}

func (runner *barrierRunner) workingDirectories() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	result := append([]string(nil), runner.directories...)
	sort.Strings(result)
	return result
}

func (runner *barrierRunner) activeCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.active
}

type countingRunner struct {
	calls int
}

func (runner *countingRunner) Run(_ context.Context, _ ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.calls++
	return ports.ProcessObservation{}, errors.New("unexpected process run")
}

func mustEnvironment(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

func testProfile(t *testing.T, family, instance, version, executableSHA256 string) RuntimeDefinition {
	t.Helper()
	executable := "/private/bin/" + family
	profile, err := NewRuntimeDefinition(
		family, instance, version, executable, executableSHA256, instance,
		[]string{executable}, nil, "/private/work", time.Second)

	if err != nil {
		t.Fatal(err)
	}
	return profile
}
func newTestProfileWithTransport(
	t *testing.T, family, instance string, baseArgv []string, transport RuntimeTransport,
) (RuntimeDefinition, error) {
	t.Helper()
	return NewRuntimeDefinitionWithTransport(
		family, instance, "", "/private/bin/"+family, "", instance,
		baseArgv, transport, nil, "/private/work", time.Second)

}

func testDefinition(t *testing.T, family, instance string) definition {
	t.Helper()
	return definition(testProfile(t, family, instance, "", ""))
}

func testInvocation(t *testing.T, instance string) ports.ProviderInvocation {
	t.Helper()
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	stdin := []byte("review bytes")
	invocation, err := ports.NewProviderInvocation(
		domain.RoleSecurity,
		instance,
		attempt,
		ports.ProviderInvocationInitial,
		stdin,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd",
		"019f596a-cf80-7c67-b265-f37053d51cce",
		testStdinDigest(stdin),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func testStdinDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

type scriptedNamespaceFactory struct {
	leases  map[string]*scriptedNamespace
	capture func(context.Context, string)
}

func (factory scriptedNamespaceFactory) AcquireProviderNamespace(ctx context.Context, instance, family string) (ports.ProviderNamespaceLease, error) {
	if factory.capture != nil {
		factory.capture(ctx, instance)
	}
	return ports.AcquireProviderNamespaceLease(ctx, instance, func(_ context.Context, _ string, binding ports.ProviderNamespaceTerminalBinding) (ports.ProviderNamespaceLease, error) {
		lease := factory.leases[instance]
		if lease == nil {
			return nil, errors.New("missing scripted namespace")
		}
		drain, err := binding.Bind(lease.generation, lease.drainTerminalEffects)
		if err != nil {
			return nil, err
		}
		lease.terminalDrain = drain
		return lease, nil
	})
}

type scriptedNamespace struct {
	instance, generation        string
	runtimeSafetyPolicyIdentity string
	mu                          sync.Mutex
	terminalDrain               ports.ProviderNamespaceTerminalDrain
	validateErr                 error
	drainCalls                  int
	failCalls                   int
	drainContext                func(context.Context)
}

func (lease *scriptedNamespace) ProviderInstance() string { return lease.instance }
func (lease *scriptedNamespace) Generation() string       { return lease.generation }
func (lease *scriptedNamespace) Environment() []ports.EnvironmentVariable {
	return nil
}
func (lease *scriptedNamespace) RuntimeSafetyPolicyIdentity() string {
	return lease.runtimeSafetyPolicyIdentity
}
func (*scriptedNamespace) ProjectCredential(context.Context, ports.CredentialProjectionRequest) (ports.CredentialProjectionReceipt, error) {
	return ports.CredentialProjectionReceipt{}, errors.New("unexpected credential projection")
}
func (lease *scriptedNamespace) ValidateForSpawn() error { return lease.validateErr }
func (lease *scriptedNamespace) DrainTerminal(ctx context.Context) (ports.ProviderNamespaceTerminalReceipt, error) {
	if lease == nil || lease.terminalDrain == nil {
		return ports.ProviderNamespaceTerminalReceipt{}, errors.New("missing scripted terminal drain")
	}
	return lease.terminalDrain(ctx)
}

func (lease *scriptedNamespace) drainTerminalEffects(ctx context.Context) error {
	if lease.drainContext != nil {
		lease.drainContext(ctx)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.drainCalls++
	if ctx.Err() != nil || lease.failCalls > 0 {
		if lease.failCalls > 0 {
			lease.failCalls--
		}
		return context.Canceled
	}
	return nil
}

type testSpawnVerifier struct{}

func (testSpawnVerifier) VerifyProviderSpawn(context.Context, RuntimeDefinition) error { return nil }

func testProductionSafetyProfile(t *testing.T, family, policyIdentity string) RuntimeDefinition {
	t.Helper()
	transport, err := defaultRuntimeTransport(family, 1)
	if err != nil {
		t.Fatal(err)
	}
	executable := "/private/bin/" + family
	profile, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		family, family+"_production", "", executable, "executable-sha256", executable, "executable-sha256",
		"", "",
		family+"_production", "generation-1", policyIdentity, []string{executable}, transport, nil,
		"/private/work", time.Second)

	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// stagedOutputRunnerFake stages provider-written files at exactly the moment a
// real provider process would: the staging lease already exists, and the
// process has not terminated yet.
type stagedOutputRunnerFake struct {
	observation   ports.ProcessObservation
	err           error
	stage         func()
	protocolLines []string
	request       ports.ProcessRequest
	calls         int
}

type zcodeSelectionNamespaceLease struct {
	ports.ProviderNamespaceLease
	selection *zcodeModelSelection
}

func (lease zcodeSelectionNamespaceLease) zcodeSessionSelection() *zcodeModelSelection {
	return cloneZCodeModelSelection(lease.selection)
}

func (runner *stagedOutputRunnerFake) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	runner.calls++
	runner.request = request
	if runner.stage != nil {
		runner.stage()
	}
	return runner.observation, runner.err
}

// Converse lets the fake carry protocol-channel routes so staged zcode tests
// exercise the conversation dispatch.
func (runner *stagedOutputRunnerFake) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	observation, err := runner.Run(nil, request)
	if len(runner.protocolLines) == 0 {
		return observation, err
	}
	driveErr := driver.Drive(ctx, newScriptedProtocolExchange(runner.protocolLines...))
	return observation, errors.Join(err, driveErr)
}

// stagedZcodeRegistry builds the ZCode registry together with the staged
// invocation the registry itself locates, so every staged test drives exactly
// the destination production would use.
func stagedZcodeRegistry(
	t *testing.T, runner ports.ProcessRunner,
) (*Registry, ports.ProviderInvocation, ports.StagedOutputDestination) {
	t.Helper()
	registry, err := NewRegistry(runner, testProfile(t, FamilyZcode, "zcode_default", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	legacy := testInvocation(t, "zcode_default")
	destination, transport, ok := registry.ProviderOutputStagingDestination(
		legacy.ProviderInstance(), legacy.AttemptID(), legacy.Purpose(),
	)
	if !ok || transport != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("staging destination = %q, transport = %q, ok = %t", destination.Directory(), transport, ok)
	}
	invocation, err := ports.NewProviderInvocationWithStagedOutput(legacy, destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(destination.Directory())) })
	return registry, invocation, destination
}

func writeStagedProviderReport(t *testing.T, destination ports.StagedOutputDestination, content []byte) {
	t.Helper()
	if err := os.WriteFile(destination.AbsolutePath(), content, 0600); err != nil {
		t.Fatalf("write staged provider report: %v", err)
	}
	if err := os.Chmod(destination.AbsolutePath(), 0600); err != nil {
		t.Fatalf("chmod staged provider report: %v", err)
	}
}

func requireStagingRemoved(t *testing.T, destination ports.StagedOutputDestination) {
	t.Helper()
	if _, err := os.Lstat(destination.Directory()); !os.IsNotExist(err) {
		t.Fatalf("staging directory survived the observation: %v", err)
	}
}

// protocolTeardownObservation builds the process observation a real protocol
// conversation returns when the app-server outlives the completed turn and
// the runner's bounded teardown ends it with SIGTERM.
func protocolTeardownObservation(t *testing.T, stdout []byte) ports.ProcessObservation {
	return protocolTeardownObservationWithStderr(t, stdout, nil)
}

func protocolTeardownObservationWithStderr(t *testing.T, stdout, stderr []byte) ports.ProcessObservation {
	t.Helper()
	packet := []byte("review bytes")
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet), testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelProtocol, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	signal, err := ports.NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(ports.ProcessGroupSignalRequestConversationTeardown, signal)
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewSignaledProcessFinalTermination(signal)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{request})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(
		stdout, stderr, ports.ProcessTerminationSignaled, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func protocolSignaledObservationWithoutTeardownRequest(t *testing.T, stdout []byte) ports.ProcessObservation {
	t.Helper()
	packet := []byte("review bytes")
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet), testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(
		ports.ProviderPacketChannelProtocol, packetIdentity, "", "",
		ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	signal, err := ports.NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewSignaledProcessFinalTermination(signal)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(
		stdout, nil, ports.ProcessTerminationSignaled, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func protocolInterruptedObservation(t *testing.T, termination ports.ProcessTermination) ports.ProcessObservation {
	t.Helper()
	packet := []byte("review bytes")
	packetIdentity, err := ports.NewProviderPacketIdentity(len(packet), testStdinDigest(packet))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ports.NewProviderPacketTransportReceipt(ports.ProviderPacketChannelProtocol, packetIdentity, "", "", ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := ports.NewStdinWriteReceipt(0, 0, testStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	signal, err := ports.NewProcessSignal(9, "SIGKILL")
	if err != nil {
		t.Fatal(err)
	}
	reason := ports.ProcessGroupSignalRequestCancellation
	if termination == ports.ProcessTerminationTimedOut {
		reason = ports.ProcessGroupSignalRequestTimeout
	}
	request, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(reason, signal)
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewSignaledProcessFinalTermination(signal)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{request})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStartedProviderProcessObservation(nil, nil, termination, stdin, transport, lifecycle, time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestRegistryObserveInterruptionOutranksZCodeModelSelectionFailureAndRetainsSession(t *testing.T) {
	for _, test := range []struct {
		name        string
		termination ports.ProcessTermination
		runnerErr   error
		status      ports.ProviderExecutionStatus
		diagnostic  string
	}{
		{name: "cancelled", termination: ports.ProcessTerminationCancelled, runnerErr: ports.ErrProviderSessionExchangeClosed, status: ports.ProviderExecutionStatusCancelled, diagnostic: "process_cancelled"},
		{name: "timed out", termination: ports.ProcessTerminationTimedOut, runnerErr: ports.ErrProviderSessionExchangeClosed, status: ports.ProviderExecutionStatusTimedOut, diagnostic: "process_timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &stagedOutputRunnerFake{
				observation: protocolInterruptedObservation(t, test.termination), err: test.runnerErr,
				protocolLines: []string{protocolCreateResult, `{"id":"mulgae-model-0","error":{"code":-32603,"message":"Provider not found","data":{"code":"provider_not_found"}}}`},
			}
			registry, invocation, destination := stagedZcodeRegistry(t, runner)
			registry.namespaces["zcode_default"] = zcodeSelectionNamespaceLease{ProviderNamespaceLease: registry.namespaces["zcode_default"], selection: &zcodeModelSelection{ProviderID: "missing", ModelID: "model"}}
			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != test.status || observed.DiagnosticCode() != test.diagnostic {
				t.Fatalf("interruption = status %q diagnostic %q", observed.Status(), observed.DiagnosticCode())
			}
			session, ok := observed.SessionObservation()
			if !ok || session.ProviderSessionID() != "sess_script" || session.Terminal() != ports.ProviderSessionFailed || !session.Input().HasProviderErrorCode {
				t.Fatalf("retained session = %#v, present = %t", session.Input(), ok)
			}
			requireStagingRemoved(t, destination)
		})
	}
}

// TestRegistryObserveAcceptsSignaledConversationTeardownAsStagedSuccess pins
// the live-e2e regression: a protocol conversation whose app-server was ended
// by the runner's receipt-proven teardown after completing its turn still
// publishes the staged report instead of collapsing into an untyped failure.
func TestRegistryObserveAcceptsSignaledConversationTeardownAsStagedSuccess(t *testing.T) {
	content := []byte("# Role report\n\nPublished from a torn-down conversation.\n")
	runner := &stagedOutputRunnerFake{
		observation: protocolTeardownObservation(t, []byte("protocol transcript")),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	runner.stage = func() { writeStagedProviderReport(t, destination, content) }

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusSucceeded ||
		observed.OutputTransport() != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("status = %q, transport = %q", observed.Status(), observed.OutputTransport())
	}
	result, ok := observed.Result()
	if !ok || !bytes.Equal(result.Stdout(), content) {
		t.Fatalf("result = %q, present=%t", result.Stdout(), ok)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObservePreservesFailedZCodeConversationTeardown(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolTeardownObservation(t, []byte("protocol transcript")),
		protocolLines: []string{
			protocolCreateResult,
			protocolSendAck,
			`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_failure","sessionId":"sess_script"}}`,
		},
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusUnavailable ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderTurnFailed {
		t.Fatalf("status = %q, cause = %q", observed.Status(), observed.PrimaryCause())
	}
	session, ok := observed.SessionObservation()
	if !ok || session.ProviderSessionID() != "sess_script" || session.ProviderTurnID() != "turn_failure" ||
		session.Terminal() != ports.ProviderSessionFailed {
		t.Fatalf("session = %#v, present = %t", session.Input(), ok)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveProjectsZCodeModelSelectionFailureAsConfiguration(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolTeardownObservation(t, []byte("protocol transcript")),
		protocolLines: []string{
			protocolCreateResult,
			`{"id":"mulgae-model-0","error":{"code":-32603,"message":"Provider not found","data":{"code":"provider_not_found"}}}`,
		},
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	registry.namespaces["zcode_default"] = zcodeSelectionNamespaceLease{
		ProviderNamespaceLease: registry.namespaces["zcode_default"],
		selection:              &zcodeModelSelection{ProviderID: "missing", ModelID: "model"},
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusConfigurationViolation ||
		observed.DiagnosticCode() != "zcode_model_selection" ||
		observed.PrimaryCause() != domain.DiagnosticCauseObservationInvalid {
		t.Fatalf("status = %q, diagnostic = %q, cause = %q", observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	session, ok := observed.SessionObservation()
	if !ok || session.ProviderSessionID() != "sess_script" || session.Terminal() != ports.ProviderSessionFailed || !session.Input().CreateAccepted ||
		!session.Input().HasProviderErrorCode || session.Input().ProviderErrorCode != -32603 {
		t.Fatalf("session = %#v, present = %t", session.Input(), ok)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObservePreservesModelSelectionEvidenceWhenProcessIsIncoherent(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolSignaledObservationWithoutTeardownRequest(t, []byte("protocol transcript")),
		protocolLines: []string{
			protocolCreateResult,
			`{"id":"mulgae-model-0","error":{"code":-32603,"message":"Provider not found","data":{"code":"provider_not_found"}}}`,
		},
	}
	registry, invocation, _ := stagedZcodeRegistry(t, runner)
	registry.namespaces["zcode_default"] = zcodeSelectionNamespaceLease{
		ProviderNamespaceLease: registry.namespaces["zcode_default"],
		selection:              &zcodeModelSelection{ProviderID: "missing", ModelID: "model"},
	}

	observed, err := registry.Observe(context.Background(), invocation)
	var invariant *ports.ProviderObservationInvariantError
	if !errors.As(err, &invariant) || observed.Validate() == nil {
		t.Fatalf("registry invariant result = observation %#v, error %v", observed, err)
	}
	if invariant.Status() != ports.ProviderExecutionStatusConfigurationViolation ||
		invariant.Cause() != domain.DiagnosticCauseObservationInvalid ||
		invariant.ProcessObservation().Termination() != ports.ProcessTerminationSignaled ||
		invariant.SessionObservation().ProviderSessionID() != "sess_script" ||
		!invariant.SessionObservation().Input().HasProviderErrorCode ||
		invariant.SessionObservation().Input().ProviderErrorCode != -32603 {
		t.Fatalf("registry invariant evidence = status %q cause %q process %q session %#v",
			invariant.Status(), invariant.Cause(), invariant.ProcessObservation().Termination(), invariant.SessionObservation().Input())
	}
}

func TestRegistryObservePreservesRateLimitedZCodeConversationTeardown(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolTeardownObservationWithStderr(t, []byte("protocol transcript"), []byte("ProviderBusinessError [1302][Rate limit reached for requests] rate_limit_error\nError: Turn execution failed")),
		protocolLines: []string{
			protocolCreateResult,
			protocolSendAck,
			`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_failure","sessionId":"sess_script"}}`,
		},
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusRateLimit ||
		observed.DiagnosticCode() != "provider_rate_limit" ||
		observed.PrimaryCause() != domain.DiagnosticCauseRateLimited {
		t.Fatalf("status = %q, diagnostic = %q, cause = %q", observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	session, ok := observed.SessionObservation()
	if !ok || session.ProviderSessionID() != "sess_script" || session.ProviderTurnID() != "turn_failure" ||
		session.Terminal() != ports.ProviderSessionFailed {
		t.Fatalf("session = %#v, present = %t", session.Input(), ok)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveReturnsTypedInvariantWhenProtocolFailureCannotMatchProcess(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolSignaledObservationWithoutTeardownRequest(t, []byte("protocol transcript")),
		protocolLines: []string{
			protocolCreateResult,
			protocolSendAck,
			`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_failure","sessionId":"sess_script"}}`,
		},
	}
	registry, invocation, _ := stagedZcodeRegistry(t, runner)

	observed, err := registry.Observe(context.Background(), invocation)
	var invariant *ports.ProviderObservationInvariantError
	if !errors.As(err, &invariant) || observed.Validate() == nil {
		t.Fatalf("registry invariant result = observation %#v, error %v", observed, err)
	}
	if invariant.Status() != ports.ProviderExecutionStatusUnavailable ||
		invariant.Cause() != domain.DiagnosticCauseProviderTurnFailed ||
		invariant.ProcessObservation().Termination() != ports.ProcessTerminationSignaled ||
		invariant.SessionObservation().ProviderTurnID() != "turn_failure" {
		t.Fatalf("registry invariant evidence = status %q cause %q process %q session %#v",
			invariant.Status(), invariant.Cause(), invariant.ProcessObservation().Termination(), invariant.SessionObservation().Input())
	}
}

func TestRegistryObservePreservesTimedOutZCodeConversationTeardown(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: protocolTeardownObservationWithStderr(t, []byte("protocol transcript"), []byte("request timed out")),
		protocolLines: []string{
			protocolCreateResult,
			protocolSendAck,
			`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_failure","sessionId":"sess_script"}}`,
		},
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusTimedOut || observed.PrimaryCause() != domain.DiagnosticCauseTimedOut {
		t.Fatalf("status = %q, cause = %q", observed.Status(), observed.PrimaryCause())
	}
	if session, ok := observed.SessionObservation(); !ok || session.Terminal() != ports.ProviderSessionFailed {
		t.Fatalf("session = %#v, present = %t", session.Input(), ok)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveAcceptsStagedFileOutputAsPrimaryResult(t *testing.T) {
	content := []byte("# Role report\n\nOne bounded finding.\n")
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, nil, []byte("provider diagnostics"), ports.ProcessTerminationExited, 0),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	runner.stage = func() { writeStagedProviderReport(t, destination, content) }

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusSucceeded ||
		observed.OutputTransport() != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("status = %q, transport = %q", observed.Status(), observed.OutputTransport())
	}
	result, ok := observed.Result()
	if !ok || !bytes.Equal(result.Stdout(), content) {
		t.Fatalf("result = %q, present = %t, want staged bytes %q", result.Stdout(), ok, content)
	}
	digest := sha256.Sum256(content)
	receipt, staged := observed.StagedOutputReceipt()
	if !staged || receipt.SHA256() != "sha256:"+hex.EncodeToString(digest[:]) ||
		receipt.ByteLength() != int64(len(content)) {
		t.Fatalf("receipt = %q/%d, present = %t", receipt.SHA256(), receipt.ByteLength(), staged)
	}
	// stdout and stderr remain bounded process evidence only.
	if len(observed.Stdout()) != 0 || !bytes.Equal(observed.Stderr(), []byte("provider diagnostics")) {
		t.Fatalf("process streams = stdout %q stderr %q", observed.Stdout(), observed.Stderr())
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveIgnoresStdoutWhenStagedFileTransportIsDeclared(t *testing.T) {
	staged := []byte("# Role report\n\nThe staged bytes are the result.\n")
	stdout := []byte(`{"sessionId":"session","response":"stdout content that must never win","usage":{"inputTokens":1}}`)
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, stdout, nil, ports.ProcessTerminationExited, 0),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	runner.stage = func() { writeStagedProviderReport(t, destination, staged) }

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := observed.Result()
	if !ok || !bytes.Equal(result.Stdout(), staged) {
		t.Fatalf("result = %q, present = %t, want staged bytes %q", result.Stdout(), ok, staged)
	}
	if !bytes.Equal(observed.Stdout(), stdout) {
		t.Fatalf("raw stdout evidence = %q, want %q", observed.Stdout(), stdout)
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveFailsClosedWhenStagedFileIsMissing(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	// The safe external code is the operational invalid-output code, so repair
	// and fallback stay available; the exact staging fact is the typed cause.
	if observed.Status() != ports.ProviderExecutionStatusArtifactFailure ||
		observed.DiagnosticCode() != "invalid_provider_output" ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderOutputFileMissing {
		t.Fatalf("missing staged file = status %q diagnostic %q cause %q",
			observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	if _, ok := observed.Result(); ok {
		t.Fatal("missing staged file produced a provider result")
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveClassifiesStagedSecurityViolation(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("# outside the staging boundary\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	runner.stage = func() {
		if err := os.Symlink(outside, destination.AbsolutePath()); err != nil {
			t.Fatalf("stage symlink: %v", err)
		}
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusSecurityViolation ||
		observed.FailureClass() != domain.FailureSecurityPolicy ||
		observed.DiagnosticCode() != "process_security" ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderOutputStagingViolation {
		t.Fatalf("staged violation = status %q class %q diagnostic %q cause %q",
			observed.Status(), observed.FailureClass(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	if _, ok := observed.Result(); ok {
		t.Fatal("staged boundary breach produced a provider result")
	}
	requireStagingRemoved(t, destination)
}

func TestRegistryObserveStagingCleanupFailureOverridesProviderSuccess(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, nil, nil, ports.ProcessTerminationExited, 0),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	renamed := filepath.Join(filepath.Dir(destination.Directory()), "renamed-staging")
	runner.stage = func() {
		writeStagedProviderReport(t, destination, []byte("# Role report\n\nOne bounded finding.\n"))
		// Read-back is descriptor-bound and survives a rename, but cleanup must
		// prove the parent entry it recorded still names the staging directory.
		// Removal therefore cannot be proven, while the provider itself succeeded.
		if err := os.Rename(destination.Directory(), renamed); err != nil {
			t.Fatalf("rename staging directory: %v", err)
		}
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusArtifactFailure ||
		observed.FailureClass() != domain.FailureArtifact ||
		observed.DiagnosticCode() != "provider_output_staging_cleanup_failed" ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderOutputStagingCleanupFailed {
		t.Fatalf("unproven cleanup = status %q class %q diagnostic %q cause %q",
			observed.Status(), observed.FailureClass(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	if _, ok := observed.Result(); ok {
		t.Fatal("unproven staging cleanup returned a provider result")
	}
}

func TestRegistryObserveRemovesStagingOnProviderFailure(t *testing.T) {
	runner := &stagedOutputRunnerFake{
		observation: testProcessObservation(t, nil, []byte("provider process failed"), ports.ProcessTerminationExited, 1),
	}
	registry, invocation, destination := stagedZcodeRegistry(t, runner)
	runner.stage = func() {
		writeStagedProviderReport(t, destination, []byte("# Role report\n\nOne bounded finding.\n"))
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	// The process failure keeps its own classification: a staged file cannot
	// promote a failed provider process to a reviewable result.
	if observed.Status() != ports.ProviderExecutionStatusUnavailable ||
		observed.DiagnosticCode() != "provider_execution_failed" ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderExecutionFailed {
		t.Fatalf("provider failure = status %q diagnostic %q cause %q",
			observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
	if _, ok := observed.Result(); ok {
		t.Fatal("failed provider process produced a provider result")
	}
	requireStagingRemoved(t, destination)
}

// The protocol transport never delivers report content on stdout: the
// review report arrives through the staged file and qualification evidence
// through the conversation, so every stdout shape fails closed.

func TestGrokJSONEnvelopeRejectsMissingOrFailedResponse(t *testing.T) {
	for _, output := range []string{
		`{"status":"SUCCESS","response":""}`,
		`{"status":"SUCCESS","response":"  "}`,
		`{"conversation_id":"c","status":"SUCCESS"}`,
		`{"status":"SUCCESS","response":null}`,
		`{"status":"SUCCESS","response":{"findings":[]}}`,
		`{"status":"ERROR","response":"No findings."}`,
		`{"status":42,"response":"No findings."}`,
	} {
		if body, _, err := providerResult(FamilyGrok, []byte(output)); err == nil {
			t.Errorf("accepted invalid envelope %s as %q", output, body)
		}
	}
}

func TestNewRuntimeDefinitionAllowsOptionalProvenance(t *testing.T) {
	for _, provenance := range []struct {
		name      string
		version   string
		hash      string
		profileID string
	}{
		{"empty", "", "", ""},
		{"arbitrary", "future-build+unknown", "not-a-sha", "vendor profile 2030.4"},
		{"different hash", "0.23.6", "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "grok.default"},
	} {
		for _, family := range []string{FamilyGrok, FamilyZcode, FamilyGrok} {
			t.Run(family+"/"+provenance.name, func(t *testing.T) {
				profile := testProfile(t, family, family+"_default", provenance.version, provenance.hash)
				profile.profileID = provenance.profileID
				registry, err := NewRegistry(&countingRunner{}, profile)
				if err != nil || registry == nil {
					t.Fatalf("registry=%v err=%v", registry, err)
				}
			})
		}
	}
}

func TestNewRegistryRejectsMalformedProfilesAndUnlistedFamilies(t *testing.T) {
	profile := testProfile(t, FamilyGrok, "grok_default", "", "")
	tests := map[string]func(*RuntimeDefinition){
		"unlisted family": func(p *RuntimeDefinition) { p.family = "other" },
		"relative executable": func(p *RuntimeDefinition) {
			p.executable, p.baseArgv[0] = "grok", "grok"
		},
		"unclean executable": func(p *RuntimeDefinition) {
			p.executable, p.baseArgv[0] = "/private/bin/../grok", "/private/bin/../grok"
		},
		"invalid argv": func(p *RuntimeDefinition) { p.baseArgv = []string{p.executable, ""} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := cloneRuntimeDefinition(profile)
			mutate(&invalid)
			if registry, err := NewRegistry(&countingRunner{}, invalid); err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
		})
	}
}

func TestNewRegistryPreservesProfileAndDefensiveCopies(t *testing.T) {
	argv := []string{"/private/bin/grok", "--safe"}
	environment := []ports.EnvironmentVariable{mustEnvironment(t, "HOME", "/private/home")}
	profile, err := NewRuntimeDefinition(FamilyGrok, "grok_default", "", argv[0], "", "grok_default", argv, environment, "/private/work", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	argv[1] = "--mutated"
	environment[0] = mustEnvironment(t, "HOME", "/mutated")
	registry, err := NewRegistry(&countingRunner{}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.definitions["grok_default"].baseArgv; !equalStrings(got, []string{"/private/bin/grok", "--safe"}) {
		t.Fatalf("runnable argv = %q", got)
	}
	if got := registry.definitions["grok_default"].environment[0].Value(); got != "/private/home" {
		t.Fatalf("runnable environment value = %q", got)
	}
}

func TestRegistryAcceptsDistinctInstancesOfSameFamilyAndRejectsDuplicateInstance(t *testing.T) {
	runner := newBarrierRunner()
	first := testDefinition(t, FamilyGrok, "grok_primary")
	second := testDefinition(t, FamilyGrok, "grok_secondary")
	registry, err := newRegistry(context.Background(), runner, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.definitions["grok_primary"]; !ok {
		t.Fatal("primary Grok instance was not registered")
	}
	if _, ok := registry.definitions["grok_secondary"]; !ok {
		t.Fatal("secondary Grok instance was not registered")
	}
	observed := make(chan error, 1)
	secondaryInvocation := testInvocation(t, "grok_secondary")
	go func() {
		_, observeErr := registry.Observe(context.Background(), secondaryInvocation)
		observed <- observeErr
	}()
	<-runner.started
	close(runner.release)
	if observeErr := <-observed; observeErr != nil {
		t.Fatalf("secondary Grok dispatch failed: %v", observeErr)
	}
	if _, err := newRegistry(context.Background(), runner, first, first); err == nil {
		t.Fatal("duplicate provider instance accepted")
	}
}

func TestRegistryRejectsUnregisteredProviderBeforeRunnerCall(t *testing.T) {
	runner := newBarrierRunner()
	grok := testDefinition(t, FamilyGrok, "grok_default")
	registry, err := newRegistry(context.Background(), runner, grok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "codex_default")); err == nil {
		t.Fatal("unregistered provider was accepted")
	}
	select {
	case <-runner.started:
		t.Fatal("runner called for unregistered provider")
	default:
	}
}

func TestRegistryAllowsDistinctProviderInstancesToOverlap(t *testing.T) {
	runner := newBarrierRunner()
	grok := testDefinition(t, FamilyGrok, "grok_default")
	zcode := testDefinition(t, FamilyZcode, "zcode_default")
	registry, err := newRegistry(context.Background(), runner, grok, zcode)
	if err != nil {
		t.Fatal(err)
	}

	var calls sync.WaitGroup
	calls.Add(2)
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	}()
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "zcode_default"))
	}()
	for range 2 {
		select {
		case <-runner.started:
		case <-time.After(time.Second):
			t.Fatal("distinct provider instances did not overlap")
		}
	}
	if active := runner.activeCount(); active != 2 {
		t.Fatalf("distinct-instance active count = %d, want 2", active)
	}
	close(runner.release)
	calls.Wait()
}

func TestIndependentRegistriesOwnDistinctNamespacesAndOverlapSameInstance(t *testing.T) {
	runner := newBarrierRunner()
	definition := testDefinition(t, FamilyGrok, "grok_default")
	first, err := newRegistry(context.Background(), runner, definition)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newRegistry(context.Background(), runner, definition)
	if err != nil {
		t.Fatal(err)
	}
	if first.namespaceGenerations[definition.instance] == second.namespaceGenerations[definition.instance] ||
		first.namespaces[definition.instance] == second.namespaces[definition.instance] {
		t.Fatal("independent registries shared one provider namespace generation")
	}
	var calls sync.WaitGroup
	calls.Add(2)
	for _, registry := range []*Registry{first, second} {
		registry := registry
		go func() {
			defer calls.Done()
			_, _ = registry.Observe(context.Background(), testInvocation(t, "grok_default"))
		}()
	}
	for range 2 {
		select {
		case <-runner.started:
		case <-time.After(time.Second):
			t.Fatal("independent registries serialized the same provider instance")
		}
	}
	close(runner.release)
	calls.Wait()
}

func TestRegistryRefusesConcurrentSameInstanceWithoutWaiting(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
		firstDone <- observeErr
	}()
	<-runner.started

	refused := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
		refused <- observeErr
	}()
	select {
	case observeErr := <-refused:
		if !errors.Is(observeErr, ports.ErrProviderInstanceAlreadyActive) {
			t.Fatalf("duplicate active instance error = %v, want typed internal invariant", observeErr)
		}
		if got := providerRuntimeCause(observeErr); got.Valid() {
			t.Fatalf("duplicate active instance exposed provider diagnostic cause %q", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("duplicate active instance waited instead of failing closed")
	}
	if active := runner.activeCount(); active != 1 {
		t.Fatalf("active count after invariant refusal = %d, want 1", active)
	}
	close(runner.release)
	if observeErr := <-firstDone; observeErr != nil {
		t.Fatalf("first observe failed: %v", observeErr)
	}

	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatalf("instance remained active after completion: %v", err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("observation after completion is invalid: %v", err)
	}
}

func TestRegistryAllowsDistinctKeysToOverlap(t *testing.T) {
	runner := newBarrierRunner()
	grok := testDefinition(t, FamilyGrok, "grok_default")
	zcode := testDefinition(t, FamilyZcode, "zcode_default")
	registry, err := newRegistry(context.Background(), runner, grok, zcode)
	if err != nil {
		t.Fatal(err)
	}
	var calls sync.WaitGroup
	calls.Add(2)
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "zcode_default"))
	}()
	go func() {
		defer calls.Done()
		_, _ = registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	}()
	<-runner.started
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("distinct concurrency keys did not overlap")
	}
	close(runner.release)
	calls.Wait()
}

func TestRegistryConcurrentSameInstanceRefusalDoesNotLeakActiveState(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
		firstDone <- observeErr
	}()
	<-runner.started

	if _, observeErr := registry.Observe(context.Background(), testInvocation(t, "grok_default")); !errors.Is(observeErr, ports.ErrProviderInstanceAlreadyActive) {
		t.Fatalf("duplicate active invocation error = %v", observeErr)
	}
	select {
	case <-runner.started:
		t.Fatal("refused duplicate call reached runner")
	default:
	}
	if active := runner.activeCount(); active != 1 {
		t.Fatalf("active count after refusal = %d, want 1", active)
	}

	close(runner.release)
	if observeErr := <-firstDone; observeErr != nil {
		t.Fatalf("first observe failed: %v", observeErr)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatalf("active instance was not released after completion: %v", err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("observation after refusal is invalid: %v", err)
	}
}

func TestRegistryObservePreservesRunnerErrorWithObservation(t *testing.T) {
	process := testProcessObservation(t, []byte("{\"role\":\"assistant\",\"content\":\"answer\"}\n"), nil, ports.ProcessTerminationExited, 0)
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseProviderProcessWaitFailed, "", process.Stdout(), process.Stderr(), errors.New("runner failed"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{observation: process, err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed ||
		string(observed.Stdout()) != string(process.Stdout()) {
		t.Fatalf("cause = %q, stdout was preserved = %t", observed.PrimaryCause(), bytes.Equal(observed.Stdout(), process.Stdout()))
	}
}

func TestRegistryObservePreservesCoherentCancellationFromRunnerError(t *testing.T) {
	process := testProcessObservation(t, nil, nil, ports.ProcessTerminationCancelled, 0)
	runner := &observationRunner{observation: process, err: context.Canceled}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusCancelled ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderExecutionFailed ||
		observed.DiagnosticCode() != "process_cancelled" {
		t.Fatalf("cancellation observation = status:%q cause:%q diagnostic:%q", observed.Status(), observed.PrimaryCause(), observed.DiagnosticCode())
	}
}

func TestRegistryObservePreservesPartialStreamsAndCleanupCause(t *testing.T) {
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseProviderProcessWaitFailed,
		domain.DiagnosticCauseProcessGroupCleanupFailed,
		[]byte("partial stdout"),
		[]byte("partial stderr"),
		errors.New("private runner detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := observed.AvailableProcessObservation(); ok {
		t.Fatal("partial execution claimed a coherent process observation")
	}
	cleanup, ok := observed.CleanupCause()
	if observed.PrimaryCause() != domain.DiagnosticCauseProviderProcessWaitFailed ||
		!ok || cleanup != domain.DiagnosticCauseProcessGroupCleanupFailed {
		t.Fatalf("primary = %q, cleanup = %q, present = %t", observed.PrimaryCause(), cleanup, ok)
	}
	if string(observed.Stdout()) != "partial stdout" || string(observed.Stderr()) != "partial stderr" {
		t.Fatal("partial runner streams were lost")
	}
}

func TestRegistryObservePreservesTransportVerificationCause(t *testing.T) {
	runnerFailure, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseTransportVerificationFailed, "", []byte("partial stdout"), nil,
		errors.New("private prompt-file identity detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := &observationRunner{err: runnerFailure}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusSecurityViolation ||
		observed.PrimaryCause() != domain.DiagnosticCauseTransportVerificationFailed ||
		string(observed.Stdout()) != "partial stdout" {
		t.Fatalf("status = %q, cause = %q, stdout preserved = %t", observed.Status(), observed.PrimaryCause(), string(observed.Stdout()) == "partial stdout")
	}
}

func TestRegistryObserveClassifiesProcessTerminations(t *testing.T) {
	tests := []struct {
		name        string
		termination ports.ProcessTermination
		exitCode    int
		wantStatus  ports.ProviderExecutionStatus
		wantCode    string
		wantCause   domain.RuntimeDiagnosticCause
	}{
		{"timeout", ports.ProcessTerminationTimedOut, 0, ports.ProviderExecutionStatusTimedOut, "process_timeout", domain.DiagnosticCauseTimedOut},
		{"cancelled", ports.ProcessTerminationCancelled, 0, ports.ProviderExecutionStatusCancelled, "process_cancelled", domain.DiagnosticCauseProviderExecutionFailed},
		{"start unavailable", ports.ProcessTerminationStartUnavailable, 0, ports.ProviderExecutionStatusUnavailable, "process_unavailable", domain.DiagnosticCauseProviderSpawnFailed},
		{"start configuration", ports.ProcessTerminationStartConfiguration, 0, ports.ProviderExecutionStatusConfigurationViolation, "process_configuration", domain.DiagnosticCauseProviderSpawnFailed},
		{"start security", ports.ProcessTerminationStartSecurity, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security", domain.DiagnosticCauseProviderSpawnFailed},
		{"residual process group", ports.ProcessTerminationResidualProcessGroup, 0, ports.ProviderExecutionStatusSecurityViolation, "process_security", domain.DiagnosticCauseProcessGroupCleanupFailed},
		{"nonzero exit", ports.ProcessTerminationExited, 1, ports.ProviderExecutionStatusUnavailable, "provider_execution_failed", domain.DiagnosticCauseProviderExecutionFailed},
		{"signaled", ports.ProcessTerminationSignaled, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderExecutionFailed},
		{"start failed", ports.ProcessTerminationStartFailed, 0, ports.ProviderExecutionStatusInternalFailure, "process_internal", domain.DiagnosticCauseProviderSpawnFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := testInvocation(t, "grok_default")
			runner := &observationRunner{
				observation: testProcessObservation(t, []byte("raw stdout"), []byte("raw stderr"), test.termination, test.exitCode),
			}
			registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
			if err != nil {
				t.Fatal(err)
			}

			observed, err := registry.Observe(context.Background(), invocation)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Status() != test.wantStatus || observed.DiagnosticCode() != test.wantCode {
				t.Fatalf("status = %q, diagnostic = %q; want %q, %q",
					observed.Status(), observed.DiagnosticCode(), test.wantStatus, test.wantCode)
			}
			if observed.PrimaryCause() != test.wantCause {
				t.Fatalf("cause = %q, want %q", observed.PrimaryCause(), test.wantCause)
			}
		})
	}
}

func TestRegistryObserveClassifiesExplicitLoginRequired(t *testing.T) {
	invocation := testInvocation(t, "grok_default")
	runner := &observationRunner{
		observation: testProcessObservation(
			t,
			nil,
			[]byte(`{"code":"auth.login_required","message":"login first"}`),
			ports.ProcessTerminationExited,
			1,
		),
	}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusAuthentication || observed.DiagnosticCode() != "login_required" {
		t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseLoginRequired {
		t.Fatalf("cause = %q", observed.PrimaryCause())
	}
}

func TestRegistryObserveDoesNotClassifyModelAuthoredStdoutAsNativeFailure(t *testing.T) {
	invocation := testInvocation(t, "grok_default")
	runner := &observationRunner{
		observation: testProcessObservation(
			t,
			[]byte("The review discusses auth.login_required and rate_limit handling."),
			[]byte("provider execution failed"),
			ports.ProcessTerminationExited,
			1,
		),
	}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusUnavailable ||
		observed.DiagnosticCode() != "provider_execution_failed" ||
		observed.PrimaryCause() != domain.DiagnosticCauseProviderExecutionFailed {
		t.Fatalf("status = %q, diagnostic = %q, cause = %q", observed.Status(), observed.DiagnosticCode(), observed.PrimaryCause())
	}
}

func TestRegistryObserveClassifiesNativeProviderTimeout(t *testing.T) {
	invocation := testInvocation(t, "grok_default")
	runner := &observationRunner{
		observation: testProcessObservation(
			t,
			nil,
			[]byte("Error: timeout waiting for response\n"),
			ports.ProcessTerminationExited,
			1,
		),
	}
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}

	observed, err := registry.Observe(context.Background(), invocation)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status() != ports.ProviderExecutionStatusTimedOut || observed.DiagnosticCode() != "provider_timeout" {
		t.Fatalf("status = %q, diagnostic = %q", observed.Status(), observed.DiagnosticCode())
	}
	if observed.PrimaryCause() != domain.DiagnosticCauseTimedOut {
		t.Fatalf("cause = %q", observed.PrimaryCause())
	}
}

func TestNativeProviderOutcomeDoesNotClassifyReviewProseAsTransient(t *testing.T) {
	reviewProse := []byte("the service is overloaded and running at capacity, returning 503 to callers")
	if status, diagnostic, cause, ok := nativeProviderOutcome(FamilyGrok, reviewProse, nil); ok {
		t.Fatalf("review prose classified as native outcome: status = %q, diagnostic = %q, cause = %q", status, diagnostic, cause)
	}
	argvEcho := []byte("Error: unknown flag --print-timeout\n")
	status, diagnostic, _, ok := nativeProviderOutcome(FamilyGrok, nil, argvEcho)
	if ok || status == ports.ProviderExecutionStatusTimedOut || diagnostic == "provider_timeout" {
		t.Fatalf("argv echo classified as native timeout: status = %q, diagnostic = %q, ok = %t", status, diagnostic, ok)
	}
	codexProse := []byte(`{"type":"item.completed","item":{"text":"The usage limit handling is correct."}}`)
	if status, diagnostic, cause, ok := nativeProviderOutcome(FamilyCodex, codexProse, nil); ok {
		t.Fatalf("Codex review prose classified as native outcome: status = %q, diagnostic = %q, cause = %q", status, diagnostic, cause)
	}
	for _, stderr := range [][]byte{
		[]byte("request completed in 1502ms"),
		[]byte("trace a429b503c504d"),
		[]byte("panic at src/session.rs:429:12"),
		[]byte("codex 0.502.0"),
		[]byte("trace req-429-7"),
		[]byte("http 4290"),
		[]byte("http 429-extra"),
	} {
		if status, diagnostic, cause, ok := nativeProviderOutcome(FamilyCodex, nil, stderr); ok {
			t.Fatalf("Codex unrelated numeric stderr classified as native outcome: status = %q, diagnostic = %q, cause = %q", status, diagnostic, cause)
		}
	}
	status, diagnostic, cause, ok := nativeProviderOutcome(FamilyCodex, nil, []byte("request failed with status 429"))
	if !ok || status != ports.ProviderExecutionStatusRateLimit || diagnostic != "provider_rate_limit" || cause != domain.DiagnosticCauseRateLimited {
		t.Fatalf("Codex standalone HTTP status was not classified: status = %q, diagnostic = %q, cause = %q, ok = %t", status, diagnostic, cause, ok)
	}
}

func TestNativeProviderOutcomeRequiresExactHTTPStatusToken(t *testing.T) {
	for _, family := range []string{FamilyCodex, FamilyGrok, FamilyZcode, FamilyGrok} {
		t.Run(family, func(t *testing.T) {
			for _, stderr := range []string{"http 4290", "http 429-extra"} {
				if _, _, _, ok := nativeProviderOutcome(family, nil, []byte(stderr)); ok {
					t.Fatalf("classified malformed status %q", stderr)
				}
			}
			status, _, _, ok := nativeProviderOutcome(family, nil, []byte("HTTP 429"))
			if !ok || status != ports.ProviderExecutionStatusRateLimit {
				t.Fatal("did not classify exact HTTP 429")
			}
		})
	}
}

func TestProviderProcessRequestRejectsMalformedWorkingDirectory(t *testing.T) {
	definition := testDefinition(t, FamilyGrok, "grok_default")
	packet := testInvocation(t, "grok_default").Packet()
	for _, workingDirectory := range []string{"relative", "/private/work/../escape", "/private/work\x00"} {
		t.Run(workingDirectory, func(t *testing.T) {
			if _, _, err := providerProcessRequest(definition, packet, workingDirectory); err == nil {
				t.Fatal("malformed working directory accepted")
			}
		})
	}
}

func TestRegistryObserveStrictDefinitionRejectsMissingWorkspaceAuthority(t *testing.T) {
	profile, err := NewProductionRuntimeDefinition(
		FamilyGrok, "grok_default", "", "/private/bin/grok", "", "grok_default",
		[]string{"/private/bin/grok"}, nil, "/private/work", time.Second)

	if err != nil {
		t.Fatal(err)
	}
	runner := &workspaceRunnerFake{}
	factory, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistryWithNamespaceFactory(runner, factory, profile)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := registry.Observe(context.Background(), testInvocation(t, "grok_default")); providerRuntimeCause(err) != domain.DiagnosticCauseProviderSpawnFailed {
		t.Fatal("strict definition accepted authority-free invocation")
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestNewProductionRegistryBindsAcquiredRuntimeSafetyPolicyIdentity(t *testing.T) {
	profile := testProductionSafetyProfile(t, FamilyGrok, "policy-expected")

	for _, test := range []struct {
		name   string
		policy string
		wantOK bool
	}{
		{name: "missing actual identity"},
		{name: "mismatched actual identity", policy: "policy-other"},
		{name: "matching actual identity", policy: "policy-expected", wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &scriptedNamespace{
				instance: profile.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: test.policy,
			}
			registry, err := NewProductionRegistry(&countingRunner{}, scriptedNamespaceFactory{
				leases: map[string]*scriptedNamespace{profile.Instance(): lease},
			}, testSpawnVerifier{}, profile)
			if test.wantOK {
				if err != nil || registry == nil {
					t.Fatalf("registry=%v err=%v", registry, err)
				}
				namespace, ok := registry.QualificationNamespace(profile.Instance())
				if !ok || namespace.RuntimeSafetyPolicyIdentity() != test.policy {
					t.Fatalf("qualification namespace policy = %q, ok=%t", namespace.RuntimeSafetyPolicyIdentity(), ok)
				}
				if _, exposesWorkingDirectory := namespace.(interface{ WorkingDirectory() string }); exposesWorkingDirectory {
					t.Fatal("qualification namespace exposed working-directory authority")
				}
				return
			}
			if err == nil || registry != nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
			if lease.drainCalls != 1 {
				t.Fatalf("drain calls = %d, want 1", lease.drainCalls)
			}
		})
	}
}

func TestNewProductionRegistryConstructionUsesCallerContextForAcquireAndCleanup(t *testing.T) {
	profile := testProductionSafetyProfile(t, FamilyGrok, "policy-expected")
	type contextKey struct{}
	key := contextKey{}
	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.WithValue(context.Background(), key, "caller-value"), deadline)
	defer cancel()

	var acquisitionContext, cleanupContext context.Context
	lease := &scriptedNamespace{
		instance: profile.Instance(), generation: "generation-1", validateErr: errors.New("invalid namespace"),
		drainContext: func(ctx context.Context) { cleanupContext = ctx },
	}
	_, err := NewProductionRegistryWithContext(ctx, &countingRunner{}, scriptedNamespaceFactory{
		leases:  map[string]*scriptedNamespace{profile.Instance(): lease},
		capture: func(ctx context.Context, _ string) { acquisitionContext = ctx },
	}, testSpawnVerifier{}, profile)
	if err == nil {
		t.Fatal("malformed namespace construction succeeded")
	}
	for name, captured := range map[string]context.Context{"acquisition": acquisitionContext, "cleanup": cleanupContext} {
		if captured == nil || captured.Value(key) != "caller-value" {
			t.Fatalf("%s context value = %#v", name, captured)
		}
		gotDeadline, ok := captured.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("%s deadline = %v, present=%t; want %v", name, gotDeadline, ok, deadline)
		}
	}
}

func TestNewProductionRegistryPolicyCleanupFailureRetainsPartialRegistry(t *testing.T) {
	first := testProductionSafetyProfile(t, FamilyGrok, "policy-grok")
	second := testProductionSafetyProfile(t, FamilyGrok, "policy-zcode")
	second.instance = "grok_secondary"
	firstLease := &scriptedNamespace{
		instance: first.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: "policy-grok",
	}
	secondLease := &scriptedNamespace{
		instance: second.Instance(), generation: "generation-1", runtimeSafetyPolicyIdentity: "wrong-policy", failCalls: 2,
	}
	registry, err := NewProductionRegistryWithContext(context.Background(), &countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{first.Instance(): firstLease, second.Instance(): secondLease},
	}, testSpawnVerifier{}, first, second)
	if registry != nil || err == nil {
		t.Fatalf("registry=%v err=%v", registry, err)
	}
	owner, ok := RegistryFromConstructionError(err)
	if !ok || owner == nil {
		t.Fatalf("construction cleanup owner = %#v, present=%t", owner, ok)
	}
	if firstLease.drainCalls != 1 || secondLease.drainCalls != 1 {
		t.Fatalf("initial drains = first:%d second:%d", firstLease.drainCalls, secondLease.drainCalls)
	}
	secondLease.failCalls = 0
	receipt, closeErr := owner.Close(context.Background())
	if closeErr != nil || !receipt.Valid() {
		t.Fatalf("retry receipt=%#v err=%v", receipt, closeErr)
	}
	if firstLease.drainCalls != 1 || secondLease.drainCalls != 2 {
		t.Fatalf("retry drains = first:%d second:%d", firstLease.drainCalls, secondLease.drainCalls)
	}
}

func TestRegistryQualificationNamespaceIsNarrowRetainedLease(t *testing.T) {
	profile := testProfile(t, FamilyGrok, "grok_default", "", "")
	lease := &scriptedNamespace{instance: "grok_default", generation: "generation-1"}
	registry, err := NewRegistryWithNamespaceFactory(&countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{"grok_default": lease},
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	namespace, ok := registry.QualificationNamespace("grok_default")
	if !ok || namespace == nil || namespace.ProviderInstance() != lease.instance ||
		namespace.Generation() != lease.generation || namespace.ValidateForSpawn() != nil {
		t.Fatalf("qualification namespace = %#v, ok=%t", namespace, ok)
	}
	if _, isLease := namespace.(ports.ProviderNamespaceLease); isLease {
		t.Fatal("qualification namespace exposed drain or credential authority")
	}
	if _, exposesWorkingDirectory := namespace.(interface{ WorkingDirectory() string }); exposesWorkingDirectory {
		t.Fatal("qualification namespace exposed working-directory authority")
	}
}

func TestRegistryCloseRetriesOnlyUndrainedNamespaces(t *testing.T) {
	first := testDefinition(t, FamilyGrok, "grok_primary")
	second := testDefinition(t, FamilyGrok, "grok_secondary")
	primary := &scriptedNamespace{instance: "grok_primary", generation: "generation-primary"}
	secondary := &scriptedNamespace{instance: "grok_secondary", generation: "generation-secondary", failCalls: 1}
	registry, err := newRegistryWithNamespaces(context.Background(), &countingRunner{}, scriptedNamespaceFactory{leases: map[string]*scriptedNamespace{
		"grok_primary": primary, "grok_secondary": secondary,
	}}, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := registry.Close(context.Background()); err == nil || receipt.Valid() {
		t.Fatalf("partial close = %#v, %v", receipt, err)
	}
	if primary.drainCalls != 1 || secondary.drainCalls != 1 {
		t.Fatalf("first drain calls = primary %d secondary %d", primary.drainCalls, secondary.drainCalls)
	}
	receipt, err := registry.Close(context.Background())
	if err != nil || !receipt.Valid() || len(receipt.NamespaceReceipts()) != 2 {
		t.Fatalf("retry receipt = %#v, %v", receipt, err)
	}
	if primary.drainCalls != 1 || secondary.drainCalls != 2 {
		t.Fatalf("retry drain calls = primary %d secondary %d", primary.drainCalls, secondary.drainCalls)
	}
}

func TestRegistryCloseRetriesAfterCancellation(t *testing.T) {
	definition := testDefinition(t, FamilyGrok, "grok_default")
	lease := &scriptedNamespace{instance: "grok_default", generation: "generation-1"}
	registry, err := newRegistryWithNamespaces(context.Background(), &countingRunner{}, scriptedNamespaceFactory{
		leases: map[string]*scriptedNamespace{"grok_default": lease},
	}, definition)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := registry.Close(cancelled); err == nil || receipt.Valid() {
		t.Fatalf("cancelled close = %#v, %v", receipt, err)
	}
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if lease.drainCalls != 1 {
		t.Fatalf("drain calls = %d, want 1 after pre-drain cancellation", lease.drainCalls)
	}
}

func TestRegistryCloseCancellationWhileObservationIsActiveIsRetryable(t *testing.T) {
	runner := newBarrierRunner()
	registry, err := newRegistry(context.Background(), runner, testDefinition(t, FamilyGrok, "grok_default"))
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan error, 1)
	go func() {
		_, observeErr := registry.Observe(context.Background(), testInvocation(t, "grok_default"))
		observed <- observeErr
	}()
	<-runner.started

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	closed := make(chan error, 1)
	go func() {
		_, closeErr := registry.Close(cancelled)
		closed <- closeErr
	}()
	select {
	case closeErr := <-closed:
		if !errors.Is(closeErr, context.Canceled) {
			t.Fatalf("cancelled close error = %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled close waited for active observation")
	}
	close(runner.release)
	<-observed
	if _, err := registry.Close(context.Background()); err != nil {
		t.Fatalf("retry close: %v", err)
	}
}

// Only the closed review purposes are staged. Unsupported synthetic purposes
// fail closed; exact replay uses its original initial or retry purpose.
