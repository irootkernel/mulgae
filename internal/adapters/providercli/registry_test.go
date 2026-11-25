package providercli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

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
	transport, err := defaultRuntimeTransport(family)
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
	first := testDefinition(t, FamilyZcode, "zcode-logic")
	second := testDefinition(t, FamilyZcode, "zcode-security")
	registry, err := newRegistry(t.Context(), &countingRunner{}, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.definitions) != 2 {
		t.Fatal("registry lost distinct instances")
	}
	if _, err := registry.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := newRegistry(t.Context(), &countingRunner{}, first, first); err == nil {
		t.Fatal("registry accepted duplicate instance")
	}
}

func TestRegistryRejectsUnregisteredProviderBeforeRunnerCall(t *testing.T) {
	runner := newBarrierRunner()
	grok := testDefinition(t, FamilyGrok, "grok_default")
	registry, err := newRegistry(context.Background(), runner, grok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), testInvocation(t, "zcode_default")); err == nil {
		t.Fatal("unregistered provider was accepted")
	}
	select {
	case <-runner.started:
		t.Fatal("runner called for unregistered provider")
	default:
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
	for _, stderr := range [][]byte{
		[]byte("request completed in 1502ms"),
		[]byte("trace a429b503c504d"),
		[]byte("panic at src/session.rs:429:12"),
		[]byte("zcode 0.502.0"),
		[]byte("trace req-429-7"),
		[]byte("http 4290"),
		[]byte("http 429-extra"),
	} {
		if status, diagnostic, cause, ok := nativeProviderOutcome(FamilyZcode, nil, stderr); ok {
			t.Fatalf("ZCode unrelated numeric stderr classified as native outcome: status = %q, diagnostic = %q, cause = %q", status, diagnostic, cause)
		}
	}
	status, diagnostic, cause, ok := nativeProviderOutcome(FamilyZcode, nil, []byte("request failed with status 429"))
	if !ok || status != ports.ProviderExecutionStatusRateLimit || diagnostic != "provider_rate_limit" || cause != domain.DiagnosticCauseRateLimited {
		t.Fatalf("ZCode standalone HTTP status was not classified: status = %q, diagnostic = %q, cause = %q, ok = %t", status, diagnostic, cause, ok)
	}
	grokQuotaStderr := []byte("ERROR responses API error status=402 Payment Required error_message=Grok Build usage balance exhausted")
	status, diagnostic, cause, ok = nativeProviderOutcome(FamilyGrok, nil, grokQuotaStderr)
	if !ok || status != ports.ProviderExecutionStatusQuota || diagnostic != "provider_quota" || cause != domain.DiagnosticCauseQuotaExceeded {
		t.Fatalf("Grok usage balance exhaustion was not classified as quota: status = %q, diagnostic = %q, cause = %q, ok = %t", status, diagnostic, cause, ok)
	}
}

func TestNativeProviderOutcomeRequiresExactHTTPStatusToken(t *testing.T) {
	for _, family := range []string{FamilyGrok, FamilyZcode} {
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

func TestRegistryObserveStrictDefinitionRejectsMissingWorkspaceAuthority(t *testing.T) {
	profile, err := NewProductionRuntimeDefinition(
		FamilyGrok, "grok_default", "", "/private/bin/grok", "", "grok_default",
		[]string{"/private/bin/grok"}, nil, "/private/work", time.Second)

	if err != nil {
		t.Fatal(err)
	}
	runner := &countingRunner{}
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

func cloneRuntimeDefinition(profile RuntimeDefinition) RuntimeDefinition {
	profile.baseArgv = append([]string(nil), profile.baseArgv...)
	profile.environment = append([]ports.EnvironmentVariable(nil), profile.environment...)
	return profile
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
