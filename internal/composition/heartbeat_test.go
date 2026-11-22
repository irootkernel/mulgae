//go:build darwin && arm64

package composition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/adapters/workspace"
	appheartbeat "github.com/irootkernel/mulgae/internal/app/heartbeat"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type stableHeartbeatLocalityAttestor struct{}

func (stableHeartbeatLocalityAttestor) Attest(context.Context, ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	return ports.ConfigLocalityContext{}, nil
}

func (stableHeartbeatLocalityAttestor) Revalidate(context.Context, ports.ConfigLocalityRequest, ports.ConfigLocalityContext) error {
	return nil
}

func TestHeartbeatBindsSyntheticQualificationLocality(t *testing.T) {
	rootPath := canonicalTestTempDir(t)
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), []byte(compositionProjectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), []byte(compositionLocalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	local, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := &configuredProductionCandidateSource{
		source: local, attestor: stableHeartbeatLocalityAttestor{}, staticRequest: request,
	}
	ctx, err := source.bindSyntheticQualifiedRunContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inner := &recordingReviewSpawnVerifier{}
	verifier, err := boundLocalitySpawnVerifier(ctx, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyProviderSpawn(ctx, providercli.RuntimeDefinition{}); err != nil {
		t.Fatal(err)
	}
	if !inner.called {
		t.Fatal("synthetic qualification did not reach the bound spawn verifier")
	}
}

func TestConfiguredProviderSettingsReachSharedReviewAndHeartbeatSource(t *testing.T) {
	source := &configuredProductionCandidateSource{config: adapterconfig.Config{Providers: adapterconfig.ProvidersConfig{
		ZCode: &adapterconfig.ZCodeProviderConfig{Model: "account:zai-individual-coding-plan/GLM-5.3", ReasoningEffort: "high"},
		Grok:  &adapterconfig.GrokProviderConfig{Model: "grok-4.5", ReasoningEffort: "high-precision"},
		Codex: &adapterconfig.CodexProviderConfig{Model: "gpt-5.3-codex", ReasoningEffort: "high"},
		Agy:   &adapterconfig.AgyProviderConfig{Model: "gemini-3", ReasoningEffort: "max"},
	}}}
	zcodeModel, zcodeEffort, grokModel, grokEffort, codexModel, codexEffort, agyModel, agyEffort := source.providerSettings()
	if zcodeModel != "account:zai-individual-coding-plan/GLM-5.3" || zcodeEffort != "high" || grokModel != "grok-4.5" || grokEffort != "high-precision" || codexModel != "gpt-5.3-codex" || codexEffort != "high" || agyModel != "gemini-3" || agyEffort != "max" {
		t.Fatalf("provider settings = %q/%q/%q/%q/%q/%q/%q/%q", zcodeModel, zcodeEffort, grokModel, grokEffort, codexModel, codexEffort, agyModel, agyEffort)
	}
	heartbeatSource := *source
	heartbeatZCodeModel, heartbeatZCodeEffort, heartbeatGrokModel, heartbeatGrokEffort, _, _, heartbeatAgyModel, heartbeatAgyEffort := heartbeatSource.providerSettings()
	if heartbeatZCodeModel != zcodeModel || heartbeatZCodeEffort != zcodeEffort || heartbeatGrokModel != grokModel || heartbeatGrokEffort != grokEffort || heartbeatAgyModel != agyModel || heartbeatAgyEffort != agyEffort {
		t.Fatalf("heartbeat settings = %q/%q/%q/%q/%q/%q", heartbeatZCodeModel, heartbeatZCodeEffort, heartbeatGrokModel, heartbeatGrokEffort, heartbeatAgyModel, heartbeatAgyEffort)
	}
}

func TestHeartbeatFailureClassification(t *testing.T) {
	tests := []struct {
		class      domain.FailureClass
		wantStatus string
		wantReason string
	}{
		{domain.FailureAuthentication, "authentication_failure", "authentication_required"},
		{domain.FailureTimeout, "timeout", "provider_timeout"},
		{domain.FailureInvalidOutput, "malformed_response", "heartbeat_response_malformed"},
		{domain.FailureProviderUnavailable, "provider_failure", "provider_failure"},
		{domain.FailureQuota, "provider_failure", "provider_failure"},
		{domain.FailureRateLimit, "provider_failure", "provider_failure"},
		{domain.FailureInternal, "execution_failure", "provider_execution_failed"},
	}
	for _, test := range tests {
		failure, err := domain.NewFailure("reviewrun.qualification", test.class, "heartbeat failure", errors.New("redacted"))
		if err != nil {
			t.Fatal(err)
		}
		status, reason := heartbeatFailure(failure)
		if status != test.wantStatus || reason != test.wantReason {
			t.Errorf("class %q = %q/%q, want %q/%q", test.class, status, reason, test.wantStatus, test.wantReason)
		}
	}
}

func TestHeartbeatAttemptedRemainsFalseForPreRequestVersionRejection(t *testing.T) {
	versionFailure, err := domain.NewFailure("reviewrun.qualification", domain.FailureConfiguration, "provider version is incompatible", nil)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeatLiveAttempted(versionFailure) {
		t.Fatal("version rejection was reported as a live request attempt")
	}
	capabilityFailure, err := domain.NewFailure("reviewrun.qualification", domain.FailureInvalidOutput, "capability response invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !heartbeatLiveAttempted(capabilityFailure) {
		t.Fatal("capability failure omitted the live request attempt")
	}
}

type heartbeatSeqNonceGenerator struct {
	mu      sync.Mutex
	counter int
	last    []string
}

func (g *heartbeatSeqNonceGenerator) NewProbeNonce() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.counter++
	sum := sha256.Sum256([]byte(fmt.Sprintf("heartbeat-nonce-%d", g.counter)))
	nonce := hex.EncodeToString(sum[:])
	g.last = append(g.last, nonce)
	return nonce, nil
}

func (g *heartbeatSeqNonceGenerator) latestPair() (rootNonce, linkNonce string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.last) < 2 {
		return "", ""
	}
	return g.last[len(g.last)-2], g.last[len(g.last)-1]
}

type heartbeatProbeProcessRunner struct {
	t *testing.T
}

func (r *heartbeatProbeProcessRunner) Run(_ context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	r.t.Helper()
	if file, _, ok := request.LaunchDirectory(); ok && file != nil {
		_ = file.Close()
	}
	emptyDigest := heartbeatStdinDigest(nil)
	stdin, err := ports.NewStdinWriteReceipt(0, 0, emptyDigest, true)
	if err != nil {
		r.t.Fatal(err)
	}
	exitCode := 0
	return ports.NewProcessObservation(
		[]byte("grok 1.0.89 (abcdef0)\n"), nil, &exitCode, ports.ProcessTerminationExited, stdin,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
}

func (*heartbeatProbeProcessRunner) Converse(context.Context, ports.ProcessRequest, ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	return ports.ProcessObservation{}, errors.New("unexpected protocol Converse call")
}

type heartbeatProbeTerminalRunner struct {
	t *testing.T

	nonces           *heartbeatSeqNonceGenerator
	onRunTerminal    func(projectedAuthPath string) error
	failLiveDrainErr error

	mu                 sync.Mutex
	projectedAuthPath  string
	stagedPrompt       string
	drainCalls         int
	cancelledDrains    int
	liveDrains         int
	liveDrainDeadlines int
}

func (r *heartbeatProbeTerminalRunner) RunTerminal(_ context.Context, req ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	r.t.Helper()
	if file, _, ok := req.Process().LaunchDirectory(); ok && file != nil {
		_ = file.Close()
	}
	homeDir := ""
	for _, env := range req.Process().Environment() {
		if env.Name() == "HOME" {
			homeDir = env.Value()
			break
		}
	}
	authPath := filepath.Join(homeDir, ".grok", "auth.json")
	if _, err := os.Lstat(authPath); err != nil {
		r.t.Fatalf("expected projected credential %q before probe completion: %v", authPath, err)
	}
	r.mu.Lock()
	r.projectedAuthPath = authPath
	r.mu.Unlock()

	if r.onRunTerminal != nil {
		if err := r.onRunTerminal(authPath); err != nil {
			return ports.TerminalExecutionObservation{}, err
		}
	}

	promptBytes, err := os.ReadFile(req.PromptFilePath().String())
	if err != nil {
		r.t.Fatalf("read staged prompt file: %v", err)
	}
	r.mu.Lock()
	r.stagedPrompt = string(promptBytes)
	r.mu.Unlock()
	promptPacket, err := ports.NewProviderPacketFromBytes(promptBytes)
	if err != nil {
		r.t.Fatalf("prompt packet identity: %v", err)
	}
	outputPath := ""
	for _, field := range strings.Fields(req.InitialInput()) {
		trimmed := strings.Trim(field, ".,;:\"'()")
		if strings.HasSuffix(trimmed, "/probe.json") {
			outputPath = trimmed
			break
		}
	}
	if outputPath == "" {
		r.t.Fatalf("could not find probe.json path in initial input %q", req.InitialInput())
	}
	rootNonce, linkNonce := r.nonces.latestPair()
	payload, err := json.Marshal(struct {
		Root string `json:"root"`
		Link string `json:"link"`
		Role string `json:"role"`
	}{Root: rootNonce, Link: linkNonce, Role: string(domain.RoleLogic)})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, append(payload, '\n'), 0o600); err != nil {
		r.t.Fatalf("write staged probe.json: %v", err)
	}

	binding, _ := req.Process().ProviderPacketBinding()
	stdin, err := ports.NewStdinWriteReceipt(0, 0, heartbeatStdinDigest(nil), true)
	if err != nil {
		r.t.Fatal(err)
	}
	transport, err := ports.NewTerminalProviderPacketTransportReceipt(binding.PacketIdentity(), promptPacket.Identity(), promptPacket.Identity())
	if err != nil {
		r.t.Fatal(err)
	}
	sig, err := ports.NewProcessSignal(15, "SIGTERM")
	if err != nil {
		r.t.Fatal(err)
	}
	sigReceipt, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(ports.ProcessGroupSignalRequestTerminalTeardown, sig)
	if err != nil {
		r.t.Fatal(err)
	}
	final, err := ports.NewSignaledProcessFinalTermination(sig)
	if err != nil {
		r.t.Fatal(err)
	}
	lifecycle, err := ports.NewProcessLifecycleReceipt(final, true, []ports.ProcessGroupSignalRequestReceipt{sigReceipt})
	if err != nil {
		r.t.Fatal(err)
	}
	procObs, err := ports.NewStartedProviderProcessObservation(
		[]byte("grok terminal screen"), nil, ports.ProcessTerminationSignaled, stdin, transport, lifecycle,
		time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC(),
	)
	if err != nil {
		r.t.Fatal(err)
	}
	rtIdentity, err := r.RuntimeIdentity(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return ports.NewTerminalExecutionObservation(ports.TerminalExecutionObservationInput{
		Process:         procObs,
		RuntimeIdentity: rtIdentity,
		ProgramStatus:   ports.TerminalProgramStatusDone,
		Reported:        true,
		TurnCount:       1,
		ScreenCapture:   []byte("grok terminal screen"),
		PaneID:          "pane-1",
	})
}

func (r *heartbeatProbeTerminalRunner) DrainLabeledPanes(ctx context.Context, _, _ string) error {
	r.mu.Lock()
	r.drainCalls++
	if err := ctx.Err(); err != nil {
		r.cancelledDrains++
		r.mu.Unlock()
		return err
	}
	r.liveDrains++
	if _, ok := ctx.Deadline(); ok {
		r.liveDrainDeadlines++
	}
	failErr := r.failLiveDrainErr
	r.mu.Unlock()
	return failErr
}

func (*heartbeatProbeTerminalRunner) RuntimeIdentity(context.Context) (ports.TerminalRuntimeIdentity, error) {
	return ports.NewTerminalRuntimeIdentity("/opt/homebrew/bin/hc", "sha256:"+strings.Repeat("a", 64), "0.1.20", 1)
}

func (*heartbeatProbeTerminalRunner) Close(context.Context) error { return nil }

func heartbeatStdinDigest(content []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

type heartbeatSpawnVerifierStub struct{}

func (heartbeatSpawnVerifierStub) VerifyProviderSpawn(context.Context, providercli.RuntimeDefinition) error {
	return nil
}

type heartbeatCleanupOwnerStub struct {
	mu           sync.Mutex
	calls        int
	liveCalls    int
	hasDeadlines int
	drainErr     error
	receipt      reviewrun.QualifiedRunTerminalReceipt
}

func (stub *heartbeatCleanupOwnerStub) Provider() ports.ObservedReviewProvider { return nil }
func (stub *heartbeatCleanupOwnerStub) Planner() reviewrun.ExecutionPlanner    { return nil }
func (stub *heartbeatCleanupOwnerStub) BuildIdentity() reviewrun.BuildIdentity {
	return reviewrun.BuildIdentity{}
}
func (stub *heartbeatCleanupOwnerStub) DrainTerminal(ctx context.Context) (reviewrun.QualifiedRunTerminalReceipt, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	if err := ctx.Err(); err != nil {
		return reviewrun.QualifiedRunTerminalReceipt{}, err
	}
	stub.liveCalls++
	if _, ok := ctx.Deadline(); ok {
		stub.hasDeadlines++
	}
	if stub.drainErr != nil {
		return reviewrun.QualifiedRunTerminalReceipt{}, stub.drainErr
	}
	return stub.receipt, nil
}

type heartbeatRetainedCleanupOwnerError struct {
	cause error
	owner reviewrun.RunAuthority
}

func (err heartbeatRetainedCleanupOwnerError) Error() string                        { return err.cause.Error() }
func (err heartbeatRetainedCleanupOwnerError) Unwrap() error                        { return err.cause }
func (err heartbeatRetainedCleanupOwnerError) CleanupOwner() reviewrun.RunAuthority { return err.owner }

func newRealGrokHeartbeatTestGraph(
	t *testing.T,
	terminalRunner *heartbeatProbeTerminalRunner,
	wrapQualifier func(reviewrun.CurrentQualifier) reviewrun.CurrentQualifier,
) (*productionRuntimeGraph, string) {
	t.Helper()
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	rootPath := canonicalTestTempDir(t)
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), []byte(compositionProjectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), []byte(compositionLocalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	local, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	localityRequest, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	nativeHome := canonicalTestTempDir(t)
	if err := os.MkdirAll(filepath.Join(nativeHome, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativeHome, ".grok", "auth.json"), []byte(`{"token":"heartbeat-secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	namespaceRoot := canonicalTestTempDir(t)
	workspaceRoot := canonicalTestTempDir(t)
	anchoredWorkspace, err := ports.NewAnchoredRoot(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspace.NewMaterializer(anchoredWorkspace, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, terminalRunner.nonces)
	if err != nil {
		t.Fatal(err)
	}

	grokPolicy, err := providercli.RuntimeSafetyPolicyForFamily(providercli.CredentialSourceGrok)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[reviewrun.Family]string, len(reviewrun.Families()))
	timeouts := make(map[reviewrun.Family]time.Duration, len(reviewrun.Families()))
	for _, family := range reviewrun.Families() {
		identity, identityErr := (providercli.RuntimeBuilder{}).RuntimeSafetyPolicyIdentity(string(family))
		if identityErr != nil {
			t.Fatal(identityErr)
		}
		identities[family] = identity
		timeouts[family] = time.Minute
	}
	identities[reviewrun.FamilyGrok] = grokPolicy.Identity()

	cfg := adapterconfig.Config{
		NativeUser: adapterconfig.NativeUserConfig{Home: nativeHome},
		Providers: adapterconfig.ProvidersConfig{
			Grok: &adapterconfig.GrokProviderConfig{Executable: executable},
		},
	}
	instanceFamilies, instancePolicies, _, err := productionInstanceFamilies(cfg, map[reviewrun.Family]providercli.RuntimeSafetyPolicy{
		reviewrun.FamilyGrok: grokPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseNamespaces, err := providercli.NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := providercli.NewCredentialProjectingNamespaceFactoryWithPolicies(baseNamespaces, nativeHome, instanceFamilies, instancePolicies)
	if err != nil {
		t.Fatal(err)
	}
	procRunner := &heartbeatProbeProcessRunner{t: t}
	probe, err := providercli.NewCurrentProbeWithTerminalRunner(procRunner, heartbeatSpawnVerifierStub{}, terminalRunner)
	if err != nil {
		t.Fatal(err)
	}
	probePort, err := providercli.NewQualificationProbeAdapter(probe, providercli.NativeProbeInvocation{})
	if err != nil {
		t.Fatal(err)
	}
	fixturePort, err := providercli.NewQualificationFixtureFactoryAdapter(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var current reviewrun.CurrentQualifier
	current, err = reviewrun.NewProviderCurrentQualifier(probePort, fixturePort)
	if err != nil {
		t.Fatal(err)
	}
	if wrapQualifier != nil {
		current = wrapQualifier(current)
	}
	registries, err := providercli.NewQualificationRegistryFactoryWithTerminalRunner(procRunner, terminalRunner, projected, nil, func(context.Context) (providercli.SpawnVerifier, error) {
		return heartbeatSpawnVerifierStub{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := reviewrun.NewQualifiedRunFactory(current, registries, mcpTestClock{})
	if err != nil {
		t.Fatal(err)
	}
	return &productionRuntimeGraph{
		clock:     mcpTestClock{},
		fixtures:  fixtures,
		qualified: qualified,
		candidates: &configuredProductionCandidateSource{
			inspector:        environment.NewInspector(),
			config:           cfg,
			policyIdentities: identities,
			providerTimeouts: timeouts,
			source:           local,
			attestor:         stableHeartbeatLocalityAttestor{},
			staticRequest:    localityRequest,
		},
	}, namespaceRoot
}

func TestHeartbeatDrainsTerminalWithDetachedContextOnLateCancellation(t *testing.T) {
	t.Run("cancelled caller context after NewQualifiedRun succeeds still drains panes and wipes projected credentials", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		terminalRunner := &heartbeatProbeTerminalRunner{
			t:      t,
			nonces: &heartbeatSeqNonceGenerator{},
		}
		graph, namespaceRoot := newRealGrokHeartbeatTestGraph(t, terminalRunner, func(inner reviewrun.CurrentQualifier) reviewrun.CurrentQualifier {
			return reviewrun.CurrentQualifierFunc(func(qCtx context.Context, req reviewrun.CurrentQualificationRequest) (reviewrun.CurrentQualificationResult, error) {
				res, err := inner.QualifyCurrent(qCtx, req)
				// Cancel caller ctx immediately after qualification succeeds so
				// probeHeartbeat invokes run.DrainTerminal with an already-cancelled ctx.
				cancel()
				return res, err
			})
		})

		result, err := graph.probeHeartbeat(ctx, appheartbeat.Request{ProviderID: "grok"})
		if err != nil {
			t.Fatalf("probeHeartbeat error = %v", err)
		}
		if err := result.Validate(); err != nil {
			t.Fatalf("result.Validate() = %v", err)
		}
		if !result.Attempted || result.Status != "succeeded" || result.ReasonCode != "heartbeat_succeeded" {
			t.Fatalf("result = %+v, want attempted=true succeeded/heartbeat_succeeded", result)
		}

		terminalRunner.mu.Lock()
		authPath := terminalRunner.projectedAuthPath
		liveDrains := terminalRunner.liveDrains
		liveDeadlines := terminalRunner.liveDrainDeadlines
		cancelledDrains := terminalRunner.cancelledDrains
		terminalRunner.mu.Unlock()
		if authPath == "" || liveDrains != 1 || liveDeadlines != 1 || cancelledDrains != 0 {
			t.Fatalf("terminal drain stats: authPath=%q liveDrains=%d liveDeadlines=%d cancelledDrains=%d",
				authPath, liveDrains, liveDeadlines, cancelledDrains)
		}
		if _, statErr := os.Lstat(authPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("projected credential %q was not unlinked after detached drain: %v", authPath, statErr)
		}
		if entries, readErr := os.ReadDir(namespaceRoot); readErr != nil || len(entries) != 0 {
			t.Fatalf("namespaceRoot %q not empty after detached drain: entries=%d err=%v", namespaceRoot, len(entries), readErr)
		}
	})

	t.Run("NewQualifiedRun failure under cancelled context drains retained registry owner and wipes projected credentials", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		terminalRunner := &heartbeatProbeTerminalRunner{
			t:      t,
			nonces: &heartbeatSeqNonceGenerator{},
			onRunTerminal: func(_ string) error {
				// Cancel caller ctx during probe so NewQualifiedRun's internal
				// closeAdmitted(ctx) fails on cancelled ctx and returns a retained owner.
				cancel()
				return context.Canceled
			},
		}
		graph, namespaceRoot := newRealGrokHeartbeatTestGraph(t, terminalRunner, nil)

		result, err := graph.probeHeartbeat(ctx, appheartbeat.Request{ProviderID: "grok"})
		if err != nil {
			t.Fatalf("probeHeartbeat error = %v", err)
		}
		if err := result.Validate(); err != nil {
			t.Fatalf("result.Validate() = %v", err)
		}
		if !result.Attempted || result.Status != "execution_failure" || result.ReasonCode != "provider_execution_failed" {
			t.Fatalf("result = %+v, want attempted=true execution_failure/provider_execution_failed", result)
		}

		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("caller ctx.Err() = %v, want context.Canceled", ctx.Err())
		}
		terminalRunner.mu.Lock()
		authPath := terminalRunner.projectedAuthPath
		cancelledDrains := terminalRunner.cancelledDrains
		liveDrains := terminalRunner.liveDrains
		liveDeadlines := terminalRunner.liveDrainDeadlines
		terminalRunner.mu.Unlock()
		// Registry.Close rejects a cancelled ctx immediately without invoking
		// DrainLabeledPanes, so liveDrains==1 proves probeHeartbeat's detached
		// drain recovered the retained cleanup owner and wiped credentials.
		if authPath == "" || cancelledDrains != 0 || liveDrains != 1 || liveDeadlines != 1 {
			t.Fatalf("retained owner drain stats: authPath=%q cancelledDrains=%d liveDrains=%d liveDeadlines=%d",
				authPath, cancelledDrains, liveDrains, liveDeadlines)
		}
		if _, statErr := os.Lstat(authPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("projected credential %q leaked after retained-owner drain: %v", authPath, statErr)
		}
		if entries, readErr := os.ReadDir(namespaceRoot); readErr != nil || len(entries) != 0 {
			t.Fatalf("namespaceRoot %q not empty after retained-owner drain: entries=%d err=%v", namespaceRoot, len(entries), readErr)
		}
	})

	t.Run("NewQualifiedRun failure carrying CleanupOwner drains owner with live bounded context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Produce one valid drained receipt for the CleanupOwner stub.
		seedRunner := &heartbeatProbeTerminalRunner{t: t, nonces: &heartbeatSeqNonceGenerator{}}
		seedGraph, _ := newRealGrokHeartbeatTestGraph(t, seedRunner, nil)
		seedLease, err := seedGraph.fixtures.Acquire(context.Background(), domain.RoleLogic)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = seedLease.DrainTerminal(context.Background()) }()
		cand, err := seedGraph.candidates.newHeartbeatCandidate(context.Background(), seedLease.WorkspaceSnapshotIdentity(), reviewrun.FamilyGrok, "")
		if err != nil {
			t.Fatal(err)
		}
		seedRun, err := seedGraph.qualified.NewQualifiedRun(context.Background(), []reviewrun.QualifiedRunCandidate{cand})
		if err != nil {
			t.Fatal(err)
		}
		validReceipt, err := seedRun.DrainTerminal(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		ownerStub := &heartbeatCleanupOwnerStub{receipt: validReceipt}
		terminalRunner := &heartbeatProbeTerminalRunner{t: t, nonces: &heartbeatSeqNonceGenerator{}}
		graph, namespaceRoot := newRealGrokHeartbeatTestGraph(t, terminalRunner, func(_ reviewrun.CurrentQualifier) reviewrun.CurrentQualifier {
			return reviewrun.CurrentQualifierFunc(func(_ context.Context, _ reviewrun.CurrentQualificationRequest) (reviewrun.CurrentQualificationResult, error) {
				cancel()
				return reviewrun.CurrentQualificationResult{}, heartbeatRetainedCleanupOwnerError{
					cause: context.Canceled,
					owner: ownerStub,
				}
			})
		})

		result, err := graph.probeHeartbeat(ctx, appheartbeat.Request{ProviderID: "grok"})
		if err != nil {
			t.Fatalf("probeHeartbeat error = %v", err)
		}
		if err := result.Validate(); err != nil {
			t.Fatalf("result.Validate() = %v", err)
		}
		ownerStub.mu.Lock()
		ownerCalls, ownerLive, ownerDeadlines := ownerStub.calls, ownerStub.liveCalls, ownerStub.hasDeadlines
		ownerStub.mu.Unlock()
		if ownerCalls != 1 || ownerLive != 1 || ownerDeadlines != 1 {
			t.Fatalf("CleanupOwner drain calls=%d live=%d deadlines=%d, want 1/1/1", ownerCalls, ownerLive, ownerDeadlines)
		}
		if entries, readErr := os.ReadDir(namespaceRoot); readErr != nil || len(entries) != 0 {
			t.Fatalf("namespaceRoot %q not empty after retained-owner drain: entries=%d err=%v", namespaceRoot, len(entries), readErr)
		}
	})

	t.Run("detached drain failures surface heartbeat_cleanup_failed on both success and failure paths", func(t *testing.T) {
		for _, failQual := range []bool{false, true} {
			name := "post-success-drain-failure"
			if failQual {
				name = "retained-owner-drain-failure"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				terminalRunner := &heartbeatProbeTerminalRunner{
					t:                t,
					nonces:           &heartbeatSeqNonceGenerator{},
					failLiveDrainErr: errors.New("pane drain failed"),
				}
				if failQual {
					terminalRunner.onRunTerminal = func(_ string) error {
						cancel()
						return context.Canceled
					}
				}
				var wrap func(reviewrun.CurrentQualifier) reviewrun.CurrentQualifier
				if !failQual {
					wrap = func(inner reviewrun.CurrentQualifier) reviewrun.CurrentQualifier {
						return reviewrun.CurrentQualifierFunc(func(qCtx context.Context, req reviewrun.CurrentQualificationRequest) (reviewrun.CurrentQualificationResult, error) {
							res, err := inner.QualifyCurrent(qCtx, req)
							cancel()
							return res, err
						})
					}
				}
				graph, _ := newRealGrokHeartbeatTestGraph(t, terminalRunner, wrap)

				result, err := graph.probeHeartbeat(ctx, appheartbeat.Request{ProviderID: "grok"})
				if err != nil {
					t.Fatalf("probeHeartbeat error = %v", err)
				}
				if err := result.Validate(); err != nil {
					t.Fatalf("result.Validate() = %v", err)
				}
				if result.Status != "execution_failure" || result.ReasonCode != "heartbeat_cleanup_failed" {
					t.Fatalf("result = %+v, want execution_failure/heartbeat_cleanup_failed", result)
				}
				terminalRunner.mu.Lock()
				liveDrains := terminalRunner.liveDrains
				terminalRunner.mu.Unlock()
				if liveDrains != 1 {
					t.Fatalf("liveDrains = %d, want 1", liveDrains)
				}
			})
		}
	})
}

func TestHeartbeatStagedCapabilityPromptUsesQualificationFixtureV4(t *testing.T) {
	terminalRunner := &heartbeatProbeTerminalRunner{
		t:      t,
		nonces: &heartbeatSeqNonceGenerator{},
	}
	graph, namespaceRoot := newRealGrokHeartbeatTestGraph(t, terminalRunner, nil)

	result, err := graph.probeHeartbeat(context.Background(), appheartbeat.Request{ProviderID: "grok"})
	if err != nil {
		t.Fatalf("probeHeartbeat error = %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("result.Validate() = %v", err)
	}
	if !result.Attempted || result.Status != "succeeded" || result.ReasonCode != "heartbeat_succeeded" {
		t.Fatalf("result = %+v, want attempted=true succeeded/heartbeat_succeeded", result)
	}

	terminalRunner.mu.Lock()
	stagedPrompt := terminalRunner.stagedPrompt
	terminalRunner.mu.Unlock()
	rootNonce, linkNonce := terminalRunner.nonces.latestPair()
	const (
		wantFirstLine   = "Prove readiness by returning exactly one JSON object and nothing else.\n"
		wantNeutralLine = "The root, link, and role values below are random synthetic test identifiers with no secret meaning.\n"
	)
	if !strings.HasPrefix(stagedPrompt, wantFirstLine) {
		t.Fatalf("staged capability prompt line 1 mismatch: %q", stagedPrompt)
	}
	wantBindings := wantNeutralLine + "root=" + rootNonce + "\nlink=" + linkNonce + "\nrole=" + string(domain.RoleLogic) + "\n"
	if rootNonce == "" || linkNonce == "" || !strings.Contains(stagedPrompt, wantBindings) {
		t.Fatalf("staged capability prompt missing v4 neutral line or bindings %q: %q", wantBindings, stagedPrompt)
	}
	if entries, readErr := os.ReadDir(namespaceRoot); readErr != nil || len(entries) != 0 {
		t.Fatalf("namespaceRoot %q not empty after heartbeat drain: entries=%d err=%v", namespaceRoot, len(entries), readErr)
	}
}
