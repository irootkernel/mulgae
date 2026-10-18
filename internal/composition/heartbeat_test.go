//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestHeartbeatCursorWithoutTokenFailsBeforeQualifiedRun(t *testing.T) {
	t.Setenv("CURSOR_AUTH_TOKEN", "")
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
	workspaceRoot := canonicalTestTempDir(t)
	anchoredWorkspace, err := ports.NewAnchoredRoot(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspace.NewMaterializer(anchoredWorkspace, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	graph := &productionRuntimeGraph{
		clock:     mcpTestClock{},
		fixtures:  fixtures,
		qualified: &reviewrun.QualifiedRunFactory{},
		candidates: &configuredProductionCandidateSource{
			inspector: environment.NewInspector(),
			config: adapterconfig.Config{Providers: adapterconfig.ProvidersConfig{
				Grok:   &adapterconfig.GrokProviderConfig{Executable: executable},
				Cursor: &adapterconfig.CursorProviderConfig{Executable: executable},
			}},
			policyIdentities: identities,
			providerTimeouts: timeouts,
			source:           local,
			attestor:         stableHeartbeatLocalityAttestor{},
			staticRequest:    localityRequest,
		},
	}
	result, err := graph.probeHeartbeat(context.Background(), appheartbeat.Request{ProviderID: "cursor"})
	if err != nil || result.Attempted || result.ProviderID != "cursor" || result.Status != "execution_failure" || result.ReasonCode != "cursor_auth_token_required" {
		t.Fatalf("heartbeat result status=%s reason=%s attempted=%t err=%v", result.Status, result.ReasonCode, result.Attempted, err)
	}
}
