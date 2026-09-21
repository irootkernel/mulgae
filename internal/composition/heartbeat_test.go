//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
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
		Grok:  &adapterconfig.GrokProviderConfig{Model: "grok-4.5", ReasoningEffort: "high-precision"},
		Codex: &adapterconfig.CodexProviderConfig{Model: "gpt-5.3-codex", ReasoningEffort: "high"},
	}}}
	grokModel, grokEffort, codexModel, codexEffort := source.providerSettings()
	if grokModel != "grok-4.5" || grokEffort != "high-precision" || codexModel != "gpt-5.3-codex" || codexEffort != "high" {
		t.Fatalf("provider settings = %q/%q/%q/%q", grokModel, grokEffort, codexModel, codexEffort)
	}
	heartbeatSource := *source
	heartbeatGrokModel, heartbeatGrokEffort, _, _ := heartbeatSource.providerSettings()
	if heartbeatGrokModel != grokModel || heartbeatGrokEffort != grokEffort {
		t.Fatalf("heartbeat settings = %q/%q, want %q/%q", heartbeatGrokModel, heartbeatGrokEffort, grokModel, grokEffort)
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
