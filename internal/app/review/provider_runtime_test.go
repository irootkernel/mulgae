package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestAttemptCaptureArtifactsAreDefensive(t *testing.T) {
	attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, []byte("candidate"), false)
	if err != nil {
		t.Fatal(err)
	}
	capture := AttemptCapture{attemptID: attemptID, sequence: 1, artifacts: []ports.CapturedAttemptArtifact{artifact}}
	artifacts := capture.Artifacts()
	artifacts[0] = ports.CapturedAttemptArtifact{}
	if got := capture.Artifacts(); len(got) != 1 || string(got[0].Bytes()) != "candidate" {
		t.Fatal("attempt capture exposed mutable artifact slice")
	}
}

func TestReplayAndDeltaInputsDefensivelyBindBytesAndParameters(t *testing.T) {
	delta := DeltaInvocationMaterial{SourceTarget: []byte("source"), CurrentTarget: []byte("current"), Delta: []byte("delta")}
	replay := ExactReplayInput{SourceProviderInstance: "fake.logic", Stdin: []byte("stdin"), AdapterParameters: map[string]string{"model": "fixed"}}
	deltaCopy := cloneDeltaInvocationMaterial(delta)
	replayCopy := cloneExactReplayInput(replay)
	delta.SourceTarget[0] = 'X'
	replay.Stdin[0] = 'X'
	replay.AdapterParameters["model"] = "other"
	if replayCopy.SourceProviderInstance != "fake.logic" || string(deltaCopy.SourceTarget) != "source" ||
		string(replayCopy.Stdin) != "stdin" ||
		!reflect.DeepEqual(replayCopy.AdapterParameters, map[string]string{"model": "fixed"}) {
		t.Fatal("explicit invocation input exposed caller mutation")
	}
	if sameAdapterParameters(replayCopy.AdapterParameters, replay.AdapterParameters) {
		t.Fatal("adapter tuple mismatch was accepted")
	}
}

type providerRuntimeWorkspaceAuthority struct {
	identity ports.WorkspaceSnapshotIdentity
}

func (authority providerRuntimeWorkspaceAuthority) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return authority.identity
}

func (providerRuntimeWorkspaceAuthority) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}

func TestProviderInvocationWorkspaceAuthorityIdentity(t *testing.T) {
	attempt, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ports.NewProviderPacket([]byte("packet"), providerRuntimePacketDigest([]byte("packet")))
	if err != nil {
		t.Fatal(err)
	}
	first := providerRuntimeWorkspaceAuthority{identity: providerRuntimeWorkspaceIdentity(t, "a")}
	second := providerRuntimeWorkspaceAuthority{identity: providerRuntimeWorkspaceIdentity(t, "a")}
	substitute := providerRuntimeWorkspaceAuthority{identity: providerRuntimeWorkspaceIdentity(t, "b")}

	offline, err := ports.NewProviderInvocationWithPacket(
		domain.RoleSecurity, "fake.logic", attempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := offline.ExecutionWorkspace(); ok {
		t.Fatal("offline invocation unexpectedly has workspace authority")
	}

	initial, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleSecurity, "fake.logic", attempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003", first,
	)
	if err != nil {
		t.Fatal(err)
	}
	repair, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleSecurity, "fake.logic", attempt, ports.ProviderInvocationRepair, packet,
		"i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003", first,
	)
	if err != nil {
		t.Fatal(err)
	}
	if initialIdentity, ok := initial.WorkspaceSnapshotIdentity(); !ok || !sameWorkspaceSnapshotIdentity(initialIdentity, repairWorkspaceIdentity(t, repair)) {
		t.Fatal("initial and repair invocations did not retain the same workspace identity")
	}

	identicalAuthority, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleSecurity, "fake.logic", attempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003", second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sameProviderInvocation(initial, identicalAuthority) {
		t.Fatal("equal workspace identities were compared by authority identity")
	}
	substituted, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleSecurity, "fake.logic", attempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000002", "019f5a09-5eec-7001-8001-000000000003", substitute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if sameProviderInvocation(initial, substituted) {
		t.Fatal("substituted workspace identity was accepted")
	}
}

func TestRuntimeProviderErrorConditionPreservesSecurityAndCancellation(t *testing.T) {
	if got := runtimeProviderErrorCondition(context.Background(), errors.Join(ports.ErrWorkspaceSnapshotDrift, errors.New("provider unavailable"))); got != AttemptConditionSecurityViolation {
		t.Fatalf("workspace drift condition = %q, want security violation", got)
	}
	if got := runtimeProviderErrorCondition(context.Background(), ports.ErrProviderPacketSecurity); got != AttemptConditionSecurityViolation {
		t.Fatalf("packet screening condition = %q, want security violation", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := runtimeProviderErrorCondition(ctx, ports.ErrWorkspaceSnapshotDrift); got != AttemptConditionCancelled {
		t.Fatalf("cancelled workspace drift condition = %q, want cancelled", got)
	}
}

func TestObservedUnparseableProviderOutputIsFallbackOnly(t *testing.T) {
	if got := observedStatusCondition(ports.ProviderExecutionStatusArtifactFailure, "invalid_provider_output"); got != AttemptConditionUnrepairableProviderOutput {
		t.Fatalf("invalid provider framing condition = %q", got)
	}
	for _, diagnostic := range []string{"stdout_limit", "stderr_limit", ""} {
		if got := observedStatusCondition(ports.ProviderExecutionStatusArtifactFailure, diagnostic); got != AttemptConditionArtifactFailure {
			t.Fatalf("artifact diagnostic %q condition = %q", diagnostic, got)
		}
	}
}

func TestObservedLoginRequiredIsFailClosed(t *testing.T) {
	if got := observedStatusCondition(ports.ProviderExecutionStatusAuthentication, "login_required"); got != AttemptConditionLoginRequired {
		t.Fatalf("login-required observation condition = %q", got)
	}
	if got := observedStatusCondition(ports.ProviderExecutionStatusAuthentication, "provider_auth"); got != AttemptConditionAuthentication {
		t.Fatalf("generic authentication observation condition = %q", got)
	}
	if got := runtimeProviderErrorCondition(context.Background(), errors.New("provider login_required")); got != AttemptConditionLoginRequired {
		t.Fatalf("login-required runtime error condition = %q", got)
	}
}

func TestInitialValidationFailureRequiresAConcreteRepairPlan(t *testing.T) {
	if got := initialValidationFailureCondition(nil); got != AttemptConditionUnrepairableProviderOutput {
		t.Fatalf("planless validation failure condition = %q", got)
	}
	plan, err := validation.NewExactEvidenceRepairPlan([]byte(`{"schema_version":"kar-provider-review-output.v2"}`), []string{"/findings/0/evidence/0/current/quote"})
	if err != nil {
		t.Fatal(err)
	}
	if got := initialValidationFailureCondition(plan); got != AttemptConditionInvalidProviderOutput {
		t.Fatalf("planned validation failure condition = %q", got)
	}
}

func TestInitialQuoteMismatchRetainsExactEvidenceRepairPlan(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
	validated := bridgeValidatedReview(t, job.Target().SHA256(), []string{bridgeFindingJSON("Quote mismatch", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line",
	}})})
	reader := &bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideHead, "src/file.go"): {availability: evidence.ImmutableTargetAvailable, bytes: []byte("line\n")},
	}}
	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ProviderInvocationRuntime{verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput)}
	outcome := runtime.accept(context.Background(), job, validated)
	if outcome.Succeeded() || coordinatorOutcomeCondition(outcome) != AttemptConditionInvalidEvidenceClaim {
		t.Fatalf("quote mismatch outcome = %#v", outcome)
	}
	pending, ok := runtime.pending[job.AttemptID()]
	wantPath := "/findings/0/evidence/0/current/quote"
	if !ok || pending.Plan().Mode() != validation.RepairModeExactEvidence || !reflect.DeepEqual(pending.Plan().AllowedPaths(), []string{wantPath}) ||
		!bytes.Equal(pending.InitialCandidate(), validated.OriginalRaw()) {
		t.Fatalf("retained exact evidence repair = %#v, present=%t", pending, ok)
	}
}

func providerRuntimeWorkspaceIdentity(t *testing.T, suffix string) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		"/capture/"+suffix, "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:"+strings.Repeat(suffix, 64), "policy-v1", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func providerRuntimePacketDigest(packet []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(packet)
	return hex.EncodeToString(hash.Sum(nil))
}

func repairWorkspaceIdentity(t *testing.T, invocation ports.ProviderInvocation) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, ok := invocation.WorkspaceSnapshotIdentity()
	if !ok {
		t.Fatal("repair invocation has no workspace identity")
	}
	return identity
}
