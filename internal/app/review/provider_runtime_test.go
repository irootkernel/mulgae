package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type providerRuntimeDiagnosticResolver struct {
	runID domain.RunID
	sink  ports.RuntimeDiagnosticSink
}

func (resolver providerRuntimeDiagnosticResolver) RuntimeDiagnosticSink(runID domain.RunID) (ports.RuntimeDiagnosticSink, bool) {
	return resolver.sink, resolver.sink != nil && runID == resolver.runID
}

type providerRuntimeRawSink struct {
	streams map[domain.RuntimeDiagnosticStream][]byte
	events  []domain.RuntimeDiagnosticEventCode
}

func (sink *providerRuntimeRawSink) Emit(_ context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	sink.events = append(sink.events, draft.Input().Event)
	return domain.RuntimeDiagnosticEvent{}, nil
}
func (sink *providerRuntimeRawSink) PersistRaw(_ context.Context, request ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	content, err := io.ReadAll(request.Source())
	if err != nil {
		return ports.RuntimeDiagnosticRawResult{}, err
	}
	if sink.streams == nil {
		sink.streams = make(map[domain.RuntimeDiagnosticStream][]byte)
	}
	sink.streams[request.Stream()] = append([]byte(nil), content...)
	path, err := ports.NewSafeRelativePath("diagnostics/test/" + string(request.Stream()) + ".raw")
	if err != nil {
		return ports.RuntimeDiagnosticRawResult{}, err
	}
	return ports.NewRuntimeDiagnosticRawResult(request.Stream(), path, nil, int64(len(content)))
}
func (*providerRuntimeRawSink) ReplaceRunStatus(context.Context, ports.RuntimeDiagnosticRunStatus) error {
	return nil
}
func (*providerRuntimeRawSink) ReplaceAttemptStatus(context.Context, ports.RuntimeDiagnosticAttemptStatus) error {
	return nil
}
func (*providerRuntimeRawSink) ReplaceInvocationStatus(context.Context, ports.RuntimeDiagnosticInvocationStatus) error {
	return nil
}
func (*providerRuntimeRawSink) Finalize(context.Context, ports.RuntimeDiagnosticFinalizeRequest) (ports.RuntimeDiagnosticFinalizeResult, error) {
	return ports.RuntimeDiagnosticFinalizeResult{}, nil
}
func (*providerRuntimeRawSink) URI() (ports.SafeRelativePath, bool) {
	return ports.SafeRelativePath{}, false
}

func TestProviderRuntimePersistsSeparatedRawReferences(t *testing.T) {
	sessionID, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	attemptID := coordinatorTypesAttemptID(t, 12)
	job, err := newCoordinatorInvocationJob(
		sessionID, runID, domain.RoleLogic, AttemptKindPrimary,
		coordinatorTypesRoute(t, "fake.logic", "diagnostic-lane"), coordinatorTypesTarget(t, 13),
		coordinatorTypesLimits(t), attemptID, domain.InvocationInitial, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	sink := &providerRuntimeRawSink{}
	key := captureKey{attemptID: attemptID, sequence: 1}
	runtime := &ProviderInvocationRuntime{
		diagnostics: providerRuntimeDiagnosticResolver{runID: runID, sink: sink},
		inventory: map[captureKey]RuntimeArtifactInventory{
			key: {
				runID: runID, attemptID: attemptID, sequence: 1,
				sourceInvocationID:    "i_019f5a09-5eec-7001-8001-000000000014",
				executionInvocationID: "019f5a09-5eec-7001-8001-000000000015",
			},
		},
	}
	if err := runtime.emitInvocationDiagnostic(context.Background(), job, domain.RuntimeDiagnosticInfo, domain.DiagnosticInvocationPrepared, "", string(domain.InvocationQueued), "", "", 0, false, "", 0); err != nil {
		t.Fatalf("emit invocation prepared: %v", err)
	}
	if err := runtime.persistDiagnosticRaw(context.Background(), job, key, []byte("stdout bytes"), []byte("stderr bytes")); err != nil {
		t.Fatal(err)
	}
	if string(sink.streams[domain.DiagnosticStdout]) != "stdout bytes" || string(sink.streams[domain.DiagnosticStderr]) != "stderr bytes" {
		t.Fatal("diagnostic sink did not retain separated streams")
	}
	inventory := runtime.inventory[key]
	stdout, hasStdout := inventory.DiagnosticStdout()
	stderr, hasStderr := inventory.DiagnosticStderr()
	if !hasStdout || !hasStderr || stdout.Stream() != domain.DiagnosticStdout || stderr.Stream() != domain.DiagnosticStderr {
		t.Fatal("runtime inventory did not retain separated raw references")
	}
}

func TestProviderRuntimeOutputReceivedRequiresNonEmptyStdout(t *testing.T) {
	sessionID, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	attemptID := coordinatorTypesAttemptID(t, 12)
	job, err := newCoordinatorInvocationJob(
		sessionID, runID, domain.RoleLogic, AttemptKindPrimary,
		coordinatorTypesRoute(t, "fake.logic", "diagnostic-lane"), coordinatorTypesTarget(t, 13),
		coordinatorTypesLimits(t), attemptID, domain.InvocationInitial, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	packetBytes := []byte("provider packet")
	packet, err := ports.NewProviderPacket(packetBytes, providerRuntimePacketDigest(packetBytes))
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := ports.NewProviderInvocationWithPacket(
		job.Role(), job.Route().ProviderInstance(), job.AttemptID(), ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000014", "019f5a09-5eec-7001-8001-000000000015",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		stdout     []byte
		wantOutput bool
	}{
		{name: "non-empty", stdout: []byte("candidate output"), wantOutput: true},
		{name: "empty", stdout: nil, wantOutput: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation, err := ports.NewPartialFailedProviderExecutionObservation(
				ports.ProviderExecutionStatusInternalFailure, invocation, test.stdout, nil,
				"process_wait_failed", domain.DiagnosticCauseProviderProcessWaitFailed, "", 1024, 1024,
			)
			if err != nil {
				t.Fatal(err)
			}
			sink := &providerRuntimeRawSink{}
			runtime := &ProviderInvocationRuntime{
				diagnostics: providerRuntimeDiagnosticResolver{runID: job.RunID(), sink: sink},
			}
			if err := runtime.emitObservationDiagnostics(context.Background(), job, observation); err != nil {
				t.Fatal(err)
			}
			gotOutput := false
			for _, event := range sink.events {
				if event == domain.DiagnosticOutputReceived {
					gotOutput = true
				}
			}
			if gotOutput != test.wantOutput {
				t.Fatalf("output-received event = %t, want %t; events=%v", gotOutput, test.wantOutput, sink.events)
			}
		})
	}
}

func TestDiagnosticPersistenceSecurityRejectionPreservesSecurityCondition(t *testing.T) {
	drop, err := ports.NewDropMetadata("stdout", "secret_detected", 1, []string{"provider:stdout"})
	if err != nil {
		t.Fatal(err)
	}
	rejection := ports.NewRuntimeDiagnosticSecurityRejectionError(drop, errors.New("private scanner detail"))
	if got := diagnosticConditionForPersistence(rejection); got != AttemptConditionSecurityViolation {
		t.Fatalf("security rejection condition = %q", got)
	}
	if got := diagnosticConditionForPersistence(errors.New("disk failure")); got != AttemptConditionArtifactFailure {
		t.Fatalf("persistence failure condition = %q", got)
	}
}

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

type explicitRuntimeTestIssuer struct {
	source    prompt.SourceInvocationID
	execution prompt.ExecutionInvocationID
}

func (issuer explicitRuntimeTestIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return issuer.source, nil
}

func (issuer explicitRuntimeTestIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return issuer.execution, nil
}

type concurrentExplicitRuntimeProvider struct {
	entered chan<- domain.Role
	release <-chan struct{}
}

func (provider concurrentExplicitRuntimeProvider) Invoke(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderResult, error) {
	select {
	case provider.entered <- invocation.Role():
	case <-ctx.Done():
		return ports.ProviderResult{}, ctx.Err()
	}
	select {
	case <-provider.release:
		return ports.ProviderResult{}, errors.New("test provider stopped")
	case <-ctx.Done():
		return ports.ProviderResult{}, ctx.Err()
	}
}

func TestExplicitRuntimeInvocationsDoNotSerializeDistinctLanes(t *testing.T) {
	targetBytes := []byte("immutable target")
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetStdin, SHA256: strings.TrimPrefix(sha256Identifier(targetBytes), "sha256:"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	roles := []domain.Role{domain.RoleLogic, domain.RoleDocumentation}
	jobs := make([]InvocationJob, len(roles))
	materials := make([]RuntimePrompt, len(roles))
	for index, role := range roles {
		attemptID := coordinatorTypesAttemptID(t, index+1)
		jobs[index], err = newCoordinatorInvocationJob(
			sessionID, runID, role, AttemptKindPrimary,
			coordinatorTypesRoute(t, "fake."+string(role), string(role)+"-lane"), target,
			coordinatorTypesLimits(t), attemptID, domain.InvocationInitial, uint64(index+1),
		)
		if err != nil {
			t.Fatal(err)
		}
		layer, layerErr := prompt.NewTrustedLayer("explicit-runtime-"+string(role), "v1", []byte("Return JSON only."))
		if layerErr != nil {
			t.Fatal(layerErr)
		}
		template, templateErr := prompt.ComposeTrustedTemplate("explicit-runtime-"+string(role), "v1", layer)
		if templateErr != nil {
			t.Fatal(templateErr)
		}
		roleTaskID, parseErr := prompt.ParseRoleTaskID(fmt.Sprintf("rt_019f5a09-5eec-7001-8001-%012d", index+20))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		coordinates, coordinateErr := prompt.NewScopeCoordinates(sessionID, runID, roleTaskID, attemptID)
		if coordinateErr != nil {
			t.Fatal(coordinateErr)
		}
		sourceID, parseErr := prompt.ParseSourceInvocationID(fmt.Sprintf("i_019f5a09-5eec-7001-8001-%012d", index+30))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		executionID, parseErr := prompt.ParseExecutionInvocationID(fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", index+40))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		compiler, compilerErr := prompt.NewCompiler(template, explicitRuntimeTestIssuer{source: sourceID, execution: executionID})
		if compilerErr != nil {
			t.Fatal(compilerErr)
		}
		compiled, compileErr := compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(targetBytes)})
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		materials[index] = RuntimePrompt{Prompt: compiled, Target: targetBytes, AdapterProfile: "test-profile"}
	}

	entered := make(chan domain.Role, len(roles))
	release := make(chan struct{})
	verifier, err := evidence.NewVerifier(&reviewTestEvidenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ProviderInvocationRuntime{
		provider:  concurrentExplicitRuntimeProvider{entered: entered, release: release},
		validator: newReviewValidator(t), verifier: verifier, policy: DefaultEvidencePolicy(),
		pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture), inventory: make(map[captureKey]RuntimeArtifactInventory),
	}
	done := make(chan struct{}, len(roles))
	for index := range roles {
		go func(index int) {
			_ = runtime.invokeExplicitMaterial(context.Background(), jobs[index], materials[index], false)
			done <- struct{}{}
		}(index)
	}
	for range roles {
		select {
		case <-entered:
		case <-time.After(500 * time.Millisecond):
			close(release)
			t.Fatal("distinct explicit runtime lane was serialized behind another provider invocation")
		}
	}
	close(release)
	for range roles {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("explicit runtime invocation did not stop")
		}
	}
	if inventories := runtime.DrainRuntimeArtifactsForRun(runID); len(inventories) != len(roles) {
		t.Fatalf("runtime inventories = %d, want %d", len(inventories), len(roles))
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
	for _, cause := range []domain.RuntimeDiagnosticCause{
		domain.DiagnosticCausePromptFilePreStartFailed,
		domain.DiagnosticCausePromptFilePostEndFailed,
		domain.DiagnosticCauseTransportReceiptMismatch,
		domain.DiagnosticCauseLifecycleReceiptInvalid,
		domain.DiagnosticCauseOutputFrameMismatch,
		domain.DiagnosticCauseSignalReceiptMismatch,
	} {
		typed, err := ports.NewProviderRuntimeError(cause, errors.New("closed local detail"))
		if err != nil {
			t.Fatal(err)
		}
		if got := runtimeProviderErrorCondition(context.Background(), typed); got != AttemptConditionSecurityViolation {
			t.Fatalf("transport/lifecycle cause %q condition = %q, want security violation", cause, got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := runtimeProviderErrorCondition(ctx, ports.ErrWorkspaceSnapshotDrift); got != AttemptConditionCancelled {
		t.Fatalf("cancelled workspace drift condition = %q, want cancelled", got)
	}
}

func TestRuntimeProviderErrorConditionDistinguishesObservedAndEnclosingTimeouts(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	observed, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseTimedOut, errors.New("closed provider detail"))
	if err != nil {
		t.Fatal(err)
	}
	if got := runtimeProviderErrorCondition(ctx, observed); got != AttemptConditionProviderTimeout {
		t.Fatalf("observed timeout condition = %q, want provider timeout", got)
	}
	processObserved, err := ports.NewProcessExecutionError(
		domain.DiagnosticCauseTimedOut,
		"",
		nil,
		nil,
		context.DeadlineExceeded,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := runtimeProviderErrorCondition(ctx, processObserved); got != AttemptConditionProviderTimeout {
		t.Fatalf("observed process timeout condition = %q, want provider timeout", got)
	}
	if got := runtimeProviderErrorCondition(ctx, context.DeadlineExceeded); got != AttemptConditionTimeout {
		t.Fatalf("enclosing timeout condition = %q, want execution timeout", got)
	}
}

func TestObservedUnparseableProviderOutputIsFallbackOnly(t *testing.T) {
	if got := observedStatusCondition(ports.ProviderExecutionStatusArtifactFailure, domain.DiagnosticCauseOutputDecodeFailed); got != AttemptConditionProviderOutputDecodeFailed {
		t.Fatalf("invalid provider framing condition = %q", got)
	}
	if got := observedStatusCondition(ports.ProviderExecutionStatusArtifactFailure, domain.DiagnosticCauseOutputMissing); got != AttemptConditionProviderOutputMissing {
		t.Fatalf("missing provider output condition = %q", got)
	}
	for _, cause := range []domain.RuntimeDiagnosticCause{domain.DiagnosticCauseObservationInvalid, domain.DiagnosticCauseProviderExecutionFailed} {
		if got := observedStatusCondition(ports.ProviderExecutionStatusArtifactFailure, cause); got != AttemptConditionArtifactFailure {
			t.Fatalf("artifact cause %q condition = %q", cause, got)
		}
	}
}

func TestObservedLoginRequiredIsFailClosed(t *testing.T) {
	if got := observedStatusCondition(ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseLoginRequired); got != AttemptConditionLoginRequired {
		t.Fatalf("login-required observation condition = %q", got)
	}
	if got := observedStatusCondition(ports.ProviderExecutionStatusAuthentication, domain.DiagnosticCauseAuthenticationFailed); got != AttemptConditionAuthentication {
		t.Fatalf("generic authentication observation condition = %q", got)
	}
	typed, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseLoginRequired, errors.New("private native detail"))
	if err != nil {
		t.Fatal(err)
	}
	if got := runtimeProviderErrorCondition(context.Background(), typed); got != AttemptConditionLoginRequired {
		t.Fatalf("typed login-required runtime condition = %q", got)
	}
	if got := runtimeProviderErrorCondition(context.Background(), errors.New("provider login_required")); got != AttemptConditionInternalInvariant {
		t.Fatalf("arbitrary runtime text condition = %q", got)
	}
}

func TestObservedSpawnFailurePolicyUsesStatusAndFailsClosedWithoutObservation(t *testing.T) {
	tests := []struct {
		name   string
		status ports.ProviderExecutionStatus
		want   AttemptCondition
	}{
		{"unavailable", ports.ProviderExecutionStatusUnavailable, AttemptConditionProviderUnavailable},
		{"configuration", ports.ProviderExecutionStatusConfigurationViolation, AttemptConditionConfigurationViolation},
		{"security", ports.ProviderExecutionStatusSecurityViolation, AttemptConditionSecurityViolation},
		{"internal", ports.ProviderExecutionStatusInternalFailure, AttemptConditionInternalInvariant},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := observedStatusCondition(test.status, domain.DiagnosticCauseProviderSpawnFailed); got != test.want {
				t.Fatalf("spawn failure status %q condition = %q, want %q", test.status, got, test.want)
			}
		})
	}

	typed, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderSpawnFailed, errors.New("private spawn detail"))
	if err != nil {
		t.Fatal(err)
	}
	if got := runtimeProviderErrorCondition(context.Background(), typed); got != AttemptConditionInternalInvariant {
		t.Fatalf("unobserved spawn failure condition = %q, want internal invariant", got)
	}
}

func TestInitialValidationFailureRequiresAConcreteRepairPlan(t *testing.T) {
	if got := initialValidationFailureCondition(nil); got != AttemptConditionUnrepairableProviderOutput {
		t.Fatalf("planless validation failure condition = %q", got)
	}
	plan, err := validation.NewExactEvidenceRepairPlan([]byte(`{"schema_version":"mulgae-provider-review-output.v1"}`), []string{"/findings/0/evidence/0/current/quote"})
	if err != nil {
		t.Fatal(err)
	}
	if got := initialValidationFailureCondition(plan); got != AttemptConditionInvalidProviderOutput {
		t.Fatalf("planned validation failure condition = %q", got)
	}
}

func TestPromptConstructionFailureDoesNotAuthorizeProviderOutputRepair(t *testing.T) {
	if got := runtimePromptErrorCondition(context.Background(), errors.New("identity issuance failed")); got != AttemptConditionInternalInvariant {
		t.Fatalf("prompt construction failure condition = %q, want %q", got, AttemptConditionInternalInvariant)
	}
	decision, err := DecideTransition(TransitionInput{
		Condition: AttemptConditionInternalInvariant, FallbackConfigured: true, FallbackEligible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ScheduleRepair() || decision.ScheduleFallback() || decision.TerminalProjection() != TerminalProjectionFailed {
		t.Fatalf("prompt construction decision = %#v", decision)
	}
}

func TestInitialQuoteMismatchRetainsExactEvidenceRepairPlan(t *testing.T) {
	for _, severity := range []domain.Severity{domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		t.Run(string(severity), func(t *testing.T) {
			job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
			finding := bridgeFindingJSON("Quote mismatch", []bridgeClaimSpec{{
				path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line",
			}})
			finding = strings.Replace(finding, `"severity":"high"`, fmt.Sprintf(`"severity":%q`, severity), 1)
			validated := bridgeValidatedReview(t, job.Target().SHA256(), []string{finding})
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
		})
	}
}

func TestRepairQuoteMismatchIsUnrepairableForOptionalSeverity(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
	job.purpose = domain.InvocationRepair
	finding := bridgeFindingJSON("Quote mismatch", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line",
	}})
	finding = strings.Replace(finding, `"severity":"high"`, `"severity":"low"`, 1)
	validated := bridgeValidatedReview(t, job.Target().SHA256(), []string{finding})
	verifier, err := evidence.NewVerifier(&bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideHead, "src/file.go"): {availability: evidence.ImmutableTargetAvailable, bytes: []byte("line\n")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ProviderInvocationRuntime{verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput)}
	outcome := runtime.accept(context.Background(), job, validated)
	if outcome.Succeeded() || coordinatorOutcomeCondition(outcome) != AttemptConditionUnrepairableEvidence || len(runtime.pending) != 0 {
		t.Fatalf("repair quote mismatch outcome = %#v, pending=%#v", outcome, runtime.pending)
	}
}

func TestRepairCorrectedOptionalQuoteMismatchSucceeds(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleSecurity, "fake.security", 1)
	job.purpose = domain.InvocationRepair
	finding := bridgeFindingJSON("Corrected quote", []bridgeClaimSpec{{
		path: "src/file.go", side: evidence.SideHead, lineStart: 1, lineEnd: 1, quote: "line\n",
	}})
	finding = strings.Replace(finding, `"severity":"high"`, `"severity":"low"`, 1)
	validated := bridgeValidatedReview(t, job.Target().SHA256(), []string{finding})
	verifier, err := evidence.NewVerifier(&bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideHead, "src/file.go"): {availability: evidence.ImmutableTargetAvailable, bytes: []byte("line\n")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ProviderInvocationRuntime{verifier: verifier, policy: DefaultEvidencePolicy(), pending: make(map[domain.AttemptID]InvocationRepairInput)}
	outcome := runtime.accept(context.Background(), job, validated)
	if !outcome.Succeeded() || len(runtime.pending) != 0 {
		t.Fatalf("corrected repair outcome = %#v, pending=%#v", outcome, runtime.pending)
	}
	output, ok := outcome.Output()
	if !ok || len(output.Findings()) != 1 || output.Findings()[0].EvidenceState() != domain.EvidenceVerified {
		t.Fatalf("corrected repair output = %#v, present=%t", output, ok)
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
	_, _ = hash.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
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
