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

type providerRuntimeDropSink struct {
	providerRuntimeRawSink
	result ports.RuntimeDiagnosticRawResult
	err    error
}

func (sink *providerRuntimeDropSink) PersistRaw(context.Context, ports.RuntimeDiagnosticRawRequest) (ports.RuntimeDiagnosticRawResult, error) {
	return sink.result, sink.err
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
		sessionID, runID, domain.RoleLogic,
		coordinatorTypesRoute(t, "fake.logic"), coordinatorTypesTarget(t, 13),
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

func TestProviderRuntimeRecordsTypedRawSecretDropWithoutFailingInvocation(t *testing.T) {
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	attemptID := coordinatorTypesAttemptID(t, 12)
	job := providerRuntimeDiagnosticJob(t, runID, attemptID)
	drop, err := ports.NewDropMetadata("provider_stdout", "credential_assignment", 1, []string{"provider:stdout"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ports.NewRuntimeDiagnosticRawResult(domain.DiagnosticStdout, ports.SafeRelativePath{}, &drop, 0)
	if err != nil {
		t.Fatal(err)
	}
	sink := &providerRuntimeDropSink{result: result, err: ports.NewRuntimeDiagnosticSecurityRejectionError(drop, errors.New("scanner rejected raw stream"))}
	key := captureKey{attemptID: attemptID, sequence: 1}
	runtime := providerRuntimeWithDiagnosticInventory(t, runID, attemptID, key, sink)
	if err := runtime.persistDiagnosticRaw(context.Background(), job, key, []byte("password=placeholder"), nil); err != nil {
		t.Fatalf("typed raw drop blocked provider outcome: %v", err)
	}
	stored, ok := runtime.inventory[key].DiagnosticStdout()
	storedDrop, dropped := stored.Drop()
	if !ok || !dropped || !sameRuntimeDiagnosticDrop(*storedDrop, drop) {
		t.Fatalf("runtime inventory did not retain typed drop: %#v", stored)
	}
	for _, artifact := range runtime.captures[key].Artifacts() {
		if !artifact.SecurityRejected() || len(artifact.Bytes()) != 0 {
			t.Fatalf("raw-drop capture retained provider bytes: kind=%q rejected=%t", artifact.Kind(), artifact.SecurityRejected())
		}
	}
}

func TestProviderRuntimeRejectsMalformedOrMismatchedRawSecretDrop(t *testing.T) {
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	attemptID := coordinatorTypesAttemptID(t, 12)
	job := providerRuntimeDiagnosticJob(t, runID, attemptID)
	drop, err := ports.NewDropMetadata("provider_stdout", "credential_assignment", 1, []string{"provider:stdout"})
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := ports.NewDropMetadata("provider_stdout", "private_key_pem", 1, []string{"provider:stdout"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := ports.NewRuntimeDiagnosticRawResult(domain.DiagnosticStdout, ports.SafeRelativePath{}, &drop, 0)
	if err != nil {
		t.Fatal(err)
	}
	key := captureKey{attemptID: attemptID, sequence: 1}
	for _, test := range []struct {
		name   string
		result ports.RuntimeDiagnosticRawResult
		err    error
	}{
		{name: "mismatched metadata", result: result, err: ports.NewRuntimeDiagnosticSecurityRejectionError(mismatch, errors.New("scanner rejected raw stream"))},
		{name: "ordinary persistence error", err: errors.New("disk failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &providerRuntimeDropSink{result: test.result, err: test.err}
			runtime := providerRuntimeWithDiagnosticInventory(t, runID, attemptID, key, sink)
			if err := runtime.persistDiagnosticRaw(context.Background(), job, key, []byte("password=placeholder"), nil); err == nil {
				t.Fatal("malformed diagnostic result was accepted")
			}
			if _, ok := runtime.inventory[key].DiagnosticStdout(); ok {
				t.Fatal("failed diagnostic result entered inventory")
			}
		})
	}
}

func providerRuntimeDiagnosticJob(t *testing.T, runID domain.RunID, attemptID domain.AttemptID) InvocationJob {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	job, err := newCoordinatorInvocationJob(
		sessionID, runID, domain.RoleLogic,
		coordinatorTypesRoute(t, "fake.logic"), coordinatorTypesTarget(t, 13),
		coordinatorTypesLimits(t), attemptID, domain.InvocationInitial, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func providerRuntimeWithDiagnosticInventory(t *testing.T, runID domain.RunID, attemptID domain.AttemptID, key captureKey, sink ports.RuntimeDiagnosticSink) *ProviderInvocationRuntime {
	t.Helper()
	candidate, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, []byte("password=placeholder"), false)
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, []byte("password=placeholder"), false)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := []ports.CapturedAttemptArtifact{candidate, stdout}
	return &ProviderInvocationRuntime{
		diagnostics: providerRuntimeDiagnosticResolver{runID: runID, sink: sink},
		inventory: map[captureKey]RuntimeArtifactInventory{key: {
			runID: runID, attemptID: attemptID, sequence: 1,
			sourceInvocationID:    "i_019f5a09-5eec-7001-8001-000000000014",
			executionInvocationID: "019f5a09-5eec-7001-8001-000000000015",
			captures:              append([]ports.CapturedAttemptArtifact(nil), artifacts...),
		}},
		captures: map[captureKey]AttemptCapture{key: {attemptID: attemptID, sequence: 1, artifacts: artifacts}},
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
		sessionID, runID, domain.RoleLogic,
		coordinatorTypesRoute(t, "fake.logic"), coordinatorTypesTarget(t, 13),
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

func TestExplicitRuntimeInvocationsDoNotSerializeDistinctProviders(t *testing.T) {
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
			sessionID, runID, role,
			coordinatorTypesRoute(t, "fake."+string(role)), target,
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
			t.Fatal("distinct explicit provider invocation was serialized behind another provider invocation")
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

func TestProviderInvocationWorkspaceSharedAcrossRoles(t *testing.T) {
	packet, err := ports.NewProviderPacket([]byte("packet"), providerRuntimePacketDigest([]byte("packet")))
	if err != nil {
		t.Fatal(err)
	}
	shared := providerRuntimeWorkspaceAuthority{identity: providerRuntimeWorkspaceIdentity(t, "c")}
	logicAttempt, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	securityAttempt, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000012")
	if err != nil {
		t.Fatal(err)
	}
	logic, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleLogic, "fake.logic", logicAttempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000013", "019f5a09-5eec-7001-8001-000000000014", shared,
	)
	if err != nil {
		t.Fatal(err)
	}
	security, err := ports.NewProviderInvocationWithPacketInWorkspace(
		domain.RoleSecurity, "fake.security", securityAttempt, ports.ProviderInvocationInitial, packet,
		"i_019f5a09-5eec-7001-8001-000000000015", "019f5a09-5eec-7001-8001-000000000016", shared,
	)
	if err != nil {
		t.Fatal(err)
	}
	logicIdentity, logicOK := logic.WorkspaceSnapshotIdentity()
	securityIdentity, securityOK := security.WorkspaceSnapshotIdentity()
	if !logicOK || !securityOK || !sameWorkspaceSnapshotIdentity(logicIdentity, securityIdentity) {
		t.Fatal("roles did not share the immutable workspace snapshot identity")
	}
	if sameProviderInvocation(logic, security) {
		t.Fatal("distinct role invocations collapsed into one invocation identity")
	}
}

func TestRuntimeProviderErrorConditionPreservesProtectedFailuresAcrossContext(t *testing.T) {
	if got := runtimeProviderErrorCondition(context.Background(), errors.Join(ports.ErrWorkspaceSnapshotDrift, errors.New("provider unavailable"))); got != AttemptConditionSecurityViolation {
		t.Fatalf("workspace drift condition = %q, want security violation", got)
	}
	if got := runtimeProviderErrorCondition(context.Background(), ports.ErrProviderPacketSecurity); got != AttemptConditionSecurityViolation {
		t.Fatalf("packet screening condition = %q, want security violation", got)
	}
	if got := runtimeProviderErrorCondition(context.Background(), fmt.Errorf("registry refusal: %w", ports.ErrProviderInstanceAlreadyActive)); got != AttemptConditionInternalInvariant {
		t.Fatalf("duplicate provider instance condition = %q, want internal invariant", got)
	}
	providerSecurity, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseTransportReceiptMismatch, errors.New("closed local detail"))
	if err != nil {
		t.Fatal(err)
	}
	processSecurity, err := ports.NewProcessExecutionError(domain.DiagnosticCausePromptFilePostEndFailed, "", nil, nil, errors.New("closed local detail"))
	if err != nil {
		t.Fatal(err)
	}
	providerArtifact, err := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderOutputStagingCleanupFailed, errors.New("closed local detail"))
	if err != nil {
		t.Fatal(err)
	}
	processArtifact, err := ports.NewProcessExecutionError(domain.DiagnosticCauseProviderOutputStagingCleanupFailed, "", nil, nil, errors.New("closed local detail"))
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelDeadline()
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{"cancelled", cancelled},
		{"deadline", deadline},
	}
	protected := []struct {
		name string
		err  error
		want AttemptCondition
	}{
		{"workspace-drift", ports.ErrWorkspaceSnapshotDrift, AttemptConditionSecurityViolation},
		{"packet-security", ports.ErrProviderPacketSecurity, AttemptConditionSecurityViolation},
		{"provider-security", providerSecurity, AttemptConditionSecurityViolation},
		{"process-security", processSecurity, AttemptConditionSecurityViolation},
		{"provider-artifact", providerArtifact, AttemptConditionArtifactFailure},
		{"process-artifact", processArtifact, AttemptConditionArtifactFailure},
		{"duplicate-instance", fmt.Errorf("registry refusal: %w", ports.ErrProviderInstanceAlreadyActive), AttemptConditionInternalInvariant},
		{"unknown-internal", errors.New("unclassified provider failure"), AttemptConditionInternalInvariant},
		{"login-required", ports.ErrProviderLoginRequired, AttemptConditionLoginRequired},
	}
	for _, contextTest := range contexts {
		for _, test := range protected {
			t.Run(contextTest.name+"/"+test.name, func(t *testing.T) {
				if got := runtimeProviderErrorCondition(contextTest.ctx, test.err); got != test.want {
					t.Fatalf("condition = %q, want %q", got, test.want)
				}
			})
		}
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
	cancelled, cancelInvocation := context.WithCancel(context.Background())
	cancelInvocation()
	if got := runtimeProviderErrorCondition(cancelled, observed); got != AttemptConditionCancelled {
		t.Fatalf("cancelled observed timeout condition = %q, want cancellation", got)
	}
	if got := runtimeProviderErrorCondition(ctx, context.DeadlineExceeded); got != AttemptConditionTimeout {
		t.Fatalf("enclosing timeout condition = %q, want execution timeout", got)
	}
	if got := runtimeProviderErrorCondition(cancelled, context.Canceled); got != AttemptConditionCancelled {
		t.Fatalf("enclosing cancellation condition = %q, want cancellation", got)
	}
}

func TestRuntimeObservedTimeoutPreservesValidatedElapsedFacts(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
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
	receipt, err := ports.NewStdinWriteReceipt(int64(len(packetBytes)), int64(len(packetBytes)), providerRuntimePacketDigest(packetBytes), true)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ended := started.Add(875 * time.Millisecond)
	process, err := ports.NewProcessObservation(nil, nil, nil, ports.ProcessTerminationTimedOut, receipt, started, ended)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewFailedProviderExecutionObservationWithCause(
		ports.ProviderExecutionStatusTimedOut, invocation, process, "provider_timeout",
		domain.DiagnosticCauseTimedOut, "", 1024, 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	outcome := runtimeObservedCondition(job, AttemptConditionProviderTimeout, observation, 625*time.Millisecond)
	facts, ok := outcome.ProviderTimeoutFacts()
	if !ok || facts.ConfiguredTimeout() != job.Limits().Timeout() || facts.Elapsed() != ended.Sub(started) {
		t.Fatalf("timeout facts = %#v/%t", facts, ok)
	}
	partial, err := ports.NewPartialFailedProviderExecutionObservation(
		ports.ProviderExecutionStatusTimedOut, invocation, nil, nil, "provider_timeout",
		domain.DiagnosticCauseTimedOut, "", 1024, 1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	partialOutcome := runtimeObservedCondition(job, AttemptConditionProviderTimeout, partial, 625*time.Millisecond)
	partialFacts, ok := partialOutcome.ProviderTimeoutFacts()
	if !ok || partialFacts.ConfiguredTimeout() != job.Limits().Timeout() || partialFacts.Elapsed() != 625*time.Millisecond {
		t.Fatalf("partial timeout facts = %#v/%t", partialFacts, ok)
	}
}

func TestProviderBoundaryRequiresTheFullConfiguredWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if contextCanRunFor(ctx, 3*time.Second) {
		t.Fatal("provider was admitted with less than its configured timeout remaining")
	}
	if !contextCanRunFor(ctx, time.Second) {
		t.Fatal("provider was rejected despite a full configured timeout remaining")
	}
	providerCtx, cancelProvider, ok := newProviderExecutionContext(ctx, time.Second)
	if !ok || providerCtx == nil || cancelProvider == nil {
		t.Fatal("provider context with a full independent window was rejected")
	}
	providerDeadline, _ := providerCtx.Deadline()
	parentDeadline, _ := ctx.Deadline()
	if !providerDeadline.Before(parentDeadline) {
		t.Fatal("provider context inherited the enclosing deadline")
	}
	cancelProvider()

	boundaryDeadline := time.Now().Add(time.Second)
	boundary, cancelBoundary := context.WithDeadline(context.Background(), boundaryDeadline)
	defer cancelBoundary()
	if truncated, cancelTruncated, ok := newProviderExecutionContext(boundary, time.Second); ok || truncated != nil || cancelTruncated != nil {
		if cancelTruncated != nil {
			cancelTruncated()
		}
		t.Fatal("provider context accepted an enclosing deadline that truncates its window")
	}

	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	outcome := runtimeProviderCondition(job, AttemptConditionProviderTimeout, 875*time.Millisecond)
	facts, ok := outcome.ProviderTimeoutFacts()
	if !ok || facts.ConfiguredTimeout() != job.Limits().Timeout() || facts.Elapsed() != 875*time.Millisecond {
		t.Fatalf("measured timeout facts = %#v/%t", facts, ok)
	}
}

func TestObservedUnparseableProviderOutputIsUnrepairable(t *testing.T) {
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
	if got := runtimeProviderErrorCondition(context.Background(), typed); got != AttemptConditionProviderSpawnFailed {
		t.Fatalf("unobserved spawn failure condition = %q, want provider spawn failure", got)
	}
}

func TestInitialValidationFailureRequiresAConcreteRepairPlan(t *testing.T) {
	if got := initialValidationFailureCondition(nil, errors.New("unclassified")); got != AttemptConditionUnrepairableProviderOutput {
		t.Fatalf("planless validation failure condition = %q", got)
	}
	plan, err := validation.NewExactEvidenceRepairPlan([]byte(`{"schema_version":"mulgae-provider-review-output.v1"}`), []string{"/findings/0/evidence/0/current/quote"})
	if err != nil {
		t.Fatal(err)
	}
	if got := initialValidationFailureCondition(plan, errors.New("repairable")); got != AttemptConditionInvalidProviderOutput {
		t.Fatalf("planned validation failure condition = %q", got)
	}
}

func TestRuntimeCauseConditionPreservesValidationAndSpawnStages(t *testing.T) {
	tests := []struct {
		cause domain.RuntimeDiagnosticCause
		want  AttemptCondition
	}{
		{domain.DiagnosticCauseOutputDecodeFailed, AttemptConditionProviderOutputDecodeFailed},
		{domain.DiagnosticCauseCandidateValidationFailed, AttemptConditionSemanticContradiction},
		{domain.DiagnosticCauseCandidateRepairPlanInvalid, AttemptConditionSemanticContradiction},
		{domain.DiagnosticCauseProviderSpawnFailed, AttemptConditionProviderSpawnFailed},
		{domain.DiagnosticCauseAuthenticationFailed, AttemptConditionAuthentication},
		{domain.DiagnosticCausePermissionDenied, AttemptConditionProviderPermissionDenied},
		{domain.DiagnosticCauseProviderOutputFileMissing, AttemptConditionProviderOutputMissing},
		{domain.DiagnosticCauseProviderOutputFileInvalid, AttemptConditionProviderOutputDecodeFailed},
		{domain.DiagnosticCauseProviderOutputStagingViolation, AttemptConditionSecurityViolation},
		{domain.DiagnosticCauseProviderOutputStagingCleanupFailed, AttemptConditionArtifactFailure},
	}
	for _, test := range tests {
		if got := runtimeCauseCondition(test.cause); got != test.want {
			t.Fatalf("runtime cause %q condition = %q, want %q", test.cause, got, test.want)
		}
	}
	if got := diagnosticCauseForCondition(AttemptConditionSemanticContradiction); got != domain.DiagnosticCauseCandidateValidationFailed {
		t.Fatalf("semantic diagnostic cause = %q", got)
	}
}

func TestPromptConstructionFailureDoesNotAuthorizeProviderOutputRepair(t *testing.T) {
	if got := runtimePromptErrorCondition(context.Background(), errors.New("identity issuance failed")); got != AttemptConditionInternalInvariant {
		t.Fatalf("prompt construction failure condition = %q, want %q", got, AttemptConditionInternalInvariant)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelDeadline()
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{"cancelled", cancelled},
		{"deadline", deadline},
	}
	for _, test := range contexts {
		t.Run(test.name+"-with-internal-failure", func(t *testing.T) {
			if got := runtimePromptErrorCondition(test.ctx, errors.New("identity issuance failed")); got != AttemptConditionInternalInvariant {
				t.Fatalf("condition = %q, want %q", got, AttemptConditionInternalInvariant)
			}
		})
	}
	if got := runtimePromptErrorCondition(context.Background(), context.Canceled); got != AttemptConditionCancelled {
		t.Fatalf("prompt cancellation condition = %q, want %q", got, AttemptConditionCancelled)
	}
	if got := runtimePromptErrorCondition(context.Background(), context.DeadlineExceeded); got != AttemptConditionTimeout {
		t.Fatalf("prompt timeout condition = %q, want %q", got, AttemptConditionTimeout)
	}
	decision, err := DecideTransition(TransitionInput{Condition: AttemptConditionInternalInvariant})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ScheduleRepair() || decision.ProviderUnusable() || decision.TerminalProjection() != TerminalProjectionFailed {
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
			outcome := runtime.accept(context.Background(), job, validated, nil, ports.ProviderOutputTransportStdout)
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
	outcome := runtime.accept(context.Background(), job, validated, nil, ports.ProviderOutputTransportStdout)
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
	outcome := runtime.accept(context.Background(), job, validated, nil, ports.ProviderOutputTransportStdout)
	if !outcome.Succeeded() || len(runtime.pending) != 0 {
		t.Fatalf("corrected repair outcome = %#v, pending=%#v", outcome, runtime.pending)
	}
	output, ok := outcome.Output()
	if !ok || len(output.Findings()) != 1 || output.Findings()[0].EvidenceState() != domain.EvidenceVerified {
		t.Fatalf("corrected repair output = %#v, present=%t", output, ok)
	}
}

func TestProviderRuntimePureProseAcceptsWithoutRepair(t *testing.T) {
	prose := []byte("  # logic review\n\nLooks fine.\n  ")
	provider := &recordingReviewProvider{responses: []reviewProviderResponse{{stdout: prose}}}
	runtime, job, material := providerRuntimeExplicitFixture(t, provider)
	outcome := runtime.invokeExplicitMaterial(context.Background(), job, material, false)
	if !outcome.Succeeded() || len(provider.invocations) != 1 || len(runtime.pending) != 0 {
		t.Fatalf("prose outcome=%#v invocations=%d pending=%d", outcome, len(provider.invocations), len(runtime.pending))
	}
	output, ok := outcome.Output()
	if !ok || !output.ReportsOnly() || !bytes.Equal(output.ReportMarkdown(), prose) {
		t.Fatalf("prose report = reportsOnly=%t markdown=%q present=%t", output.ReportsOnly(), output.ReportMarkdown(), ok)
	}
}

func TestProviderRuntimeMalformedStructuredLikeSchedulesAtMostOneRepair(t *testing.T) {
	malformed := []byte("```json\n{\"findings\":\n```")
	provider := &recordingReviewProvider{responses: []reviewProviderResponse{{stdout: malformed}}}
	runtime, job, material := providerRuntimeExplicitFixture(t, provider)
	outcome := runtime.invokeExplicitMaterial(context.Background(), job, material, false)
	if outcome.Succeeded() || len(provider.invocations) != 1 {
		t.Fatalf("malformed structured-like outcome=%#v invocations=%d", outcome, len(provider.invocations))
	}
	pending, ok := runtime.pending[job.AttemptID()]
	if !ok || pending.Plan().Mode() != validation.RepairModeReformatOnly ||
		!bytes.Equal(pending.InitialCandidate(), []byte(`{"findings":`)) ||
		!bytes.Equal(pending.PrimaryReport(), malformed) {
		t.Fatalf("repair pending = %#v present=%t", pending, ok)
	}
	decision, err := DecideTransition(TransitionInput{
		Condition:  coordinatorOutcomeCondition(outcome),
		RepairUsed: false,
	})
	if err != nil || !decision.ScheduleRepair() {
		t.Fatalf("malformed structured-like decision = %#v err=%v", decision, err)
	}
}

func TestProviderRuntimeTrailingJSONIsFreeFormNotRepair(t *testing.T) {
	trailing := []byte("{\"findings\":[]}\ntrailing")
	provider := &recordingReviewProvider{responses: []reviewProviderResponse{{stdout: trailing}}}
	runtime, job, material := providerRuntimeExplicitFixture(t, provider)
	outcome := runtime.invokeExplicitMaterial(context.Background(), job, material, false)
	if !outcome.Succeeded() || len(provider.invocations) != 1 || len(runtime.pending) != 0 {
		t.Fatalf("trailing JSON outcome=%#v invocations=%d pending=%d", outcome, len(provider.invocations), len(runtime.pending))
	}
	output, ok := outcome.Output()
	if !ok || !output.ReportsOnly() || !bytes.Equal(output.ReportMarkdown(), trailing) {
		t.Fatalf("trailing JSON report = %#v present=%t", output, ok)
	}
}

func TestProviderRuntimeMalformedThenFreeFormRepairPublishesReportsOnly(t *testing.T) {
	malformed := []byte("```json\n{\"findings\":\n```")
	repairProse := []byte("# repair response\n\nFree-form prose after exhausted structured repair.\n")
	provider := &recordingReviewProvider{responses: []reviewProviderResponse{
		{stdout: malformed},
		{stdout: repairProse},
	}}
	runtime, initialJob, material := providerRuntimeExplicitFixture(t, provider)
	initial := runtime.invokeExplicitMaterial(context.Background(), initialJob, material, false)
	if initial.Succeeded() || len(provider.invocations) != 1 {
		t.Fatalf("initial malformed outcome=%#v invocations=%d", initial, len(provider.invocations))
	}
	pending, ok := runtime.pending[initialJob.AttemptID()]
	if !ok || pending.Plan().Mode() != validation.RepairModeReformatOnly ||
		!bytes.Equal(pending.PrimaryReport(), malformed) {
		t.Fatalf("initial pending = %#v present=%t", pending, ok)
	}
	decision, err := DecideTransition(TransitionInput{
		Condition:  coordinatorOutcomeCondition(initial),
		RepairUsed: false,
	})
	if err != nil || !decision.ScheduleRepair() {
		t.Fatalf("initial decision = %#v err=%v", decision, err)
	}

	repairJob, err := newCoordinatorInvocationJob(
		initialJob.SessionID(), initialJob.RunID(), initialJob.Role(),
		initialJob.Route(), initialJob.Target(), initialJob.Limits(), initialJob.AttemptID(),
		domain.InvocationRepair, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	repaired := runtime.invokeExplicitMaterial(context.Background(), repairJob, material, false)
	if !repaired.Succeeded() || len(provider.invocations) != 2 || len(runtime.pending) != 0 {
		t.Fatalf("repair outcome=%#v invocations=%d pending=%d", repaired, len(provider.invocations), len(runtime.pending))
	}
	output, ok := repaired.Output()
	if !ok || !output.ReportsOnly() ||
		!bytes.Equal(output.ReportMarkdown(), malformed) ||
		output.ParseState() != domain.ParseInvalidJSON ||
		output.ValidationState() != domain.ValidationRepairExhausted {
		t.Fatalf("repair reports-only output = reportsOnly=%t markdown=%q parse=%q validation=%q present=%t",
			output.ReportsOnly(), output.ReportMarkdown(), output.ParseState(), output.ValidationState(), ok)
	}
	capture, present := runtime.Capture(repairJob.AttemptID(), invocationSequence(domain.InvocationRepair))
	if !present {
		t.Fatal("repair capture is absent")
	}
	for _, artifact := range capture.Artifacts() {
		if artifact.Kind() == ports.AttemptArtifactRepairedCandidate {
			t.Fatalf("primary report persisted as repaired candidate: %#v", artifact)
		}
	}
}

func providerRuntimeExplicitFixture(t *testing.T, provider ports.ReviewProvider) (*ProviderInvocationRuntime, InvocationJob, RuntimePrompt) {
	t.Helper()
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
	attemptID := coordinatorTypesAttemptID(t, 21)
	limits, err := NewInvocationLimits(time.Second, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	job, err := newCoordinatorInvocationJob(
		sessionID, runID, domain.RoleLogic,
		coordinatorTypesRoute(t, "fake.logic"), target,
		limits, attemptID, domain.InvocationInitial, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := prompt.NewTrustedLayer("explicit-runtime-logic", "v1", []byte("Return a review."))
	if err != nil {
		t.Fatal(err)
	}
	template, err := prompt.ComposeTrustedTemplate("explicit-runtime-logic", "v1", layer)
	if err != nil {
		t.Fatal(err)
	}
	roleTaskID, err := prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-000000000020")
	if err != nil {
		t.Fatal(err)
	}
	coordinates, err := prompt.NewScopeCoordinates(sessionID, runID, roleTaskID, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	sourceID, err := prompt.ParseSourceInvocationID("i_019f5a09-5eec-7001-8001-000000000030")
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := prompt.ParseExecutionInvocationID("019f5a09-5eec-7001-8001-000000000040")
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := prompt.NewCompiler(template, explicitRuntimeTestIssuer{source: sourceID, execution: executionID})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(targetBytes)})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := evidence.NewVerifier(&reviewTestEvidenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &ProviderInvocationRuntime{
		provider: provider, validator: newReviewValidator(t), verifier: verifier, policy: DefaultEvidencePolicy(),
		pending: make(map[domain.AttemptID]InvocationRepairInput), captures: make(map[captureKey]AttemptCapture),
		inventory: make(map[captureKey]RuntimeArtifactInventory), activeExplicit: make(map[captureKey]struct{}),
	}
	return runtime, job, RuntimePrompt{Prompt: compiled, Target: targetBytes, AdapterProfile: "test-profile"}
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

// providerRuntimeStreamLimit matches the explicit fixture stream ceilings so a
// fake observation is always coherent with the job limits.
const providerRuntimeStreamLimit = 1 << 20

// providerRuntimeObservation describes one fake provider execution. staged
// selects the staged_file transport and carries the bytes Mulgae read back from
// the staged file; stdout alone selects the ordinary stdout transport; cause
// selects a classified failure; boundary returns an error instead.
type providerRuntimeObservation struct {
	staged     []byte
	stdout     []byte
	stderr     []byte
	status     ports.ProviderExecutionStatus
	diagnostic string
	cause      domain.RuntimeDiagnosticCause
	boundary   error
}

type recordingObservedProvider struct {
	t           *testing.T
	responses   []providerRuntimeObservation
	invocations []ports.ProviderInvocation
}

func (provider *recordingObservedProvider) Observe(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.t.Helper()
	index := len(provider.invocations)
	provider.invocations = append(provider.invocations, invocation)
	if index >= len(provider.responses) {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("unexpected provider invocation %d", index+1)
	}
	response := provider.responses[index]
	if response.boundary != nil {
		return ports.ProviderExecutionObservation{}, response.boundary
	}
	process := providerRuntimeProcessObservation(provider.t, invocation, response.stdout, response.stderr)
	if response.cause != "" {
		observation, err := ports.NewFailedProviderExecutionObservationWithCause(
			response.status, invocation, process, response.diagnostic, response.cause, "",
			providerRuntimeStreamLimit, providerRuntimeStreamLimit,
		)
		if err != nil {
			provider.t.Fatal(err)
		}
		return observation, nil
	}
	if response.staged != nil {
		result, err := ports.NewProviderResultForInput(response.staged, invocation.InputIdentity())
		if err != nil {
			provider.t.Fatal(err)
		}
		receipt, err := ports.NewStagedOutputReceipt(sha256Identifier(response.staged), int64(len(response.staged)))
		if err != nil {
			provider.t.Fatal(err)
		}
		observation, err := ports.NewStagedFileSuccessfulProviderExecutionObservation(
			invocation, result, process, providerRuntimeStreamLimit, providerRuntimeStreamLimit, receipt,
		)
		if err != nil {
			provider.t.Fatal(err)
		}
		return observation, nil
	}
	result, err := ports.NewProviderResultForInput(response.stdout, invocation.InputIdentity())
	if err != nil {
		provider.t.Fatal(err)
	}
	observation, err := ports.NewSuccessfulProviderExecutionObservation(
		invocation, result, process, providerRuntimeStreamLimit, providerRuntimeStreamLimit,
	)
	if err != nil {
		provider.t.Fatal(err)
	}
	return observation, nil
}

func providerRuntimeProcessObservation(t *testing.T, invocation ports.ProviderInvocation, stdout, stderr []byte) ports.ProcessObservation {
	t.Helper()
	packet := invocation.PacketBytes()
	receipt, err := ports.NewStdinWriteReceipt(
		int64(len(packet)), int64(len(packet)), providerRuntimePacketDigest(packet), true,
	)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	started := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	process, err := ports.NewProcessObservation(
		stdout, stderr, &exitCode, ports.ProcessTerminationExited, receipt, started, started.Add(250*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	return process
}

// providerRuntimeStagingLocator mirrors the adapter locator: one staging
// directory per attempt and purpose, and a declared stdout transport for every
// instance that does not stage. It is pure identity; nothing here touches disk.
type providerRuntimeStagingLocator struct {
	stagedInstance string
}

func (locator providerRuntimeStagingLocator) ProviderOutputStagingDestination(
	providerInstance string,
	attemptID domain.AttemptID,
	purpose ports.ProviderInvocationPurpose,
) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	if providerInstance != locator.stagedInstance {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, true
	}
	ordinal := 0
	if purpose == ports.ProviderInvocationRepair {
		ordinal = 1
	}
	destination, err := ports.NewStagedOutputDestination(
		fmt.Sprintf("/mulgae/scratch/output/%s-%d", attemptID.String(), ordinal), "role-report.md",
	)
	if err != nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	return destination, ports.ProviderOutputTransportStagedFile, true
}

// providerRuntimeStagingPromptSource composes one launch prompt exactly as the
// production prompt authority does: the repair contract is appended for a repair
// launch and the Mulgae-owned output destination layer is always appended last.
type providerRuntimeStagingPromptSource struct {
	t           *testing.T
	template    prompt.TrustedTemplate
	scope       prompt.ScopeCoordinates
	target      []byte
	locator     ports.ProviderOutputStagingLocator
	sourceID    prompt.SourceInvocationID
	executionID prompt.ExecutionInvocationID
	prompts     []RuntimePrompt
}

func (source *providerRuntimeStagingPromptSource) Prompt(_ context.Context, job InvocationJob, repair *InvocationRepairInput) (RuntimePrompt, error) {
	source.t.Helper()
	template := source.template
	if repair != nil {
		layers, err := trustedLayersForRepair(template)
		if err != nil {
			return RuntimePrompt{}, err
		}
		repairLayer, err := prompt.NewTrustedLayer(
			"review:repair-plan", "1", []byte("Mulgae ROOT REVIEW REPAIR PLAN/1\nmode:"+string(repair.Plan().Mode())),
		)
		if err != nil {
			return RuntimePrompt{}, err
		}
		template, err = prompt.ComposeTrustedTemplate(template.ID()+"/repair", "1", append(layers, repairLayer)...)
		if err != nil {
			return RuntimePrompt{}, err
		}
	}
	if destination, staged := ResolveStagedOutputDestination(source.locator, job); staged {
		composed, err := ComposeRootReviewOutputDestination(template, destination)
		if err != nil {
			return RuntimePrompt{}, err
		}
		template = composed
	}
	compiler, err := prompt.NewCompiler(template, explicitRuntimeTestIssuer{source: source.sourceID, execution: source.executionID})
	if err != nil {
		return RuntimePrompt{}, err
	}
	compiled, err := compiler.Compile(prompt.CompileInput{Scope: source.scope, ReviewTarget: prompt.NewPayload(source.target)})
	if err != nil {
		return RuntimePrompt{}, err
	}
	material := RuntimePrompt{
		Prompt: compiled, Target: append([]byte(nil), source.target...), AdapterProfile: "test-profile",
	}
	source.prompts = append(source.prompts, material)
	return material, nil
}

// providerRuntimeObservedFixture binds an observation-boundary provider and the
// launch-aware prompt authority to the explicit fixture, then binds the same
// locator to the runtime so both resolve every destination identically.
func providerRuntimeObservedFixture(
	t *testing.T,
	provider ports.ObservedReviewProvider,
	locator ports.ProviderOutputStagingLocator,
) (*ProviderInvocationRuntime, InvocationJob, *providerRuntimeStagingPromptSource) {
	t.Helper()
	runtime, job, material := providerRuntimeExplicitFixture(t, nil)
	scope := material.Prompt.Scope()
	source := &providerRuntimeStagingPromptSource{
		t: t, template: material.Prompt.TrustedTemplate(), scope: scope.Coordinates(),
		target: material.Target, locator: locator,
		sourceID: scope.SourceInvocationID(), executionID: scope.ExecutionInvocationID(),
	}
	runtime.provider = nil
	runtime.observed = provider
	runtime.source = source
	if !nilInterface(locator) {
		if err := runtime.BindProviderOutputStaging(locator); err != nil {
			t.Fatal(err)
		}
	}
	return runtime, job, source
}

// providerRuntimeStagedLocator stages every launch of the fixture instance.
func providerRuntimeStagedLocator() providerRuntimeStagingLocator {
	return providerRuntimeStagingLocator{stagedInstance: "fake.logic"}
}

func TestInvokeAcceptsStagedFileReportWithEmptyStdout(t *testing.T) {
	staged := []byte("# logic review\n\nStaged report body.\n")
	provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{staged: staged}}}
	runtime, job, _ := providerRuntimeObservedFixture(t, provider, providerRuntimeStagedLocator())

	outcome := runtime.Invoke(context.Background(), job)
	if !outcome.Succeeded() || len(provider.invocations) != 1 {
		t.Fatalf("staged outcome = %#v invocations=%d", outcome, len(provider.invocations))
	}
	output, ok := outcome.Output()
	if !ok || !output.ReportsOnly() || !bytes.Equal(output.ReportMarkdown(), staged) {
		t.Fatalf("staged report = reportsOnly=%t markdown=%q present=%t", output.ReportsOnly(), output.ReportMarkdown(), ok)
	}
	capture, present := runtime.Capture(job.AttemptID(), invocationSequence(domain.InvocationInitial))
	if !present || len(capture.Artifacts()) != 0 {
		t.Fatalf("empty process streams captured artifacts: %#v present=%t", capture.Artifacts(), present)
	}
}

func TestInvokeRecordsStagedFileTransportOnRoleOutput(t *testing.T) {
	prose := []byte("# logic review\n\nLooks fine.\n")
	for _, test := range []struct {
		name     string
		response providerRuntimeObservation
		staged   bool
		want     ports.ProviderOutputTransport
	}{
		{name: "staged file", response: providerRuntimeObservation{staged: prose}, staged: true, want: ports.ProviderOutputTransportStagedFile},
		{name: "stdout", response: providerRuntimeObservation{stdout: prose}, want: ports.ProviderOutputTransportStdout},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{test.response}}
			var locator ports.ProviderOutputStagingLocator
			if test.staged {
				locator = providerRuntimeStagedLocator()
			}
			runtime, job, _ := providerRuntimeObservedFixture(t, provider, locator)
			outcome := runtime.Invoke(context.Background(), job)
			output, ok := outcome.Output()
			if !outcome.Succeeded() || !ok {
				t.Fatalf("outcome = %#v output present=%t", outcome, ok)
			}
			if output.OutputTransport() != test.want {
				t.Fatalf("role output transport = %q, want %q", output.OutputTransport(), test.want)
			}
		})
	}
}

func TestInvokeStructuredExtractionRunsOnStagedFileBytes(t *testing.T) {
	staged := []byte("# logic review\n\n```json\n" + string(validNoFindingReview()) + "\n```\n")
	provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{staged: staged}}}
	runtime, job, _ := providerRuntimeObservedFixture(t, provider, providerRuntimeStagedLocator())

	outcome := runtime.Invoke(context.Background(), job)
	output, ok := outcome.Output()
	if !outcome.Succeeded() || !ok {
		t.Fatalf("structured staged outcome = %#v output present=%t", outcome, ok)
	}
	if output.ReportsOnly() || output.ParseState() != domain.ParseValid || output.ValidationState() != domain.ValidationValid {
		t.Fatalf("structured extraction did not run on staged bytes: reportsOnly=%t parse=%q validation=%q",
			output.ReportsOnly(), output.ParseState(), output.ValidationState())
	}
	if !bytes.Equal(output.ReportMarkdown(), staged) || output.OutputTransport() != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("structured staged report = markdown=%q transport=%q", output.ReportMarkdown(), output.OutputTransport())
	}
}

func TestInvokeMapsStagedFileMissingToProviderOutputMissing(t *testing.T) {
	// Exactly what the adapter emits for a staged file the provider never wrote:
	// an artifact-failure status carrying the typed operational cause.
	provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{
		status:     ports.ProviderExecutionStatusArtifactFailure,
		diagnostic: "invalid_provider_output",
		cause:      domain.DiagnosticCauseProviderOutputFileMissing,
		stderr:     []byte("provider staged nothing"),
	}}}
	runtime, job, _ := providerRuntimeObservedFixture(t, provider, providerRuntimeStagedLocator())

	outcome := runtime.Invoke(context.Background(), job)
	condition := coordinatorOutcomeCondition(outcome)
	if outcome.Succeeded() || condition != AttemptConditionProviderOutputMissing {
		t.Fatalf("staged missing condition = %q, want %q", condition, AttemptConditionProviderOutputMissing)
	}
	decision, err := DecideTransition(TransitionInput{Condition: condition})
	if err != nil || decision.ScheduleRepair() || decision.CancelRun() ||
		!decision.Terminal() || decision.TerminalClass() != domain.FailureInvalidOutput {
		t.Fatalf("staged missing decision = %#v err=%v", decision, err)
	}
}

func TestInvokeMapsStagingViolationToSecurityViolation(t *testing.T) {
	stagingViolation, err := ports.NewProviderRuntimeError(
		domain.DiagnosticCauseProviderOutputStagingViolation, errors.New("closed staging detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		response providerRuntimeObservation
	}{
		{name: "observed failure", response: providerRuntimeObservation{
			status:     ports.ProviderExecutionStatusSecurityViolation,
			diagnostic: "process_security",
			cause:      domain.DiagnosticCauseProviderOutputStagingViolation,
		}},
		{name: "boundary failure", response: providerRuntimeObservation{boundary: stagingViolation}},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{test.response}}
			runtime, job, _ := providerRuntimeObservedFixture(t, provider, providerRuntimeStagedLocator())

			outcome := runtime.Invoke(context.Background(), job)
			condition := coordinatorOutcomeCondition(outcome)
			if outcome.Succeeded() || condition != AttemptConditionSecurityViolation {
				t.Fatalf("staging violation condition = %q, want %q", condition, AttemptConditionSecurityViolation)
			}
			decision, decisionErr := DecideTransition(TransitionInput{Condition: condition})
			if decisionErr != nil || !decision.CancelRun() || decision.ScheduleRepair() {
				t.Fatalf("staging violation decision = %#v err=%v", decision, decisionErr)
			}
		})
	}
}

func TestInvokeCleanupFailureIsArtifactCondition(t *testing.T) {
	cleanupFailure, err := ports.NewProviderRuntimeError(
		domain.DiagnosticCauseProviderOutputStagingCleanupFailed, errors.New("closed cleanup detail"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		response providerRuntimeObservation
	}{
		{name: "observed failure", response: providerRuntimeObservation{
			status:     ports.ProviderExecutionStatusArtifactFailure,
			diagnostic: "provider_output_staging_cleanup_failed",
			cause:      domain.DiagnosticCauseProviderOutputStagingCleanupFailed,
		}},
		{name: "boundary failure", response: providerRuntimeObservation{boundary: cleanupFailure}},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{test.response}}
			runtime, job, _ := providerRuntimeObservedFixture(t, provider, providerRuntimeStagedLocator())

			outcome := runtime.Invoke(context.Background(), job)
			condition := coordinatorOutcomeCondition(outcome)
			if outcome.Succeeded() || condition != AttemptConditionArtifactFailure {
				t.Fatalf("staging cleanup condition = %q, want %q", condition, AttemptConditionArtifactFailure)
			}
			decision, decisionErr := DecideTransition(TransitionInput{Condition: condition})
			if decisionErr != nil || decision.ScheduleRepair() ||
				decision.TerminalProjection() != TerminalProjectionFailed || decision.TerminalClass() != domain.FailureArtifact {
				t.Fatalf("staging cleanup decision = %#v err=%v", decision, decisionErr)
			}
		})
	}
}

func TestObservedStagedOutputCausesKeyOnTypedCause(t *testing.T) {
	// The adapter projects both operational staged causes onto an artifact
	// failure status. Only the typed cause keeps them publishable as ordinary
	// provider faults rather than fail-closed integrity failures.
	for _, test := range []struct {
		cause         domain.RuntimeDiagnosticCause
		status        ports.ProviderExecutionStatus
		want          AttemptCondition
		providerFault bool
	}{
		{domain.DiagnosticCauseProviderOutputFileMissing, ports.ProviderExecutionStatusArtifactFailure, AttemptConditionProviderOutputMissing, true},
		{domain.DiagnosticCauseProviderOutputFileInvalid, ports.ProviderExecutionStatusArtifactFailure, AttemptConditionProviderOutputDecodeFailed, true},
		{domain.DiagnosticCauseProviderOutputStagingViolation, ports.ProviderExecutionStatusSecurityViolation, AttemptConditionSecurityViolation, false},
		{domain.DiagnosticCauseProviderOutputStagingCleanupFailed, ports.ProviderExecutionStatusArtifactFailure, AttemptConditionArtifactFailure, false},
	} {
		t.Run(string(test.cause), func(t *testing.T) {
			got := observedStatusCondition(test.status, test.cause)
			if got != test.want {
				t.Fatalf("observed staged cause condition = %q, want %q", got, test.want)
			}
			decision, err := DecideTransition(TransitionInput{Condition: got})
			if err != nil {
				t.Fatal(err)
			}
			if decision.TerminalClass().ProviderFault() != test.providerFault || decision.ScheduleRepair() {
				t.Fatalf("staged cause decision = %#v, want provider fault %t", decision, test.providerFault)
			}
		})
	}
}

func TestProviderInvocationCarriesStagedDestinationThroughRepair(t *testing.T) {
	malformed := []byte("```json\n{\"findings\":\n```")
	repairProse := []byte("# repair response\n\nFree-form prose after exhausted structured repair.\n")
	provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{
		{staged: malformed},
		{staged: repairProse},
	}}
	locator := providerRuntimeStagedLocator()
	runtime, initialJob, source := providerRuntimeObservedFixture(t, provider, locator)

	initial := runtime.Invoke(context.Background(), initialJob)
	if initial.Succeeded() || len(runtime.pending) != 1 {
		t.Fatalf("initial staged outcome = %#v pending=%d", initial, len(runtime.pending))
	}
	repairJob, err := newCoordinatorInvocationJob(
		initialJob.SessionID(), initialJob.RunID(), initialJob.Role(),
		initialJob.Route(), initialJob.Target(), initialJob.Limits(), initialJob.AttemptID(),
		domain.InvocationRepair, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	repaired := runtime.Invoke(context.Background(), repairJob)
	if !repaired.Succeeded() || len(provider.invocations) != 2 || len(source.prompts) != 2 {
		t.Fatalf("repair staged outcome = %#v invocations=%d prompts=%d", repaired, len(provider.invocations), len(source.prompts))
	}
	// Each launch carries the destination the locator resolved for its own
	// purpose, and states that same absolute path in its own last trusted layer.
	launches := []InvocationJob{initialJob, repairJob}
	wantPurposes := []ports.ProviderInvocationPurpose{ports.ProviderInvocationInitial, ports.ProviderInvocationRepair}
	paths := make([]string, 0, len(launches))
	for index, invocation := range provider.invocations {
		expected, resolved := ResolveStagedOutputDestination(locator, launches[index])
		staged, ok := invocation.StagedOutputDestination()
		if !resolved || !ok || staged != expected {
			t.Fatalf("invocation %d staged destination = %#v present=%t, want %#v", index, staged, ok, expected)
		}
		if invocation.Purpose() != wantPurposes[index] {
			t.Fatalf("invocation %d purpose = %q, want %q", index, invocation.Purpose(), wantPurposes[index])
		}
		assertStagedDestinationLayerLast(t, source.prompts[index], staged)
		paths = append(paths, staged.AbsolutePath())
	}
	if paths[0] == paths[1] {
		t.Fatalf("initial and repair launches shared the staged path %q", paths[0])
	}

	staged := provider.invocations[0]
	bare, err := ports.NewProviderInvocationWithPacket(
		staged.Role(), staged.ProviderInstance(), staged.AttemptID(), staged.Purpose(), staged.Packet(),
		staged.SourceInvocationID(), staged.ExecutionInvocationID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherDestination, err := ports.NewStagedOutputDestination("/mulgae/scratch/output/substitute-0", "role-report.md")
	if err != nil {
		t.Fatal(err)
	}
	substituted, err := ports.NewProviderInvocationWithStagedOutput(bare, otherDestination)
	if err != nil {
		t.Fatal(err)
	}
	if !sameProviderInvocation(staged, staged) {
		t.Fatal("identical staged invocations were not recognized as the same invocation")
	}
	if sameProviderInvocation(staged, bare) {
		t.Fatal("a dropped staged destination was accepted as the same invocation")
	}
	if sameProviderInvocation(staged, substituted) {
		t.Fatal("a substituted staged destination was accepted as the same invocation")
	}

	// Exact replay reproduces stored provider wire authority: its historical
	// stdin carries no destination layer and its invocation carries no
	// destination, even though the same locator is bound.
	replayProvider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{stdout: repairProse}}}
	replayRuntime, replayJob, _ := providerRuntimeObservedFixture(t, replayProvider, locator)
	_, _, replayMaterial := providerRuntimeExplicitFixture(t, nil)
	if outcome := replayRuntime.invokeExplicitMaterial(context.Background(), replayJob, replayMaterial, true); !outcome.Succeeded() {
		t.Fatalf("exact replay outcome = %#v", outcome)
	}
	if len(replayProvider.invocations) != 1 {
		t.Fatalf("exact replay invocations = %d", len(replayProvider.invocations))
	}
	if _, ok := replayProvider.invocations[0].StagedOutputDestination(); ok {
		t.Fatal("exact replay invocation carried a staged output destination")
	}
	if stdin := replayMaterial.Prompt.Stdin(); bytes.Contains(stdin, []byte("Mulgae ROOT REVIEW OUTPUT DESTINATION/1")) {
		t.Fatal("exact replay stdin carried the output destination layer")
	}
}

func TestInvokeAppendsDestinationLayerLastForStagedRoutes(t *testing.T) {
	report := []byte("# logic review\n\nStaged report body.\n")
	malformed := []byte("```json\n{\"findings\":\n```")
	t.Run("staged route appends the layer last on every launch", func(t *testing.T) {
		provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{
			{staged: malformed}, {staged: report},
		}}
		locator := providerRuntimeStagedLocator()
		runtime, initialJob, source := providerRuntimeObservedFixture(t, provider, locator)
		if outcome := runtime.Invoke(context.Background(), initialJob); outcome.Succeeded() {
			t.Fatalf("initial malformed outcome = %#v", outcome)
		}
		repairJob, err := newCoordinatorInvocationJob(
			initialJob.SessionID(), initialJob.RunID(), initialJob.Role(),
			initialJob.Route(), initialJob.Target(), initialJob.Limits(), initialJob.AttemptID(),
			domain.InvocationRepair, 2,
		)
		if err != nil {
			t.Fatal(err)
		}
		if outcome := runtime.Invoke(context.Background(), repairJob); !outcome.Succeeded() {
			t.Fatalf("repair staged outcome = %#v", outcome)
		}
		if len(source.prompts) != 2 {
			t.Fatalf("composed prompts = %d, want 2", len(source.prompts))
		}
		wantLayers := [][]string{
			{"explicit-runtime-logic", OutputDestinationTrustedLayerID},
			{"explicit-runtime-logic", "review:repair-plan", OutputDestinationTrustedLayerID},
		}
		for index, material := range source.prompts {
			manifest := material.Prompt.TrustedTemplate().TrustedLayerManifest()
			if len(manifest) != len(wantLayers[index]) {
				t.Fatalf("launch %d layers = %d, want %d", index, len(manifest), len(wantLayers[index]))
			}
			for position, want := range wantLayers[index] {
				if manifest[position].ID() != want || manifest[position].Ordinal() != position+1 {
					t.Fatalf("launch %d layer %d = %q, want %q", index, position, manifest[position].ID(), want)
				}
			}
		}
	})
	for _, test := range []struct {
		name    string
		locator ports.ProviderOutputStagingLocator
	}{
		{name: "stdout transport route", locator: providerRuntimeStagingLocator{stagedInstance: "agy.logic"}},
		{name: "absent locator", locator: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{stdout: report}}}
			runtime, job, source := providerRuntimeObservedFixture(t, provider, test.locator)
			if outcome := runtime.Invoke(context.Background(), job); !outcome.Succeeded() {
				t.Fatalf("stdout outcome = %#v", outcome)
			}
			if len(source.prompts) != 1 {
				t.Fatalf("composed prompts = %d, want 1", len(source.prompts))
			}
			manifest := source.prompts[0].Prompt.TrustedTemplate().TrustedLayerManifest()
			for _, provenance := range manifest {
				if provenance.ID() == OutputDestinationTrustedLayerID {
					t.Fatal("stdout launch carried the output destination layer")
				}
			}
			if bytes.Contains(source.prompts[0].Prompt.Stdin(), []byte("Mulgae ROOT REVIEW OUTPUT DESTINATION/1")) {
				t.Fatal("stdout launch stdin carried the output destination contract")
			}
			if _, ok := provider.invocations[0].StagedOutputDestination(); ok {
				t.Fatal("stdout launch invocation carried a staged output destination")
			}
		})
	}
}

func TestInvokeRejectsStagedLaunchWithoutItsDestinationLayer(t *testing.T) {
	provider := &recordingObservedProvider{t: t, responses: []providerRuntimeObservation{{staged: []byte("# report\n")}}}
	runtime, job, material := providerRuntimeExplicitFixture(t, nil)
	runtime.provider = nil
	runtime.observed = provider
	runtime.source = explicitRuntimePromptSource{material: material}
	if err := runtime.BindProviderOutputStaging(providerRuntimeStagedLocator()); err != nil {
		t.Fatal(err)
	}
	outcome := runtime.Invoke(context.Background(), job)
	if outcome.Succeeded() || coordinatorOutcomeCondition(outcome) != AttemptConditionConfigurationViolation {
		t.Fatalf("silent staged launch condition = %q, want %q", coordinatorOutcomeCondition(outcome), AttemptConditionConfigurationViolation)
	}
	if len(provider.invocations) != 0 {
		t.Fatalf("provider was launched without stating its staged path: invocations=%d", len(provider.invocations))
	}
}

// assertStagedDestinationLayerLast proves the launch prompt ends its trusted
// template with exactly the destination layer for destination, and that the
// exact absolute path reached the provider stdin.
func assertStagedDestinationLayerLast(t *testing.T, material RuntimePrompt, destination ports.StagedOutputDestination) {
	t.Helper()
	layer, err := OutputDestinationTrustedLayer(destination)
	if err != nil {
		t.Fatal(err)
	}
	template := material.Prompt.TrustedTemplate()
	manifest := template.TrustedLayerManifest()
	if len(manifest) == 0 {
		t.Fatal("launch template has no trusted layer manifest")
	}
	last := manifest[len(manifest)-1]
	if last.ID() != OutputDestinationTrustedLayerID || last.SHA256() != layer.SHA256() {
		t.Fatalf("last trusted layer = %q/%s, want %q/%s", last.ID(), last.SHA256(), OutputDestinationTrustedLayerID, layer.SHA256())
	}
	if !bytes.HasSuffix(template.Bytes(), layer.Bytes()) {
		t.Fatal("output destination layer is not the final trusted template content")
	}
	if !bytes.Contains(material.Prompt.Stdin(), []byte(destination.AbsolutePath())) {
		t.Fatalf("launch stdin does not state %q", destination.AbsolutePath())
	}
	if !promptDeclaresStagedOutputDestination(material.Prompt, destination) {
		t.Fatal("runtime did not accept the composed destination layer")
	}
}
