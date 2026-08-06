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
		sessionID, runID, domain.RoleLogic, AttemptKindPrimary,
		coordinatorTypesRoute(t, "fake.logic", "diagnostic-lane"), coordinatorTypesTarget(t, 13),
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
			outcome := runtime.accept(context.Background(), job, validated, nil)
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
	outcome := runtime.accept(context.Background(), job, validated, nil)
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
	outcome := runtime.accept(context.Background(), job, validated, nil)
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
		Condition:          coordinatorOutcomeCondition(outcome),
		RepairUsed:         false,
		FallbackConfigured: false,
		FallbackEligible:   false,
	})
	if err != nil || !decision.ScheduleRepair() || decision.ScheduleFallback() {
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
		Condition:          coordinatorOutcomeCondition(initial),
		RepairUsed:         false,
		FallbackConfigured: false,
		FallbackEligible:   false,
	})
	if err != nil || !decision.ScheduleRepair() {
		t.Fatalf("initial decision = %#v err=%v", decision, err)
	}

	repairJob, err := newCoordinatorInvocationJob(
		initialJob.SessionID(), initialJob.RunID(), initialJob.Role(), AttemptKindPrimary,
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
		sessionID, runID, domain.RoleLogic, AttemptKindPrimary,
		coordinatorTypesRoute(t, "fake.logic", "logic-lane"), target,
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
