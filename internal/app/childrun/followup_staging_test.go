package childrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	childrunStagedInstance   = "zcode-logic"
	childrunFramesBoundary   = "\nMulgae-FRAMES/1\n"
	childrunDestinationLead  = "Mulgae ROOT REVIEW OUTPUT DESTINATION/1"
	childrunStagingStreamCap = 64 << 10
)

func TestFollowupPromptCarriesStagedOutputDestination(t *testing.T) {
	t.Parallel()

	execution, run, attemptID := childrunStagingExecution(t)
	locator := childrunStagingLocator{stagedInstance: childrunStagedInstance}
	source, err := NewProductionFollowupPromptSourceWithStaging(
		&childrunStagingIssuer{}, childrunStagingRoleTask, childrunStagedInstance,
		childrunStagingWorkspace{identity: childrunStagingWorkspaceIdentity(t)}, locator,
	)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := source.BuildFollowupInvocation(context.Background(), execution, run, attemptID)
	if err != nil {
		t.Fatalf("BuildFollowupInvocation() error = %v", err)
	}
	destination, staged := invocation.StagedOutputDestination()
	if !staged {
		t.Fatal("staged followup invocation carries no output destination")
	}
	want, _, ok := locator.ProviderOutputStagingDestination(childrunStagedInstance, attemptID, ports.ProviderInvocationInitial)
	if !ok || destination != want {
		t.Fatalf("invocation destination = %#v, want %#v", destination, want)
	}
	assertChildrunStagedPacket(t, invocation, destination)

	// The published template identity must describe the exact composed launch,
	// not the base followup template the staged launch never sent.
	artifact, err := source.BuildFollowupRuntimeArtifact(context.Background(), execution, run, invocation)
	if err != nil {
		t.Fatal(err)
	}
	base, err := productionFollowupTrustedTemplate(execution.Current.Identity)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := review.ComposeRootReviewOutputDestination(base, destination)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.RuntimeTemplateID != composed.ID() || artifact.RuntimeTemplateSHA256 != composed.SHA256() {
		t.Fatalf("runtime template identity = %q/%s, want %q/%s",
			artifact.RuntimeTemplateID, artifact.RuntimeTemplateSHA256, composed.ID(), composed.SHA256())
	}

	// A prompt authority without staging authority, and one whose instance the
	// registry keeps on stdout, both leave the launch on the stdout transport.
	for _, test := range []struct {
		name     string
		instance string
		locator  ports.ProviderOutputStagingLocator
	}{
		{name: "absent locator", instance: childrunStagedInstance, locator: nil},
		{name: "stdout transport instance", instance: "agy-logic", locator: locator},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdoutSource, sourceErr := NewProductionFollowupPromptSourceWithStaging(
				&childrunStagingIssuer{}, childrunStagingRoleTask, test.instance,
				childrunStagingWorkspace{identity: childrunStagingWorkspaceIdentity(t)}, test.locator,
			)
			if sourceErr != nil {
				t.Fatal(sourceErr)
			}
			stdoutInvocation, buildErr := stdoutSource.BuildFollowupInvocation(context.Background(), execution, run, attemptID)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if _, present := stdoutInvocation.StagedOutputDestination(); present {
				t.Fatal("stdout launch invocation carried a staged output destination")
			}
			if bytes.Contains(stdoutInvocation.PacketBytes(), []byte(childrunDestinationLead)) {
				t.Fatal("stdout launch packet carried the output destination contract")
			}
		})
	}
}

func TestFollowupStagedRepairUsesRepairDestination(t *testing.T) {
	t.Parallel()

	execution, run, attemptID := childrunStagingExecution(t)
	locator := childrunStagingLocator{stagedInstance: childrunStagedInstance}
	source, err := NewProductionFollowupPromptSourceWithStaging(
		&childrunStagingIssuer{}, childrunStagingRoleTask, childrunStagedInstance,
		childrunStagingWorkspace{identity: childrunStagingWorkspaceIdentity(t)}, locator,
	)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := source.BuildFollowupInvocation(context.Background(), execution, run, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	repair, err := source.BuildFollowupRepairInvocation(
		context.Background(), execution, run, attemptID, []byte(`{"schema_version":"mulgae-provider-followup-output.v1"`),
	)
	if err != nil {
		t.Fatalf("BuildFollowupRepairInvocation() error = %v", err)
	}
	if repair.Purpose() != ports.ProviderInvocationRepair {
		t.Fatalf("repair purpose = %q", repair.Purpose())
	}
	initialDestination, initialStaged := initial.StagedOutputDestination()
	repairDestination, repairStaged := repair.StagedOutputDestination()
	if !initialStaged || !repairStaged {
		t.Fatalf("launch destinations staged = initial %t repair %t", initialStaged, repairStaged)
	}
	if initialDestination == repairDestination {
		t.Fatalf("initial and repair launches share destination %q", initialDestination.AbsolutePath())
	}
	assertChildrunStagedPacket(t, repair, repairDestination)
	if bytes.Contains(repair.PacketBytes(), []byte(initialDestination.AbsolutePath())) {
		t.Fatalf("repair packet states the initial destination %q", initialDestination.AbsolutePath())
	}
	if bytes.Contains(initial.PacketBytes(), []byte(repairDestination.AbsolutePath())) {
		t.Fatalf("initial packet states the repair destination %q", repairDestination.AbsolutePath())
	}
}

func TestFollowupExecutorRejectsStagedLaunchWithoutItsDestinationLayer(t *testing.T) {
	t.Parallel()

	execution, run, attemptID := childrunStagingExecution(t)
	locator := childrunStagingLocator{stagedInstance: childrunStagedInstance}
	silent, err := NewProductionFollowupPromptSource(
		&childrunStagingIssuer{}, childrunStagingRoleTask, childrunStagedInstance,
		childrunStagingWorkspace{identity: childrunStagingWorkspaceIdentity(t)},
	)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := silent.BuildFollowupInvocation(context.Background(), execution, run, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if err := followupStagedOutputDeclaration(invocation); err != nil {
		t.Fatalf("stdout launch was rejected: %v", err)
	}
	destination, _, ok := locator.ProviderOutputStagingDestination(childrunStagedInstance, attemptID, ports.ProviderInvocationInitial)
	if !ok {
		t.Fatal("staging locator resolved no destination")
	}
	silentStaged, err := ports.NewProviderInvocationWithStagedOutput(invocation, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := followupStagedOutputDeclaration(silentStaged); err == nil {
		t.Fatal("staged launch whose packet states no destination was accepted")
	}
}

func TestAcceptFollowupOutputUsesStagedFileBytesAsPrimaryReport(t *testing.T) {
	t.Parallel()

	staged := []byte("# logic followup\n\nThe source finding is resolved in the current target.\n")
	executor, execution, run, attemptID, scope := childrunStagedPublicationFixture(t)
	invocation := childrunStagingInvocation(t, attemptID, ports.ProviderInvocationInitial)
	observation := childrunStagedObservation(t, invocation, staged)
	if observation.OutputTransport() != ports.ProviderOutputTransportStagedFile {
		t.Fatalf("observation transport = %q", observation.OutputTransport())
	}
	if len(observation.Stdout()) != 0 {
		t.Fatalf("staged observation raw stdout = %q, want empty", observation.Stdout())
	}
	result, present := observation.Result()
	if !present || !bytes.Equal(result.Stdout(), staged) {
		t.Fatalf("staged result bytes = %q present=%t", result.Stdout(), present)
	}

	observations := []ports.ProviderExecutionObservation{observation}
	runtimes := []publication.FollowupRuntimeArtifactInput{childrunStagingRuntimeArtifact(execution, run, invocation)}
	drops := []childDiagnosticObservation{{}}
	validated, repaired, initialCandidate, err := executor.acceptFollowupOutput(
		context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
		scope, result.Stdout(), &observations, &runtimes, &drops,
	)
	if err != nil {
		t.Fatalf("acceptFollowupOutput() error = %v", err)
	}
	if repaired || !validated.ReportsOnly() {
		t.Fatalf("staged accept = repaired=%t reportsOnly=%t", repaired, validated.ReportsOnly())
	}
	if !bytes.Equal(validated.ProviderRaw(), staged) {
		t.Fatalf("accepted followup report = %q, want the staged bytes", validated.ProviderRaw())
	}
	if err := bindFollowupRuntimeCaptures(runtimes, observations, drops, validated, repaired, initialCandidate); err != nil {
		t.Fatal(err)
	}

	candidate, err := publication.PrepareFollowupCandidate(publication.FollowupCandidateInput{
		Run: run, SourceSessionID: execution.Source.SessionID, SourceRunID: execution.Source.RunID,
		SourceReviewID: execution.Source.ReviewID, SourceFindingID: execution.Source.Finding.ID,
		SourceTargetSHA256:  "sha256:" + execution.Source.Target.SHA256(),
		SourceExcerptSHA256: "sha256:" + execution.Source.Receipt.ExcerptSHA256,
		AttemptID:           attemptID, Provider: scope.ProviderInstance, Output: validated,
		Observation: observation, Runtime: runtimes[0], Observations: observations, Runtimes: runtimes,
		SeverityThreshold: domain.SeverityHigh, MulgaeVersion: "0.0.0-test", MulgaeCommit: "commit",
	})
	if err != nil {
		t.Fatalf("PrepareFollowupCandidate() error = %v", err)
	}
	bundle, err := candidate.Build(
		context.Background(), childrunStagingSchema{}, childrunReviewID(t, "019f596a-cf85-7c67-b265-f37053d51ccf"),
		time.Unix(0, 0).UTC(), 1,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var manifest struct {
		RoleReports []struct {
			Role      string `json:"role"`
			Transport string `json:"transport"`
		} `json:"role_reports"`
	}
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.RoleReports) != 1 || manifest.RoleReports[0].Transport != string(ports.ProviderOutputTransportStagedFile) {
		t.Fatalf("published role report transports = %#v, want one staged_file report", manifest.RoleReports)
	}
}

func TestFollowupStagedFileMissingFailsAsInvalidProviderOutput(t *testing.T) {
	t.Parallel()

	attemptID, err := domain.ParseAttemptID("a_019f596a-cfb4-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	invocation := childrunStagingInvocation(t, attemptID, ports.ProviderInvocationInitial)
	for _, test := range []struct {
		name      string
		cause     domain.RuntimeDiagnosticCause
		condition review.AttemptCondition
		class     domain.FailureClass
	}{
		{
			name: "staged file missing", cause: domain.DiagnosticCauseProviderOutputFileMissing,
			condition: review.AttemptConditionProviderOutputMissing, class: domain.FailureInvalidOutput,
		},
		{
			name: "staged file invalid", cause: domain.DiagnosticCauseProviderOutputFileInvalid,
			condition: review.AttemptConditionProviderOutputDecodeFailed, class: domain.FailureInvalidOutput,
		},
		{
			name: "staging violation", cause: domain.DiagnosticCauseProviderOutputStagingViolation,
			condition: review.AttemptConditionSecurityViolation, class: domain.FailureSecurityPolicy,
		},
		{
			name: "staging cleanup failed", cause: domain.DiagnosticCauseProviderOutputStagingCleanupFailed,
			condition: review.AttemptConditionArtifactFailure, class: domain.FailureArtifact,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// The adapter projects every staged failure onto an artifact-failure
			// status, so only the typed cause proves the operational outcomes.
			observation, observationErr := ports.NewFailedProviderExecutionObservationWithCause(
				ports.ProviderExecutionStatusArtifactFailure, invocation,
				childrunStagingProcess(t, invocation, nil), "provider_output_staging", test.cause, "",
				childrunStagingStreamCap, childrunStagingStreamCap,
			)
			if observationErr != nil {
				t.Fatal(observationErr)
			}
			failureErr := followupObservationFailure(
				childrunStagedInstance, domain.RoleLogic, observation, fmt.Errorf("safe staged failure"),
			)
			failures, ok := reviewrun.ProviderExecutionFailuresFromError(failureErr)
			if !ok || len(failures) != 1 {
				t.Fatalf("provider failures = %#v present=%t", failures, ok)
			}
			if failures[0].ReasonCode() != string(test.condition) || failures[0].FailureClass() != test.class {
				t.Fatalf("provider failure = reason %q class %q, want %q/%q",
					failures[0].ReasonCode(), failures[0].FailureClass(), test.condition, test.class)
			}
		})
	}
}

// TestChildStagingLocatorSelectsQualifiedRegistryAuthority pins the single
// assertion idiom child composition uses to thread staging into the followup
// prompt authority and into the shared delta/rerun prompt source and runtime.
func TestChildStagingLocatorSelectsQualifiedRegistryAuthority(t *testing.T) {
	t.Parallel()

	locator := childrunStagingLocator{stagedInstance: childrunStagedInstance}
	if resolved := ProviderOutputStagingLocator(nil); resolved != nil {
		t.Fatalf("absent provider produced locator %#v", resolved)
	}
	var typedNil *childrunStagingProvider
	if resolved := ProviderOutputStagingLocator(typedNil); resolved != nil {
		t.Fatalf("typed-nil registry produced locator %#v", resolved)
	}
	if resolved := ProviderOutputStagingLocator(childrunStdoutProvider{}); resolved != nil {
		t.Fatalf("stdout-only provider produced locator %#v", resolved)
	}
	resolved := ProviderOutputStagingLocator(&childrunStagingProvider{locator: locator})
	if resolved == nil {
		t.Fatal("staging registry authority was not detected")
	}
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf84-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	destination, transport, ok := resolved.ProviderOutputStagingDestination(
		childrunStagedInstance, attemptID, ports.ProviderInvocationInitial,
	)
	want, _, _ := locator.ProviderOutputStagingDestination(childrunStagedInstance, attemptID, ports.ProviderInvocationInitial)
	if !ok || transport != ports.ProviderOutputTransportStagedFile || destination != want {
		t.Fatalf("threaded locator resolved %#v/%q/%t", destination, transport, ok)
	}
}

func assertChildrunStagedPacket(t *testing.T, invocation ports.ProviderInvocation, destination ports.StagedOutputDestination) {
	t.Helper()
	layer, err := review.OutputDestinationTrustedLayer(destination)
	if err != nil {
		t.Fatal(err)
	}
	packet := invocation.PacketBytes()
	boundary := bytes.Index(packet, []byte(childrunFramesBoundary))
	if boundary <= 0 {
		t.Fatal("followup packet has no trusted template boundary")
	}
	if !bytes.HasSuffix(packet[:boundary], layer.Bytes()) {
		t.Fatal("output destination layer is not the last trusted layer of the followup packet")
	}
	if !bytes.Contains(packet, []byte(destination.AbsolutePath())) {
		t.Fatalf("followup packet does not state %q", destination.AbsolutePath())
	}
	if err := followupStagedOutputDeclaration(invocation); err != nil {
		t.Fatalf("executor rejected its own staged launch: %v", err)
	}
}

// childrunStagingLocator mirrors the adapter locator: one staging directory per
// attempt and purpose, and a declared stdout transport for every instance that
// does not stage. It is pure identity; nothing here touches disk.
type childrunStagingLocator struct{ stagedInstance string }

func (locator childrunStagingLocator) ProviderOutputStagingDestination(
	instance string, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose,
) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	if instance == "" || attemptID.String() == "" || !purpose.Valid() {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	if instance != locator.stagedInstance {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, true
	}
	ordinal := 0
	if purpose == ports.ProviderInvocationRepair {
		ordinal = 1
	}
	destination, err := ports.NewStagedOutputDestination(
		fmt.Sprintf("/scratch/output/%s-%d", attemptID.String(), ordinal), "role-report.md",
	)
	if err != nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	return destination, ports.ProviderOutputTransportStagedFile, true
}

// childrunStagingProvider is the qualified-provider shape the composition
// asserts against: a registry that also owns the staging locator.
type childrunStagingProvider struct {
	locator ports.ProviderOutputStagingLocator
}

func (*childrunStagingProvider) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return ports.ProviderExecutionObservation{}, fmt.Errorf("childrun staging provider: observe is unused")
}

func (provider *childrunStagingProvider) ProviderOutputStagingDestination(
	instance string, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose,
) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	if provider == nil || provider.locator == nil {
		return ports.StagedOutputDestination{}, ports.ProviderOutputTransportStdout, false
	}
	return provider.locator.ProviderOutputStagingDestination(instance, attemptID, purpose)
}

// childrunStdoutProvider is a legacy registry without staging authority.
type childrunStdoutProvider struct{}

func (childrunStdoutProvider) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return ports.ProviderExecutionObservation{}, fmt.Errorf("childrun stdout provider: observe is unused")
}

type childrunStagingWorkspace struct {
	identity ports.WorkspaceSnapshotIdentity
}

func (workspace childrunStagingWorkspace) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return workspace.identity
}

func (childrunStagingWorkspace) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, fmt.Errorf("childrun staging workspace: execution is unused")
}

func childrunStagingWorkspaceIdentity(t *testing.T) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		"/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// childrunStagingIssuer mints one fresh identity pair per call so a replay can
// prove it received a new execution identity for the same stored packet.
type childrunStagingIssuer struct{ issued int }

func (issuer *childrunStagingIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	issuer.issued++
	return prompt.ParseSourceInvocationID(fmt.Sprintf("i_019f5a09-5eec-7001-8001-%012d", issuer.issued))
}

func (issuer *childrunStagingIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	issuer.issued++
	return prompt.ParseExecutionInvocationID(fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", 900000+issuer.issued))
}

func childrunStagingRoleTask() (prompt.RoleTaskID, error) {
	return prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-000000000003")
}

func childrunStagingExecution(t *testing.T) (appfollowup.Execution, domain.Run, domain.AttemptID) {
	t.Helper()
	sessionID := childrunSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cf81-7c67-b265-f37053d51ccf")
	reviewID := childrunReviewID(t, "019f596a-cf82-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf83-7c67-b265-f37053d51ccf")
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf84-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	target := childrunTarget(t)
	task, err := domain.NewRoleTask(domain.RoleLogic, true, childrunStagedInstance, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewFollowupChildRunFromImmutableSource(childRunID, sessionID, sourceRunID, sourceRunID, target, task)
	if err != nil {
		t.Fatal(err)
	}
	execution := appfollowup.Execution{
		SessionID: sessionID,
		Source: appfollowup.VerifiedSource{
			ProviderInstance: childrunStagedInstance, SessionID: sessionID, RunID: sourceRunID, ReviewID: reviewID,
			Finding: appfollowup.SourceFinding{ID: "F001", Role: domain.RoleLogic, Normalized: []byte(`{"id":"F001"}`)},
			Target:  target, Final: []byte("# source report\n"),
			Receipt: appfollowup.SourceReceipt{ExcerptSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		Current: appfollowup.CurrentTarget{Identity: target, Bytes: []byte("return nil\n")},
	}
	return execution, run, attemptID
}

// childrunStagedPublicationFixture binds one followup execution whose current
// target bytes, target identity, and child run agree, so the publication
// candidate this staged accept produces is fully bindable.
func childrunStagedPublicationFixture(t *testing.T) (*FollowupExecutor, appfollowup.Execution, domain.Run, domain.AttemptID, validation.FollowupValidationScope) {
	t.Helper()
	current := []byte("return nil\n")
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetPatch, SHA256: childrunStagingHex(current),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := childrunSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cf81-7c67-b265-f37053d51ccf")
	reviewID := childrunReviewID(t, "019f596a-cf82-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf83-7c67-b265-f37053d51ccf")
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf84-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	task, err := domain.NewRoleTask(domain.RoleLogic, true, childrunStagedInstance, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewFollowupChildRunFromImmutableSource(childRunID, sessionID, sourceRunID, sourceRunID, target, task)
	if err != nil {
		t.Fatal(err)
	}
	excerpt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	execution := appfollowup.Execution{
		SessionID: sessionID,
		Source: appfollowup.VerifiedSource{
			ProviderInstance: childrunStagedInstance, SessionID: sessionID, RunID: sourceRunID, ReviewID: reviewID,
			Finding: appfollowup.SourceFinding{ID: "F001", Role: domain.RoleLogic, Normalized: []byte(`{"id":"F001"}`)},
			Target:  target, Final: []byte("# source report\n"),
			Receipt: appfollowup.SourceReceipt{ExcerptSHA256: excerpt},
		},
		Current: appfollowup.CurrentTarget{Identity: target, Bytes: current},
	}
	scope := validation.FollowupValidationScope{
		SessionID: sessionID, SourceRunID: sourceRunID, ReviewID: reviewID, FindingID: "F001",
		SourceTargetSHA256: "sha256:" + target.SHA256(), SourceExcerptSHA256: "sha256:" + excerpt,
		CurrentTargetSHA256: "sha256:" + target.SHA256(), Role: domain.RoleLogic, ProviderInstance: childrunStagedInstance,
	}
	executor := &FollowupExecutor{
		prompts:          followupPrimaryReportPrompts{providerInstance: childrunStagedInstance},
		providerInstance: childrunStagedInstance,
	}
	return executor, execution, run, attemptID, scope
}

func childrunStagingInvocation(t *testing.T, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose) ports.ProviderInvocation {
	t.Helper()
	locator := childrunStagingLocator{stagedInstance: childrunStagedInstance}
	destination, _, ok := locator.ProviderOutputStagingDestination(childrunStagedInstance, attemptID, purpose)
	if !ok {
		t.Fatal("staging locator resolved no destination")
	}
	stdin := []byte("Mulgae FOLLOWUP REVIEW/1 staged launch")
	invocation, err := followupPrimaryReportInvocation(domain.RoleLogic, childrunStagedInstance, attemptID, purpose, stdin)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := ports.NewProviderInvocationWithStagedOutput(invocation, destination)
	if err != nil {
		t.Fatal(err)
	}
	return staged
}

func childrunStagingProcess(t *testing.T, invocation ports.ProviderInvocation, stdout []byte) ports.ProcessObservation {
	t.Helper()
	packet := invocation.PacketBytes()
	receipt, err := ports.NewStdinWriteReceipt(
		int64(len(packet)), int64(len(packet)), invocation.CompleteStdinSHA256(), true,
	)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	started := time.Unix(0, 0).UTC()
	process, err := ports.NewProcessObservation(
		stdout, nil, &exitCode, ports.ProcessTerminationExited, receipt, started, started.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	return process
}

func childrunStagedObservation(t *testing.T, invocation ports.ProviderInvocation, staged []byte) ports.ProviderExecutionObservation {
	t.Helper()
	result, err := ports.NewProviderResultForInput(staged, invocation.InputIdentity())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ports.NewStagedOutputReceipt(childrunStagingDigest(staged), int64(len(staged)))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ports.NewStagedFileSuccessfulProviderExecutionObservation(
		invocation, result, childrunStagingProcess(t, invocation, nil),
		childrunStagingStreamCap, childrunStagingStreamCap, receipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func childrunStagingRuntimeArtifact(execution appfollowup.Execution, run domain.Run, invocation ports.ProviderInvocation) publication.FollowupRuntimeArtifactInput {
	return publication.FollowupRuntimeArtifactInput{
		RuntimeRunID: run.ID(), RuntimeAttemptID: invocation.AttemptID(), RuntimeSequence: 1,
		RuntimePurpose: domain.InvocationInitial, RuntimeRole: invocation.Role(),
		RuntimeTarget: append([]byte(nil), execution.Current.Bytes...), RuntimeTargetIdentity: execution.Current.Identity,
		RuntimeStdin: invocation.Stdin(), RuntimeStdinSHA256: invocation.CompleteStdinSHA256(),
		RuntimeTemplateID: "followup-review/output-destination", RuntimeTemplateVersion: "1",
		RuntimeTemplateSHA256:     childrunStagingDigest([]byte("followup-review/output-destination")),
		RuntimeSourceInvocationID: invocation.SourceInvocationID(), RuntimeExecutionInvocationID: invocation.ExecutionInvocationID(),
		RuntimeScope: run.SessionID().String() + "/" + run.ID().String(), RuntimeAdapterProfile: "followup-review",
	}
}

type childrunStagingSchema struct{}

func (childrunStagingSchema) Validate(context.Context, ports.AssetID, []byte) error { return nil }

func childrunStagingHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func childrunStagingDigest(value []byte) string {
	return "sha256:" + childrunStagingHex(value)
}
