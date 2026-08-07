package childrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAcceptFollowupOutputPreservesPrimaryStdoutAcrossRepair(t *testing.T) {
	t.Parallel()

	primary := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","resolution":"still_open","rationale":"The current target preserves the source finding.","evidence":[{"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"return nil"}}],"new_findings":[],"limitations":[]}`)
	validRepair := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"F001 remains open.","resolution":"still_open","rationale":"The current target preserves the source finding.","evidence":[{"current":{"path":"a.go","line_start":1,"line_end":1,"side":"head","quote":"return nil"}}],"new_findings":[],"limitations":[]}`)
	repairProse := []byte("# repair response\n\nFree-form prose must not become the role report.\n")

	t.Run("repair valid keeps primary report and repaired-valid structured resolution", func(t *testing.T) {
		t.Parallel()
		executor, execution, run, attemptID, scope := followupPrimaryReportFixture(t, [][]byte{validRepair}, nil)
		observations := []ports.ProviderExecutionObservation{}
		runtimes := []publication.FollowupRuntimeArtifactInput{}
		drops := []childDiagnosticObservation{}
		validated, repaired, _, err := executor.acceptFollowupOutput(
			context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
			scope, primary, &observations, &runtimes, &drops,
		)
		if err != nil {
			t.Fatalf("acceptFollowupOutput() error = %v", err)
		}
		if !repaired || validated.ReportsOnly() || validated.Resolution() != domain.FollowupStillOpen {
			t.Fatalf("structured repair result = repaired=%t reportsOnly=%t resolution=%q", repaired, validated.ReportsOnly(), validated.Resolution())
		}
		if validated.ValidationState() != domain.ValidationRepairedValid || validated.ParseState() != domain.ParseValid {
			t.Fatalf("extraction state = parse=%q validation=%q", validated.ParseState(), validated.ValidationState())
		}
		if !bytes.Equal(validated.ProviderRaw(), primary) {
			t.Fatalf("role report = %q, want exact primary stdout", validated.ProviderRaw())
		}
		if len(observations) != 1 {
			t.Fatalf("repair observations = %d, want 1", len(observations))
		}
	})

	t.Run("repair free-form keeps primary report as reports-only", func(t *testing.T) {
		t.Parallel()
		executor, execution, run, attemptID, scope := followupPrimaryReportFixture(t, [][]byte{repairProse}, nil)
		observations := []ports.ProviderExecutionObservation{}
		runtimes := []publication.FollowupRuntimeArtifactInput{}
		drops := []childDiagnosticObservation{}
		validated, repaired, _, err := executor.acceptFollowupOutput(
			context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
			scope, primary, &observations, &runtimes, &drops,
		)
		if err != nil {
			t.Fatalf("acceptFollowupOutput() error = %v", err)
		}
		if !repaired || !validated.ReportsOnly() || validated.Resolution().Valid() {
			t.Fatalf("reports-only repair result = repaired=%t reportsOnly=%t resolution=%q", repaired, validated.ReportsOnly(), validated.Resolution())
		}
		if validated.ParseState() != domain.ParseValid || validated.ValidationState() != domain.ValidationRepairExhausted {
			t.Fatalf("repair free-form extraction = parse=%q validation=%q, want parse=valid validation=repair_exhausted",
				validated.ParseState(), validated.ValidationState())
		}
		if !bytes.Equal(validated.ProviderRaw(), primary) {
			t.Fatalf("role report = %q, want exact primary stdout (not repair prose)", validated.ProviderRaw())
		}
		if bytes.Contains(validated.ProviderRaw(), []byte("Free-form prose must not become")) {
			t.Fatal("repair response replaced the primary role report")
		}
	})

	t.Run("repair provider failure remains fail-closed", func(t *testing.T) {
		t.Parallel()
		observeErr := errors.New("repair provider process failed")
		executor, execution, run, attemptID, scope := followupPrimaryReportFixture(t, nil, observeErr)
		observations := []ports.ProviderExecutionObservation{}
		runtimes := []publication.FollowupRuntimeArtifactInput{}
		drops := []childDiagnosticObservation{}
		validated, repaired, _, err := executor.acceptFollowupOutput(
			context.Background(), nil, execution, run, attemptID, executor.prompts.(FollowupRuntimeInventorySource),
			scope, primary, &observations, &runtimes, &drops,
		)
		if err == nil || repaired || validated.Resolution().Valid() || validated.ReportsOnly() {
			t.Fatalf("repair failure = err=%v repaired=%t validated=%#v", err, repaired, validated)
		}
		if !errors.Is(err, observeErr) && !bytes.Contains([]byte(err.Error()), []byte("repair provider process failed")) {
			t.Fatalf("repair failure error = %v, want provider process failure", err)
		}
	})
}

type followupPrimaryReportProvider struct {
	responses [][]byte
	err       error
	calls     int
}

func (provider *followupPrimaryReportProvider) Observe(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	provider.calls++
	if provider.err != nil {
		return ports.ProviderExecutionObservation{}, provider.err
	}
	if len(provider.responses) == 0 {
		return ports.ProviderExecutionObservation{}, errors.New("unexpected provider observe")
	}
	stdout := provider.responses[0]
	provider.responses = provider.responses[1:]
	result, err := ports.NewProviderResult(stdout, len(invocation.Stdin()), invocation.CompleteStdinSHA256())
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	stdin, err := ports.NewStdinWriteReceipt(int64(len(invocation.Stdin())), int64(len(invocation.Stdin())), invocation.CompleteStdinSHA256(), true)
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	exit := 0
	started := time.Unix(0, 0).UTC()
	process, err := ports.NewProcessObservation(stdout, nil, &exit, ports.ProcessTerminationExited, stdin, started, started.Add(time.Second))
	if err != nil {
		return ports.ProviderExecutionObservation{}, err
	}
	return ports.NewSuccessfulProviderExecutionObservation(invocation, result, process, 64<<10, 64<<10)
}

type followupPrimaryReportPrompts struct {
	providerInstance string
}

func (source followupPrimaryReportPrompts) BuildFollowupInvocation(context.Context, appfollowup.Execution, domain.Run, domain.AttemptID) (ports.ProviderInvocation, error) {
	return ports.ProviderInvocation{}, errors.New("initial prompt unused in acceptFollowupOutput tests")
}

func (source followupPrimaryReportPrompts) BuildFollowupRepairInvocation(_ context.Context, execution appfollowup.Execution, _ domain.Run, attemptID domain.AttemptID, prior []byte) (ports.ProviderInvocation, error) {
	if len(prior) == 0 {
		return ports.ProviderInvocation{}, errors.New("repair requires prior primary stdout")
	}
	stdin := []byte("followup-repair:" + execution.Source.Finding.ID)
	return followupPrimaryReportInvocation(execution.Source.Finding.Role, source.providerInstance, attemptID, ports.ProviderInvocationRepair, stdin)
}

func (source followupPrimaryReportPrompts) BuildFollowupRuntimeArtifact(_ context.Context, execution appfollowup.Execution, run domain.Run, invocation ports.ProviderInvocation) (publication.FollowupRuntimeArtifactInput, error) {
	sequence := uint64(1)
	purpose := domain.InvocationInitial
	if invocation.Purpose() == ports.ProviderInvocationRepair {
		sequence = 2
		purpose = domain.InvocationRepair
	}
	return publication.FollowupRuntimeArtifactInput{
		RuntimeRunID: run.ID(), RuntimeAttemptID: invocation.AttemptID(), RuntimeSequence: sequence, RuntimePurpose: purpose,
		RuntimeRole: invocation.Role(), RuntimeTarget: append([]byte(nil), execution.Current.Bytes...), RuntimeTargetIdentity: execution.Current.Identity,
		RuntimeStdin: invocation.Stdin(), RuntimeStdinSHA256: invocation.CompleteStdinSHA256(),
		RuntimeTemplateID: "followup-test", RuntimeTemplateVersion: "v1", RuntimeTemplateSHA256: followupPrimaryReportDigest([]byte("followup-test")),
		RuntimeSourceInvocationID: invocation.SourceInvocationID(), RuntimeExecutionInvocationID: invocation.ExecutionInvocationID(),
		RuntimeScope: run.SessionID().String() + "/" + run.ID().String(), RuntimeAdapterProfile: "test",
	}, nil
}

func followupPrimaryReportFixture(t *testing.T, repairResponses [][]byte, repairErr error) (*FollowupExecutor, appfollowup.Execution, domain.Run, domain.AttemptID, validation.FollowupValidationScope) {
	t.Helper()
	providerInstance := "test.provider"
	schemaID, err := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := validation.NewFollowupValidator(followupPrimaryReportSchema{}, schemaID)
	if err != nil {
		t.Fatal(err)
	}
	prompts := followupPrimaryReportPrompts{providerInstance: providerInstance}
	provider := &followupPrimaryReportProvider{responses: append([][]byte(nil), repairResponses...), err: repairErr}
	executor := &FollowupExecutor{
		provider: provider, prompts: prompts, validator: validator, providerInstance: providerInstance,
	}
	sessionID := childrunSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cf81-7c67-b265-f37053d51ccf")
	reviewID := childrunReviewID(t, "019f596a-cf82-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf83-7c67-b265-f37053d51ccf")
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf84-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	target := childrunTarget(t)
	task, err := domain.NewRoleTask(domain.RoleLogic, true, providerInstance)
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
			ProviderInstance: providerInstance, SessionID: sessionID, RunID: sourceRunID, ReviewID: reviewID,
			Finding: appfollowup.SourceFinding{ID: "F001", Role: domain.RoleLogic},
			Target:  target,
			Receipt: appfollowup.SourceReceipt{ExcerptSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		Current: appfollowup.CurrentTarget{Identity: target, Bytes: []byte("return nil\n")},
	}
	scope := validation.FollowupValidationScope{
		SessionID: sessionID, SourceRunID: sourceRunID, ReviewID: reviewID, FindingID: "F001",
		SourceTargetSHA256: "sha256:" + target.SHA256(), SourceExcerptSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CurrentTargetSHA256: "sha256:" + target.SHA256(), Role: domain.RoleLogic, ProviderInstance: providerInstance,
	}
	return executor, execution, run, attemptID, scope
}

type followupPrimaryReportSchema struct{}

func (followupPrimaryReportSchema) Validate(_ context.Context, _ ports.AssetID, raw []byte) error {
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	if _, ok := document["summary"]; !ok {
		return errors.New("summary is required")
	}
	return nil
}

func followupPrimaryReportInvocation(role domain.Role, provider string, attemptID domain.AttemptID, purpose ports.ProviderInvocationPurpose, stdin []byte) (ports.ProviderInvocation, error) {
	sum := sha256.Sum256(append([]byte("Mulgae-PROVIDER-STDIN/1\x00"), stdin...))
	return ports.NewProviderInvocation(role, provider, attemptID, purpose, stdin,
		"i_019f596a-cf85-7c67-b265-f37053d51ccf", "019f596a-cf86-7c67-b265-f37053d51ccf", hex.EncodeToString(sum[:]))
}

func followupPrimaryReportDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
