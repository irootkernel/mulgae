package mulgae

import (
	"context"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type historicalChildFixture struct {
	RunID        string
	TerminalExit domain.OperationalExitDecision
}

// Historical fixtures use typed publication inputs and real P2 storage. They
// grant no child execution, replay, or capture authority to production wiring.
func buildHistoricalChildFixture(t *testing.T, fixture *g008RealE2EFixture, root g008RealE2ERootResult, workflow string) (historicalChildFixture, error) {
	t.Helper()
	ctx := context.Background()
	parent, err := fixture.queries.ResolveRun(ctx, fixture.root, root.RunID)
	if err != nil {
		return historicalChildFixture{}, err
	}
	committed, err := fixture.queries.ReadCommitted(ctx, parent)
	if err != nil {
		return historicalChildFixture{}, err
	}
	if workflow == "followup" {
		return buildHistoricalFollowupFixture(t, fixture, parent, committed)
	}
	id, err := fixture.ids.NewRunID(fixture.clock.Now())
	if err != nil {
		return historicalChildFixture{}, err
	}
	target, runType, assignments := fixture.target, domain.RunTypeRerun, fixture.assignments[:1]
	if workflow == "delta" {
		target, runType, assignments = fixture.deltaTarget, domain.RunTypeDelta, fixture.assignments[:2]
	}
	tasks := make([]domain.RoleTask, len(assignments))
	for i, assignment := range assignments {
		tasks[i], err = domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.ProviderInstance())
		if err != nil {
			return historicalChildFixture{}, err
		}
	}
	var run domain.Run
	if runType == domain.RunTypeRerun {
		run, err = domain.NewRerunChildRunFromImmutableSource(id, committed.SessionID(), root.RunID, root.RunID, target, tasks[0])
	} else {
		run, err = domain.NewChildRunFromImmutableSource(id, runType, committed.SessionID(), root.RunID, root.RunID, target, tasks)
	}
	if err != nil {
		return historicalChildFixture{}, err
	}
	result, err := fixture.coordinator.ExecuteRun(ctx, &run, assignments, domain.SeverityHigh, nil)
	if err != nil {
		return historicalChildFixture{}, err
	}
	var mode *publication.ReplayMode
	var sourceAttempt *domain.AttemptID
	if runType == domain.RunTypeRerun {
		value := publication.ReplayModeRecompose
		if workflow == "exact rerun" {
			value = publication.ReplayModeExact
		}
		mode, sourceAttempt = &value, &root.AttemptID
	}
	lineage, err := publication.NewChildPublicationContext(runType, root.RunID, root.RunID, root.ReviewID, sourceAttempt, nil, mode)
	if err != nil {
		return historicalChildFixture{}, err
	}
	observed := fixture.runtime.DrainRuntimeArtifactsForRun(id)
	inputs := make([]publication.FollowupRuntimeArtifactInput, len(observed))
	for i, inventory := range observed {
		inputs[i] = historicalInventoryInput(inventory)
		if workflow == "exact rerun" {
			attempt, err := fixture.queries.ReadCommittedAttempt(ctx, parent, root.AttemptID)
			if err != nil {
				return historicalChildFixture{}, err
			}
			prompt := attempt.Prompt()
			// This fixture represents an already stored historical exact receipt;
			// no replay operation is invoked. Preserve its source wire authority.
			inputs[i].RuntimeStdin, inputs[i].RuntimeStdinSHA256 = prompt.Stdin(), prompt.CompleteStdinSHA256()
			inputs[i].RuntimeTemplateID, inputs[i].RuntimeTemplateVersion, inputs[i].RuntimeTemplateSHA256 = prompt.TemplateID(), prompt.TemplateVersion(), prompt.TemplateSHA256()
			inputs[i].RuntimeSourceInvocationID, inputs[i].RuntimeScope = prompt.SourceInvocationID(), prompt.Scope()
		}
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(result, target, domain.SeverityHigh, "historical-fixture", "historical-fixture", lineage, inputs)
	if err != nil {
		return historicalChildFixture{}, err
	}
	published, err := fixture.publisher.PublishNext(ctx, fixture.root, candidate)
	return historicalFixtureReceipt(id, published, err)
}

func historicalInventoryInput(input review.RuntimeArtifactInventory) publication.FollowupRuntimeArtifactInput {
	return publication.FollowupRuntimeArtifactInput{RuntimeRunID: input.RunID(), RuntimeAttemptID: input.AttemptID(), RuntimeSequence: input.Sequence(), RuntimePurpose: input.Purpose(), RuntimeRole: input.Role(), RuntimeTarget: input.Target(), RuntimeCapturedArchive: input.CapturedArchive(), RuntimeTargetIdentity: input.TargetIdentity(), RuntimeStdin: input.Stdin(), RuntimeStdinSHA256: input.StdinSHA256(), RuntimeTemplateID: input.TemplateID(), RuntimeTemplateVersion: input.TemplateVersion(), RuntimeTemplateSHA256: input.TemplateSHA256(), RuntimeSourceInvocationID: input.SourceInvocationID(), RuntimeExecutionInvocationID: input.ExecutionInvocationID(), RuntimeScope: input.Scope(), RuntimeAdapterProfile: input.AdapterProfile(), RuntimeAdapterParameters: input.AdapterParameters(), RuntimeCaptures: input.Captures()}
}

func buildHistoricalFollowupFixture(t *testing.T, fixture *g008RealE2EFixture, parent ports.PublicationRun, committed query.CommittedReview) (historicalChildFixture, error) {
	t.Helper()
	ctx := context.Background()
	finding, err := fixture.queries.ReadCommittedFindingSource(ctx, parent, "F001")
	if err != nil {
		return historicalChildFixture{}, err
	}
	id, _ := fixture.ids.NewRunID(fixture.clock.Now())
	attempt, _ := fixture.ids.NewAttemptID(fixture.clock.Now())
	current := []byte("queueFallback(task)")
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: g008RealTargetHash(current)})
	if err != nil {
		return historicalChildFixture{}, err
	}
	task, _ := domain.NewRoleTask(domain.RoleLogic, true, "g008.logic")
	run, err := domain.NewFollowupChildRunFromImmutableSource(id, committed.SessionID(), committed.RunID(), committed.RunID(), target, task)
	if err != nil {
		return historicalChildFixture{}, err
	}
	raw := []byte(`{"schema_version":"mulgae-provider-followup-output.v1","summary":"F001 remains open.","resolution":"still_open","rationale":"The current target preserves the source finding.","evidence":[{"current":{"path":"internal/app/coordinator.go","line_start":1,"line_end":1,"side":"head","quote":"queueFallback(task)"}}],"new_findings":[],"limitations":[]}`)
	schema, _ := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	validator, err := validation.NewFollowupValidator(fixture.validator, schema)
	if err != nil {
		return historicalChildFixture{}, err
	}
	output, err := validator.Validate(ctx, raw, validation.FollowupValidationScope{SessionID: committed.SessionID(), SourceRunID: committed.RunID(), ReviewID: committed.ReviewID(), FindingID: "F001", SourceTargetSHA256: committed.TargetSHA256(), SourceExcerptSHA256: g008RealTargetHash(finding.Excerpt()), CurrentTargetSHA256: target.SHA256(), Role: domain.RoleLogic, ProviderInstance: "g008.logic"})
	if err != nil {
		return historicalChildFixture{}, err
	}
	stdin := []byte("historical followup fixture")
	sourceID, executionID := "i_019f5a09-5eed-7001-8001-000000000001", "019f5a09-5eed-7002-8002-000000000002"
	invocation, err := ports.NewProviderInvocation(domain.RoleLogic, "g008.logic", attempt, ports.ProviderInvocationInitial, stdin, sourceID, executionID, prompt.CompleteStdinSHA256(stdin))
	if err != nil {
		return historicalChildFixture{}, err
	}
	result, _ := ports.NewProviderResult(raw, len(stdin), invocation.CompleteStdinSHA256())
	write, _ := ports.NewStdinWriteReceipt(int64(len(stdin)), int64(len(stdin)), invocation.CompleteStdinSHA256(), true)
	exit := 0
	process, err := ports.NewProcessObservation(raw, nil, &exit, ports.ProcessTerminationExited, write, fixture.clock.Now(), fixture.clock.Now())
	if err != nil {
		return historicalChildFixture{}, err
	}
	observation, err := ports.NewSuccessfulProviderExecutionObservation(invocation, result, process)
	if err != nil {
		return historicalChildFixture{}, err
	}
	normalized, _ := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, output.NormalizedRaw(), false)
	stdout, _ := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, raw, false)
	runtime := publication.FollowupRuntimeArtifactInput{RuntimeRunID: id, RuntimeAttemptID: attempt, RuntimeSequence: 1, RuntimePurpose: domain.InvocationInitial, RuntimeRole: domain.RoleLogic, RuntimeTarget: current, RuntimeTargetIdentity: target, RuntimeStdin: stdin, RuntimeStdinSHA256: invocation.CompleteStdinSHA256(), RuntimeTemplateID: "historical-followup", RuntimeTemplateVersion: "v1", RuntimeTemplateSHA256: g008RealTargetHash([]byte("historical followup template")), RuntimeSourceInvocationID: sourceID, RuntimeExecutionInvocationID: executionID, RuntimeScope: committed.SessionID().String() + "/" + id.String() + "/" + attempt.String(), RuntimeAdapterProfile: "historical-fixture", RuntimeAdapterParameters: map[string]string{}, RuntimeCaptures: []ports.CapturedAttemptArtifact{normalized, stdout}}
	candidate, err := publication.PrepareFollowupCandidate(publication.FollowupCandidateInput{Run: run, SourceSessionID: committed.SessionID(), SourceRunID: committed.RunID(), SourceReviewID: committed.ReviewID(), SourceFindingID: "F001", SourceTargetSHA256: committed.TargetSHA256(), SourceExcerptSHA256: "sha256:" + g008RealTargetHash(finding.Excerpt()), AttemptID: attempt, Provider: "g008.logic", Output: output, Observation: observation, Runtime: runtime, SeverityThreshold: domain.SeverityHigh, MulgaeVersion: "historical-fixture", MulgaeCommit: "historical-fixture"})
	if err != nil {
		return historicalChildFixture{}, err
	}
	published, err := fixture.publisher.PublishNext(ctx, fixture.root, candidate)
	return historicalFixtureReceipt(id, published, err)
}

func historicalFixtureReceipt(id domain.RunID, result publication.PublicationResult, err error) (historicalChildFixture, error) {
	if err != nil {
		return historicalChildFixture{}, err
	}
	_, hasFinal := result.Final()
	exit, hasExit := result.TerminalExit()
	if !hasFinal || !hasExit {
		return historicalChildFixture{}, fmt.Errorf("historical fixture: missing P2 receipt")
	}
	return historicalChildFixture{RunID: id.String(), TerminalExit: exit}, nil
}
