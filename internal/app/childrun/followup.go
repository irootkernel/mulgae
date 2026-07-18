package childrun

import (
	"context"
	"fmt"
	"time"

	appfollowup "github.com/irootkernel/kkachi-agent-review/internal/app/followup"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// FollowupIDIssuer mints the fresh child and its one bounded provider attempt.
type FollowupIDIssuer interface {
	NewRunID(time.Time) (domain.RunID, error)
	NewAttemptID(time.Time) (domain.AttemptID, error)
}

// FollowupPromptSource is the sole trusted source of a followup provider
// invocation. It must bind source bytes, current bytes, objective, and the
// selected role before the provider boundary is reached.
type FollowupPromptSource interface {
	BuildFollowupInvocation(context.Context, appfollowup.Execution, domain.Run, domain.AttemptID) (ports.ProviderInvocation, error)
}

// FollowupRuntimeInventorySource supplies the immutable target and prompt
// manifest metadata required to publish a specialized followup invocation.
type FollowupRuntimeInventorySource interface {
	BuildFollowupRuntimeArtifact(context.Context, appfollowup.Execution, domain.Run, ports.ProviderInvocation) (publication.FollowupRuntimeArtifactInput, error)
}

// FollowupExecutor performs the intentionally non-coordinator, exactly-one
// specialized provider invocation for one selected source finding.
type FollowupExecutor struct {
	clock             ports.Clock
	ids               FollowupIDIssuer
	provider          ports.ObservedReviewProvider
	prompts           FollowupPromptSource
	validator         *validation.FollowupValidator
	publisher         *publication.Service
	artifactRoot      ports.AnchoredRoot
	providerInstance  string
	epochs            *PublicationEpochSource
	severityThreshold domain.Severity
	karVersion        string
	karCommit         string
}

type FollowupExecutorConfig struct {
	ProviderInstance       string
	PublicationEpoch       uint64
	PublicationEpochSource *PublicationEpochSource
	SeverityThreshold      domain.Severity
	KARVersion             string
	KARCommit              string
}

func NewFollowupExecutor(clock ports.Clock, ids FollowupIDIssuer, provider ports.ObservedReviewProvider, prompts FollowupPromptSource, validator *validation.FollowupValidator, publisher *publication.Service, artifactRoot ports.AnchoredRoot, config FollowupExecutorConfig) (*FollowupExecutor, error) {
	if clock == nil || ids == nil || provider == nil || prompts == nil || validator == nil || publisher == nil || !artifactRoot.Valid() {
		return nil, fmt.Errorf("followup executor: execution authority is incomplete")
	}
	if _, ok := prompts.(FollowupRuntimeInventorySource); !ok {
		return nil, fmt.Errorf("followup executor: runtime inventory authority is incomplete")
	}
	if config.ProviderInstance == "" || (config.PublicationEpoch == 0 && config.PublicationEpochSource == nil) || config.KARVersion == "" || config.KARCommit == "" {
		return nil, fmt.Errorf("followup executor: publication identity is incomplete")
	}
	epochs := config.PublicationEpochSource
	if epochs == nil {
		epochs = NewPublicationEpochSource(config.PublicationEpoch - 1)
	}
	if config.SeverityThreshold == "" {
		config.SeverityThreshold = domain.SeverityHigh
	}
	if !config.SeverityThreshold.Valid() {
		return nil, fmt.Errorf("followup executor: severity threshold is invalid")
	}
	return &FollowupExecutor{clock: clock, ids: ids, provider: provider, prompts: prompts, validator: validator, publisher: publisher, artifactRoot: artifactRoot, providerInstance: config.ProviderInstance, epochs: epochs, severityThreshold: config.SeverityThreshold, karVersion: config.KARVersion, karCommit: config.KARCommit}, nil
}

// ExecuteFollowup observes exactly one provider call and publishes only its
// schema-valid, trusted-scope normalized result.
func (executor *FollowupExecutor) ExecuteFollowup(ctx context.Context, execution appfollowup.Execution) (appfollowup.ExecutionResult, error) {
	if executor == nil || ctx == nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: executor and context are required")
	}
	if err := ctx.Err(); err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	if execution.SessionID != execution.Source.SessionID || execution.Source.RunID.String() == "" || execution.Source.ReviewID.String() == "" || execution.Source.Finding.ID == "" || !execution.Source.Finding.Role.Valid() || execution.Current.Identity.Kind() == "" {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: trusted execution identity is invalid")
	}
	role := execution.Source.Finding.Role
	if execution.Role != nil && *execution.Role != role {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: selected role differs from source finding")
	}
	runID, err := executor.ids.NewRunID(executor.clock.Now())
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: issue run ID: %w", err)
	}
	attemptID, err := executor.ids.NewAttemptID(executor.clock.Now())
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: issue attempt ID: %w", err)
	}
	task, err := domain.NewRoleTask(role, true, executor.providerInstance, nil)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	run, err := domain.NewFollowupChildRunFromImmutableSource(runID, execution.SessionID, execution.Source.RunID, execution.Source.RunID, execution.Current.Identity, task)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	invocation, err := executor.prompts.BuildFollowupInvocation(ctx, execution, run, attemptID)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: build trusted prompt: %w", err)
	}
	if invocation.AttemptID() != attemptID || invocation.Role() != role || invocation.ProviderInstance() != executor.providerInstance {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: prompt invocation identity mismatch")
	}
	runtimeSource, ok := executor.prompts.(FollowupRuntimeInventorySource)
	if !ok {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: prompt source does not supply runtime inventory")
	}
	runtime, err := runtimeSource.BuildFollowupRuntimeArtifact(ctx, execution, run, invocation)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: build runtime inventory: %w", err)
	}
	if runtime.RuntimeRunID != run.ID() || runtime.RuntimeAttemptID != attemptID ||
		runtime.RuntimeSequence != 1 || runtime.RuntimePurpose != domain.InvocationInitial ||
		runtime.RuntimeRole != role || runtime.RuntimeTargetIdentity != execution.Current.Identity ||
		string(runtime.RuntimeTarget) != string(execution.Current.Bytes) ||
		string(runtime.RuntimeStdin) != string(invocation.Stdin()) ||
		runtime.RuntimeStdinSHA256 != invocation.CompleteStdinSHA256() ||
		runtime.RuntimeSourceInvocationID != invocation.SourceInvocationID() ||
		runtime.RuntimeExecutionInvocationID != invocation.ExecutionInvocationID() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: runtime inventory differs from invocation")
	}
	observation, err := executor.provider.Observe(ctx, invocation)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: observe provider: %w", err)
	}
	if err := observation.Validate(); err != nil || !observation.Succeeded() || observation.Invocation().ExecutionInvocationID() != invocation.ExecutionInvocationID() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: provider execution was not a matching success")
	}
	result, ok := observation.Result()
	if !ok || result.CompleteStdinSHA256() != invocation.CompleteStdinSHA256() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: provider result identity mismatch")
	}
	validated, err := executor.validator.Validate(ctx, result.Stdout(), validation.FollowupValidationScope{SessionID: execution.SessionID, SourceRunID: execution.Source.RunID, ReviewID: execution.Source.ReviewID, FindingID: execution.Source.Finding.ID, SourceTargetSHA256: execution.Source.Target.SHA256(), SourceExcerptSHA256: execution.Source.Receipt.ExcerptSHA256, CurrentTargetSHA256: execution.Current.Identity.SHA256(), Role: role, ProviderInstance: executor.providerInstance})
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: validate provider output: %w", err)
	}
	captures := make([]ports.CapturedAttemptArtifact, 0, 3)
	for _, capture := range []struct {
		kind  ports.AttemptArtifactKind
		bytes []byte
	}{
		{ports.AttemptArtifactInitialCandidate, validated.NormalizedRaw()},
		{ports.AttemptArtifactStdout, observation.Stdout()},
		{ports.AttemptArtifactStderr, observation.Stderr()},
	} {
		if len(capture.bytes) == 0 {
			continue
		}
		artifact, artifactErr := ports.NewCapturedAttemptArtifact(capture.kind, capture.bytes, false)
		if artifactErr != nil {
			return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: capture %s: %w", capture.kind, artifactErr)
		}
		captures = append(captures, artifact)
	}
	runtime.RuntimeCaptures = captures
	epoch, err := executor.epochs.Next()
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: allocate publication epoch: %w", err)
	}
	published, err := executor.publisher.PublishFollowup(ctx, executor.artifactRoot, publication.FollowupCandidateInput{Run: run, SourceSessionID: execution.Source.SessionID, SourceRunID: execution.Source.RunID, SourceReviewID: execution.Source.ReviewID, SourceFindingID: execution.Source.Finding.ID, SourceTargetSHA256: "sha256:" + execution.Source.Target.SHA256(), SourceExcerptSHA256: "sha256:" + execution.Source.Receipt.ExcerptSHA256, AttemptID: attemptID, Provider: executor.providerInstance, Output: validated, Observation: observation, Runtime: runtime, SeverityThreshold: executor.severityThreshold, KARVersion: executor.karVersion, KARCommit: executor.karCommit}, epoch)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: publish: %w", err)
	}
	final, ok := published.Final()
	if !ok || !final.Valid() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: publication has no P2 final receipt")
	}
	terminalExit, err := committedTerminalExit(published)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: publication terminal exit: %w", err)
	}
	executionResult, err := appfollowup.NewExecutionResult(run.SessionID(), run.ID(), receiptURI(executor.artifactRoot, final), validated, terminalExit)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	return executionResult, nil
}

var _ appfollowup.ChildExecutor = (*FollowupExecutor)(nil)
