package childrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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

// FollowupRepairPromptSource is the optional bounded repair authority. The
// production prompt source implements it; legacy injected fixtures that do not
// explicitly grant repair remain single-invocation and fail closed.
type FollowupRepairPromptSource interface {
	BuildFollowupRepairInvocation(context.Context, appfollowup.Execution, domain.Run, domain.AttemptID, []byte) (ports.ProviderInvocation, error)
}

// FollowupRuntimeInventorySource supplies the immutable target and prompt
// manifest metadata required to publish a specialized followup invocation.
type FollowupRuntimeInventorySource interface {
	BuildFollowupRuntimeArtifact(context.Context, appfollowup.Execution, domain.Run, ports.ProviderInvocation) (publication.FollowupRuntimeArtifactInput, error)
}

// FollowupExecutor performs one source-bound followup invocation and, only for
// structurally repairable output, one same-provider repair invocation.
type FollowupExecutor struct {
	clock             ports.Clock
	ids               FollowupIDIssuer
	provider          ports.ObservedReviewProvider
	prompts           FollowupPromptSource
	validator         *validation.FollowupValidator
	publisher         *publication.Service
	artifactRoot      ports.AnchoredRoot
	providerInstance  string
	severityThreshold domain.Severity
	mulgaeVersion     string
	mulgaeCommit      string
	diagnostics       ports.RuntimeDiagnosticSinkFactory
}

type FollowupExecutorConfig struct {
	ProviderInstance  string
	SeverityThreshold domain.Severity
	MulgaeVersion     string
	MulgaeCommit      string
	Diagnostics       ports.RuntimeDiagnosticSinkFactory
}

func NewFollowupExecutor(clock ports.Clock, ids FollowupIDIssuer, provider ports.ObservedReviewProvider, prompts FollowupPromptSource, validator *validation.FollowupValidator, publisher *publication.Service, artifactRoot ports.AnchoredRoot, config FollowupExecutorConfig) (*FollowupExecutor, error) {
	if clock == nil || ids == nil || provider == nil || prompts == nil || validator == nil || publisher == nil || !artifactRoot.Valid() {
		return nil, fmt.Errorf("followup executor: execution authority is incomplete")
	}
	if _, ok := prompts.(FollowupRuntimeInventorySource); !ok {
		return nil, fmt.Errorf("followup executor: runtime inventory authority is incomplete")
	}
	if config.ProviderInstance == "" || config.MulgaeVersion == "" || config.MulgaeCommit == "" {
		return nil, fmt.Errorf("followup executor: publication identity is incomplete")
	}
	if config.SeverityThreshold == "" {
		config.SeverityThreshold = domain.SeverityHigh
	}
	if !config.SeverityThreshold.Valid() {
		return nil, fmt.Errorf("followup executor: severity threshold is invalid")
	}
	return &FollowupExecutor{clock: clock, ids: ids, provider: provider, prompts: prompts, validator: validator, publisher: publisher, artifactRoot: artifactRoot, providerInstance: config.ProviderInstance, severityThreshold: config.SeverityThreshold, mulgaeVersion: config.MulgaeVersion, mulgaeCommit: config.MulgaeCommit, diagnostics: config.Diagnostics}, nil
}

// ExecuteFollowup publishes only a schema-valid, trusted-scope normalized
// result. Repair never changes provider, attempt, role, target, or lineage.
func (executor *FollowupExecutor) ExecuteFollowup(ctx context.Context, execution appfollowup.Execution) (_ appfollowup.ExecutionResult, retErr error) {
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
	lifecycle, err := openChildDiagnostics(ctx, executor.diagnostics, executor.artifactRoot, executor.clock, run)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	var diagnosticP2 ports.SafeRelativePath
	defer func() {
		if finishErr := lifecycle.finish(ctx, retErr, diagnosticP2); finishErr != nil {
			retErr = finishErr
		}
	}()
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
		!bytes.Equal(runtime.RuntimeCapturedArchive, execution.Current.CapturedArchive) ||
		string(runtime.RuntimeStdin) != string(invocation.Stdin()) ||
		runtime.RuntimeStdinSHA256 != invocation.CompleteStdinSHA256() ||
		runtime.RuntimeSourceInvocationID != invocation.SourceInvocationID() ||
		runtime.RuntimeExecutionInvocationID != invocation.ExecutionInvocationID() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: runtime inventory differs from invocation")
	}
	observation, err := executor.provider.Observe(ctx, invocation)
	if err != nil {
		return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionProviderUnavailable, domain.FailureProviderUnavailable, err)
	}
	diagnosticDrop, err := lifecycle.persistObservation(ctx, observation, 1)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	if err := validateFollowupObservation(observation, invocation); err != nil {
		return appfollowup.ExecutionResult{}, followupObservationFailure(executor.providerInstance, role, observation, err)
	}
	result, ok := observation.Result()
	if !ok || result.CompleteStdinSHA256() != invocation.CompleteStdinSHA256() {
		return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidProviderOutput, domain.FailureInvalidOutput, fmt.Errorf("provider result identity mismatch"))
	}
	scope := validation.FollowupValidationScope{SessionID: execution.SessionID, SourceRunID: execution.Source.RunID, ReviewID: execution.Source.ReviewID, FindingID: execution.Source.Finding.ID, SourceTargetSHA256: execution.Source.Target.SHA256(), SourceExcerptSHA256: execution.Source.Receipt.ExcerptSHA256, CurrentTargetSHA256: execution.Current.Identity.SHA256(), Role: role, ProviderInstance: executor.providerInstance}
	initialRaw := result.Stdout()
	validated, repairable, validationErr := executor.validator.ValidateWithRepairAuthority(ctx, initialRaw, scope)
	observations := []ports.ProviderExecutionObservation{observation}
	runtimes := []publication.FollowupRuntimeArtifactInput{runtime}
	diagnosticDrops := []childDiagnosticObservation{diagnosticDrop}
	repaired := false
	if validationErr != nil && repairable {
		repairPrompts, repairAuthorized := executor.prompts.(FollowupRepairPromptSource)
		if !repairAuthorized {
			return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidProviderOutput, domain.FailureInvalidOutput, validationErr)
		}
		repairInvocation, buildErr := repairPrompts.BuildFollowupRepairInvocation(ctx, execution, run, attemptID, initialRaw)
		if buildErr != nil {
			return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: build trusted repair prompt: %w", buildErr)
		}
		if repairInvocation.AttemptID() != attemptID || repairInvocation.Role() != role || repairInvocation.ProviderInstance() != executor.providerInstance || repairInvocation.Purpose() != ports.ProviderInvocationRepair {
			return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: repair prompt invocation identity mismatch")
		}
		repairRuntime, runtimeErr := runtimeSource.BuildFollowupRuntimeArtifact(ctx, execution, run, repairInvocation)
		if runtimeErr != nil {
			return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: build repair runtime inventory: %w", runtimeErr)
		}
		repairObservation, observeErr := executor.provider.Observe(ctx, repairInvocation)
		if observeErr != nil {
			return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionProviderUnavailable, domain.FailureProviderUnavailable, observeErr)
		}
		repairDiagnosticDrop, persistErr := lifecycle.persistObservation(ctx, repairObservation, 2)
		if persistErr != nil {
			return appfollowup.ExecutionResult{}, persistErr
		}
		if observeErr = validateFollowupObservation(repairObservation, repairInvocation); observeErr != nil {
			return appfollowup.ExecutionResult{}, followupObservationFailure(executor.providerInstance, role, repairObservation, observeErr)
		}
		repairResult, present := repairObservation.Result()
		if !present || repairResult.CompleteStdinSHA256() != repairInvocation.CompleteStdinSHA256() {
			return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidProviderOutput, domain.FailureInvalidOutput, fmt.Errorf("repair result identity mismatch"))
		}
		validated, _, validationErr = executor.validator.ValidateWithRepairAuthority(ctx, repairResult.Stdout(), scope)
		observations = append(observations, repairObservation)
		runtimes = append(runtimes, repairRuntime)
		diagnosticDrops = append(diagnosticDrops, repairDiagnosticDrop)
		repaired = true
	}
	if validationErr != nil {
		condition := review.AttemptConditionUnrepairableProviderOutput
		if repaired {
			condition = review.AttemptConditionInvalidProviderOutput
		}
		return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, condition, domain.FailureInvalidOutput, validationErr)
	}
	for index := range runtimes {
		candidate := validated.NormalizedRaw()
		candidateKind := ports.AttemptArtifactInitialCandidate
		if repaired && index == 0 {
			candidate = initialRaw
		}
		if index == 1 {
			candidateKind = ports.AttemptArtifactRepairedCandidate
		}
		captures := make([]ports.CapturedAttemptArtifact, 0, 3)
		for _, capture := range []struct {
			kind  ports.AttemptArtifactKind
			bytes []byte
			drop  bool
		}{
			{candidateKind, candidate, diagnosticDrops[index].stdoutSecurityDropped},
			{ports.AttemptArtifactStdout, observations[index].Stdout(), diagnosticDrops[index].stdoutSecurityDropped},
			{ports.AttemptArtifactStderr, observations[index].Stderr(), diagnosticDrops[index].stderrSecurityDropped},
		} {
			if len(capture.bytes) == 0 && !capture.drop {
				continue
			}
			content := capture.bytes
			if capture.drop {
				content = nil
			}
			artifact, artifactErr := ports.NewCapturedAttemptArtifact(capture.kind, content, capture.drop)
			if artifactErr != nil {
				return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: capture %s: %w", capture.kind, artifactErr)
			}
			captures = append(captures, artifact)
		}
		runtimes[index].RuntimeCaptures = captures
	}
	candidate, err := publication.PrepareFollowupCandidate(publication.FollowupCandidateInput{Run: run, SourceSessionID: execution.Source.SessionID, SourceRunID: execution.Source.RunID, SourceReviewID: execution.Source.ReviewID, SourceFindingID: execution.Source.Finding.ID, SourceTargetSHA256: "sha256:" + execution.Source.Target.SHA256(), SourceExcerptSHA256: "sha256:" + execution.Source.Receipt.ExcerptSHA256, AttemptID: attemptID, Provider: executor.providerInstance, Output: validated, Observation: observations[len(observations)-1], Runtime: runtimes[len(runtimes)-1], Observations: observations, Runtimes: runtimes, Repaired: repaired, InitialCandidate: initialRaw, SeverityThreshold: executor.severityThreshold, MulgaeVersion: executor.mulgaeVersion, MulgaeCommit: executor.mulgaeCommit})
	if err != nil {
		return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidEvidenceClaim, domain.FailureInvalidOutput, err)
	}
	published, err := executor.publisher.PublishNext(ctx, executor.artifactRoot, candidate)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: publish: %w", err)
	}
	final, ok := published.Final()
	if !ok || !final.Valid() {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: publication has no P2 final receipt")
	}
	diagnosticP2, _ = ports.NewSafeRelativePath(".mulgae/" + final.Path().String())
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

func validateFollowupObservation(observation ports.ProviderExecutionObservation, invocation ports.ProviderInvocation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	if !observation.Succeeded() || observation.Invocation().ExecutionInvocationID() != invocation.ExecutionInvocationID() {
		return fmt.Errorf("provider execution was not a matching success")
	}
	return nil
}

func followupObservationFailure(provider string, role domain.Role, observation ports.ProviderExecutionObservation, cause error) error {
	class := observation.FailureClass()
	condition := review.AttemptConditionProviderUnavailable
	switch observation.PrimaryCause() {
	case domain.DiagnosticCauseOutputMissing:
		class = domain.FailureInvalidOutput
		condition = review.AttemptConditionProviderOutputMissing
	case domain.DiagnosticCauseOutputFrameMissing,
		domain.DiagnosticCauseOutputEnvelopeInvalid,
		domain.DiagnosticCauseOutputDecodeFailed,
		domain.DiagnosticCauseResultBindingFailed:
		class = domain.FailureInvalidOutput
		condition = review.AttemptConditionProviderOutputDecodeFailed
	case domain.DiagnosticCausePermissionDenied:
		class = domain.FailureAuthentication
		condition = review.AttemptConditionProviderPermissionDenied
	}
	if condition != review.AttemptConditionProviderUnavailable {
		return followupExecutionFailure(provider, role, condition, class, cause)
	}
	switch class {
	case domain.FailureTimeout:
		condition = review.AttemptConditionTimeout
	case domain.FailureAuthentication:
		condition = review.AttemptConditionAuthentication
	case domain.FailureQuota:
		condition = review.AttemptConditionQuota
	case domain.FailureRateLimit:
		condition = review.AttemptConditionRateLimit
	case domain.FailureSecurityPolicy:
		condition = review.AttemptConditionSecurityViolation
	case domain.FailureCancelled:
		condition = review.AttemptConditionCancelled
	case domain.FailureConfiguration:
		condition = review.AttemptConditionConfigurationViolation
	case domain.FailureArtifact:
		condition = review.AttemptConditionArtifactFailure
	}
	if !class.Valid() {
		class = domain.FailureInternal
		condition = review.AttemptConditionInternalInvariant
	}
	return followupExecutionFailure(provider, role, condition, class, cause)
}

func followupExecutionFailure(provider string, role domain.Role, condition review.AttemptCondition, class domain.FailureClass, cause error) error {
	fact, err := reviewrun.NewProviderExecutionFailure(provider, role, string(condition), class)
	if err != nil {
		return fmt.Errorf("followup executor: construct provider failure: %w", errors.Join(err, cause))
	}
	aggregate := reviewrun.NewProviderExecutionFailuresError([]reviewrun.ProviderExecutionFailure{fact})
	failure, err := domain.NewFailure("childrun.followup", class, "source provider followup failed", errors.Join(aggregate, cause))
	if err != nil {
		return fmt.Errorf("followup executor: construct typed failure: %w", errors.Join(err, cause))
	}
	return failure
}

var _ appfollowup.ChildExecutor = (*FollowupExecutor)(nil)
