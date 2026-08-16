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
	task, err := domain.NewRoleTask(role, true, executor.providerInstance)
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
	if declarationErr := followupStagedOutputDeclaration(invocation); declarationErr != nil {
		return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionConfigurationViolation, domain.FailureConfiguration, declarationErr)
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
	assistantContent := result.Stdout()
	observations := []ports.ProviderExecutionObservation{observation}
	runtimes := []publication.FollowupRuntimeArtifactInput{runtime}
	diagnosticDrops := []childDiagnosticObservation{diagnosticDrop}
	validated, repaired, initialCandidate, err := executor.acceptFollowupOutput(ctx, lifecycle, execution, run, attemptID, runtimeSource, scope, assistantContent, &observations, &runtimes, &diagnosticDrops)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	if err := bindFollowupRuntimeCaptures(runtimes, observations, diagnosticDrops, validated, repaired, initialCandidate); err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	candidateInput := publication.FollowupCandidateInput{
		Run: run, SourceSessionID: execution.Source.SessionID, SourceRunID: execution.Source.RunID, SourceReviewID: execution.Source.ReviewID,
		SourceFindingID: execution.Source.Finding.ID, SourceTargetSHA256: "sha256:" + execution.Source.Target.SHA256(), SourceExcerptSHA256: "sha256:" + execution.Source.Receipt.ExcerptSHA256,
		AttemptID: attemptID, Provider: executor.providerInstance, Output: validated, Observation: observations[len(observations)-1],
		Runtime: runtimes[len(runtimes)-1], Observations: observations, Runtimes: runtimes,
		Repaired: repaired, InitialCandidate: initialCandidate,
		SeverityThreshold: executor.severityThreshold, MulgaeVersion: executor.mulgaeVersion, MulgaeCommit: executor.mulgaeCommit,
	}
	candidate, err := publication.PrepareFollowupCandidate(candidateInput)
	if err != nil && errors.Is(err, publication.ErrFollowupStructuredRejected) && !validated.ReportsOnly() {
		reportsOnly, reportErr := validation.NewReportsOnlyValidatedFollowup(
			role, executor.providerInstance, assistantContent, domain.ParseValid, domain.ValidationInvalid,
		)
		if reportErr != nil {
			return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidEvidenceClaim, domain.FailureInvalidOutput, err)
		}
		validated = reportsOnly
		if bindErr := bindFollowupRuntimeCaptures(runtimes, observations, diagnosticDrops, validated, repaired, initialCandidate); bindErr != nil {
			return appfollowup.ExecutionResult{}, bindErr
		}
		candidateInput.Output = validated
		candidateInput.Runtimes = runtimes
		candidate, err = publication.PrepareFollowupCandidate(candidateInput)
	}
	if err != nil {
		if errors.Is(err, publication.ErrFollowupStructuredRejected) {
			return appfollowup.ExecutionResult{}, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidEvidenceClaim, domain.FailureInvalidOutput, err)
		}
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: prepare publication: %w", err)
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
	roleReportURIs, err := projectFollowupRoleReportURIs(published)
	if err != nil {
		return appfollowup.ExecutionResult{}, fmt.Errorf("followup executor: role report identities: %w", err)
	}
	executionResult, err := appfollowup.NewExecutionResult(run.SessionID(), run.ID(), receiptURI(executor.artifactRoot, final), validated, roleReportURIs, terminalExit)
	if err != nil {
		return appfollowup.ExecutionResult{}, err
	}
	return executionResult, nil
}

func (executor *FollowupExecutor) acceptFollowupOutput(
	ctx context.Context,
	lifecycle *childDiagnosticLifecycle,
	execution appfollowup.Execution,
	run domain.Run,
	attemptID domain.AttemptID,
	runtimeSource FollowupRuntimeInventorySource,
	scope validation.FollowupValidationScope,
	assistantContent []byte,
	observations *[]ports.ProviderExecutionObservation,
	runtimes *[]publication.FollowupRuntimeArtifactInput,
	diagnosticDrops *[]childDiagnosticObservation,
) (validation.ValidatedFollowup, bool, []byte, error) {
	role := scope.Role
	// The exact primary assistant stdout is the published role-report body on
	// every successful path. Repair stdout is a structured candidate only.
	primaryReport := append([]byte(nil), assistantContent...)
	class, structuredCandidate := review.ClassifyAssistantContent(primaryReport)
	initialClass := class
	initialCandidate := append([]byte(nil), structuredCandidate...)
	var (
		validated     validation.ValidatedFollowup
		validationErr error
		repairable    bool
	)
	if class == review.AssistantContentStructured || class == review.AssistantContentStructuredLike {
		validated, repairable, validationErr = executor.validator.ValidateWithRepairAuthority(ctx, structuredCandidate, scope)
	} else {
		validationErr = fmt.Errorf("followup executor: structured followup candidate is absent")
	}
	repaired := false
	if validationErr != nil && repairable {
		repairPrompts, repairAuthorized := executor.prompts.(FollowupRepairPromptSource)
		if !repairAuthorized {
			// Structurally repairable output without repair authority demotes to
			// reports-only when assistant content remains publishable.
			goto reportsOnly
		}
		repairInvocation, buildErr := repairPrompts.BuildFollowupRepairInvocation(ctx, execution, run, attemptID, primaryReport)
		if buildErr != nil {
			return validation.ValidatedFollowup{}, false, nil, fmt.Errorf("followup executor: build trusted repair prompt: %w", buildErr)
		}
		if repairInvocation.AttemptID() != attemptID || repairInvocation.Role() != role || repairInvocation.ProviderInstance() != executor.providerInstance || repairInvocation.Purpose() != ports.ProviderInvocationRepair {
			return validation.ValidatedFollowup{}, false, nil, fmt.Errorf("followup executor: repair prompt invocation identity mismatch")
		}
		if declarationErr := followupStagedOutputDeclaration(repairInvocation); declarationErr != nil {
			return validation.ValidatedFollowup{}, false, nil, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionConfigurationViolation, domain.FailureConfiguration, declarationErr)
		}
		repairRuntime, runtimeErr := runtimeSource.BuildFollowupRuntimeArtifact(ctx, execution, run, repairInvocation)
		if runtimeErr != nil {
			return validation.ValidatedFollowup{}, false, nil, fmt.Errorf("followup executor: build repair runtime inventory: %w", runtimeErr)
		}
		repairObservation, observeErr := executor.provider.Observe(ctx, repairInvocation)
		if observeErr != nil {
			return validation.ValidatedFollowup{}, false, nil, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionProviderUnavailable, domain.FailureProviderUnavailable, observeErr)
		}
		repairDiagnosticDrop, persistErr := lifecycle.persistObservation(ctx, repairObservation, 2)
		if persistErr != nil {
			return validation.ValidatedFollowup{}, false, nil, persistErr
		}
		if observeErr = validateFollowupObservation(repairObservation, repairInvocation); observeErr != nil {
			return validation.ValidatedFollowup{}, false, nil, followupObservationFailure(executor.providerInstance, role, repairObservation, observeErr)
		}
		repairResult, present := repairObservation.Result()
		if !present || repairResult.CompleteStdinSHA256() != repairInvocation.CompleteStdinSHA256() {
			return validation.ValidatedFollowup{}, false, nil, followupExecutionFailure(executor.providerInstance, role, review.AttemptConditionInvalidProviderOutput, domain.FailureInvalidOutput, fmt.Errorf("repair result identity mismatch"))
		}
		repairStdout := repairResult.Stdout()
		repairClass, repairCandidate := review.ClassifyAssistantContent(repairStdout)
		*observations = append(*observations, repairObservation)
		*runtimes = append(*runtimes, repairRuntime)
		*diagnosticDrops = append(*diagnosticDrops, repairDiagnosticDrop)
		repaired = true
		if repairClass != review.AssistantContentStructured && repairClass != review.AssistantContentStructuredLike {
			validationErr = fmt.Errorf("followup executor: repair response lacks structured candidate")
			class = repairClass
			goto reportsOnly
		}
		validated, _, validationErr = executor.validator.ValidateWithRepairAuthority(ctx, repairCandidate, scope)
		class = repairClass
		if len(initialCandidate) == 0 {
			initialCandidate = append([]byte(nil), structuredCandidate...)
		}
	}
	if validationErr == nil {
		if err := lifecycle.emitDiscardedProviderFields(ctx, attemptID, role, executor.providerInstance, validated.DiscardedPaths()); err != nil {
			return validation.ValidatedFollowup{}, repaired, nil, err
		}
		bound, bindErr := validated.WithReportBody(primaryReport, repaired)
		if bindErr != nil {
			return validation.ValidatedFollowup{}, false, nil, fmt.Errorf("followup executor: bind report body: %w", bindErr)
		}
		return bound, repaired, initialCandidate, nil
	}
	if followupOwnershipViolation(validationErr) {
		return validation.ValidatedFollowup{}, repaired, nil, followupExecutionFailure(
			executor.providerInstance, role,
			review.AttemptConditionSecurityViolation,
			domain.FailureSecurityPolicy,
			validationErr,
		)
	}
reportsOnly:
	parseState, validationState := followupReportsOnlyExtractionStates(class, initialClass, repaired)
	reportsOnly, reportErr := validation.NewReportsOnlyValidatedFollowup(
		role, executor.providerInstance, primaryReport, parseState, validationState,
	)
	if reportErr != nil {
		condition := review.AttemptConditionUnrepairableProviderOutput
		if repaired {
			condition = review.AttemptConditionInvalidProviderOutput
		}
		if validationErr != nil {
			return validation.ValidatedFollowup{}, false, nil, followupExecutionFailure(executor.providerInstance, role, condition, domain.FailureInvalidOutput, errors.Join(validationErr, reportErr))
		}
		return validation.ValidatedFollowup{}, false, nil, followupExecutionFailure(executor.providerInstance, role, condition, domain.FailureInvalidOutput, reportErr)
	}
	return reportsOnly, repaired, initialCandidate, nil
}

func followupOwnershipViolation(err error) bool {
	cause, ok := validation.RuntimeCause(err)
	return ok && cause == domain.DiagnosticCauseObservationMismatch
}

// followupReportsOnlyExtractionStates records Mulgae-owned parse/validation
// coverage for a successful reports-only followup accept. Free-form repair
// responses keep the primary attempt's structured parse class and mark
// validation as repair_exhausted rather than the initial validation_invalid.
func followupReportsOnlyExtractionStates(class, initialClass review.AssistantContentClass, repaired bool) (domain.ParseState, domain.ValidationState) {
	if repaired && class == review.AssistantContentFreeForm {
		class = initialClass
	}
	switch class {
	case review.AssistantContentStructured:
		if repaired {
			return domain.ParseValid, domain.ValidationRepairExhausted
		}
		return domain.ParseValid, domain.ValidationInvalid
	case review.AssistantContentStructuredLike:
		if repaired {
			return domain.ParseInvalidJSON, domain.ValidationRepairExhausted
		}
		return domain.ParseInvalidJSON, domain.ValidationInvalid
	default:
		return domain.ParseNotStarted, domain.ValidationNotStarted
	}
}

func bindFollowupRuntimeCaptures(
	runtimes []publication.FollowupRuntimeArtifactInput,
	observations []ports.ProviderExecutionObservation,
	diagnosticDrops []childDiagnosticObservation,
	validated validation.ValidatedFollowup,
	repaired bool,
	initialCandidate []byte,
) error {
	for index := range runtimes {
		candidateKind := ports.AttemptArtifactInitialCandidate
		var candidateBytes []byte
		switch {
		case index == 1:
			candidateKind = ports.AttemptArtifactRepairedCandidate
			if !validated.ReportsOnly() {
				candidateBytes = validated.NormalizedRaw()
			}
		case validated.ReportsOnly():
			candidateBytes = initialCandidate
		default:
			candidateBytes = validated.NormalizedRaw()
		}
		if repaired && index == 0 {
			candidateBytes = initialCandidate
		}
		captures := make([]ports.CapturedAttemptArtifact, 0, 3)
		for _, capture := range []struct {
			kind  ports.AttemptArtifactKind
			bytes []byte
			drop  bool
		}{
			{candidateKind, candidateBytes, diagnosticDrops[index].stdoutSecurityDropped},
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
				return fmt.Errorf("followup executor: capture %s: %w", capture.kind, artifactErr)
			}
			captures = append(captures, artifact)
		}
		runtimes[index].RuntimeCaptures = captures
	}
	return nil
}

// followupPromptFramesPreamble is the exact boundary the prompt compiler writes
// between the trusted template and the untrusted frames of one packet.
const followupPromptFramesPreamble = "\nMulgae-FRAMES/1\n"

// followupStagedOutputDeclaration repeats, for the followup launch path, the
// fail-closed pre-launch check the review runtime performs for root review. The
// followup executor invokes its provider directly rather than through that
// runtime, so a staged invocation whose packet does not end with the exact
// destination layer would send the provider to a path Mulgae never granted.
func followupStagedOutputDeclaration(invocation ports.ProviderInvocation) error {
	destination, staged := invocation.StagedOutputDestination()
	if !staged {
		return nil
	}
	layer, err := review.OutputDestinationTrustedLayer(destination)
	if err != nil {
		return fmt.Errorf("staged output destination is invalid: %w", err)
	}
	packet := invocation.PacketBytes()
	boundary := bytes.Index(packet, []byte(followupPromptFramesPreamble))
	if boundary <= 0 || !bytes.HasSuffix(packet[:boundary], layer.Bytes()) {
		return fmt.Errorf("staged launch prompt does not state its output destination")
	}
	return nil
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
	case domain.DiagnosticCauseOutputMissing,
		// A staged file the provider never wrote is missing output, exactly like
		// an empty stdout transport: operational, and repair stays available.
		domain.DiagnosticCauseProviderOutputFileMissing:
		class = domain.FailureInvalidOutput
		condition = review.AttemptConditionProviderOutputMissing
	case domain.DiagnosticCauseOutputFrameMissing,
		domain.DiagnosticCauseOutputEnvelopeInvalid,
		domain.DiagnosticCauseOutputDecodeFailed,
		domain.DiagnosticCauseResultBindingFailed,
		// Staged bytes Mulgae could not read back as usable output are an
		// ordinary decode failure rather than a boundary breach.
		domain.DiagnosticCauseProviderOutputFileInvalid:
		class = domain.FailureInvalidOutput
		condition = review.AttemptConditionProviderOutputDecodeFailed
	case domain.DiagnosticCausePermissionDenied:
		class = domain.FailureAuthentication
		condition = review.AttemptConditionProviderPermissionDenied
	case domain.DiagnosticCauseProviderOutputStagingViolation:
		// A provider that wrote outside the single staged file it was granted
		// breached a boundary, so staging violations fail the followup closed.
		class = domain.FailureSecurityPolicy
		condition = review.AttemptConditionSecurityViolation
	case domain.DiagnosticCauseProviderOutputStagingCleanupFailed:
		// Staging Mulgae cannot prove it removed is an artifact fact: fail closed
		// rather than reuse the attempt through repair.
		class = domain.FailureArtifact
		condition = review.AttemptConditionArtifactFailure
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
