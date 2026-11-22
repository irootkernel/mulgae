package review

import (
	"context"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requirementSectionState struct {
	present bool
	invalid bool
	answers []validation.ValidatedRequirementAnswer
	spent   bool
}

// BindRequirements is internal run admission, before any invocation. It neither
// enables extraction nor changes the coordinator's existing second-slot policy.
func (runtime *ProviderInvocationRuntime) BindRequirements(input validation.RequirementsInput, path string) error {
	if runtime == nil || !runtime.liveIdentity.Valid() || len(input.Requirements()) == 0 {
		return fmt.Errorf("requirements runtime: invalid admission")
	}
	if _, err := ports.NewSafeRelativePath(path); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.requirements != nil || len(runtime.inventory) != 0 {
		return fmt.Errorf("requirements runtime: already executing")
	}
	runtime.requirements = &input
	runtime.requirementsPath = path
	runtime.requirementSections = make(map[domain.Role]requirementSectionState)
	runtime.requirementOutputs = make(map[domain.Role]ValidatedRoleOutput)
	runtime.requirementFindings = make(map[domain.Role]validation.ValidatedReview)
	runtime.normalizedRequirements = make(map[domain.Role]validation.NormalizedRequirementsOutput)
	return nil
}
func (runtime *ProviderInvocationRuntime) ownsRequirements(role domain.Role) bool {
	if runtime.requirements == nil {
		return false
	}
	for _, r := range runtime.requirements.Requirements() {
		if r.OwnerRole() == role {
			return true
		}
	}
	return false
}

func (runtime *ProviderInvocationRuntime) RequirementsResult(extraction bool) (validation.RequirementResults, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.requirements == nil {
		return validation.RequirementResults{}, fmt.Errorf("requirements runtime: not admitted")
	}
	var answers []validation.ValidatedRequirementAnswer
	reasons := make(map[domain.Role]domain.AssessmentReason)
	for _, r := range runtime.requirements.Requirements() {
		state := runtime.requirementSections[r.OwnerRole()]
		reason := domain.AssessmentAnswerOmitted
		if state.present {
			if state.invalid {
				reason = domain.AssessmentInvalidContent
			}
		} else if !extraction {
			reason = domain.AssessmentExtractionDisabled
		} else if state.spent {
			reason = domain.AssessmentExtractionAllowanceSpent
		}
		reasons[r.OwnerRole()] = reason
	}
	for _, state := range runtime.requirementSections {
		answers = append(answers, state.answers...)
	}
	return validation.NormalizeRequirements(*runtime.requirements, answers, reasons, runtime.liveIdentity.SHA256(), false)
}

func (runtime *ProviderInvocationRuntime) invokeRequirements(
	ctx context.Context,
	job InvocationJob,
	candidate, primary, stdout, stderr []byte,
	transport ports.ProviderOutputTransport,
	scope validation.ReviewValidationScope,
) (AttemptOutcome, domain.ParseState, domain.ValidationState) {
	if job.Purpose() == domain.InvocationExtract {
		defer func() {
			runtime.mu.Lock()
			delete(runtime.pendingExtraction, job.AttemptID())
			runtime.mu.Unlock()
		}()
	}
	repaired := job.Purpose() == domain.InvocationRepair
	var repair InvocationRepairInput
	if repaired {
		runtime.mu.Lock()
		repair = runtime.pending[job.AttemptID()]
		runtime.mu.Unlock()
		defer func() {
			runtime.mu.Lock()
			delete(runtime.pending, job.AttemptID())
			runtime.mu.Unlock()
		}()
	}
	invParseState, invValidationState := domain.ParseNotStarted, domain.ValidationNotStarted
	runtime.mu.Lock()
	state := runtime.requirementSections[job.Role()]
	prior, hasPrior := runtime.requirementOutputs[job.Role()]
	runtime.mu.Unlock()

	report := primary
	if repaired {
		report = repair.PrimaryReport()
	}
	if job.Purpose() == domain.InvocationExtract && hasPrior {
		report = prior.ReportMarkdown()
		transport = prior.OutputTransport()
	}
	finalizeAccepted := func(outcome AttemptOutcome, acceptedFindings *validation.ValidatedReview) (AttemptOutcome, domain.ParseState, domain.ValidationState) {
		output, ok := outcome.Output()
		if !ok {
			return outcome, invParseState, invValidationState
		}
		// A valid available section owns omissions. Only absence leaves extraction
		// pending, and coordinator admission still controls whether it can run.
		output.assessmentPending = runtime.ownsRequirements(job.Role()) && !state.present && job.Purpose() == domain.InvocationInitial
		if job.Purpose() == domain.InvocationInitial {
			runtime.mu.Lock()
			runtime.pendingExtraction[job.AttemptID()] = InvocationExtractionInput{acceptedReport: output.ReportMarkdown(), reportTransport: transport}
			runtime.mu.Unlock()
		}
		runtime.mu.Lock()
		runtime.requirementOutputs[job.Role()] = output.clone()
		if !output.ReportsOnly() {
			if acceptedFindings != nil && !(job.Purpose() == domain.InvocationExtract && hasPrior && !prior.ReportsOnly()) {
				runtime.requirementFindings[job.Role()] = *acceptedFindings
			}
			if state.present && !state.invalid {
				composed, err := validation.ComposeRequirementsOutput(runtime.requirementFindings[job.Role()], state.answers, scope)
				if err != nil {
					runtime.mu.Unlock()
					return runtimeCondition(job, AttemptConditionInternalInvariant), invParseState, invValidationState
				}
				runtime.normalizedRequirements[job.Role()] = composed
			}
		}
		runtime.mu.Unlock()
		result, err := NewAttemptOutcome(job, &output, nil)
		if err != nil {
			return runtimeCondition(job, AttemptConditionInternalInvariant), invParseState, invValidationState
		}
		return result, invParseState, invValidationState
	}
	fallbackReport := func(captureCandidate []byte, reportParse domain.ParseState, reportValidation domain.ValidationState) (AttemptOutcome, domain.ParseState, domain.ValidationState) {
		if job.Purpose() == domain.InvocationExtract && hasPrior {
			if err := runtime.capture(ctx, job, captureCandidate, stdout, stderr, false); err != nil {
				return runtimePersistenceOutcome(job, err), invParseState, invValidationState
			}
			// Ordinary peer failure retains both the accepted report and any already
			// verified findings. Assessment state remains independent of that output.
			copied := prior.clone()
			copied.assessmentPending = false
			outcome, _ := NewAttemptOutcome(job, &copied, nil)
			return finalizeAccepted(outcome, nil)
		}
		outcome, accepted := runtime.acceptFreeFormReport(ctx, job, report, captureCandidate, stdout, stderr, reportParse, reportValidation, transport)
		if !accepted {
			if err := runtime.capture(ctx, job, captureCandidate, stdout, stderr, false); err != nil {
				return runtimePersistenceOutcome(job, err), invParseState, invValidationState
			}
			return runtimeCondition(job, AttemptConditionArtifactFailure), invParseState, invValidationState
		}
		if !outcome.Succeeded() {
			// acceptFreeFormReport already executed runtime.capture.
			return outcome, invParseState, invValidationState
		}
		return finalizeAccepted(outcome, nil)
	}

	state.spent = state.spent || job.Purpose() == domain.InvocationRetry || repaired

	// Pure prose skips structured parsing and validation diagnostics entirely,
	// retaining ParseNotStarted / ValidationNotStarted on this invocation.
	if len(candidate) == 0 {
		runtime.mu.Lock()
		runtime.requirementSections[job.Role()] = state
		runtime.mu.Unlock()
		reportParse, reportValidation := domain.ParseNotStarted, domain.ValidationNotStarted
		if repaired {
			reportParse = repair.parseState
			reportValidation = domain.ValidationRepairExhausted
		}
		return fallbackReport(nil, reportParse, reportValidation)
	}

	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParseStarted, "", "", "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState
	}
	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticValidationStarted, "", "", "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState
	}

	findings, section, present, parseErr := validation.SplitRequirementsResponse(candidate)
	if parseErr != nil {
		invParseState = diagnosticParseState(parseErr, candidate)
		invValidationState = domain.ValidationInvalid
		if repaired {
			invValidationState = domain.ValidationRepairExhausted
		}
		if err := runtime.emitValidationDiagnostics(ctx, job, parseErr, repaired); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState
		}
		// Retry/repair already owns the shared additional slot. An extraction launch
		// itself is eligible transcription, not an unavailable-allowance condition.
		if job.Purpose() == domain.InvocationInitial {
			if plan := validation.RequirementsReformatPlan(candidate); plan != nil {
				runtime.mu.Lock()
				runtime.pending[job.AttemptID()] = InvocationRepairInput{
					initial:         append([]byte(nil), candidate...),
					primaryReport:   append([]byte(nil), primary...),
					plan:            *plan,
					parseState:      invParseState,
					validationState: domain.ValidationInvalid,
				}
				runtime.mu.Unlock()
				// Structured candidate artifacts are bounded at 8 MiB while
				// requirements-bearing raw responses are unbounded in stdout.raw;
				// malformed responses have no bounded findings projection.
				if err := runtime.capture(ctx, job, nil, stdout, stderr, false); err != nil {
					return runtimePersistenceOutcome(job, err), invParseState, invValidationState
				}
				return runtimeCondition(job, AttemptConditionInvalidProviderOutput), invParseState, invValidationState
			}
		}
		if present && !state.present {
			state.present = true
			state.invalid = true
		}
		runtime.mu.Lock()
		runtime.requirementSections[job.Role()] = state
		runtime.mu.Unlock()
		return fallbackReport(nil, invParseState, invValidationState)
	}

	invParseState = domain.ParseValid
	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParsed, "", string(domain.ParseValid), "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState
	}

	// Candidate artifacts (candidate.*.json) remain bounded structured
	// publication members (ports.PublicationStructuredMemberMaxBytes), so omit
	// the structured candidate member when findings exceeds that bound while
	// preserving full unbounded output in stdout.raw and normalized
	// requirements/items/*.json.
	protectedReturn := func(condition AttemptCondition, cause domain.RuntimeDiagnosticCause, err error) (AttemptOutcome, domain.ParseState, domain.ValidationState) {
		invValidationState = domain.ValidationInvalid
		if repaired {
			invValidationState = domain.ValidationRepairExhausted
		}
		diagCause := cause
		if !diagCause.Valid() {
			if c, ok := validation.RuntimeCause(err); ok {
				diagCause = c
			}
		}
		reject := isSecurityRejectionCondition(condition)
		if emitErr := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); emitErr != nil {
			if persisted := runtimePersistenceOutcome(job, emitErr); persistenceOverridesCondition(condition, persisted) {
				return persisted, invParseState, invValidationState
			}
		}
		captureCandidate := boundedCandidate(findings)
		if repaired {
			captureCandidate = nil
		}
		if captureErr := runtime.capture(ctx, job, captureCandidate, stdout, stderr, reject); captureErr != nil {
			if persisted := runtimePersistenceOutcome(job, captureErr); persistenceOverridesCondition(condition, persisted) {
				return persisted, invParseState, invValidationState
			}
		}
		return runtimeConditionWithCause(job, condition, cause), invParseState, invValidationState
	}

	var reqErr error
	if present {
		answers, err := validation.DecodeProviderRequirements(ctx, section, runtime.requirements.Requirements(), job.Role(), runtime.liveIdentity, runtime.verifier, runtime.liveVisuals, runtime.requirementsPath, runtime.requirements.SHA256())
		reqErr = err
		if condition, cause, protected := requirementsFailureCondition(ctx, err); protected {
			return protectedReturn(condition, cause, err)
		}
		// A later failed section never erases a previously accepted valid section.
		if !state.present || state.invalid {
			state.present = true
			state.invalid = err != nil
			if err == nil {
				state.answers = answers
			}
		}
	}
	runtime.mu.Lock()
	runtime.requirementSections[job.Role()] = state
	runtime.mu.Unlock()

	validated, _, findingsErr := runtime.validator.Validate(ctx, findings, scope)
	if findingsErr == nil {
		if err := runtime.emitDiscardedFieldDiagnostics(ctx, job, validated.DiscardedPaths()); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState
		}
	}
	if condition, cause, protected := requirementsFailureCondition(ctx, findingsErr); protected {
		return protectedReturn(condition, cause, findingsErr)
	}

	var outcome AttemptOutcome
	var acceptedFindings *validation.ValidatedReview
	if findingsErr == nil {
		acceptedFindings = &validated
		if job.Purpose() == domain.InvocationExtract && hasPrior && !prior.ReportsOnly() {
			copied := prior.clone()
			outcome, _ = NewAttemptOutcome(job, &copied, nil)
		} else if job.Purpose() == domain.InvocationExtract {
			outcome = runtime.acceptExtraction(ctx, job, validated, report, transport)
		} else {
			outcome = runtime.accept(ctx, job, validated, report, transport)
		}
	}
	if !outcome.Succeeded() {
		if job.Purpose() == domain.InvocationInitial {
			// Requirements mode converts bounded findings/evidence failures to
			// reports-only fallback instead of scheduling evidence repair, and
			// protected failures terminate the attempt without repair.
			runtime.mu.Lock()
			delete(runtime.pending, job.AttemptID())
			runtime.mu.Unlock()
		}
		reportValidation := domain.ValidationInvalid
		if repaired {
			reportValidation = domain.ValidationRepairExhausted
		}
		invValidationState = reportValidation
		if condition, ok := outcome.Condition(); ok && (condition == AttemptConditionTimeout || app.FailurePrecedence(conditionFailureClass(condition)) > extractionBoundedFailureCeiling) {
			reject := isSecurityRejectionCondition(condition)
			diagCause := outcome.diagnosticCause
			if emitErr := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); emitErr != nil {
				if persisted := runtimePersistenceOutcome(job, emitErr); persistenceOverridesCondition(condition, persisted) {
					return persisted, invParseState, invValidationState
				}
			}
			captureCandidate := boundedCandidate(findings)
			if repaired {
				captureCandidate = nil
			}
			if captureErr := runtime.capture(ctx, job, captureCandidate, stdout, stderr, reject); captureErr != nil {
				if persisted := runtimePersistenceOutcome(job, captureErr); persistenceOverridesCondition(condition, persisted) {
					return persisted, invParseState, invValidationState
				}
			}
			return outcome, invParseState, invValidationState
		}
		var diagCause domain.RuntimeDiagnosticCause
		if findingsErr != nil {
			diagCause, _ = validation.RuntimeCause(findingsErr)
		} else if reqErr != nil {
			diagCause, _ = validation.RuntimeCause(reqErr)
		}
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState
		}
		captureCandidate := boundedCandidate(findings)
		if repaired {
			captureCandidate = nil
		}
		return fallbackReport(captureCandidate, invParseState, reportValidation)
	}
	if reqErr == nil {
		invValidationState = domain.ValidationValid
		if repaired {
			invValidationState = domain.ValidationRepairedValid
		}
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, true, repaired, ""); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState
		}
	} else {
		invValidationState = domain.ValidationInvalid
		if repaired {
			invValidationState = domain.ValidationRepairExhausted
		}
		diagCause, _ := validation.RuntimeCause(reqErr)
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState
		}
	}
	if err := runtime.capture(ctx, job, boundedCandidate(findings), stdout, stderr, false); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState
	}
	return finalizeAccepted(outcome, acceptedFindings)
}

func boundedCandidate(candidate []byte) []byte {
	if len(candidate) == 0 || int64(len(candidate)) > ports.PublicationStructuredMemberMaxBytes {
		return nil
	}
	return candidate
}

func (runtime *ProviderInvocationRuntime) emitRequirementsValidationTerminal(
	ctx context.Context,
	job InvocationJob,
	valid bool,
	repaired bool,
	cause domain.RuntimeDiagnosticCause,
) error {
	if valid {
		state := domain.ValidationValid
		if repaired {
			state = domain.ValidationRepairedValid
		}
		if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticValidationSucceeded, "", string(state), "", "", 0, false, "", 0); err != nil {
			return err
		}
		if repaired {
			return runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticWarn, domain.DiagnosticRepairCompleted, "", string(state), "", "", 0, false, "", 0)
		}
		return nil
	}
	if !cause.Valid() {
		cause = domain.DiagnosticCauseCandidateValidationFailed
	}
	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticError, domain.DiagnosticValidationFailed, cause, string(domain.ValidationInvalid), "", "", 0, false, "", 0); err != nil {
		return err
	}
	if repaired {
		return runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticError, domain.DiagnosticRepairExhausted, cause, string(domain.ValidationRepairExhausted), "", "", 0, false, "", 0)
	}
	return nil
}

// ComposeRequirementsReview adds only trusted framing. Requirement bodies enter
// the compiler separately as an untrusted payload.
func (templates TemplateSet) ComposeRequirementsReview(original prompt.TrustedTemplate, layer prompt.TrustedLayer) (prompt.TrustedTemplate, error) {
	if layer.ID() == "" {
		return prompt.TrustedTemplate{}, fmt.Errorf("requirements prompt: missing contract")
	}
	layers, err := trustedLayersForRepair(original)
	if err != nil {
		return prompt.TrustedTemplate{}, err
	}
	return prompt.ComposeTrustedTemplate(original.ID(), original.Version(), append(layers, layer)...)
}

func requirementsFailureCondition(ctx context.Context, err error) (AttemptCondition, domain.RuntimeDiagnosticCause, bool) {
	return selectRequirementsFailure(ctx, err, false)
}
func requirementsSourceCondition(ctx context.Context, err error) (AttemptCondition, domain.RuntimeDiagnosticCause) {
	condition, cause, _ := selectRequirementsFailure(ctx, err, true)
	return condition, cause
}

// Map the closed source/validator observations, then let the existing selector
// visit every typed cause and joined child with canonical failure precedence.
func selectRequirementsFailure(ctx context.Context, err error, sourceBoundary bool) (AttemptCondition, domain.RuntimeDiagnosticCause, bool) {
	if err == nil {
		return "", "", false
	}
	observations := []error{err}
	if ctx != nil && ctx.Err() != nil {
		observations = append(observations, ctx.Err())
	}
	if _, ok := validation.RequirementsSourceFailure(err); ok {
		sourceBoundary = true
	}
	observe := func(class domain.FailureClass) {
		failure, _ := domain.NewFailure("requirements.validation", class, "requirements validation failed", nil)
		observations = append(observations, failure)
	}
	var securityCause domain.RuntimeDiagnosticCause
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if source, ok := current.(*ports.LiveSourceError); ok {
			cond, cause := classifyLiveSourceErrorNode(source)
			switch cond {
			case AttemptConditionUnrepairableEvidence:
				observe(domain.FailureInvalidOutput)
			case AttemptConditionSecurityViolation:
				observe(domain.FailureSecurityPolicy)
				if securityCause == "" && cause.Valid() {
					securityCause = cause
				}
			case AttemptConditionArtifactFailure:
				observe(domain.FailureArtifact)
			case AttemptConditionConfigurationViolation:
				observe(domain.FailureConfiguration)
			default:
				observe(domain.FailureInternal)
			}
		}
		if failure, ok := current.(*validation.RuntimeError); ok &&
			(failure.Cause() == domain.DiagnosticCauseProviderOwnershipViolation || failure.Cause() == domain.DiagnosticCauseObservationMismatch) {
			observe(domain.FailureSecurityPolicy)
			if securityCause == "" {
				securityCause = failure.Cause()
			}
		}
		if diagnostic, ok := current.(interface{ DocumentViolation() bool }); ok && !diagnostic.DocumentViolation() {
			observe(domain.FailureInternal)
		}
		switch nested := current.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range nested.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(nested.Unwrap())
		}
	}
	visit(err)
	selected, ok := app.SelectFailure(errors.Join(observations...), app.FailureTypedOnly, domain.FailureInternal)
	if !ok {
		if sourceBoundary {
			return AttemptConditionInternalInvariant, "", true
		}
		return "", "", false
	}
	var condition AttemptCondition
	var cause domain.RuntimeDiagnosticCause
	switch selected.Class {
	case domain.FailureInternal:
		condition = AttemptConditionInternalInvariant
	case domain.FailureSecurityPolicy:
		condition = AttemptConditionSecurityViolation
		cause = securityCause
	case domain.FailureArtifact:
		condition = AttemptConditionArtifactFailure
	case domain.FailureConfiguration:
		condition = AttemptConditionConfigurationViolation
	case domain.FailureCancelled:
		condition = AttemptConditionCancelled
	case domain.FailureTimeout:
		condition = AttemptConditionTimeout
	case domain.FailureAuthentication:
		condition = AttemptConditionAuthentication
	case domain.FailureQuota:
		condition = AttemptConditionQuota
	case domain.FailureRateLimit:
		condition = AttemptConditionRateLimit
	case domain.FailureProviderUnavailable:
		condition = AttemptConditionProviderUnavailable
	default:
		if sourceBoundary {
			condition = AttemptConditionUnrepairableEvidence
		} else {
			condition = AttemptConditionInvalidProviderOutput
		}
	}
	return condition, cause, selected.Class != domain.FailureInvalidOutput
}

// NormalizedRequirementsOutput exposes the trusted complete in-memory v3
// composition without creating another persisted artifact or provider call.
func (runtime *ProviderInvocationRuntime) NormalizedRequirementsOutput(role domain.Role) (validation.NormalizedRequirementsOutput, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	output, ok := runtime.normalizedRequirements[role]
	return output, ok
}
