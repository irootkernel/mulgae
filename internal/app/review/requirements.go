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

func (runtime *ProviderInvocationRuntime) invokeRequirements(ctx context.Context, job InvocationJob, candidate, primary, stdout, stderr []byte, transport ports.ProviderOutputTransport, scope validation.ReviewValidationScope) AttemptOutcome {
	findings, section, present, parseErr := validation.SplitRequirementsResponse(candidate)
	runtime.mu.Lock()
	state := runtime.requirementSections[job.Role()]
	prior, hasPrior := runtime.requirementOutputs[job.Role()]
	runtime.mu.Unlock()
	// Retry/repair already owns the shared additional slot. An extraction launch
	// itself is eligible transcription, not an unavailable-allowance condition.
	if parseErr != nil && job.Purpose() == domain.InvocationInitial {
		if plan := validation.RequirementsReformatPlan(candidate); plan != nil {
			runtime.mu.Lock()
			runtime.pending[job.AttemptID()] = InvocationRepairInput{initial: append([]byte(nil), candidate...), primaryReport: append([]byte(nil), primary...), plan: *plan, parseState: domain.ParseInvalidJSON, validationState: domain.ValidationInvalid}
			runtime.mu.Unlock()
			if err := runtime.capture(ctx, job, nil, stdout, stderr, false); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			return runtimeCondition(job, AttemptConditionInvalidProviderOutput)
		}
	}
	if present && parseErr != nil && !state.present {
		state.present = true
		state.invalid = true
	}
	state.spent = state.spent || job.Purpose() == domain.InvocationRetry || job.Purpose() == domain.InvocationRepair
	if present && parseErr == nil {
		answers, err := validation.DecodeProviderRequirements(ctx, section, runtime.requirements.Requirements(), job.Role(), runtime.liveIdentity, runtime.verifier, runtime.liveVisuals, runtime.requirementsPath, runtime.requirements.SHA256())
		if condition, protected := requirementsFailureCondition(ctx, err); protected {
			if captureErr := runtime.capture(ctx, job, nil, stdout, stderr, condition == AttemptConditionSecurityViolation); captureErr != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(captureErr))
			}
			return runtimeCondition(job, condition)
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
	parseState, validationState := domain.ParseNotStarted, domain.ValidationNotStarted
	if len(candidate) > 0 {
		parseState = diagnosticParseState(parseErr, candidate)
		validationState = domain.ValidationInvalid
	}
	report := primary
	if job.Purpose() == domain.InvocationRepair {
		runtime.mu.Lock()
		repair := runtime.pending[job.AttemptID()]
		delete(runtime.pending, job.AttemptID())
		runtime.mu.Unlock()
		report = repair.PrimaryReport()
		validationState = domain.ValidationRepairExhausted
		if len(candidate) == 0 {
			parseState = repair.parseState
		}
	}
	if job.Purpose() == domain.InvocationExtract && hasPrior {
		report = prior.ReportMarkdown()
		transport = prior.OutputTransport()
	}
	var outcome AttemptOutcome
	var acceptedFindings *validation.ValidatedReview
	if parseErr == nil {
		validated, _, err := runtime.validator.Validate(ctx, findings, scope)
		if condition, protected := requirementsFailureCondition(ctx, err); protected {
			if err := runtime.capture(ctx, job, nil, stdout, stderr, condition == AttemptConditionSecurityViolation); err != nil {
				return runtimeCondition(job, diagnosticConditionForPersistence(err))
			}
			return runtimeCondition(job, condition)
		}
		if err == nil {
			acceptedFindings = &validated
			if job.Purpose() == domain.InvocationExtract && hasPrior && !prior.ReportsOnly() {
				copy := prior.clone()
				outcome, _ = NewAttemptOutcome(job, &copy, nil)
			} else if job.Purpose() == domain.InvocationExtract {
				outcome = runtime.acceptExtraction(ctx, job, validated, report, transport)
			} else {
				outcome = runtime.accept(ctx, job, validated, report, transport)
			}
		}
	}
	if !outcome.Succeeded() {
		if condition, ok := outcome.Condition(); ok && (condition == AttemptConditionTimeout || app.FailurePrecedence(conditionFailureClass(condition)) > extractionBoundedFailureCeiling) {
			return outcome
		}
		if job.Purpose() == domain.InvocationExtract && hasPrior {
			// Ordinary peer failure retains both the accepted report and any already
			// verified findings. Assessment state remains independent of that output.
			copy := prior.clone()
			copy.assessmentPending = false
			outcome, _ = NewAttemptOutcome(job, &copy, nil)
		} else {
			var accepted bool
			outcome, accepted = runtime.acceptFreeFormReport(ctx, job, report, findings, stdout, stderr, parseState, validationState, transport)
			if !accepted {
				return runtimeCondition(job, AttemptConditionArtifactFailure)
			}
		}
	} else if err := runtime.capture(ctx, job, findings, stdout, stderr, false); err != nil {
		return runtimeCondition(job, diagnosticConditionForPersistence(err))
	}
	output, ok := outcome.Output()
	if !ok {
		return outcome
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
				return runtimeCondition(job, AttemptConditionInternalInvariant)
			}
			runtime.normalizedRequirements[job.Role()] = composed
		}
	}
	runtime.mu.Unlock()
	result, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return runtimeCondition(job, AttemptConditionInternalInvariant)
	}
	return result
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

func requirementsFailureCondition(ctx context.Context, err error) (AttemptCondition, bool) {
	return selectRequirementsFailure(ctx, err, false)
}
func requirementsSourceCondition(ctx context.Context, err error) AttemptCondition {
	condition, _ := selectRequirementsFailure(ctx, err, true)
	return condition
}

// Map the closed source/validator observations, then let the existing selector
// visit every typed cause and joined child with canonical failure precedence.
func selectRequirementsFailure(ctx context.Context, err error, sourceBoundary bool) (AttemptCondition, bool) {
	if err == nil {
		return "", false
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
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if source, ok := current.(*ports.LiveSourceError); ok {
			switch source.Code() {
			case ports.LiveSourceInvalid, ports.LiveSourceUnsupported:
				observe(domain.FailureInvalidOutput)
			case ports.LiveSourceUnsafe:
				observe(domain.FailureSecurityPolicy)
			case ports.LiveSourceUnavailable:
				observe(domain.FailureArtifact)
			case ports.LiveSourceConflict, ports.LiveSourceRevision, ports.LiveSourceNoMergeBase:
				observe(domain.FailureConfiguration)
			default:
				observe(domain.FailureInternal)
			}
		}
		if failure, ok := current.(*validation.RuntimeError); ok && failure.Cause() == domain.DiagnosticCauseObservationMismatch {
			observe(domain.FailureSecurityPolicy)
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
			return AttemptConditionInternalInvariant, true
		}
		return "", false
	}
	var condition AttemptCondition
	switch selected.Class {
	case domain.FailureInternal:
		condition = AttemptConditionInternalInvariant
	case domain.FailureSecurityPolicy:
		condition = AttemptConditionSecurityViolation
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
		condition = AttemptConditionInvalidProviderOutput
	}
	return condition, selected.Class != domain.FailureInvalidOutput
}

// NormalizedRequirementsOutput exposes the trusted complete in-memory v3
// composition without creating another persisted artifact or provider call.
func (runtime *ProviderInvocationRuntime) NormalizedRequirementsOutput(role domain.Role) (validation.NormalizedRequirementsOutput, bool) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	output, ok := runtime.normalizedRequirements[role]
	return output, ok
}
