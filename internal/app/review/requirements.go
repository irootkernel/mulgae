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
	present        bool
	sectionInvalid bool
	answers        map[string]validation.ValidatedRequirementAnswer
	invalidIDs     map[string]bool
	spent          bool
}

func cloneRequirementSectionState(state requirementSectionState) requirementSectionState {
	cloned := requirementSectionState{
		present:        state.present,
		sectionInvalid: state.sectionInvalid,
		spent:          state.spent,
	}
	if len(state.answers) > 0 {
		cloned.answers = make(map[string]validation.ValidatedRequirementAnswer, len(state.answers))
		for id, answer := range state.answers {
			cloned.answers[id] = answer
		}
	}
	if len(state.invalidIDs) > 0 {
		cloned.invalidIDs = make(map[string]bool, len(state.invalidIDs))
		for id, invalid := range state.invalidIDs {
			if invalid {
				cloned.invalidIDs[id] = true
			}
		}
	}
	return cloned
}

// orderedRequirementAnswers projects accepted requirement answers in admitted
// input order so both normalized support and v3 composition stay deterministic.
func orderedRequirementAnswers(
	selected []domain.Requirement,
	stateForRole func(domain.Role) requirementSectionState,
	filterRole domain.Role,
) []validation.ValidatedRequirementAnswer {
	ordered := make([]validation.ValidatedRequirementAnswer, 0, len(selected))
	for _, r := range selected {
		if filterRole != "" && r.OwnerRole() != filterRole {
			continue
		}
		if answer, ok := stateForRole(r.OwnerRole()).answers[r.ID()]; ok {
			ordered = append(ordered, answer)
		}
	}
	return ordered
}

// mergeRequirementSectionState applies the monotone initial -> extract merge
// rule for one role's requirement section:
//   - Section-wide ordinary failures mark sectionInvalid only when no section
//     was previously present, preserving any earlier valid or partial section.
//   - Structurally valid sections insert missing answers, may upgrade an
//     earlier provider unverified answer to a decisive verdict without ever
//     overwriting or downgrading a decisive answer, clear resolved IDs from
//     invalidIDs, and mark newly invalid IDs only when not already accepted.
func mergeRequirementSectionState(
	state *requirementSectionState,
	decoded validation.ProviderRequirementsDecodeResult,
	sectionErr error,
) {
	if sectionErr != nil {
		if !state.present {
			state.present = true
			state.sectionInvalid = true
		}
		return
	}
	state.present = true
	state.sectionInvalid = false
	if len(decoded.Answers) > 0 && state.answers == nil {
		state.answers = make(map[string]validation.ValidatedRequirementAnswer, len(decoded.Answers))
	}
	for _, ans := range decoded.Answers {
		id := ans.Assessment().RequirementID()
		existing, exists := state.answers[id]
		if !exists {
			state.answers[id] = ans
		} else if existing.Assessment().Verdict() == domain.RequirementUnverified && ans.Assessment().Verdict() != domain.RequirementUnverified {
			state.answers[id] = ans
		}
		delete(state.invalidIDs, id)
	}
	if len(decoded.InvalidIDs) > 0 {
		if state.invalidIDs == nil {
			state.invalidIDs = make(map[string]bool, len(decoded.InvalidIDs))
		}
		for id, invalid := range decoded.InvalidIDs {
			if !invalid {
				continue
			}
			if _, exists := state.answers[id]; !exists {
				state.invalidIDs[id] = true
			}
		}
	}
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
	selected := runtime.requirements.Requirements()
	answers := orderedRequirementAnswers(selected, func(role domain.Role) requirementSectionState {
		return runtime.requirementSections[role]
	}, "")
	reasons := make(map[string]domain.AssessmentReason, len(selected))
	for _, r := range selected {
		state := runtime.requirementSections[r.OwnerRole()]
		if _, ok := state.answers[r.ID()]; ok {
			continue
		}
		var reason domain.AssessmentReason
		switch {
		case state.invalidIDs[r.ID()] || state.sectionInvalid:
			reason = domain.AssessmentInvalidContent
		case state.present:
			reason = domain.AssessmentAnswerOmitted
		case !extraction:
			reason = domain.AssessmentExtractionDisabled
		case state.spent:
			reason = domain.AssessmentExtractionAllowanceSpent
		default:
			reason = domain.AssessmentAnswerOmitted
		}
		reasons[r.ID()] = reason
	}
	return validation.NormalizeRequirements(*runtime.requirements, answers, reasons, runtime.liveIdentity.SHA256(), false)
}

type requirementsCommit struct {
	onSuccess       func()
	onPendingRepair func()
}

func (commit requirementsCommit) apply(outcome AttemptOutcome) {
	if commit.onSuccess != nil && outcome.Succeeded() {
		commit.onSuccess()
		return
	}
	if commit.onPendingRepair != nil {
		if cond, failed := outcome.Condition(); failed && cond == AttemptConditionInvalidProviderOutput {
			commit.onPendingRepair()
		}
	}
}

func (runtime *ProviderInvocationRuntime) invokeRequirements(
	ctx context.Context,
	job InvocationJob,
	candidate, primary, stdout, stderr []byte,
	transport ports.ProviderOutputTransport,
	scope validation.ReviewValidationScope,
) (AttemptOutcome, domain.ParseState, domain.ValidationState) {
	outcome, parseState, validationState, commit := runtime.invokeRequirementsDeferred(ctx, job, candidate, primary, stdout, stderr, transport, scope)
	commit.apply(outcome)
	return outcome, parseState, validationState
}

func (runtime *ProviderInvocationRuntime) invokeRequirementsDeferred(
	ctx context.Context,
	job InvocationJob,
	candidate, primary, stdout, stderr []byte,
	transport ports.ProviderOutputTransport,
	scope validation.ReviewValidationScope,
) (AttemptOutcome, domain.ParseState, domain.ValidationState, requirementsCommit) {
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
	state := cloneRequirementSectionState(runtime.requirementSections[job.Role()])
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
	finalizeAccepted := func(outcome AttemptOutcome, acceptedFindings *validation.ValidatedReview) (AttemptOutcome, domain.ParseState, domain.ValidationState, requirementsCommit) {
		output, ok := outcome.Output()
		if !ok {
			return outcome, invParseState, invValidationState, requirementsCommit{}
		}
		// A structurally valid section with no invalid items owns its omissions.
		// Absent, section-invalid, or partial-invalid initial sections remain
		// eligible for the shared extraction slot under coordinator policy.
		output.assessmentPending = runtime.ownsRequirements(job.Role()) && job.Purpose() == domain.InvocationInitial && (!state.present || state.sectionInvalid || len(state.invalidIDs) > 0)

		var (
			nextFindings  validation.ValidatedReview
			storeFindings bool
			hasFindings   bool
			composed      validation.NormalizedRequirementsOutput
			hasComposed   bool
		)
		if !output.ReportsOnly() {
			if acceptedFindings != nil && !(job.Purpose() == domain.InvocationExtract && hasPrior && !prior.ReportsOnly()) {
				nextFindings = *acceptedFindings
				storeFindings = true
				hasFindings = true
			} else {
				runtime.mu.Lock()
				nextFindings, hasFindings = runtime.requirementFindings[job.Role()]
				runtime.mu.Unlock()
			}
			if state.present && !state.sectionInvalid && len(state.invalidIDs) == 0 {
				if !hasFindings {
					return runtimeCondition(job, AttemptConditionInternalInvariant), invParseState, invValidationState, requirementsCommit{}
				}
				roleAnswers := orderedRequirementAnswers(runtime.requirements.Requirements(), func(domain.Role) requirementSectionState {
					return state
				}, job.Role())
				var err error
				composed, err = validation.ComposeRequirementsOutput(nextFindings, roleAnswers, scope)
				if err != nil {
					return runtimeCondition(job, AttemptConditionInternalInvariant), invParseState, invValidationState, requirementsCommit{}
				}
				hasComposed = true
			}
		}

		result, err := NewAttemptOutcome(job, &output, nil)
		if err != nil {
			return runtimeCondition(job, AttemptConditionInternalInvariant), invParseState, invValidationState, requirementsCommit{}
		}

		outputSnapshot := output.clone()
		stateSnapshot := cloneRequirementSectionState(state)
		commit := requirementsCommit{
			onSuccess: func() {
				runtime.mu.Lock()
				if job.Purpose() == domain.InvocationInitial {
					runtime.pendingExtraction[job.AttemptID()] = InvocationExtractionInput{acceptedReport: outputSnapshot.ReportMarkdown(), reportTransport: transport}
				}
				runtime.requirementSections[job.Role()] = stateSnapshot
				runtime.requirementOutputs[job.Role()] = outputSnapshot
				if storeFindings {
					runtime.requirementFindings[job.Role()] = nextFindings
				}
				if hasComposed {
					runtime.normalizedRequirements[job.Role()] = composed
				}
				runtime.mu.Unlock()
			},
		}
		return result, invParseState, invValidationState, commit
	}
	fallbackReport := func(captureCandidate []byte, reportParse domain.ParseState, reportValidation domain.ValidationState) (AttemptOutcome, domain.ParseState, domain.ValidationState, requirementsCommit) {
		if job.Purpose() == domain.InvocationExtract && hasPrior {
			if err := runtime.capture(ctx, job, captureCandidate, stdout, stderr, false); err != nil {
				return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
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
				return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
			}
			return runtimeCondition(job, AttemptConditionArtifactFailure), invParseState, invValidationState, requirementsCommit{}
		}
		if !outcome.Succeeded() {
			// acceptFreeFormReport already executed runtime.capture.
			return outcome, invParseState, invValidationState, requirementsCommit{}
		}
		return finalizeAccepted(outcome, nil)
	}

	state.spent = state.spent || job.Purpose() == domain.InvocationRetry || repaired

	// Pure prose skips structured parsing and validation diagnostics entirely,
	// retaining ParseNotStarted / ValidationNotStarted on this invocation.
	if len(candidate) == 0 {
		reportParse, reportValidation := domain.ParseNotStarted, domain.ValidationNotStarted
		if repaired {
			reportParse = repair.parseState
			reportValidation = domain.ValidationRepairExhausted
		}
		return fallbackReport(nil, reportParse, reportValidation)
	}

	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParseStarted, "", "", "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
	}
	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticValidationStarted, "", "", "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
	}

	findings, section, present, findingsHasKey, parseErr := validation.SplitRequirementsResponse(candidate)
	if parseErr != nil {
		invParseState = diagnosticParseState(parseErr, candidate)
		invValidationState = domain.ValidationInvalid
		if repaired {
			invValidationState = domain.ValidationRepairExhausted
		}
		if err := runtime.emitValidationDiagnostics(ctx, job, parseErr, repaired); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
		}
		// Retry/repair already owns the shared additional slot. An extraction launch
		// itself is eligible transcription, not an unavailable-allowance condition.
		if job.Purpose() == domain.InvocationInitial {
			if plan := validation.RequirementsReformatPlan(candidate); plan != nil {
				// Structured candidate artifacts are bounded at 8 MiB while
				// requirements-bearing raw responses are unbounded in stdout.raw;
				// malformed responses have no bounded findings projection.
				if err := runtime.capture(ctx, job, nil, stdout, stderr, false); err != nil {
					return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
				}
				pendingInput := InvocationRepairInput{
					initial:         append([]byte(nil), candidate...),
					primaryReport:   append([]byte(nil), primary...),
					plan:            *plan,
					parseState:      invParseState,
					validationState: domain.ValidationInvalid,
				}
				return runtimeCondition(job, AttemptConditionInvalidProviderOutput), invParseState, invValidationState, requirementsCommit{
					onPendingRepair: func() {
						runtime.mu.Lock()
						runtime.pending[job.AttemptID()] = pendingInput
						runtime.mu.Unlock()
					},
				}
			}
		}
		if present && !state.present {
			state.present = true
			state.sectionInvalid = true
		}
		return fallbackReport(nil, invParseState, invValidationState)
	}

	invParseState = domain.ParseValid
	if err := runtime.emitInvocationDiagnostic(ctx, job, domain.RuntimeDiagnosticInfo, domain.DiagnosticOutputParsed, "", string(domain.ParseValid), "", "", 0, false, "", 0); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
	}

	// Candidate artifacts (candidate.*.json) remain bounded structured
	// publication members (ports.PublicationStructuredMemberMaxBytes), so omit
	// the structured candidate member when findings exceeds that bound while
	// preserving full unbounded output in stdout.raw and normalized
	// requirements/items/*.json.
	protectedReturn := func(condition AttemptCondition, cause domain.RuntimeDiagnosticCause, err error) (AttemptOutcome, domain.ParseState, domain.ValidationState, requirementsCommit) {
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
				return persisted, invParseState, invValidationState, requirementsCommit{}
			}
		}
		captureCandidate := boundedCandidate(findings)
		if repaired || (!findingsHasKey && !reject) {
			captureCandidate = nil
		}
		if captureErr := runtime.capture(ctx, job, captureCandidate, stdout, stderr, reject); captureErr != nil {
			if persisted := runtimePersistenceOutcome(job, captureErr); persistenceOverridesCondition(condition, persisted) {
				return persisted, invParseState, invValidationState, requirementsCommit{}
			}
		}
		return runtimeConditionWithCause(job, condition, cause), invParseState, invValidationState, requirementsCommit{}
	}

	var sectionErr error
	var decoded validation.ProviderRequirementsDecodeResult
	if present {
		decoded, sectionErr = validation.DecodeProviderRequirements(ctx, section, runtime.requirements.Requirements(), job.Role(), runtime.liveIdentity, runtime.verifier, runtime.liveVisuals, runtime.requirementsPath, runtime.requirements.SHA256())
		if condition, cause, protected := requirementsFailureCondition(ctx, sectionErr); protected {
			return protectedReturn(condition, cause, sectionErr)
		}
		mergeRequirementSectionState(&state, decoded, sectionErr)
	}
	reqDiagErr := sectionErr
	if reqDiagErr == nil {
		reqDiagErr = decoded.ItemErr
	}

	validated, _, findingsErr := runtime.validator.Validate(ctx, findings, scope)
	if findingsErr == nil {
		if err := runtime.emitDiscardedFieldDiagnostics(ctx, job, validated.DiscardedPaths()); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
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
					return persisted, invParseState, invValidationState, requirementsCommit{}
				}
			}
			captureCandidate := boundedCandidate(findings)
			if repaired {
				captureCandidate = nil
			}
			if captureErr := runtime.capture(ctx, job, captureCandidate, stdout, stderr, reject); captureErr != nil {
				if persisted := runtimePersistenceOutcome(job, captureErr); persistenceOverridesCondition(condition, persisted) {
					return persisted, invParseState, invValidationState, requirementsCommit{}
				}
			}
			return outcome, invParseState, invValidationState, requirementsCommit{}
		}
		var diagCause domain.RuntimeDiagnosticCause
		if findingsErr != nil {
			diagCause, _ = validation.RuntimeCause(findingsErr)
		} else if reqDiagErr != nil {
			diagCause, _ = validation.RuntimeCause(reqDiagErr)
		}
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
		}
		captureCandidate := boundedCandidate(findings)
		if repaired || !findingsHasKey {
			captureCandidate = nil
		}
		return fallbackReport(captureCandidate, invParseState, reportValidation)
	}
	if reqDiagErr == nil {
		invValidationState = domain.ValidationValid
		if repaired {
			invValidationState = domain.ValidationRepairedValid
		}
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, true, repaired, ""); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
		}
	} else {
		invValidationState = domain.ValidationInvalid
		if repaired {
			invValidationState = domain.ValidationRepairExhausted
		}
		diagCause, _ := validation.RuntimeCause(reqDiagErr)
		if err := runtime.emitRequirementsValidationTerminal(ctx, job, false, repaired, diagCause); err != nil {
			return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
		}
	}
	if err := runtime.capture(ctx, job, boundedCandidate(findings), stdout, stderr, false); err != nil {
		return runtimePersistenceOutcome(job, err), invParseState, invValidationState, requirementsCommit{}
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
	_, isReqSource := validation.RequirementsSourceFailure(err)
	if isReqSource {
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
	if sourceBoundary && selected.Class == domain.FailureInvalidOutput {
		if isReqSource || !validation.IsPureRequirementsCitationError(ctx, err) {
			return AttemptConditionInternalInvariant, "", true
		}
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
