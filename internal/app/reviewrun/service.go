package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	coreapp "github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func classifyReviewPreparationFailure(
	ctx context.Context,
	diagnostics *runtimeDiagnosticLifecycle,
	stage ReviewPreparationStage,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	var typed *domain.Failure
	if errors.As(cause, &typed) || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	failure := NewReviewPreparationFailure(stage, cause)
	if diagnostics == nil {
		return failure
	}
	if diagnosticErr := diagnostics.observePreparationFailure(ctx, stage); diagnosticErr != nil {
		return errors.Join(failure, diagnosticErr)
	}
	return failure
}

func classifyCoordinatorExecutionFailure(
	ctx context.Context,
	diagnostics *runtimeDiagnosticLifecycle,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	executionErr := fmt.Errorf("review run: execute: %w", cause)
	admissionCause, admissionFailed := review.CoordinatorAdmissionFailureFromError(cause)
	if !admissionFailed {
		return executionErr
	}
	directErr := fmt.Errorf("review run: coordinator admission: %w", admissionCause)
	var typed *domain.Failure
	if errors.As(directErr, &typed) || errors.Is(directErr, context.Canceled) || errors.Is(directErr, context.DeadlineExceeded) {
		return executionErr
	}
	classified := classifyReviewPreparationFailure(ctx, diagnostics, ReviewPreparationCoordinatorAdmission, directErr)
	return errors.Join(classified, executionErr)
}

// CoordinatorExecutionFailure applies the shared pre-publication terminal
// policy to root and child coordinator results. Operational provider failures
// remain publishable as incomplete coverage; authentication and closed fatal
// classes retain their typed execution authority instead of being flattened by
// a later publication validation error.
func CoordinatorExecutionFailure(result review.CoordinatorResult) error {
	if providers := coordinatorLoginRequiredProviders(result); len(providers) != 0 {
		failure, err := domain.NewFailure(
			"reviewrun.execute",
			domain.FailureAuthentication,
			"provider login required",
			ports.ErrProviderLoginRequired,
		)
		if err != nil {
			return err
		}
		return newProviderLoginRequiredError(providers, failure)
	}
	return coordinatorNonPublishableFailure(result)
}

func coordinatorNonPublishableFailure(result review.CoordinatorResult) error {
	summaries := result.RoleSummaries()
	classes := make([]domain.FailureClass, 0, len(summaries))
	for _, summary := range summaries {
		classes = append(classes, summary.FailureClass())
	}
	selected := reduceNonPublishableCoordinatorFailures(classes...)
	if selected == "" {
		return nil
	}
	providerFailures := make([]ProviderExecutionFailure, 0, len(summaries))
	for _, summary := range summaries {
		if !summary.FailureClass().Valid() {
			continue
		}
		attempts := summary.Attempts()
		if len(attempts) == 0 {
			continue
		}
		terminalAttempt := attempts[len(attempts)-1]
		providerFailure, err := providerExecutionFailureFromSummary(terminalAttempt, summary)
		if err != nil {
			return err
		}
		providerFailures = append(providerFailures, providerFailure)
	}
	cause := newProviderExecutionFailuresError(providerFailures)
	failure, err := domain.NewFailure(
		"reviewrun.execute",
		selected,
		"coordinator terminated with a non-publishable provider outcome",
		cause,
	)
	if err != nil {
		return fmt.Errorf("review run: invalid non-publishable coordinator failure")
	}
	return failure
}

func providerExecutionFailureFromSummary(attempt review.CoordinatorAttemptSummary, summary review.CoordinatorRoleSummary) (ProviderExecutionFailure, error) {
	if facts, ok := attempt.ProviderTimeoutFacts(); ok {
		return NewProviderExecutionFailureWithTimeoutFacts(
			attempt.Route().ProviderInstance(), summary.Role(), summary.ReasonCode(), summary.FailureClass(), facts,
		)
	}
	return NewProviderExecutionFailure(
		attempt.Route().ProviderInstance(), summary.Role(), summary.ReasonCode(), summary.FailureClass(),
	)
}

func reduceNonPublishableCoordinatorFailures(classes ...domain.FailureClass) domain.FailureClass {
	selected := domain.FailureClass("")
	selectedRank := -1
	for _, class := range classes {
		if !nonPublishableCoordinatorFailure(class) {
			continue
		}
		if rank := coreapp.FailurePrecedence(class); rank > selectedRank {
			selected = class
			selectedRank = rank
		}
	}
	return selected
}

func nonPublishableCoordinatorFailure(class domain.FailureClass) bool {
	switch class {
	case domain.FailureSecurityPolicy,
		domain.FailureConfiguration,
		domain.FailureArtifact,
		domain.FailureInternal,
		domain.FailureCancelled:
		return true
	default:
		return false
	}
}

func coordinatorLoginRequiredProviders(result review.CoordinatorResult) []string {
	roles := result.RoleSummaries()
	for _, role := range roles {
		switch role.FailureClass() {
		case domain.FailureInternal,
			domain.FailureSecurityPolicy,
			domain.FailureArtifact,
			domain.FailureCancelled,
			domain.FailureConfiguration:
			return nil
		}
	}
	providers := make([]string, 0, len(roles))
	for _, role := range roles {
		if role.ReasonCode() != string(review.AttemptConditionLoginRequired) {
			continue
		}
		attempts := role.Attempts()
		if len(attempts) == 0 {
			continue
		}
		providers = append(providers, attempts[len(attempts)-1].Route().ProviderInstance())
	}
	sort.Strings(providers)
	write := 0
	for _, provider := range providers {
		if provider == "" || (write > 0 && providers[write-1] == provider) {
			continue
		}
		providers[write] = provider
		write++
	}
	return providers[:write]
}

type terminalDrainCleanupError struct {
	cause    error
	owner    RunAuthority
	terminal ports.ProviderRunTerminalReceipt
}

func (err *terminalDrainCleanupError) Error() string {
	return fmt.Sprintf("review run: terminal drain could not be proven: %v", err.cause)
}

func (err *terminalDrainCleanupError) Unwrap() error { return err.cause }

func (err *terminalDrainCleanupError) CleanupOwner() RunAuthority { return err.owner }

func (err *terminalDrainCleanupError) PartialProviderRunTerminalReceipt() ports.ProviderRunTerminalReceipt {
	return err.terminal
}

// CleanupOwnerFromError exposes retained terminal-drain ownership so callers can
// retry cleanup without treating incomplete evidence as terminal proof.
func CleanupOwnerFromError(err error) (RunAuthority, bool) {
	var retained interface{ CleanupOwner() RunAuthority }
	if !errors.As(err, &retained) || nilInterface(retained.CleanupOwner()) {
		return nil, false
	}
	return retained.CleanupOwner(), true
}

// PartialProviderRunTerminalReceiptFromError exposes the last drain observation.
// The returned receipt is not terminal proof unless Valid reports true.
func PartialProviderRunTerminalReceiptFromError(err error) (ports.ProviderRunTerminalReceipt, bool) {
	var retained interface {
		PartialProviderRunTerminalReceipt() ports.ProviderRunTerminalReceipt
	}
	if !errors.As(err, &retained) {
		return ports.ProviderRunTerminalReceipt{}, false
	}
	return retained.PartialProviderRunTerminalReceipt(), true
}

// DrainRunAuthorityTerminal retries one partial or failed terminal drain with a
// fresh bounded context. Root and child workflows must use the same cleanup
// proof policy so a transient first drain cannot change command semantics.
func DrainRunAuthorityTerminal(parent context.Context, qualified RunAuthority) (QualifiedRunTerminalReceipt, error) {
	return drainRunAuthorityTerminal(context.WithoutCancel(parent), qualified)
}

func drainRunAuthorityTerminal(parent context.Context, qualified RunAuthority) (QualifiedRunTerminalReceipt, error) {
	var (
		lastErr  error
		terminal QualifiedRunTerminalReceipt
	)
	for attempt := 0; attempt < 2; attempt++ {
		if err := parent.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		drainCtx, cancel := context.WithTimeout(parent, time.Minute)
		next, err := qualified.DrainTerminal(drainCtx)
		cancel()
		if err == nil && next.Drained() {
			return next, nil
		}
		if err == nil {
			err = fmt.Errorf("review run: terminal drain returned incomplete receipt")
		}
		terminal, lastErr = next, err
	}
	return QualifiedRunTerminalReceipt{}, &terminalDrainCleanupError{
		cause:    lastErr,
		owner:    qualified,
		terminal: terminal.ProviderRunTerminalReceipt(),
	}
}

func publicationCandidateFailure(cause error) error {
	failure, err := domain.NewFailure("publication.candidate", domain.FailureArtifact, "publication candidate preparation failed", cause)
	if err != nil {
		return fmt.Errorf("review run: construct publication candidate failure: %w", err)
	}
	return failure
}

type rootRunIdentity struct {
	sessionID domain.SessionID
	runID     domain.RunID
	startedAt time.Time
}

func issueRootRunIdentity(clock ports.Clock, ids review.IdentityGenerator, selection RunSelection) (rootRunIdentity, error) {
	now := clock.Now().UTC()
	if now.IsZero() {
		return rootRunIdentity{}, fmt.Errorf("review run: clock returned zero time")
	}
	sessionID, hasSession := selection.SessionID()
	if !hasSession {
		var err error
		sessionID, err = ids.NewSessionID(now)
		if err != nil {
			return rootRunIdentity{}, fmt.Errorf("review run: issue session ID: %w", err)
		}
	}
	runID, err := ids.NewRunID(now)
	if err != nil {
		return rootRunIdentity{}, fmt.Errorf("review run: issue run ID: %w", err)
	}
	return rootRunIdentity{sessionID: sessionID, runID: runID, startedAt: now}, nil
}

func newRootReviewRun(identity rootRunIdentity, target domain.TargetIdentity, assignments []review.Assignment) (domain.Run, error) {
	byRole := make(map[domain.Role]review.Assignment, len(assignments))
	for _, assignment := range assignments {
		if !assignment.Role().Valid() || !assignment.PrimaryRoute().Valid() {
			return domain.Run{}, fmt.Errorf("review run: invalid root assignment")
		}
		if _, duplicate := byRole[assignment.Role()]; duplicate {
			return domain.Run{}, fmt.Errorf("review run: duplicate root assignment for role %q", assignment.Role())
		}
		byRole[assignment.Role()] = assignment
	}
	tasks := make([]domain.RoleTask, 0, len(assignments))
	for _, role := range domain.FixedRoleOrder() {
		assignment, ok := byRole[role]
		if !ok {
			continue
		}
		task, err := domain.NewRoleTask(role, assignment.Required(), assignment.PrimaryRoute().ProviderInstance())
		if err != nil {
			return domain.Run{}, fmt.Errorf("review run: construct root role %q: %w", role, err)
		}
		tasks = append(tasks, task)
	}
	if len(tasks) != len(assignments) {
		return domain.Run{}, fmt.Errorf("review run: root assignments must use fixed roles")
	}
	_, run, err := domain.NewReviewSession(identity.sessionID, identity.startedAt, identity.runID, target, tasks)
	if err != nil {
		return domain.Run{}, fmt.Errorf("review run: construct identified root run: %w", err)
	}
	return run, nil
}

type packetScreeningProvider struct {
	provider ports.ObservedReviewProvider
	detector ports.ReviewInputContentDetector

	mu          sync.Mutex
	blocked     bool
	detectorErr error
}

func (provider *packetScreeningProvider) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	if provider == nil || nilInterface(provider.provider) || nilInterface(provider.detector) {
		failure, _ := ports.NewProviderRuntimeError(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("review run: packet screening provider is unavailable"))
		return ports.ProviderExecutionObservation{}, failure
	}
	packet := invocation.PacketBytes()
	defer clear(packet)
	detection, err := provider.detector.DetectReviewInput(ctx, ports.ReviewInputPacket, invocation.SourceInvocationID(), packet)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: detect provider packet: %w", err)
		}
		provider.mu.Lock()
		provider.detectorErr = err
		provider.mu.Unlock()
		failure, _ := ports.NewProviderRuntimeError(domain.DiagnosticCauseObservationInvalid, fmt.Errorf("review run: detect provider packet: %w", err))
		return ports.ProviderExecutionObservation{}, failure
	}
	if !detection.Valid() {
		invalid := fmt.Errorf("review run: detector returned invalid packet detection")
		provider.mu.Lock()
		provider.detectorErr = invalid
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, errors.Join(ports.ErrProviderPacketSecurity, invalid)
	}
	if detection.Verdict() != ports.ReviewInputClean {
		provider.mu.Lock()
		provider.blocked = true
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, ports.ErrProviderPacketSecurity
	}
	return provider.provider.Observe(ctx, invocation)
}

func (provider *packetScreeningProvider) Blocked() bool {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.blocked
}
func (provider *packetScreeningProvider) DetectorError() error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.detectorErr
}

// invocationIDs adapts the existing time-based issuer to the prompt issuer.
type invocationIDs struct {
	ids   review.IdentityGenerator
	clock interface{ Now() time.Time }
}

func (issuer invocationIDs) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	value, err := issuer.ids.NewSourceInvocationID(issuer.clock.Now())
	if err != nil {
		return prompt.SourceInvocationID{}, err
	}
	return prompt.ParseSourceInvocationID(value)
}
func (issuer invocationIDs) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	value, err := issuer.ids.NewExecutionInvocationID(issuer.clock.Now())
	if err != nil {
		return prompt.ExecutionInvocationID{}, err
	}
	return prompt.ParseExecutionInvocationID(value)
}

// providerOutputStagingLocator returns the adapter-owned staging authority when
// the qualified provider registry implements it. A provider without that
// authority resolves no destination, so every launch keeps the stdout transport
// and legacy or fake providers are unaffected.
func providerOutputStagingLocator(provider ports.ObservedReviewProvider) ports.ProviderOutputStagingLocator {
	if nilInterface(provider) {
		return nil
	}
	locator, ok := provider.(ports.ProviderOutputStagingLocator)
	if !ok || nilInterface(locator) {
		return nil
	}
	return locator
}
