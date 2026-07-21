package reviewrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// Service is the provider-neutral root review composition boundary. It delegates
// scheduling, runtime validation/evidence, repair, and publication to their
// existing authoritative services.
type Service struct {
	dependencies Dependencies
	templates    review.TemplateSet
}

func NewService(dependencies Dependencies) (*Service, error) {
	if nilInterface(dependencies.Clock) || nilInterface(dependencies.IDs) || !dependencies.Build.Valid() || nilInterface(dependencies.RunAuthorityFactory) || dependencies.Validator == nil || nilInterface(dependencies.Publication) || dependencies.Templates.Common().ID() == "" {
		return nil, fmt.Errorf("review run: invalid dependencies")
	}
	return &Service{dependencies: dependencies, templates: dependencies.Templates}, nil
}

// Execute captures input once, fails closed before provider observation on any
// admission failure, and returns only a coherent P2 publication result.
func (service *Service) Execute(ctx context.Context, request Request) (_ Result, err error) {
	if service == nil {
		return Result{}, fmt.Errorf("review run: nil service")
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("review run: context is required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if nilInterface(request.InputSource) || !request.ProjectRoot.Valid() || !request.ArtifactRoot.Valid() || !request.Selection.Valid() {
		return Result{}, fmt.Errorf("review run: malformed request")
	}
	captured, err := request.InputSource.Capture(ctx, request)
	if err != nil {
		return Result{}, fmt.Errorf("review run: capture immutable input: %w", err)
	}
	lease := captured.WorkspaceLease()
	if nilInterface(lease) {
		return Result{}, fmt.Errorf("review run: capture returned invalid authority")
	}
	cleanup := newReviewRunCleanup(lease)
	abortReason := ports.WorkspaceAbortCaptureFailure
	defer func() {
		if err == nil || cleanup.WorkspaceDrained() {
			return
		}
		if cleanupErr := cleanup.DrainAndAbort(ctx, workspaceAbortReason(err, abortReason)); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	input := captured.Input()

	reader := captured.ImmutableTargetReader()
	detector := captured.PacketDetector()
	if !input.Target().Valid() {
		return Result{}, fmt.Errorf("review run: capture returned invalid authority")
	}
	target := input.Target().Identity()
	if !service.dependencies.Build.Valid() {
		return Result{}, fmt.Errorf("review run: invalid build identity")
	}
	if input.Target().NoChange() {
		abortReason = ports.WorkspaceAbortPublicationFailure
		return service.publishNoChange(ctx, request, cleanup, input, target)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if nilInterface(detector) || nilInterface(reader) {
		return Result{}, fmt.Errorf("review run: capture returned invalid authority")
	}
	abortReason = ports.WorkspaceAbortPlanningFailure
	qualified, err := service.dependencies.RunAuthorityFactory.NewQualifiedRun(ctx, captured, request.Selection)
	if !nilInterface(qualified) {
		cleanup.setProviderOwner(qualified)
	}
	if constructionOwner, ok := CleanupOwnerFromError(err); ok {
		cleanup.setProviderOwner(constructionOwner)
	} else if constructionOwner, ok := RunAuthorityFromError(err); ok {
		cleanup.setProviderOwner(constructionOwner)
	}
	if err != nil {
		constructionTerminal, hasConstructionTerminal := ProviderRunTerminalReceiptFromError(err)
		if partialTerminal, hasPartialTerminal := PartialProviderRunTerminalReceiptFromError(err); hasPartialTerminal {
			cleanup.terminal = partialTerminal
			if partialTerminal.Valid() {
				constructionTerminal, hasConstructionTerminal = partialTerminal, true
			}
		}
		if !hasConstructionTerminal || !constructionTerminal.Valid() {
			return Result{}, errors.Join(
				fmt.Errorf("review run: qualify run: %w", err),
				fmt.Errorf("review run: missing terminal cleanup evidence after authority construction"),
			)
		}
		cleanup.setProviderTerminal(constructionTerminal)
		return Result{}, fmt.Errorf("review run: qualify run: %w", err)
	}
	if nilInterface(qualified) || nilInterface(qualified.Provider()) || nilInterface(qualified.Planner()) || !qualified.BuildIdentity().Valid() {
		return Result{}, fmt.Errorf("review run: qualified run returned invalid authority")
	}

	verifier, err := evidence.NewVerifier(reader)
	if err != nil {
		return Result{}, fmt.Errorf("review run: immutable evidence verifier: %w", err)
	}
	planningRequest, err := NewPlanningRequest(input, request.Selection.Roles())
	if err != nil {
		return Result{}, err
	}
	plan, err := qualified.Planner().Plan(ctx, planningRequest)
	if err != nil {
		return Result{}, fmt.Errorf("review run: plan: %w", err)
	}
	plan = plan.clone()
	receipt, err := validatePlan(plan, request.Selection.Roles())
	if err != nil {
		return Result{}, err
	}
	source, err := newPromptSource(input, service.templates, invocationIDs{ids: service.dependencies.IDs, clock: service.dependencies.Clock}, func() (prompt.RoleTaskID, error) {
		value, err := service.dependencies.IDs.NewRoleTaskID(service.dependencies.Clock.Now())
		if err != nil {
			return prompt.RoleTaskID{}, err
		}
		return prompt.ParseRoleTaskID(value)
	})
	if err != nil {
		return Result{}, err
	}
	abortReason = ports.WorkspaceAbortExecutionFailure
	screenedProvider := &packetScreeningProvider{provider: qualified.Provider(), detector: detector}
	runtime, err := review.NewObservedProviderInvocationRuntimeWithWorkspace(screenedProvider, source, lease, service.dependencies.Validator, verifier)
	if err != nil {
		return Result{}, fmt.Errorf("review run: runtime: %w", err)
	}
	coordinator, err := review.NewCoordinator(service.dependencies.Clock, service.dependencies.IDs, runtime, service.dependencies.Locker, plan.MaxLanes, receipt)
	if err != nil {
		return Result{}, fmt.Errorf("review run: coordinator: %w", err)
	}
	coordinatorResult, err := coordinator.Execute(ctx, target, plan.Assignments, plan.Threshold, plan.Policy)
	if detectorErr := screenedProvider.DetectorError(); detectorErr != nil {
		return Result{}, fmt.Errorf("review run: detect provider packet: %w", detectorErr)
	}
	if screenedProvider.Blocked() {
		return Result{}, fmt.Errorf("review run: provider packet rejected")
	}
	if err != nil {
		return Result{}, fmt.Errorf("review run: execute: %w", err)
	}
	inventory := runtime.DrainRuntimeArtifactsForRun(coordinatorResult.RunID())
	typedTerminal, drainErr := drainQualifiedTerminal(ctx, qualified)
	if drainErr != nil {
		return Result{}, drainErr
	}
	cleanup.setProviderTerminal(typedTerminal.ProviderRunTerminalReceipt())
	workspaceSnapshot := lease.Receipt()
	if !workspaceSnapshot.Valid() {
		return Result{}, fmt.Errorf("review run: workspace snapshot receipt is invalid")
	}

	completion, err := ports.NewWorkspaceCompletionEvidence(lease.WorkspaceSnapshotIdentity(), coordinatorResult.RunID().String(), cleanup.ProviderTerminalReceipt())
	if err != nil {
		return Result{}, fmt.Errorf("review run: construct workspace completion evidence: %w", err)
	}
	workspaceReceipt, releaseErr := lease.Release(completion)
	if releaseErr != nil {
		return Result{}, fmt.Errorf("review run: release workspace lease: %w", releaseErr)
	}
	if !workspaceReceiptMatchesCompletion(workspaceReceipt, completion) {
		return Result{}, fmt.Errorf("review run: workspace release receipt does not match completion evidence")
	}
	cleanup.setWorkspaceDrained()

	if qualified.BuildIdentity() != service.dependencies.Build {
		return Result{}, fmt.Errorf("review run: qualified build identity does not match configured build")
	}
	publicationContext, err := productionPublicationContext(qualified.BuildIdentity(), input, workspaceSnapshot, typedTerminal, workspaceReceipt)
	if err != nil {
		return Result{}, fmt.Errorf("review run: production publication context: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(coordinatorResult, target, plan.Threshold, qualified.BuildIdentity().Version, qualified.BuildIdentity().Commit, publicationContext, inventory)
	if err != nil {
		return Result{}, fmt.Errorf("review run: prepare publication candidate: %w", err)
	}
	published, err := service.dependencies.Publication.PublishNext(ctx, request.ArtifactRoot, candidate)
	if err != nil {
		return Result{}, fmt.Errorf("review run: publish: %w", err)
	}
	if published.Decision().Authority() != domain.PublicationAuthorityP2 {
		return Result{}, fmt.Errorf("review run: publication did not reach P2")
	}
	final, hasFinal := published.Final()
	snapshot, hasSnapshot := published.Snapshot()
	exit, hasExit := published.TerminalExit()
	if !hasFinal || !hasSnapshot || !hasExit {
		return Result{}, fmt.Errorf("review run: incomplete P2 publication authority")
	}
	return newResult(coordinatorResult.SessionID(), coordinatorResult.RunID(), coordinatorResult, final, snapshot, exit)
}
func productionPublicationContext(
	build BuildIdentity,
	input ImmutableReviewInput,
	snapshot ports.WorkspaceSnapshotReceipt,
	terminal QualifiedRunTerminalReceipt,
	workspace ports.WorkspaceTerminalReceipt,
) (publication.RunPublicationContext, error) {
	if !build.Valid() || !snapshot.Valid() || !terminal.Drained() || !workspace.Valid() {
		return publication.RunPublicationContext{}, fmt.Errorf("incomplete production provenance")
	}
	providers := terminal.Providers()
	provenanceProviders := make([]publication.ProductionProviderProvenance, len(providers))
	for index, provider := range providers {
		identity := provider.Identity()
		provenanceProviders[index] = publication.ProductionProviderProvenance{
			Family:                    string(identity.Family),
			Instance:                  identity.Instance,
			Version:                   identity.Version,
			Executable:                identity.Executable,
			ExecutableSHA256:          identity.ExecutableSHA256,
			Launcher:                  identity.Launcher,
			LauncherSHA256:            identity.LauncherSHA256,
			ProfileGeneration:         identity.ProfileGeneration,
			AdapterProfile:            identity.AdapterProfile,
			QualificationReceiptIDs:   provider.QualificationReceiptIDs(),
			PacketTransportReceiptIDs: provider.PacketTransportReceiptIDs(),
			NamespaceTerminalReceipt:  provider.NamespaceTerminalReceiptID(),
		}
	}
	provenance := publication.ProductionReviewProvenance{
		BuildProduct:             build.Product,
		BuildVersion:             build.Version,
		BuildCommit:              build.Commit,
		HasObjective:             input.HasObjective(),
		SnapshotManifestSHA256:   snapshot.ManifestSHA256(),
		Providers:                provenanceProviders,
		WorkspaceTerminalReceipt: workspace.ReceiptID(),
	}
	if provenance.HasObjective {
		digest := sha256.Sum256(input.Objective())
		provenance.ObjectiveSHA256 = "sha256:" + hex.EncodeToString(digest[:])
	}
	return publication.NewProductionPublicationContext(provenance)
}

func noChangeObjectiveDigest(input ImmutableReviewInput) string {
	if !input.HasObjective() {
		return ""
	}
	digest := sha256.Sum256(input.Objective())
	return "sha256:" + hex.EncodeToString(digest[:])
}

func workspaceReceiptMatchesCompletion(receipt ports.WorkspaceTerminalReceipt, completion ports.WorkspaceCompletionEvidence) bool {
	if !receipt.Valid() ||
		receipt.WorkspaceSnapshotIdentity() != completion.WorkspaceSnapshotIdentity() ||
		receipt.RunID() != completion.RunID() {
		return false
	}
	return providerTerminalMatches(receipt.ProviderRunTerminalReceipt(), completion.ProviderRunTerminalReceipt())
}

func providerTerminalMatches(left, right ports.ProviderRunTerminalReceipt) bool {
	if left.NoNamespaces() != right.NoNamespaces() {
		return false
	}
	leftReceipts, rightReceipts := left.NamespaceReceipts(), right.NamespaceReceipts()
	if len(leftReceipts) != len(rightReceipts) {
		return false
	}
	for index := range leftReceipts {
		if leftReceipts[index] != rightReceipts[index] {
			return false
		}
	}
	return true
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

// ReviewRunCleanup retains the exact provider and workspace cleanup authorities
// until both terminal operations have conclusively succeeded.
type ReviewRunCleanup struct {
	provider         RunAuthority
	workspace        ports.WorkspaceSnapshotLease
	terminal         ports.ProviderRunTerminalReceipt
	providerDrained  bool
	workspaceDrained bool
}

func newReviewRunCleanup(workspace ports.WorkspaceSnapshotLease) *ReviewRunCleanup {
	return &ReviewRunCleanup{
		workspace:       workspace,
		terminal:        ports.NewEmptyProviderRunTerminalReceipt(),
		providerDrained: true,
	}
}

func (cleanup *ReviewRunCleanup) setProviderOwner(provider RunAuthority) {
	cleanup.provider = provider
	cleanup.terminal = ports.ProviderRunTerminalReceipt{}
	cleanup.providerDrained = false
}

func (cleanup *ReviewRunCleanup) setProviderTerminal(terminal ports.ProviderRunTerminalReceipt) {
	cleanup.terminal = terminal
	cleanup.providerDrained = terminal.Valid()
}

func (cleanup *ReviewRunCleanup) setWorkspaceDrained() { cleanup.workspaceDrained = true }

func (cleanup *ReviewRunCleanup) ProviderOwner() RunAuthority { return cleanup.provider }

func (cleanup *ReviewRunCleanup) WorkspaceLease() ports.WorkspaceSnapshotLease {
	return cleanup.workspace
}

func (cleanup *ReviewRunCleanup) ProviderDrained() bool { return cleanup.providerDrained }

func (cleanup *ReviewRunCleanup) WorkspaceDrained() bool { return cleanup.workspaceDrained }

func (cleanup *ReviewRunCleanup) ProviderTerminalReceipt() ports.ProviderRunTerminalReceipt {
	return cleanup.terminal
}

func (cleanup *ReviewRunCleanup) DrainAndAbort(ctx context.Context, reason ports.WorkspaceAbortReason) error {
	if cleanup == nil || nilInterface(cleanup.workspace) {
		return fmt.Errorf("review run: cleanup state is unavailable")
	}

	var cleanupErr error
	if !cleanup.providerDrained {
		if nilInterface(cleanup.provider) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("review run: terminal drain: qualified run is unavailable"))
		} else {
			terminal, err := drainQualifiedTerminal(ctx, cleanup.provider)
			if err != nil {
				partial, ok := PartialProviderRunTerminalReceiptFromError(err)
				if ok {
					cleanup.terminal = partial
				}
				cleanupErr = errors.Join(cleanupErr, err)
			} else {
				cleanup.setProviderTerminal(terminal.ProviderRunTerminalReceipt())
			}
		}
	}
	if !cleanup.workspaceDrained {
		if !cleanup.terminal.Valid() {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("review run: workspace cleanup requires complete provider terminal evidence"))
		} else if err := abortWorkspace(cleanup.workspace, reason, cleanup.terminal); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			cleanup.workspaceDrained = true
		}
	}
	if cleanupErr == nil && cleanup.providerDrained && cleanup.workspaceDrained {
		return nil
	}
	if cleanupErr == nil {
		cleanupErr = fmt.Errorf("review run: cleanup remained unresolved")
	}
	return &reviewRunCleanupError{cause: cleanupErr, cleanup: cleanup}
}

type reviewRunCleanupError struct {
	cause   error
	cleanup *ReviewRunCleanup
}

func (err *reviewRunCleanupError) Error() string {
	return fmt.Sprintf("review run: composite cleanup could not be proven: %v", err.cause)
}

func (err *reviewRunCleanupError) Unwrap() error { return err.cause }

func (err *reviewRunCleanupError) CleanupOwner() RunAuthority { return err.cleanup.ProviderOwner() }

func (err *reviewRunCleanupError) CleanupState() *ReviewRunCleanup { return err.cleanup }

// CleanupStateFromError exposes the retained composite cleanup authority for
// retry. It is terminal proof only when both cleanup operations are drained.
func CleanupStateFromError(err error) (*ReviewRunCleanup, bool) {
	var retained interface{ CleanupState() *ReviewRunCleanup }
	if !errors.As(err, &retained) || retained.CleanupState() == nil {
		return nil, false
	}
	return retained.CleanupState(), true
}

func drainQualifiedTerminal(parent context.Context, qualified RunAuthority) (QualifiedRunTerminalReceipt, error) {
	var (
		lastErr  error
		terminal QualifiedRunTerminalReceipt
	)
	for attempt := 0; attempt < 2; attempt++ {
		drainCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Minute)
		terminal, lastErr = qualified.DrainTerminal(drainCtx)
		cancel()
		if lastErr == nil && terminal.Drained() {
			return terminal, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("review run: terminal drain returned incomplete receipt")
		}
	}
	return QualifiedRunTerminalReceipt{}, &terminalDrainCleanupError{
		cause:    lastErr,
		owner:    qualified,
		terminal: terminal.ProviderRunTerminalReceipt(),
	}
}

func abortWorkspace(lease ports.WorkspaceSnapshotLease, reason ports.WorkspaceAbortReason, terminal ports.ProviderRunTerminalReceipt) error {
	evidence, err := ports.NewWorkspaceAbortEvidence(lease.WorkspaceSnapshotIdentity(), reason, terminal)
	if err != nil {
		return fmt.Errorf("review run: construct workspace abort evidence: %w", err)
	}
	if err := lease.Abort(evidence); err != nil {
		return fmt.Errorf("review run: abort workspace lease: %w", err)
	}
	return nil
}

func workspaceAbortReason(err error, fallback ports.WorkspaceAbortReason) ports.WorkspaceAbortReason {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ports.WorkspaceAbortCancellation
	}
	var failure *domain.Failure
	if errors.As(err, &failure) && failure.Class() == domain.FailureSecurityPolicy {
		return ports.WorkspaceAbortSecurityViolation
	}
	return fallback
}

func (service *Service) publishNoChange(
	ctx context.Context,
	request Request,
	cleanup *ReviewRunCleanup,
	input ImmutableReviewInput,
	target domain.TargetIdentity,
) (_ Result, err error) {
	terminal := ports.NewEmptyProviderRunTerminalReceipt()
	now := service.dependencies.Clock.Now().UTC()
	if now.IsZero() {
		return Result{}, fmt.Errorf("review run: clock returned zero time")
	}
	sessionID, hasSession := request.Selection.SessionID()
	if !hasSession {
		sessionID, err = service.dependencies.IDs.NewSessionID(now)
		if err != nil {
			return Result{}, fmt.Errorf("review run: issue no-change session ID: %w", err)
		}
	}
	runID, err := service.dependencies.IDs.NewRunID(now)
	if err != nil {
		return Result{}, fmt.Errorf("review run: issue no-change run ID: %w", err)
	}
	roles := request.Selection.Roles()
	order := make(map[domain.Role]int, len(domain.FixedRoleOrder()))
	for index, role := range domain.FixedRoleOrder() {
		order[role] = index
	}
	sort.Slice(roles, func(left, right int) bool { return order[roles[left]] < order[roles[right]] })
	completion, err := ports.NewWorkspaceCompletionEvidence(cleanup.WorkspaceLease().WorkspaceSnapshotIdentity(), runID.String(), terminal)
	if err != nil {
		return Result{}, fmt.Errorf("review run: construct no-change workspace completion evidence: %w", err)
	}
	workspaceSnapshot := cleanup.WorkspaceLease().Receipt()
	if !workspaceSnapshot.Valid() {
		return Result{}, fmt.Errorf("review run: no-change workspace snapshot receipt is invalid")
	}
	workspaceReceipt, releaseErr := cleanup.WorkspaceLease().Release(completion)
	if releaseErr != nil {
		return Result{}, fmt.Errorf("review run: release no-change workspace lease: %w", releaseErr)
	}
	cleanup.setWorkspaceDrained()
	if !workspaceReceiptMatchesCompletion(workspaceReceipt, completion) {
		return Result{}, fmt.Errorf("review run: no-change workspace release receipt does not match completion evidence")
	}
	candidate, err := publication.PrepareNoChangeCandidate(
		sessionID, runID, target, roles, domain.SeverityHigh, publication.NoChangeProvenance{
			BuildProduct:             service.dependencies.Build.Product,
			BuildVersion:             service.dependencies.Build.Version,
			BuildCommit:              service.dependencies.Build.Commit,
			HasObjective:             input.HasObjective(),
			ObjectiveSHA256:          noChangeObjectiveDigest(input),
			SnapshotManifestSHA256:   workspaceSnapshot.ManifestSHA256(),
			WorkspaceTerminalReceipt: workspaceReceipt.ReceiptID(),
		},
	)
	if err != nil {
		return Result{}, fmt.Errorf("review run: prepare no-change publication candidate: %w", err)
	}
	published, err := service.dependencies.Publication.PublishNext(ctx, request.ArtifactRoot, candidate)
	if err != nil {
		return Result{}, fmt.Errorf("review run: publish: %w", err)
	}
	if published.Decision().Authority() != domain.PublicationAuthorityP2 {
		return Result{}, fmt.Errorf("review run: publication did not reach P2")
	}
	final, hasFinal := published.Final()
	snapshot, hasSnapshot := published.Snapshot()
	exit, hasExit := published.TerminalExit()
	if !hasFinal || !hasSnapshot || !hasExit {
		return Result{}, fmt.Errorf("review run: incomplete P2 publication authority")
	}
	return newResult(sessionID, runID, review.CoordinatorResult{}, final, snapshot, exit)
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
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: packet screening provider is unavailable")
	}
	packet := invocation.PacketBytes()
	defer clear(packet)
	detection, err := provider.detector.DetectReviewInput(ctx, ports.ReviewInputPacket, invocation.SourceInvocationID(), packet)
	if err != nil {
		provider.mu.Lock()
		provider.detectorErr = err
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: detect provider packet: %w", err)
	}
	if !detection.Valid() {
		invalid := fmt.Errorf("review run: detector returned invalid packet detection")
		provider.mu.Lock()
		provider.detectorErr = invalid
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, invalid
	}
	if detection.Verdict() != ports.ReviewInputClean {
		provider.mu.Lock()
		provider.blocked = true
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: provider packet rejected")
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
