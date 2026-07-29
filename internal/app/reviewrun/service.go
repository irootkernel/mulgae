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

	coreapp "github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Service is the provider-neutral root review composition boundary. It delegates
// scheduling, runtime validation/evidence, repair, and publication to their
// existing authoritative services.
type Service struct {
	dependencies Dependencies
	templates    review.TemplateSet
}

func NewService(dependencies Dependencies) (*Service, error) {
	if nilInterface(dependencies.Clock) || nilInterface(dependencies.IDs) || !dependencies.Build.Valid() || nilInterface(dependencies.RunAuthorityFactory) || dependencies.Validator == nil || nilInterface(dependencies.Publication) || dependencies.Templates.Common().ID() == "" || nilInterface(dependencies.Diagnostics) {
		return nil, fmt.Errorf("review run: invalid dependencies")
	}
	return &Service{dependencies: dependencies, templates: dependencies.Templates}, nil
}

// Execute captures input once, fails closed before provider observation on any
// admission failure, and returns only a coherent P2 publication result.
func (service *Service) Execute(ctx context.Context, request Request) (result Result, err error) {
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
	var diagnostics *runtimeDiagnosticLifecycle
	var terminalCoordinator review.CoordinatorResult
	defer func() {
		if err != nil && !cleanup.WorkspaceDrained() {
			if cleanupErr := cleanup.DrainAndAbort(ctx, workspaceAbortReason(err, abortReason)); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
		if diagnostics == nil {
			return
		}
		state, cause := runtimeDiagnosticTerminalDecision(ctx, result, err)
		p2URI, p2Err := runtimeDiagnosticP2URI(result, err)
		if p2Err != nil {
			err = errors.Join(err, p2Err)
		}
		finalized, finalizeErr := diagnostics.finalize(ctx, state, cause, p2URI, terminalCoordinator)
		if finalizeErr != nil {
			result = Result{}
			err = errors.Join(err, finalizeErr)
			return
		}
		if err != nil {
			projectURI, uriErr := ports.NewSafeRelativePath(".mulgae/" + finalized.URI().String())
			if uriErr != nil {
				result = Result{}
				err = errors.Join(err, diagnosticArtifactFailure("reviewrun.diagnostics.project_uri", uriErr))
				return
			}
			err = runtimeDiagnosticReferenceError(projectURI, err)
			return
		}
		result.diagnostic = finalized.URI()
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
	identity, err := service.issueRootRunIdentity(request.Selection)
	if err != nil {
		return Result{}, err
	}
	runIDs, err := newRunIdentityAuthority(service.dependencies.Clock, service.dependencies.IDs)
	if err != nil {
		return Result{}, err
	}
	diagnostics, err = openRuntimeDiagnosticLifecycle(ctx, service.dependencies.Diagnostics, request.ArtifactRoot, identity, request.Selection.Roles(), service.dependencies.Clock)
	if err != nil {
		return Result{}, err
	}
	cleanup.setDiagnostics(diagnostics)
	if input.Target().NoChange() {
		abortReason = ports.WorkspaceAbortPublicationFailure
		return service.publishNoChange(ctx, request, cleanup, input, target, identity, diagnostics)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if nilInterface(detector) || nilInterface(reader) {
		return Result{}, fmt.Errorf("review run: capture returned invalid authority")
	}
	abortReason = ports.WorkspaceAbortPlanningFailure
	if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationStarted, "qualification", "admit", ""); err != nil {
		return Result{}, err
	}
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
		for _, observation := range qualificationObservationsFromError(err) {
			if diagnosticErr := diagnostics.observeQualificationCandidate(ctx, observation); diagnosticErr != nil {
				return Result{}, diagnosticErr
			}
		}
		if diagnosticErr := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); diagnosticErr != nil {
			return Result{}, diagnosticErr
		}
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
		if diagnosticErr := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); diagnosticErr != nil {
			return Result{}, diagnosticErr
		}
		return Result{}, fmt.Errorf("review run: qualified run returned invalid authority")
	}
	observedCandidates := false
	if source, ok := qualified.(interface {
		QualificationObservations() []ProviderQualificationObservation
	}); ok {
		for _, observation := range source.QualificationObservations() {
			if err := diagnostics.observeQualificationCandidate(ctx, observation); err != nil {
				return Result{}, err
			}
			observedCandidates = true
		}
	}
	if !observedCandidates {
		if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationCandidateChecked, "qualification", "candidate", ""); err != nil {
			return Result{}, err
		}
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
		if _, qualificationRejected := ProviderQualificationFailuresFromError(err); qualificationRejected {
			if diagnosticErr := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationRejected, "qualification", "admit", ""); diagnosticErr != nil {
				return Result{}, diagnosticErr
			}
		}
		return Result{}, fmt.Errorf("review run: plan: %w", err)
	}
	if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticQualificationSucceeded, "qualification", "admit", ""); err != nil {
		return Result{}, err
	}
	plan = plan.clone()
	receipt, err := validatePlan(plan, request.Selection.Roles())
	if err != nil {
		return Result{}, err
	}
	if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticReviewPlanCreated, "planning", "plan", ""); err != nil {
		return Result{}, err
	}
	for _, assignment := range plan.Assignments {
		if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticAssignmentResolved, "planning", "assign", assignment.Role()); err != nil {
			return Result{}, err
		}
	}
	if err := diagnostics.observeRunEvent(ctx, domain.DiagnosticRunBudgetAccepted, "planning", "budget", ""); err != nil {
		return Result{}, err
	}
	source, err := newPromptSource(input, service.templates, invocationIDs{ids: runIDs, clock: service.dependencies.Clock}, func() (prompt.RoleTaskID, error) {
		value, err := runIDs.NewRoleTaskID(time.Time{})
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
	runtime, err := review.NewObservedProviderInvocationRuntimeWithWorkspaceAndDiagnostics(screenedProvider, source, lease, service.dependencies.Validator, verifier, diagnostics)
	if err != nil {
		return Result{}, fmt.Errorf("review run: runtime: %w", err)
	}
	var inventory []review.RuntimeArtifactInventory
	inventoryDrained := false
	drainRuntimeInventory := func() []review.RuntimeArtifactInventory {
		if !inventoryDrained {
			inventory = runtime.DrainRuntimeArtifactsForRun(identity.runID)
			inventoryDrained = true
		}
		return inventory
	}
	defer drainRuntimeInventory()
	coordinator, err := review.NewCoordinatorWithRuntimeDiagnostics(service.dependencies.Clock, runIDs, runtime, service.dependencies.Locker, plan.MaxLanes, receipt, diagnostics.Sink())
	if err != nil {
		return Result{}, fmt.Errorf("review run: coordinator: %w", err)
	}
	rootRun, err := newRootReviewRun(identity, target, plan.Assignments)
	if err != nil {
		return Result{}, err
	}
	coordinatorResult, err := coordinator.ExecuteRun(ctx, &rootRun, plan.Assignments, plan.Threshold, plan.Policy)
	terminalCoordinator = coordinatorResult
	if detectorErr := screenedProvider.DetectorError(); detectorErr != nil {
		return Result{}, fmt.Errorf("review run: detect provider packet: %w", detectorErr)
	}
	if screenedProvider.Blocked() {
		return Result{}, fmt.Errorf("review run: provider packet rejected")
	}
	if err != nil {
		return Result{}, fmt.Errorf("review run: execute: %w", err)
	}
	if failure := CoordinatorExecutionFailure(coordinatorResult); failure != nil {
		return Result{}, failure
	}
	inventory = drainRuntimeInventory()
	if err := cleanup.observe(ctx, domain.DiagnosticNamespaceDrainStarted, "provider_namespace", "drain"); err != nil {
		return Result{}, err
	}
	typedTerminal, drainErr := DrainRunAuthorityTerminal(ctx, qualified)
	if drainErr != nil {
		return Result{}, drainErr
	}
	cleanup.setProviderTerminal(typedTerminal.ProviderRunTerminalReceipt())
	if err := cleanup.observe(ctx, domain.DiagnosticNamespaceDrained, "provider_namespace", "drain"); err != nil {
		return Result{}, err
	}
	workspaceSnapshot := lease.Receipt()
	if !workspaceSnapshot.Valid() {
		return Result{}, fmt.Errorf("review run: workspace snapshot receipt is invalid")
	}

	completion, err := ports.NewWorkspaceCompletionEvidence(lease.WorkspaceSnapshotIdentity(), coordinatorResult.RunID().String(), cleanup.ProviderTerminalReceipt())
	if err != nil {
		return Result{}, fmt.Errorf("review run: construct workspace completion evidence: %w", err)
	}
	if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupStarted, "workspace", "cleanup"); err != nil {
		return Result{}, err
	}
	workspaceReceipt, releaseErr := lease.Release(completion)
	if releaseErr != nil {
		return Result{}, fmt.Errorf("review run: release workspace lease: %w", releaseErr)
	}
	if !workspaceReceiptMatchesCompletion(workspaceReceipt, completion) {
		return Result{}, fmt.Errorf("review run: workspace release receipt does not match completion evidence")
	}
	cleanup.setWorkspaceDrained()
	if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupCompleted, "workspace", "cleanup"); err != nil {
		return Result{}, err
	}

	if qualified.BuildIdentity() != service.dependencies.Build {
		return Result{}, fmt.Errorf("review run: qualified build identity does not match configured build")
	}
	publicationContext, err := productionPublicationContext(qualified.BuildIdentity(), input, workspaceSnapshot, typedTerminal, workspaceReceipt)
	if err != nil {
		return Result{}, fmt.Errorf("review run: production publication context: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(coordinatorResult, target, plan.Threshold, qualified.BuildIdentity().Version, qualified.BuildIdentity().ImmutableReference(), publicationContext, inventory)
	if err != nil {
		return Result{}, fmt.Errorf("review run: prepare publication candidate: %w", err)
	}
	published, err := service.publishNext(ctx, request.ArtifactRoot, candidate, diagnostics)
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
		providerFailure, err := NewProviderExecutionFailure(
			attempts[len(attempts)-1].Route().ProviderInstance(),
			summary.Role(),
			summary.ReasonCode(),
			summary.FailureClass(),
		)
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
		BuildCommit:              build.ImmutableReference(),
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
	diagnostics      *runtimeDiagnosticLifecycle
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

func (cleanup *ReviewRunCleanup) setDiagnostics(diagnostics *runtimeDiagnosticLifecycle) {
	cleanup.diagnostics = diagnostics
}

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
		if err := cleanup.observe(ctx, domain.DiagnosticNamespaceDrainStarted, "provider_namespace", "drain"); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if nilInterface(cleanup.provider) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("review run: terminal drain: qualified run is unavailable"))
		} else {
			terminal, err := DrainRunAuthorityTerminal(ctx, cleanup.provider)
			if err != nil {
				partial, ok := PartialProviderRunTerminalReceiptFromError(err)
				if ok {
					cleanup.terminal = partial
				}
				cleanupErr = errors.Join(cleanupErr, err)
			} else {
				cleanup.setProviderTerminal(terminal.ProviderRunTerminalReceipt())
				if err := cleanup.observe(ctx, domain.DiagnosticNamespaceDrained, "provider_namespace", "drain"); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			}
		}
	}
	if !cleanup.workspaceDrained {
		if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupStarted, "workspace", "cleanup"); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if !cleanup.terminal.Valid() {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("review run: workspace cleanup requires complete provider terminal evidence"))
		} else if err := abortWorkspace(cleanup.workspace, reason, cleanup.terminal); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			cleanup.workspaceDrained = true
			if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupCompleted, "workspace", "cleanup"); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
			}
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

func (cleanup *ReviewRunCleanup) observe(ctx context.Context, event domain.RuntimeDiagnosticEventCode, component string, operation string) error {
	if cleanup == nil || cleanup.diagnostics == nil {
		return nil
	}
	cleanup.diagnostics.mu.Lock()
	finalized := cleanup.diagnostics.finalized
	cleanup.diagnostics.mu.Unlock()
	if finalized {
		return nil
	}
	return cleanup.diagnostics.observeRunEvent(context.WithoutCancel(ctx), event, component, operation, "")
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

// DrainRunAuthorityTerminal retries one partial or failed terminal drain with a
// fresh bounded context. Root and child workflows must use the same cleanup
// proof policy so a transient first drain cannot change command semantics.
func DrainRunAuthorityTerminal(parent context.Context, qualified RunAuthority) (QualifiedRunTerminalReceipt, error) {
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
	identity rootRunIdentity,
	diagnostics *runtimeDiagnosticLifecycle,
) (_ Result, err error) {
	terminal := ports.NewEmptyProviderRunTerminalReceipt()
	sessionID, runID := identity.sessionID, identity.runID
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
	if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupStarted, "workspace", "cleanup"); err != nil {
		return Result{}, err
	}
	workspaceReceipt, releaseErr := cleanup.WorkspaceLease().Release(completion)
	if releaseErr != nil {
		return Result{}, fmt.Errorf("review run: release no-change workspace lease: %w", releaseErr)
	}
	cleanup.setWorkspaceDrained()
	if err := cleanup.observe(ctx, domain.DiagnosticWorkspaceCleanupCompleted, "workspace", "cleanup"); err != nil {
		return Result{}, err
	}
	if !workspaceReceiptMatchesCompletion(workspaceReceipt, completion) {
		return Result{}, fmt.Errorf("review run: no-change workspace release receipt does not match completion evidence")
	}
	candidate, err := publication.PrepareNoChangeCandidate(
		sessionID, runID, target, roles, domain.SeverityHigh, publication.NoChangeProvenance{
			BuildProduct:             service.dependencies.Build.Product,
			BuildVersion:             service.dependencies.Build.Version,
			BuildCommit:              service.dependencies.Build.ImmutableReference(),
			HasObjective:             input.HasObjective(),
			ObjectiveSHA256:          noChangeObjectiveDigest(input),
			SnapshotManifestSHA256:   workspaceSnapshot.ManifestSHA256(),
			WorkspaceTerminalReceipt: workspaceReceipt.ReceiptID(),
		},
	)
	if err != nil {
		return Result{}, fmt.Errorf("review run: prepare no-change publication candidate: %w", err)
	}
	published, err := service.publishNext(ctx, request.ArtifactRoot, candidate, diagnostics)
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

func (service *Service) publishNext(
	ctx context.Context,
	root ports.AnchoredRoot,
	candidate publication.PreparedCandidate,
	diagnostics *runtimeDiagnosticLifecycle,
) (publication.PublicationResult, error) {
	if observed, ok := service.dependencies.Publication.(publication.ObservedPublicationCommitter); ok {
		return observed.PublishNextObserved(ctx, root, candidate, diagnostics)
	}
	return service.dependencies.Publication.PublishNext(ctx, root, candidate)
}

type rootRunIdentity struct {
	sessionID domain.SessionID
	runID     domain.RunID
	startedAt time.Time
}

func (service *Service) issueRootRunIdentity(selection RunSelection) (rootRunIdentity, error) {
	now := service.dependencies.Clock.Now().UTC()
	if now.IsZero() {
		return rootRunIdentity{}, fmt.Errorf("review run: clock returned zero time")
	}
	sessionID, hasSession := selection.SessionID()
	if !hasSession {
		var err error
		sessionID, err = service.dependencies.IDs.NewSessionID(now)
		if err != nil {
			return rootRunIdentity{}, fmt.Errorf("review run: issue session ID: %w", err)
		}
	}
	runID, err := service.dependencies.IDs.NewRunID(now)
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
		var fallbackProvider *string
		if fallback, hasFallback := assignment.FallbackRoute(); hasFallback {
			provider := fallback.ProviderInstance()
			fallbackProvider = &provider
		}
		task, err := domain.NewRoleTask(role, assignment.Required(), assignment.PrimaryRoute().ProviderInstance(), fallbackProvider)
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
		return ports.ProviderExecutionObservation{}, fmt.Errorf("review run: packet screening provider is unavailable")
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
