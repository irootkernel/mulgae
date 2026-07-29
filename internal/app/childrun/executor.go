// Package childrun executes and publishes supplied child review runs.
package childrun

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ExecutorConfig contains the immutable review and publication authority for
// child review runs. The coordinator already owns the corresponding prompt,
// assignment budget, and provider execution authority.
type ExecutorConfig struct {
	Assignments       []review.Assignment
	SeverityThreshold domain.Severity
	Policy            *domain.CIPolicy
	MulgaeVersion     string
	MulgaeCommit      string
	Diagnostics       ports.RuntimeDiagnosticSinkFactory
	Clock             ports.Clock
}

// Executor is the production delta child executor. It deliberately accepts a
// supplied domain.Run rather than minting or substituting child identity.
type Executor struct {
	coordinator  *review.Coordinator
	runtime      *review.ProviderInvocationRuntime
	publisher    *publication.Service
	artifactRoot ports.AnchoredRoot
	config       ExecutorConfig
	diagnostics  *childDiagnosticRegistry
}

// NewExecutor constructs a child executor with all execution and publication
// authority supplied explicitly.
func NewExecutor(
	coordinator *review.Coordinator,
	runtime *review.ProviderInvocationRuntime,
	publisher *publication.Service,
	artifactRoot ports.AnchoredRoot,
	config ExecutorConfig,
) (*Executor, error) {
	if coordinator == nil {
		return nil, fmt.Errorf("child executor: coordinator is required")
	}
	if runtime == nil {
		return nil, fmt.Errorf("child executor: provider invocation runtime is required")
	}
	if publisher == nil {
		return nil, fmt.Errorf("child executor: publication service is required")
	}
	if !artifactRoot.Valid() {
		return nil, fmt.Errorf("child executor: artifact root is invalid")
	}
	if len(config.Assignments) == 0 {
		return nil, fmt.Errorf("child executor: assignments are required")
	}
	if !config.SeverityThreshold.Valid() {
		return nil, fmt.Errorf("child executor: severity threshold is invalid")
	}
	if config.MulgaeVersion == "" || config.MulgaeCommit == "" {
		return nil, fmt.Errorf("child executor: publication identity is incomplete")
	}
	registry := &childDiagnosticRegistry{}
	if config.Diagnostics != nil {
		if config.Clock == nil {
			return nil, fmt.Errorf("child executor: diagnostic clock is required")
		}
		if err := runtime.BindRuntimeDiagnostics(registry); err != nil {
			return nil, err
		}
	}
	return &Executor{
		coordinator: coordinator, runtime: runtime, publisher: publisher, artifactRoot: artifactRoot,
		diagnostics: registry,
		config: ExecutorConfig{
			Assignments: append([]review.Assignment(nil), config.Assignments...), SeverityThreshold: config.SeverityThreshold,
			Policy: config.Policy, MulgaeVersion: config.MulgaeVersion, MulgaeCommit: config.MulgaeCommit, Diagnostics: config.Diagnostics, Clock: config.Clock,
		},
	}, nil
}

func (executor *Executor) openDiagnostics(ctx context.Context, run domain.Run) (*childDiagnosticLifecycle, error) {
	lifecycle, err := openChildDiagnostics(ctx, executor.config.Diagnostics, executor.artifactRoot, executor.config.Clock, run)
	if err != nil || lifecycle == nil {
		return lifecycle, err
	}
	if err := executor.diagnostics.bind(run.ID(), lifecycle.sink); err != nil {
		return nil, err
	}
	if err := executor.coordinator.BindRuntimeDiagnostics(lifecycle.sink); err != nil {
		return nil, err
	}
	return lifecycle, nil
}

// ExecuteDelta executes exactly request.Run, binds only that run's runtime
// inventory, and returns a URI derived from the P2 publication receipt.
func (executor *Executor) ExecuteDelta(ctx context.Context, request delta.ChildRequest) (_ delta.ExecutionResult, retErr error) {
	if executor == nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: nil executor")
	}
	if ctx == nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: context is required")
	}
	if err := ctx.Err(); err != nil {
		return delta.ExecutionResult{}, err
	}
	run := request.Run
	if run.Type() != domain.RunTypeDelta {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta request requires a delta run")
	}
	if run.Target() != request.CurrentTarget.Identity() {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta run target differs from supplied current target")
	}
	lifecycle, err := executor.openDiagnostics(ctx, run)
	if err != nil {
		return delta.ExecutionResult{}, err
	}
	var diagnosticP2 ports.SafeRelativePath
	defer func() {
		if finishErr := lifecycle.finish(ctx, retErr, diagnosticP2); finishErr != nil {
			retErr = finishErr
		}
	}()
	parent, hasParent := run.ParentRunID()
	source, hasSource := run.SourceRunID()
	if !hasParent || !hasSource || parent != source || request.SourceReviewID.String() == "" {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta lineage differs from supplied authority")
	}

	assignments, err := assignmentsForRun(run, executor.config.Assignments)
	if err != nil {
		return delta.ExecutionResult{}, err
	}
	run, err = deltaRunWithConfiguredAssignments(run, assignments)
	if err != nil {
		return delta.ExecutionResult{}, err
	}
	result, err := executor.coordinator.ExecuteDeltaRun(ctx, &run, assignments, executor.config.SeverityThreshold, executor.config.Policy, review.DeltaInvocationMaterial{
		SourceRunID:           source,
		SourceTarget:          request.SourceTarget.Bytes(),
		SourceTargetIdentity:  request.SourceTarget.Identity(),
		CurrentTarget:         request.CurrentTarget.Bytes(),
		CurrentTargetIdentity: request.CurrentTarget.Identity(),
		Delta:                 append([]byte(nil), request.Delta.Bytes...),
	})
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: execute delta run: %w", err)
	}
	inventory := executor.runtime.DrainRuntimeArtifactsForRun(run.ID())
	if failure := reviewrun.CoordinatorExecutionFailure(result); failure != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta run did not reach publication authority: %w", failure)
	}
	publicationContext, err := publication.NewChildPublicationContext(domain.RunTypeDelta, parent, source, request.SourceReviewID, nil, nil)
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta publication lineage: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(result, run.Target(), executor.config.SeverityThreshold, executor.config.MulgaeVersion, executor.config.MulgaeCommit, publicationContext, inventory)
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: prepare delta publication: %w", err)
	}
	published, err := executor.publisher.PublishNext(ctx, executor.artifactRoot, candidate)
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: publish delta run: %w", err)
	}
	final, ok := published.Final()
	if !ok || !final.Valid() {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: publication did not return a P2 final receipt")
	}
	diagnosticP2, _ = ports.NewSafeRelativePath(".mulgae/" + final.Path().String())
	terminalExit, err := committedTerminalExit(published)
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta publication terminal exit: %w", err)
	}
	execution, err := delta.NewExecutionResult(run.SessionID(), run.ID(), receiptURI(executor.artifactRoot, final), terminalExit)
	if err != nil {
		return delta.ExecutionResult{}, err
	}
	return execution, nil
}

func deltaRunWithConfiguredAssignments(run domain.Run, assignments []review.Assignment) (domain.Run, error) {
	parent, hasParent := run.ParentRunID()
	source, hasSource := run.SourceRunID()
	if run.Type() != domain.RunTypeDelta || !hasParent || !hasSource {
		return domain.Run{}, fmt.Errorf("child executor: delta run lineage is incomplete")
	}
	byRole := make(map[domain.Role]review.Assignment, len(assignments))
	for _, assignment := range assignments {
		if _, duplicate := byRole[assignment.Role()]; duplicate {
			return domain.Run{}, fmt.Errorf("child executor: delta role assignment is ambiguous")
		}
		byRole[assignment.Role()] = assignment
	}
	tasks := make([]domain.RoleTask, 0, len(run.RoleTasks()))
	for _, sourceTask := range run.RoleTasks() {
		assignment, ok := byRole[sourceTask.Role()]
		if !ok || assignment.Required() != sourceTask.Required() {
			return domain.Run{}, fmt.Errorf("child executor: delta assignment differs from source-selected role policy")
		}
		var fallback *string
		if route, ok := assignment.FallbackRoute(); ok {
			value := route.ProviderInstance()
			fallback = &value
		}
		task, err := domain.NewRoleTask(sourceTask.Role(), sourceTask.Required(), assignment.ProviderInstance(), fallback)
		if err != nil {
			return domain.Run{}, fmt.Errorf("child executor: configure delta role %q: %w", sourceTask.Role(), err)
		}
		tasks = append(tasks, task)
	}
	configured, err := domain.NewChildRunFromImmutableSource(run.ID(), domain.RunTypeDelta, run.SessionID(), parent, source, run.Target(), tasks)
	if err != nil {
		return domain.Run{}, fmt.Errorf("child executor: configure delta run: %w", err)
	}
	return configured, nil
}

// ExecuteChildReplay executes the already-authorized fresh rerun without
// replacing any identity or lineage supplied by rerun.Service.
func (executor *Executor) ExecuteChildReplay(ctx context.Context, child rerun.ChildReplay) (_ rerun.ChildReplayResult, retErr error) {
	if executor == nil || ctx == nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun executor and context are required")
	}
	if err := ctx.Err(); err != nil {
		return rerun.ChildReplayResult{}, err
	}
	run := child.Run
	if run.Type() != domain.RunTypeRerun || run.SessionID() != child.SessionID ||
		run.ID() == child.SourceRunID || run.Target().SHA256() != child.Target.SHA256 ||
		(child.Target.Identity.Kind() != "" && run.Target() != child.Target.Identity) {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: supplied rerun run differs from replay authority")
	}
	parent, hasParent := run.ParentRunID()
	source, hasSource := run.SourceRunID()
	if !hasParent || !hasSource || parent != child.ParentRunID || source != child.SourceRunID ||
		child.Publication.ParentRunID != parent || child.Publication.SourceRunID != source ||
		child.Publication.SourceReviewID != child.SourceReviewID || child.Publication.SourceAttemptID != child.SourceAttemptID {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun lineage differs from replay authority")
	}
	if !child.Mode.Valid() {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: replay mode is invalid")
	}
	lifecycle, err := executor.openDiagnostics(ctx, run)
	if err != nil {
		return rerun.ChildReplayResult{}, err
	}
	var diagnosticP2 ports.SafeRelativePath
	defer func() {
		if finishErr := lifecycle.finish(ctx, retErr, diagnosticP2); finishErr != nil {
			retErr = finishErr
		}
	}()
	if child.Mode == rerun.ExactReplay && (child.Exact == nil ||
		child.Exact.SourceManifestURI != child.Publication.SourceManifestURI ||
		child.Exact.SourceManifestSHA256 != child.Publication.SourceManifestSHA256 ||
		child.Exact.ComposedStdinSHA256 == "" || child.Exact.CompleteStdinSHA256 == "" ||
		child.Exact.SourceInvocationID == "" || child.Exact.SourceExecutionInvocationID == "" || child.Exact.SourceProviderInstance == "" || child.Exact.TemplateID == "" || child.Exact.TemplateVersion == "" || child.Exact.TemplateSHA256 == "" ||
		child.Exact.AdapterProfile == "") {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: exact replay authority is incomplete")
	}
	if child.Mode == rerun.RecomposeReplay && child.Exact != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: recomposed replay contains exact prompt authority")
	}

	result, err := executor.executeReplay(ctx, &run, child)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: execute rerun run: %w", err)
	}
	inventory := executor.runtime.DrainRuntimeArtifactsForRun(run.ID())
	if failure := reviewrun.CoordinatorExecutionFailure(result); failure != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun did not reach publication authority: %w", failure)
	}
	mode := publication.ReplayMode(child.Mode)
	publicationContext, err := publication.NewChildPublicationContext(
		domain.RunTypeRerun, parent, source, child.SourceReviewID, nil, &mode,
	)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun publication lineage: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(
		result, run.Target(), executor.config.SeverityThreshold, executor.config.MulgaeVersion,
		executor.config.MulgaeCommit, publicationContext, inventory,
	)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: prepare rerun publication: %w", err)
	}
	published, err := executor.publisher.PublishNext(ctx, executor.artifactRoot, candidate)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: publish rerun run: %w", err)
	}
	final, ok := published.Final()
	if !ok || !final.Valid() {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: publication did not return a P2 final receipt")
	}
	diagnosticP2, _ = ports.NewSafeRelativePath(".mulgae/" + final.Path().String())
	selectedInventory, err := terminalReplayInventory(result, inventory, domain.Role(child.Role), child.Mode)
	if err != nil {
		return rerun.ChildReplayResult{}, err
	}
	executionID := selectedInventory.ExecutionInvocationID()
	if executionID == "" {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun execution identity is absent")
	}
	promptManifest, ok := published.PromptManifestArtifact(selectedInventory.AttemptID(), selectedInventory.Sequence())
	if !ok {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: publication did not return the persisted prompt manifest")
	}
	terminalExit, err := committedTerminalExit(published)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun publication terminal exit: %w", err)
	}
	execution, err := rerun.NewChildReplayResult(
		run.SessionID(), run.ID(), parent, source, child.SourceReviewID, child.SourceAttemptID,
		executionID, selectedInventory.TemplateSHA256(),
		supportURI(executor.artifactRoot, promptManifest.Path()), strings.TrimPrefix(promptManifest.SHA256(), "sha256:"),
		child.Mode, child.Mode == rerun.ExactReplay, terminalExit,
	)
	if err != nil {
		return rerun.ChildReplayResult{}, err
	}
	return execution, nil
}

func terminalReplayInventory(
	result review.CoordinatorResult,
	inventory []review.RuntimeArtifactInventory,
	role domain.Role,
	mode rerun.ReplayMode,
) (review.RuntimeArtifactInventory, error) {
	roles := result.RoleSummaries()
	if len(roles) != 1 || roles[0].Role() != role {
		return review.RuntimeArtifactInventory{}, fmt.Errorf("child executor: rerun coordinator result is incomplete")
	}
	attempts := roles[0].Attempts()
	if len(attempts) == 0 {
		return review.RuntimeArtifactInventory{}, fmt.Errorf("child executor: rerun coordinator attempt is absent")
	}
	terminalAttempt := attempts[len(attempts)-1]
	invocations := terminalAttempt.Invocations()
	if len(invocations) == 0 {
		return review.RuntimeArtifactInventory{}, fmt.Errorf("child executor: rerun coordinator invocation is absent")
	}
	if mode == rerun.ExactReplay && (len(inventory) != 1 || len(attempts) != 1 || len(invocations) != 1 || invocations[0].Purpose() != domain.InvocationInitial) {
		return review.RuntimeArtifactInventory{}, fmt.Errorf("child executor: exact rerun scheduled more than one invocation")
	}
	terminalInvocation := invocations[len(invocations)-1]
	candidates := make([]replayInventoryCandidate, len(inventory))
	for index, candidate := range inventory {
		candidates[index] = replayInventoryCandidate{
			role: candidate.Role(), attemptID: candidate.AttemptID(), sequence: candidate.Sequence(), purpose: candidate.Purpose(),
		}
	}
	selectedIndex, err := terminalReplayInventoryIndex(candidates, role, terminalAttempt.ID(), terminalInvocation.Sequence(), terminalInvocation.Purpose())
	if err != nil {
		return review.RuntimeArtifactInventory{}, err
	}
	return inventory[selectedIndex], nil
}

type replayInventoryCandidate struct {
	role      domain.Role
	attemptID domain.AttemptID
	sequence  uint64
	purpose   domain.InvocationPurpose
}

func terminalReplayInventoryIndex(candidates []replayInventoryCandidate, role domain.Role, attemptID domain.AttemptID, sequence uint64, purpose domain.InvocationPurpose) (int, error) {
	selected := -1
	for index, candidate := range candidates {
		if candidate.role != role {
			return -1, fmt.Errorf("child executor: rerun runtime inventory contains another role")
		}
		if candidate.attemptID == attemptID && candidate.sequence == sequence && candidate.purpose == purpose {
			if selected >= 0 {
				return -1, fmt.Errorf("child executor: terminal rerun runtime inventory is ambiguous")
			}
			selected = index
		}
	}
	if selected < 0 {
		return -1, fmt.Errorf(
			"child executor: terminal rerun runtime inventory is incomplete for role=%s attempt=%s sequence=%d purpose=%s",
			role, attemptID, sequence, purpose,
		)
	}
	return selected, nil
}

func receiptURI(root ports.AnchoredRoot, final ports.FinalReviewIdentity) string {
	return (&url.URL{Scheme: "file", Path: filepath.Join(root.String(), final.Path().String())}).String()
}
func committedTerminalExit(result publication.PublicationResult) (domain.OperationalExitDecision, error) {
	exit, ok := result.TerminalExit()
	if !ok {
		return domain.OperationalExitDecision{}, fmt.Errorf("publication omitted terminal exit authority")
	}
	switch exit.Code() {
	case domain.ExitCommittedPass, domain.ExitCommittedCIRejected, domain.ExitIncompleteCoverage:
		return exit, nil
	default:
		return domain.OperationalExitDecision{}, fmt.Errorf("publication terminal exit %d is not a committed P2 outcome", exit.Code())
	}
}

func (executor *Executor) executeReplay(ctx context.Context, run *domain.Run, child rerun.ChildReplay) (review.CoordinatorResult, error) {
	if child.Mode != rerun.ExactReplay {
		return executor.coordinator.ExecuteRun(ctx, run, append([]review.Assignment(nil), child.Assignments...), executor.config.SeverityThreshold, executor.config.Policy)
	}
	assignment, err := assignmentForRole(domain.Role(child.Role), child.Assignments)
	if err != nil {
		return review.CoordinatorResult{}, err
	}
	parameters := make(map[string]string, len(child.Exact.Parameters))
	for _, parameter := range child.Exact.Parameters {
		if parameter.Name == "" {
			return review.CoordinatorResult{}, fmt.Errorf("child executor: exact replay parameter is invalid")
		}
		if _, exists := parameters[parameter.Name]; exists {
			return review.CoordinatorResult{}, fmt.Errorf("child executor: exact replay parameters contain duplicates")
		}
		parameters[parameter.Name] = parameter.Value
	}
	return executor.coordinator.ExecuteExactReplayRun(ctx, run, assignment, executor.config.SeverityThreshold, executor.config.Policy, review.ExactReplayInput{
		SourceRunID: child.SourceRunID, SourceAttemptID: child.SourceAttemptID,
		SourceProviderInstance: child.Exact.SourceProviderInstance,
		Stdin:                  append([]byte(nil), child.Exact.ComposedStdin...), CompleteStdinSHA256: child.Exact.CompleteStdinSHA256,
		SourceInvocationID: child.Exact.SourceInvocationID, Role: domain.Role(child.Role),
		SourceExecutionInvocationID: child.Exact.SourceExecutionInvocationID,
		TemplateID:                  child.Exact.TemplateID, TemplateVersion: child.Exact.TemplateVersion, TemplateSHA256: child.Exact.TemplateSHA256,
		AdapterProfile: child.Exact.AdapterProfile, AdapterParameters: parameters,
	})
}

func supportURI(root ports.AnchoredRoot, path ports.SafeRelativePath) string {
	return (&url.URL{Scheme: "file", Path: filepath.Join(root.String(), path.String())}).String()
}

func assignmentForRole(role domain.Role, assignments []review.Assignment) (review.Assignment, error) {
	var selected review.Assignment
	for _, assignment := range assignments {
		if assignment.Role() != role {
			continue
		}
		if selected.Role() != "" {
			return review.Assignment{}, fmt.Errorf("child executor: replay role assignment is ambiguous")
		}
		selected = assignment
	}
	if selected.Role() == "" {
		return review.Assignment{}, fmt.Errorf("child executor: replay role assignment is absent")
	}
	return selected, nil
}

func assignmentsForRun(run domain.Run, configured []review.Assignment) ([]review.Assignment, error) {
	selected := make(map[domain.Role]struct{}, len(run.RoleTasks()))
	for _, task := range run.RoleTasks() {
		selected[task.Role()] = struct{}{}
	}
	assignments := make([]review.Assignment, 0, len(selected))
	for _, assignment := range configured {
		if _, ok := selected[assignment.Role()]; ok {
			assignments = append(assignments, assignment)
		}
	}
	if len(assignments) != len(selected) {
		return nil, fmt.Errorf("child executor: supplied assignments do not cover child roles")
	}
	return assignments, nil
}
