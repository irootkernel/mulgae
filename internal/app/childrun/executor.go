// Package childrun executes and publishes supplied child review runs.
package childrun

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/irootkernel/kkachi-agent-review/internal/app/delta"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/rerun"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// ExecutorConfig contains the immutable review and publication authority for
// child review runs. The coordinator already owns the corresponding prompt,
// assignment budget, and provider execution authority.
type ExecutorConfig struct {
	Assignments       []review.Assignment
	SeverityThreshold domain.Severity
	Policy            *domain.CIPolicy
	KARVersion        string
	KARCommit         string
}

// Executor is the production delta child executor. It deliberately accepts a
// supplied domain.Run rather than minting or substituting child identity.
type Executor struct {
	coordinator  *review.Coordinator
	runtime      *review.ProviderInvocationRuntime
	publisher    *publication.Service
	artifactRoot ports.AnchoredRoot
	config       ExecutorConfig
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
	if config.KARVersion == "" || config.KARCommit == "" {
		return nil, fmt.Errorf("child executor: publication identity is incomplete")
	}
	return &Executor{
		coordinator: coordinator, runtime: runtime, publisher: publisher, artifactRoot: artifactRoot,
		config: ExecutorConfig{
			Assignments: append([]review.Assignment(nil), config.Assignments...), SeverityThreshold: config.SeverityThreshold,
			Policy: config.Policy, KARVersion: config.KARVersion, KARCommit: config.KARCommit,
		},
	}, nil
}

// ExecuteDelta executes exactly request.Run, binds only that run's runtime
// inventory, and returns a URI derived from the P2 publication receipt.
func (executor *Executor) ExecuteDelta(ctx context.Context, request delta.ChildRequest) (delta.ExecutionResult, error) {
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
	parent, hasParent := run.ParentRunID()
	source, hasSource := run.SourceRunID()
	if !hasParent || !hasSource || parent != source || request.SourceReviewID.String() == "" {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta lineage differs from supplied authority")
	}

	assignments, err := assignmentsForRun(run, executor.config.Assignments)
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
	publicationContext, err := publication.NewChildPublicationContext(domain.RunTypeDelta, parent, source, request.SourceReviewID, nil, nil)
	if err != nil {
		return delta.ExecutionResult{}, fmt.Errorf("child executor: delta publication lineage: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(result, run.Target(), executor.config.SeverityThreshold, executor.config.KARVersion, executor.config.KARCommit, publicationContext, inventory)
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

// ExecuteChildReplay executes the already-authorized fresh rerun without
// replacing any identity or lineage supplied by rerun.Service.
func (executor *Executor) ExecuteChildReplay(ctx context.Context, child rerun.ChildReplay) (rerun.ChildReplayResult, error) {
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
	if child.Mode == rerun.ExactReplay && (child.Exact == nil ||
		child.Exact.SourceManifestURI != child.Publication.SourceManifestURI ||
		child.Exact.SourceManifestSHA256 != child.Publication.SourceManifestSHA256 ||
		child.Exact.ComposedStdinSHA256 == "" || child.Exact.CompleteStdinSHA256 == "" ||
		child.Exact.SourceInvocationID == "" || child.Exact.SourceProviderInstance == "" ||
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
	mode := publication.ReplayMode(child.Mode)
	publicationContext, err := publication.NewChildPublicationContext(
		domain.RunTypeRerun, parent, source, child.SourceReviewID, nil, &mode,
	)
	if err != nil {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun publication lineage: %w", err)
	}
	candidate, err := publication.PrepareCandidateWithRuntimeArtifacts(
		result, run.Target(), executor.config.SeverityThreshold, executor.config.KARVersion,
		executor.config.KARCommit, publicationContext, inventory,
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
	if len(inventory) != 1 || inventory[0].Role() != domain.Role(child.Role) {
		return rerun.ChildReplayResult{}, fmt.Errorf("child executor: rerun runtime inventory is incomplete")
	}
	selectedInventory := inventory[0]
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
