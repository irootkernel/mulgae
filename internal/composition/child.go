//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/irootkernel/mulgae/internal/app/childrun"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	appreplay "github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type productionChildComposer struct {
	build            reviewrun.BuildIdentity
	root             ports.AnchoredRoot
	artifactRoot     ports.AnchoredRoot
	catalog          *builtin.Catalog
	validator        validation.SchemaValidator
	projectReader    ports.TrustedProjectReader
	clock            ports.Clock
	ids              review.IdentityGenerator
	writer           ports.SecureFileWriter
	publicationStore ports.PublicationStore
	stdin            ports.CapturedStdinStore
	sources          *mulgae.G008Sources
}

func (composer productionChildComposer) graph(ctx context.Context) (*productionRuntimeGraph, error) {
	return composeProductionRuntimeGraph(ctx, composer.build, composer.root, composer.catalog, composer.validator, composer.projectReader, composer.clock, composer.ids, composer.writer, composer.publicationStore, composer.stdin)
}

type deferredFollowupRunService struct{ composer productionChildComposer }
type deferredDeltaRunService struct{ composer productionChildComposer }
type deferredRerunService struct{ composer productionChildComposer }

func (service deferredFollowupRunService) StartFollowupRun(ctx context.Context, request appfollowup.Request) (_ mulgae.StartedRun, err error) {
	graph, err := service.composer.graph(ctx)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	defer func() { err = errors.Join(err, graph.cleanupRoots()) }()
	source, err := service.composer.sources.ReadFollowupSource(ctx, request.SourceRunID, request.FindingID)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	role := source.Finding.Role
	captured, selection, err := graph.capture(ctx, service.composer.artifactRoot, followupSelector(request.Target), []domain.Role{role})
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	authorityFactory, err := graph.sourceBoundAuthority(role, sourceProviderForFinding(source))
	if err != nil {
		return mulgae.StartedRun{}, abortCaptured(captured, err)
	}
	authority, err := authorityFactory.NewQualifiedRun(ctx, captured, selection)
	if err != nil {
		return mulgae.StartedRun{}, abortCapturedAfterAuthorityError(captured, err)
	}
	completed := false
	var childRunID string
	defer func() {
		cleanupErr := finishChildAuthority(ctx, captured, authority, childRunID, completed)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	promptIDs := productionPromptIDs{ids: graph.ids, clock: graph.clock}
	prompts, err := childrun.NewProductionFollowupPromptSourceWithStaging(
		promptIDs, promptIDs.newRoleTaskID, sourceProviderForFinding(source), captured.WorkspaceLease(),
		childrun.ProviderOutputStagingLocator(authority.Provider()),
	)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	followupSchema, err := ports.ParseAssetID(validation.ProviderFollowupSchemaID)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	followupValidator, err := validation.NewFollowupValidator(service.composer.validator, followupSchema)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	executor, err := childrun.NewFollowupExecutor(graph.clock, graph.ids, newChildPacketScreeningProvider(authority.Provider(), graph.detector), prompts, followupValidator, graph.publisher, service.composer.artifactRoot, childrun.FollowupExecutorConfig{
		ProviderInstance: sourceProviderForFinding(source), SeverityThreshold: graph.policy.planner.Threshold, MulgaeVersion: graph.build.Version, MulgaeCommit: graph.build.ImmutableReference(), Diagnostics: graph.diagnostics,
	})
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	capturer := staticFollowupTargetCapturer{target: appfollowup.CurrentTarget{Identity: captured.Input().Target().Identity(), Bytes: captured.Input().Target().Bytes(), CapturedArchive: captured.Input().CapturedArchive()}}
	workflow, err := appfollowup.NewService(service.composer.sources, capturer, executor)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	result, err := mulgae.NewFollowupRunService(workflow).StartFollowupRun(ctx, request)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	childRunID, completed = result.RunID, true
	return result, nil
}

func (service deferredDeltaRunService) StartDeltaRun(ctx context.Context, request appdelta.StartRequest) (_ mulgae.StartedRun, err error) {
	graph, err := service.composer.graph(ctx)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	defer func() { err = errors.Join(err, graph.cleanupRoots()) }()
	roles := append([]domain.Role(nil), request.Roles...)
	if len(roles) == 0 {
		source, sourceErr := service.composer.sources.ReadSource(ctx, request.SourceRunID)
		if sourceErr != nil {
			return mulgae.StartedRun{}, sourceErr
		}
		for _, task := range source.Roles {
			roles = append(roles, task.Role())
		}
	}
	captured, selection, err := graph.capture(ctx, service.composer.artifactRoot, deltaSelector(request.Target), roles)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	authority, err := graph.authority.NewQualifiedRun(ctx, captured, selection)
	if err != nil {
		return mulgae.StartedRun{}, abortCapturedAfterAuthorityError(captured, err)
	}
	completed := false
	var childRunID string
	defer func() {
		cleanupErr := finishChildAuthority(ctx, captured, authority, childRunID, completed)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	executor, assignments, err := graph.childExecutor(ctx, service.composer.artifactRoot, captured, selection, authority, service.composer.sources)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	_ = assignments
	target, err := deltaTargetFromCapture(request.Target, captured.Input().Target(), captured.Input().CapturedArchive())
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	workflow, err := appdelta.NewService(graph.clock, graph.ids, service.composer.sources, staticDeltaTargetCapturer{target: target}, canonicalDeltaComparator{}, executor)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	result, err := mulgae.NewDeltaRunService(workflow).StartDeltaRun(ctx, request)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	childRunID, completed = result.RunID, true
	return result, nil
}

func (service deferredRerunService) StartRerun(ctx context.Context, request appreplay.Request) (_ mulgae.StartedRun, err error) {
	graph, err := service.composer.graph(ctx)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	defer func() { err = errors.Join(err, graph.cleanupRoots()) }()
	source, err := service.composer.sources.ReadRerunSource(ctx, request.SourceRunID, request.SourceAttemptID)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	role := domain.Role(source.Prompt.Role)
	var captured reviewrun.CapturedRunInput
	var selection reviewrun.RunSelection
	if len(source.Target.CapturedArchive) > 0 {
		captured, selection, err = graph.captureArchive(ctx, source.Target.CapturedArchive, []domain.Role{role})
	} else {
		var selector ports.ReviewTargetSelector
		selector, err = replaySelector(source)
		if err == nil {
			captured, selection, err = graph.capture(ctx, service.composer.artifactRoot, selector, []domain.Role{role})
		}
	}
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	authorityFactory := graph.authority
	if request.ReplayMode == appreplay.ExactReplay {
		authorityFactory, err = graph.sourceBoundAuthority(role, source.ProviderInstance)
		if err != nil {
			return mulgae.StartedRun{}, abortCaptured(captured, err)
		}
	}
	authority, err := authorityFactory.NewQualifiedRun(ctx, captured, selection)
	if err != nil {
		return mulgae.StartedRun{}, abortCapturedAfterAuthorityError(captured, err)
	}
	completed := false
	var childRunID string
	defer func() {
		cleanupErr := finishChildAuthority(ctx, captured, authority, childRunID, completed)
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()
	executor, assignments, err := graph.childExecutor(ctx, service.composer.artifactRoot, captured, selection, authority, service.composer.sources)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	workflow, err := appreplay.NewService(service.composer.sources, executor, appreplay.Config{Clock: graph.clock, IDs: graph.ids, Assignments: assignments})
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	result, err := mulgae.NewRerunService(workflow).StartRerun(ctx, request)
	if err != nil {
		return mulgae.StartedRun{}, err
	}
	childRunID, completed = result.RunID, true
	return result, nil
}

func (graph *productionRuntimeGraph) captureArchive(ctx context.Context, archive []byte, roles []domain.Role) (reviewrun.CapturedRunInput, reviewrun.RunSelection, error) {
	selection, err := reviewrun.NewRunSelection(roles, nil)
	if err != nil {
		return reviewrun.CapturedRunInput{}, reviewrun.RunSelection{}, err
	}
	captured, err := graph.inputs.CaptureArchived(ctx, archive, nil, false)
	return captured, selection, err
}

func (graph *productionRuntimeGraph) capture(ctx context.Context, artifactRoot ports.AnchoredRoot, selector ports.ReviewTargetSelector, roles []domain.Role) (reviewrun.CapturedRunInput, reviewrun.RunSelection, error) {
	selection, err := reviewrun.NewRunSelection(roles, nil)
	if err != nil {
		return reviewrun.CapturedRunInput{}, reviewrun.RunSelection{}, err
	}
	captureRequest, err := reviewrun.NewInputCaptureRequest(graph.root, selector, nil, false)
	if err != nil {
		return reviewrun.CapturedRunInput{}, reviewrun.RunSelection{}, err
	}
	source, err := graph.inputs.NewImmutableInputSource(ctx, captureRequest)
	if err != nil {
		return reviewrun.CapturedRunInput{}, reviewrun.RunSelection{}, err
	}
	captured, err := source.Capture(ctx, reviewrun.Request{InputSource: source, ProjectRoot: graph.root, ArtifactRoot: artifactRoot, Selection: selection})
	return captured, selection, err
}

func (graph *productionRuntimeGraph) childExecutor(ctx context.Context, artifactRoot ports.AnchoredRoot, captured reviewrun.CapturedRunInput, selection reviewrun.RunSelection, authority reviewrun.RunAuthority, sources *mulgae.G008Sources) (*childrun.Executor, []review.Assignment, error) {
	planning, err := reviewrun.NewPlanningRequest(captured.Input(), selection.Roles())
	if err != nil {
		return nil, nil, err
	}
	plan, err := authority.Planner().Plan(ctx, planning)
	if err != nil {
		return nil, nil, err
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(plan.Budgets, plan.Ceilings, plan.MaxLanes)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := evidence.NewVerifier(captured.ImmutableTargetReader())
	if err != nil {
		return nil, nil, err
	}
	promptIDs := productionPromptIDs{ids: graph.ids, clock: graph.clock}
	// Delta and recomposed rerun compose current templates, so both state their
	// own staged destination once the locator is bound here. Exact replay
	// reproduces stored wire bytes and is excluded by the runtime itself.
	stagingLocator := childrun.ProviderOutputStagingLocator(authority.Provider())
	promptSource, err := reviewrun.NewProductionPromptSourceWithStaging(captured.Input(), graph.templates, promptIDs, promptIDs.newRoleTaskID, stagingLocator)
	if err != nil {
		return nil, nil, err
	}
	trustedPrompts, err := mulgae.NewG008RuntimePromptSource(sources, promptSource, promptSource, promptSource)
	if err != nil {
		return nil, nil, err
	}
	provider := newChildPacketScreeningProvider(authority.Provider(), graph.detector)
	runtime, err := review.NewObservedProviderInvocationRuntimeWithWorkspace(provider, trustedPrompts, captured.WorkspaceLease(), graph.reviewValidator, verifier)
	if err != nil {
		return nil, nil, err
	}
	if stagingLocator != nil {
		if err := runtime.BindProviderOutputStaging(stagingLocator); err != nil {
			return nil, nil, fmt.Errorf("child composition: provider output staging: %w", err)
		}
	}
	coordinator, err := review.NewCoordinator(graph.clock, graph.ids, runtime, graph.locker, plan.MaxLanes, receipt)
	if err != nil {
		return nil, nil, err
	}
	executor, err := childrun.NewExecutor(coordinator, runtime, graph.publisher, artifactRoot, childrun.ExecutorConfig{Assignments: plan.Assignments, SeverityThreshold: plan.Threshold, Policy: plan.Policy, MulgaeVersion: graph.build.Version, MulgaeCommit: graph.build.ImmutableReference(), Diagnostics: graph.diagnostics, Clock: graph.clock})
	if err != nil {
		return nil, nil, err
	}
	return executor, append([]review.Assignment(nil), plan.Assignments...), nil
}

type productionPromptIDs struct {
	ids   review.IdentityGenerator
	clock ports.Clock
}

func (issuer productionPromptIDs) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	value, err := issuer.ids.NewSourceInvocationID(issuer.clock.Now())
	if err != nil {
		return prompt.SourceInvocationID{}, err
	}
	return prompt.ParseSourceInvocationID(value)
}
func (issuer productionPromptIDs) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	value, err := issuer.ids.NewExecutionInvocationID(issuer.clock.Now())
	if err != nil {
		return prompt.ExecutionInvocationID{}, err
	}
	return prompt.ParseExecutionInvocationID(value)
}
func (issuer productionPromptIDs) newRoleTaskID() (prompt.RoleTaskID, error) {
	value, err := issuer.ids.NewRoleTaskID(issuer.clock.Now())
	if err != nil {
		return prompt.RoleTaskID{}, err
	}
	return prompt.ParseRoleTaskID(value)
}

type staticFollowupTargetCapturer struct{ target appfollowup.CurrentTarget }

func (capturer staticFollowupTargetCapturer) CaptureFollowupTarget(context.Context, appfollowup.Target) (appfollowup.CurrentTarget, error) {
	return appfollowup.CurrentTarget{Identity: capturer.target.Identity, Bytes: append([]byte(nil), capturer.target.Bytes...), CapturedArchive: append([]byte(nil), capturer.target.CapturedArchive...)}, nil
}

type staticDeltaTargetCapturer struct{ target appdelta.ImmutableTarget }

func (capturer staticDeltaTargetCapturer) CaptureTarget(context.Context, appdelta.TargetRequest) (appdelta.ImmutableTarget, error) {
	return capturer.target, nil
}

type canonicalDeltaComparator struct{}

func (canonicalDeltaComparator) Compare(_ context.Context, source, current appdelta.ImmutableTarget) (appdelta.Delta, error) {
	if len(source.CapturedArchive()) == 0 || len(current.CapturedArchive()) == 0 {
		return appdelta.Delta{Bytes: []byte(fmt.Sprintf("Mulgae-DELTA/1\nsource_sha256:%s\ncurrent_sha256:%s\n", source.SHA256(), current.SHA256()))}, nil
	}
	sourceMaterial, err := ports.UnmarshalCapturedReviewMaterial(source.CapturedArchive())
	if err != nil {
		return appdelta.Delta{}, fmt.Errorf("delta comparator: source archive: %w", err)
	}
	currentMaterial, err := ports.UnmarshalCapturedReviewMaterial(current.CapturedArchive())
	if err != nil {
		return appdelta.Delta{}, fmt.Errorf("delta comparator: current archive: %w", err)
	}
	left := snapshotFileMap(sourceMaterial.Snapshot().Files())
	right := snapshotFileMap(currentMaterial.Snapshot().Files())
	paths := make([]string, 0, len(left)+len(right))
	seen := make(map[string]struct{}, len(left)+len(right))
	for path := range left {
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for path := range right {
		if _, ok := seen[path]; !ok {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	var output strings.Builder
	output.WriteString("Mulgae-DELTA/2\n")
	output.WriteString("source_sha256:" + source.SHA256() + "\ncurrent_sha256:" + current.SHA256() + "\n")
	for _, path := range paths {
		before, beforeOK := left[path]
		after, afterOK := right[path]
		if beforeOK && afterOK && bytes.Equal(before, after) {
			continue
		}
		writeWholeFileDelta(&output, path, before, beforeOK, after, afterOK)
	}
	return appdelta.Delta{Bytes: []byte(output.String())}, nil
}

func snapshotFileMap(files []ports.WorkspaceSnapshotFile) map[string][]byte {
	result := make(map[string][]byte, len(files))
	for _, file := range files {
		result[file.Path().String()] = file.Bytes()
	}
	return result
}

func writeWholeFileDelta(output *strings.Builder, path string, before []byte, beforeOK bool, after []byte, afterOK bool) {
	leftName, rightName := "/dev/null", "b/"+path
	if beforeOK {
		leftName = "a/" + path
	}
	if !afterOK {
		rightName = "/dev/null"
	}
	output.WriteString("--- " + leftName + "\n+++ " + rightName + "\n")
	beforeLines := splitDeltaLines(before, beforeOK)
	afterLines := splitDeltaLines(after, afterOK)
	output.WriteString(fmt.Sprintf("@@ -1,%d +1,%d @@\n", len(beforeLines), len(afterLines)))
	for _, line := range beforeLines {
		output.WriteByte('-')
		output.WriteString(line)
		output.WriteByte('\n')
	}
	for _, line := range afterLines {
		output.WriteByte('+')
		output.WriteString(line)
		output.WriteByte('\n')
	}
}

func splitDeltaLines(value []byte, exists bool) []string {
	if !exists || len(value) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(value), "\n"), "\n")
}

func followupSelector(target appfollowup.Target) ports.ReviewTargetSelector {
	selector, _ := ports.NewReviewTargetSelector(ports.ReviewTargetSelectorKind(target.Kind), target.Value)
	return selector
}

func deltaSelector(target appdelta.TargetRequest) ports.ReviewTargetSelector {
	selector, _ := ports.NewReviewTargetSelector(ports.ReviewTargetSelectorKind(target.Kind), target.Value)
	return selector
}

func replaySelector(source appreplay.SourceAttempt) (ports.ReviewTargetSelector, error) {
	if source.Target.Identity.Kind() != domain.TargetGit {
		return ports.ReviewTargetSelector{}, fmt.Errorf("rerun composition: production replay currently requires a Git-backed source target")
	}
	return ports.NewReviewTargetSelector(ports.ReviewTargetDiff, source.Target.Identity.BaseObjectID()+"..."+source.Target.Identity.HeadObjectID())
}

func deltaTargetFromCapture(request appdelta.TargetRequest, captured ports.CapturedReviewTarget, archive []byte) (appdelta.ImmutableTarget, error) {
	var target appdelta.ImmutableTarget
	var err error
	if captured.Kind() == domain.TargetGit {
		repository, _ := captured.RepositoryID()
		base, _ := captured.BaseObjectID()
		head, _ := captured.HeadObjectID()
		tree, _ := captured.HeadTreeID()
		index, hasIndex := captured.IndexTreeID()
		var indexPointer *ports.GitObjectID
		if hasIndex {
			indexPointer = &index
		}
		var gitTarget ports.CapturedGitTarget
		gitTarget, err = ports.NewCapturedGitTarget(repository, base, head, tree, indexPointer, captured.Bytes())
		if err != nil {
			return appdelta.ImmutableTarget{}, err
		}
		target, err = appdelta.NewGitImmutableTargetForKind(request.Kind, request.Value, gitTarget)
	} else {
		target, err = appdelta.NewByteImmutableTarget(request.Kind, request.Value, captured.Bytes())
	}
	if err != nil {
		return appdelta.ImmutableTarget{}, err
	}
	if len(archive) > 0 {
		return target.WithCapturedArchive(archive)
	}
	return target, nil
}

func sourceProviderForFinding(source appfollowup.VerifiedSource) string {
	return source.ProviderInstance
}

func finishChildAuthority(ctx context.Context, captured reviewrun.CapturedRunInput, authority reviewrun.RunAuthority, runID string, completed bool) error {
	terminal, err := reviewrun.DrainRunAuthorityTerminal(ctx, authority)
	if err != nil {
		return err
	}
	providerReceipt := terminal.ProviderRunTerminalReceipt()
	if completed {
		evidence, err := ports.NewWorkspaceCompletionEvidence(captured.WorkspaceLease().WorkspaceSnapshotIdentity(), runID, providerReceipt)
		if err != nil {
			return err
		}
		receipt, err := captured.WorkspaceLease().Release(evidence)
		if err != nil || !receipt.Valid() {
			return fmt.Errorf("child composition: workspace release failed: %w", err)
		}
		return nil
	}
	abort, err := ports.NewWorkspaceAbortEvidence(captured.WorkspaceLease().WorkspaceSnapshotIdentity(), ports.WorkspaceAbortExecutionFailure, providerReceipt)
	if err != nil {
		return err
	}
	return captured.WorkspaceLease().Abort(abort)
}

func abortCaptured(captured reviewrun.CapturedRunInput, cause error) error {
	abort, err := ports.NewWorkspaceAbortEvidence(captured.WorkspaceLease().WorkspaceSnapshotIdentity(), ports.WorkspaceAbortPlanningFailure, ports.NewEmptyProviderRunTerminalReceipt())
	if err == nil {
		err = captured.WorkspaceLease().Abort(abort)
	}
	return errors.Join(cause, err)
}

func abortCapturedAfterAuthorityError(captured reviewrun.CapturedRunInput, cause error) error {
	receipt := ports.NewEmptyProviderRunTerminalReceipt()
	if terminal, ok := reviewrun.ProviderRunTerminalReceiptFromError(cause); ok && terminal.Valid() {
		receipt = terminal
	}
	abort, err := ports.NewWorkspaceAbortEvidence(captured.WorkspaceLease().WorkspaceSnapshotIdentity(), ports.WorkspaceAbortPlanningFailure, receipt)
	if err == nil {
		err = captured.WorkspaceLease().Abort(abort)
	}
	return errors.Join(cause, err)
}

type childPacketScreeningProvider struct {
	provider ports.ObservedReviewProvider
	detector ports.ReviewInputContentDetector
	mu       sync.Mutex
	blocked  bool
}

func newChildPacketScreeningProvider(provider ports.ObservedReviewProvider, detector ports.ReviewInputContentDetector) *childPacketScreeningProvider {
	return &childPacketScreeningProvider{provider: provider, detector: detector}
}

func (provider *childPacketScreeningProvider) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	if provider == nil || provider.provider == nil || provider.detector == nil {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("child composition: packet screening unavailable")
	}
	packet := invocation.PacketBytes()
	detection, err := provider.detector.DetectReviewInput(ctx, ports.ReviewInputPacket, invocation.SourceInvocationID(), packet)
	clear(packet)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ports.ProviderExecutionObservation{}, fmt.Errorf("child composition: detect provider packet: %w", err)
	}
	if err != nil || !detection.Valid() || detection.Verdict() != ports.ReviewInputClean {
		provider.mu.Lock()
		provider.blocked = true
		provider.mu.Unlock()
		return ports.ProviderExecutionObservation{}, fmt.Errorf("child composition: %w", ports.ErrProviderPacketSecurity)
	}
	return provider.provider.Observe(ctx, invocation)
}

var _ mulgae.FollowupRunService = deferredFollowupRunService{}
var _ mulgae.DeltaRunService = deferredDeltaRunService{}
var _ mulgae.RerunService = deferredRerunService{}
