package childrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/adapters/workspace"
	"github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestDeltaRunWithConfiguredAssignmentsUsesCurrentPlannerRoutes(t *testing.T) {
	sessionID := childrunSessionID(t, "s_019f596a-cf70-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cf71-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf72-7c67-b265-f37053d51ccf")
	task, err := domain.NewRoleTask(domain.RoleLogic, true, "source-fallback")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewChildRunFromImmutableSource(childRunID, domain.RunTypeDelta, sessionID, sourceRunID, sourceRunID, childrunTarget(t), []domain.RoleTask{task})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := ports.NewProviderRoute("primary")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := review.NewScheduledAssignment(domain.RoleLogic, true, primary)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := deltaRunWithConfiguredAssignments(run, []review.Assignment{assignment})
	if err != nil {
		t.Fatal(err)
	}
	roles := configured.RoleTasks()
	if len(roles) != 1 || roles[0].PrimaryProvider() != "primary" {
		t.Fatalf("configured delta roles = %#v", roles)
	}
}

func TestTerminalReplayInventoryIndexSelectsRepairInvocation(t *testing.T) {
	attemptID, err := domain.ParseAttemptID("a_019f596a-cf73-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	candidates := []replayInventoryCandidate{
		{role: domain.RoleLogic, attemptID: attemptID, sequence: 1, purpose: domain.InvocationInitial},
		{role: domain.RoleLogic, attemptID: attemptID, sequence: 2, purpose: domain.InvocationRepair},
	}
	index, err := terminalReplayInventoryIndex(candidates, domain.RoleLogic, attemptID, 2, domain.InvocationRepair)
	if err != nil {
		t.Fatal(err)
	}
	if index != 1 {
		t.Fatalf("terminalReplayInventoryIndex() = %d, want repair inventory index 1", index)
	}
}

func TestExecuteDeltaRejectsInvalidSourceLineageBeforeExecution(t *testing.T) {
	t.Parallel()

	sessionID := childrunSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	parentRunID := childrunRunID(t, "r_019f596a-cf81-7c67-b265-f37053d51ccf")
	otherSourceRunID := childrunRunID(t, "r_019f596a-cf82-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf83-7c67-b265-f37053d51ccf")
	current, err := delta.NewByteImmutableTarget(delta.TargetPatch, "current.patch", []byte("current"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := delta.NewByteImmutableTarget(delta.TargetPatch, "source.patch", []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewChildRunFromImmutableSource(
		childRunID, domain.RunTypeDelta, sessionID, parentRunID, otherSourceRunID,
		current.Identity(), childrunRequiredRoles(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	reviewID := childrunReviewID(t, "019f596a-cf84-7c67-b265-f37053d51ccf")

	_, err = (&Executor{}).ExecuteDelta(context.Background(), delta.ChildRequest{
		Run: run, SourceReviewID: reviewID, SourceTarget: source, CurrentTarget: current,
	})
	if err == nil || !strings.Contains(err.Error(), "lineage differs") {
		t.Fatalf("ExecuteDelta wrong-source error = %v, want lineage rejection", err)
	}
}

func TestExecuteDeltaRejectsPartialSourceAuthorityBeforeExecution(t *testing.T) {
	t.Parallel()

	sessionID := childrunSessionID(t, "s_019f596a-cf90-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cf91-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cf92-7c67-b265-f37053d51ccf")
	current, err := delta.NewByteImmutableTarget(delta.TargetPatch, "current.patch", []byte("current"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewChildRunFromImmutableSource(
		childRunID, domain.RunTypeDelta, sessionID, sourceRunID, sourceRunID,
		current.Identity(), childrunRequiredRoles(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = (&Executor{}).ExecuteDelta(context.Background(), delta.ChildRequest{Run: run, CurrentTarget: current})
	if err == nil || !strings.Contains(err.Error(), "lineage differs") {
		t.Fatalf("ExecuteDelta partial-authority error = %v, want lineage rejection", err)
	}
}

func TestExecuteChildReplayRejectsPartialPublicationAuthorityBeforeExecution(t *testing.T) {
	t.Parallel()

	sessionID := childrunSessionID(t, "s_019f596a-cfa0-7c67-b265-f37053d51ccf")
	sourceRunID := childrunRunID(t, "r_019f596a-cfa1-7c67-b265-f37053d51ccf")
	childRunID := childrunRunID(t, "r_019f596a-cfa2-7c67-b265-f37053d51ccf")
	target := childrunTarget(t)
	selected, err := domain.NewRoleTask(domain.RoleLogic, true, "provider")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.NewRerunChildRunFromImmutableSource(
		childRunID, sessionID, sourceRunID, sourceRunID, target, selected,
	)
	if err != nil {
		t.Fatal(err)
	}
	reviewID := childrunReviewID(t, "019f596a-cfa3-7c67-b265-f37053d51ccf")
	attemptID, err := domain.ParseAttemptID("a_019f596a-cfa4-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}

	_, err = (&Executor{}).ExecuteChildReplay(context.Background(), rerun.ChildReplay{
		SessionID: sessionID, ParentRunID: sourceRunID, SourceRunID: sourceRunID,
		SourceReviewID: reviewID, SourceAttemptID: attemptID, Mode: rerun.RecomposeReplay,
		Target: rerun.Target{Identity: target, SHA256: target.SHA256()}, Run: run,
		Publication: rerun.ChildPublicationContext{SessionID: sessionID, ParentRunID: sourceRunID},
	})
	if err == nil || !strings.Contains(err.Error(), "lineage differs") {
		t.Fatalf("ExecuteChildReplay partial-authority error = %v, want lineage rejection", err)
	}
}

func childrunRequiredRoles(t *testing.T) []domain.RoleTask {
	t.Helper()
	roles := make([]domain.RoleTask, 0, 2)
	for _, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		task, err := domain.NewRoleTask(role, true, "provider")
		if err != nil {
			t.Fatal(err)
		}
		roles = append(roles, task)
	}
	return roles
}

func childrunTarget(t *testing.T) domain.TargetIdentity {
	t.Helper()
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetPatch, SHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func childrunSessionID(t *testing.T, value string) domain.SessionID {
	t.Helper()
	id, err := domain.ParseSessionID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func childrunRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	id, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func childrunReviewID(t *testing.T, value string) domain.ReviewID {
	t.Helper()
	id, err := domain.ParseReviewID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPreserveFailedReplayRefusesExpiredContext(t *testing.T) {
	executor := &Executor{recoveryCleanup: func(context.Context, domain.RunID) (ports.WorkspaceTerminalReceipt, error) {
		t.Fatal("expired retention called cleanup")
		return ports.WorkspaceTerminalReceipt{}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := executor.preserveFailedReplay(ctx, review.CoordinatorResult{}, domain.TargetIdentity{}, publication.RunPublicationContext{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preserveFailedReplay expired context: %v", err)
	}
}

func TestExecuteChildReplayPreservesFailureWhenRecoveryFails(t *testing.T) {
	for _, test := range []struct {
		name      string
		condition review.AttemptCondition
		class     domain.FailureClass
		state     domain.RunState
	}{
		{"configuration", review.AttemptConditionConfigurationViolation, domain.FailureConfiguration, domain.RunFailed},
		{"cancellation", review.AttemptConditionCancelled, domain.FailureCancelled, domain.RunCancelled},
	} {
		for _, boundary := range []string{"unavailable", "inputs", "cleanup", "cleanup-deadline", "storage", "storage-deadline"} {
			t.Run(test.name+"/"+boundary, func(t *testing.T) {
				ctx := context.Background()
				ids := &childRecoveryIDs{}
				target, err := ports.NewCapturedReviewPatchTarget([]byte("immutable target"))
				if err != nil {
					t.Fatal(err)
				}
				request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
				if err != nil {
					t.Fatal(err)
				}
				captured, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
				if err != nil {
					t.Fatal(err)
				}
				material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, captured)
				if err != nil {
					t.Fatal(err)
				}
				archive, err := ports.MarshalCapturedReviewMaterial(material)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := evidence.NewVerifier(childRecoveryEvidenceReader{})
				if err != nil {
					t.Fatal(err)
				}
				runtime, err := review.NewProviderInvocationRuntime(childRecoveryProvider{}, childRecoveryPromptSource{target.Bytes(), archive, ids}, &validation.ReviewValidator{}, verifier)
				if err != nil {
					t.Fatal(err)
				}
				fault := &childRecoveryRuntime{runtime: runtime, condition: test.condition}
				route, err := ports.NewProviderRoute("provider")
				if err != nil {
					t.Fatal(err)
				}
				assignment, err := review.NewScheduledAssignment(domain.RoleLogic, true, route)
				if err != nil {
					t.Fatal(err)
				}
				limits, err := review.NewInvocationLimits(time.Second)
				if err != nil {
					t.Fatal(err)
				}
				routeBudget, err := review.NewRouteBudget(route, limits)
				if err != nil {
					t.Fatal(err)
				}
				budget, err := review.NewRoleBudget(domain.RoleLogic, routeBudget)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := review.PreflightRunBudgetWithCapacity([]review.RoleBudget{budget}, review.DefaultHarnessCeilings(), 1)
				if err != nil {
					t.Fatal(err)
				}
				clock := childRecoveryClock{}
				coordinator, err := review.NewCoordinator(clock, ids, fault, 1, receipt)
				if err != nil {
					t.Fatal(err)
				}
				session := childrunSessionID(t, "s_019f596a-cfa0-7c67-b265-f37053d51ccf")
				source := childrunRunID(t, "r_019f596a-cfa1-7c67-b265-f37053d51ccf")
				runID := childrunRunID(t, "r_019f596a-cfa2-7c67-b265-f37053d51ccf")
				role, err := domain.NewRoleTask(domain.RoleLogic, true, "provider")
				if err != nil {
					t.Fatal(err)
				}
				run, err := domain.NewRerunChildRunFromImmutableSource(runID, session, source, source, target.Identity(), role)
				if err != nil {
					t.Fatal(err)
				}
				reviewID := childrunReviewID(t, "019f596a-cfa3-7c67-b265-f37053d51ccf")
				attemptID, err := domain.ParseAttemptID("a_019f596a-cfa4-7c67-b265-f37053d51ccf")
				if err != nil {
					t.Fatal(err)
				}
				root, err := ports.NewAnchoredRoot(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				validator, err := jsonschema.New(ctx, builtin.NewCatalog())
				if err != nil {
					t.Fatal(err)
				}
				store := &childRecoveryStore{}
				if boundary == "storage-deadline" {
					store.err = context.DeadlineExceeded
				}
				if test.class == domain.FailureCancelled && (boundary == "storage" || boundary == "storage-deadline") {
					store.check = func(persistCtx context.Context) {
						assertRetentionTenMinuteDeadlineLive(t, "persist", persistCtx)
					}
				}
				publisher, err := publication.NewService(store, validator, clock, 8<<20)
				if err != nil {
					t.Fatal(err)
				}
				executor := &Executor{coordinator: coordinator, runtime: runtime, publisher: publisher, artifactRoot: root, config: ExecutorConfig{SeverityThreshold: domain.SeverityHigh}}
				cleanupCalled := false
				var cleanupCtx context.Context
				if boundary != "unavailable" {
					workspaceRoot, err := ports.NewAnchoredRoot(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					materializer, err := workspace.NewMaterializer(workspaceRoot, filesystem.NewContentDetector())
					if err != nil {
						t.Fatal(err)
					}
					lease, err := materializer.MaterializeLease(ctx, material.Snapshot())
					if err != nil {
						t.Fatal(err)
					}
					released := false
					t.Cleanup(func() {
						if released {
							return
						}
						abort, err := ports.NewWorkspaceAbortEvidence(lease.WorkspaceSnapshotIdentity(), ports.WorkspaceAbortExecutionFailure, ports.NewEmptyProviderRunTerminalReceipt())
						if err != nil {
							t.Error(err)
							return
						}
						if err := lease.Abort(abort); err != nil {
							t.Error(err)
						}
					})
					err = executor.BindRecoveryCleanup(lease.WorkspaceSnapshotIdentity().ManifestSHA256(), func(ctx context.Context, id domain.RunID) (ports.WorkspaceTerminalReceipt, error) {
						cleanupCalled = true
						cleanupCtx = ctx
						if test.class == domain.FailureCancelled && (boundary == "cleanup" || boundary == "cleanup-deadline" || boundary == "storage" || boundary == "storage-deadline") {
							assertRetentionTenMinuteDeadlineLive(t, "cleanup", ctx)
						}
						if boundary == "cleanup" {
							return ports.WorkspaceTerminalReceipt{}, errors.New("injected cleanup failure")
						}
						if boundary == "cleanup-deadline" {
							return ports.WorkspaceTerminalReceipt{}, context.DeadlineExceeded
						}
						completion, err := ports.NewWorkspaceCompletionEvidence(lease.WorkspaceSnapshotIdentity(), id.String(), ports.NewEmptyProviderRunTerminalReceipt())
						if err != nil {
							return ports.WorkspaceTerminalReceipt{}, err
						}
						terminal, err := lease.Release(completion)
						released = err == nil
						return terminal, err
					})
					if err != nil {
						t.Fatal(err)
					}
					if boundary == "inputs" {
						fault.discardInputs = true
					}
				}
				_, err = executor.ExecuteChildReplay(ctx, rerun.ChildReplay{
					SessionID: session, ParentRunID: source, SourceRunID: source, SourceReviewID: reviewID, SourceAttemptID: attemptID, Mode: rerun.RecomposeReplay,
					Target: rerun.Target{Identity: target.Identity(), SHA256: target.Identity().SHA256()}, Run: run, Role: string(domain.RoleLogic), Assignments: []review.Assignment{assignment},
					Publication: rerun.ChildPublicationContext{SessionID: session, ParentRunID: source, SourceRunID: source, SourceReviewID: reviewID, SourceAttemptID: attemptID},
				})
				if err == nil || fault.calls != 1 {
					t.Fatalf("execution did not reach failing provider: calls=%d err=%v", fault.calls, err)
				}
				wantReason := "recovery_cleanup_unavailable"
				if boundary != "unavailable" {
					wantReason = "recovery_" + boundary + "_failed"
					if boundary == "cleanup-deadline" {
						wantReason = "recovery_cleanup_failed"
					}
					if boundary == "storage-deadline" {
						wantReason = "recovery_storage_failed"
					}
					if boundary == "inputs" || test.class == domain.FailureConfiguration {
						wantReason = "recovery_inputs_invalid"
					}
				}
				if !strings.Contains(err.Error(), wantReason) {
					t.Fatalf("wrong recovery boundary: %v, want %s", err, wantReason)
				}
				var primary *domain.Failure
				if !errors.As(err, &primary) || primary.Class() != test.class {
					t.Fatalf("original failure lost: %v", err)
				}
				for current := err; current != nil; current = errors.Unwrap(current) {
					if _, joined := current.(interface{ Unwrap() []error }); joined {
						t.Fatalf("secondary recovery error joined primary authority: %v", err)
					}
				}
				facts, ok := reviewrun.ProviderExecutionFailuresFromError(err)
				if !ok || len(facts) != 1 || facts[0].FailureClass() != test.class {
					t.Fatalf("provider failure facts lost: %v", err)
				}
				if state, _ := childDiagnosticTerminalDecision(err); state != test.state {
					t.Fatalf("diagnostic state=%s, want %s", state, test.state)
				}
				wantCleanup := test.class == domain.FailureCancelled && (boundary == "cleanup" || boundary == "cleanup-deadline" || boundary == "storage" || boundary == "storage-deadline")
				if cleanupCalled != wantCleanup || store.writes != 0 && !wantCleanup {
					t.Fatal("recovery crossed a forbidden boundary")
				}
				if test.class == domain.FailureCancelled && (boundary == "storage" || boundary == "storage-deadline") && store.writes != 1 {
					t.Fatal("storage fault was not exercised")
				}
				if test.class == domain.FailureCancelled && (boundary == "cleanup" || boundary == "storage") && cleanupCtx == nil {
					t.Fatal("failed-rerun retention cleanup did not receive a context")
				}
			})
		}
	}
}

type childRecoveryRuntime struct {
	runtime       *review.ProviderInvocationRuntime
	condition     review.AttemptCondition
	discardInputs bool
	calls         int
}

func (runtime *childRecoveryRuntime) PrepareInitial(ctx context.Context, jobs []review.InvocationJob) error {
	if err := runtime.runtime.PrepareInitial(ctx, jobs); err != nil {
		return err
	}
	if runtime.discardInputs {
		runtime.runtime.DrainInitialInputsForRun(jobs[0].RunID())
	}
	return nil
}
func (runtime *childRecoveryRuntime) Invoke(_ context.Context, job review.InvocationJob) review.AttemptOutcome {
	runtime.calls++
	outcome, err := review.NewAttemptOutcome(job, nil, &runtime.condition)
	if err != nil {
		panic(err)
	}
	return outcome
}

type childRecoveryClock struct{}

func (childRecoveryClock) Now() time.Time { return time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) }

type childRecoveryStore struct {
	ports.PublicationStore
	writes int
	err    error
	check  func(context.Context)
}

func (store *childRecoveryStore) PersistAuxiliaryArtifact(ctx context.Context, _ ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	store.writes++
	if store.check != nil {
		store.check(ctx)
	}
	if store.err != nil {
		return ports.PersistAuxiliaryArtifactResult{}, store.err
	}
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("injected storage failure")
}

func assertRetentionTenMinuteDeadlineLive(t *testing.T, name string, ctx context.Context) {
	t.Helper()
	if ctx.Err() != nil {
		t.Errorf("failed-rerun retention %s inherited cancellation: %v", name, ctx.Err())
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Errorf("failed-rerun retention %s context has no deadline", name)
		return
	}
	remaining := time.Until(deadline)
	if remaining < 9*time.Minute || remaining > 10*time.Minute+2*time.Second {
		t.Errorf("failed-rerun retention %s remaining = %s, want approximately 10m", name, remaining)
	}
}

type childRecoveryEvidenceReader struct{}

func (childRecoveryEvidenceReader) ReadImmutableTarget(context.Context, string, evidence.Side, ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	return evidence.ImmutableTargetUnavailable, nil, nil
}

type childRecoveryProvider struct{}

func (childRecoveryProvider) Invoke(context.Context, ports.ProviderInvocation) (ports.ProviderResult, error) {
	return ports.ProviderResult{}, fmt.Errorf("unexpected real provider invocation")
}

type childRecoveryPromptSource struct {
	target, archive []byte
	ids             *childRecoveryIDs
}

func (source childRecoveryPromptSource) Prompt(_ context.Context, job review.InvocationJob, _ *review.InvocationRepairInput) (review.RuntimePrompt, error) {
	roleTask, err := prompt.ParseRoleTaskID(strings.Replace(job.AttemptID().String(), "a_", "rt_", 1))
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	coordinates, err := prompt.NewScopeCoordinates(job.SessionID(), job.RunID(), roleTask, job.AttemptID())
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	template, err := prompt.NewTrustedTemplate("recovery-test", "v1", []byte("Return a review."))
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	compiler, err := prompt.NewCompiler(template, source.ids)
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	compiled, err := compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(source.target)})
	if err != nil {
		return review.RuntimePrompt{}, err
	}
	return review.RuntimePrompt{Prompt: compiled, Target: source.target, CapturedArchive: source.archive, AdapterProfile: "test", AdapterParameters: map[string]string{}}, nil
}

type childRecoveryIDs struct{ next int }

func (ids *childRecoveryIDs) uuid() string {
	ids.next++
	return fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", ids.next)
}
func (ids *childRecoveryIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.uuid())
}
func (ids *childRecoveryIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.uuid())
}
func (ids *childRecoveryIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.uuid())
}
func (ids *childRecoveryIDs) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_" + ids.uuid())
}
func (ids *childRecoveryIDs) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID(ids.uuid())
}
