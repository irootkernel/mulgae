package publication

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPrepareAndPersistFailedRunRecoveryRefuseExpiredContext(t *testing.T) {
	result, target, inputs, _ := failedRecoveryCoordinator(t, review.AttemptConditionInternalInvariant)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareFailedRunRecovery(ctx, result, target, domain.SeverityHigh, "sha256:"+strings.Repeat("a", 64), RunPublicationContext{}, inputs); !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareFailedRunRecovery cancelled context: %v", err)
	}
	store := &recoveryPersistStore{}
	service, err := NewService(store, &publicationTestValidator{}, publicationServiceClock{now: publicationTestTime()}, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PersistFailedRunRecovery(ctx, root, recovery.Prepared{}, ports.WorkspaceTerminalReceipt{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("PersistFailedRunRecovery cancelled context: %v", err)
	}
	if store.writes != 0 {
		t.Fatalf("expired persist installed %d artifacts", store.writes)
	}
}

type recoveryPersistStore struct {
	ports.PublicationStore
	writes int
}

func (store *recoveryPersistStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	store.writes++
	return ports.PersistAuxiliaryArtifactResult{}, fmt.Errorf("unexpected persist")
}

func TestPersistFailedRunRecoveryExpiresDuringValidationWithoutManifest(t *testing.T) {
	result, target, inputs, _ := failedRecoveryCoordinator(t, review.AttemptConditionInternalInvariant)
	manifest := "sha256:" + strings.Repeat("a", 64)
	prepared, err := PrepareFailedRunRecovery(context.Background(), result, target, domain.SeverityHigh, manifest, RunPublicationContext{}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	receipt := failedRecoveryTerminalReceipt(t, result.RunID(), manifest)
	ctx, cancel := context.WithCancel(context.Background())
	store := &recoveryPersistStore{}
	service, err := NewService(store, cancellingRecoveryValidator{cancel: cancel}, publicationServiceClock{now: publicationTestTime()}, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PersistFailedRunRecovery(ctx, root, prepared, receipt); !errors.Is(err, context.Canceled) {
		t.Fatalf("persist during validation: %v", err)
	}
	if store.writes != 0 {
		t.Fatalf("expired validation installed %d artifacts", store.writes)
	}
}

type recoveryReceiptLease struct {
	identity ports.WorkspaceSnapshotIdentity
	release  ports.WorkspaceTerminalRelease
}

func (lease recoveryReceiptLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (lease recoveryReceiptLease) Receipt() ports.WorkspaceSnapshotReceipt {
	return ports.WorkspaceSnapshotReceipt{}
}
func (lease recoveryReceiptLease) Release(completion ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	return lease.release(completion)
}
func (lease recoveryReceiptLease) Abort(ports.WorkspaceAbortEvidence) error { return nil }
func (recoveryReceiptLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, fmt.Errorf("unexpected workspace revalidation")
}

type cancellingRecoveryValidator struct{ cancel context.CancelFunc }

func (validator cancellingRecoveryValidator) Validate(context.Context, ports.AssetID, []byte) error {
	validator.cancel()
	return nil
}

func TestPrepareFailedRunRecoveryAdmitsAndRejectsTerminalFailures(t *testing.T) {
	tests := []struct {
		condition review.AttemptCondition
		admitted  bool
	}{
		{review.AttemptConditionInternalInvariant, true},
		{review.AttemptConditionTimeout, true},
		{review.AttemptConditionSecurityViolation, false},
		{review.AttemptConditionArtifactFailure, false},
	}
	for _, test := range tests {
		t.Run(string(test.condition), func(t *testing.T) {
			result, target, inputs, calls := failedRecoveryCoordinator(t, test.condition)
			if len(calls) != 3 || calls[0] != domain.RoleLogic || calls[1] != domain.RoleDocumentation {
				t.Fatalf("unexpected dispatch: %v", calls)
			}
			if len(inputs) != 3 || len(result.RoleSummaries()) != 3 {
				t.Fatal("queued role inputs were lost")
			}
			manifest := "sha256:" + strings.Repeat("a", 64)
			prepared, err := PrepareFailedRunRecovery(context.Background(), result, target, domain.SeverityHigh, manifest, RunPublicationContext{}, inputs)
			if !test.admitted {
				if err == nil {
					t.Fatalf("%s failure granted recovery", test.condition)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepared.Seal(context.Background(), ports.WorkspaceTerminalReceipt{}); err == nil {
				t.Fatal("recovery sealed before cleanup")
			}
			if _, err := PrepareFailedRunRecovery(context.Background(), result, target, domain.SeverityHigh, "sha256:"+strings.Repeat("a", 64), RunPublicationContext{}, inputs[:2]); err == nil {
				t.Fatal("missing queued input was accepted")
			}
			if test.condition == review.AttemptConditionTimeout {
				snapshot, err := prepared.Seal(context.Background(), failedRecoveryTerminalReceipt(t, result.RunID(), manifest))
				if err != nil {
					t.Fatal(err)
				}
				document := snapshot.Document()
				var found bool
				for _, attempt := range document.Attempts {
					if attempt.Role == domain.RoleDocumentation {
						found = attempt.State == domain.AttemptTimedOut && attempt.FailureClass == domain.FailureTimeout && attempt.ReasonCode == string(review.AttemptConditionTimeout)
					}
				}
				if !found {
					t.Fatalf("timed-out attempt was not retained: %#v", document.Attempts)
				}
			}
		})
	}
}

func TestPrepareFailedRunRecoveryBindsRecoveryRerunLineage(t *testing.T) {
	result, target, inputs, _ := failedRecoveryCoordinatorForRoles(t, review.AttemptConditionInternalInvariant, []domain.Role{domain.RoleDocumentation})
	parent, err := domain.ParseRunID("r_019f596a-cf81-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	sourceRun, err := domain.ParseRunID("r_019f596a-cf82-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	sourceAttempt, err := domain.ParseAttemptID("a_019f596a-cf83-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	sourceManifest := "sha256:" + strings.Repeat("b", 64)
	source, err := domain.NewRecoverySourceReference(sourceRun, sourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := NewRecoveryRerunPublicationContext(parent, source, sourceAttempt, ReplayModeExact)
	if err != nil {
		t.Fatal(err)
	}
	workspaceManifest := "sha256:" + strings.Repeat("a", 64)
	prepared, err := PrepareFailedRunRecovery(context.Background(), result, target, domain.SeverityHigh, workspaceManifest, lineage, inputs)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := prepared.Seal(context.Background(), failedRecoveryTerminalReceipt(t, result.RunID(), workspaceManifest))
	if err != nil {
		t.Fatal(err)
	}
	document := snapshot.Document()
	if document.RunType != domain.RunTypeRerun || document.Source == nil ||
		document.Source.Kind != "failed_run_recovery" || document.Source.RunID != sourceRun.String() ||
		document.Source.RecoveryManifestSHA256 == nil || *document.Source.RecoveryManifestSHA256 != sourceManifest ||
		document.Source.AttemptID != sourceAttempt.String() || document.Source.ReplayMode != string(ReplayModeExact) {
		t.Fatalf("prepared recovery rerun lineage = %#v", document.Source)
	}
}

func failedRecoveryTerminalReceipt(t *testing.T, runID domain.RunID, manifest string) ports.WorkspaceTerminalReceipt {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef", manifest, "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := ports.AcquireWorkspaceSnapshotLease(context.Background(), func(_ context.Context, binding ports.WorkspaceTerminalBinding) (ports.WorkspaceSnapshotLease, error) {
		release, err := binding.Bind(identity, func(ports.WorkspaceCompletionEvidence) error { return nil })
		if err != nil {
			return nil, err
		}
		return recoveryReceiptLease{identity: identity, release: release}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := ports.NewWorkspaceCompletionEvidence(identity, runID.String(), ports.NewEmptyProviderRunTerminalReceipt())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := lease.Release(completion)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func failedRecoveryCoordinator(t *testing.T, condition review.AttemptCondition) (review.CoordinatorResult, domain.TargetIdentity, []review.RuntimeArtifactInventory, []domain.Role) {
	return failedRecoveryCoordinatorForRoles(t, condition, []domain.Role{domain.RoleLogic, domain.RoleDocumentation, domain.RoleTesting})
}

func failedRecoveryCoordinatorForRoles(t *testing.T, condition review.AttemptCondition, roles []domain.Role) (review.CoordinatorResult, domain.TargetIdentity, []review.RuntimeArtifactInventory, []domain.Role) {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("immutable target"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	capturedEvidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, capturedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	ids := &failedRecoveryIDs{}
	source := failedRecoveryPromptSource{target: target.Bytes(), archive: archive, ids: ids}
	verifier, err := evidence.NewVerifier(publicationEvidenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := review.NewProviderInvocationRuntime(failedRecoveryProvider{}, source, &validation.ReviewValidator{}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	faultRuntime := &failedRecoveryRuntime{runtime: runtime, condition: condition}
	var assignments []review.Assignment
	var budgets []review.RoleBudget
	for _, role := range roles {
		route, err := ports.NewProviderRoute("provider-" + string(role))
		if err != nil {
			t.Fatal(err)
		}
		assignment, err := review.NewScheduledAssignment(role, true, route)
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
		limits, err := review.NewInvocationLimits(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		routeBudget, err := review.NewRouteBudget(route, limits)
		if err != nil {
			t.Fatal(err)
		}
		budget, err := review.NewRoleBudget(role, routeBudget)
		if err != nil {
			t.Fatal(err)
		}
		budgets = append(budgets, budget)
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(budgets, review.DefaultHarnessCeilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := review.NewCoordinator(publicationServiceClock{now: publicationTestTime()}, ids, faultRuntime, 1, receipt)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(context.Background(), target.Identity(), assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result, target.Identity(), runtime.DrainInitialInputsForRun(result.RunID()), faultRuntime.calls
}

type failedRecoveryRuntime struct {
	runtime   *review.ProviderInvocationRuntime
	condition review.AttemptCondition
	calls     []domain.Role
}

func (runtime *failedRecoveryRuntime) PrepareInitial(ctx context.Context, jobs []review.InvocationJob) error {
	return runtime.runtime.PrepareInitial(ctx, jobs)
}
func (runtime *failedRecoveryRuntime) Invoke(ctx context.Context, job review.InvocationJob) review.AttemptOutcome {
	runtime.calls = append(runtime.calls, job.Role())
	if job.Role() == domain.RoleTesting {
		<-ctx.Done()
		condition := review.AttemptConditionCancelled
		result, _ := review.NewAttemptOutcome(job, nil, &condition)
		return result
	}
	if job.Role() != domain.RoleLogic {
		result, _ := review.NewAttemptOutcome(job, nil, &runtime.condition)
		return result
	}
	output, err := review.NewValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), nil, "complete", nil)
	if err != nil {
		panic(err)
	}
	result, err := review.NewAttemptOutcome(job, &output, nil)
	if err != nil {
		panic(err)
	}
	return result
}

type failedRecoveryProvider struct{}

func (failedRecoveryProvider) Invoke(context.Context, ports.ProviderInvocation) (ports.ProviderResult, error) {
	return ports.ProviderResult{}, fmt.Errorf("unexpected real provider invocation")
}

type failedRecoveryPromptSource struct {
	target, archive []byte
	ids             *failedRecoveryIDs
}

func (source failedRecoveryPromptSource) Prompt(_ context.Context, job review.InvocationJob, _ *review.InvocationRepairInput) (review.RuntimePrompt, error) {
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

type failedRecoveryIDs struct{ next int }

func (ids *failedRecoveryIDs) uuid() string {
	ids.next++
	return fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", ids.next)
}
func (ids *failedRecoveryIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.uuid())
}
func (ids *failedRecoveryIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.uuid())
}
func (ids *failedRecoveryIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.uuid())
}
func (ids *failedRecoveryIDs) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_" + ids.uuid())
}
func (ids *failedRecoveryIDs) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID(ids.uuid())
}
