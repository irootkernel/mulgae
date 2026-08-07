package childrun

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/delta"
	"github.com/irootkernel/mulgae/internal/app/rerun"
	"github.com/irootkernel/mulgae/internal/app/review"
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
	primaryKey, _ := ports.ParseConcurrencyKey("primary-lane")
	primary, err := ports.NewProviderRoute("primary", primaryKey)
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
