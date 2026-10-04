package reviewrun

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCapturedReviewTargetValidatesExactBytesAndGitMetadata(t *testing.T) {
	base := reviewRunObjectID(t, "1")
	head := reviewRunObjectID(t, "2")
	tree := reviewRunObjectID(t, "3")
	input := []byte("diff --git a/a b/a\n")
	target, err := ports.NewCapturedReviewGitTarget("repository:test", base, head, tree, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if got := target.Bytes(); !bytes.Equal(got, []byte("diff --git a/a b/a\n")) {
		t.Fatalf("Bytes() = %q", got)
	}
	returned := target.Bytes()
	returned[0] = 'Y'
	if got := target.Bytes(); got[0] != 'd' {
		t.Fatalf("Bytes() retained accessor mutation: %q", got)
	}
	sum := sha256.Sum256([]byte("diff --git a/a b/a\n"))
	if got, want := target.Identity().SHA256(), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("identity SHA256 = %q, want exact-byte SHA %q", got, want)
	}
	if target.Kind() != domain.TargetGit || target.NoChange() {
		t.Fatalf("Git kind/no-change = %q/%t", target.Kind(), target.NoChange())
	}
	if got, ok := target.RepositoryID(); !ok || got != "repository:test" {
		t.Fatalf("RepositoryID() = %q, %t", got, ok)
	}
	if got, ok := target.BaseObjectID(); !ok || got != base {
		t.Fatalf("BaseObjectID() = %q, %t", got.String(), ok)
	}
	if _, ok := target.IndexTreeID(); ok {
		t.Fatal("IndexTreeID() reported absent index tree")
	}

	empty, err := ports.NewCapturedReviewGitTarget("repository:test", base, head, tree, nil, nil)
	if err != nil || !empty.NoChange() {
		t.Fatalf("empty Git target = %#v, %v", empty, err)
	}
	for _, construct := range []func([]byte) (ports.CapturedReviewTarget, error){ports.NewCapturedReviewPatchTarget, ports.NewCapturedReviewStdinTarget} {
		if _, err := construct(nil); err == nil {
			t.Fatal("empty non-Git input accepted")
		}
		if _, err := construct([]byte{0}); err == nil {
			t.Fatal("NUL input accepted")
		}
		if _, err := construct([]byte{0xff}); err == nil {
			t.Fatal("invalid UTF-8 input accepted")
		}
		if _, err := construct([]byte(strings.Repeat("x", 180000))); err != nil {
			t.Fatalf("180000-byte input rejected: %v", err)
		}
		if target, err := construct([]byte(strings.Repeat("x", 180001))); err != nil || len(target.Bytes()) != 180001 {
			t.Fatalf("180001-byte input rejected: %v", err)
		}
	}
	patch, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := patch.RepositoryID(); ok {
		t.Fatal("non-Git RepositoryID() reported metadata")
	}
	if _, ok := patch.BaseObjectID(); ok {
		t.Fatal("non-Git BaseObjectID() reported metadata")
	}
	if patch.NoChange() {
		t.Fatal("non-Git target reported no change")
	}
}

func TestRunSelectionDefendsOwnedValues(t *testing.T) {
	roles := []domain.Role{domain.RoleSecurity, domain.RoleLogic}
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRunSelection(roles, &session)
	if err != nil {
		t.Fatal(err)
	}
	roles[0] = domain.RoleProduct
	if got := selection.Roles(); !equalRoles(got, []domain.Role{domain.RoleSecurity, domain.RoleLogic}) {
		t.Fatalf("Roles() = %v", got)
	}
	copy := selection.Roles()
	copy[0] = domain.RoleProduct
	if got := selection.Roles(); got[0] != domain.RoleSecurity {
		t.Fatalf("Roles() retained accessor mutation: %v", got)
	}
	if got, ok := selection.SessionID(); !ok || got != session {
		t.Fatalf("SessionID() = %q, %t", got.String(), ok)
	}
	withoutSession, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutSession.SessionID(); ok {
		t.Fatal("nil session reported present")
	}
	for _, roles := range [][]domain.Role{nil, {domain.RoleLogic, domain.RoleLogic}, {domain.Role("invalid")}} {
		if _, err := NewRunSelection(roles, nil); err == nil {
			t.Fatalf("invalid role selection accepted: %v", roles)
		}
	}

}

type reviewRunPromptIssuer struct{}

func (reviewRunPromptIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_019f5a09-5eec-7001-8001-000000000001")
}

func (reviewRunPromptIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID("019f5a09-5eec-7001-8001-000000000002")
}

func reviewRunRoleTask() (prompt.RoleTaskID, error) {
	return prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-000000000003")
}

func reviewRunPromptScope(t *testing.T) prompt.ScopeCoordinates {
	t.Helper()
	session, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000005")
	if err != nil {
		t.Fatal(err)
	}
	roleTask, err := reviewRunRoleTask()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000006")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := prompt.NewScopeCoordinates(session, run, roleTask, attempt)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestValidatePlanRejectsRoleAddDropAndReorder(t *testing.T) {
	requested := []domain.Role{domain.RoleLogic, domain.RoleSecurity}
	valid := reviewRunPlan(t, requested)
	if _, err := validatePlan(valid, append(requested, domain.RoleProduct)); err == nil {
		t.Fatal("added planned role accepted")
	}
	if _, err := validatePlan(valid, requested[:1]); err == nil {
		t.Fatal("dropped planned role accepted")
	}
	if _, err := validatePlan(valid, []domain.Role{domain.RoleSecurity, domain.RoleLogic}); err == nil {
		t.Fatal("reordered planned roles accepted")
	}
}

func reviewRunObjectID(t *testing.T, digit string) ports.GitObjectID {
	t.Helper()
	value, err := ports.ParseGitObjectID(strings.Repeat(digit, 40))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func reviewRunPatchTarget(t *testing.T) ports.CapturedReviewTarget {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func reviewRunPlan(t *testing.T, roles []domain.Role) ExecutionPlan {
	t.Helper()
	limits, err := review.NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assignments := make([]review.Assignment, 0, len(roles))
	budgets := make([]review.RoleBudget, 0, len(roles))
	for _, role := range roles {
		route, err := ports.NewProviderRoute("provider." + string(role))
		if err != nil {
			t.Fatal(err)
		}
		assignment, err := review.NewScheduledAssignment(role, false, route)
		if err != nil {
			t.Fatal(err)
		}
		routeBudget, err := review.NewRouteBudget(assignment.PrimaryRoute(), limits)
		if err != nil {
			t.Fatal(err)
		}
		budget, err := review.NewRoleBudget(role, routeBudget)
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
		budgets = append(budgets, budget)
	}
	return ExecutionPlan{Assignments: assignments, Budgets: budgets, Threshold: domain.SeverityLow, MaxWorkers: 1}
}

func equalRoles(left, right []domain.Role) bool {
	return len(left) == len(right) && func() bool {
		for index := range left {
			if left[index] != right[index] {
				return false
			}
		}
		return true
	}()
}
