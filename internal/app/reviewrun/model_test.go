package reviewrun

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
		if _, err := construct([]byte(strings.Repeat("x", 180001))); err == nil {
			t.Fatal("180001-byte input accepted")
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

func TestRunSelectionAndImmutableInputDefendOwnedValues(t *testing.T) {
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

	target := reviewRunPatchTarget(t)
	objective := []byte("objective")
	projectContext := []byte("context")
	input, err := NewImmutableReviewInput(target, objective, true, projectContext)
	if err != nil {
		t.Fatal(err)
	}
	objective[0], projectContext[0] = 'X', 'X'
	if got := string(input.Objective()); got != "objective" {
		t.Fatalf("Objective() = %q", got)
	}
	contextCopy := input.ProjectContext()
	contextCopy[0] = 'Y'
	if got := string(input.ProjectContext()); got != "context" {
		t.Fatalf("ProjectContext() = %q", got)
	}
	absent, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if absent.HasObjective() || absent.Objective() != nil {
		t.Fatalf("absent objective = present %t, bytes %q", absent.HasObjective(), absent.Objective())
	}
	empty, err := NewImmutableReviewInput(target, []byte{}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.HasObjective() || len(empty.Objective()) != 0 {
		t.Fatalf("present empty objective = present %t, bytes %q", empty.HasObjective(), empty.Objective())
	}
	if _, err := NewImmutableReviewInput(target, []byte("objective"), false, nil); err == nil {
		t.Fatal("absent objective with bytes accepted")
	}
	if _, err := NewImmutableReviewInput(ports.CapturedReviewTarget{}, nil, false, nil); err == nil {
		t.Fatal("zero target accepted")
	}
}
func TestImmutableReviewInputPreservesProjectContextPresence(t *testing.T) {
	target := reviewRunPatchTarget(t)
	for _, test := range []struct {
		name    string
		context []byte
		present bool
	}{
		{name: "absent", context: nil, present: false},
		{name: "present empty", context: []byte{}, present: true},
		{name: "present bytes", context: []byte("context"), present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, err := NewImmutableReviewInputWithProjectContext(target, nil, false, test.context, test.present)
			if err != nil {
				t.Fatal(err)
			}
			if input.HasProjectContext() != test.present {
				t.Fatalf("HasProjectContext() = %t, want %t", input.HasProjectContext(), test.present)
			}
			if test.present && len(test.context) > 0 {
				test.context[0] = 'X'
				if got := string(input.ProjectContext()); got != "context" {
					t.Fatalf("ProjectContext() = %q", got)
				}
				copy := input.ProjectContext()
				copy[0] = 'Y'
				if got := string(input.ProjectContext()); got != "context" {
					t.Fatalf("ProjectContext() retained accessor mutation: %q", got)
				}
			}
			source, err := newPromptSource(input, review.TemplateSet{}, &reviewRunPromptIssuer{}, reviewRunRoleTask)
			if err != nil {
				t.Fatal(err)
			}
			if source.input.HasProjectContext() != test.present {
				t.Fatalf("cloned HasProjectContext() = %t, want %t", source.input.HasProjectContext(), test.present)
			}
		})
	}
	if _, err := NewImmutableReviewInputWithProjectContext(target, nil, false, []byte("context"), false); err == nil {
		t.Fatal("absent project context with bytes accepted")
	}
	absent, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	presentEmpty, err := NewImmutableReviewInput(target, nil, false, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if absent.HasProjectContext() || !presentEmpty.HasProjectContext() {
		t.Fatalf("compatibility constructor presence = absent %t, present empty %t", absent.HasProjectContext(), presentEmpty.HasProjectContext())
	}
}

func TestPromptCompilerProjectContextFramePresence(t *testing.T) {
	template, err := prompt.NewTrustedTemplate("test", "1", []byte("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	scope := reviewRunPromptScope(t)
	target := reviewRunPatchTarget(t)
	for _, test := range []struct {
		name    string
		context []byte
		present bool
		want    int
	}{
		{name: "absent", present: false, want: 0},
		{name: "present empty", context: []byte{}, present: true, want: 1},
		{name: "present bytes", context: []byte("context"), present: true, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, err := NewImmutableReviewInputWithProjectContext(target, nil, false, test.context, test.present)
			if err != nil {
				t.Fatal(err)
			}
			compiler, err := prompt.NewCompiler(template, &reviewRunPromptIssuer{})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := compiler.Compile(compileInputForReview(scope, input, domain.RoleLogic))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, section := range compiled.Sections() {
				if section.Kind() == prompt.SectionProjectContext {
					count++
					if test.name == "present bytes" && string(section.Payload()) != "context" {
						t.Fatalf("project-context payload = %q", section.Payload())
					}
				}
			}
			if count != test.want {
				t.Fatalf("project-context frame count = %d, want %d", count, test.want)
			}
		})
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
	limits, err := review.NewInvocationLimits(time.Second, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	assignments := make([]review.Assignment, 0, len(roles))
	budgets := make([]review.RoleBudget, 0, len(roles))
	for _, role := range roles {
		assignment, err := review.NewAssignment(role, false, "provider."+string(role))
		if err != nil {
			t.Fatal(err)
		}
		routeBudget, err := review.NewRouteBudget(assignment.PrimaryRoute(), limits)
		if err != nil {
			t.Fatal(err)
		}
		budget, err := review.NewRoleBudget(role, routeBudget, nil)
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
		budgets = append(budgets, budget)
	}
	return ExecutionPlan{Assignments: assignments, Budgets: budgets, Threshold: domain.SeverityLow, MaxLanes: 1}
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
