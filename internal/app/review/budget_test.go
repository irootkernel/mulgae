package review

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPreflightRunBudgetSixRoleFormulaUsesOnePathPerRole(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 24, 4*time.Second, 9*time.Second, 2, 12)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	// Six roles retain one independent initial-to-repair path each.
	if got, want := receipt.TotalInvocations(), 12; got != want {
		t.Fatalf("total invocations = %d, want %d", got, want)
	}
	paths := receipt.RolePathDeadlines()
	if len(paths) != 6 {
		t.Fatalf("role path count = %d, want 6", len(paths))
	}
	for index, path := range paths {
		if path.Role() != domain.CoreRoleOrder()[index] ||
			path.ProviderInstance() != fmt.Sprintf("primary-%d", index) ||
			path.InvocationCount() != 2 ||
			path.TransitionCount() != 1 ||
			path.InvocationTimeouts() != 2*time.Second ||
			path.Deadline() != 4*time.Second {
			t.Fatalf("role path %d = role=%q provider=%q invocations=%d transitions=%d timeouts=%s deadline=%s",
				index, path.Role(), path.ProviderInstance(), path.InvocationCount(), path.TransitionCount(), path.InvocationTimeouts(), path.Deadline())
		}
	}
	if got, want := receipt.RunDeadline(), 9*time.Second; got != want {
		t.Fatalf("run deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetIndependentRolePathsUseMaximumDeadline(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, 3*time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	ceilings := budgetTestCeilings(t, 5*time.Second, 1, 1, 24, 8*time.Second, 13*time.Second, 2, 12)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	paths := receipt.RolePathDeadlines()
	if len(paths) != 6 {
		t.Fatalf("role path count = %d, want one per role (6)", len(paths))
	}
	for _, path := range paths {
		// Two invocations at 3s plus one 2s transition.
		if path.InvocationCount() != 2 || path.TransitionCount() != 1 || path.Deadline() != 8*time.Second {
			t.Fatalf("role path %q = invocations=%d transitions=%d deadline=%s", path.Role(), path.InvocationCount(), path.TransitionCount(), path.Deadline())
		}
	}
	if got, want := receipt.CriticalPathDeadline(), 8*time.Second; got != want {
		t.Fatalf("critical path = %s, want provider+repair %s", got, want)
	}
	if got, want := receipt.RunDeadline(), 13*time.Second; got != want {
		t.Fatalf("run deadline = %s, want critical path plus grace %s", got, want)
	}
}

func TestPreflightRunBudgetCapacityCoversQueueAndRoleDependencyPaths(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, 3*time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	ceilings := budgetTestCeilings(t, 5*time.Second, 1, 1, 24, 30*time.Second, 3*time.Minute, 2, 12)

	// Six 8s role paths: 48s of work on a critical path of 8s. W/C + (1-1/C)L.
	for _, test := range []struct {
		capacity int
		want     time.Duration
	}{
		{capacity: 1, want: 53 * time.Second},
		{capacity: 2, want: 33 * time.Second},
		{capacity: 6, want: 13 * time.Second},
	} {
		receipt, err := PreflightRunBudgetWithCapacity(roles, ceilings, test.capacity)
		if err != nil {
			t.Fatalf("PreflightRunBudgetWithCapacity(%d) error = %v", test.capacity, err)
		}
		if got := receipt.MaxActiveLanes(); got != test.capacity {
			t.Fatalf("capacity = %d, want %d", got, test.capacity)
		}
		if got := receipt.CriticalPathDeadline(); got != 8*time.Second {
			t.Fatalf("critical path = %s, want 8s", got)
		}
		if got := receipt.RunDeadline(); got != test.want {
			t.Fatalf("capacity %d run deadline = %s, want %s", test.capacity, got, test.want)
		}
	}
}

func TestPreflightRunBudgetAcceptsThirtyAndSixtyMinuteProviderBoundaries(t *testing.T) {
	t.Parallel()

	for _, timeout := range []time.Duration{30 * time.Minute, 60 * time.Minute} {
		limits := budgetTestLimits(t, timeout, 1, 1)
		primary := budgetTestRoute(t, "primary", limits)
		roles := []RoleBudget{budgetTestRole(t, domain.RoleLogic, primary)}

		receipt, err := PreflightRunBudgetWithCapacity(roles, DefaultHarnessCeilings(), 1)
		if err != nil {
			t.Fatalf("timeout %s rejected: %v", timeout, err)
		}
		wantRolePath := 2*timeout + budgetTransitionGrace
		if got := receipt.RolePathDeadlines()[0].Deadline(); got != wantRolePath {
			t.Fatalf("timeout %s role path deadline = %s, want %s", timeout, got, wantRolePath)
		}
		if got := receipt.RunDeadline(); got != wantRolePath+budgetRunGrace {
			t.Fatalf("timeout %s run deadline = %s, want %s", timeout, got, wantRolePath+budgetRunGrace)
		}
	}

	over := budgetTestLimits(t, 60*time.Minute+time.Nanosecond, 1, 1)
	roles := []RoleBudget{budgetTestRole(t, domain.RoleLogic, budgetTestRoute(t, "primary-over", over))}
	receipt, err := PreflightRunBudgetWithCapacity(roles, DefaultHarnessCeilings(), 1)
	if err == nil || receipt.ReasonCode() != BudgetReasonInvocationCapExceeded {
		t.Fatalf("one-over timeout = error:%v reason:%q", err, receipt.ReasonCode())
	}
}

func TestPreflightRunBudgetAcceptsProductionSixRoleTopology(t *testing.T) {
	t.Parallel()

	standard := budgetTestLimits(t, 4*time.Minute, 256<<10, 256<<10)
	zcode := budgetTestLimits(t, 6*time.Minute, 256<<10, 256<<10)
	route := func(instance string) RouteBudget {
		t.Helper()
		limits := standard
		if len(instance) >= len("zcode-") && instance[:len("zcode-")] == "zcode-" {
			limits = zcode
		}
		return budgetTestRoute(t, instance, limits)
	}
	role := func(name domain.Role, primary string) RoleBudget {
		t.Helper()
		return budgetTestRole(t, name, route(primary))
	}
	roles := []RoleBudget{
		role(domain.RoleLogic, "kimi-logic"),
		role(domain.RoleSecurity, "zcode-security"),
		role(domain.RoleMaintainability, "zcode-maintainability"),
		role(domain.RoleProduct, "zcode-product"),
		role(domain.RoleDocumentation, "agy-documentation"),
		role(domain.RoleTesting, "zcode-testing"),
	}

	receipt, err := PreflightRunBudget(roles, DefaultHarnessCeilings())
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	if !receipt.Eligible() || receipt.TotalInvocations() != 12 {
		t.Fatalf("production receipt = eligible=%t reason=%q invocations=%d",
			receipt.Eligible(), receipt.ReasonCode(), receipt.TotalInvocations())
	}
	// One path per role: two invocations plus one transition each.
	wantDeadlines := map[string]time.Duration{
		"kimi-logic":            8*time.Minute + 2*time.Second,
		"zcode-security":        12*time.Minute + 2*time.Second,
		"zcode-maintainability": 12*time.Minute + 2*time.Second,
		"zcode-product":         12*time.Minute + 2*time.Second,
		"agy-documentation":     8*time.Minute + 2*time.Second,
		"zcode-testing":         12*time.Minute + 2*time.Second,
	}
	for _, path := range receipt.RolePathDeadlines() {
		want, ok := wantDeadlines[path.ProviderInstance()]
		if !ok || path.Deadline() != want {
			t.Fatalf("role path %q deadline = %s, want %s", path.ProviderInstance(), path.Deadline(), want)
		}
		delete(wantDeadlines, path.ProviderInstance())
	}
	if len(wantDeadlines) != 0 {
		t.Fatalf("missing production role path deadlines: %v", wantDeadlines)
	}
	if got, want := receipt.RunDeadline(), 12*time.Minute+7*time.Second; got != want {
		t.Fatalf("production run deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetRolePathAndRunDeadlineOneOver(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	// Every role path needs 4s and the run 9s; each ceiling is one second short.
	pathCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 24, 3*time.Second, 9*time.Second, 2, 12)
	pathRejected, err := PreflightRunBudget(roles, pathCeiling)
	if err == nil || pathRejected.ReasonCode() != BudgetReasonRolePathDeadlineLimit {
		t.Fatalf("role path one-over = error=%v reason=%q", err, pathRejected.ReasonCode())
	}
	if got, want := pathRejected.RunDeadline(), 9*time.Second; got != want {
		t.Fatalf("role-path-rejected run deadline = %s, want %s", got, want)
	}

	runCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 24, 4*time.Second, 8*time.Second, 2, 12)
	runRejected, err := PreflightRunBudget(roles, runCeiling)
	if err == nil || runRejected.ReasonCode() != BudgetReasonRunDeadlineLimit {
		t.Fatalf("run one-over = error=%v reason=%q", err, runRejected.ReasonCode())
	}
	if got, want := runRejected.RunDeadline(), 9*time.Second; got != want {
		t.Fatalf("run-rejected deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetCanonicalizesShuffledInputs(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, 2*time.Second, 2, 3)
	roles := budgetTestCompleteRoles(t, limits)
	shuffled := []RoleBudget{roles[5], roles[2], roles[0], roles[4], roles[1], roles[3]}
	ceilings := budgetTestCeilings(t, 3*time.Second, 4, 5, 200, time.Minute, 2*time.Minute, 2, 12)

	first, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget(ordered) error = %v", err)
	}
	second, err := PreflightRunBudget(shuffled, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget(shuffled) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("canonical receipts differ\nordered: %#v\nshuffled: %#v", first, second)
	}
	for index, role := range domain.CoreRoleOrder() {
		if got := first.RoleBudgets()[index].Role(); got != role {
			t.Fatalf("canonical role %d = %q, want %q", index, got, role)
		}
	}
}

func TestPreflightRunBudgetAcceptsRoleSubsetsAndRejectsInvalidSelection(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 2, 12)

	for _, selected := range [][]RoleBudget{
		roles[:2],
		roles[:3],
	} {
		receipt, err := PreflightRunBudget(selected, ceilings)
		if err != nil {
			t.Fatalf("PreflightRunBudget(%d roles) error = %v", len(selected), err)
		}
		if !receipt.Eligible() || receipt.ReasonCode() != BudgetReasonEligible {
			t.Fatalf("PreflightRunBudget(%d roles) = eligible=%t reason=%q, want true/%q",
				len(selected), receipt.Eligible(), receipt.ReasonCode(), BudgetReasonEligible)
		}
	}

	duplicate := append(append([]RoleBudget(nil), roles...), roles[0])
	assertBudgetRejection(t, duplicate, ceilings, BudgetReasonDuplicateRole)

	optionalOnly, err := PreflightRunBudget(roles[5:], ceilings)
	if err != nil || !optionalOnly.Eligible() {
		t.Fatalf("optional-only subset rejected: receipt=%#v error=%v", optionalOnly, err)
	}

	invalidRole := append([]RoleBudget(nil), roles...)
	invalidRole[0].role = domain.Role("invalid")
	assertBudgetRejection(t, invalidRole, ceilings, BudgetReasonInvalidRole)

	invalidPrimary := append([]RoleBudget(nil), roles...)
	invalidPrimary[0].primary = RouteBudget{}
	assertBudgetRejection(t, invalidPrimary, ceilings, BudgetReasonInvalidPrimaryRoute)

}

func TestRunBudgetReceiptDefensiveCopies(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits)
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 2, 12)
	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}

	roles[0] = RoleBudget{}
	copiedRoles := receipt.RoleBudgets()
	copiedRoles[0] = RoleBudget{}
	if got, want := receipt.RoleBudgets()[0].Role(), domain.RoleLogic; got != want {
		t.Fatalf("role getter leaked a mutable slice: got %q, want %q", got, want)
	}

	copiedPaths := receipt.RolePathDeadlines()
	copiedPaths[0] = RolePathDeadline{}
	paths := receipt.RolePathDeadlines()
	if len(paths) != 6 || paths[0].Role() != domain.RoleLogic {
		t.Fatalf("role path getter leaked a mutable slice: %#v", paths)
	}
}
func TestDefaultHarnessCeilingsAreClosedAndValid(t *testing.T) {
	t.Parallel()

	ceilings := DefaultHarnessCeilings()
	if !ceilings.Valid() {
		t.Fatal("DefaultHarnessCeilings() returned invalid ceilings")
	}
	if ceilings.MaxInvocationsPerRole() != 2 ||
		ceilings.MaxInvocationsPerRun() != 14 ||
		ceilings.MaxTimeout() != 60*time.Minute ||
		ceilings.MaxRolePathDeadline() != 14*time.Hour+14*time.Second ||
		ceilings.MaxRunDeadline() != 14*time.Hour+19*time.Second {
		t.Fatalf("default ceilings = role=%d run=%d timeout=%s role_path=%s deadline=%s",
			ceilings.MaxInvocationsPerRole(),
			ceilings.MaxInvocationsPerRun(),
			ceilings.MaxTimeout(),
			ceilings.MaxRolePathDeadline(),
			ceilings.MaxRunDeadline())
	}
}
func TestNewHarnessCeilingsRejectsOneOverFixedSOTMaxima(t *testing.T) {
	t.Parallel()

	type ceilingInput struct {
		maxTimeout            time.Duration
		maxRolePathDeadline   time.Duration
		maxRunDeadline        time.Duration
		maxInvocationsPerRole int
		maxInvocationsPerRun  int
	}
	exactRolePathDeadline, overflow := topologyDeadlineCeiling(maxBudgetProviderTimeout, maxBudgetInvocationsPerRun)
	if overflow {
		t.Fatal("exact topology ceiling overflowed")
	}
	exactRunDeadline, overflow := addDuration(exactRolePathDeadline, budgetRunGrace)
	if overflow {
		t.Fatal("exact run ceiling overflowed")
	}
	exact := ceilingInput{
		maxTimeout:            maxBudgetProviderTimeout,
		maxRolePathDeadline:   exactRolePathDeadline,
		maxRunDeadline:        exactRunDeadline,
		maxInvocationsPerRole: maxBudgetInvocationsPerRole,
		maxInvocationsPerRun:  maxBudgetInvocationsPerRun,
	}
	construct := func(input ceilingInput) (HarnessCeilings, error) {
		return NewHarnessCeilings(
			input.maxTimeout,
			input.maxRolePathDeadline,
			input.maxRunDeadline,
			input.maxInvocationsPerRole,
			input.maxInvocationsPerRun,
		)
	}

	accepted, err := construct(exact)
	if err != nil || !accepted.Valid() {
		t.Fatalf("exact fixed ceilings rejected: ceilings=%#v error=%v", accepted, err)
	}

	for _, test := range []struct {
		name   string
		change func(*ceilingInput)
	}{
		{
			name: "provider timeout",
			change: func(input *ceilingInput) {
				input.maxTimeout = maxBudgetProviderTimeout + time.Nanosecond
			},
		},
		{
			name: "role invocations",
			change: func(input *ceilingInput) {
				input.maxInvocationsPerRole = maxBudgetInvocationsPerRole + 1
			},
		},
		{
			name: "run invocations",
			change: func(input *ceilingInput) {
				input.maxInvocationsPerRun = maxBudgetInvocationsPerRun + 1
			},
		},
		{
			name: "role path deadline",
			change: func(input *ceilingInput) {
				input.maxRolePathDeadline = exactRolePathDeadline + time.Nanosecond
			},
		},
		{
			name: "run deadline",
			change: func(input *ceilingInput) {
				input.maxRunDeadline = exactRunDeadline + time.Nanosecond
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := exact
			test.change(&input)
			ceilings, err := construct(input)
			if err == nil {
				t.Fatalf("NewHarnessCeilings() accepted one-over %s: %#v", test.name, ceilings)
			}
			if ceilings != (HarnessCeilings{}) {
				t.Fatalf("NewHarnessCeilings() returned nonzero ceilings after rejection: %#v", ceilings)
			}
		})
	}
}

func budgetTestLimits(t *testing.T, timeout time.Duration, _ ...int64) InvocationLimits {
	t.Helper()
	limits, err := NewInvocationLimits(timeout)
	if err != nil {
		t.Fatalf("NewInvocationLimits() error = %v", err)
	}
	return limits
}

func budgetTestRoute(t *testing.T, providerInstance string, limits InvocationLimits) RouteBudget {
	t.Helper()
	route, err := ports.NewProviderRoute(providerInstance)
	if err != nil {
		t.Fatalf("NewProviderRoute(%q) error = %v", providerInstance, err)
	}
	budget, err := NewRouteBudget(route, limits)
	if err != nil {
		t.Fatalf("NewRouteBudget() error = %v", err)
	}
	return budget
}

func budgetTestRole(t *testing.T, role domain.Role, primary RouteBudget) RoleBudget {
	t.Helper()
	budget, err := NewRoleBudget(role, primary)
	if err != nil {
		t.Fatalf("NewRoleBudget(%q) error = %v", role, err)
	}
	return budget
}

func budgetTestCompleteRoles(t *testing.T, limits InvocationLimits) []RoleBudget {
	t.Helper()
	roles := make([]RoleBudget, 0, len(domain.CoreRoleOrder()))
	for index, role := range domain.CoreRoleOrder() {
		primary := budgetTestRoute(t, fmt.Sprintf("primary-%d", index), limits)
		roles = append(roles, budgetTestRole(t, role, primary))
	}
	return roles
}

func budgetTestCeilings(
	t *testing.T,
	maxTimeout time.Duration,
	_, _, _ int64,
	maxRolePathDeadline, maxRunDeadline time.Duration,
	maxInvocationsPerRole, maxInvocationsPerRun int,
) HarnessCeilings {
	t.Helper()
	ceilings, err := NewHarnessCeilings(
		maxTimeout,
		maxRolePathDeadline,
		maxRunDeadline,
		maxInvocationsPerRole,
		maxInvocationsPerRun,
	)
	if err != nil {
		t.Fatalf("NewHarnessCeilings() error = %v", err)
	}
	return ceilings
}

func assertBudgetRejection(t *testing.T, roles []RoleBudget, ceilings HarnessCeilings, want BudgetReasonCode) {
	t.Helper()
	receipt, err := PreflightRunBudget(roles, ceilings)
	if err == nil {
		t.Fatalf("PreflightRunBudget() succeeded, want reason %q", want)
	}
	if receipt.Eligible() || receipt.ReasonCode() != want {
		t.Fatalf("receipt = eligible=%t reason=%q, want false/%q", receipt.Eligible(), receipt.ReasonCode(), want)
	}
}
