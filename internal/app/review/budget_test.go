package review

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPreflightRunBudgetExactOutputBoundaryAndCapOneOver(t *testing.T) {
	t.Parallel()

	const mib = int64(1 << 20)
	ceilings := budgetTestCeilings(t, time.Second, 11*mib-1, 1, 32*mib, 2*time.Minute, 3*time.Minute, 2, 12)
	roles := make([]RoleBudget, 0, len(domain.CoreRoleOrder()))
	for index, role := range domain.CoreRoleOrder() {
		outputCap := mib
		if index == 0 {
			outputCap = 11 * mib
		}
		limits := budgetTestLimits(t, time.Second, outputCap-1, 1)
		primary := budgetTestRoute(t, fmt.Sprintf("primary-%d", index), "shared", limits)
		roles = append(roles, budgetTestRole(t, role, primary))
	}

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	if !receipt.Eligible() || receipt.ReasonCode() != BudgetReasonEligible {
		t.Fatalf("receipt eligibility = %t/%q, want true/%q", receipt.Eligible(), receipt.ReasonCode(), BudgetReasonEligible)
	}
	if got, want := receipt.TotalOutputCap(), 32*mib; got != want {
		t.Fatalf("total output cap = %d, want %d", got, want)
	}

	over := append([]RoleBudget(nil), roles...)
	overLimits := budgetTestLimits(t, time.Second, 11*mib, 1)
	over[0].primary = budgetTestRoute(t, "primary-0", "shared", overLimits)
	rejected, err := PreflightRunBudget(over, ceilings)
	if err == nil {
		t.Fatal("PreflightRunBudget() succeeded with a cap one byte over its trusted ceiling")
	}
	if rejected.Eligible() || rejected.ReasonCode() != BudgetReasonInvocationCapExceeded {
		t.Fatalf("rejected receipt = eligible=%t reason=%q", rejected.Eligible(), rejected.ReasonCode())
	}
	if got, want := rejected.TotalOutputCap(), 32*mib+2; got != want {
		t.Fatalf("rejected total output cap = %d, want %d", got, want)
	}
}

func TestPreflightRunBudgetSixRoleFormulaAndSharedLaneDeadline(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 24, 24*time.Second, 29*time.Second, 2, 12)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	// Six roles, two invocations and one transition each, all on one lane.
	if got, want := receipt.TotalInvocations(), 12; got != want {
		t.Fatalf("total invocations = %d, want %d", got, want)
	}
	if got, want := receipt.TotalOutputCap(), int64(24); got != want {
		t.Fatalf("total output cap = %d, want %d", got, want)
	}
	lanes := receipt.LaneDeadlines()
	if len(lanes) != 1 {
		t.Fatalf("lane count = %d, want 1", len(lanes))
	}
	lane := lanes[0]
	if lane.ConcurrencyKey().String() != "shared" ||
		lane.InvocationCount() != 12 ||
		lane.TransitionCount() != 6 ||
		lane.InvocationTimeouts() != 12*time.Second ||
		lane.Deadline() != 24*time.Second {
		t.Fatalf("shared lane = key=%q invocations=%d transitions=%d timeouts=%s deadline=%s",
			lane.ConcurrencyKey().String(), lane.InvocationCount(), lane.TransitionCount(), lane.InvocationTimeouts(), lane.Deadline())
	}
	if got, want := receipt.RunDeadline(), 29*time.Second; got != want {
		t.Fatalf("run deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetIndependentLanesUseMaximumDeadline(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, 3*time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, func(index int) string { return fmt.Sprintf("primary-%d", index) })
	ceilings := budgetTestCeilings(t, 5*time.Second, 1, 1, 24, 8*time.Second, 13*time.Second, 2, 12)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	lanes := receipt.LaneDeadlines()
	if len(lanes) != 6 {
		t.Fatalf("lane count = %d, want one per role (6)", len(lanes))
	}
	for _, lane := range lanes {
		// Two invocations at 3s plus one 2s transition.
		if lane.InvocationCount() != 2 || lane.TransitionCount() != 1 || lane.Deadline() != 8*time.Second {
			t.Fatalf("lane %q = invocations=%d transitions=%d deadline=%s", lane.ConcurrencyKey().String(), lane.InvocationCount(), lane.TransitionCount(), lane.Deadline())
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
	roles := budgetTestCompleteRoles(t, limits, func(index int) string { return fmt.Sprintf("capacity-primary-%d", index) })
	ceilings := budgetTestCeilings(t, 5*time.Second, 1, 1, 24, 30*time.Second, 3*time.Minute, 2, 12)

	// Six 8s lanes: 48s of work on a critical path of 8s. W/C + (1-1/C)L.
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
		primary := budgetTestRoute(t, "primary", "shared-boundary", limits)
		roles := []RoleBudget{budgetTestRole(t, domain.RoleLogic, primary)}

		receipt, err := PreflightRunBudgetWithCapacity(roles, DefaultHarnessCeilings(), 1)
		if err != nil {
			t.Fatalf("timeout %s rejected: %v", timeout, err)
		}
		wantLane := 2*timeout + budgetTransitionGrace
		if got := receipt.LaneDeadlines()[0].Deadline(); got != wantLane {
			t.Fatalf("timeout %s lane deadline = %s, want %s", timeout, got, wantLane)
		}
		if got := receipt.RunDeadline(); got != wantLane+budgetRunGrace {
			t.Fatalf("timeout %s run deadline = %s, want %s", timeout, got, wantLane+budgetRunGrace)
		}
	}

	over := budgetTestLimits(t, 60*time.Minute+time.Nanosecond, 1, 1)
	roles := []RoleBudget{budgetTestRole(t, domain.RoleLogic, budgetTestRoute(t, "primary-over", "over", over))}
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
		return budgetTestRoute(t, instance, instance, limits)
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
	// One lane per role: two invocations plus one transition each.
	wantDeadlines := map[string]time.Duration{
		"kimi-logic":            8*time.Minute + 2*time.Second,
		"zcode-security":        12*time.Minute + 2*time.Second,
		"zcode-maintainability": 12*time.Minute + 2*time.Second,
		"zcode-product":         12*time.Minute + 2*time.Second,
		"agy-documentation":     8*time.Minute + 2*time.Second,
		"zcode-testing":         12*time.Minute + 2*time.Second,
	}
	for _, lane := range receipt.LaneDeadlines() {
		want, ok := wantDeadlines[lane.ConcurrencyKey().String()]
		if !ok || lane.Deadline() != want {
			t.Fatalf("lane %q deadline = %s, want %s", lane.ConcurrencyKey(), lane.Deadline(), want)
		}
		delete(wantDeadlines, lane.ConcurrencyKey().String())
	}
	if len(wantDeadlines) != 0 {
		t.Fatalf("missing production lane deadlines: %v", wantDeadlines)
	}
	if got, want := receipt.RunDeadline(), 12*time.Minute+7*time.Second; got != want {
		t.Fatalf("production run deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetLaneAndRunDeadlineOneOver(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, func(int) string { return "shared" })
	// The shared lane needs 24s and the run 29s; each ceiling is one second short.
	laneCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 24, 23*time.Second, 29*time.Second, 2, 12)
	laneRejected, err := PreflightRunBudget(roles, laneCeiling)
	if err == nil || laneRejected.ReasonCode() != BudgetReasonLaneDeadlineLimit {
		t.Fatalf("lane one-over = error=%v reason=%q", err, laneRejected.ReasonCode())
	}
	if got, want := laneRejected.RunDeadline(), 29*time.Second; got != want {
		t.Fatalf("lane-rejected run deadline = %s, want %s", got, want)
	}

	runCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 24, 24*time.Second, 28*time.Second, 2, 12)
	runRejected, err := PreflightRunBudget(roles, runCeiling)
	if err == nil || runRejected.ReasonCode() != BudgetReasonRunDeadlineLimit {
		t.Fatalf("run one-over = error=%v reason=%q", err, runRejected.ReasonCode())
	}
	if got, want := runRejected.RunDeadline(), 29*time.Second; got != want {
		t.Fatalf("run-rejected deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetCanonicalizesShuffledInputs(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, 2*time.Second, 2, 3)
	roles := budgetTestCompleteRoles(t, limits, func(index int) string { return fmt.Sprintf("primary-%d", index) })
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
	roles := budgetTestCompleteRoles(t, limits, func(int) string { return "shared" })
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

func TestPreflightRunBudgetRejectsRouteCapOverflow(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 2, 1)
	roles := budgetTestCompleteRoles(t, limits, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 2, 12)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err == nil {
		t.Fatal("PreflightRunBudget() succeeded with a stdout cap over the trusted ceiling")
	}
	if receipt.Eligible() || receipt.ReasonCode() != BudgetReasonInvocationCapExceeded {
		t.Fatalf("receipt = eligible=%t reason=%q", receipt.Eligible(), receipt.ReasonCode())
	}
}

func TestRunBudgetReceiptDefensiveCopies(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, func(int) string { return "shared" })
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

	copiedLanes := receipt.LaneDeadlines()
	copiedLanes[0] = LaneDeadline{}
	lanes := receipt.LaneDeadlines()
	if len(lanes) != 1 || lanes[0].ConcurrencyKey().String() != "shared" {
		t.Fatalf("lane getter leaked a mutable slice: %#v", lanes)
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
		ceilings.MaxTotalOutput() != 64<<20 ||
		ceilings.MaxRunDeadline() != 14*time.Hour+19*time.Second {
		t.Fatalf("default ceilings = role=%d run=%d timeout=%s output=%d deadline=%s",
			ceilings.MaxInvocationsPerRole(),
			ceilings.MaxInvocationsPerRun(),
			ceilings.MaxTimeout(),
			ceilings.MaxTotalOutput(),
			ceilings.MaxRunDeadline())
	}
}
func TestNewHarnessCeilingsRejectsOneOverFixedSOTMaxima(t *testing.T) {
	t.Parallel()

	type ceilingInput struct {
		maxTimeout            time.Duration
		maxStdout             int64
		maxStderr             int64
		maxTotalOutput        int64
		maxLaneDeadline       time.Duration
		maxRunDeadline        time.Duration
		maxInvocationsPerRole int
		maxInvocationsPerRun  int
	}
	exactLaneDeadline, overflow := topologyDeadlineCeiling(maxBudgetProviderTimeout, maxBudgetInvocationsPerRun)
	if overflow {
		t.Fatal("exact topology ceiling overflowed")
	}
	exactRunDeadline, overflow := addDuration(exactLaneDeadline, budgetRunGrace)
	if overflow {
		t.Fatal("exact run ceiling overflowed")
	}
	exact := ceilingInput{
		maxTimeout:            maxBudgetProviderTimeout,
		maxStdout:             256 << 10,
		maxStderr:             256 << 10,
		maxTotalOutput:        maxBudgetTotalOutputBytes,
		maxLaneDeadline:       exactLaneDeadline,
		maxRunDeadline:        exactRunDeadline,
		maxInvocationsPerRole: maxBudgetInvocationsPerRole,
		maxInvocationsPerRun:  maxBudgetInvocationsPerRun,
	}
	construct := func(input ceilingInput) (HarnessCeilings, error) {
		return NewHarnessCeilings(
			input.maxTimeout,
			input.maxStdout,
			input.maxStderr,
			input.maxTotalOutput,
			input.maxLaneDeadline,
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
			name: "total output",
			change: func(input *ceilingInput) {
				input.maxTotalOutput = maxBudgetTotalOutputBytes + 1
			},
		},
		{
			name: "lane deadline",
			change: func(input *ceilingInput) {
				input.maxLaneDeadline = exactLaneDeadline + time.Nanosecond
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

func budgetTestLimits(t *testing.T, timeout time.Duration, stdoutCap, stderrCap int64) InvocationLimits {
	t.Helper()
	limits, err := NewInvocationLimits(timeout, stdoutCap, stderrCap)
	if err != nil {
		t.Fatalf("NewInvocationLimits() error = %v", err)
	}
	return limits
}

func budgetTestRoute(t *testing.T, providerInstance, concurrencyKey string, limits InvocationLimits) RouteBudget {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(concurrencyKey)
	if err != nil {
		t.Fatalf("ParseConcurrencyKey(%q) error = %v", concurrencyKey, err)
	}
	route, err := ports.NewProviderRoute(providerInstance, key)
	if err != nil {
		t.Fatalf("NewProviderRoute(%q, %q) error = %v", providerInstance, concurrencyKey, err)
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

func budgetTestCompleteRoles(t *testing.T, limits InvocationLimits, lane func(int) string) []RoleBudget {
	t.Helper()
	roles := make([]RoleBudget, 0, len(domain.CoreRoleOrder()))
	for index, role := range domain.CoreRoleOrder() {
		primary := budgetTestRoute(t, fmt.Sprintf("primary-%d", index), lane(index), limits)
		roles = append(roles, budgetTestRole(t, role, primary))
	}
	return roles
}

func budgetTestCeilings(
	t *testing.T,
	maxTimeout time.Duration,
	maxStdout, maxStderr, maxTotalOutput int64,
	maxLaneDeadline, maxRunDeadline time.Duration,
	maxInvocationsPerRole, maxInvocationsPerRun int,
) HarnessCeilings {
	t.Helper()
	ceilings, err := NewHarnessCeilings(
		maxTimeout,
		maxStdout,
		maxStderr,
		maxTotalOutput,
		maxLaneDeadline,
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
