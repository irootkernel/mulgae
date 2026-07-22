package review

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestPreflightRunBudgetExactOutputBoundaryAndCapOneOver(t *testing.T) {
	t.Parallel()

	const mib = int64(1 << 20)
	ceilings := budgetTestCeilings(t, time.Second, 11*mib-1, 1, 64*mib, 2*time.Minute, 3*time.Minute, 4, 24)
	roles := make([]RoleBudget, 0, len(domain.FixedRoleOrder()))
	for index, role := range domain.FixedRoleOrder() {
		outputCap := mib
		if index == 0 {
			outputCap = 11 * mib
		}
		limits := budgetTestLimits(t, time.Second, outputCap-1, 1)
		primary := budgetTestRoute(t, fmt.Sprintf("primary-%d", index), "shared", limits)
		fallback := budgetTestRoute(t, fmt.Sprintf("fallback-%d", index), "shared", limits)
		roles = append(roles, budgetTestRole(t, role, primary, &fallback))
	}

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	if !receipt.Eligible() || receipt.ReasonCode() != BudgetReasonEligible {
		t.Fatalf("receipt eligibility = %t/%q, want true/%q", receipt.Eligible(), receipt.ReasonCode(), BudgetReasonEligible)
	}
	if got, want := receipt.TotalOutputCap(), 64*mib; got != want {
		t.Fatalf("total output cap = %d, want %d", got, want)
	}

	over := append([]RoleBudget(nil), roles...)
	overLimits := budgetTestLimits(t, time.Second, 11*mib, 1)
	over[0].primary = budgetTestRoute(t, "primary-0", "shared", overLimits)
	overFallback := budgetTestRoute(t, "fallback-0", "shared", overLimits)
	over[0].fallback = overFallback
	rejected, err := PreflightRunBudget(over, ceilings)
	if err == nil {
		t.Fatal("PreflightRunBudget() succeeded with a cap one byte over its trusted ceiling")
	}
	if rejected.Eligible() || rejected.ReasonCode() != BudgetReasonInvocationCapExceeded {
		t.Fatalf("rejected receipt = eligible=%t reason=%q", rejected.Eligible(), rejected.ReasonCode())
	}
	if got, want := rejected.TotalOutputCap(), 64*mib+4; got != want {
		t.Fatalf("rejected total output cap = %d, want %d", got, want)
	}
}

func TestPreflightRunBudgetSixRoleFormulaAndSharedLaneDeadline(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, limits, func(int) string { return "shared" }, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 65*time.Second, 4, 24)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	if got, want := receipt.TotalInvocations(), 24; got != want {
		t.Fatalf("total invocations = %d, want %d", got, want)
	}
	if got, want := receipt.TotalOutputCap(), int64(48); got != want {
		t.Fatalf("total output cap = %d, want %d", got, want)
	}
	lanes := receipt.LaneDeadlines()
	if len(lanes) != 1 {
		t.Fatalf("lane count = %d, want 1", len(lanes))
	}
	lane := lanes[0]
	if lane.ConcurrencyKey().String() != "shared" ||
		lane.InvocationCount() != 24 ||
		lane.TransitionCount() != 18 ||
		lane.InvocationTimeouts() != 24*time.Second ||
		lane.Deadline() != time.Minute {
		t.Fatalf("shared lane = key=%q invocations=%d transitions=%d timeouts=%s deadline=%s",
			lane.ConcurrencyKey().String(), lane.InvocationCount(), lane.TransitionCount(), lane.InvocationTimeouts(), lane.Deadline())
	}
	if got, want := receipt.RunDeadline(), 65*time.Second; got != want {
		t.Fatalf("run deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetIndependentLanesUseMaximumDeadline(t *testing.T) {
	t.Parallel()

	primaryLimits := budgetTestLimits(t, 3*time.Second, 1, 1)
	fallbackLimits := budgetTestLimits(t, 5*time.Second, 1, 1)
	roles := budgetTestCompleteRoles(
		t,
		primaryLimits,
		fallbackLimits,
		func(index int) string { return fmt.Sprintf("primary-%d", index) },
		func(index int) string { return fmt.Sprintf("fallback-%d", index) },
	)
	ceilings := budgetTestCeilings(t, 5*time.Second, 1, 1, 48, 12*time.Second, 17*time.Second, 4, 24)

	receipt, err := PreflightRunBudget(roles, ceilings)
	if err != nil {
		t.Fatalf("PreflightRunBudget() error = %v", err)
	}
	lanes := receipt.LaneDeadlines()
	if len(lanes) != 12 {
		t.Fatalf("lane count = %d, want 12", len(lanes))
	}
	for _, lane := range lanes {
		switch {
		case len(lane.ConcurrencyKey().String()) >= len("primary-") && lane.ConcurrencyKey().String()[:len("primary-")] == "primary-":
			if lane.InvocationCount() != 2 || lane.TransitionCount() != 2 || lane.Deadline() != 10*time.Second {
				t.Fatalf("primary lane %q = invocations=%d transitions=%d deadline=%s", lane.ConcurrencyKey().String(), lane.InvocationCount(), lane.TransitionCount(), lane.Deadline())
			}
		case len(lane.ConcurrencyKey().String()) >= len("fallback-") && lane.ConcurrencyKey().String()[:len("fallback-")] == "fallback-":
			if lane.InvocationCount() != 2 || lane.TransitionCount() != 1 || lane.Deadline() != 12*time.Second {
				t.Fatalf("fallback lane %q = invocations=%d transitions=%d deadline=%s", lane.ConcurrencyKey().String(), lane.InvocationCount(), lane.TransitionCount(), lane.Deadline())
			}
		default:
			t.Fatalf("unexpected lane %q", lane.ConcurrencyKey().String())
		}
	}
	if got, want := receipt.RunDeadline(), 17*time.Second; got != want {
		t.Fatalf("run deadline = %s, want maximum lane plus grace %s", got, want)
	}
}

func TestPreflightRunBudgetLaneAndRunDeadlineOneOver(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, limits, func(int) string { return "shared" }, func(int) string { return "shared" })
	laneCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 48, 59*time.Second, 65*time.Second, 4, 24)
	laneRejected, err := PreflightRunBudget(roles, laneCeiling)
	if err == nil || laneRejected.ReasonCode() != BudgetReasonLaneDeadlineLimit {
		t.Fatalf("lane one-over = error=%v reason=%q", err, laneRejected.ReasonCode())
	}
	if got, want := laneRejected.RunDeadline(), 65*time.Second; got != want {
		t.Fatalf("lane-rejected run deadline = %s, want %s", got, want)
	}

	runCeiling := budgetTestCeilings(t, 2*time.Second, 1, 1, 48, time.Minute, 64*time.Second, 4, 24)
	runRejected, err := PreflightRunBudget(roles, runCeiling)
	if err == nil || runRejected.ReasonCode() != BudgetReasonRunDeadlineLimit {
		t.Fatalf("run one-over = error=%v reason=%q", err, runRejected.ReasonCode())
	}
	if got, want := runRejected.RunDeadline(), 65*time.Second; got != want {
		t.Fatalf("run-rejected deadline = %s, want %s", got, want)
	}
}

func TestPreflightRunBudgetCanonicalizesShuffledInputs(t *testing.T) {
	t.Parallel()

	primaryLimits := budgetTestLimits(t, 2*time.Second, 2, 3)
	fallbackLimits := budgetTestLimits(t, 3*time.Second, 4, 5)
	roles := budgetTestCompleteRoles(
		t,
		primaryLimits,
		fallbackLimits,
		func(index int) string { return fmt.Sprintf("primary-%d", index) },
		func(index int) string { return fmt.Sprintf("fallback-%d", index) },
	)
	shuffled := []RoleBudget{roles[5], roles[2], roles[0], roles[4], roles[1], roles[3]}
	ceilings := budgetTestCeilings(t, 3*time.Second, 4, 5, 200, time.Minute, 2*time.Minute, 4, 24)

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
	for index, role := range domain.FixedRoleOrder() {
		if got := first.RoleBudgets()[index].Role(); got != role {
			t.Fatalf("canonical role %d = %q, want %q", index, got, role)
		}
	}
}

func TestPreflightRunBudgetAcceptsRoleSubsetsAndRejectsInvalidSelection(t *testing.T) {
	t.Parallel()

	limits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, limits, limits, func(int) string { return "shared" }, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 4, 24)

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

	missingLogic := append([]RoleBudget(nil), roles[1:]...)
	assertBudgetRejection(t, missingLogic, ceilings, BudgetReasonMissingRequiredRole)

	missingSecurity := append([]RoleBudget{roles[0]}, roles[2:]...)
	assertBudgetRejection(t, missingSecurity, ceilings, BudgetReasonMissingRequiredRole)

	invalidRole := append([]RoleBudget(nil), roles...)
	invalidRole[0].role = domain.Role("invalid")
	assertBudgetRejection(t, invalidRole, ceilings, BudgetReasonInvalidRole)

	invalidPrimary := append([]RoleBudget(nil), roles...)
	invalidPrimary[0].primary = RouteBudget{}
	assertBudgetRejection(t, invalidPrimary, ceilings, BudgetReasonInvalidPrimaryRoute)

	invalidFallback := append([]RoleBudget(nil), roles...)
	invalidFallback[0].fallback = RouteBudget{}
	assertBudgetRejection(t, invalidFallback, ceilings, BudgetReasonInvalidFallbackRoute)
}

func TestPreflightRunBudgetRejectsRouteCapOverflow(t *testing.T) {
	t.Parallel()

	primaryLimits := budgetTestLimits(t, time.Second, 2, 1)
	fallbackLimits := budgetTestLimits(t, time.Second, 1, 1)
	roles := budgetTestCompleteRoles(t, primaryLimits, fallbackLimits, func(int) string { return "shared" }, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 4, 24)

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
	roles := budgetTestCompleteRoles(t, limits, limits, func(int) string { return "shared" }, func(int) string { return "shared" })
	ceilings := budgetTestCeilings(t, time.Second, 1, 1, 48, time.Minute, 2*time.Minute, 4, 24)
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
	if ceilings.MaxInvocationsPerRole() != 4 ||
		ceilings.MaxInvocationsPerRun() != 24 ||
		ceilings.MaxTimeout() != 4*time.Minute ||
		ceilings.MaxTotalOutput() != 64<<20 ||
		ceilings.MaxRunDeadline() != 50*time.Minute {
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
	exact := ceilingInput{
		maxTimeout:            180 * time.Second,
		maxStdout:             256 << 10,
		maxStderr:             256 << 10,
		maxTotalOutput:        maxBudgetTotalOutputBytes,
		maxLaneDeadline:       maxBudgetRunDeadline,
		maxRunDeadline:        maxBudgetRunDeadline,
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
				input.maxLaneDeadline = maxBudgetRunDeadline + time.Nanosecond
			},
		},
		{
			name: "run deadline",
			change: func(input *ceilingInput) {
				input.maxRunDeadline = maxBudgetRunDeadline + time.Nanosecond
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

func budgetTestRole(t *testing.T, role domain.Role, primary RouteBudget, fallback *RouteBudget) RoleBudget {
	t.Helper()
	budget, err := NewRoleBudget(role, primary, fallback)
	if err != nil {
		t.Fatalf("NewRoleBudget(%q) error = %v", role, err)
	}
	return budget
}

func budgetTestCompleteRoles(
	t *testing.T,
	primaryLimits, fallbackLimits InvocationLimits,
	primaryLane, fallbackLane func(int) string,
) []RoleBudget {
	t.Helper()
	roles := make([]RoleBudget, 0, len(domain.FixedRoleOrder()))
	for index, role := range domain.FixedRoleOrder() {
		primary := budgetTestRoute(t, fmt.Sprintf("primary-%d", index), primaryLane(index), primaryLimits)
		fallback := budgetTestRoute(t, fmt.Sprintf("fallback-%d", index), fallbackLane(index), fallbackLimits)
		roles = append(roles, budgetTestRole(t, role, primary, &fallback))
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
