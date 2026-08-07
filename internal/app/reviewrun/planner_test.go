package reviewrun

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	adapterruntime "github.com/irootkernel/mulgae/internal/adapters/runtime"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type plannerCoordinatorRuntime struct {
	entered chan review.InvocationJob
	release chan struct{}
	mu      sync.Mutex
	jobs    []review.InvocationJob
}

func (runtime *plannerCoordinatorRuntime) Invoke(_ context.Context, job review.InvocationJob) review.AttemptOutcome {
	runtime.mu.Lock()
	runtime.jobs = append(runtime.jobs, job)
	runtime.mu.Unlock()
	runtime.entered <- job
	<-runtime.release
	output, err := review.NewValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), nil, "complete", nil)
	if err != nil {
		condition := review.AttemptConditionInternalInvariant
		outcome, _ := review.NewAttemptOutcome(job, nil, &condition)
		return outcome
	}
	outcome, err := review.NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return review.AttemptOutcome{}
	}
	return outcome
}

func TestQualifiedPlannerGoldenProviderSubsetsAndPermutations(t *testing.T) {
	roles := domain.CoreRoleOrder()
	for _, test := range []struct {
		name     string
		routes   []QualifiedRoute
		want     []string
		fallback []bool
	}{
		{
			name:     "singleton null fallback",
			routes:   []QualifiedRoute{plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles)},
			want:     repeatPlannerTestString("kimi.one", len(roles)),
			fallback: make([]bool, len(roles)),
		},
		{
			name: "all configured providers follow role matrix",
			routes: []QualifiedRoute{
				plannerTestRoute(t, FamilyAGY, "agy.one", "lane-agy", roles),
				plannerTestRoute(t, FamilyZCode, "zcode.one", "lane-zcode", roles),
				plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi-one", roles),
			},
			want:     []string{"kimi.one", "zcode.one", "zcode.one", "zcode.one", "agy.one", "zcode.one"},
			fallback: repeatPlannerTestBool(true, len(roles)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			families := make([]Family, 0, len(test.routes))
			for _, route := range test.routes {
				families = append(families, route.Qualification().Identity().Family)
			}
			planner, err := NewQualifiedPlanner(test.routes, plannerTestCanonicalPolicy(t, families))
			if err != nil {
				t.Fatal(err)
			}
			plan := plannerTestPlan(t, planner, roles)
			got := plannerTestAssignments(plan)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("assignment golden = %v, want %v", got, test.want)
			}
		})
	}
}
func TestQualifiedPlannerGoldenEveryProviderSubset(t *testing.T) {
	roles := domain.CoreRoleOrder()
	families := []Family{FamilyKimi, FamilyZCode, FamilyAGY}
	for mask := 1; mask < 1<<len(families); mask++ {
		routes := make([]QualifiedRoute, 0, len(families))
		selected := make([]Family, 0, len(families))
		for index, family := range families {
			if mask&(1<<index) != 0 {
				selected = append(selected, family)
				routes = append(routes, plannerTestRoute(t, family, string(family)+".one", "lane-"+string(family), roles))
			}
		}
		planner, err := NewQualifiedPlanner(routes, plannerTestCanonicalPolicy(t, selected))
		if err != nil {
			t.Fatalf("subset %03b: %v", mask, err)
		}
		plan := plannerTestPlan(t, planner, roles)
		if _, err := validatePlan(plan, roles); err != nil {
			t.Fatalf("subset %03b plan preflight: %v", mask, err)
		}
	}
}

func TestQualifiedPlannerGoldenInputPermutations(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := []QualifiedRoute{
		plannerTestRoute(t, FamilyAGY, "agy.one", "lane-agy", roles),
		plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles),
		plannerTestRoute(t, FamilyZCode, "zcode.one", "lane-zcode", roles),
	}
	policy := plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY})
	var golden []string
	for _, permutation := range [][]QualifiedRoute{routes, {routes[2], routes[0], routes[1]}, {routes[1], routes[2], routes[0]}} {
		planner, err := NewQualifiedPlanner(permutation, policy)
		if err != nil {
			t.Fatal(err)
		}
		got := plannerTestAssignments(plannerTestPlan(t, planner, roles))
		if golden == nil {
			golden = got
		} else if !reflect.DeepEqual(got, golden) {
			t.Fatalf("permuted routes chose %v, want %v", got, golden)
		}
	}
}

func TestQualifiedPlannerUsesExactConfiguredPrimaryAndFallbackMatrix(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := []QualifiedRoute{
		plannerTestRoute(t, FamilyAGY, "agy.one", "lane-agy", roles),
		plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles),
		plannerTestRoute(t, FamilyZCode, "zcode.one", "lane-zcode", roles),
	}
	planner, err := NewQualifiedPlanner(routes, plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY}))
	if err != nil {
		t.Fatal(err)
	}
	plan := plannerTestPlan(t, planner, roles)
	primary := plannerTestRouteInstances(plan)
	if want := []string{"kimi.one", "zcode.one", "zcode.one", "zcode.one", "agy.one", "zcode.one"}; !reflect.DeepEqual(primary, want) {
		t.Fatalf("primary matrix = %v, want %v", primary, want)
	}
}

func TestQualifiedPlannerUsesProviderRoleRoutesWithoutAmbiguity(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := make([]QualifiedRoute, 0, 12)
	primaryFamilies := []Family{FamilyKimi, FamilyZCode, FamilyZCode, FamilyZCode, FamilyAGY, FamilyZCode}
	fallbackFamilies := []Family{FamilyZCode, FamilyAGY, FamilyAGY, FamilyAGY, FamilyZCode, FamilyAGY}
	for index, role := range roles {
		for _, family := range []Family{primaryFamilies[index], fallbackFamilies[index]} {
			instance := string(family) + "-" + string(role)
			routes = append(routes, plannerTestRoute(t, family, instance, instance, []domain.Role{role}))
		}
	}
	planner, err := NewQualifiedPlanner(routes, plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY}))
	if err != nil {
		t.Fatal(err)
	}
	plan := plannerTestPlan(t, planner, roles)
	primary := plannerTestRouteInstances(plan)
	if want := []string{"kimi-logic", "zcode-security", "zcode-maintainability", "zcode-product", "agy-documentation", "zcode-testing"}; !reflect.DeepEqual(primary, want) {
		t.Fatalf("sharded primary matrix = %v, want %v", primary, want)
	}
	for index, assignment := range plan.Assignments {
		wantPrimary := primary[index]
		if got := assignment.PrimaryRoute().ConcurrencyKey().String(); got != wantPrimary {
			t.Fatalf("primary concurrency key for %q = %q, want %q", assignment.Role(), got, wantPrimary)
		}
		if got := plan.Budgets[index].Primary().Route(); got != assignment.PrimaryRoute() {
			t.Fatalf("primary route for %q changed between assignment and budget", assignment.Role())
		}
	}
}

func TestIntegrationQualifiedPlannerRoutesReachSixLaneCoordinatorUnchanged(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := make([]QualifiedRoute, 0, 12)
	primaryFamilies := []Family{FamilyKimi, FamilyZCode, FamilyZCode, FamilyZCode, FamilyAGY, FamilyZCode}
	fallbackFamilies := []Family{FamilyZCode, FamilyAGY, FamilyAGY, FamilyAGY, FamilyZCode, FamilyAGY}
	for index, role := range roles {
		for _, family := range []Family{primaryFamilies[index], fallbackFamilies[index]} {
			instance := string(family) + "-" + string(role)
			routes = append(routes, plannerTestRoute(t, family, instance, instance, []domain.Role{role}))
		}
	}
	policy := plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY})
	policy.MaxLanes = 6
	planner, err := NewQualifiedPlanner(routes, policy)
	if err != nil {
		t.Fatal(err)
	}
	request := plannerTestRequest(t, roles)
	plan, err := planner.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(plan.Budgets, plan.Ceilings, plan.MaxLanes)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &plannerCoordinatorRuntime{entered: make(chan review.InvocationJob, 6), release: make(chan struct{})}
	coordinator, err := review.NewCoordinator(adapterruntime.SystemClock{}, adapterruntime.NewUUIDv7Generator(), runtime, nil, plan.MaxLanes, receipt)
	if err != nil {
		t.Fatal(err)
	}
	type execution struct {
		result review.CoordinatorResult
		err    error
	}
	done := make(chan execution, 1)
	go func() {
		result, executeErr := coordinator.Execute(context.Background(), request.Input().Target().Identity(), plan.Assignments, plan.Threshold, plan.Policy)
		done <- execution{result: result, err: executeErr}
	}()
	want := map[domain.Role]string{
		domain.RoleLogic: "kimi-logic", domain.RoleSecurity: "zcode-security",
		domain.RoleMaintainability: "zcode-maintainability", domain.RoleProduct: "zcode-product",
		domain.RoleDocumentation: "agy-documentation", domain.RoleTesting: "zcode-testing",
	}
	seen := make(map[domain.Role]bool, 6)
	for range roles {
		select {
		case job := <-runtime.entered:
			instance := want[job.Role()]
			if job.Route().ProviderInstance() != instance || job.Route().ConcurrencyKey().String() != instance {
				close(runtime.release)
				t.Fatalf("coordinator job for %q = %q/%q, want %q/%q", job.Role(), job.Route().ProviderInstance(), job.Route().ConcurrencyKey(), instance, instance)
			}
			seen[job.Role()] = true
		case <-time.After(3 * time.Second):
			close(runtime.release)
			t.Fatal("planner routes did not reach all six coordinator lanes")
		}
	}
	if len(seen) != 6 {
		close(runtime.release)
		t.Fatalf("coordinator received %d roles, want 6", len(seen))
	}
	close(runtime.release)
	executed := <-done
	if executed.err != nil || executed.result.RunState() != domain.RunCompleted {
		t.Fatalf("planned coordinator execution = state:%q error:%v", executed.result.RunState(), executed.err)
	}
}

func TestQualifiedPlannerFailsClosedWhenConfiguredFamilyIsNotQualified(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := []QualifiedRoute{
		plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles),
		plannerTestRoute(t, FamilyAGY, "agy.one", "lane-agy", roles),
	}
	planner, err := NewQualifiedPlanner(routes, plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Plan(context.Background(), plannerTestRequest(t, roles)); err == nil {
		t.Fatal("Plan() substituted an available family for the missing configured provider")
	}
}

func TestQualifiedPlannerAttributesRejectedConfiguredFamily(t *testing.T) {
	roles := domain.CoreRoleOrder()
	routes := []QualifiedRoute{
		plannerTestRoute(t, FamilyZCode, "zcode.one", "lane-zcode", roles),
		plannerTestRoute(t, FamilyAGY, "agy.one", "lane-agy", roles),
	}
	cause, err := domain.NewFailure("capability", domain.FailureInvalidOutput, "invalid capability output", nil)
	if err != nil {
		t.Fatal(err)
	}
	rejection, err := NewProviderQualificationFailure("kimi.one", FamilyKimi, string(domain.FailureInvalidOutput), cause)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := newQualifiedPlanner(
		routes,
		plannerTestCanonicalPolicy(t, []Family{FamilyKimi, FamilyZCode, FamilyAGY}),
		[]ProviderQualificationFailure{rejection},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = planner.Plan(context.Background(), plannerTestRequest(t, []domain.Role{domain.RoleLogic}))
	failures, ok := ProviderQualificationFailuresFromError(err)
	if !ok || len(failures) != 1 || failures[0].ProviderInstance() != "kimi.one" ||
		failures[0].ReasonCode() != string(domain.FailureInvalidOutput) {
		t.Fatalf("attributed planner failure = %#v present=%t error=%v", failures, ok, err)
	}
}

func TestQualifiedPlannerPreservesRequestedRoleOrder(t *testing.T) {
	roles := []domain.Role{domain.RoleTesting, domain.RoleSecurity, domain.RoleLogic, domain.RoleProduct, domain.RoleDocumentation, domain.RoleMaintainability}
	route := plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", domain.CoreRoleOrder())
	planner, err := NewQualifiedPlanner([]QualifiedRoute{route}, plannerTestCanonicalPolicy(t, []Family{FamilyKimi}))
	if err != nil {
		t.Fatal(err)
	}
	plan := plannerTestPlan(t, planner, roles)
	for index, assignment := range plan.Assignments {
		if assignment.Role() != roles[index] || plan.Budgets[index].Role() != roles[index] {
			t.Fatalf("role at %d = %q/%q, want %q", index, assignment.Role(), plan.Budgets[index].Role(), roles[index])
		}
	}
}

func TestQualifiedRouteRejectsInvalidOrMismatchedQualification(t *testing.T) {
	roles := domain.CoreRoleOrder()
	valid := plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles)
	qualification := valid.Qualification()
	route, err := ports.NewProviderRoute("kimi.other", valid.Route().ConcurrencyKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQualifiedRoute(qualification, route, valid.Limits(), roles, domain.RoleLogic, valid.FamilyOrdinal()); err == nil {
		t.Fatal("NewQualifiedRoute() accepted mismatched instance")
	}
	stale := qualification
	stale.available = false
	if _, err := NewQualifiedRoute(stale, valid.Route(), valid.Limits(), roles, domain.RoleLogic, valid.FamilyOrdinal()); err == nil {
		t.Fatal("NewQualifiedRoute() accepted unavailable qualification")
	}
}

func TestQualifiedPlannerAcceptsRunSubsetWithoutProjectFloor(t *testing.T) {
	roles := domain.CoreRoleOrder()
	route := plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", roles)
	planner, err := NewQualifiedPlanner([]QualifiedRoute{route}, plannerTestCanonicalPolicy(t, []Family{FamilyKimi}))
	if err != nil {
		t.Fatal(err)
	}
	requestRoles := roles[1:]
	target, err := ports.NewCapturedReviewPatchTarget([]byte("diff --git a/a b/a\n"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPlanningRequest(input, requestRoles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Plan(context.Background(), request); err != nil {
		t.Fatalf("Plan() rejected an explicit subset without logic: %v", err)
	}
}

func TestQualifiedPlannerAcceptsLogicOnlyProjectPolicy(t *testing.T) {
	assignment, err := NewRoleProviderAssignment(domain.RoleLogic, FamilyKimi)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultPlannerPolicy()
	policy.Assignments = []RoleProviderAssignment{assignment}
	policy.RequiredRoles = []domain.Role{domain.RoleLogic}
	route := plannerTestRoute(t, FamilyKimi, "kimi-logic", "kimi-logic", []domain.Role{domain.RoleLogic})
	planner, err := NewQualifiedPlanner([]QualifiedRoute{route}, policy)
	if err != nil {
		t.Fatalf("logic-only project policy was rejected: %v", err)
	}
	plan := plannerTestPlan(t, planner, []domain.Role{domain.RoleLogic})
	if len(plan.Assignments) != 1 || plan.Assignments[0].Role() != domain.RoleLogic || !plan.Assignments[0].Required() {
		t.Fatalf("logic-only plan = %#v", plan.Assignments)
	}
}

func TestQualifiedPlannerRejectsProjectPolicyWithoutLogic(t *testing.T) {
	assignment, err := NewRoleProviderAssignment(domain.RoleSecurity, FamilyZCode)
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultPlannerPolicy()
	policy.Assignments = []RoleProviderAssignment{assignment}
	policy.RequiredRoles = []domain.Role{domain.RoleSecurity}
	if _, err := normalizePlannerPolicy(policy); err == nil {
		t.Fatal("project policy without logic was accepted")
	}
}
func TestQualifiedPlannerAcceptsSingleProviderLogicAndSecurityWithProductionLimits(t *testing.T) {
	templates, err := trustedProductionCandidateTemplates(providercli.RuntimeBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	roles := []domain.Role{domain.RoleLogic, domain.RoleSecurity}
	key, err := ports.ParseConcurrencyKey("agy-production")
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute("agy-production", key)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := NewQualifiedRoute(
		plannerTestQualification(t, FamilyAGY, "agy-production", plannerTestGuidanceVersion(t, FamilyAGY), ReceiptPass),
		route, templates[2].limits, roles, domain.RoleLogic, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewQualifiedPlanner([]QualifiedRoute{qualified}, plannerTestCanonicalPolicy(t, []Family{FamilyAGY}))
	if err != nil {
		t.Fatal(err)
	}
	plan := plannerTestPlan(t, planner, roles)
	if _, err := validatePlan(plan, roles); err != nil {
		t.Fatalf("production plan preflight: %v", err)
	}
	instances := plannerTestAssignments(plan)
	if want := []string{"agy-production", "agy-production"}; !reflect.DeepEqual(instances, want) {
		t.Fatalf("production assignments = %v, want %v", instances, want)
	}
	repeatedInstances := plannerTestAssignments(plannerTestPlan(t, planner, roles))
	if !reflect.DeepEqual(repeatedInstances, instances) {
		t.Fatalf("production planning was nondeterministic: %v then %v", instances, repeatedInstances)
	}
}

func TestQualifiedRouteAcceptsYellowOnlyWithPassingReceipts(t *testing.T) {
	roles := domain.CoreRoleOrder()
	yellow := plannerTestQualification(t, FamilyAGY, "agy.yellow", "9.0.0", ReceiptPass)
	key, err := ports.ParseConcurrencyKey("lane-yellow")
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute("agy.yellow", key)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewInvocationLimits(time.Second, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQualifiedRoute(yellow, route, limits, roles, domain.RoleLogic, 2); err != nil {
		t.Fatalf("NewQualifiedRoute() rejected fully passing yellow qualification: %v", err)
	}
	failed := plannerTestQualification(t, FamilyAGY, "agy.failed", "9.0.0", ReceiptFailed)
	failedRoute, err := ports.NewProviderRoute("agy.failed", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQualifiedRoute(failed, failedRoute, limits, roles, domain.RoleLogic, 2); err == nil {
		t.Fatal("NewQualifiedRoute() accepted failed yellow qualification")
	}
	for _, family := range []Family{FamilyKimi, FamilyZCode} {
		qualification := plannerTestQualification(t, family, string(family)+".yellow", "9.0.0", ReceiptPass)
		route, err := ports.NewProviderRoute(string(family)+".yellow", key)
		if err != nil {
			t.Fatal(err)
		}
		ordinal, ok := familyOrdinal(family)
		if !ok {
			t.Fatalf("family ordinal unavailable for %q", family)
		}
		if !qualification.Available() || qualification.Reason() != "eligible" {
			t.Fatalf("%s passing authority-bound qualification = available %t, reason %q", family, qualification.Available(), qualification.Reason())
		}
		if _, err := NewQualifiedRoute(qualification, route, limits, roles, domain.RoleLogic, ordinal); err != nil {
			t.Fatalf("NewQualifiedRoute() rejected %s passing authority-bound qualification: %v", family, err)
		}
	}
}

func plannerTestPlan(t *testing.T, planner ExecutionPlanner, roles []domain.Role) ExecutionPlan {
	t.Helper()
	request := plannerTestRequest(t, roles)
	plan, err := planner.Plan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func plannerTestRequest(t *testing.T, roles []domain.Role) PlanningRequest {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("diff --git a/a b/a\n"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewPlanningRequest(input, roles)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func plannerTestAssignments(plan ExecutionPlan) []string {
	instances := make([]string, len(plan.Assignments))
	for index, assignment := range plan.Assignments {
		instances[index] = assignment.PrimaryRoute().ProviderInstance()
	}
	return instances
}

func plannerTestRouteInstances(plan ExecutionPlan) []string {
	primary := make([]string, len(plan.Assignments))
	for index, assignment := range plan.Assignments {
		primary[index] = assignment.PrimaryRoute().ProviderInstance()
	}
	return primary
}

func plannerTestCanonicalPolicy(t *testing.T, families []Family) PlannerPolicy {
	t.Helper()
	configured := make(map[Family]struct{}, len(families))
	for _, family := range families {
		configured[family] = struct{}{}
	}
	// A role takes the first configured family from its preference order.
	pick := func(preferences []Family) Family {
		for _, family := range preferences {
			if _, ok := configured[family]; ok {
				return family
			}
		}
		return ""
	}
	policy := DefaultPlannerPolicy()
	for _, role := range domain.CoreRoleOrder() {
		preferences := []Family{FamilyZCode, FamilyAGY, FamilyKimi}
		if role == domain.RoleLogic {
			preferences = []Family{FamilyKimi, FamilyZCode, FamilyAGY}
		} else if role == domain.RoleDocumentation {
			preferences = []Family{FamilyAGY, FamilyZCode, FamilyKimi}
		}
		assignment, err := NewRoleProviderAssignment(role, pick(preferences))
		if err != nil {
			t.Fatal(err)
		}
		policy.Assignments = append(policy.Assignments, assignment)
	}
	return policy
}

func plannerTestRoute(t *testing.T, family Family, instance, lane string, roles []domain.Role) QualifiedRoute {
	t.Helper()
	qualification := plannerTestQualification(t, family, instance, plannerTestGuidanceVersion(t, family), ReceiptPass)
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute(instance, key)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewInvocationLimits(time.Second, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ordinal, ok := familyOrdinal(family)
	if !ok {
		t.Fatal("invalid test family")
	}
	base := qualificationBaseRole(roles)
	qualified, err := NewQualifiedRoute(qualification, route, limits, roles, base, ordinal)
	if err != nil {
		t.Fatal(err)
	}
	return qualified
}

func plannerTestQualification(t *testing.T, family Family, instance, version string, state ReceiptState) Qualification {
	t.Helper()
	input := currentProbeAuthorityInputForInstance(t, family, instance, version)
	for index := range input.Receipts {
		input.Receipts[index].State = state
	}
	qualification := ValidateQualification(input)
	if state == ReceiptPass && !qualification.Available() {
		t.Fatalf("qualification unexpectedly unavailable: %s", qualification.Reason())
	}
	return qualification
}
func plannerTestGuidanceVersion(t *testing.T, family Family) string {
	t.Helper()
	guidance, ok := Guidance(family)
	if !ok {
		t.Fatalf("Guidance(%q) unavailable", family)
	}
	return guidance.VerifiedLatest
}

func repeatPlannerTestString(value string, count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = value
	}
	return values
}

func repeatPlannerTestBool(value bool, count int) []bool {
	values := make([]bool, count)
	for index := range values {
		values[index] = value
	}
	return values
}
