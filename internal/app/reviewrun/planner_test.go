package reviewrun

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestQualifiedPlannerGoldenProviderSubsetsAndPermutations(t *testing.T) {
	roles := domain.FixedRoleOrder()
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
			got, fallbacks := plannerTestAssignments(plan)
			if !reflect.DeepEqual(got, test.want) || !reflect.DeepEqual(fallbacks, test.fallback) {
				t.Fatalf("assignment golden = %v/%v, want %v/%v", got, fallbacks, test.want, test.fallback)
			}
		})
	}
}
func TestQualifiedPlannerGoldenEveryProviderSubset(t *testing.T) {
	roles := domain.FixedRoleOrder()
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
	roles := domain.FixedRoleOrder()
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
		got, _ := plannerTestAssignments(plannerTestPlan(t, planner, roles))
		if golden == nil {
			golden = got
		} else if !reflect.DeepEqual(got, golden) {
			t.Fatalf("permuted routes chose %v, want %v", got, golden)
		}
	}
}

func TestQualifiedPlannerUsesExactConfiguredPrimaryAndFallbackMatrix(t *testing.T) {
	roles := domain.FixedRoleOrder()
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
	primary, fallback := plannerTestRouteInstances(plan)
	if want := []string{"kimi.one", "zcode.one", "zcode.one", "zcode.one", "agy.one", "zcode.one"}; !reflect.DeepEqual(primary, want) {
		t.Fatalf("primary matrix = %v, want %v", primary, want)
	}
	if want := []string{"zcode.one", "agy.one", "agy.one", "agy.one", "zcode.one", "agy.one"}; !reflect.DeepEqual(fallback, want) {
		t.Fatalf("fallback matrix = %v, want %v", fallback, want)
	}
}

func TestQualifiedPlannerFailsClosedWhenConfiguredFamilyIsNotQualified(t *testing.T) {
	roles := domain.FixedRoleOrder()
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
	roles := domain.FixedRoleOrder()
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
	route := plannerTestRoute(t, FamilyKimi, "kimi.one", "lane-kimi", domain.FixedRoleOrder())
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
	roles := domain.FixedRoleOrder()
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

func TestQualifiedPlannerRejectsMissingRequiredRole(t *testing.T) {
	roles := domain.FixedRoleOrder()
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
	if _, err := planner.Plan(context.Background(), request); err == nil {
		t.Fatal("Plan() accepted a role set without the required logic floor")
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
	instances, fallbacks := plannerTestAssignments(plan)
	if want := []string{"agy-production", "agy-production"}; !reflect.DeepEqual(instances, want) || !reflect.DeepEqual(fallbacks, []bool{false, false}) {
		t.Fatalf("production assignments = %v/%v, want %v/%v", instances, fallbacks, want, []bool{false, false})
	}
	repeatedInstances, repeatedFallbacks := plannerTestAssignments(plannerTestPlan(t, planner, roles))
	if !reflect.DeepEqual(repeatedInstances, instances) || !reflect.DeepEqual(repeatedFallbacks, fallbacks) {
		t.Fatalf("production planning was nondeterministic: %v/%v then %v/%v", instances, fallbacks, repeatedInstances, repeatedFallbacks)
	}
}

func TestQualifiedRouteAcceptsYellowOnlyWithPassingReceipts(t *testing.T) {
	roles := domain.FixedRoleOrder()
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

func plannerTestAssignments(plan ExecutionPlan) ([]string, []bool) {
	instances := make([]string, len(plan.Assignments))
	fallbacks := make([]bool, len(plan.Assignments))
	for index, assignment := range plan.Assignments {
		instances[index] = assignment.PrimaryRoute().ProviderInstance()
		fallbacks[index] = assignment.HasFallback()
	}
	return instances, fallbacks
}

func plannerTestRouteInstances(plan ExecutionPlan) ([]string, []string) {
	primary := make([]string, len(plan.Assignments))
	fallback := make([]string, len(plan.Assignments))
	for index, assignment := range plan.Assignments {
		primary[index] = assignment.PrimaryRoute().ProviderInstance()
		if route, ok := assignment.FallbackRoute(); ok {
			fallback[index] = route.ProviderInstance()
		}
	}
	return primary, fallback
}

func plannerTestCanonicalPolicy(t *testing.T, families []Family) PlannerPolicy {
	t.Helper()
	configured := make(map[Family]struct{}, len(families))
	for _, family := range families {
		configured[family] = struct{}{}
	}
	pick := func(preferences []Family) (Family, Family) {
		selected := make([]Family, 0, 2)
		for _, family := range preferences {
			if _, ok := configured[family]; ok {
				selected = append(selected, family)
				if len(selected) == 2 {
					break
				}
			}
		}
		if len(selected) == 1 {
			return selected[0], ""
		}
		return selected[0], selected[1]
	}
	policy := DefaultPlannerPolicy()
	for _, role := range domain.FixedRoleOrder() {
		preferences := []Family{FamilyZCode, FamilyAGY, FamilyKimi}
		if role == domain.RoleLogic {
			preferences = []Family{FamilyKimi, FamilyZCode, FamilyAGY}
		} else if role == domain.RoleDocumentation {
			preferences = []Family{FamilyAGY, FamilyZCode, FamilyKimi}
		}
		primary, fallback := pick(preferences)
		assignment, err := NewRoleProviderAssignment(role, primary, fallback)
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
	qualified, err := NewQualifiedRoute(qualification, route, limits, roles, domain.RoleLogic, ordinal)
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
