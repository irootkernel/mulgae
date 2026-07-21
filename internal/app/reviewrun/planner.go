package reviewrun

import (
	"context"
	"fmt"
	"sort"

	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// QualifiedRoute is the complete immutable planning authority for one provider
// instance and concurrency lane. It contains no discovery or invocation power.
type QualifiedRoute struct {
	qualification  Qualification
	route          ports.ProviderRoute
	limits         review.InvocationLimits
	supportedRoles []domain.Role
	baseRole       domain.Role
	familyOrdinal  int
}

// NewQualifiedRoute accepts only a current, fully passing qualification bound to
// the supplied provider route. The base role must be included in supportedRoles.
func NewQualifiedRoute(qualification Qualification, route ports.ProviderRoute, limits review.InvocationLimits, supportedRoles []domain.Role, baseRole domain.Role, providedOrdinal int) (QualifiedRoute, error) {
	if !qualification.Available() || !route.Valid() || !limits.Valid() || !baseRole.Valid() {
		return QualifiedRoute{}, fmt.Errorf("review run: invalid qualified route")
	}
	identity := qualification.Identity()
	expectedOrdinal, ok := familyOrdinal(identity.Family)
	if !ok || providedOrdinal != expectedOrdinal || identity.Instance != route.ProviderInstance() || !passingQualification(qualification) {
		return QualifiedRoute{}, fmt.Errorf("review run: mismatched qualified route")
	}
	roles := append([]domain.Role(nil), supportedRoles...)
	if len(roles) == 0 {
		return QualifiedRoute{}, fmt.Errorf("review run: qualified route has no supported roles")
	}
	seen := make(map[domain.Role]struct{}, len(roles))
	containsBase := false
	for _, role := range roles {
		if !role.Valid() {
			return QualifiedRoute{}, fmt.Errorf("review run: invalid supported role %q", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return QualifiedRoute{}, fmt.Errorf("review run: duplicate supported role %q", role)
		}
		seen[role] = struct{}{}
		containsBase = containsBase || role == baseRole
	}
	if !containsBase {
		return QualifiedRoute{}, fmt.Errorf("review run: base role is not supported")
	}
	sort.Slice(roles, func(left, right int) bool { return roleOrdinal(roles[left]) < roleOrdinal(roles[right]) })
	return QualifiedRoute{
		qualification:  qualification,
		route:          route,
		limits:         limits,
		supportedRoles: roles,
		baseRole:       baseRole,
		familyOrdinal:  providedOrdinal,
	}, nil
}

// Qualification returns the immutable current admission decision.
func (route QualifiedRoute) Qualification() Qualification { return route.qualification }

// Route returns the immutable provider instance and lane binding.
func (route QualifiedRoute) Route() ports.ProviderRoute { return route.route }

// Limits returns immutable invocation limits for this route.
func (route QualifiedRoute) Limits() review.InvocationLimits { return route.limits }

// SupportedRoles returns a caller-owned canonical role list.
func (route QualifiedRoute) SupportedRoles() []domain.Role {
	return append([]domain.Role(nil), route.supportedRoles...)
}

// BaseRole returns the role whose current base-role receipt was passed.
func (route QualifiedRoute) BaseRole() domain.Role { return route.baseRole }

// FamilyOrdinal returns the canonical allowlist ordinal used for deterministic planning.
func (route QualifiedRoute) FamilyOrdinal() int { return route.familyOrdinal }

// Supports reports whether this route has passing authority for role.
func (route QualifiedRoute) Supports(role domain.Role) bool {
	for _, supported := range route.supportedRoles {
		if supported == role {
			return true
		}
	}
	return false
}

// Valid reports whether route remains a complete immutable planning operand.
func (route QualifiedRoute) Valid() bool {
	_, err := NewQualifiedRoute(route.qualification, route.route, route.limits, route.supportedRoles, route.baseRole, route.familyOrdinal)
	return err == nil
}

// PlannerPolicy supplies trusted execution limits and outcome policy. Zero
// threshold, ceilings, and lane count select the closed defaults.
type PlannerPolicy struct {
	Ceilings  review.HarnessCeilings
	Threshold domain.Severity
	Policy    *domain.CIPolicy
	MaxLanes  int
}

// DefaultPlannerPolicy returns the closed planner policy used when no narrower
// trusted policy is supplied.
func DefaultPlannerPolicy() PlannerPolicy {
	return PlannerPolicy{
		Ceilings:  review.DefaultHarnessCeilings(),
		Threshold: domain.SeverityHigh,
		MaxLanes:  1,
	}
}

type qualifiedPlanner struct {
	routes []QualifiedRoute
	policy PlannerPolicy
}

// NewQualifiedPlanner freezes current qualified routes for pure deterministic
// assignment planning. Discovery availability alone is never accepted.
func NewQualifiedPlanner(routes []QualifiedRoute, policy PlannerPolicy) (ExecutionPlanner, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("review run: no qualified routes")
	}
	policy, err := normalizePlannerPolicy(policy)
	if err != nil {
		return nil, err
	}
	frozen := append([]QualifiedRoute(nil), routes...)
	for index, route := range frozen {
		if !route.Valid() {
			return nil, fmt.Errorf("review run: invalid qualified route %d", index)
		}
		for prior := 0; prior < index; prior++ {
			if sameQualifiedRoute(frozen[prior], route) {
				return nil, fmt.Errorf("review run: duplicate qualified route")
			}
		}
	}
	sort.Slice(frozen, func(left, right int) bool { return compareQualifiedRoutes(frozen[left], frozen[right]) < 0 })
	return &qualifiedPlanner{routes: frozen, policy: clonePlannerPolicy(policy)}, nil
}

func (planner *qualifiedPlanner) Plan(ctx context.Context, request PlanningRequest) (ExecutionPlan, error) {
	if planner == nil {
		return ExecutionPlan{}, fmt.Errorf("review run: qualified planner unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ExecutionPlan{}, err
	}
	if !request.Input().Target().Valid() {
		return ExecutionPlan{}, fmt.Errorf("review run: invalid planning request")
	}
	roles := request.RequestedRoles()
	if _, err := NewRunSelection(roles, nil); err != nil {
		return ExecutionPlan{}, fmt.Errorf("review run: invalid planning request: %w", err)
	}
	candidates := make([][]QualifiedRoute, len(roles))
	for index, role := range roles {
		for _, route := range planner.routes {
			if route.Supports(role) {
				candidates[index] = append(candidates[index], route)
			}
		}
		if len(candidates[index]) == 0 {
			return ExecutionPlan{}, fmt.Errorf("review run: no qualified route for role %q", role)
		}
	}

	var best *plannedCandidate
	primaries := make([]QualifiedRoute, len(roles))
	var choosePrimaries func(int) error
	choosePrimaries = func(index int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index == len(roles) {
			return planner.chooseFallbacks(roles, primaries, &best, ctx)
		}
		for _, route := range candidates[index] {
			primaries[index] = route
			if err := choosePrimaries(index + 1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := choosePrimaries(0); err != nil {
		return ExecutionPlan{}, err
	}
	if best == nil {
		return ExecutionPlan{}, fmt.Errorf("review run: no feasible qualified execution plan")
	}
	return best.plan.clone(), nil
}

func (planner *qualifiedPlanner) chooseFallbacks(roles []domain.Role, primaries []QualifiedRoute, best **plannedCandidate, ctx context.Context) error {
	fallbacks := make([]*QualifiedRoute, len(roles))
	var choose func(int) error
	choose = func(index int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index == len(roles) {
			candidate, ok := planner.makeCandidate(roles, primaries, fallbacks)
			if ok && (*best == nil || candidate.betterThan(**best, roles)) {
				*best = &candidate
			}
			return nil
		}
		// A singleton has no safe fallback. When distinct routes exist, enumerate
		// both the resilient and null shapes; preflight selects the feasible one.
		if err := choose(index + 1); err != nil {
			return err
		}
		for _, route := range planner.routes {
			if !route.Supports(roles[index]) || !distinctRoutes(primaries[index], route) {
				continue
			}
			fallback := route
			fallbacks[index] = &fallback
			if err := choose(index + 1); err != nil {
				return err
			}
		}
		fallbacks[index] = nil
		return nil
	}
	return choose(0)
}

func (planner *qualifiedPlanner) makeCandidate(roles []domain.Role, primaries []QualifiedRoute, fallbacks []*QualifiedRoute) (plannedCandidate, bool) {
	assignments := make([]review.Assignment, 0, len(roles))
	budgets := make([]review.RoleBudget, 0, len(roles))
	fallbackCount := 0
	for index, role := range roles {
		var fallbackRoute *ports.ProviderRoute
		var fallbackBudget *review.RouteBudget
		if fallback := fallbacks[index]; fallback != nil {
			route := fallback.Route()
			budget, err := review.NewRouteBudget(route, fallback.Limits())
			if err != nil {
				return plannedCandidate{}, false
			}
			fallbackRoute, fallbackBudget = &route, &budget
			fallbackCount++
		}
		assignment, err := review.NewScheduledAssignment(role, role.RequiredFloor(), primaries[index].Route(), fallbackRoute)
		if err != nil {
			return plannedCandidate{}, false
		}
		primaryBudget, err := review.NewRouteBudget(primaries[index].Route(), primaries[index].Limits())
		if err != nil {
			return plannedCandidate{}, false
		}
		budget, err := review.NewRoleBudget(role, primaryBudget, fallbackBudget)
		if err != nil {
			return plannedCandidate{}, false
		}
		assignments, budgets = append(assignments, assignment), append(budgets, budget)
	}
	plan := ExecutionPlan{Assignments: assignments, Budgets: budgets, Ceilings: planner.policy.Ceilings, Threshold: planner.policy.Threshold, Policy: planner.policy.Policy, MaxLanes: planner.policy.MaxLanes}
	if _, err := validatePlan(plan, roles); err != nil {
		return plannedCandidate{}, false
	}
	return plannedCandidate{plan: plan, primaries: append([]QualifiedRoute(nil), primaries...), fallbacks: append([]*QualifiedRoute(nil), fallbacks...), fallbackCount: fallbackCount}, true
}

type plannedCandidate struct {
	plan          ExecutionPlan
	primaries     []QualifiedRoute
	fallbacks     []*QualifiedRoute
	fallbackCount int
}

func (candidate plannedCandidate) betterThan(other plannedCandidate, roles []domain.Role) bool {
	candidateDistinct := logicSecurityDistinct(candidate.primaries, roles)
	otherDistinct := logicSecurityDistinct(other.primaries, roles)
	if candidateDistinct != otherDistinct {
		return candidateDistinct
	}
	if candidate.fallbackCount != other.fallbackCount {
		return candidate.fallbackCount > other.fallbackCount
	}
	for index := range candidate.primaries {
		if compared := compareQualifiedRoutes(candidate.primaries[index], other.primaries[index]); compared != 0 {
			return compared < 0
		}
	}
	for index := range candidate.fallbacks {
		if candidate.fallbacks[index] == nil || other.fallbacks[index] == nil {
			if candidate.fallbacks[index] != nil {
				return true
			}
			if other.fallbacks[index] != nil {
				return false
			}
			continue
		}
		if compared := compareQualifiedRoutes(*candidate.fallbacks[index], *other.fallbacks[index]); compared != 0 {
			return compared < 0
		}
	}
	return false
}

func normalizePlannerPolicy(policy PlannerPolicy) (PlannerPolicy, error) {
	defaults := DefaultPlannerPolicy()
	if policy.Ceilings == (review.HarnessCeilings{}) {
		policy.Ceilings = defaults.Ceilings
	}
	if policy.Threshold == "" {
		policy.Threshold = defaults.Threshold
	}
	if policy.MaxLanes == 0 {
		policy.MaxLanes = defaults.MaxLanes
	}
	if !policy.Ceilings.Valid() || !policy.Threshold.Valid() || policy.MaxLanes < 1 {
		return PlannerPolicy{}, fmt.Errorf("review run: invalid planner policy")
	}
	return policy, nil
}

func clonePlannerPolicy(policy PlannerPolicy) PlannerPolicy {
	result := policy
	if policy.Policy != nil {
		copy := *policy.Policy
		result.Policy = &copy
	}
	return result
}

func passingQualification(qualification Qualification) bool {
	identity := qualification.Identity()
	receipts := qualification.Receipts()
	if len(receipts) != len(ReceiptKinds()) {
		return false
	}
	seen := make(map[ReceiptKind]struct{}, len(receipts))
	for _, receipt := range receipts {
		if !requiredReceiptKind(receipt.Kind) || receipt.State != ReceiptPass || receipt.Identity != identity {
			return false
		}
		if _, duplicate := seen[receipt.Kind]; duplicate {
			return false
		}
		seen[receipt.Kind] = struct{}{}
	}
	return true
}

func familyOrdinal(family Family) (int, bool) {
	for ordinal, candidate := range Families() {
		if family == candidate {
			return ordinal, true
		}
	}
	return 0, false
}

func roleOrdinal(role domain.Role) int {
	for ordinal, candidate := range domain.FixedRoleOrder() {
		if role == candidate {
			return ordinal
		}
	}
	return len(domain.FixedRoleOrder())
}

func sameQualifiedRoute(left, right QualifiedRoute) bool {
	return left.familyOrdinal == right.familyOrdinal && left.route == right.route
}

func compareQualifiedRoutes(left, right QualifiedRoute) int {
	if left.familyOrdinal != right.familyOrdinal {
		return left.familyOrdinal - right.familyOrdinal
	}
	if left.route.ProviderInstance() < right.route.ProviderInstance() {
		return -1
	}
	if left.route.ProviderInstance() > right.route.ProviderInstance() {
		return 1
	}
	if left.route.ConcurrencyKey().String() < right.route.ConcurrencyKey().String() {
		return -1
	}
	if left.route.ConcurrencyKey().String() > right.route.ConcurrencyKey().String() {
		return 1
	}
	return 0
}

func distinctRoutes(left, right QualifiedRoute) bool {
	return left.route.ProviderInstance() != right.route.ProviderInstance() && left.route.ConcurrencyKey().String() != right.route.ConcurrencyKey().String()
}

func logicSecurityDistinct(routes []QualifiedRoute, roles []domain.Role) bool {
	logic, security := -1, -1
	for index, role := range roles {
		switch role {
		case domain.RoleLogic:
			logic = index
		case domain.RoleSecurity:
			security = index
		}
	}
	return logic >= 0 && security >= 0 && distinctRoutes(routes[logic], routes[security])
}
