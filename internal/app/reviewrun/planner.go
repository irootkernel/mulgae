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

// RoleProviderAssignment is the configured provider-family route for one role.
// An empty fallback family means that the configured provider set is a singleton.
type RoleProviderAssignment struct {
	role     domain.Role
	primary  Family
	fallback Family
}

// NewRoleProviderAssignment validates one explicit Config v2 assignment.
func NewRoleProviderAssignment(role domain.Role, primary, fallback Family) (RoleProviderAssignment, error) {
	if !role.Valid() || !primary.Valid() || (fallback != "" && (!fallback.Valid() || fallback == primary)) {
		return RoleProviderAssignment{}, fmt.Errorf("review run: invalid role provider assignment")
	}
	if role == domain.RoleArtist && (primary == FamilyKimi || fallback == FamilyKimi) {
		return RoleProviderAssignment{}, fmt.Errorf("review run: artist requires agy or zcode")
	}
	return RoleProviderAssignment{role: role, primary: primary, fallback: fallback}, nil
}

func (assignment RoleProviderAssignment) Role() domain.Role { return assignment.role }
func (assignment RoleProviderAssignment) Primary() Family   { return assignment.primary }
func (assignment RoleProviderAssignment) Fallback() (Family, bool) {
	return assignment.fallback, assignment.fallback != ""
}

// PlannerPolicy supplies trusted execution limits, explicit Config v2
// provider assignments, and outcome policy. Zero threshold, ceilings, and lane
// count select the closed defaults; assignments never default.
type PlannerPolicy struct {
	Ceilings      review.HarnessCeilings
	Threshold     domain.Severity
	Policy        *domain.CIPolicy
	MaxLanes      int
	Assignments   []RoleProviderAssignment
	RequiredRoles []domain.Role
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
	routes                []QualifiedRoute
	policy                PlannerPolicy
	qualificationFailures []ProviderQualificationFailure
}

// NewQualifiedPlanner freezes current qualified routes for pure deterministic
// assignment planning. Discovery availability alone is never accepted.
func NewQualifiedPlanner(routes []QualifiedRoute, policy PlannerPolicy) (ExecutionPlanner, error) {
	return newQualifiedPlanner(routes, policy, nil)
}

func newQualifiedPlanner(routes []QualifiedRoute, policy PlannerPolicy, qualificationFailures []ProviderQualificationFailure) (ExecutionPlanner, error) {
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
	return &qualifiedPlanner{
		routes: frozen, policy: clonePlannerPolicy(policy),
		qualificationFailures: append([]ProviderQualificationFailure(nil), qualificationFailures...),
	}, nil
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
	primaries := make([]QualifiedRoute, len(roles))
	fallbacks := make([]*QualifiedRoute, len(roles))
	for index, role := range roles {
		configured, ok := planner.configuredAssignment(role)
		if !ok {
			return ExecutionPlan{}, fmt.Errorf("review run: no configured provider assignment for role %q", role)
		}
		primary, err := planner.configuredRoute(role, configured.primary)
		if err != nil {
			return ExecutionPlan{}, err
		}
		primaries[index] = primary
		if configured.fallback != "" {
			fallback, err := planner.configuredRoute(role, configured.fallback)
			if err != nil {
				return ExecutionPlan{}, err
			}
			fallbacks[index] = &fallback
		}
	}
	plan, err := planner.makeConfiguredPlan(roles, primaries, fallbacks)
	if err != nil {
		return ExecutionPlan{}, err
	}
	return plan.clone(), nil
}

func (planner *qualifiedPlanner) configuredAssignment(role domain.Role) (RoleProviderAssignment, bool) {
	for _, assignment := range planner.policy.Assignments {
		if assignment.role == role {
			return assignment, true
		}
	}
	return RoleProviderAssignment{}, false
}

func (planner *qualifiedPlanner) configuredRoute(role domain.Role, family Family) (QualifiedRoute, error) {
	var matched *QualifiedRoute
	for _, route := range planner.routes {
		if route.Qualification().Identity().Family != family || !route.Supports(role) {
			continue
		}
		if matched != nil {
			return QualifiedRoute{}, fmt.Errorf("review run: multiple qualified %s routes for role %q", family, role)
		}
		copy := route
		matched = &copy
	}
	if matched == nil {
		failures := make([]ProviderQualificationFailure, 0, 1)
		for _, failure := range planner.qualificationFailures {
			if failure.Family() == family {
				failures = append(failures, failure)
			}
		}
		if len(failures) != 0 {
			return QualifiedRoute{}, providerQualificationReadinessError(failures)
		}
		return QualifiedRoute{}, fmt.Errorf("review run: configured %s route is not qualified for role %q", family, role)
	}
	return *matched, nil
}

func (planner *qualifiedPlanner) makeConfiguredPlan(roles []domain.Role, primaries []QualifiedRoute, fallbacks []*QualifiedRoute) (ExecutionPlan, error) {
	assignments := make([]review.Assignment, 0, len(roles))
	budgets := make([]review.RoleBudget, 0, len(roles))
	for index, role := range roles {
		var fallbackRoute *ports.ProviderRoute
		var fallbackBudget *review.RouteBudget
		if fallback := fallbacks[index]; fallback != nil {
			route := fallback.Route()
			budget, err := review.NewRouteBudget(route, fallback.Limits())
			if err != nil {
				return ExecutionPlan{}, err
			}
			fallbackRoute, fallbackBudget = &route, &budget
		}
		required := role.RequiredFloor()
		for _, configuredRequired := range planner.policy.RequiredRoles {
			required = required || configuredRequired == role
		}
		assignment, err := review.NewScheduledAssignment(role, required, primaries[index].Route(), fallbackRoute)
		if err != nil {
			return ExecutionPlan{}, err
		}
		primaryBudget, err := review.NewRouteBudget(primaries[index].Route(), primaries[index].Limits())
		if err != nil {
			return ExecutionPlan{}, err
		}
		budget, err := review.NewRoleBudget(role, primaryBudget, fallbackBudget)
		if err != nil {
			return ExecutionPlan{}, err
		}
		assignments, budgets = append(assignments, assignment), append(budgets, budget)
	}
	plan := ExecutionPlan{Assignments: assignments, Budgets: budgets, Ceilings: planner.policy.Ceilings, Threshold: planner.policy.Threshold, Policy: planner.policy.Policy, MaxLanes: planner.policy.MaxLanes}
	if _, err := validatePlan(plan, roles); err != nil {
		return ExecutionPlan{}, err
	}
	return plan, nil
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
	if err := validatePlannerAssignments(policy.Assignments); err != nil {
		return PlannerPolicy{}, err
	}
	lastRequired := -1
	for _, required := range policy.RequiredRoles {
		ordinal := roleOrdinal(required)
		if ordinal <= lastRequired {
			return PlannerPolicy{}, fmt.Errorf("review run: invalid required role policy")
		}
		if !plannerRoleConfigured(policy.Assignments, required) {
			return PlannerPolicy{}, fmt.Errorf("review run: required role is not configured")
		}
		lastRequired = ordinal
	}
	return policy, nil
}

func plannerRoleConfigured(assignments []RoleProviderAssignment, role domain.Role) bool {
	for _, assignment := range assignments {
		if assignment.role == role {
			return true
		}
	}
	return false
}

func validatePlannerAssignments(assignments []RoleProviderAssignment) error {
	if len(assignments) < 2 || len(assignments) > len(domain.FixedRoleOrder()) {
		return fmt.Errorf("review run: planner policy requires the project role set")
	}
	lastOrdinal := -1
	seen := make(map[domain.Role]bool, len(assignments))
	for _, assignment := range assignments {
		ordinal := roleOrdinal(assignment.role)
		if ordinal <= lastOrdinal || !assignment.primary.Valid() || (assignment.fallback != "" && (!assignment.fallback.Valid() || assignment.fallback == assignment.primary)) {
			return fmt.Errorf("review run: invalid configured assignment for role %q", assignment.role)
		}
		seen[assignment.role], lastOrdinal = true, ordinal
	}
	if !seen[domain.RoleLogic] || !seen[domain.RoleSecurity] {
		return fmt.Errorf("review run: planner policy omits the project role floor")
	}
	return nil
}

func clonePlannerPolicy(policy PlannerPolicy) PlannerPolicy {
	result := policy
	result.Assignments = append([]RoleProviderAssignment(nil), policy.Assignments...)
	result.RequiredRoles = append([]domain.Role(nil), policy.RequiredRoles...)
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
