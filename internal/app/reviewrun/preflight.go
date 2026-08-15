package reviewrun

import (
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// PreflightConfiguredPlan projects the production route topology and its
// enclosing budgets without discovering, qualifying, or invoking providers.
// It deliberately shares the production instance, output-cap, timeout,
// assignment, and budget authorities used by qualified execution planning.
func PreflightConfiguredPlan(
	policy PlannerPolicy,
	providerTimeouts map[Family]time.Duration,
	selectedRoles []domain.Role,
) (ExecutionPlan, review.RunBudgetReceipt, error) {
	policy, err := normalizePlannerPolicy(policy)
	if err != nil {
		return ExecutionPlan{}, review.RunBudgetReceipt{}, err
	}
	if err := validateProductionProviderTimeouts(providerTimeouts); err != nil {
		return ExecutionPlan{}, review.RunBudgetReceipt{}, err
	}
	if _, err := NewRunSelection(selectedRoles, nil); err != nil {
		return ExecutionPlan{}, review.RunBudgetReceipt{}, err
	}

	assignments := make([]review.Assignment, 0, len(selectedRoles))
	budgets := make([]review.RoleBudget, 0, len(selectedRoles))
	for _, role := range selectedRoles {
		configured, ok := configuredAssignmentForRole(policy.Assignments, role)
		if !ok {
			return ExecutionPlan{}, review.RunBudgetReceipt{}, fmt.Errorf("review run: no configured provider assignment for role %q", role)
		}
		primaryRoute, primaryBudget, err := configuredPreflightRoute(role, configured, providerTimeouts)
		if err != nil {
			return ExecutionPlan{}, review.RunBudgetReceipt{}, err
		}
		required := role.RequiredFloor()
		for _, configuredRequired := range policy.RequiredRoles {
			required = required || configuredRequired == role
		}
		assignment, err := review.NewScheduledAssignment(role, required, primaryRoute)
		if err != nil {
			return ExecutionPlan{}, review.RunBudgetReceipt{}, err
		}
		budget, err := review.NewRoleBudget(role, primaryBudget)
		if err != nil {
			return ExecutionPlan{}, review.RunBudgetReceipt{}, err
		}
		assignments = append(assignments, assignment)
		budgets = append(budgets, budget)
	}
	plan := ExecutionPlan{
		Assignments: assignments,
		Budgets:     budgets,
		Ceilings:    policy.Ceilings,
		Threshold:   policy.Threshold,
		Policy:      policy.Policy,
		MaxWorkers:  policy.MaxWorkers,
	}
	receipt, err := validatePlan(plan, selectedRoles)
	if err != nil {
		return ExecutionPlan{}, receipt, err
	}
	return plan.clone(), receipt, nil
}

func configuredAssignmentForRole(assignments []RoleProviderAssignment, role domain.Role) (RoleProviderAssignment, bool) {
	for _, assignment := range assignments {
		if assignment.Role() == role {
			return assignment, true
		}
	}
	return RoleProviderAssignment{}, false
}

func configuredPreflightRoute(
	role domain.Role,
	assignment RoleProviderAssignment,
	providerTimeouts map[Family]time.Duration,
) (ports.ProviderRoute, review.RouteBudget, error) {
	route, limits, err := productionRouteAndLimitsForInstance(assignment.Primary(), role, assignment.ProviderInstance(), providerTimeouts)
	if err != nil {
		return ports.ProviderRoute{}, review.RouteBudget{}, err
	}
	budget, err := review.NewRouteBudget(route, limits)
	if err != nil {
		return ports.ProviderRoute{}, review.RouteBudget{}, err
	}
	return route, budget, nil
}
