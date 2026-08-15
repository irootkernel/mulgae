package reviewrun

import (
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestPreflightConfiguredPlanUsesProductionRoutesAndConfiguredTimeouts(t *testing.T) {
	policy := DefaultPlannerPolicy()
	logic, err := NewRoleProviderAssignment(domain.RoleLogic, FamilyZCode)
	if err != nil {
		t.Fatal(err)
	}
	documentation, err := NewRoleProviderAssignment(domain.RoleDocumentation, FamilyAGY)
	if err != nil {
		t.Fatal(err)
	}
	policy.Assignments = []RoleProviderAssignment{logic, documentation}
	timeouts := map[Family]time.Duration{
		FamilyKimi:  10 * time.Minute,
		FamilyZCode: 30 * time.Minute,
		FamilyAGY:   15 * time.Minute,
	}
	plan, receipt, err := PreflightConfiguredPlan(policy, timeouts, []domain.Role{domain.RoleLogic, domain.RoleDocumentation})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Eligible() || len(plan.Assignments) != 2 || len(plan.Budgets) != 2 {
		t.Fatalf("preflight plan/receipt = %#v/%#v", plan, receipt)
	}
	assertPreflightRoute := func(index int, wantInstance string, wantTimeout time.Duration) {
		t.Helper()
		budget := plan.Budgets[index].Primary()
		if budget.Route().ProviderInstance() != wantInstance || budget.Limits().Timeout() != wantTimeout {
			t.Fatalf("route = %s/%s, want %s/%s", budget.Route().ProviderInstance(), budget.Limits().Timeout(), wantInstance, wantTimeout)
		}
	}
	// One route per role, each carrying its own family's configured timeout.
	assertPreflightRoute(0, "zcode-logic", 30*time.Minute)
	assertPreflightRoute(1, "agy-documentation", 15*time.Minute)
	if receipt.TotalInvocations() != 4 {
		t.Fatalf("budget total invocations = %d", receipt.TotalInvocations())
	}
}
