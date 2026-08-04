package reviewrun

import (
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestPreflightConfiguredPlanUsesProductionRoutesAndConfiguredTimeouts(t *testing.T) {
	policy := DefaultPlannerPolicy()
	logic, err := NewRoleProviderAssignment(domain.RoleLogic, FamilyZCode, FamilyAGY)
	if err != nil {
		t.Fatal(err)
	}
	documentation, err := NewRoleProviderAssignment(domain.RoleDocumentation, FamilyAGY, FamilyZCode)
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
	assertPreflightRoute := func(index int, fallback bool, wantInstance string, wantTimeout time.Duration) {
		t.Helper()
		budget := plan.Budgets[index].Primary()
		if fallback {
			var present bool
			budget, present = plan.Budgets[index].Fallback()
			if !present {
				t.Fatalf("role %d has no fallback", index)
			}
		}
		if budget.Route().ProviderInstance() != wantInstance || budget.Route().ConcurrencyKey().String() != wantInstance || budget.Limits().Timeout() != wantTimeout {
			t.Fatalf("route = %s/%s/%s, want %s/%s/%s", budget.Route().ProviderInstance(), budget.Route().ConcurrencyKey(), budget.Limits().Timeout(), wantInstance, wantInstance, wantTimeout)
		}
	}
	assertPreflightRoute(0, false, "zcode-logic", 30*time.Minute)
	assertPreflightRoute(0, true, "agy-logic", 15*time.Minute)
	assertPreflightRoute(1, false, "agy-documentation", 15*time.Minute)
	assertPreflightRoute(1, true, "zcode-documentation", 30*time.Minute)
	if receipt.TotalInvocations() != 8 || receipt.TotalOutputCap() != 8*(512<<10) {
		t.Fatalf("budget totals = %d/%d", receipt.TotalInvocations(), receipt.TotalOutputCap())
	}
}
