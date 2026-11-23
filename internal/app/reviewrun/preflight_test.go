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
	documentation, err := NewRoleProviderAssignment(domain.RoleDocumentation, FamilyGrok)
	if err != nil {
		t.Fatal(err)
	}
	policy.Assignments = []RoleProviderAssignment{logic, documentation}
	timeouts := map[Family]time.Duration{
		FamilyZCode: 30 * time.Minute,
		FamilyGrok:  25 * time.Minute,
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
	assertPreflightRoute(1, "grok-documentation", 25*time.Minute)
	if receipt.TotalInvocations() != 4 {
		t.Fatalf("budget total invocations = %d", receipt.TotalInvocations())
	}
}

func TestRoleProviderInstanceMatchesConfiguredAssignment(t *testing.T) {
	for _, test := range []struct {
		name     string
		family   Family
		role     domain.Role
		instance string
		want     bool
	}{
		{name: "legacy zcode", family: FamilyZCode, role: domain.RoleLogic, instance: "zcode-logic", want: true},
		{name: "grok documentation", family: FamilyGrok, role: domain.RoleDocumentation, instance: "grok-documentation", want: true},
		{name: "profile on grok rejected", family: FamilyGrok, role: domain.RoleLogic, instance: "grok-work-logic"},
		{name: "unsupported grok artist", family: FamilyGrok, role: domain.RoleArtist, instance: "grok-artist"},
		{name: "retired cursor family", family: Family("cursor"), role: domain.RoleLogic, instance: "cursor-logic"},
		{name: "retired codex family", family: Family("codex"), role: domain.RoleLogic, instance: "codex-logic"},
		{name: "retired agy family", family: Family("agy"), role: domain.RoleDocumentation, instance: "agy-documentation"},
		{name: "wrong role", family: FamilyZCode, role: domain.RoleSecurity, instance: "zcode-logic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RoleProviderInstanceMatches(test.family, test.role, test.instance); got != test.want {
				t.Fatalf("RoleProviderInstanceMatches(%q, %q, %q) = %t, want %t", test.family, test.role, test.instance, got, test.want)
			}
		})
	}
}
