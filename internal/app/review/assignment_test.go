package review

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestNewAssignmentPreservesG004CompatibilityAndLegacyLane(t *testing.T) {
	t.Parallel()

	for _, role := range domain.CoreRoleOrder() {
		t.Run(string(role), func(t *testing.T) {
			assignment, err := NewAssignment(role, false, "fake."+string(role))
			if err != nil {
				t.Fatal(err)
			}
			if assignment.Role() != role {
				t.Fatalf("Role() = %q, want %q", assignment.Role(), role)
			}
			if assignment.Required() != role.RequiredFloor() {
				t.Fatalf("Required() = %t, want %t", assignment.Required(), role.RequiredFloor())
			}
			if got, want := assignment.ProviderInstance(), "fake."+string(role); got != want {
				t.Fatalf("ProviderInstance() = %q, want %q", got, want)
			}
			primary := assignment.PrimaryRoute()
			if !primary.Valid() {
				t.Fatal("PrimaryRoute() is invalid")
			}
			if got := primary.ConcurrencyKey().String(); got != legacyConcurrencyKey {
				t.Fatalf("PrimaryRoute().ConcurrencyKey() = %q, want %q", got, legacyConcurrencyKey)
			}
		})
	}
}

func TestNewScheduledAssignmentStoresTheSingleExplicitRoute(t *testing.T) {
	t.Parallel()

	primary := assignmentTestRoute(t, "primary.product", "product-primary")
	assignment, err := NewScheduledAssignment(domain.RoleProduct, false, primary)
	if err != nil {
		t.Fatal(err)
	}

	if assignment.Role() != domain.RoleProduct || assignment.Required() {
		t.Fatalf("assignment role/required = %q/%t, want product/false", assignment.Role(), assignment.Required())
	}
	if assignment.ProviderInstance() != primary.ProviderInstance() {
		t.Fatalf("ProviderInstance() = %q, want %q", assignment.ProviderInstance(), primary.ProviderInstance())
	}
	if got := assignment.PrimaryRoute(); got != primary {
		t.Fatalf("PrimaryRoute() = %+v, want %+v", got, primary)
	}
}

func TestNewScheduledAssignmentPreservesRequiredFloorForAllRoles(t *testing.T) {
	t.Parallel()

	for _, role := range domain.CoreRoleOrder() {
		t.Run(string(role), func(t *testing.T) {
			primary := assignmentTestRoute(t, "scheduled."+string(role), "lane-"+string(role))
			assignment, err := NewScheduledAssignment(role, false, primary)
			if err != nil {
				t.Fatal(err)
			}
			if assignment.Required() != role.RequiredFloor() {
				t.Fatalf("Required() = %t, want %t", assignment.Required(), role.RequiredFloor())
			}
		})
	}
}

func TestNewScheduledAssignmentRejectsInvalidRoutes(t *testing.T) {
	t.Parallel()

	if _, err := NewScheduledAssignment(domain.RoleProduct, false, ports.ProviderRoute{}); err == nil {
		t.Fatal("NewScheduledAssignment() accepted a zero route")
	}
}

func assignmentTestRoute(t *testing.T, providerInstance, concurrencyKey string) ports.ProviderRoute {
	t.Helper()

	key, err := ports.ParseConcurrencyKey(concurrencyKey)
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute(providerInstance, key)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
