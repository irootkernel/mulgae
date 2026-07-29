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
			if assignment.HasFallback() {
				t.Fatal("HasFallback() = true, want false")
			}
			if fallback, ok := assignment.FallbackRoute(); ok || fallback.Valid() {
				t.Fatalf("FallbackRoute() = (%+v, %t), want invalid route and false", fallback, ok)
			}
		})
	}
}

func TestNewScheduledAssignmentStoresExplicitRoutes(t *testing.T) {
	t.Parallel()

	primary := assignmentTestRoute(t, "primary.product", "product-primary")
	fallback := assignmentTestRoute(t, "fallback.product", "product-fallback")
	assignment, err := NewScheduledAssignment(domain.RoleProduct, false, primary, &fallback)
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
	if !assignment.HasFallback() {
		t.Fatal("HasFallback() = false, want true")
	}
	if got, ok := assignment.FallbackRoute(); !ok || got != fallback {
		t.Fatalf("FallbackRoute() = (%+v, %t), want (%+v, true)", got, ok, fallback)
	}
}

func TestNewScheduledAssignmentPreservesRequiredFloorForAllRoles(t *testing.T) {
	t.Parallel()

	for _, role := range domain.CoreRoleOrder() {
		t.Run(string(role), func(t *testing.T) {
			primary := assignmentTestRoute(t, "scheduled."+string(role), "lane-"+string(role))
			assignment, err := NewScheduledAssignment(role, false, primary, nil)
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

	primary := assignmentTestRoute(t, "primary.product", "product-primary")
	zero := ports.ProviderRoute{}
	for _, test := range []struct {
		name     string
		primary  ports.ProviderRoute
		fallback *ports.ProviderRoute
	}{
		{name: "zero primary", primary: zero},
		{name: "zero fallback", primary: primary, fallback: &zero},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewScheduledAssignment(domain.RoleProduct, false, test.primary, test.fallback); err == nil {
				t.Fatal("NewScheduledAssignment() succeeded")
			}
		})
	}
}

func TestNewScheduledAssignmentRejectsUnsafeFallbackRoutes(t *testing.T) {
	t.Parallel()

	primary := assignmentTestRoute(t, "primary.security", "security-primary")
	sameProvider := assignmentTestRoute(t, "primary.security", "security-fallback")
	sameLane := assignmentTestRoute(t, "fallback.security", "security-primary")
	for _, test := range []struct {
		name     string
		fallback ports.ProviderRoute
	}{
		{name: "same provider instance", fallback: sameProvider},
		{name: "same normalized concurrency key", fallback: sameLane},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewScheduledAssignment(domain.RoleSecurity, false, primary, &test.fallback); err == nil {
				t.Fatal("NewScheduledAssignment() succeeded")
			}
		})
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
