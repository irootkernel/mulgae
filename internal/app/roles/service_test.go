package roles

import "testing"

func TestListRolesReturnsCanonicalInventory(t *testing.T) {
	roles := ListRoles()
	if len(roles) != 7 {
		t.Fatalf("role count = %d, want 7", len(roles))
	}
	for index, id := range []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"} {
		if roles[index].ID != id || roles[index].Mandatory != (id == "logic") {
			t.Fatalf("role %d = %#v", index, roles[index])
		}
	}
	if roles[6].Availability != AvailabilityUIProjects {
		t.Fatalf("artist availability = %q", roles[6].Availability)
	}
}
