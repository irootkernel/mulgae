package providercli

import (
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestDeriveEquivalentRouteRequiresSourceMatches(t *testing.T) {
	definition, authority := currentProbeAuthorityForDefinition(t)
	foreign := definition
	foreign.instance = "other"
	foreign.profileID = "other-profile"
	if _, err := DeriveEquivalentRouteDirectExecutionAuthority(
		authority, foreign, definition, "1.2.3", "generation", "generation",
		[]domain.Role{domain.RoleLogic}, []domain.Role{domain.RoleLogic},
	); err == nil {
		t.Fatal("derivation accepted source authority that does not match source runtime")
	}
}

func repeatHex(digit byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = digit
	}
	return string(out)
}
