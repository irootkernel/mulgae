// Package roles exposes the fixed build-owned review role inventory.
package roles

import "github.com/irootkernel/mulgae/internal/domain"

type Availability string

const (
	AvailabilityAllProjects Availability = "all_projects"
	AvailabilityUIProjects  Availability = "ui_projects"
)

type Role struct {
	ID           string       `json:"id"`
	Mandatory    bool         `json:"mandatory"`
	Availability Availability `json:"availability"`
}

// ListRoles returns every built-in role in canonical order.
func ListRoles() []Role {
	roles := make([]Role, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		availability := AvailabilityAllProjects
		if role == domain.RoleArtist {
			availability = AvailabilityUIProjects
		}
		roles = append(roles, Role{
			ID:           string(role),
			Mandatory:    role.RequiredFloor(),
			Availability: availability,
		})
	}
	return roles
}
