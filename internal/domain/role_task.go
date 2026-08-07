package domain

import (
	"fmt"
	"strings"
)

type Role string

const (
	RoleLogic           Role = "logic"
	RoleSecurity        Role = "security"
	RoleMaintainability Role = "maintainability"
	RoleProduct         Role = "product"
	RoleDocumentation   Role = "documentation"
	RoleTesting         Role = "testing"
	RoleArtist          Role = "artist"
)

var fixedRoleOrder = [...]Role{RoleLogic, RoleSecurity, RoleMaintainability, RoleProduct, RoleDocumentation, RoleTesting, RoleArtist}

func (role Role) Valid() bool {
	return oneOf(string(role), string(RoleLogic), string(RoleSecurity), string(RoleMaintainability), string(RoleProduct), string(RoleDocumentation), string(RoleTesting), string(RoleArtist))
}

func (role Role) RequiredFloor() bool { return role == RoleLogic }

func FixedRoleOrder() []Role { return append([]Role(nil), fixedRoleOrder[:]...) }

// CoreRoleOrder returns the six unconditional roles retained for non-UI projects.
func CoreRoleOrder() []Role { return append([]Role(nil), fixedRoleOrder[:len(fixedRoleOrder)-1]...) }

// RoleTask is one role's assignment to exactly one provider. A role never
// changes provider mid-run: a failure is reported against the configured
// provider and the operator chooses any replacement.
type RoleTask struct {
	role            Role
	required        bool
	state           RoleTaskState
	primaryProvider string
}

func NewRoleTask(role Role, required bool, primaryProvider string) (RoleTask, error) {
	if !role.Valid() {
		return RoleTask{}, fmt.Errorf("role task: %w: invalid role %q", ErrInvariant, role)
	}
	primaryProvider = strings.TrimSpace(primaryProvider)
	if primaryProvider == "" {
		return RoleTask{}, fmt.Errorf("role task: %w: primary provider is required", ErrInvariant)
	}
	return RoleTask{role: role, required: required || role.RequiredFloor(), state: RoleTaskPending, primaryProvider: primaryProvider}, nil
}

func (task *RoleTask) transition(next RoleTaskState) error {
	if task == nil {
		return fmt.Errorf("role task: %w: nil receiver", ErrInvariant)
	}
	if err := task.state.RequireTransition(next); err != nil {
		return err
	}
	task.state = next
	return nil
}

func (task RoleTask) Role() Role              { return task.role }
func (task RoleTask) Required() bool          { return task.required }
func (task RoleTask) State() RoleTaskState    { return task.state }
func (task RoleTask) PrimaryProvider() string { return task.primaryProvider }
