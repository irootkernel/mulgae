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
)

var fixedRoleOrder = [...]Role{RoleLogic, RoleSecurity, RoleMaintainability, RoleProduct, RoleDocumentation, RoleTesting}

func (role Role) Valid() bool {
	return oneOf(string(role), string(RoleLogic), string(RoleSecurity), string(RoleMaintainability), string(RoleProduct), string(RoleDocumentation), string(RoleTesting))
}

func (role Role) RequiredFloor() bool { return role == RoleLogic || role == RoleSecurity }

func FixedRoleOrder() []Role { return append([]Role(nil), fixedRoleOrder[:]...) }

type RoleTask struct {
	role                Role
	required            bool
	state               RoleTaskState
	primaryProvider     string
	fallbackProvider    string
	hasFallback         bool
	primaryFailureClass FailureClass
	hasPrimaryFailure   bool
}

func NewRoleTask(role Role, required bool, primaryProvider string, fallbackProvider *string) (RoleTask, error) {
	if !role.Valid() {
		return RoleTask{}, fmt.Errorf("role task: %w: invalid role %q", ErrInvariant, role)
	}
	primaryProvider = strings.TrimSpace(primaryProvider)
	if primaryProvider == "" {
		return RoleTask{}, fmt.Errorf("role task: %w: primary provider is required", ErrInvariant)
	}
	task := RoleTask{role: role, required: required || role.RequiredFloor(), state: RoleTaskPending, primaryProvider: primaryProvider}
	if fallbackProvider != nil {
		fallback := strings.TrimSpace(*fallbackProvider)
		if fallback == "" || fallback == primaryProvider {
			return RoleTask{}, fmt.Errorf("role task: %w: fallback must be non-empty and different from primary", ErrInvariant)
		}
		task.fallbackProvider = fallback
		task.hasFallback = true
	}
	return task, nil
}

func (task *RoleTask) transition(next RoleTaskState) error {
	if task == nil {
		return fmt.Errorf("role task: %w: nil receiver", ErrInvariant)
	}
	if next == RoleTaskFallbackQueued {
		return fmt.Errorf("role task: %w: fallback queuing requires Run.QueueRoleFallback", ErrInvariant)
	}
	if (task.state == RoleTaskFallbackQueued || task.state == RoleTaskFallbackRunning || next == RoleTaskFallbackRunning) && !task.fallbackEligible() {
		return fmt.Errorf("role task: %w: fallback progression requires a recorded eligible primary failure", ErrInvariant)
	}
	if err := task.state.RequireTransition(next); err != nil {
		return err
	}
	task.state = next
	return nil
}

func (task *RoleTask) queueFallback(failureClass FailureClass) error {
	if task == nil {
		return fmt.Errorf("role task: %w: nil receiver", ErrInvariant)
	}
	if !task.hasFallback {
		return fmt.Errorf("role task: %w: fallback provider is not configured", ErrInvariant)
	}
	if task.state != RoleTaskPrimaryRunning {
		return fmt.Errorf("role task: %w: fallback requires a running primary", ErrInvariant)
	}
	if !failureClass.Valid() || !failureClass.FallbackAllowed() {
		return fmt.Errorf("role task: %w: failure class %q is not eligible for fallback", ErrInvariant, failureClass)
	}
	if err := task.state.RequireTransition(RoleTaskFallbackQueued); err != nil {
		return err
	}
	task.primaryFailureClass = failureClass
	task.hasPrimaryFailure = true
	task.state = RoleTaskFallbackQueued
	return nil
}

func (task RoleTask) fallbackEligible() bool {
	return task.hasFallback && task.hasPrimaryFailure && task.primaryFailureClass.Valid() && task.primaryFailureClass.FallbackAllowed()
}

func (task RoleTask) Role() Role              { return task.role }
func (task RoleTask) Required() bool          { return task.required }
func (task RoleTask) State() RoleTaskState    { return task.state }
func (task RoleTask) PrimaryProvider() string { return task.primaryProvider }
func (task RoleTask) FallbackProvider() (string, bool) {
	return task.fallbackProvider, task.hasFallback
}
func (task RoleTask) PrimaryFailureClass() (FailureClass, bool) {
	return task.primaryFailureClass, task.hasPrimaryFailure
}
