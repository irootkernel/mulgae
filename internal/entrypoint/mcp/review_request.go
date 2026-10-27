package mcpentry

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ErrReviewTargetInvalid marks selector rejection before request-field mapping.
var ErrReviewTargetInvalid = errors.New("MCP review target is invalid")

// NewReviewRequest maps decoded MCP fields without constructing a CLI invocation.
// Public handlers enforce their JSON grammar and 4096-byte objective bound first.
// Mapping preserves supported/public-admitted behavior, plus the former direct
// byte guard and role normalization. It does not recreate every private CLI
// parsing cause for arbitrary malformed direct calls.
func NewReviewRequest(input RunReviewInput, root, requestID string, preflight bool) (reviewrun.Request, error) {
	target, err := ports.NewLiveSourceSelector(domain.LiveSourceScope(input.Target.Kind), input.Target.Value)
	if err != nil {
		return reviewrun.Request{}, ErrReviewTargetInvalid
	}
	if root == "" || len(root) > 4096 || strings.ContainsAny(root, "\x00\r\n\\") || !filepath.IsAbs(root) || filepath.Clean(root) != root || !matches(requestIDPattern, requestID) {
		return reviewrun.Request{}, fmt.Errorf("MCP review identity is invalid")
	}
	// The former parser rejected flag-like operands before semantic field checks.
	if strings.HasPrefix(input.Target.Value, "--") {
		return reviewrun.Request{}, fmt.Errorf("MCP review target operand is malformed")
	}
	if input.ExpectedProjectBinding != nil && strings.HasPrefix(*input.ExpectedProjectBinding, "--") {
		return reviewrun.Request{}, fmt.Errorf("MCP review binding operand is malformed")
	}
	if input.Objective != "" && (len(input.Objective) > prompt.MaxObjectiveBytes || strings.ContainsAny(input.Objective, "\x00\r\n") || strings.HasPrefix(input.Objective, "--")) {
		return reviewrun.Request{}, fmt.Errorf("MCP review objective is malformed")
	}
	roles := make([]string, 0, len(domain.FixedRoleOrder()))
	if len(input.Roles) == 0 {
		for _, role := range domain.CoreRoleOrder() {
			roles = append(roles, string(role))
		}
	} else {
		// Preserve the old mapping's CSV normalization for direct backend callers;
		// the public tool grammar already admits only individual fixed role IDs.
		requested := strings.Split(strings.Join(input.Roles, ","), ",")
		if len(requested) > len(domain.FixedRoleOrder()) {
			return reviewrun.Request{}, fmt.Errorf("MCP review roles are invalid")
		}
		seen := make(map[domain.Role]bool, len(requested))
		for _, value := range requested {
			role := domain.Role(value)
			if !role.Valid() || seen[role] {
				return reviewrun.Request{}, fmt.Errorf("MCP review roles are invalid")
			}
			seen[role] = true
		}
		for _, role := range domain.FixedRoleOrder() {
			if seen[role] {
				roles = append(roles, string(role))
			}
		}
	}
	var binding domain.ProjectBinding
	if input.ExpectedProjectBinding != nil {
		binding, err = domain.ParseProjectBinding(*input.ExpectedProjectBinding)
		if err != nil {
			return reviewrun.Request{}, reviewrun.ErrGuardInvalid
		}
	}
	var requirementsPath string
	if input.RequirementsPath != nil {
		requirementsPath = *input.RequirementsPath
		if _, err := ports.NewSafeRelativePath(requirementsPath); err != nil || strings.HasPrefix(requirementsPath, "--") {
			return reviewrun.Request{}, fmt.Errorf("MCP requirements path is invalid")
		}
	}
	return reviewrun.NewRequest(reviewrun.RequestInput{
		RequirementsPath: requirementsPath, HasRequirements: input.RequirementsPath != nil,
		Target: target, Objective: input.Objective, HasObjective: input.Objective != "",
		Roles: roles, RolesExplicit: len(input.Roles) != 0, Preflight: preflight, ExpectedProjectBinding: binding,
	}), nil
}
