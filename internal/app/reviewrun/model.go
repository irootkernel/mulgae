package reviewrun

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RunSelection is the trusted ordered role selection and optional existing
// session identity for one root review invocation.
type RunSelection struct {
	roles     []domain.Role
	sessionID *domain.SessionID
}

// NewRunSelection validates a non-empty, duplicate-free ordered role list.
// sessionID may be nil; a supplied ID must be canonical.
func NewRunSelection(roles []domain.Role, sessionID *domain.SessionID) (RunSelection, error) {
	if len(roles) == 0 {
		return RunSelection{}, fmt.Errorf("review run: at least one role is required")
	}
	seen := make(map[domain.Role]struct{}, len(roles))
	for _, role := range roles {
		if !role.Valid() {
			return RunSelection{}, fmt.Errorf("review run: invalid role %q", role)
		}
		if _, exists := seen[role]; exists {
			return RunSelection{}, fmt.Errorf("review run: duplicate role %q", role)
		}
		seen[role] = struct{}{}
	}
	selection := RunSelection{roles: append([]domain.Role(nil), roles...)}
	if sessionID != nil {
		if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
			return RunSelection{}, fmt.Errorf("review run: invalid session ID: %w", err)
		}
		sessionCopy := *sessionID
		selection.sessionID = &sessionCopy
	}
	return selection, nil
}

// Roles returns a caller-owned copy in the original requested order.
func (selection RunSelection) Roles() []domain.Role {
	return append([]domain.Role(nil), selection.roles...)
}

// SessionID returns the optional canonical session ID.
func (selection RunSelection) SessionID() (domain.SessionID, bool) {
	if selection.sessionID == nil {
		return domain.SessionID{}, false
	}
	return *selection.sessionID, true
}

func (selection RunSelection) Valid() bool {
	session, hasSession := selection.SessionID()
	if !hasSession {
		_, err := NewRunSelection(selection.roles, nil)
		return err == nil
	}
	_, err := NewRunSelection(selection.roles, &session)
	return err == nil
}

// ExecutionPlan contains only already-qualified routing and trusted execution
// limits. Planning has no provider invocation or publication authority.
type ExecutionPlan struct {
	Assignments []review.Assignment
	Budgets     []review.RoleBudget
	Ceilings    review.HarnessCeilings
	Threshold   domain.Severity
	Policy      *domain.CIPolicy
	MaxWorkers  int
	Extraction  bool
}

func (plan ExecutionPlan) clone() ExecutionPlan {
	result := plan
	result.Assignments = append([]review.Assignment(nil), plan.Assignments...)
	result.Budgets = append([]review.RoleBudget(nil), plan.Budgets...)
	if plan.Policy != nil {
		policy := *plan.Policy
		result.Policy = &policy
	}
	return result
}

// ExecutionPlanner supplies already-qualified assignments and matching budgets.
type ExecutionPlanner interface {
	PlanSelectedRoles(context.Context, []domain.Role) (ExecutionPlan, error)
}

// BuildIdentity is immutable provenance attached to a qualified production run.
type BuildIdentity struct {
	Product     string
	Version     string
	Module      string
	ModuleSum   string
	VCSRevision string
}

func (identity BuildIdentity) Valid() bool {
	return identity.Product == "mulgae" &&
		identity.Version != "" &&
		identity.Module == "github.com/irootkernel/mulgae" &&
		(identity.ModuleSum != "" || identity.VCSRevision != "")
}

func (identity BuildIdentity) ImmutableReference() string {
	if identity.VCSRevision != "" {
		return identity.VCSRevision
	}
	return identity.ModuleSum
}

// RunAuthority owns provider credentials and routing authority for exactly one
// changed run. DrainTerminal must be bounded and idempotent.
type RunAuthority interface {
	Provider() ports.ObservedReviewProvider
	Planner() ExecutionPlanner
	BuildIdentity() BuildIdentity
	DrainTerminal(context.Context) (QualifiedRunTerminalReceipt, error)
}

// RoleReportURI is one trusted project-relative role-report identity projected
// from a PublicationResult verified support inventory before Result is built.
type RoleReportURI struct {
	Role       string
	URI        string
	SHA256     string
	ByteLength int
}

// Result exposes only the coherent P2 authority returned by publication.
type Result struct {
	projectBinding domain.ProjectBinding
	sourceIdentity string
	guarded        bool
	sessionID      domain.SessionID
	runID          domain.RunID
	coordinator    review.CoordinatorResult
	final          ports.FinalReviewIdentity
	snapshot       ports.CommittedPublicationSnapshot
	exit           domain.OperationalExitDecision
	roleReportURIs []RoleReportURI
	diagnostic     ports.SafeRelativePath
}

func newResult(sessionID domain.SessionID, runID domain.RunID, coordinator review.CoordinatorResult, final ports.FinalReviewIdentity, snapshot ports.CommittedPublicationSnapshot, roleReportURIs []RoleReportURI, exit domain.OperationalExitDecision) (Result, error) {
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return Result{}, fmt.Errorf("review run: invalid result session ID")
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return Result{}, fmt.Errorf("review run: invalid result run ID")
	}
	if err := validateRoleReportURIs(sessionID, runID, roleReportURIs); err != nil {
		return Result{}, fmt.Errorf("review run: %w", err)
	}
	return Result{
		sessionID: sessionID, runID: runID, coordinator: coordinator, final: final, snapshot: snapshot,
		exit: exit, roleReportURIs: append([]RoleReportURI(nil), roleReportURIs...),
	}, nil
}

func (result Result) Guarded() bool { return result.guarded }

func (result Result) SessionID() domain.SessionID                  { return result.sessionID }
func (result Result) LiveProjectBinding() domain.ProjectBinding    { return result.projectBinding }
func (result Result) SourceIdentitySHA256() string                 { return result.sourceIdentity }
func (result Result) RunID() domain.RunID                          { return result.runID }
func (result Result) Coordinator() review.CoordinatorResult        { return result.coordinator }
func (result Result) Final() ports.FinalReviewIdentity             { return result.final }
func (result Result) Snapshot() ports.CommittedPublicationSnapshot { return result.snapshot }
func (result Result) TerminalExit() domain.OperationalExitDecision { return result.exit }
func (result Result) RoleReportURIs() []RoleReportURI {
	return append([]RoleReportURI(nil), result.roleReportURIs...)
}
func (result Result) RuntimeDiagnosticURI() (ports.SafeRelativePath, bool) {
	return result.diagnostic, result.diagnostic.Valid()
}

// projectRoleReportURIs maps PublicationResult support-inventory authority into
// app-neutral Result fields. Callers must not invent paths from manifests alone.
func projectRoleReportURIs(published publication.PublicationResult) ([]RoleReportURI, error) {
	projected, err := publication.ProjectRoleReportURIs(published)
	if err != nil {
		return nil, err
	}
	uris := make([]RoleReportURI, 0, len(projected))
	for _, report := range projected {
		uris = append(uris, RoleReportURI{
			Role:       report.Role,
			URI:        report.URI,
			SHA256:     report.SHA256,
			ByteLength: report.ByteLength,
		})
	}
	return uris, nil
}

func validateRoleReportURIs(sessionID domain.SessionID, runID domain.RunID, reports []RoleReportURI) error {
	prefix := ".mulgae/" + sessionID.String() + "/" + runID.String() + "/role-reports/"
	seen := make(map[string]struct{}, len(reports))
	for _, report := range reports {
		if !domain.Role(report.Role).Valid() ||
			report.URI != prefix+report.Role+".md" ||
			!validRoleReportDigest(report.SHA256) ||
			report.ByteLength <= 0 {
			return fmt.Errorf("role report identity is invalid")
		}
		if _, duplicate := seen[report.Role]; duplicate {
			return fmt.Errorf("role report identity is duplicated")
		}
		seen[report.Role] = struct{}{}
	}
	return nil
}

func validRoleReportDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Interface || v.Kind() == reflect.Func || v.Kind() == reflect.Chan) && v.IsNil()
}

func validatePlan(plan ExecutionPlan, requestedRoles []domain.Role) (review.RunBudgetReceipt, error) {
	if len(requestedRoles) == 0 || len(plan.Assignments) == 0 || len(plan.Budgets) == 0 || plan.MaxWorkers < 1 || !plan.Threshold.Valid() {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: incomplete execution plan")
	}
	if len(plan.Assignments) != len(requestedRoles) || len(plan.Budgets) != len(requestedRoles) {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: plan does not exactly match requested roles")
	}
	for index, assignment := range plan.Assignments {
		if assignment.Role() != requestedRoles[index] || plan.Budgets[index].Role() != requestedRoles[index] || assignment.Role() != plan.Budgets[index].Role() || !assignment.PrimaryRoute().Valid() || assignment.PrimaryRoute() != plan.Budgets[index].Primary().Route() {
			return review.RunBudgetReceipt{}, fmt.Errorf("review run: assignment and budget mismatch")
		}
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(plan.Budgets, plan.Ceilings, plan.MaxWorkers)
	if err != nil || !receipt.Eligible() {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: budget preflight failed: %w", err)
	}
	return receipt, nil
}
