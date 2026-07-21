package reviewrun

import (
	"context"
	"fmt"
	"reflect"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/publication"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type InputCaptureRequest struct {
	root         ports.AnchoredRoot
	target       ports.ReviewTargetSelector
	objective    []byte
	hasObjective bool
}

func NewInputCaptureRequest(root ports.AnchoredRoot, target ports.ReviewTargetSelector, objective []byte, hasObjective bool) (InputCaptureRequest, error) {
	if !root.Valid() || !target.Valid() || !hasObjective && len(objective) != 0 {
		return InputCaptureRequest{}, fmt.Errorf("review run: invalid input capture request")
	}
	return InputCaptureRequest{root: root, target: target, objective: append([]byte(nil), objective...), hasObjective: hasObjective}, nil
}
func (request InputCaptureRequest) Root() ports.AnchoredRoot           { return request.root }
func (request InputCaptureRequest) Target() ports.ReviewTargetSelector { return request.target }
func (request InputCaptureRequest) Objective() ([]byte, bool) {
	return append([]byte(nil), request.objective...), request.hasObjective
}
func (request InputCaptureRequest) Valid() bool {
	_, err := NewInputCaptureRequest(request.root, request.target, request.objective, request.hasObjective)
	return err == nil
}

type ImmutableInputSourceFactory interface {
	NewImmutableInputSource(context.Context, InputCaptureRequest) (ImmutableInputSource, error)
}

// Request identifies the one trusted root-review invocation. ProjectRoot binds
// capture to the original repository while ArtifactRoot binds durable P2 output
// to its private project-local namespace.
type Request struct {
	InputSource  ImmutableInputSource
	ProjectRoot  ports.AnchoredRoot
	ArtifactRoot ports.AnchoredRoot
	Selection    RunSelection
}

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

// ImmutableReviewInput is the single captured snapshot used throughout a run.
type ImmutableReviewInput struct {
	target            ports.CapturedReviewTarget
	objective         []byte
	hasObjective      bool
	projectContext    []byte
	hasProjectContext bool
}

// NewImmutableReviewInputWithProjectContext validates a captured target and
// takes defensive ownership of the exact objective and project-context bytes.
func NewImmutableReviewInputWithProjectContext(target ports.CapturedReviewTarget, objective []byte, hasObjective bool, projectContext []byte, hasProjectContext bool) (ImmutableReviewInput, error) {
	if !target.Valid() || (!hasObjective && len(objective) != 0) || (!hasProjectContext && len(projectContext) != 0) {
		return ImmutableReviewInput{}, fmt.Errorf("review run: invalid captured review target")
	}
	input := ImmutableReviewInput{
		target: target, objective: append([]byte(nil), objective...), hasObjective: hasObjective,
		hasProjectContext: hasProjectContext,
	}
	if hasProjectContext {
		input.projectContext = append([]byte{}, projectContext...)
	}
	return input, nil
}

// NewImmutableReviewInput is the compatibility constructor for callers without
// explicit project-context presence. A nil context is absent; a non-nil context
// is present, including an empty slice.
func NewImmutableReviewInput(target ports.CapturedReviewTarget, objective []byte, hasObjective bool, projectContext []byte) (ImmutableReviewInput, error) {
	return NewImmutableReviewInputWithProjectContext(target, objective, hasObjective, projectContext, projectContext != nil)
}

func (input ImmutableReviewInput) Target() ports.CapturedReviewTarget { return input.target }
func (input ImmutableReviewInput) Objective() []byte                  { return append([]byte(nil), input.objective...) }
func (input ImmutableReviewInput) HasObjective() bool                 { return input.hasObjective }
func (input ImmutableReviewInput) ProjectContext() []byte {
	if !input.hasProjectContext {
		return nil
	}
	return append([]byte{}, input.projectContext...)
}
func (input ImmutableReviewInput) HasProjectContext() bool { return input.hasProjectContext }

// CapturedRunInput transfers the immutable input, immutable evidence reader,
// and sole workspace lease from capture into the review service.
type CapturedRunInput struct {
	input          ImmutableReviewInput
	lease          ports.WorkspaceSnapshotLease
	reader         evidence.ImmutableTargetReader
	packetDetector ports.ReviewInputContentDetector
}

func NewCapturedRunInput(input ImmutableReviewInput, lease ports.WorkspaceSnapshotLease, reader evidence.ImmutableTargetReader, packetDetectors ...ports.ReviewInputContentDetector) (CapturedRunInput, error) {
	if !input.Target().Valid() || nilInterface(lease) || !lease.WorkspaceSnapshotIdentity().Valid() || len(packetDetectors) > 1 {
		return CapturedRunInput{}, fmt.Errorf("review run: invalid captured run input")
	}
	if !input.Target().NoChange() && nilInterface(reader) {
		return CapturedRunInput{}, fmt.Errorf("review run: changed target requires immutable evidence reader")
	}
	var packetDetector ports.ReviewInputContentDetector
	if len(packetDetectors) == 1 {
		packetDetector = packetDetectors[0]
		if nilInterface(packetDetector) {
			return CapturedRunInput{}, fmt.Errorf("review run: invalid captured run input")
		}
	}
	return CapturedRunInput{input: input, lease: lease, reader: reader, packetDetector: packetDetector}, nil
}
func (captured CapturedRunInput) Input() ImmutableReviewInput { return captured.input }
func (captured CapturedRunInput) WorkspaceLease() ports.WorkspaceSnapshotLease {
	return captured.lease
}
func (captured CapturedRunInput) ImmutableTargetReader() evidence.ImmutableTargetReader {
	return captured.reader
}
func (captured CapturedRunInput) PacketDetector() ports.ReviewInputContentDetector {
	return captured.packetDetector
}

// ImmutableInputSource captures all user-controlled material and its sole
// workspace lease exactly once.
type ImmutableInputSource interface {
	Capture(context.Context, Request) (CapturedRunInput, error)
}

// ExecutionPlan contains only already-qualified routing and trusted execution
// limits. Planning has no provider invocation or publication authority.
type ExecutionPlan struct {
	Assignments []review.Assignment
	Budgets     []review.RoleBudget
	Ceilings    review.HarnessCeilings
	Threshold   domain.Severity
	Policy      *domain.CIPolicy
	MaxLanes    int
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

// PlanningRequest binds immutable input to the exact ordered role selection
// that a planner is authorized to assign.
type PlanningRequest struct {
	input          ImmutableReviewInput
	requestedRoles []domain.Role
}

// NewPlanningRequest validates and defensively retains requested role order.
func NewPlanningRequest(input ImmutableReviewInput, requestedRoles []domain.Role) (PlanningRequest, error) {
	if !input.Target().Valid() {
		return PlanningRequest{}, fmt.Errorf("review run: invalid immutable input")
	}
	if _, err := NewRunSelection(requestedRoles, nil); err != nil {
		return PlanningRequest{}, err
	}
	return PlanningRequest{input: input, requestedRoles: append([]domain.Role(nil), requestedRoles...)}, nil
}

// Input returns the immutable captured input.
func (request PlanningRequest) Input() ImmutableReviewInput { return request.input }

// RequestedRoles returns a caller-owned copy in requested order.
func (request PlanningRequest) RequestedRoles() []domain.Role {
	return append([]domain.Role(nil), request.requestedRoles...)
}

// ExecutionPlanner supplies already-qualified assignments and matching budgets.
type ExecutionPlanner interface {
	Plan(context.Context, PlanningRequest) (ExecutionPlan, error)
}

// BuildIdentity is immutable provenance attached to a qualified production run.
type BuildIdentity struct {
	Product string
	Version string
	Commit  string
}

func (identity BuildIdentity) Valid() bool {
	return identity.Product != "" && identity.Version != "" && identity.Commit != ""
}

// RunAuthorityFactory is the sole production authority factory for a changed
// run. It is deliberately invoked only after no-change admission.
type RunAuthorityFactory interface {
	NewQualifiedRun(context.Context, CapturedRunInput, RunSelection) (RunAuthority, error)
}

// RunAuthority owns provider credentials and routing authority for exactly one
// changed run. DrainTerminal must be bounded and idempotent.
type RunAuthority interface {
	Provider() ports.ObservedReviewProvider
	Planner() ExecutionPlanner
	BuildIdentity() BuildIdentity
	DrainTerminal(context.Context) (QualifiedRunTerminalReceipt, error)
}

// Dependencies are injected application services and ports. They intentionally
// exclude filesystem, process construction, and provider discovery.
type Dependencies struct {
	Clock               ports.Clock
	IDs                 review.IdentityGenerator
	Build               BuildIdentity
	RunAuthorityFactory RunAuthorityFactory
	Validator           *validation.ReviewValidator
	Locker              ports.LaneLocker
	Publication         publication.PublicationCommitter
	Templates           review.TemplateSet
}

// Result exposes only the coherent P2 authority returned by publication.
type Result struct {
	sessionID   domain.SessionID
	runID       domain.RunID
	coordinator review.CoordinatorResult
	final       ports.FinalReviewIdentity
	snapshot    ports.CommittedPublicationSnapshot
	exit        domain.OperationalExitDecision
}

func newResult(sessionID domain.SessionID, runID domain.RunID, coordinator review.CoordinatorResult, final ports.FinalReviewIdentity, snapshot ports.CommittedPublicationSnapshot, exit domain.OperationalExitDecision) (Result, error) {
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return Result{}, fmt.Errorf("review run: invalid result session ID")
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return Result{}, fmt.Errorf("review run: invalid result run ID")
	}
	return Result{sessionID: sessionID, runID: runID, coordinator: coordinator, final: final, snapshot: snapshot, exit: exit}, nil
}

func (result Result) SessionID() domain.SessionID                  { return result.sessionID }
func (result Result) RunID() domain.RunID                          { return result.runID }
func (result Result) Coordinator() review.CoordinatorResult        { return result.coordinator }
func (result Result) Final() ports.FinalReviewIdentity             { return result.final }
func (result Result) Snapshot() ports.CommittedPublicationSnapshot { return result.snapshot }
func (result Result) TerminalExit() domain.OperationalExitDecision { return result.exit }

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Ptr || v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Interface || v.Kind() == reflect.Func || v.Kind() == reflect.Chan) && v.IsNil()
}

func validatePlan(plan ExecutionPlan, requestedRoles []domain.Role) (review.RunBudgetReceipt, error) {
	if len(requestedRoles) == 0 || len(plan.Assignments) == 0 || len(plan.Budgets) == 0 || plan.MaxLanes < 1 || !plan.Threshold.Valid() {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: incomplete execution plan")
	}
	if len(plan.Assignments) != len(requestedRoles) || len(plan.Budgets) != len(requestedRoles) {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: plan does not exactly match requested roles")
	}
	for index, assignment := range plan.Assignments {
		if assignment.Role() != requestedRoles[index] || plan.Budgets[index].Role() != requestedRoles[index] || assignment.Role() != plan.Budgets[index].Role() || !assignment.PrimaryRoute().Valid() || assignment.PrimaryRoute() != plan.Budgets[index].Primary().Route() {
			return review.RunBudgetReceipt{}, fmt.Errorf("review run: assignment and budget mismatch")
		}
		budgetFallback, hasBudgetFallback := plan.Budgets[index].Fallback()
		assignmentFallback, hasAssignmentFallback := assignment.FallbackRoute()
		if hasBudgetFallback != hasAssignmentFallback || hasBudgetFallback && budgetFallback.Route() != assignmentFallback {
			return review.RunBudgetReceipt{}, fmt.Errorf("review run: fallback assignment and budget mismatch")
		}
	}
	receipt, err := review.PreflightRunBudget(plan.Budgets, plan.Ceilings)
	if err != nil || !receipt.Eligible() {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: budget preflight failed: %w", err)
	}
	return receipt, nil
}
