package reviewrun

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type InputCaptureRequest struct {
	root            ports.AnchoredRoot
	target          ports.ReviewTargetSelector
	objective       []byte
	hasObjective    bool
	artistInputs    ports.ArtistReviewInputs
	hasArtistInputs bool
}

func NewInputCaptureRequest(root ports.AnchoredRoot, target ports.ReviewTargetSelector, objective []byte, hasObjective bool) (InputCaptureRequest, error) {
	return newInputCaptureRequest(root, target, objective, hasObjective, ports.ArtistReviewInputs{}, false)
}

func NewInputCaptureRequestWithArtistInputs(root ports.AnchoredRoot, target ports.ReviewTargetSelector, objective []byte, hasObjective bool, artistInputs ports.ArtistReviewInputs) (InputCaptureRequest, error) {
	return newInputCaptureRequest(root, target, objective, hasObjective, artistInputs, true)
}

func NewInputCaptureRequestWithAutomaticArtistInputs(root ports.AnchoredRoot, target ports.ReviewTargetSelector, objective []byte, hasObjective bool, artistInputs ports.ArtistReviewInputs) (InputCaptureRequest, error) {
	if !artistInputs.Automatic() {
		return InputCaptureRequest{}, fmt.Errorf("review run: automatic artist inputs are required")
	}
	return newInputCaptureRequest(root, target, objective, hasObjective, artistInputs, true)
}

func newInputCaptureRequest(root ports.AnchoredRoot, target ports.ReviewTargetSelector, objective []byte, hasObjective bool, artistInputs ports.ArtistReviewInputs, hasArtistInputs bool) (InputCaptureRequest, error) {
	if !root.Valid() || !target.Valid() || !hasObjective && len(objective) != 0 || hasArtistInputs != artistInputs.Valid() {
		return InputCaptureRequest{}, fmt.Errorf("review run: invalid input capture request")
	}
	return InputCaptureRequest{root: root, target: target, objective: append([]byte(nil), objective...), hasObjective: hasObjective, artistInputs: artistInputs, hasArtistInputs: hasArtistInputs}, nil
}
func (request InputCaptureRequest) Root() ports.AnchoredRoot           { return request.root }
func (request InputCaptureRequest) Target() ports.ReviewTargetSelector { return request.target }
func (request InputCaptureRequest) Objective() ([]byte, bool) {
	return append([]byte(nil), request.objective...), request.hasObjective
}
func (request InputCaptureRequest) ArtistInputs() (ports.ArtistReviewInputs, bool) {
	if !request.hasArtistInputs {
		return ports.ArtistReviewInputs{}, false
	}
	var inputs ports.ArtistReviewInputs
	if request.artistInputs.Automatic() {
		inputs, _ = ports.NewAutomaticArtistReviewInputs(request.artistInputs.BriefPath(), request.artistInputs.DesignSpecGlobs())
	} else {
		inputs, _ = ports.NewArtistReviewInputs(request.artistInputs.BriefPath(), request.artistInputs.DesignSpecGlobs())
	}
	return inputs, true
}
func (request InputCaptureRequest) Valid() bool {
	_, err := newInputCaptureRequest(request.root, request.target, request.objective, request.hasObjective, request.artistInputs, request.hasArtistInputs)
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
	capturedArchive   []byte
	objective         []byte
	hasObjective      bool
	projectContext    []byte
	hasProjectContext bool
}

// NewImmutableReviewInputWithProjectContext validates a captured target and
// takes defensive ownership of the exact objective and project-context bytes.
func NewImmutableReviewInputWithProjectContext(target ports.CapturedReviewTarget, objective []byte, hasObjective bool, projectContext []byte, hasProjectContext bool) (ImmutableReviewInput, error) {
	return NewImmutableReviewInputWithCapturedArchive(target, objective, hasObjective, projectContext, hasProjectContext, nil)
}

// NewImmutableReviewInputWithCapturedArchive additionally retains the exact
// authority-free capture needed to reproduce this input after publication.
func NewImmutableReviewInputWithCapturedArchive(target ports.CapturedReviewTarget, objective []byte, hasObjective bool, projectContext []byte, hasProjectContext bool, capturedArchive []byte) (ImmutableReviewInput, error) {
	if !target.Valid() || (!hasObjective && len(objective) != 0) || (!hasProjectContext && len(projectContext) != 0) {
		return ImmutableReviewInput{}, fmt.Errorf("review run: invalid captured review target")
	}
	if len(capturedArchive) > 0 {
		material, err := ports.UnmarshalCapturedReviewMaterial(capturedArchive)
		if err != nil || material.Target().Identity() != target.Identity() || !reflect.DeepEqual(material.Target().Bytes(), target.Bytes()) {
			return ImmutableReviewInput{}, fmt.Errorf("review run: captured archive does not bind target")
		}
	}
	input := ImmutableReviewInput{
		target: target, objective: append([]byte(nil), objective...), hasObjective: hasObjective,
		hasProjectContext: hasProjectContext, capturedArchive: append([]byte(nil), capturedArchive...),
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
func (input ImmutableReviewInput) CapturedArchive() []byte {
	return append([]byte(nil), input.capturedArchive...)
}
func (input ImmutableReviewInput) Objective() []byte  { return append([]byte(nil), input.objective...) }
func (input ImmutableReviewInput) HasObjective() bool { return input.hasObjective }
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
	Publication         publication.PublicationCommitter
	Templates           review.TemplateSet
	Diagnostics         ports.RuntimeDiagnosticSinkFactory
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

func (result Result) SessionID() domain.SessionID                  { return result.sessionID }
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
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(plan.Budgets, plan.Ceilings, plan.MaxLanes)
	if err != nil || !receipt.Eligible() {
		return review.RunBudgetReceipt{}, fmt.Errorf("review run: budget preflight failed: %w", err)
	}
	return receipt, nil
}
