package review

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// CoordinatorIDIssuer is the narrow identity dependency required by a review
// coordinator. It intentionally excludes prompt and publication identities.
type CoordinatorIDIssuer interface {
	NewSessionID(time.Time) (domain.SessionID, error)
	NewRunID(time.Time) (domain.RunID, error)
	NewAttemptID(time.Time) (domain.AttemptID, error)
}

// CoordinatorIdentityIssuer is an explicit alias for CoordinatorIDIssuer.
type CoordinatorIdentityIssuer = CoordinatorIDIssuer

type coordinatorRunContextFactory func(context.Context, time.Duration) (context.Context, context.CancelFunc)

// Coordinator owns one review run's mutable domain aggregates. Provider lanes
// receive only immutable InvocationJobs and return immutable AttemptOutcomes.
type Coordinator struct {
	clock                             ports.Clock
	ids                               CoordinatorIDIssuer
	runtime                           InvocationRuntime
	locker                            ports.LaneLocker
	maxActiveLanes                    int
	receipt                           RunBudgetReceipt
	policy                            EvidencePolicy
	resultCollectedHook               func(InvocationJob)
	runContextFactory                 coordinatorRunContextFactory
	beforeOutcomeCommitHook           func(InvocationJob)
	waveReadyHook                     func([]InvocationJob)
	lanesCloseAuthorizedHook          func()
	beforeLanesCloseLinearizationHook func()
	diagnostics                       ports.RuntimeDiagnosticSink
}

func coordinatorAdmissionContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("review coordinator: admission deadline elapsed: %w", err)
	}
	return nil
}

// NewCoordinator constructs a deterministic in-memory review coordinator with
// the default authoritative evidence policy.
func NewCoordinator(
	clock ports.Clock,
	ids CoordinatorIDIssuer,
	runtime InvocationRuntime,
	locker ports.LaneLocker,
	maxActiveLanes int,
	receipt RunBudgetReceipt,
) (*Coordinator, error) {
	return NewCoordinatorWithEvidencePolicy(
		clock,
		ids,
		runtime,
		locker,
		maxActiveLanes,
		receipt,
		DefaultEvidencePolicy(),
	)
}

// NewCoordinatorWithRuntimeDiagnostics constructs a coordinator whose logical
// decisions are synchronously persisted through the already-opened run sink.
func NewCoordinatorWithRuntimeDiagnostics(
	clock ports.Clock,
	ids CoordinatorIDIssuer,
	runtime InvocationRuntime,
	locker ports.LaneLocker,
	maxActiveLanes int,
	receipt RunBudgetReceipt,
	diagnostics ports.RuntimeDiagnosticSink,
) (*Coordinator, error) {
	if nilInterface(diagnostics) {
		return nil, fmt.Errorf("review coordinator: nil runtime diagnostics")
	}
	coordinator, err := NewCoordinator(clock, ids, runtime, locker, maxActiveLanes, receipt)
	if err != nil {
		return nil, err
	}
	coordinator.diagnostics = diagnostics
	return coordinator, nil
}

// NewCoordinatorWithEvidencePolicy constructs a deterministic in-memory review
// coordinator with an immutable authoritative evidence policy.
func NewCoordinatorWithEvidencePolicy(
	clock ports.Clock,
	ids CoordinatorIDIssuer,
	runtime InvocationRuntime,
	locker ports.LaneLocker,
	maxActiveLanes int,
	receipt RunBudgetReceipt,
	policy EvidencePolicy,
) (*Coordinator, error) {
	if nilInterface(clock) {
		return nil, fmt.Errorf("review coordinator: nil clock")
	}
	if nilInterface(ids) {
		return nil, fmt.Errorf("review coordinator: nil ID issuer")
	}
	if nilInvocationRuntime(runtime) {
		return nil, fmt.Errorf("review coordinator: nil invocation runtime")
	}
	if locker != nil && nilInterface(locker) {
		return nil, fmt.Errorf("review coordinator: nil lane locker")
	}
	if maxActiveLanes < 1 {
		return nil, fmt.Errorf("review coordinator: max active lanes must be positive")
	}
	if !validCoordinatorReceipt(receipt) {
		return nil, fmt.Errorf("review coordinator: run budget receipt is not eligible")
	}
	if !validCoordinatorEvidencePolicy(policy) {
		return nil, fmt.Errorf("review coordinator: evidence policy is invalid")
	}
	return &Coordinator{
		clock:             clock,
		ids:               ids,
		runtime:           runtime,
		locker:            locker,
		maxActiveLanes:    maxActiveLanes,
		receipt:           receipt,
		policy:            cloneCoordinatorEvidencePolicy(policy),
		runContextFactory: context.WithTimeout,
	}, nil
}

func validCoordinatorEvidencePolicy(policy EvidencePolicy) bool {
	return !policy.structural && policy.valid()
}

func cloneCoordinatorEvidencePolicy(policy EvidencePolicy) EvidencePolicy {
	return EvidencePolicy{
		required:   append([]domain.Severity(nil), policy.required...),
		structural: policy.structural,
	}
}

func validCoordinatorReceipt(receipt RunBudgetReceipt) bool {
	if !receipt.Eligible() || receipt.ReasonCode() != BudgetReasonEligible {
		return false
	}
	canonical, err := PreflightRunBudget(receipt.RoleBudgets(), receipt.Ceilings())
	if err != nil || !canonical.Eligible() {
		return false
	}
	return canonical.totalInvocations == receipt.totalInvocations &&
		canonical.totalOutputCap == receipt.totalOutputCap &&
		canonical.runDeadline == receipt.runDeadline &&
		equalRoleBudgets(canonical.roles, receipt.roles) &&
		equalLaneDeadlines(canonical.lanes, receipt.lanes)
}

func equalRoleBudgets(left, right []RoleBudget) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalLaneDeadlines(left, right []LaneDeadline) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// CoordinatorInvocationSummary is the immutable terminal projection of one
// invocation within a role attempt.
type CoordinatorInvocationSummary struct {
	sequence uint64
	purpose  domain.InvocationPurpose
	state    domain.InvocationState
}

// Sequence returns the attempt-local invocation sequence.
func (summary CoordinatorInvocationSummary) Sequence() uint64 { return summary.sequence }

// Purpose returns whether this invocation was initial or repair work.
func (summary CoordinatorInvocationSummary) Purpose() domain.InvocationPurpose {
	return summary.purpose
}

// State returns the invocation's terminal state.
func (summary CoordinatorInvocationSummary) State() domain.InvocationState { return summary.state }

// CoordinatorAttemptSummary is the immutable terminal projection of one
// primary or fallback provider attempt.
type CoordinatorAttemptSummary struct {
	id          domain.AttemptID
	kind        AttemptKind
	route       ports.ProviderRoute
	state       domain.AttemptState
	invocations []CoordinatorInvocationSummary
}

// ID returns the coordinator-issued attempt ID.
func (summary CoordinatorAttemptSummary) ID() domain.AttemptID { return summary.id }

// Kind returns whether this was the primary or fallback attempt.
func (summary CoordinatorAttemptSummary) Kind() AttemptKind { return summary.kind }

// Route returns the selected immutable provider route.
func (summary CoordinatorAttemptSummary) Route() ports.ProviderRoute { return summary.route }

// State returns the attempt's terminal state.
func (summary CoordinatorAttemptSummary) State() domain.AttemptState { return summary.state }

// Invocations returns caller-owned immutable invocation summaries.
func (summary CoordinatorAttemptSummary) Invocations() []CoordinatorInvocationSummary {
	return append([]CoordinatorInvocationSummary(nil), summary.invocations...)
}

// CoordinatorRoleSummary is the immutable terminal projection of one selected
// role. ReasonCode retains security and mutation terminal reasons even though
// those roles end in the cancelled state.
type CoordinatorRoleSummary struct {
	role              domain.Role
	required          bool
	state             domain.RoleTaskState
	valid             bool
	degraded          bool
	repaired          bool
	fallbackScheduled bool
	failureClass      domain.FailureClass
	reasonCode        string
	attempts          []CoordinatorAttemptSummary
}

// Role returns the selected role.
func (summary CoordinatorRoleSummary) Role() domain.Role { return summary.role }

// Required reports whether the selected role was required for this run.
func (summary CoordinatorRoleSummary) Required() bool { return summary.required }

// State returns the role's terminal domain state.
func (summary CoordinatorRoleSummary) State() domain.RoleTaskState { return summary.state }

// Valid reports whether validated provider output was accepted for this role.
func (summary CoordinatorRoleSummary) Valid() bool { return summary.valid }

// Degraded reports whether accepted role output declared incomplete coverage.
func (summary CoordinatorRoleSummary) Degraded() bool { return summary.degraded }

// Repaired reports whether a repair invocation produced accepted output.
func (summary CoordinatorRoleSummary) Repaired() bool { return summary.repaired }

// FallbackScheduled reports whether this role used its configured fallback.
func (summary CoordinatorRoleSummary) FallbackScheduled() bool { return summary.fallbackScheduled }

// FailureClass returns the terminal failure class, or empty on success.
func (summary CoordinatorRoleSummary) FailureClass() domain.FailureClass { return summary.failureClass }

// ReasonCode returns the stable terminal policy reason, or empty on success.
func (summary CoordinatorRoleSummary) ReasonCode() string { return summary.reasonCode }

// Attempts returns caller-owned attempt summaries in creation order.
func (summary CoordinatorRoleSummary) Attempts() []CoordinatorAttemptSummary {
	return cloneCoordinatorAttemptSummaries(summary.attempts)
}

// CoordinatorResult is the immutable terminal snapshot of one coordinator run.
// It contains neither domain aggregates nor publication authority.
type CoordinatorResult struct {
	sessionID         domain.SessionID
	runID             domain.RunID
	runState          domain.RunState
	findings          []domain.Finding
	axes              domain.OutcomeAxes
	evidence          []VerifiedFindingEvidence
	roleSummaries     []CoordinatorRoleSummary
	trace             []CoordinatorTraceEvent
	fallbackScheduled bool
}

// SessionID returns the immutable review-session identity.
func (result CoordinatorResult) SessionID() domain.SessionID { return result.sessionID }

// RunID returns the immutable review-run identity.
func (result CoordinatorResult) RunID() domain.RunID { return result.runID }

// RunState returns the terminal review-run state.
func (result CoordinatorResult) RunState() domain.RunState { return result.runState }

// Findings returns caller-owned deterministically ordered findings.
func (result CoordinatorResult) Findings() []domain.Finding {
	return append([]domain.Finding(nil), result.findings...)
}

// Evidence returns defensive verifier receipt-group copies in final finding order.
func (result CoordinatorResult) Evidence() []VerifiedFindingEvidence {
	return cloneVerifiedFindingEvidence(result.evidence)
}

// Outcomes returns the four system-owned outcome axes.
func (result CoordinatorResult) Outcomes() domain.OutcomeAxes { return result.axes }

// OutcomeAxes is an explicit alias for Outcomes.
func (result CoordinatorResult) OutcomeAxes() domain.OutcomeAxes { return result.axes }

// RoleSummaries returns caller-owned immutable role projections in fixed role order.
func (result CoordinatorResult) RoleSummaries() []CoordinatorRoleSummary {
	return cloneCoordinatorRoleSummaries(result.roleSummaries)
}

// Roles is an explicit alias for RoleSummaries.
func (result CoordinatorResult) Roles() []CoordinatorRoleSummary { return result.RoleSummaries() }

// Trace returns caller-owned logical trace events in canonical ordinal order.
func (result CoordinatorResult) Trace() []CoordinatorTraceEvent {
	return append([]CoordinatorTraceEvent(nil), result.trace...)
}

// TraceEvents is an explicit alias for Trace.
func (result CoordinatorResult) TraceEvents() []CoordinatorTraceEvent { return result.Trace() }

// FallbackScheduled reports whether any role entered its configured fallback.
func (result CoordinatorResult) FallbackScheduled() bool { return result.fallbackScheduled }

func cloneCoordinatorRoleSummaries(source []CoordinatorRoleSummary) []CoordinatorRoleSummary {
	copied := make([]CoordinatorRoleSummary, len(source))
	for index := range source {
		copied[index] = source[index]
		copied[index].attempts = cloneCoordinatorAttemptSummaries(source[index].attempts)
	}
	return copied
}

func cloneCoordinatorAttemptSummaries(source []CoordinatorAttemptSummary) []CoordinatorAttemptSummary {
	copied := make([]CoordinatorAttemptSummary, len(source))
	for index := range source {
		copied[index] = source[index]
		copied[index].invocations = append([]CoordinatorInvocationSummary(nil), source[index].invocations...)
	}
	return copied
}

type coordinatorIssuer struct {
	clock ports.Clock
	ids   CoordinatorIDIssuer
	used  map[string]struct{}
}

func newCoordinatorIssuer(clock ports.Clock, ids CoordinatorIDIssuer) *coordinatorIssuer {
	return &coordinatorIssuer{clock: clock, ids: ids, used: make(map[string]struct{})}
}

func (issuer *coordinatorIssuer) now() (time.Time, error) {
	if issuer == nil || nilInterface(issuer.clock) {
		return time.Time{}, fmt.Errorf("review coordinator: invalid clock")
	}
	now := issuer.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("review coordinator: clock returned zero time")
	}
	return now, nil
}

func (issuer *coordinatorIssuer) newSessionID() (domain.SessionID, error) {
	now, err := issuer.now()
	if err != nil {
		return domain.SessionID{}, err
	}
	issued, err := issuer.ids.NewSessionID(now)
	if err != nil {
		return domain.SessionID{}, fmt.Errorf("review coordinator: issue session ID: %w", err)
	}
	id, err := domain.ParseSessionID(issued.String())
	if err != nil {
		return domain.SessionID{}, fmt.Errorf("review coordinator: invalid issued session ID: %w", err)
	}
	if err := issuer.reserve(id.String()[2:]); err != nil {
		return domain.SessionID{}, err
	}
	return id, nil
}

func (issuer *coordinatorIssuer) newRunID() (domain.RunID, error) {
	now, err := issuer.now()
	if err != nil {
		return domain.RunID{}, err
	}
	issued, err := issuer.ids.NewRunID(now)
	if err != nil {
		return domain.RunID{}, fmt.Errorf("review coordinator: issue run ID: %w", err)
	}
	id, err := domain.ParseRunID(issued.String())
	if err != nil {
		return domain.RunID{}, fmt.Errorf("review coordinator: invalid issued run ID: %w", err)
	}
	if err := issuer.reserve(id.String()[2:]); err != nil {
		return domain.RunID{}, err
	}
	return id, nil
}

func (issuer *coordinatorIssuer) newAttemptID() (domain.AttemptID, error) {
	now, err := issuer.now()
	if err != nil {
		return domain.AttemptID{}, err
	}
	issued, err := issuer.ids.NewAttemptID(now)
	if err != nil {
		return domain.AttemptID{}, fmt.Errorf("review coordinator: issue attempt ID: %w", err)
	}
	id, err := domain.ParseAttemptID(issued.String())
	if err != nil {
		return domain.AttemptID{}, fmt.Errorf("review coordinator: invalid issued attempt ID: %w", err)
	}
	if err := issuer.reserve(id.String()[2:]); err != nil {
		return domain.AttemptID{}, err
	}
	return id, nil
}

func (issuer *coordinatorIssuer) reserve(rawUUID string) error {
	if _, exists := issuer.used[rawUUID]; exists {
		return fmt.Errorf("review coordinator: identity issuer reused UUIDv7 identity")
	}
	issuer.used[rawUUID] = struct{}{}
	return nil
}

type coordinatorAttempt struct {
	kind       AttemptKind
	route      ports.ProviderRoute
	attempt    domain.Attempt
	repairUsed bool
}

type coordinatorRole struct {
	assignment        Assignment
	attempts          []coordinatorAttempt
	currentAttempt    int
	output            *ValidatedRoleOutput
	repaired          bool
	fallbackScheduled bool
	failureClass      domain.FailureClass
	reasonCode        string
}

type coordinatorExecution struct {
	coordinator              *Coordinator
	run                      *domain.Run
	issuer                   *coordinatorIssuer
	roles                    map[domain.Role]*coordinatorRole
	trace                    []CoordinatorTraceEvent
	nextEvent                uint64
	nextJob                  uint64
	stopping                 bool
	runContext               context.Context
	callerCtx                context.Context
	cancelled                bool
	runStarted               bool
	lanesCloseAuthorized     bool
	runTerminalRecorded      bool
	terminalRoles            map[domain.Role]struct{}
	dispatchStopRecorded     bool
	stopCondition            AttemptCondition
	dispatchStopCondition    AttemptCondition
	diagnosticAttemptStarted map[domain.AttemptID]time.Time
}

// Execute runs every selected role. It owns all mutable Run and Attempt state
// in this goroutine; lane workers only execute immutable jobs.
// Execute runs a new root review run.
func (coordinator *Coordinator) Execute(
	ctx context.Context,
	target domain.TargetIdentity,
	assignments []Assignment,
	threshold domain.Severity,
	policy *domain.CIPolicy,
) (CoordinatorResult, error) {
	return coordinator.execute(ctx, target, assignments, threshold, policy, nil)
}

// ExecuteDeltaRun executes supplied child roles with the explicit immutable
// A-to-B provider material. The ordinary prompt path is not available.
func (coordinator *Coordinator) ExecuteDeltaRun(
	ctx context.Context,
	run *domain.Run,
	assignments []Assignment,
	threshold domain.Severity,
	policy *domain.CIPolicy,
	material DeltaInvocationMaterial,
) (CoordinatorResult, error) {
	if coordinator == nil || coordinator.runtime == nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: delta execution dependencies are invalid")
	}
	runtime, ok := coordinator.runtime.(*ProviderInvocationRuntime)
	if !ok || runtime == nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: delta execution requires provider invocation runtime")
	}
	explicit := *coordinator
	explicit.runtime = deltaInvocationRuntime{runtime: runtime, material: cloneDeltaInvocationMaterial(material)}
	return explicit.ExecuteRun(ctx, run, assignments, threshold, policy)
}

// ExecuteExactReplayRun executes one selected child role with its stored wire
// authority. It removes fallback authority and the wrapper rejects any
// non-initial invocation, so repair or multi-role scheduling cannot reach a
// provider.
func (coordinator *Coordinator) ExecuteExactReplayRun(
	ctx context.Context,
	run *domain.Run,
	assignment Assignment,
	threshold domain.Severity,
	policy *domain.CIPolicy,
	input ExactReplayInput,
) (CoordinatorResult, error) {
	if coordinator == nil || coordinator.runtime == nil || assignment.Role() != input.Role ||
		!validCoordinatorProviderInstance(input.SourceProviderInstance) ||
		assignment.PrimaryRoute().ProviderInstance() != input.SourceProviderInstance {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: exact replay authority is invalid")
	}
	runtime, ok := coordinator.runtime.(*ProviderInvocationRuntime)
	if !ok || runtime == nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: exact replay requires provider invocation runtime")
	}
	selected, err := NewScheduledAssignment(assignment.Role(), assignment.Required(), assignment.PrimaryRoute(), nil)
	if err != nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: exact replay assignment: %w", err)
	}
	explicit := *coordinator
	explicit.runtime = exactReplayInvocationRuntime{runtime: runtime, input: cloneExactReplayInput(input)}
	return explicit.ExecuteRun(ctx, run, []Assignment{selected}, threshold, policy)
}

type deltaInvocationRuntime struct {
	runtime  *ProviderInvocationRuntime
	material DeltaInvocationMaterial
}

func (runtime deltaInvocationRuntime) Invoke(ctx context.Context, job InvocationJob) AttemptOutcome {
	return runtime.runtime.InvokeDelta(ctx, job, runtime.material)
}

type exactReplayInvocationRuntime struct {
	runtime *ProviderInvocationRuntime
	input   ExactReplayInput
}

func (runtime exactReplayInvocationRuntime) Invoke(ctx context.Context, job InvocationJob) AttemptOutcome {
	if job.Purpose() != domain.InvocationInitial || job.Role() != runtime.input.Role ||
		job.Route().ProviderInstance() != runtime.input.SourceProviderInstance {
		return runtimeCondition(job, AttemptConditionConfigurationViolation)
	}
	return runtime.runtime.InvokeExactReplay(ctx, job, runtime.input)
}

// ExecuteRun executes one supplied fresh pending run without replacing its run,
// session, or lineage identities. Root review runs have no lineage while child
// runs must retain both parent and source lineage.
func (coordinator *Coordinator) ExecuteRun(
	ctx context.Context,
	run *domain.Run,
	assignments []Assignment,
	threshold domain.Severity,
	policy *domain.CIPolicy,
) (CoordinatorResult, error) {
	if run == nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: run is required")
	}
	return coordinator.execute(ctx, run.Target(), assignments, threshold, policy, run)
}

func (coordinator *Coordinator) execute(
	ctx context.Context,
	target domain.TargetIdentity,
	assignments []Assignment,
	threshold domain.Severity,
	policy *domain.CIPolicy,
	supplied *domain.Run,
) (result CoordinatorResult, err error) {
	if coordinator == nil || nilInterface(coordinator.clock) || nilInterface(coordinator.ids) ||
		nilInvocationRuntime(coordinator.runtime) || coordinator.maxActiveLanes < 1 ||
		(coordinator.locker != nil && nilInterface(coordinator.locker)) ||
		coordinator.runContextFactory == nil ||
		!validCoordinatorReceipt(coordinator.receipt) ||
		!validCoordinatorEvidencePolicy(coordinator.policy) {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: dependencies are invalid")
	}
	if ctx == nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: context is required")
	}
	workCtx, cancelWork := coordinator.runContextFactory(ctx, coordinator.receipt.RunDeadline())
	defer cancelWork()
	localPolicy := domain.CIPolicy{}
	var localPolicyPointer *domain.CIPolicy
	if policy != nil {
		localPolicy = *policy
		localPolicyPointer = &localPolicy
	}
	if threshold != "" && !threshold.Valid() {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: invalid request-changes threshold %q", threshold)
	}
	if supplied != nil {
		if _, err := domain.ParseRunID(supplied.ID().String()); err != nil {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: invalid supplied run ID: %w", err)
		}
		if _, err := domain.ParseSessionID(supplied.SessionID().String()); err != nil {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: invalid supplied session ID: %w", err)
		}
		if !supplied.Type().Valid() || supplied.State() != domain.RunPending {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: supplied run must be fresh and pending")
		}
		_, hasParent := supplied.ParentRunID()
		_, hasSource := supplied.SourceRunID()
		if supplied.Type() == domain.RunTypeReview {
			if hasParent || hasSource {
				return CoordinatorResult{}, fmt.Errorf("review coordinator: supplied root run must not have lineage")
			}
		} else if !hasParent || !hasSource {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: supplied child run is missing lineage")
		}
		target = supplied.Target()
	}
	canonicalTarget, err := canonicalCoordinatorTarget(target)
	if err != nil {
		return CoordinatorResult{}, err
	}
	allowSubset := supplied != nil && supplied.Type() != domain.RunTypeReview
	canonicalAssignments, roleTasks, err := coordinatorAssignments(assignments, coordinator.receipt, allowSubset)
	if err != nil {
		return CoordinatorResult{}, err
	}

	if err := coordinatorAdmissionContextError(workCtx); err != nil {
		return CoordinatorResult{}, err
	}

	issuer := newCoordinatorIssuer(coordinator.clock, coordinator.ids)
	var sessionID domain.SessionID
	var runID domain.RunID
	var run domain.Run
	if supplied != nil {
		defer func() { *supplied = run }()
	}
	if supplied != nil {
		sessionID, runID = supplied.SessionID(), supplied.ID()
		run = *supplied
		if !sameCoordinatorRoleTasks(run.RoleTasks(), roleTasks) {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: assignments do not match supplied run roles")
		}
	} else {
		if err := coordinatorAdmissionContextError(workCtx); err != nil {
			return CoordinatorResult{}, err
		}
		sessionID, err = issuer.newSessionID()
		if err != nil {
			return CoordinatorResult{}, err
		}
		if err := coordinatorAdmissionContextError(workCtx); err != nil {
			return CoordinatorResult{}, err
		}
		runID, err = issuer.newRunID()
		if err != nil {
			return CoordinatorResult{}, err
		}
		if err := coordinatorAdmissionContextError(workCtx); err != nil {
			return CoordinatorResult{}, err
		}
		createdAt, clockErr := issuer.now()
		if clockErr != nil {
			return CoordinatorResult{}, clockErr
		}
		runSession, createdRun, createErr := domain.NewReviewSession(sessionID, createdAt, runID, canonicalTarget, roleTasks)
		_ = runSession
		if createErr != nil {
			return CoordinatorResult{}, fmt.Errorf("review coordinator: create session and run: %w", createErr)
		}
		run = createdRun
	}
	if err := coordinatorAdmissionContextError(workCtx); err != nil {
		return CoordinatorResult{}, err
	}
	if err := run.Transition(domain.RunRunning); err != nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: start run: %w", err)
	}

	scheduler := newLaneScheduler(workCtx, coordinator.runtime, coordinator.locker, coordinator.maxActiveLanes, coordinator.receipt.TotalInvocations())
	lanesClosed := false
	defer func() {
		if !lanesClosed {
			scheduler.cancelDispatch()
			scheduler.close()
		}
	}()

	execution := &coordinatorExecution{
		coordinator:              coordinator,
		run:                      &run,
		issuer:                   issuer,
		roles:                    make(map[domain.Role]*coordinatorRole, len(canonicalAssignments)),
		runContext:               workCtx,
		callerCtx:                ctx,
		terminalRoles:            make(map[domain.Role]struct{}, len(canonicalAssignments)),
		diagnosticAttemptStarted: make(map[domain.AttemptID]time.Time),
	}
	for _, assignment := range canonicalAssignments {
		execution.roles[assignment.Role()] = &coordinatorRole{assignment: assignment, currentAttempt: -1}
	}
	defer func() {
		if err == nil {
			return
		}
		aborted, finalizationErr := execution.abort(
			scheduler,
			sessionID,
			runID,
			threshold,
			localPolicyPointer,
		)
		lanesClosed = true
		result = aborted
		err = errors.Join(err, finalizationErr)
	}()
	if err := execution.record(CoordinatorEventRunStarted, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
		return CoordinatorResult{}, err
	}

	wave := make([]InvocationJob, 0, len(canonicalAssignments))
	for _, role := range domain.FixedRoleOrder() {
		state := execution.roles[role]
		if state == nil {
			continue
		}
		job, err := execution.startPrimary(role)
		if err != nil {
			return CoordinatorResult{}, err
		}
		wave = append(wave, job)
	}

	for len(wave) > 0 {
		if workCtx.Err() != nil {
			if err := execution.cancelAll(scheduler, execution.contextCondition()); err != nil {
				return CoordinatorResult{}, err
			}
			break
		}

		dispatched, _, err := execution.dispatchWave(workCtx, scheduler, wave)
		if err != nil {
			return CoordinatorResult{}, err
		}
		if len(dispatched) == 0 {
			if err := execution.cancelAll(scheduler, execution.contextCondition()); err != nil {
				return CoordinatorResult{}, err
			}
			break
		}
		collected, err := execution.collectWave(scheduler, dispatched)
		if err != nil {
			return CoordinatorResult{}, err
		}
		next, err := execution.commitWave(scheduler, dispatched, collected)
		if err != nil {
			return CoordinatorResult{}, err
		}
		if workCtx.Err() != nil {
			if err := execution.cancelAll(scheduler, execution.contextCondition()); err != nil {
				return CoordinatorResult{}, err
			}
		}
		if execution.stopping {
			break
		}
		wave = next
	}
	if workCtx.Err() != nil {
		if err := execution.cancelAll(scheduler, execution.contextCondition()); err != nil {
			return CoordinatorResult{}, err
		}
	}

	if !execution.allRolesTerminal() {
		if err := execution.cancelAll(scheduler, AttemptConditionInternalInvariant); err != nil {
			return CoordinatorResult{}, err
		}
	}
	if execution.coordinator.beforeLanesCloseLinearizationHook != nil {
		execution.coordinator.beforeLanesCloseLinearizationHook()
	}
	// This context sample is the lane-close linearization point. A cancellation
	// observed after authorization belongs after this coordinator execution.
	if workCtx.Err() != nil {
		if err := execution.cancelAll(scheduler, execution.contextCondition()); err != nil {
			return CoordinatorResult{}, err
		}
	}
	if err := execution.record(CoordinatorEventLanesCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
		return CoordinatorResult{}, err
	}
	if execution.coordinator.lanesCloseAuthorizedHook != nil {
		execution.coordinator.lanesCloseAuthorizedHook()
	}
	scheduler.close()
	lanesClosed = true

	if err := execution.finishRun(); err != nil {
		return CoordinatorResult{}, err
	}
	if err := execution.record(CoordinatorEventRunTerminal, domain.Role(""), nil, nil, nil, "", run.State()); err != nil {
		return CoordinatorResult{}, err
	}
	return execution.snapshot(sessionID, runID, threshold, localPolicyPointer)
}
func sameCoordinatorRoleTasks(left, right []domain.RoleTask) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Role() != right[index].Role() || left[index].Required() != right[index].Required() || left[index].State() != right[index].State() {
			return false
		}
	}
	return true
}

func (execution *coordinatorExecution) abort(
	scheduler *laneScheduler,
	sessionID domain.SessionID,
	runID domain.RunID,
	threshold domain.Severity,
	policy *domain.CIPolicy,
) (CoordinatorResult, error) {
	var finalizationErrors []error
	if !execution.runStarted {
		finalizationErrors = append(finalizationErrors, execution.record(
			CoordinatorEventRunStarted,
			domain.Role(""),
			nil,
			nil,
			nil,
			"",
			domain.RunState(""),
		))
	}
	if !execution.allRolesTerminal() {
		finalizationErrors = append(
			finalizationErrors,
			execution.cancelAll(scheduler, AttemptConditionInternalInvariant),
		)
	}
	if !execution.lanesCloseAuthorized {
		finalizationErrors = append(finalizationErrors, execution.record(
			CoordinatorEventLanesCloseAuthorized,
			domain.Role(""),
			nil,
			nil,
			nil,
			"",
			domain.RunState(""),
		))
	}
	scheduler.close()
	if !coordinatorTerminalRunState(execution.run.State()) {
		finalizationErrors = append(finalizationErrors, execution.finishRun())
	}
	if !execution.runTerminalRecorded && coordinatorTerminalRunState(execution.run.State()) {
		finalizationErrors = append(finalizationErrors, execution.record(
			CoordinatorEventRunTerminal,
			domain.Role(""),
			nil,
			nil,
			nil,
			"",
			execution.run.State(),
		))
	}
	snapshot, snapshotErr := execution.snapshot(sessionID, runID, threshold, policy)
	finalizationErrors = append(finalizationErrors, snapshotErr)
	return snapshot, errors.Join(finalizationErrors...)
}

func canonicalCoordinatorTarget(target domain.TargetIdentity) (domain.TargetIdentity, error) {
	canonical, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind:              target.Kind(),
		SHA256:            target.SHA256(),
		RepositoryID:      target.RepositoryID(),
		BaseObjectID:      target.BaseObjectID(),
		HeadObjectID:      target.HeadObjectID(),
		HeadTreeObjectID:  target.HeadTreeObjectID(),
		IndexTreeObjectID: target.IndexTreeObjectID(),
	})
	if err != nil {
		return domain.TargetIdentity{}, fmt.Errorf("review coordinator: invalid target: %w", err)
	}
	return canonical, nil
}

func coordinatorAssignments(assignments []Assignment, receipt RunBudgetReceipt, allowSubset bool) ([]Assignment, []domain.RoleTask, error) {
	byRole := make(map[domain.Role]Assignment, len(assignments))
	for _, assignment := range assignments {
		if !assignment.Role().Valid() || !assignment.PrimaryRoute().Valid() ||
			assignment.ProviderInstance() != assignment.PrimaryRoute().ProviderInstance() {
			return nil, nil, fmt.Errorf("review coordinator: invalid assignment")
		}
		if assignment.HasFallback() {
			fallback, ok := assignment.FallbackRoute()
			if !ok || !fallback.Valid() || fallback.ProviderInstance() == assignment.PrimaryRoute().ProviderInstance() {
				return nil, nil, fmt.Errorf("review coordinator: invalid fallback assignment for role %q", assignment.Role())
			}
		}
		if _, duplicate := byRole[assignment.Role()]; duplicate {
			return nil, nil, fmt.Errorf("review coordinator: duplicate assignment for role %q", assignment.Role())
		}
		byRole[assignment.Role()] = assignment
	}

	budgets := receipt.RoleBudgets()
	if len(assignments) > len(budgets) || (!allowSubset && len(assignments) != len(budgets)) {
		return nil, nil, fmt.Errorf("review coordinator: assignments do not match budget roles")
	}
	budgetByRole := make(map[domain.Role]RoleBudget, len(budgets))
	for _, budget := range budgets {
		if !budget.Valid() {
			return nil, nil, fmt.Errorf("review coordinator: invalid budget role")
		}
		if _, duplicate := budgetByRole[budget.Role()]; duplicate {
			return nil, nil, fmt.Errorf("review coordinator: duplicate budget role %q", budget.Role())
		}
		budgetByRole[budget.Role()] = budget
	}

	canonical := make([]Assignment, 0, len(assignments))
	roleTasks := make([]domain.RoleTask, 0, len(assignments))
	for _, role := range domain.FixedRoleOrder() {
		assignment, exists := byRole[role]
		if !exists {
			continue
		}
		budget, exists := budgetByRole[role]
		if !exists || !sameCoordinatorRoute(assignment.PrimaryRoute(), budget.Primary().Route()) {
			return nil, nil, fmt.Errorf("review coordinator: primary assignment route does not match budget for role %q", role)
		}
		fallback, hasFallback := assignment.FallbackRoute()
		budgetFallback, budgetHasFallback := budget.Fallback()
		if hasFallback != budgetHasFallback || hasFallback && !sameCoordinatorRoute(fallback, budgetFallback.Route()) {
			return nil, nil, fmt.Errorf("review coordinator: fallback assignment route does not match budget for role %q", role)
		}
		var fallbackProvider *string
		if hasFallback {
			provider := fallback.ProviderInstance()
			fallbackProvider = &provider
		}
		task, err := domain.NewRoleTask(role, assignment.Required(), assignment.PrimaryRoute().ProviderInstance(), fallbackProvider)
		if err != nil {
			return nil, nil, fmt.Errorf("review coordinator: canonical role task %q: %w", role, err)
		}
		canonical = append(canonical, assignment)
		roleTasks = append(roleTasks, task)
	}
	if len(canonical) != len(assignments) || (!allowSubset && len(canonical) != len(budgets)) {
		return nil, nil, fmt.Errorf("review coordinator: assignments must use only fixed review roles")
	}
	return canonical, roleTasks, nil
}

func sameCoordinatorRoute(left, right ports.ProviderRoute) bool {
	return left.ProviderInstance() == right.ProviderInstance() &&
		left.ConcurrencyKey().String() == right.ConcurrencyKey().String()
}

func (execution *coordinatorExecution) startPrimary(role domain.Role) (InvocationJob, error) {
	state := execution.roles[role]
	if state == nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: missing role state %q", role)
	}
	if err := execution.run.TransitionRole(role, domain.RoleTaskPrimaryQueued); err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: queue primary role %q: %w", role, err)
	}
	return execution.startAttempt(role, AttemptKindPrimary, state.assignment.PrimaryRoute(), CoordinatorEventAttemptQueued)
}

func (execution *coordinatorExecution) startAttempt(
	role domain.Role,
	kind AttemptKind,
	route ports.ProviderRoute,
	event CoordinatorEventKind,
) (InvocationJob, error) {
	state := execution.roles[role]
	attemptID, err := execution.issuer.newAttemptID()
	if err != nil {
		return InvocationJob{}, err
	}
	initial, err := domain.NewInvocation(1, domain.InvocationInitial)
	if err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: create initial invocation: %w", err)
	}
	attempt, err := domain.NewAttempt(attemptID, route.ProviderInstance(), initial)
	if err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: create attempt: %w", err)
	}
	if err := attempt.Transition(domain.AttemptRunning); err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: start attempt: %w", err)
	}
	state.attempts = append(state.attempts, coordinatorAttempt{kind: kind, route: route, attempt: attempt})
	state.currentAttempt = len(state.attempts) - 1
	current := &state.attempts[state.currentAttempt]
	if kind == AttemptKindPrimary {
		if err := execution.run.TransitionRole(role, domain.RoleTaskPrimaryRunning); err != nil {
			return InvocationJob{}, fmt.Errorf("review coordinator: start primary role %q: %w", role, err)
		}
	} else if err := execution.run.TransitionRole(role, domain.RoleTaskFallbackRunning); err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: start fallback role %q: %w", role, err)
	}
	if err := execution.record(event, role, current, nil, nil, "", domain.RunState("")); err != nil {
		return InvocationJob{}, err
	}
	return execution.newJob(role, current, domain.InvocationInitial)
}

func (execution *coordinatorExecution) newJob(role domain.Role, attempt *coordinatorAttempt, purpose domain.InvocationPurpose) (InvocationJob, error) {
	limits, err := execution.invocationLimits(role, attempt.kind, attempt.route)
	if err != nil {
		return InvocationJob{}, err
	}
	execution.nextJob++
	job, err := newCoordinatorInvocationJob(
		execution.run.SessionID(),
		execution.run.ID(),
		role,
		attempt.kind,
		attempt.route,
		execution.run.Target(),
		limits,
		attempt.attempt.ID(),
		purpose,
		execution.nextJob,
	)
	if err != nil {
		return InvocationJob{}, fmt.Errorf("review coordinator: create invocation job: %w", err)
	}
	return job, nil
}

func (execution *coordinatorExecution) invocationLimits(
	role domain.Role,
	kind AttemptKind,
	route ports.ProviderRoute,
) (InvocationLimits, error) {
	for _, budget := range execution.coordinator.receipt.RoleBudgets() {
		if budget.Role() != role {
			continue
		}
		if kind == AttemptKindPrimary && sameCoordinatorRoute(budget.Primary().Route(), route) {
			return budget.Primary().Limits(), nil
		}
		if kind == AttemptKindFallback {
			fallback, ok := budget.Fallback()
			if ok && sameCoordinatorRoute(fallback.Route(), route) {
				return fallback.Limits(), nil
			}
		}
	}
	return InvocationLimits{}, fmt.Errorf("review coordinator: invocation route has no validated budget for role %q", role)
}

func (execution *coordinatorExecution) dispatchWave(ctx context.Context, scheduler *laneScheduler, wave []InvocationJob) ([]InvocationJob, bool, error) {
	dispatched := make([]InvocationJob, 0, len(wave))
	startGate := make(chan struct{})
	for _, job := range wave {
		if ctx.Err() != nil {
			scheduler.cancelDispatch()
			return dispatched, true, nil
		}
		attempt, err := execution.attemptFor(job)
		if err != nil {
			return nil, false, err
		}
		if !scheduler.admitWithGate(job, startGate) {
			scheduler.cancelDispatch()
			return dispatched, true, nil
		}
		sequence := invocationSequence(job.Purpose())
		if err := attempt.attempt.TransitionInvocation(sequence, domain.InvocationRunning); err != nil {
			return nil, false, fmt.Errorf("review coordinator: start invocation: %w", err)
		}
		if err := execution.record(CoordinatorEventInvocationDispatched, job.Role(), attempt, &job.purpose, nil, "", domain.RunState("")); err != nil {
			return nil, false, err
		}
		dispatched = append(dispatched, job)
	}
	if execution.coordinator.waveReadyHook != nil {
		execution.coordinator.waveReadyHook(append([]InvocationJob(nil), dispatched...))
	}
	close(startGate)
	return dispatched, false, nil
}

type coordinatorCollectedWave struct {
	outcomes map[uint64]AttemptOutcome
}

func (execution *coordinatorExecution) collectWave(
	scheduler *laneScheduler,
	wave []InvocationJob,
) (coordinatorCollectedWave, error) {
	collected := coordinatorCollectedWave{
		outcomes: make(map[uint64]AttemptOutcome, len(wave)),
	}
	expected := make(map[uint64]InvocationJob, len(wave))
	for _, job := range wave {
		expected[job.Ordinal()] = job
	}
	stopping := false
	for range wave {
		result := <-scheduler.results
		job, exists := expected[result.job.Ordinal()]
		if !exists {
			return coordinatorCollectedWave{}, fmt.Errorf("review coordinator: lane result has unknown ordinal %d", result.job.Ordinal())
		}
		if _, duplicate := collected.outcomes[result.job.Ordinal()]; duplicate {
			return coordinatorCollectedWave{}, fmt.Errorf("review coordinator: duplicate lane result ordinal %d", result.job.Ordinal())
		}
		normalized, err := execution.normalizedOutcome(job, result.outcome)
		if err != nil {
			return coordinatorCollectedWave{}, err
		}
		collected.outcomes[result.job.Ordinal()] = normalized
		if !stopping && conditionStopsCoordinatorRun(coordinatorOutcomeCondition(normalized)) {
			stopping = true
			scheduler.cancelDispatch()
		}
		if execution.coordinator.resultCollectedHook != nil {
			execution.coordinator.resultCollectedHook(job)
		}
	}
	return collected, nil
}

func orderedCoordinatorWave(wave []InvocationJob) []InvocationJob {
	ordered := append([]InvocationJob(nil), wave...)
	sort.Slice(ordered, func(left, right int) bool {
		leftRank, rightRank := roleRank(ordered[left].Role()), roleRank(ordered[right].Role())
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return ordered[left].Ordinal() < ordered[right].Ordinal()
	})
	return ordered
}

func coordinatorOutcomeCondition(outcome AttemptOutcome) AttemptCondition {
	if outcome.Succeeded() {
		return AttemptConditionValidReview
	}
	if condition, ok := outcome.Condition(); ok {
		return condition
	}
	return AttemptConditionInternalInvariant
}

func conditionCancelsCoordinatorRun(condition AttemptCondition) bool {
	return condition == AttemptConditionLoginRequired ||
		condition == AttemptConditionSecurityViolation ||
		condition == AttemptConditionMutationViolation ||
		condition == AttemptConditionCancelled
}

func conditionStopsCoordinatorRun(condition AttemptCondition) bool {
	return condition == AttemptConditionInternalInvariant ||
		condition == AttemptConditionArtifactFailure ||
		condition == AttemptConditionLoginRequired ||
		condition == AttemptConditionSecurityViolation ||
		condition == AttemptConditionMutationViolation ||
		condition == AttemptConditionCancelled
}

func conditionRetainsAuthorityAfterContext(
	condition AttemptCondition,
	contextCondition AttemptCondition,
) bool {
	switch contextCondition {
	case AttemptConditionCancelled:
		return condition == AttemptConditionInternalInvariant ||
			condition == AttemptConditionArtifactFailure ||
			condition == AttemptConditionLoginRequired ||
			condition == AttemptConditionSecurityViolation ||
			condition == AttemptConditionMutationViolation
	case AttemptConditionTimeout:
		return condition == AttemptConditionInternalInvariant ||
			condition == AttemptConditionArtifactFailure ||
			condition == AttemptConditionLoginRequired ||
			condition == AttemptConditionSecurityViolation ||
			condition == AttemptConditionMutationViolation ||
			condition == AttemptConditionConfigurationViolation
	default:
		return false
	}
}

func (execution *coordinatorExecution) commitWave(
	scheduler *laneScheduler,
	wave []InvocationJob,
	collected coordinatorCollectedWave,
) ([]InvocationJob, error) {
	ordered := orderedCoordinatorWave(wave)
	outcomes := make(map[uint64]AttemptOutcome, len(ordered))
	conditions := make([]AttemptCondition, 0, len(ordered))
	for _, job := range ordered {
		outcome, exists := collected.outcomes[job.Ordinal()]
		if !exists {
			return nil, fmt.Errorf("review coordinator: missing lane result ordinal %d", job.Ordinal())
		}
		normalized, err := execution.normalizedOutcome(job, outcome)
		if err != nil {
			return nil, err
		}
		outcomes[job.Ordinal()] = normalized
		conditions = append(conditions, coordinatorOutcomeCondition(normalized))
	}
	condition, err := ReduceAttemptConditions(conditions...)
	if err != nil {
		return nil, fmt.Errorf("review coordinator: reduce wave conditions: %w", err)
	}
	contextFacts := execution.contextConditions()
	if len(contextFacts) > 0 {
		contextCondition, err := ReduceAttemptConditions(contextFacts...)
		if err != nil {
			return nil, fmt.Errorf("review coordinator: reduce context conditions: %w", err)
		}
		if !conditionRetainsAuthorityAfterContext(condition, contextCondition) {
			return nil, execution.cancelAll(scheduler, contextCondition)
		}
	}
	if conditionStopsCoordinatorRun(condition) {
		if err := execution.requestDispatchStop(scheduler, condition); err != nil {
			return nil, err
		}
		for _, job := range ordered {
			if execution.coordinator.beforeOutcomeCommitHook != nil {
				execution.coordinator.beforeOutcomeCommitHook(job)
			}
			commitCondition, cancellationObserved, _, err := execution.prepareOutcomeCommit(
				scheduler,
				coordinatorOutcomeCondition(outcomes[job.Ordinal()]),
			)
			if err != nil {
				return nil, err
			}
			if _, err := execution.commitOutcome(
				job,
				outcomes[job.Ordinal()],
				commitCondition,
				cancellationObserved,
				true,
			); err != nil {
				return nil, err
			}
		}
		if err := execution.cancelAll(scheduler, condition); err != nil {
			return nil, err
		}
		return nil, nil
	}

	next := make([]InvocationJob, 0, len(ordered))
	for _, job := range ordered {
		if execution.coordinator.beforeOutcomeCommitHook != nil {
			execution.coordinator.beforeOutcomeCommitHook(job)
		}
		commitCondition, cancellationObserved, contextStopsFollowup, err := execution.prepareOutcomeCommit(
			scheduler,
			coordinatorOutcomeCondition(outcomes[job.Ordinal()]),
		)
		if err != nil {
			return nil, err
		}
		generated, err := execution.commitOutcome(
			job,
			outcomes[job.Ordinal()],
			commitCondition,
			cancellationObserved,
			contextStopsFollowup,
		)
		if err != nil {
			return nil, err
		}
		next = append(next, generated...)
		if execution.stopping {
			return nil, nil
		}
	}
	return next, nil
}

func (execution *coordinatorExecution) normalizedOutcome(job InvocationJob, outcome AttemptOutcome) (AttemptOutcome, error) {
	if !outcome.validFor(job) {
		condition := AttemptConditionInternalInvariant
		normalized, err := NewAttemptOutcome(job, nil, &condition)
		if err != nil {
			return AttemptOutcome{}, fmt.Errorf("review coordinator: normalize lane result: %w", err)
		}
		return normalized, nil
	}
	if !outcome.Succeeded() {
		return outcome, nil
	}
	output, ok := outcome.Output()
	if !ok {
		condition := AttemptConditionInternalInvariant
		normalized, err := NewAttemptOutcome(job, nil, &condition)
		if err != nil {
			return AttemptOutcome{}, fmt.Errorf("review coordinator: normalize lane output: %w", err)
		}
		return normalized, nil
	}
	output, condition := execution.reduceOutputEvidence(output)
	if condition != AttemptConditionValidReview {
		normalized, err := NewAttemptOutcome(job, nil, &condition)
		if err != nil {
			return AttemptOutcome{}, fmt.Errorf("review coordinator: normalize lane evidence: %w", err)
		}
		return normalized, nil
	}
	normalized, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return AttemptOutcome{}, fmt.Errorf("review coordinator: normalize lane output: %w", err)
	}
	return normalized, nil
}

func (execution *coordinatorExecution) reduceOutputEvidence(output ValidatedRoleOutput) (ValidatedRoleOutput, AttemptCondition) {
	if condition := coordinatorEvidenceBindingCondition(
		output.Findings(),
		output.Evidence(),
		execution.run.Target().SHA256(),
	); condition != AttemptConditionValidReview {
		return ValidatedRoleOutput{}, condition
	}
	reduced, err := ReduceVerifiedFindingEvidence(
		output.Findings(),
		output.Evidence(),
		execution.coordinator.policy,
	)
	if err != nil {
		if _, policyRejected := AsEvidencePolicyError(err); policyRejected {
			return ValidatedRoleOutput{}, AttemptConditionInvalidEvidenceClaim
		}
		return ValidatedRoleOutput{}, AttemptConditionInternalInvariant
	}
	output.findings = append([]domain.Finding(nil), reduced...)
	return output, AttemptConditionValidReview
}

func coordinatorEvidenceBindingCondition(
	findings []domain.Finding,
	groups []VerifiedFindingEvidence,
	runTargetSHA256 string,
) AttemptCondition {
	if runTargetSHA256 == "" || len(findings) != len(groups) {
		return AttemptConditionInternalInvariant
	}
	expectedTargetSHA256 := "sha256:" + runTargetSHA256
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		group := groups[index]
		groupFinding := group.findingProof()
		proof := group.validationProof
		proofClaims := proof.Claims()
		claims := group.claims
		receipts := group.Receipts()

		if finding.ID() != expectedID ||
			group.FindingID() != expectedID ||
			groupFinding.ID() != expectedID ||
			proof.FindingID() != expectedID ||
			!proof.MatchesFinding(groupFinding) ||
			len(proofClaims) == 0 ||
			len(proofClaims) != len(claims) ||
			len(claims) != len(receipts) {
			return AttemptConditionInternalInvariant
		}

		for claimIndex, receipt := range receipts {
			proofTargetSHA256 := proofClaims[claimIndex].TargetSHA256()
			claimTargetSHA256 := claims[claimIndex].TargetSHA256()
			receiptTargetSHA256 := receipt.Claim().TargetSHA256()
			if proofTargetSHA256 == "" || claimTargetSHA256 == "" || receiptTargetSHA256 == "" {
				return AttemptConditionInternalInvariant
			}
			if proofTargetSHA256 != expectedTargetSHA256 ||
				claimTargetSHA256 != expectedTargetSHA256 ||
				receiptTargetSHA256 != expectedTargetSHA256 {
				return AttemptConditionInternalInvariant
			}
			if !currentEvidenceClaimsEqual(claims[claimIndex], proofClaims[claimIndex]) {
				return AttemptConditionInternalInvariant
			}
			if !receiptMatchesValidationClaim(receipt, claims[claimIndex]) {
				return AttemptConditionInternalInvariant
			}
		}
		if !group.matchesFinding(finding) {
			return AttemptConditionInternalInvariant
		}
	}
	return AttemptConditionValidReview
}

func (execution *coordinatorExecution) commitOutcome(
	job InvocationJob,
	outcome AttemptOutcome,
	condition AttemptCondition,
	cancellationObserved bool,
	suppressFollowup bool,
) ([]InvocationJob, error) {
	state := execution.roles[job.Role()]
	attempt, err := execution.attemptFor(job)
	if err != nil {
		return nil, err
	}
	var output ValidatedRoleOutput
	if outcome.Succeeded() {
		var ok bool
		output, ok = outcome.Output()
		if !ok {
			return nil, fmt.Errorf("review coordinator: normalized successful outcome has no output")
		}
	}
	if err := execution.record(CoordinatorEventInvocationCommitted, job.Role(), attempt, &job.purpose, &condition, "", domain.RunState("")); err != nil {
		return nil, err
	}

	if conditionRequiresValidation(condition) {
		if err := attempt.attempt.TransitionInvocation(invocationSequence(job.Purpose()), domain.InvocationSucceeded); err != nil {
			return nil, fmt.Errorf("review coordinator: complete provider invocation: %w", err)
		}
		if err := attempt.attempt.Transition(domain.AttemptValidating); err != nil {
			return nil, fmt.Errorf("review coordinator: validate provider invocation: %w", err)
		}
	} else {
		if err := transitionFailedInvocation(&attempt.attempt, job.Purpose(), condition); err != nil {
			return nil, err
		}
	}

	fallbackConfigured := job.AttemptKind() == AttemptKindPrimary && state.assignment.HasFallback()
	repairUsed := attempt.repairUsed
	if suppressFollowup {
		fallbackConfigured = false
		repairUsed = true
	}
	decision, err := DecideTransition(TransitionInput{
		Condition:            condition,
		RepairUsed:           repairUsed,
		FallbackConfigured:   fallbackConfigured,
		FallbackEligible:     fallbackConfigured && conditionFailureClass(condition).FallbackAllowed(),
		CancellationObserved: cancellationObserved,
	})
	if err != nil {
		return nil, fmt.Errorf("review coordinator: decide transition: %w", err)
	}
	if decision.ScheduleRepair() {
		if err := attempt.attempt.Transition(domain.AttemptRepairing); err != nil {
			return nil, fmt.Errorf("review coordinator: enter repair: %w", err)
		}
		repair, err := domain.NewInvocation(2, domain.InvocationRepair)
		if err != nil {
			return nil, fmt.Errorf("review coordinator: create repair invocation: %w", err)
		}
		if err := attempt.attempt.AppendRepairInvocation(repair); err != nil {
			return nil, fmt.Errorf("review coordinator: append repair invocation: %w", err)
		}
		attempt.repairUsed = true
		job, err := execution.newJob(job.Role(), attempt, domain.InvocationRepair)
		if err != nil {
			return nil, err
		}
		if err := execution.record(CoordinatorEventRepairQueued, job.Role(), attempt, &job.purpose, nil, decision.ReasonCode(), domain.RunState("")); err != nil {
			return nil, err
		}
		return []InvocationJob{job}, nil
	}
	if decision.ScheduleFallback() {
		if err := terminalizeAttempt(&attempt.attempt, condition); err != nil {
			return nil, err
		}
		fallback, ok := state.assignment.FallbackRoute()
		if !ok {
			return nil, fmt.Errorf("review coordinator: policy scheduled missing fallback route")
		}
		if err := execution.run.QueueRoleFallback(job.Role(), decision.TerminalClass()); err != nil {
			return nil, fmt.Errorf("review coordinator: queue fallback: %w", err)
		}
		state.fallbackScheduled = true
		if err := execution.record(CoordinatorEventFallbackQueued, job.Role(), attempt, nil, &condition, decision.ReasonCode(), domain.RunState("")); err != nil {
			return nil, err
		}
		fallbackJob, err := execution.startAttempt(job.Role(), AttemptKindFallback, fallback, CoordinatorEventAttemptQueued)
		if err != nil {
			return nil, err
		}
		return []InvocationJob{fallbackJob}, nil
	}

	if err := terminalizeAttempt(&attempt.attempt, decision.Condition()); err != nil {
		return nil, err
	}
	switch decision.TerminalProjection() {
	case TerminalProjectionSucceeded:
		if err := execution.run.TransitionRole(job.Role(), domain.RoleTaskSucceeded); err != nil {
			return nil, fmt.Errorf("review coordinator: succeed role: %w", err)
		}
		copied := output.clone()
		state.output = &copied
		state.repaired = job.Purpose() == domain.InvocationRepair
	case TerminalProjectionFailed:
		if err := execution.run.TransitionRole(job.Role(), domain.RoleTaskFailed); err != nil {
			return nil, fmt.Errorf("review coordinator: fail role: %w", err)
		}
		state.failureClass = decision.TerminalClass()
		state.reasonCode = decision.ReasonCode()
	case TerminalProjectionCancelled:
		if err := execution.run.TransitionRole(job.Role(), domain.RoleTaskCancelled); err != nil {
			return nil, fmt.Errorf("review coordinator: cancel role: %w", err)
		}
		state.failureClass = decision.TerminalClass()
		state.reasonCode = decision.ReasonCode()
	default:
		return nil, fmt.Errorf("review coordinator: terminal decision has no terminal projection")
	}
	if err := execution.record(CoordinatorEventRoleTerminal, job.Role(), attempt, nil, &condition, decision.ReasonCode(), domain.RunState("")); err != nil {
		return nil, err
	}
	return nil, nil
}

func conditionRequiresValidation(condition AttemptCondition) bool {
	switch condition {
	case AttemptConditionValidReview,
		AttemptConditionInvalidProviderOutput,
		AttemptConditionInvalidEvidenceClaim,
		AttemptConditionSemanticContradiction:
		return true
	default:
		return false
	}
}

func invocationSequence(purpose domain.InvocationPurpose) uint64 {
	if purpose == domain.InvocationRepair {
		return 2
	}
	return 1
}

func transitionFailedInvocation(attempt *domain.Attempt, purpose domain.InvocationPurpose, condition AttemptCondition) error {
	sequence := invocationSequence(purpose)
	nextInvocation := domain.InvocationFailed
	nextAttempt := domain.AttemptFailed
	switch condition {
	case AttemptConditionTimeout:
		nextInvocation, nextAttempt = domain.InvocationTimedOut, domain.AttemptTimedOut
	case AttemptConditionCancelled:
		nextInvocation, nextAttempt = domain.InvocationCancelled, domain.AttemptCancelled
	}
	if err := attempt.TransitionInvocation(sequence, nextInvocation); err != nil {
		return fmt.Errorf("review coordinator: fail invocation: %w", err)
	}
	if err := attempt.Transition(nextAttempt); err != nil {
		return fmt.Errorf("review coordinator: fail attempt: %w", err)
	}
	return nil
}

func terminalizeAttempt(attempt *domain.Attempt, condition AttemptCondition) error {
	if attempt.State() == domain.AttemptSucceeded || attempt.State() == domain.AttemptFailed ||
		attempt.State() == domain.AttemptTimedOut || attempt.State() == domain.AttemptCancelled || attempt.State() == domain.AttemptBlocked {
		return nil
	}
	next := domain.AttemptFailed
	switch condition {
	case AttemptConditionValidReview:
		next = domain.AttemptSucceeded
	case AttemptConditionTimeout:
		next = domain.AttemptTimedOut
	case AttemptConditionCancelled:
		next = domain.AttemptCancelled
	}
	if err := attempt.Transition(next); err != nil {
		return fmt.Errorf("review coordinator: terminalize attempt: %w", err)
	}
	return nil
}

func conditionFailureClass(condition AttemptCondition) domain.FailureClass {
	decision, err := DecideTransition(TransitionInput{Condition: condition})
	if err != nil {
		return domain.FailureInternal
	}
	return decision.TerminalClass()
}

func (execution *coordinatorExecution) attemptFor(job InvocationJob) (*coordinatorAttempt, error) {
	state := execution.roles[job.Role()]
	if state == nil {
		return nil, fmt.Errorf("review coordinator: result for unknown role %q", job.Role())
	}
	limits, err := execution.invocationLimits(job.Role(), job.AttemptKind(), job.Route())
	if err != nil {
		return nil, err
	}
	for index := range state.attempts {
		attempt := &state.attempts[index]
		if attempt.attempt.ID() == job.AttemptID() && attempt.kind == job.AttemptKind() &&
			sameCoordinatorRoute(attempt.route, job.Route()) && job.Limits() == limits {
			return attempt, nil
		}
	}
	return nil, fmt.Errorf("review coordinator: result for unknown attempt %q", job.AttemptID().String())
}

func (execution *coordinatorExecution) contextConditions() []AttemptCondition {
	conditions := make([]AttemptCondition, 0, 2)
	if execution.callerCtx != nil && execution.callerCtx.Err() != nil {
		conditions = append(conditions, AttemptConditionCancelled)
	}
	if execution.runContext != nil && execution.runContext.Err() == context.DeadlineExceeded {
		conditions = append(conditions, AttemptConditionTimeout)
	}
	return conditions
}
func (execution *coordinatorExecution) conditionForTransition(
	condition AttemptCondition,
) (
	effective AttemptCondition,
	cancellationObserved bool,
	contextCondition AttemptCondition,
	contextObserved bool,
	err error,
) {
	callerCancelled := execution.callerCtx != nil && execution.callerCtx.Err() != nil
	if callerCancelled {
		reduced, reduceErr := ReduceAttemptConditions(condition, AttemptConditionCancelled)
		return reduced, true, AttemptConditionCancelled, true, reduceErr
	}
	if execution.runContext != nil && execution.runContext.Err() == context.DeadlineExceeded {
		if conditionRetainsAuthorityAfterContext(condition, AttemptConditionTimeout) {
			return condition, false, AttemptConditionTimeout, true, nil
		}
		return AttemptConditionTimeout, false, AttemptConditionTimeout, true, nil
	}
	return condition, false, "", false, nil
}

func (execution *coordinatorExecution) prepareOutcomeCommit(
	scheduler *laneScheduler,
	condition AttemptCondition,
) (AttemptCondition, bool, bool, error) {
	effective, cancellationObserved, _, contextObserved, err := execution.conditionForTransition(condition)
	if err != nil {
		return "", false, false, fmt.Errorf("review coordinator: reduce transition context: %w", err)
	}
	if contextObserved {
		if err := execution.requestDispatchStop(scheduler, effective); err != nil {
			return "", false, false, err
		}
	}
	return effective, cancellationObserved, contextObserved, nil
}

func (execution *coordinatorExecution) requestDispatchStop(
	scheduler *laneScheduler,
	condition AttemptCondition,
) error {
	scheduler.cancelDispatch()
	if execution.dispatchStopRecorded {
		reduced, err := ReduceAttemptConditions(execution.dispatchStopCondition, condition)
		if err != nil {
			return fmt.Errorf("review coordinator: reduce dispatch stop: %w", err)
		}
		if reduced == execution.dispatchStopCondition {
			return nil
		}
		condition = reduced
	}
	if err := execution.record(CoordinatorEventCancellationRequested, domain.Role(""), nil, nil, &condition, string(condition), domain.RunState("")); err != nil {
		return err
	}
	execution.dispatchStopRecorded = true
	execution.dispatchStopCondition = condition
	return nil
}

func (execution *coordinatorExecution) contextCondition() AttemptCondition {
	if execution.callerCtx != nil && execution.callerCtx.Err() != nil {
		return AttemptConditionCancelled
	}
	if execution.runContext != nil && execution.runContext.Err() == context.DeadlineExceeded {
		return AttemptConditionTimeout
	}
	return AttemptConditionCancelled
}

func (execution *coordinatorExecution) cancelAll(scheduler *laneScheduler, condition AttemptCondition) error {
	effective := condition
	if execution.stopCondition.Valid() {
		reduced, err := ReduceAttemptConditions(execution.stopCondition, condition)
		if err != nil {
			return fmt.Errorf("review coordinator: reduce run stop: %w", err)
		}
		effective = reduced
	}
	execution.stopping = true
	execution.stopCondition = effective
	execution.cancelled = conditionCancelsCoordinatorRun(effective)
	if err := execution.requestDispatchStop(scheduler, effective); err != nil {
		return err
	}
	roleCondition := execution.contextCondition()
	for _, role := range domain.FixedRoleOrder() {
		state := execution.roles[role]
		if state == nil || coordinatorRoleTerminal(execution.run, role) {
			continue
		}
		var attempt *coordinatorAttempt
		if state.currentAttempt >= 0 {
			attempt = &state.attempts[state.currentAttempt]
			if err := stopCoordinatorAttempt(&attempt.attempt, roleCondition); err != nil {
				return err
			}
		}
		if roleCondition == AttemptConditionCancelled {
			if err := execution.run.TransitionRole(role, domain.RoleTaskCancelled); err != nil {
				return fmt.Errorf("review coordinator: cancel role %q: %w", role, err)
			}
			state.failureClass = domain.FailureCancelled
			state.reasonCode = string(AttemptConditionCancelled)
		} else {
			if err := execution.run.TransitionRole(role, domain.RoleTaskFailed); err != nil {
				return fmt.Errorf("review coordinator: fail role %q: %w", role, err)
			}
			state.failureClass = conditionFailureClass(roleCondition)
			state.reasonCode = string(roleCondition)
		}
		if err := execution.record(CoordinatorEventRoleTerminal, role, attempt, nil, &roleCondition, state.reasonCode, domain.RunState("")); err != nil {
			return err
		}
	}
	return nil
}

func stopCoordinatorAttempt(attempt *domain.Attempt, condition AttemptCondition) error {
	if attempt == nil || attempt.State() == domain.AttemptSucceeded || attempt.State() == domain.AttemptFailed ||
		attempt.State() == domain.AttemptTimedOut || attempt.State() == domain.AttemptCancelled || attempt.State() == domain.AttemptBlocked {
		return nil
	}
	invocations := attempt.Invocations()
	if len(invocations) == 0 {
		return fmt.Errorf("review coordinator: active attempt has no invocation")
	}
	current := invocations[len(invocations)-1]
	if current.State() == domain.InvocationQueued || current.State() == domain.InvocationRunning {
		next := domain.InvocationFailed
		switch condition {
		case AttemptConditionCancelled:
			next = domain.InvocationCancelled
		case AttemptConditionTimeout:
			if current.State() == domain.InvocationRunning {
				next = domain.InvocationTimedOut
			} else {
				next = domain.InvocationCancelled
			}
		}
		if err := attempt.TransitionInvocation(current.Sequence(), next); err != nil {
			return fmt.Errorf("review coordinator: stop invocation: %w", err)
		}
	}
	nextAttempt := domain.AttemptFailed
	switch condition {
	case AttemptConditionCancelled:
		nextAttempt = domain.AttemptCancelled
	case AttemptConditionTimeout:
		if attempt.State() == domain.AttemptRunning || attempt.State() == domain.AttemptRepairing {
			nextAttempt = domain.AttemptTimedOut
		}
	}
	if err := attempt.Transition(nextAttempt); err != nil {
		return fmt.Errorf("review coordinator: stop attempt: %w", err)
	}
	return nil
}

func coordinatorRoleTerminal(run *domain.Run, role domain.Role) bool {
	for _, task := range run.RoleTasks() {
		if task.Role() != role {
			continue
		}
		switch task.State() {
		case domain.RoleTaskSucceeded, domain.RoleTaskFailed, domain.RoleTaskCancelled, domain.RoleTaskBlocked:
			return true
		default:
			return false
		}
	}
	return false
}

func (execution *coordinatorExecution) allRolesTerminal() bool {
	for _, task := range execution.run.RoleTasks() {
		if !coordinatorRoleTerminal(execution.run, task.Role()) {
			return false
		}
	}
	return true
}

func (execution *coordinatorExecution) finishRun() error {
	if execution.cancelled {
		if err := execution.run.Transition(domain.RunCancelled); err != nil {
			return fmt.Errorf("review coordinator: cancel run: %w", err)
		}
		return nil
	}
	if execution.stopCondition.Valid() &&
		execution.stopCondition != AttemptConditionValidReview {
		if err := execution.run.Transition(domain.RunFailed); err != nil {
			return fmt.Errorf("review coordinator: fail stopped run: %w", err)
		}
		return nil
	}
	allSucceeded := true
	requiredFailed := false
	optionalFailed := false
	for _, task := range execution.run.RoleTasks() {
		if task.State() == domain.RoleTaskSucceeded {
			continue
		}
		allSucceeded = false
		if task.Required() {
			requiredFailed = true
		} else {
			optionalFailed = true
		}
	}
	if allSucceeded {
		if err := execution.run.Transition(domain.RunCompleted); err != nil {
			return fmt.Errorf("review coordinator: complete run: %w", err)
		}
		return nil
	}
	if !requiredFailed && optionalFailed {
		if err := execution.run.Transition(domain.RunDegraded); err != nil {
			return fmt.Errorf("review coordinator: degrade run: %w", err)
		}
		return nil
	}
	if err := execution.run.Transition(domain.RunFailed); err != nil {
		return fmt.Errorf("review coordinator: fail run: %w", err)
	}
	return nil
}

func (execution *coordinatorExecution) snapshot(
	sessionID domain.SessionID,
	runID domain.RunID,
	threshold domain.Severity,
	policy *domain.CIPolicy,
) (CoordinatorResult, error) {
	findings := make([]domain.Finding, 0)
	evidenceAssociations := make([]coordinatorFindingEvidenceAssociation, 0)
	roles := make([]CoordinatorRoleSummary, 0, len(execution.roles))
	roleResults := make([]domain.RoleResultSummary, 0, len(execution.roles))
	fallbackScheduled := false
	for _, role := range domain.FixedRoleOrder() {
		state := execution.roles[role]
		if state == nil {
			continue
		}
		roleState := coordinatorRoleState(execution.run, role)
		valid := roleState == domain.RoleTaskSucceeded && state.output != nil
		degraded := valid && coordinatorOutputDegraded(state.output)
		if valid {
			roleFindings := state.output.Findings()
			roleEvidence := state.output.Evidence()
			associations, err := coordinatorEvidenceAssociations(roleFindings, roleEvidence)
			if err != nil {
				return CoordinatorResult{}, fmt.Errorf("review coordinator: correlate role evidence for %q: %w", role, err)
			}
			findings = append(findings, roleFindings...)
			evidenceAssociations = append(evidenceAssociations, associations...)
		}
		roles = append(roles, CoordinatorRoleSummary{
			role:              role,
			required:          state.assignment.Required(),
			state:             roleState,
			valid:             valid,
			degraded:          degraded,
			repaired:          state.repaired,
			fallbackScheduled: state.fallbackScheduled,
			failureClass:      state.failureClass,
			reasonCode:        state.reasonCode,
			attempts:          coordinatorAttemptSnapshots(state.attempts),
		})
		roleResults = append(roleResults, domain.RoleResultSummary{
			Role:     role,
			Selected: true,
			Required: state.assignment.Required(),
			Valid:    valid,
			Degraded: degraded,
		})
		fallbackScheduled = fallbackScheduled || state.fallbackScheduled
	}
	ordered, err := domain.OrderAndAssignFindings(findings)
	if err != nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: order findings: %w", err)
	}
	orderedEvidence, err := coordinatorFinalEvidence(ordered, evidenceAssociations)
	if err != nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: correlate final evidence: %w", err)
	}
	axes, err := domain.ComputeOutcomeAxes(ordered, roleResults, threshold, domain.PublicationNotPublished, policy)
	if err != nil {
		return CoordinatorResult{}, fmt.Errorf("review coordinator: compute outcome axes: %w", err)
	}
	return CoordinatorResult{
		sessionID:         sessionID,
		runID:             runID,
		runState:          execution.run.State(),
		findings:          append([]domain.Finding(nil), ordered...),
		evidence:          cloneVerifiedFindingEvidence(orderedEvidence),
		axes:              axes,
		roleSummaries:     cloneCoordinatorRoleSummaries(roles),
		trace:             append([]CoordinatorTraceEvent(nil), execution.trace...),
		fallbackScheduled: fallbackScheduled,
	}, nil
}
func coordinatorOutputDegraded(output *ValidatedRoleOutput) bool {
	if output == nil {
		return false
	}
	if output.Completeness() == "incomplete" || len(output.Limitations()) != 0 {
		return true
	}
	for _, finding := range output.Findings() {
		if finding.EvidenceState() != domain.EvidenceVerified {
			return true
		}
	}
	return false
}

type coordinatorFindingEvidenceAssociation struct {
	finding  domain.Finding
	evidence VerifiedFindingEvidence
}

func coordinatorEvidenceAssociations(
	findings []domain.Finding,
	groups []VerifiedFindingEvidence,
) ([]coordinatorFindingEvidenceAssociation, error) {
	if len(findings) != len(groups) {
		return nil, fmt.Errorf("finding count %d does not match receipt group count %d", len(findings), len(groups))
	}
	associations := make([]coordinatorFindingEvidenceAssociation, len(findings))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID() != expectedID || groups[index].FindingID() != expectedID {
			return nil, fmt.Errorf("finding and receipt group %d do not have canonical local ID %q", index, expectedID)
		}
		if len(groups[index].Receipts()) == 0 {
			return nil, fmt.Errorf("finding %q has no verifier receipts", expectedID)
		}
		associations[index] = coordinatorFindingEvidenceAssociation{
			finding:  finding,
			evidence: cloneVerifiedFindingEvidence(groups[index : index+1])[0],
		}
	}
	return associations, nil
}

func coordinatorFinalEvidence(
	findings []domain.Finding,
	associations []coordinatorFindingEvidenceAssociation,
) ([]VerifiedFindingEvidence, error) {
	if len(findings) != len(associations) {
		return nil, fmt.Errorf("final finding count %d does not match receipt group count %d", len(findings), len(associations))
	}

	ordered := make([]VerifiedFindingEvidence, len(findings))
	used := make([]bool, len(associations))
	for findingIndex, finding := range findings {
		identity := coordinatorFindingIdentityFor(finding)
		match := -1
		for associationIndex, association := range associations {
			if coordinatorFindingIdentityFor(association.finding) != identity {
				continue
			}
			if match >= 0 {
				return nil, fmt.Errorf("final finding %q has ambiguous receipt correlation", finding.ID())
			}
			match = associationIndex
		}
		if match < 0 {
			return nil, fmt.Errorf("final finding %q has no receipt correlation", finding.ID())
		}
		if used[match] {
			return nil, fmt.Errorf("final finding %q reuses a receipt correlation", finding.ID())
		}
		used[match] = true
		evidence := cloneVerifiedFindingEvidence([]VerifiedFindingEvidence{associations[match].evidence})[0]
		evidence.findingID = finding.ID()
		ordered[findingIndex] = evidence
	}
	for associationIndex, consumed := range used {
		if !consumed {
			return nil, fmt.Errorf("receipt group %d has no final finding correlation", associationIndex)
		}
	}
	return ordered, nil
}

func coordinatorRoleState(run *domain.Run, role domain.Role) domain.RoleTaskState {
	for _, task := range run.RoleTasks() {
		if task.Role() == role {
			return task.State()
		}
	}
	return domain.RoleTaskBlocked
}

func coordinatorAttemptSnapshots(attempts []coordinatorAttempt) []CoordinatorAttemptSummary {
	snapshots := make([]CoordinatorAttemptSummary, len(attempts))
	for index, attempt := range attempts {
		invocations := attempt.attempt.Invocations()
		snapshots[index] = CoordinatorAttemptSummary{
			id:          attempt.attempt.ID(),
			kind:        attempt.kind,
			route:       attempt.route,
			state:       attempt.attempt.State(),
			invocations: make([]CoordinatorInvocationSummary, len(invocations)),
		}
		for invocationIndex, invocation := range invocations {
			snapshots[index].invocations[invocationIndex] = CoordinatorInvocationSummary{
				sequence: invocation.Sequence(),
				purpose:  invocation.Purpose(),
				state:    invocation.State(),
			}
		}
	}
	return snapshots
}

func (execution *coordinatorExecution) record(
	kind CoordinatorEventKind,
	role domain.Role,
	attempt *coordinatorAttempt,
	purpose *domain.InvocationPurpose,
	condition *AttemptCondition,
	reason string,
	runState domain.RunState,
) error {
	if execution.runTerminalRecorded {
		return fmt.Errorf("review coordinator: record trace: run terminal is already recorded")
	}
	if kind == CoordinatorEventRunStarted {
		if execution.runStarted || execution.nextEvent != 0 || len(execution.trace) != 0 {
			return fmt.Errorf("review coordinator: record trace: run started must be first and unique")
		}
	} else if !execution.runStarted {
		return fmt.Errorf("review coordinator: record trace: run started is required first")
	}
	if execution.lanesCloseAuthorized && kind != CoordinatorEventRunTerminal {
		return fmt.Errorf("review coordinator: record trace: lanes are already close-authorized")
	}

	roleEvent := kind == CoordinatorEventAttemptQueued ||
		kind == CoordinatorEventInvocationDispatched ||
		kind == CoordinatorEventInvocationCommitted ||
		kind == CoordinatorEventRepairQueued ||
		kind == CoordinatorEventFallbackQueued ||
		kind == CoordinatorEventRoleTerminal
	if roleEvent {
		if !role.Valid() {
			return fmt.Errorf("review coordinator: record trace: role event has invalid role")
		}
		if _, terminal := execution.terminalRoles[role]; terminal {
			return fmt.Errorf("review coordinator: record trace: role %q is already terminal", role)
		}
	} else if role.Valid() {
		return fmt.Errorf("review coordinator: record trace: global event has role %q", role)
	}

	switch kind {
	case CoordinatorEventLanesCloseAuthorized:
		if execution.lanesCloseAuthorized {
			return fmt.Errorf("review coordinator: record trace: lanes close is already authorized")
		}
		if execution.run == nil || !execution.allRolesTerminal() {
			return fmt.Errorf("review coordinator: record trace: lanes close requires every role terminal")
		}
	case CoordinatorEventRunTerminal:
		if !execution.lanesCloseAuthorized {
			return fmt.Errorf("review coordinator: record trace: run terminal requires lanes close authorization")
		}
		if execution.run == nil || !coordinatorTerminalRunState(runState) || execution.run.State() != runState {
			return fmt.Errorf("review coordinator: record trace: run terminal requires current terminal run state")
		}
	}

	event := CoordinatorTraceEvent{
		ordinal:  execution.nextEvent + 1,
		kind:     kind,
		role:     role,
		reason:   reason,
		runState: runState,
	}
	if attempt != nil {
		event.attemptID = attempt.attempt.ID()
		event.hasAttempt = true
		event.attemptKind = attempt.kind
		event.lane = attempt.route.ConcurrencyKey()
		event.hasLane = true
	}
	if purpose != nil {
		event.purpose = *purpose
		event.hasPurpose = true
	}
	if condition != nil {
		event.condition = *condition
		event.hasCondition = true
	}
	if err := event.validate(); err != nil {
		return fmt.Errorf("review coordinator: record trace: %w", err)
	}
	if err := execution.emitRuntimeDiagnostics(event); err != nil {
		return err
	}
	execution.trace = append(execution.trace, event)
	execution.nextEvent++
	switch kind {
	case CoordinatorEventRunStarted:
		execution.runStarted = true
	case CoordinatorEventRoleTerminal:
		if execution.terminalRoles == nil {
			execution.terminalRoles = make(map[domain.Role]struct{})
		}
		execution.terminalRoles[role] = struct{}{}
	case CoordinatorEventLanesCloseAuthorized:
		execution.lanesCloseAuthorized = true
	case CoordinatorEventRunTerminal:
		execution.runTerminalRecorded = true
	}
	return nil
}

func coordinatorTerminalRunState(state domain.RunState) bool {
	return state == domain.RunCompleted ||
		state == domain.RunDegraded ||
		state == domain.RunFailed ||
		state == domain.RunCancelled
}
