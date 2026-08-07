package domain

import (
	"fmt"
	"time"
)

type Run struct {
	id          RunID
	sessionID   SessionID
	runType     RunType
	state       RunState
	parentRunID RunID
	hasParent   bool
	sourceRunID RunID
	hasSource   bool
	target      TargetIdentity
	roles       []RoleTask
}

func NewChildRun(id RunID, runType RunType, parent Run, source Run, target TargetIdentity, roles []RoleTask) (Run, error) {
	if err := validateChildProvenance("parent", parent); err != nil {
		return Run{}, err
	}
	if err := validateChildProvenance("source", source); err != nil {
		return Run{}, err
	}
	if parent.sessionID != source.sessionID {
		return Run{}, fmt.Errorf("child run: %w: parent and source must belong to the same session", ErrInvariant)
	}
	return NewChildRunFromImmutableSource(id, runType, parent.sessionID, parent.id, source.id, target, roles)
}

// NewFollowupChildRun creates a fresh, finding-scoped followup child. Followups
// deliberately execute only the selected source role. Broad recomposed runs
// validate the exact non-empty role subset selected by their caller.
func NewFollowupChildRun(id RunID, parent Run, source Run, target TargetIdentity, selected RoleTask) (Run, error) {
	if err := validateChildProvenance("parent", parent); err != nil {
		return Run{}, err
	}
	if err := validateChildProvenance("source", source); err != nil {
		return Run{}, err
	}
	if parent.sessionID != source.sessionID {
		return Run{}, fmt.Errorf("followup child run: %w: parent and source must belong to the same session", ErrInvariant)
	}
	if !selected.Role().Valid() {
		return Run{}, fmt.Errorf("followup child run: %w: selected role is invalid", ErrInvariant)
	}
	if selected.State() != RoleTaskPending {
		return Run{}, fmt.Errorf("followup child run: %w: selected role task is not pending", ErrInvariant)
	}
	if id == parent.id || id == source.id {
		return Run{}, fmt.Errorf("followup child run: %w: child ID cannot reference its parent or source", ErrInvariant)
	}
	run, err := newFollowupRun(id, parent.sessionID, target, selected)
	if err != nil {
		return Run{}, err
	}
	run.parentRunID, run.hasParent = parent.id, true
	run.sourceRunID, run.hasSource = source.id, true
	return run, nil
}

func newFollowupRun(id RunID, sessionID SessionID, target TargetIdentity, selected RoleTask) (Run, error) {
	if _, err := ParseRunID(id.String()); err != nil {
		return Run{}, fmt.Errorf("followup child run: %w: invalid run ID: %v", ErrInvariant, err)
	}
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Run{}, fmt.Errorf("followup child run: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if target.Kind() == "" {
		return Run{}, fmt.Errorf("followup child run: %w: target identity is required", ErrInvariant)
	}
	if !selected.Role().Valid() || selected.State() != RoleTaskPending {
		return Run{}, fmt.Errorf("followup child run: %w: invalid selected role task", ErrInvariant)
	}
	return Run{id: id, sessionID: sessionID, runType: RunTypeFollowup, state: RunPending, target: target, roles: []RoleTask{selected}}, nil
}

// NewFollowupChildRunFromImmutableSource is the immutable-lineage form of
// NewFollowupChildRun. It keeps the followup's single selected-role exception
// isolated from the broad child constructors.
func NewFollowupChildRunFromImmutableSource(
	id RunID,
	sessionID SessionID,
	parentRunID RunID,
	sourceRunID RunID,
	target TargetIdentity,
	selected RoleTask,
) (Run, error) {
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Run{}, fmt.Errorf("followup child run: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(parentRunID.String()); err != nil {
		return Run{}, fmt.Errorf("followup child run: %w: invalid parent run ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(sourceRunID.String()); err != nil {
		return Run{}, fmt.Errorf("followup child run: %w: invalid source run ID: %v", ErrInvariant, err)
	}
	if id == parentRunID || id == sourceRunID {
		return Run{}, fmt.Errorf("followup child run: %w: child ID cannot reference its parent or source", ErrInvariant)
	}
	run, err := newFollowupRun(id, sessionID, target, selected)
	if err != nil {
		return Run{}, err
	}
	run.parentRunID, run.hasParent = parentRunID, true
	run.sourceRunID, run.hasSource = sourceRunID, true
	return run, nil
}

// NewRerunChildRunFromImmutableSource creates an exact-replay child with only
// the source-selected role. Broad recomposed reruns continue to use
// NewChildRunFromImmutableSource and validate their exact selected subset.
func NewRerunChildRunFromImmutableSource(
	id RunID,
	sessionID SessionID,
	parentRunID RunID,
	sourceRunID RunID,
	target TargetIdentity,
	selected RoleTask,
) (Run, error) {
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Run{}, fmt.Errorf("rerun child run: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(parentRunID.String()); err != nil {
		return Run{}, fmt.Errorf("rerun child run: %w: invalid parent run ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(sourceRunID.String()); err != nil {
		return Run{}, fmt.Errorf("rerun child run: %w: invalid source run ID: %v", ErrInvariant, err)
	}
	if id == parentRunID || id == sourceRunID {
		return Run{}, fmt.Errorf("rerun child run: %w: child ID cannot reference its parent or source", ErrInvariant)
	}
	if _, err := ParseRunID(id.String()); err != nil {
		return Run{}, fmt.Errorf("rerun child run: %w: invalid run ID: %v", ErrInvariant, err)
	}
	if target.Kind() == "" {
		return Run{}, fmt.Errorf("rerun child run: %w: target identity is required", ErrInvariant)
	}
	if !selected.Role().Valid() || selected.State() != RoleTaskPending {
		return Run{}, fmt.Errorf("rerun child run: %w: invalid selected role task", ErrInvariant)
	}
	return Run{
		id: id, sessionID: sessionID, runType: RunTypeRerun,
		state: RunPending, target: target, roles: []RoleTask{selected},
		parentRunID: parentRunID, hasParent: true,
		sourceRunID: sourceRunID, hasSource: true,
	}, nil
}

// NewChildRunFromImmutableSource creates a fresh child using only verified
// immutable lineage identifiers. It does not require or reconstruct source run
// state.
func NewChildRunFromImmutableSource(
	id RunID,
	runType RunType,
	sessionID SessionID,
	parentRunID RunID,
	sourceRunID RunID,
	target TargetIdentity,
	roles []RoleTask,
) (Run, error) {
	if !runType.Valid() {
		return Run{}, fmt.Errorf("child run: %w: invalid type %q", ErrInvariant, runType)
	}
	if runType == RunTypeReview {
		return Run{}, fmt.Errorf("child run: %w: review runs must be constructed with NewReviewSession", ErrInvariant)
	}
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Run{}, fmt.Errorf("child run: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(parentRunID.String()); err != nil {
		return Run{}, fmt.Errorf("child run: %w: invalid parent run ID: %v", ErrInvariant, err)
	}
	if _, err := ParseRunID(sourceRunID.String()); err != nil {
		return Run{}, fmt.Errorf("child run: %w: invalid source run ID: %v", ErrInvariant, err)
	}
	if id == parentRunID || id == sourceRunID {
		return Run{}, fmt.Errorf("child run: %w: child ID cannot reference its parent or source", ErrInvariant)
	}
	run, err := newRun(id, sessionID, runType, target, roles)
	if err != nil {
		return Run{}, err
	}
	run.parentRunID, run.hasParent = parentRunID, true
	run.sourceRunID, run.hasSource = sourceRunID, true
	return run, nil
}

func validateChildProvenance(name string, run Run) error {
	if _, err := ParseRunID(run.id.String()); err != nil {
		return fmt.Errorf("child run: %w: invalid %s run ID: %v", ErrInvariant, name, err)
	}
	if _, err := ParseSessionID(run.sessionID.String()); err != nil {
		return fmt.Errorf("child run: %w: invalid %s session ID: %v", ErrInvariant, name, err)
	}
	return nil
}

func newRun(id RunID, sessionID SessionID, runType RunType, target TargetIdentity, roles []RoleTask) (Run, error) {
	if _, err := ParseRunID(id.String()); err != nil {
		return Run{}, fmt.Errorf("run: %w: invalid run ID: %v", ErrInvariant, err)
	}
	if _, err := ParseSessionID(sessionID.String()); err != nil {
		return Run{}, fmt.Errorf("run: %w: invalid session ID: %v", ErrInvariant, err)
	}
	if !runType.Valid() {
		return Run{}, fmt.Errorf("run: %w: invalid type %q", ErrInvariant, runType)
	}
	if target.Kind() == "" {
		return Run{}, fmt.Errorf("run: %w: target identity is required", ErrInvariant)
	}
	canonicalRoles, err := validateRoleTasks(roles)
	if err != nil {
		return Run{}, err
	}
	return Run{
		id:        id,
		sessionID: sessionID,
		runType:   runType,
		state:     RunPending,
		target:    target,
		roles:     canonicalRoles,
	}, nil
}

func validateRoleTasks(roles []RoleTask) ([]RoleTask, error) {
	if len(roles) == 0 {
		return nil, fmt.Errorf("run: %w: at least one role task is required", ErrInvariant)
	}
	seen := make(map[Role]RoleTask, len(roles))
	for _, task := range roles {
		if !task.Role().Valid() {
			return nil, fmt.Errorf("run: %w: invalid role task", ErrInvariant)
		}
		if task.Role().RequiredFloor() && !task.Required() {
			return nil, fmt.Errorf("run: %w: selected required-floor role %q is not required", ErrInvariant, task.Role())
		}
		if task.State() != RoleTaskPending {
			return nil, fmt.Errorf("run: %w: fresh role task %q is not pending", ErrInvariant, task.Role())
		}
		if _, duplicate := seen[task.Role()]; duplicate {
			return nil, fmt.Errorf("run: %w: duplicate role task %q", ErrInvariant, task.Role())
		}
		seen[task.Role()] = task
	}
	canonical := make([]RoleTask, 0, len(roles))
	for _, role := range FixedRoleOrder() {
		if task, exists := seen[role]; exists {
			canonical = append(canonical, task)
		}
	}
	return canonical, nil
}

func (run *Run) Transition(next RunState) error {
	if run == nil {
		return fmt.Errorf("run: %w: nil receiver", ErrInvariant)
	}
	if err := run.state.RequireTransition(next); err != nil {
		return err
	}
	switch next {
	case RunCompleted:
		for _, task := range run.roles {
			if task.State() != RoleTaskSucceeded {
				return fmt.Errorf("run: %w: completion requires every selected role to succeed", ErrInvariant)
			}
		}
	case RunDegraded:
		optionalNonSuccess := false
		for _, task := range run.roles {
			if !roleTaskTerminal(task.State()) {
				return fmt.Errorf("run: %w: degradation requires every selected role to be terminal", ErrInvariant)
			}
			if task.Required() && task.State() != RoleTaskSucceeded {
				return fmt.Errorf("run: %w: degradation requires every required role to succeed", ErrInvariant)
			}
			if !task.Required() && task.State() != RoleTaskSucceeded {
				optionalNonSuccess = true
			}
		}
		if !optionalNonSuccess {
			return fmt.Errorf("run: %w: degradation requires an optional non-success result", ErrInvariant)
		}
	}
	run.state = next
	return nil
}

func roleTaskTerminal(state RoleTaskState) bool {
	switch state {
	case RoleTaskSucceeded, RoleTaskFailed, RoleTaskCancelled, RoleTaskBlocked:
		return true
	default:
		return false
	}
}

func (run *Run) TransitionRole(role Role, next RoleTaskState) error {
	if run == nil {
		return fmt.Errorf("run: %w: nil receiver", ErrInvariant)
	}
	if run.state != RunRunning {
		return fmt.Errorf("run: %w: role tasks can transition only while run is running", ErrInvariant)
	}
	if !role.Valid() {
		return fmt.Errorf("run: %w: invalid role %q", ErrInvariant, role)
	}
	for index := range run.roles {
		if run.roles[index].Role() == role {
			return run.roles[index].transition(next)
		}
	}
	return fmt.Errorf("run: %w: role %q is not selected", ErrInvariant, role)
}

func (run Run) ID() RunID                  { return run.id }
func (run Run) SessionID() SessionID       { return run.sessionID }
func (run Run) Type() RunType              { return run.runType }
func (run Run) State() RunState            { return run.state }
func (run Run) ParentRunID() (RunID, bool) { return run.parentRunID, run.hasParent }
func (run Run) SourceRunID() (RunID, bool) { return run.sourceRunID, run.hasSource }
func (run Run) Target() TargetIdentity     { return run.target }
func (run Run) RoleTasks() []RoleTask      { return append([]RoleTask(nil), run.roles...) }

type ReviewArtifact struct {
	id         ReviewID
	axes       OutcomeAxes
	createdAt  time.Time
	fileSHA256 string
}

func NewReviewArtifact(id ReviewID, axes OutcomeAxes, createdAt time.Time, fileSHA256 string) (ReviewArtifact, error) {
	if _, err := ParseReviewID(id.String()); err != nil {
		return ReviewArtifact{}, fmt.Errorf("review artifact: %w", err)
	}
	if !axes.ContentVerdict().Valid() || !axes.CoverageStatus().Valid() || !axes.PublicationStatus().Valid() || !axes.CIDecision().Valid() {
		return ReviewArtifact{}, fmt.Errorf("review artifact: all four outcome axes must be valid")
	}
	if createdAt.IsZero() || createdAt.Location() != time.UTC {
		return ReviewArtifact{}, fmt.Errorf("review artifact: created_at must be non-zero UTC")
	}
	if !lowerSHA256Pattern.MatchString(fileSHA256) {
		return ReviewArtifact{}, fmt.Errorf("review artifact: file SHA-256 must be canonical lowercase hexadecimal")
	}
	return ReviewArtifact{id: id, axes: axes, createdAt: createdAt, fileSHA256: fileSHA256}, nil
}

func (artifact ReviewArtifact) ID() ReviewID          { return artifact.id }
func (artifact ReviewArtifact) Outcomes() OutcomeAxes { return artifact.axes }
func (artifact ReviewArtifact) CreatedAt() time.Time  { return artifact.createdAt }
func (artifact ReviewArtifact) FileSHA256() string    { return artifact.fileSHA256 }
