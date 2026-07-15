package domain

import (
	"errors"
	"testing"
	"time"
)

func validIDs(t *testing.T) (SessionID, RunID, AttemptID, ReviewID) {
	t.Helper()
	session, err := ParseSessionID("s_" + testUUIDv7)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ParseRunID("r_" + testUUIDv7)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := ParseAttemptID("a_" + testUUIDv7)
	if err != nil {
		t.Fatal(err)
	}
	review, err := ParseReviewID(testUUIDv7)
	if err != nil {
		t.Fatal(err)
	}
	return session, run, attempt, review
}

func validTarget(t *testing.T) TargetIdentity {
	t.Helper()
	target, err := NewTargetIdentity(TargetIdentityInput{
		Kind:   TargetPatch,
		SHA256: "a962bf1a6f4e99c7fe9e0bcb553bbc748cbdfbddfb34f0b90610e33768ae6d17",
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func validRoleTasks(t *testing.T) []RoleTask {
	t.Helper()
	logic, err := NewRoleTask(RoleLogic, true, "provider-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	security, err := NewRoleTask(RoleSecurity, true, "provider-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	return []RoleTask{logic, security}
}

func roleTask(t *testing.T, role Role, required bool, primary string, fallback *string) RoleTask {
	t.Helper()
	task, err := NewRoleTask(role, required, primary, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func mustSessionID(t *testing.T, uuid string) SessionID {
	t.Helper()
	id, err := ParseSessionID("s_" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustRunID(t *testing.T, uuid string) RunID {
	t.Helper()
	id, err := ParseRunID("r_" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newReviewRun(t *testing.T, sessionUUID, runUUID string, roles []RoleTask) (Session, Run) {
	t.Helper()
	session, run, err := NewReviewSession(
		mustSessionID(t, sessionUUID),
		time.Unix(1, 0).UTC(),
		mustRunID(t, runUUID),
		validTarget(t),
		roles,
	)
	if err != nil {
		t.Fatal(err)
	}
	return session, run
}

func requireInvariant(t *testing.T, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, ErrInvariant) {
		t.Fatalf("error = %v, want ErrInvariant", err)
	}
}

func requireInvariantError(t *testing.T, err error, want string) {
	t.Helper()
	requireInvariant(t, err)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func startRun(t *testing.T, run *Run) {
	t.Helper()
	if err := run.Transition(RunRunning); err != nil {
		t.Fatal(err)
	}
}

func transitionRole(t *testing.T, run *Run, role Role, next RoleTaskState) {
	t.Helper()
	if err := run.TransitionRole(role, next); err != nil {
		t.Fatal(err)
	}
}

func succeedRole(t *testing.T, run *Run, role Role) {
	t.Helper()
	transitionRole(t, run, role, RoleTaskPrimaryQueued)
	transitionRole(t, run, role, RoleTaskPrimaryRunning)
	transitionRole(t, run, role, RoleTaskSucceeded)
}

func failPrimaryRole(t *testing.T, run *Run, role Role) {
	t.Helper()
	transitionRole(t, run, role, RoleTaskPrimaryQueued)
	transitionRole(t, run, role, RoleTaskPrimaryRunning)
	transitionRole(t, run, role, RoleTaskFailed)
}

func selectedRoleTask(t *testing.T, run Run, role Role) RoleTask {
	t.Helper()
	for _, task := range run.RoleTasks() {
		if task.Role() == role {
			return task
		}
	}
	t.Fatalf("selected role %q is missing", role)
	return RoleTask{}
}

func TestNewReviewSessionPairsRootRun(t *testing.T) {
	t.Parallel()

	sessionID, runID, _, _ := validIDs(t)
	session, root, err := NewReviewSession(sessionID, time.Unix(1, 0).UTC(), runID, validTarget(t), validRoleTasks(t))
	if err != nil {
		t.Fatal(err)
	}
	if session.ID() != sessionID || session.RootRunID() != runID {
		t.Fatalf("session pairing = %q/%q, want %q/%q", session.ID().String(), session.RootRunID().String(), sessionID.String(), runID.String())
	}
	if root.ID() != session.RootRunID() || root.SessionID() != session.ID() || root.Type() != RunTypeReview {
		t.Fatalf("root run = id %q session %q type %q", root.ID().String(), root.SessionID().String(), root.Type())
	}
	if _, ok := root.ParentRunID(); ok {
		t.Fatal("root run has parent provenance")
	}
	if _, ok := root.SourceRunID(); ok {
		t.Fatal("root run has source provenance")
	}
}

func TestNewChildRunDerivesImmutableProvenance(t *testing.T) {
	t.Parallel()

	session, parent := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	source, err := NewChildRun(
		mustRunID(t, "019f596a-cf81-7c67-b265-f37053d51ccf"),
		RunTypeFollowup,
		parent,
		parent,
		validTarget(t),
		validRoleTasks(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	child, err := NewChildRun(
		mustRunID(t, "019f596a-cf82-7c67-b265-f37053d51ccf"),
		RunTypeDelta,
		parent,
		source,
		validTarget(t),
		validRoleTasks(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedParent, expectedSource := parent.ID(), source.ID()
	parent.id = RunID{}
	source.id = RunID{}
	if got, ok := child.ParentRunID(); !ok || got != expectedParent {
		t.Fatalf("parent provenance = %q/%v, want %q/true", got.String(), ok, expectedParent.String())
	}
	if got, ok := child.SourceRunID(); !ok || got != expectedSource {
		t.Fatalf("source provenance = %q/%v, want %q/true", got.String(), ok, expectedSource.String())
	}
	if child.SessionID() != session.ID() {
		t.Fatalf("child session = %q, want %q", child.SessionID().String(), session.ID().String())
	}
}

func TestNewChildRunRejectsForgedLineageInputs(t *testing.T) {
	t.Parallel()

	_, parent := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	source, err := NewChildRun(
		mustRunID(t, "019f596a-cf81-7c67-b265-f37053d51ccf"),
		RunTypeFollowup,
		parent,
		parent,
		validTarget(t),
		validRoleTasks(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	childID := mustRunID(t, "019f596a-cf82-7c67-b265-f37053d51ccf")
	_, err = NewChildRun(childID, RunTypeReview, parent, source, validTarget(t), validRoleTasks(t))
	requireInvariantError(t, err, "child run: domain invariant violation: review runs must be constructed with NewReviewSession")

	_, err = NewChildRun(RunID{}, RunTypeDelta, parent, source, validTarget(t), validRoleTasks(t))
	requireInvariantError(t, err, "run: domain invariant violation: invalid run ID: run id: must start with \"r_\"")
	_, err = NewChildRun(childID, RunTypeDelta, Run{}, source, validTarget(t), validRoleTasks(t))
	requireInvariantError(t, err, "child run: domain invariant violation: invalid parent run ID: run id: must start with \"r_\"")
	_, err = NewChildRun(parent.ID(), RunTypeDelta, parent, source, validTarget(t), validRoleTasks(t))
	requireInvariantError(t, err, "child run: domain invariant violation: child ID cannot reference its parent or source")
	_, err = NewChildRun(source.ID(), RunTypeDelta, parent, source, validTarget(t), validRoleTasks(t))
	requireInvariantError(t, err, "child run: domain invariant violation: child ID cannot reference its parent or source")
}

func TestNewChildRunRejectsCrossSessionOwnership(t *testing.T) {
	t.Parallel()

	_, parent := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	_, source := newReviewRun(t, "019f596a-cf81-7c67-b265-f37053d51ccf", "019f596a-cf81-7c67-b265-f37053d51ccf", validRoleTasks(t))
	_, err := NewChildRun(
		mustRunID(t, "019f596a-cf82-7c67-b265-f37053d51ccf"),
		RunTypeFollowup,
		parent,
		source,
		validTarget(t),
		validRoleTasks(t),
	)
	requireInvariantError(t, err, "child run: domain invariant violation: parent and source must belong to the same session")
}

func TestRunCanonicalizesRoleSelectionAndDefendsCopies(t *testing.T) {
	t.Parallel()

	documentation := roleTask(t, RoleDocumentation, false, "provider-docs", nil)
	testingRole := roleTask(t, RoleTesting, false, "provider-tests", nil)
	roles := []RoleTask{documentation, validRoleTasks(t)[1], testingRole, validRoleTasks(t)[0]}
	_, run := newReviewRun(t, testUUIDv7, testUUIDv7, roles)
	want := []Role{RoleLogic, RoleSecurity, RoleDocumentation, RoleTesting}
	got := run.RoleTasks()
	if len(got) != len(want) {
		t.Fatalf("selected roles = %d, want %d", len(got), len(want))
	}
	for index, role := range want {
		if got[index].Role() != role {
			t.Fatalf("selected role %d = %q, want %q", index, got[index].Role(), role)
		}
	}
	roles[0] = RoleTask{}
	if got := run.RoleTasks()[0].Role(); got != RoleLogic {
		t.Fatalf("run retained caller role slice: first role = %q", got)
	}
	copyRoles := run.RoleTasks()
	copyRoles[0].state = RoleTaskPrimaryQueued
	if run.RoleTasks()[0].State() != RoleTaskPending {
		t.Fatal("run exposed mutable role slice")
	}
	err := run.TransitionRole(RoleLogic, RoleTaskPrimaryQueued)
	requireInvariantError(t, err, "run: domain invariant violation: role tasks can transition only while run is running")
	if got := selectedRoleTask(t, run, RoleLogic).State(); got != RoleTaskPending {
		t.Fatalf("role state after pending-run mutation = %q, want pending", got)
	}

	startRun(t, &run)
	transitionRole(t, &run, RoleLogic, RoleTaskPrimaryQueued)
	if err := run.TransitionRole(RoleMaintainability, RoleTaskPrimaryQueued); err == nil {
		t.Error("run transitioned an unselected role")
	}
}

func TestRunRejectsInvalidRoleSelections(t *testing.T) {
	t.Parallel()

	sessionID, runID, _, _ := validIDs(t)
	roles := validRoleTasks(t)
	duplicate := append(append([]RoleTask(nil), roles...), roles[0])
	_, _, err := NewReviewSession(sessionID, time.Unix(1, 0).UTC(), runID, validTarget(t), duplicate)
	requireInvariant(t, err)

	_, _, err = NewReviewSession(sessionID, time.Unix(1, 0).UTC(), runID, validTarget(t), validRoleTasks(t)[:1])
	requireInvariant(t, err)

	forgedFloor := validRoleTasks(t)
	forgedFloor[0].required = false
	_, _, err = NewReviewSession(sessionID, time.Unix(1, 0).UTC(), runID, validTarget(t), forgedFloor)
	requireInvariant(t, err)

	pretransitioned := validRoleTasks(t)
	pretransitioned[0].state = RoleTaskPrimaryQueued
	_, _, err = NewReviewSession(sessionID, time.Unix(1, 0).UTC(), runID, validTarget(t), pretransitioned)
	requireInvariant(t, err)
}

func TestRunCompletionRequiresSuccessfulRoles(t *testing.T) {
	t.Parallel()

	_, run := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	startRun(t, &run)
	err := run.Transition(RunCompleted)
	requireInvariantError(t, err, "run: domain invariant violation: completion requires every selected role to succeed")
	if run.State() != RunRunning {
		t.Fatalf("run state after rejected completion = %q, want running", run.State())
	}
	succeedRole(t, &run, RoleLogic)
	succeedRole(t, &run, RoleSecurity)
	if err := run.Transition(RunCompleted); err != nil {
		t.Fatal(err)
	}
}

func TestRunDegradedRequiresTerminalRequiredAndOptionalOutcomes(t *testing.T) {
	t.Parallel()

	roles := append(validRoleTasks(t), roleTask(t, RoleProduct, false, "provider-product", nil))
	_, run := newReviewRun(t, testUUIDv7, testUUIDv7, roles)
	startRun(t, &run)
	err := run.Transition(RunDegraded)
	requireInvariantError(t, err, "run: domain invariant violation: degradation requires every selected role to be terminal")
	if run.State() != RunRunning {
		t.Fatalf("run state after rejected degraded transition = %q, want running", run.State())
	}
	failPrimaryRole(t, &run, RoleLogic)
	succeedRole(t, &run, RoleSecurity)
	failPrimaryRole(t, &run, RoleProduct)
	err = run.Transition(RunDegraded)
	requireInvariantError(t, err, "run: domain invariant violation: degradation requires every required role to succeed")
	if run.State() != RunRunning {
		t.Fatalf("run state after required-role rejection = %q, want running", run.State())
	}

	_, allSucceeded := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	startRun(t, &allSucceeded)
	succeedRole(t, &allSucceeded, RoleLogic)
	succeedRole(t, &allSucceeded, RoleSecurity)
	err = allSucceeded.Transition(RunDegraded)
	requireInvariantError(t, err, "run: domain invariant violation: degradation requires an optional non-success result")
	if allSucceeded.State() != RunRunning {
		t.Fatalf("run state after optional-result rejection = %q, want running", allSucceeded.State())
	}

	_, degraded := newReviewRun(t, testUUIDv7, testUUIDv7, roles)
	startRun(t, &degraded)
	succeedRole(t, &degraded, RoleLogic)
	succeedRole(t, &degraded, RoleSecurity)
	failPrimaryRole(t, &degraded, RoleProduct)
	if err := degraded.Transition(RunDegraded); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalRunCannotMutateRoles(t *testing.T) {
	t.Parallel()

	_, run := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
	startRun(t, &run)
	succeedRole(t, &run, RoleLogic)
	succeedRole(t, &run, RoleSecurity)
	if err := run.Transition(RunCompleted); err != nil {
		t.Fatal(err)
	}
	err := run.TransitionRole(RoleLogic, RoleTaskFailed)
	requireInvariantError(t, err, "run: domain invariant violation: role tasks can transition only while run is running")
	if got := selectedRoleTask(t, run, RoleLogic).State(); got != RoleTaskSucceeded {
		t.Fatalf("role state after terminal mutation = %q, want succeeded", got)
	}
}

func TestRunQueueRoleFallback(t *testing.T) {
	t.Parallel()

	t.Run("absent fallback leaves state unchanged", func(t *testing.T) {
		_, run := newReviewRun(t, testUUIDv7, testUUIDv7, validRoleTasks(t))
		startRun(t, &run)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryQueued)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryRunning)
		err := run.QueueRoleFallback(RoleLogic, FailureProviderUnavailable)
		requireInvariantError(t, err, "role task: domain invariant violation: fallback provider is not configured")
		task := selectedRoleTask(t, run, RoleLogic)
		if task.State() != RoleTaskPrimaryRunning {
			t.Fatalf("state after absent fallback = %q, want primary_running", task.State())
		}
		if _, ok := task.PrimaryFailureClass(); ok {
			t.Fatal("absent fallback recorded a primary failure")
		}
	})

	t.Run("noneligible failure and generic fallback transitions are rejected", func(t *testing.T) {
		fallback := "provider-fallback"
		roles := validRoleTasks(t)
		roles[0] = roleTask(t, RoleLogic, true, "provider-a", &fallback)
		_, run := newReviewRun(t, testUUIDv7, testUUIDv7, roles)
		startRun(t, &run)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryQueued)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryRunning)

		err := run.TransitionRole(RoleLogic, RoleTaskFallbackQueued)
		requireInvariantError(t, err, "run: domain invariant violation: fallback queuing requires QueueRoleFallback")
		err = run.TransitionRole(RoleLogic, RoleTaskFallbackRunning)
		requireInvariantError(t, err, "role task: domain invariant violation: fallback progression requires a recorded eligible primary failure")
		err = run.QueueRoleFallback(RoleLogic, FailureSecurityPolicy)
		requireInvariantError(t, err, "role task: domain invariant violation: failure class \"security_policy_violation\" is not eligible for fallback")

		task := selectedRoleTask(t, run, RoleLogic)
		if task.State() != RoleTaskPrimaryRunning {
			t.Fatalf("state after rejected fallback requests = %q, want primary_running", task.State())
		}
		if _, ok := task.PrimaryFailureClass(); ok {
			t.Fatal("rejected fallback request recorded a primary failure")
		}
	})

	t.Run("eligible configured fallback records failure before progression", func(t *testing.T) {
		fallback := "provider-fallback"
		roles := validRoleTasks(t)
		roles[0] = roleTask(t, RoleLogic, true, "provider-a", &fallback)
		_, run := newReviewRun(t, testUUIDv7, testUUIDv7, roles)
		startRun(t, &run)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryQueued)
		transitionRole(t, &run, RoleLogic, RoleTaskPrimaryRunning)
		if err := run.QueueRoleFallback(RoleLogic, FailureProviderUnavailable); err != nil {
			t.Fatal(err)
		}
		task := selectedRoleTask(t, run, RoleLogic)
		if task.State() != RoleTaskFallbackQueued {
			t.Fatalf("queued fallback state = %q, want fallback_queued", task.State())
		}
		if class, ok := task.PrimaryFailureClass(); !ok || class != FailureProviderUnavailable {
			t.Fatalf("recorded primary failure = %q/%v, want %q/true", class, ok, FailureProviderUnavailable)
		}
		transitionRole(t, &run, RoleLogic, RoleTaskFallbackRunning)
		transitionRole(t, &run, RoleLogic, RoleTaskSucceeded)
	})
}

func TestAttemptInvocationOrderingAndCopies(t *testing.T) {
	t.Parallel()

	_, _, attemptID, _ := validIDs(t)
	initial, err := NewInvocation(1, InvocationInitial)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewAttempt(attemptID, "provider", initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationRunning); err == nil {
		t.Error("invocation transitioned while attempt was queued")
	}
	if err := attempt.Transition(AttemptRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(1, InvocationRunning); err == nil {
		t.Error("succeeded invocation transitioned again")
	}
	if err := attempt.Transition(AttemptValidating); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Transition(AttemptRepairing); err != nil {
		t.Fatal(err)
	}
	lower := lifecycleInvocation(t, 1, InvocationRepair)
	if err := attempt.AppendRepairInvocation(lower); err == nil {
		t.Error("lower invocation sequence accepted")
	}
	notRepair := lifecycleInvocation(t, 2, InvocationInitial)
	if err := attempt.AppendRepairInvocation(notRepair); err == nil {
		t.Error("initial invocation appended as repair")
	}
	repair, err := NewInvocation(2, InvocationRepair)
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.AppendRepairInvocation(repair); err != nil {
		t.Fatal(err)
	}
	duplicate := lifecycleInvocation(t, 3, InvocationRepair)
	if err := attempt.AppendRepairInvocation(duplicate); err == nil {
		t.Error("second repair invocation accepted")
	}
	if err := attempt.TransitionInvocation(1, InvocationRunning); err == nil {
		t.Error("initial invocation transitioned during repair")
	}
	if err := attempt.TransitionInvocation(2, InvocationRunning); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(2, InvocationSucceeded); err != nil {
		t.Fatal(err)
	}
	if err := attempt.TransitionInvocation(99, InvocationRunning); err == nil {
		t.Error("unknown invocation sequence transitioned")
	}
	if _, err := NewAttempt(attemptID, "provider", Invocation{}); err == nil {
		t.Error("attempt accepted malformed initial invocation")
	}
	pretransitioned := initial
	pretransitioned.state = InvocationRunning
	if _, err := NewAttempt(attemptID, "provider", pretransitioned); err == nil {
		t.Error("attempt accepted pre-transitioned initial invocation")
	}
	if _, err := NewAttempt(attemptID, " ", initial); err == nil {
		t.Error("attempt accepted blank provider")
	}
	var zero Attempt
	if err := zero.AppendRepairInvocation(repair); err == nil {
		t.Error("zero attempt accepted repair")
	}
	if err := zero.Transition(AttemptRunning); err == nil {
		t.Error("zero attempt transitioned")
	}

	copyInvocations := attempt.Invocations()
	copyInvocations[0].state = InvocationFailed
	if attempt.Invocations()[0].State() != InvocationSucceeded {
		t.Fatal("attempt exposed mutable invocation slice")
	}
}

func TestRunMutatorsRejectZeroAndNilReceivers(t *testing.T) {
	t.Parallel()

	actions := []struct {
		name   string
		action func(*Run) error
	}{
		{"transition", func(run *Run) error { return run.Transition(RunRunning) }},
		{"transition role", func(run *Run) error { return run.TransitionRole(RoleLogic, RoleTaskPrimaryQueued) }},
		{"queue fallback", func(run *Run) error { return run.QueueRoleFallback(RoleLogic, FailureTimeout) }},
	}
	for _, test := range actions {
		test := test
		t.Run("zero "+test.name, func(t *testing.T) {
			var run Run
			before := run
			requireInvariant(t, test.action(&run))
			if run.state != before.state || len(run.roles) != len(before.roles) {
				t.Fatalf("zero run mutated after rejected %s", test.name)
			}
		})
		t.Run("nil "+test.name, func(t *testing.T) {
			var run *Run
			requireInvariant(t, test.action(run))
		})
	}
}

func TestReviewArtifactRequiresFourValidAxes(t *testing.T) {
	t.Parallel()

	_, _, _, reviewID := validIDs(t)
	axes, err := ComputeOutcomeAxes(nil, validRequiredResults(), SeverityHigh, PublicationCommitted, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := NewReviewArtifact(reviewID, axes, time.Unix(2, 0).UTC(), "a962bf1a6f4e99c7fe9e0bcb553bbc748cbdfbddfb34f0b90610e33768ae6d17")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Outcomes().PublicationStatus() != PublicationCommitted {
		t.Fatal("review artifact lost publication axis")
	}
}
