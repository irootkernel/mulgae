package review

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCoordinatorScenarios(t *testing.T) {
	t.Run("distinct-providers-run-concurrently", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		entered := make(chan struct{}, len(assignments))
		release := make(chan struct{})
		var mu sync.Mutex
		active, maximum := 0, 0
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			mu.Lock()
			active++
			if active > maximum {
				maximum = active
			}
			mu.Unlock()
			entered <- struct{}{}
			<-release
			mu.Lock()
			active--
			mu.Unlock()
			return coordinatorSuccessOutcome(t, job)
		}}
		coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
		done := make(chan coordinatorTestExecution, 1)
		go func() {
			result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		for range assignments {
			<-entered
		}
		close(release)
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
		mu.Lock()
		gotMaximum := maximum
		mu.Unlock()
		if gotMaximum < 2 || execution.result.RunState() != domain.RunCompleted {
			t.Fatalf("maximum/run state = %d/%q, want concurrent completed execution", gotMaximum, execution.result.RunState())
		}
	})

	t.Run("repair-exhaustion-closes-the-role-on-its-own-provider", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var sequenceMu sync.Mutex
		var sequence []string
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			sequenceMu.Lock()
			sequence = append(sequence, job.Route().ProviderInstance()+"/"+string(job.Purpose()))
			sequenceMu.Unlock()
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		// One attempt carrying two invocations: the provider call and its one
		// repair. There is no second attempt, because there is no second provider.
		if len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 2 {
			t.Fatalf("logic summary did not repair in place: %#v", logic)
		}
		if logic.State() != domain.RoleTaskFailed {
			t.Fatalf("logic state = %q, want failed", logic.State())
		}
		attempt := logic.Attempts()[0]
		if attempt.FailureClass() != domain.FailureInvalidOutput ||
			attempt.ReasonCode() != string(AttemptConditionInvalidProviderOutput) {
			t.Fatalf("failed attempt lost terminal failure facts: %#v", attempt)
		}
		sequenceMu.Lock()
		gotSequence := append([]string(nil), sequence...)
		sequenceMu.Unlock()
		wantSequence := []string{"primary.logic/initial", "primary.logic/repair"}
		if !reflect.DeepEqual(gotSequence, wantSequence) {
			t.Fatalf("logic invocation order = %q, want %q", gotSequence, wantSequence)
		}
		// Every peer role kept its own provider and finished normally.
		for _, role := range domain.CoreRoleOrder() {
			if role == domain.RoleLogic {
				continue
			}
			if peer := coordinatorRoleByRole(t, result, role); peer.State() != domain.RoleTaskSucceeded {
				t.Fatalf("peer role %q = %q, want succeeded", role, peer.State())
			}
		}
		repairIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventRepairQueued, domain.RoleLogic)
		closeIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventWorkersCloseAuthorized, "")
		if repairIndex >= closeIndex {
			t.Fatalf("repair/close trace order = %d/%d", repairIndex, closeIndex)
		}
	})

	t.Run("repair-success-keeps-one-attempt", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationInitial {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidEvidenceClaim)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.Repaired() || len(logic.Attempts()) != 1 {
			t.Fatalf("logic repair = repaired:%t attempts:%d", logic.Repaired(), len(logic.Attempts()))
		}
	})

	t.Run("decoded-planless-validation-failure-fails-closed-without-invariant", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		invocations := 0
		var invocationMu sync.Mutex
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			invocationMu.Lock()
			invocations++
			invocationMu.Unlock()
			return coordinatorConditionOutcome(t, job, AttemptConditionSemanticContradiction)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if logic.State() != domain.RoleTaskFailed {
			t.Fatalf("decoded validation role = %#v", logic)
		}
		invocationMu.Lock()
		gotInvocations := invocations
		invocationMu.Unlock()
		// A contradiction is unrepairable, so the role stops after one call.
		if gotInvocations != 1 || len(logic.Attempts()) != 1 {
			t.Fatalf("logic invocations/attempts = %d/%d, want 1/1", gotInvocations, len(logic.Attempts()))
		}
		attempt := logic.Attempts()[0]
		if attempt.ReasonCode() != string(AttemptConditionSemanticContradiction) || attempt.FailureClass() != domain.FailureInvalidOutput {
			t.Fatalf("decoded validation classification = %#v", attempt)
		}
		if attempt.ReasonCode() == string(AttemptConditionInternalInvariant) {
			t.Fatalf("ordinary failure path reported internal invariant: %#v", attempt)
		}
	})

	t.Run("valid-request-changes-invokes-once", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var callsMu sync.Mutex
		logicCalls := 0
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			callsMu.Lock()
			logicCalls++
			callsMu.Unlock()
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "request changes",
				path:         "src/coordinator-request-changes.go",
				quote:        "request changes\n",
				targetBytes:  "request changes\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		if result.ProviderUnusable() || result.Outcomes().ContentVerdict() != domain.ContentRequestChanges {
			t.Fatalf("provider blamed/content = %t/%q", result.ProviderUnusable(), result.Outcomes().ContentVerdict())
		}
		callsMu.Lock()
		gotLogicCalls := logicCalls
		callsMu.Unlock()
		if gotLogicCalls != 1 {
			t.Fatalf("valid request-changes logic invocations = %d, want 1", gotLogicCalls)
		}
	})

	t.Run("security-condition-dominates-provider-failure", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic {
				return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
			}
			if job.Role() == domain.RoleSecurity {
				return coordinatorConditionOutcome(t, job, AttemptConditionSecurityViolation)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		security := coordinatorRoleByRole(t, result, domain.RoleSecurity)
		if result.RunState() != domain.RunCancelled ||
			security.ReasonCode() != string(AttemptConditionSecurityViolation) {
			t.Fatalf("run/security reason = %q/%q", result.RunState(), security.ReasonCode())
		}
		for _, event := range result.Trace() {
			if event.Kind() == CoordinatorEventRepairQueued {
				t.Fatalf("global security cancellation queued follow-up work: %#v", event)
			}
		}
	})

	t.Run("user-cancel-kills-and-closes", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		started := make(chan struct{}, len(assignments))
		runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
			started <- struct{}{}
			<-ctx.Done()
			return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
		}}
		coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan coordinatorTestExecution, 1)
		go func() {
			result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		for range assignments {
			<-started
		}
		cancel()
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
		if execution.result.RunState() != domain.RunCancelled {
			t.Fatalf("run state = %q, want %q", execution.result.RunState(), domain.RunCancelled)
		}
		for _, summary := range execution.result.RoleSummaries() {
			if summary.State() != domain.RoleTaskCancelled {
				t.Fatalf("role %q state = %q, want cancelled", summary.Role(), summary.State())
			}
		}
	})

	t.Run("timeout-closes-its-role-before-worker-shutdown", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic {
				return coordinatorConditionOutcome(t, job, AttemptConditionTimeout)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if logic.State() != domain.RoleTaskFailed || logic.FailureClass() != domain.FailureTimeout {
			t.Fatalf("timed-out role = state:%q class:%q", logic.State(), logic.FailureClass())
		}
		// A timeout is transient: it must not claim the provider is unusable.
		if logic.ProviderUnusable() {
			t.Fatal("a timeout was reported as an unusable provider")
		}
		terminalIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventRoleTerminal, domain.RoleLogic)
		closeIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventWorkersCloseAuthorized, "")
		if terminalIndex >= closeIndex {
			t.Fatalf("role closed after worker close authorization: %d/%d", terminalIndex, closeIndex)
		}
	})

	t.Run("random-completion-deterministic-aggregation", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		first := coordinatorRandomCompletionResult(t, assignments, receipt, domain.CoreRoleOrder())
		secondOrder := domain.CoreRoleOrder()
		for left, right := 0, len(secondOrder)-1; left < right; left, right = left+1, right-1 {
			secondOrder[left], secondOrder[right] = secondOrder[right], secondOrder[left]
		}
		second := coordinatorRandomCompletionResult(t, assignments, receipt, secondOrder)
		if !reflect.DeepEqual(first.Findings(), second.Findings()) || !reflect.DeepEqual(first.Trace(), second.Trace()) ||
			!reflect.DeepEqual(first.RoleSummaries(), second.RoleSummaries()) || first.Outcomes() != second.Outcomes() {
			t.Fatal("aggregation changed with invocation completion order")
		}
	})
}

func TestCoordinatorExecuteRunPreservesSuppliedRootIdentity(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	identityIDs := &coordinatorTestIDs{}
	sessionID, err := identityIDs.NewSessionID(now)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := identityIDs.NewRunID(now)
	if err != nil {
		t.Fatal(err)
	}
	tasks := make([]domain.RoleTask, 0, len(assignments))
	for _, assignment := range assignments {
		task, taskErr := domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.PrimaryRoute().ProviderInstance())
		if taskErr != nil {
			t.Fatal(taskErr)
		}
		tasks = append(tasks, task)
	}
	_, root, err := domain.NewReviewSession(sessionID, now, runID, coordinatorTestTarget(t), tasks)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	result, err := coordinatorTestCoordinator(t, runtime, len(assignments), receipt).ExecuteRun(
		context.Background(), &root, assignments, domain.SeverityHigh, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionID() != sessionID || result.RunID() != runID || root.ID() != runID || root.SessionID() != sessionID {
		t.Fatalf("root identity = %s/%s result=%s/%s", root.SessionID(), root.ID(), result.SessionID(), result.RunID())
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.jobs) != len(assignments) {
		t.Fatalf("job count = %d, want %d", len(runtime.jobs), len(assignments))
	}
	for _, job := range runtime.jobs {
		if job.SessionID() != sessionID || job.RunID() != runID {
			t.Fatalf("job identity = %s/%s, want %s/%s", job.SessionID(), job.RunID(), sessionID, runID)
		}
	}
}

// TestCoordinatorDiagnosticsPersistProviderFailureBeforeRoleTerminal proves a
// provider failure is durably recorded before the role closes, and that only
// deterministic failures additionally record the provider as unusable.
func TestCoordinatorDiagnosticsPersistProviderFailureBeforeRoleTerminal(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionProviderUnavailable,
		AttemptConditionProviderSpawnFailed,
		AttemptConditionTimeout,
		AttemptConditionProviderTimeout,
		AttemptConditionAuthentication,
		AttemptConditionProviderPermissionDenied,
		AttemptConditionQuota,
		AttemptConditionRateLimit,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorSuccessOutcome(t, job)
			}}
			root, request := coordinatorDiagnosticRoot(t, assignments)
			base, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics := &coordinatorDiagnosticSink{RuntimeDiagnosticSink: base}
			coordinator, err := NewCoordinatorWithRuntimeDiagnostics(
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, len(assignments), receipt, diagnostics,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil); err != nil {
				t.Fatal(err)
			}
			want := []domain.RuntimeDiagnosticEventCode{
				domain.DiagnosticAttemptFailed,
				domain.DiagnosticRoleExhausted,
			}
			position := 0
			for _, event := range diagnostics.events {
				if position < len(want) && event == want[position] {
					position++
				}
			}
			if position != len(want) {
				t.Fatalf("%s diagnostic order = %v, missing suffix %v", condition, diagnostics.events, want[position:])
			}
			// Deterministic provider failures must additionally record that the
			// provider itself is unusable, so the operator knows to fix it.
			deterministic := condition != AttemptConditionProviderUnavailable &&
				condition != AttemptConditionRateLimit &&
				condition != AttemptConditionTimeout &&
				condition != AttemptConditionProviderTimeout
			quarantined := false
			for _, event := range diagnostics.events {
				quarantined = quarantined || event == domain.DiagnosticProviderQuarantined
			}
			if quarantined != deterministic {
				t.Fatalf("%s provider_quarantined = %t, want %t", condition, quarantined, deterministic)
			}
		})
	}
}

// TestCoordinatorProviderFailuresRemainTypedAndActionable proves a failed role
// keeps the provider's own classification all the way to the summary, so the
// report can name the real reason instead of a generic failure.
func TestCoordinatorProviderFailuresRemainTypedAndActionable(t *testing.T) {
	tests := []AttemptCondition{
		AttemptConditionProviderPermissionDenied,
		AttemptConditionAuthentication,
		AttemptConditionProviderSpawnFailed,
		AttemptConditionInvalidProviderOutput,
		AttemptConditionProviderTimeout,
		AttemptConditionCancelled,
		AttemptConditionConfigurationViolation,
	}
	for _, failureCondition := range tests {
		t.Run(string(failureCondition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			fallbackCalls := 0
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				fallbackCalls++
				return coordinatorConditionOutcome(t, job, failureCondition)
			}}
			result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if fallbackCalls == 0 || len(logic.Attempts()) != 1 {
				t.Fatalf("role execution = calls:%d summary:%#v", fallbackCalls, logic)
			}
			attempt := logic.Attempts()[0]
			if attempt.ReasonCode() == string(AttemptConditionInternalInvariant) || logic.ReasonCode() == string(AttemptConditionInternalInvariant) {
				t.Fatalf("ordinary provider failure collapsed to invariant: %#v", logic)
			}
			// An invalid output is repaired once on the same provider; every other
			// condition closes the role after a single call. Either way the
			// operator sees the provider's own typed reason, not a substitute.
			if failureCondition == AttemptConditionInvalidProviderOutput {
				if fallbackCalls != 2 {
					t.Fatalf("invalid output repair exhaustion = calls:%d", fallbackCalls)
				}
			} else if fallbackCalls != 1 {
				t.Fatalf("%q calls = %d, want 1", failureCondition, fallbackCalls)
			}
			if attempt.ReasonCode() != string(failureCondition) {
				t.Fatalf("failure reason = %q, want %q", attempt.ReasonCode(), failureCondition)
			}
		})
	}
}

func TestCoordinatorDiagnosticsPersistUnrepairableFailureBeforeRoleTerminal(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionUnrepairableProviderOutput,
		AttemptConditionUnrepairableEvidence,
		AttemptConditionSemanticContradiction,
		AttemptConditionConfigurationViolation,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorSuccessOutcome(t, job)
			}}
			root, request := coordinatorDiagnosticRoot(t, assignments)
			base, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics := &coordinatorDiagnosticSink{RuntimeDiagnosticSink: base}
			coordinator, err := NewCoordinatorWithRuntimeDiagnostics(
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, len(assignments), receipt, diagnostics,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil); err != nil {
				t.Fatal(err)
			}
			failureIndex, terminalIndex, reductionIndex := -1, -1, -1
			for index, input := range diagnostics.inputs {
				switch input.Event {
				case domain.DiagnosticAttemptFailed:
					if input.Role == domain.RoleLogic && input.Failure == string(condition) && failureIndex < 0 {
						failureIndex = index
					}
				case domain.DiagnosticRoleExhausted:
					if input.Role == domain.RoleLogic && input.Failure == string(condition) && terminalIndex < 0 {
						terminalIndex = index
					}
				case domain.DiagnosticReductionStarted:
					if reductionIndex < 0 {
						reductionIndex = index
					}
				}
			}
			if failureIndex < 0 || terminalIndex <= failureIndex || reductionIndex <= terminalIndex {
				t.Fatalf("%s terminal diagnostic chronology = %#v", condition, diagnostics.inputs)
			}
		})
	}
}

func TestCoordinatorDiagnosticsReportRepairLifecycle(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationInitial {
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	root, request := coordinatorDiagnosticRoot(t, assignments)
	base, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := &coordinatorDiagnosticSink{RuntimeDiagnosticSink: base}
	coordinator, err := NewCoordinatorWithRuntimeDiagnostics(
		coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, len(assignments), receipt, diagnostics,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil); err != nil {
		t.Fatal(err)
	}
	want := []domain.RuntimeDiagnosticEventCode{
		domain.DiagnosticRepairScheduled,
		domain.DiagnosticRepairStarted,
		domain.DiagnosticRepairCompleted,
	}
	position := 0
	for _, event := range diagnostics.events {
		if position < len(want) && event == want[position] {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("repair diagnostic order = %v, missing %v", diagnostics.events, want[position:])
	}
}

func TestCoordinatorDiagnosticFailureStopsBeforeFollowUpScheduling(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	root, request := coordinatorDiagnosticRoot(t, assignments)
	base, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := &coordinatorDiagnosticSink{RuntimeDiagnosticSink: base, failOn: domain.DiagnosticAttemptFailed}
	coordinator, err := NewCoordinatorWithRuntimeDiagnostics(
		coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, len(assignments), receipt, diagnostics,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("diagnostic failure = %v, want artifact failure", err)
	}
	for _, job := range runtime.jobs {
		if job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationRepair {
			t.Fatal("follow-up work was scheduled after diagnostic persistence failure")
		}
	}
}

// TestCoordinatorDiagnosticsPersistInitiatingCauseBeforePeerCancellation proves
// the initiating failure is durably recorded before any peer role is cancelled,
// so the runtime log always explains why the run stopped.
func TestCoordinatorDiagnosticsPersistInitiatingCauseBeforePeerCancellation(t *testing.T) {
	for _, test := range []struct {
		condition AttemptCondition
		state     domain.RunState
	}{
		{condition: AttemptConditionSecurityViolation, state: domain.RunCancelled},
		{condition: AttemptConditionMutationViolation, state: domain.RunCancelled},
		{condition: AttemptConditionCancelled, state: domain.RunCancelled},
		{condition: AttemptConditionArtifactFailure, state: domain.RunFailed},
		{condition: AttemptConditionInternalInvariant, state: domain.RunFailed},
	} {
		t.Run(string(test.condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, test.condition)
				}
				<-ctx.Done()
				return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
			}}
			root, request := coordinatorDiagnosticRoot(t, assignments)
			base, err := ports.NewInMemoryRuntimeDiagnosticSink(request)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics := &coordinatorDiagnosticSink{RuntimeDiagnosticSink: base}
			coordinator, err := NewCoordinatorWithRuntimeDiagnostics(
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, len(assignments), receipt, diagnostics,
			)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.RunState() != test.state {
				t.Fatalf("run state = %q, want %q", result.RunState(), test.state)
			}
			failureIndex, cancellationIndex := -1, -1
			for index, input := range diagnostics.inputs {
				switch input.Event {
				case domain.DiagnosticAttemptFailed:
					if input.Failure == string(test.condition) && failureIndex < 0 {
						failureIndex = index
					}
				case domain.DiagnosticRolePathCancelled:
					if cancellationIndex < 0 {
						cancellationIndex = index
					}
				}
			}
			if failureIndex < 0 || cancellationIndex >= 0 && cancellationIndex <= failureIndex {
				t.Fatalf("%s diagnostic chronology = %#v", test.condition, diagnostics.inputs)
			}
		})
	}
}

func TestCoordinatorProtectedConditionsNeverScheduleFollowup(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionLoginRequired,
		AttemptConditionSecurityViolation,
		AttemptConditionMutationViolation,
		AttemptConditionConfigurationViolation,
		AttemptConditionArtifactFailure,
		AttemptConditionCancelled,
		AttemptConditionInternalInvariant,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorSuccessOutcome(t, job)
			}}
			result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			for _, event := range result.Trace() {
				if event.Kind() == CoordinatorEventRepairQueued {
					t.Fatalf("%q scheduled follow-up event: %#v", condition, event)
				}
			}
			// login_required fails only its own role. Provider families
			// authenticate separately, so it says nothing about the peers.
			wantState := domain.RunFailed
			if condition == AttemptConditionSecurityViolation ||
				condition == AttemptConditionMutationViolation ||
				condition == AttemptConditionCancelled {
				wantState = domain.RunCancelled
			}
			if result.RunState() != wantState || logic.ReasonCode() != string(condition) {
				t.Fatalf("%q result = run:%q logic:%#v, want run %q", condition, result.RunState(), logic, wantState)
			}
		})
	}
}

func TestCoordinatorTerminalTraceClosesRun(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
	for _, role := range result.RoleSummaries() {
		for _, attempt := range role.Attempts() {
			if attempt.State() != domain.AttemptSucceeded {
				t.Fatalf("attempt %q is not terminal: %q", attempt.ID().String(), attempt.State())
			}
			for _, invocation := range attempt.Invocations() {
				if invocation.State() != domain.InvocationSucceeded {
					t.Fatalf("invocation %d is not terminal: %q", invocation.Sequence(), invocation.State())
				}
			}
		}
	}
	trace := result.Trace()
	if len(trace) == 0 || trace[len(trace)-1].Kind() != CoordinatorEventRunTerminal {
		t.Fatalf("terminal trace does not end at run terminal: %#v", trace)
	}
	for index, event := range trace {
		if err := event.validate(); err != nil {
			t.Fatalf("trace event %d is invalid: %v", index, err)
		}
		if event.Ordinal() != uint64(index+1) {
			t.Fatalf("trace ordinal at index %d = %d, want %d", index, event.Ordinal(), index+1)
		}
		if event.Kind() == CoordinatorEventRunTerminal && index != len(trace)-1 {
			t.Fatalf("trace contains work after terminal event at index %d: %#v", index, trace[index+1:])
		}
	}
}

func TestCoordinatorMaxActiveLanes(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	entered := make(chan struct{}, len(assignments))
	release := make(chan struct{})
	var mu sync.Mutex
	active, maximum := 0, 0
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, 2, receipt)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	<-entered
	<-entered
	close(release)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	mu.Lock()
	gotMaximum := maximum
	mu.Unlock()
	if gotMaximum != 2 {
		t.Fatalf("maximum active workers = %d, want 2", gotMaximum)
	}
}

func TestIntegrationCoordinatorSixDistinctProvidersEnterBarrier(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	if len(assignments) != 6 {
		t.Fatalf("assignment count = %d, want 6", len(assignments))
	}
	entered := make(chan InvocationJob, len(assignments))
	release := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- job
		<-release
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, 6, receipt)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()

	roles := make(map[domain.Role]struct{}, 6)
	providers := make(map[string]struct{}, 6)
	for range assignments {
		select {
		case job := <-entered:
			roles[job.Role()] = struct{}{}
			providers[job.Route().ProviderInstance()] = struct{}{}
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("six primary invocations did not all enter the barrier")
		}
	}
	if len(roles) != 6 || len(providers) != 6 {
		close(release)
		t.Fatalf("barrier entrants = roles:%d providers:%d, want 6/6", len(roles), len(providers))
	}
	close(release)
	execution := <-done
	if execution.err != nil || execution.result.RunState() != domain.RunCompleted {
		t.Fatalf("six-role execution = state:%q error:%v", execution.result.RunState(), execution.err)
	}
}

// TestIntegrationCoordinatorProviderFailureDoesNotSerializeOrCancelPeerInvocations is
// the load-bearing guarantee of one-provider-per-role: provider families
// authenticate and meter independently, so one family being unusable must leave
// every role on the other families running and reported normally. login_required
// is the sharpest case, because it used to cancel the whole run.
func TestIntegrationCoordinatorProviderFailureDoesNotSerializeOrCancelPeerInvocations(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionLoginRequired,
		AttemptConditionAuthentication,
		AttemptConditionQuota,
		AttemptConditionProviderUnavailable,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			entered := make(chan InvocationJob, len(assignments))
			release := make(chan struct{})
			var mu sync.Mutex
			active, maximum := 0, 0
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				mu.Lock()
				active++
				if active > maximum {
					maximum = active
				}
				mu.Unlock()
				defer func() {
					mu.Lock()
					active--
					mu.Unlock()
				}()

				entered <- job
				<-release
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorSuccessOutcome(t, job)
			}}
			coordinator := coordinatorTestCoordinator(t, runtime, 6, receipt)
			done := make(chan coordinatorTestExecution, 1)
			go func() {
				result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
				done <- coordinatorTestExecution{result: result, err: err}
			}()
			for range assignments {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					close(release)
					t.Fatal("peer invocations did not all enter concurrently")
				}
			}
			close(release)
			mu.Lock()
			gotMaximum := maximum
			mu.Unlock()
			if gotMaximum != 6 {
				t.Fatalf("wave maximum concurrency = %d, want 6", gotMaximum)
			}

			execution := <-done
			if execution.err != nil {
				t.Fatal(execution.err)
			}
			logic := coordinatorRoleByRole(t, execution.result, domain.RoleLogic)
			if logic.State() != domain.RoleTaskFailed || logic.ReasonCode() != string(condition) {
				t.Fatalf("logic = state:%q reason:%q, want failed/%q", logic.State(), logic.ReasonCode(), condition)
			}
			// Only the role on the failing provider is affected.
			for _, role := range execution.result.RoleSummaries() {
				if role.Role() == domain.RoleLogic {
					continue
				}
				if role.State() != domain.RoleTaskSucceeded {
					t.Fatalf("peer role %q was serialized or cancelled by a %q on another provider: %#v", role.Role(), condition, role)
				}
			}
			// The run is reported as failed, not cancelled: the peers' work stands.
			if execution.result.RunState() != domain.RunFailed {
				t.Fatalf("run state = %q, want failed", execution.result.RunState())
			}
			// Transient unavailability consumes the one same-provider retry slot;
			// deterministic failures still make exactly one call.
			runtime.mu.Lock()
			invocations := len(runtime.jobs)
			runtime.mu.Unlock()
			wantInvocations := len(assignments)
			if condition == AttemptConditionProviderUnavailable {
				wantInvocations++
			}
			if invocations != wantInvocations {
				t.Fatalf("invocations = %d, want %d", invocations, wantInvocations)
			}
			if execution.result.ProviderUnusable() != (condition != AttemptConditionProviderUnavailable) {
				t.Fatalf("%q provider unusable = %t", condition, execution.result.ProviderUnusable())
			}
		})
	}
}

func TestCoordinatorRetriesTransientFailureOnceOnSameRoute(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	var logicJobs []InvocationJob
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		logicJobs = append(logicJobs, job)
		if len(logicJobs) == 1 {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderTurnFailed)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if logic.State() != domain.RoleTaskSucceeded || logic.Repaired() || len(logicJobs) != 2 {
		t.Fatalf("logic retry result=%#v jobs=%d", logic, len(logicJobs))
	}
	first, second := logicJobs[0], logicJobs[1]
	if first.Purpose() != domain.InvocationInitial || second.Purpose() != domain.InvocationRetry ||
		first.AttemptID() != second.AttemptID() || first.Route().ProviderInstance() != second.Route().ProviderInstance() ||
		first.Target() != second.Target() {
		t.Fatalf("retry identity drift: first=%#v second=%#v", first, second)
	}
	invocations := logic.Attempts()[0].Invocations()
	if len(invocations) != 2 || invocations[0].State() != domain.InvocationFailed || invocations[1].State() != domain.InvocationSucceeded {
		t.Fatalf("retry lifecycle=%#v", invocations)
	}
}

func TestCoordinatorResultDefensiveCopies(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        string(job.Role()),
			path:         "src/coordinator-" + string(job.Role()) + ".go",
			quote:        string(job.Role()) + "\n",
			targetBytes:  string(job.Role()) + "\n",
			availability: evidence.ImmutableTargetAvailable,
		})
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, 6)
	findings := result.Findings()
	roles := result.RoleSummaries()
	trace := result.Trace()
	evidenceGroups := result.Evidence()
	findings[0] = domain.Finding{}
	trace[0] = CoordinatorTraceEvent{}
	if len(roles) == 0 || len(roles[0].attempts) == 0 || len(roles[0].attempts[0].invocations) == 0 {
		t.Fatal("coordinator result did not contain nested attempt summaries")
	}
	roles[0].attempts[0].invocations[0] = CoordinatorInvocationSummary{}
	roles[0] = CoordinatorRoleSummary{}
	if len(evidenceGroups) == 0 || len(evidenceGroups[0].Receipts()) == 0 {
		t.Fatal("coordinator result did not contain verifier evidence")
	}
	receipts := evidenceGroups[0].Receipts()
	evidenceGroups[0] = VerifiedFindingEvidence{}
	receipts[0] = evidence.CurrentReceipt{}
	if len(result.Findings()) != len(assignments) || result.RoleSummaries()[0].Role() == "" ||
		len(result.RoleSummaries()[0].Attempts()) == 0 ||
		len(result.RoleSummaries()[0].Attempts()[0].Invocations()) == 0 ||
		result.RoleSummaries()[0].Attempts()[0].Invocations()[0].Sequence() == 0 ||
		result.Trace()[0].Kind() == "" || result.Evidence()[0].FindingID() != result.Findings()[0].ID() ||
		result.Evidence()[0].Receipts()[0].Status() != evidence.ReceiptVerified {
		t.Fatal("coordinator result leaked a mutable slice")
	}
}
func TestIntegrationCoordinatorEvidencePolicy(t *testing.T) {
	t.Run("verified high is accepted", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "verified high",
				path:         "src/coordinator-verified-high.go",
				quote:        "verified\n",
				targetBytes:  "verified\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
		if len(result.Findings()) != 1 || result.Findings()[0].EvidenceState() != domain.EvidenceVerified ||
			len(result.Evidence()) != 1 || result.Evidence()[0].FindingID() != result.Findings()[0].ID() ||
			coordinatorRoleByRole(t, result, domain.RoleLogic).ProviderUnusable() {
			t.Fatalf("verified high result = findings:%#v evidence:%#v role:%#v",
				result.Findings(), result.Evidence(), coordinatorRoleByRole(t, result, domain.RoleLogic))
		}
	})

	for _, test := range []struct {
		name         string
		availability evidence.ImmutableTargetAvailability
		targetBytes  string
		quote        string
	}{
		{
			name:         "stale",
			availability: evidence.ImmutableTargetStale,
			quote:        "stale\n",
		},
		{
			name:         "quote mismatch",
			availability: evidence.ImmutableTargetAvailable,
			targetBytes:  "actual\n",
			quote:        "expected\n",
		},
		{
			name:         "unavailable",
			availability: evidence.ImmutableTargetUnavailable,
			quote:        "unavailable\n",
		},
	} {
		t.Run("required high "+test.name+" repairs then exhausts fallback", func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
					severity:     domain.SeverityHigh,
					title:        "unverified " + test.name,
					path:         "src/coordinator-" + test.name + ".go",
					quote:        test.quote,
					targetBytes:  test.targetBytes,
					availability: test.availability,
				})
			}}
			result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if !logic.Required() || logic.State() != domain.RoleTaskFailed ||
				logic.ReasonCode() != string(AttemptConditionInvalidEvidenceClaim) ||
				len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 2 ||
				len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
				t.Fatalf("unaccepted high evidence result = role:%#v findings:%#v evidence:%#v",
					logic, result.Findings(), result.Evidence())
			}
		})
	}

	t.Run("default policy accepts unverified low with exact state", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityLow,
				title:        "unverified low",
				path:         "src/coordinator-unverified-low.go",
				quote:        "unavailable\n",
				availability: evidence.ImmutableTargetUnavailable,
			})
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
		if len(result.Findings()) != 1 || result.Findings()[0].EvidenceState() != domain.EvidenceUnverified ||
			len(result.Evidence()) != 1 || result.Evidence()[0].FindingID() != result.Findings()[0].ID() ||
			result.Outcomes().CoverageStatus() != domain.CoverageDegraded ||
			result.Outcomes().CIDecision() != domain.CIFail ||
			!coordinatorRoleByRole(t, result, domain.RoleLogic).Degraded() {
			t.Fatalf("default low evidence result = findings:%#v evidence:%#v axes:%#v",
				result.Findings(), result.Evidence(), result.Outcomes())
		}
	})
	t.Run("optional unverified evidence degrades coverage", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleMaintainability {
				return coordinatorSuccessOutcome(t, job)
			}
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityLow,
				title:        "optional unverified low",
				path:         "src/coordinator-optional-unverified-low.go",
				quote:        "unavailable\n",
				availability: evidence.ImmutableTargetUnavailable,
			})
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
		maintainability := coordinatorRoleByRole(t, result, domain.RoleMaintainability)
		if result.RunState() != domain.RunCompleted ||
			!maintainability.Valid() ||
			!maintainability.Degraded() ||
			result.Outcomes().CoverageStatus() != domain.CoverageDegraded ||
			result.Outcomes().CIDecision() != domain.CIFail {
			t.Fatalf("optional unverified evidence = run:%q role:%#v axes:%#v",
				result.RunState(), maintainability, result.Outcomes())
		}
	})

	for _, severity := range []domain.Severity{domain.SeverityMedium, domain.SeverityLow} {
		t.Run("custom policy requires "+string(severity), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			policy, err := NewEvidencePolicy([]domain.Severity{
				domain.SeverityLow,
				domain.SeverityMedium,
				domain.SeverityHigh,
				domain.SeverityCritical,
				domain.SeverityBlocker,
			})
			if err != nil {
				t.Fatal(err)
			}
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
					severity:     severity,
					title:        "custom " + string(severity),
					path:         "src/coordinator-custom-" + string(severity) + ".go",
					quote:        "unavailable\n",
					availability: evidence.ImmutableTargetUnavailable,
				})
			}}
			coordinator, err := NewCoordinatorWithEvidencePolicy(
				coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
				&coordinatorTestIDs{},
				runtime,
				len(assignments),
				receipt,
				policy,
			)
			if err != nil {
				t.Fatal(err)
			}
			policy.required[0] = domain.SeverityInfo
			result, err := coordinator.Execute(
				context.Background(),
				coordinatorTestTarget(t),
				assignments,
				"",
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if logic.State() != domain.RoleTaskFailed || logic.ReasonCode() != string(AttemptConditionInvalidEvidenceClaim) ||
				len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 2 ||
				len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
				t.Fatalf("custom policy result = role:%#v findings:%#v evidence:%#v",
					logic, result.Findings(), result.Evidence())
			}
		})
	}
}

func TestCoordinatorEvidenceInvariantFailsClosed(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		outcome := coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "malformed proof",
			path:         "src/coordinator-malformed-proof.go",
			quote:        "proof\n",
			targetBytes:  "proof\n",
			availability: evidence.ImmutableTargetAvailable,
		})
		outcome.output.evidence[0].findingID = "F002"
		return outcome
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if logic.State() != domain.RoleTaskFailed || logic.FailureClass() != domain.FailureInternal ||
		logic.ReasonCode() != string(AttemptConditionInternalInvariant) || logic.ProviderUnusable() ||
		len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 1 ||
		len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
		t.Fatalf("reduction invariant result = role:%#v findings:%#v evidence:%#v",
			logic, result.Findings(), result.Evidence())
	}
}
func TestCoordinatorEvidenceSubstitutionsRejectWithoutAcceptance(t *testing.T) {
	for _, substitution := range []string{
		"two-review-same-F001-swap",
		"different-run-target",
		"path-mismatch",
		"range-mismatch",
		"quote-mismatch",
	} {
		t.Run(substitution, func(t *testing.T) {
			wantReason := AttemptConditionInternalInvariant
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				return coordinatorSubstitutedEvidenceOutcome(job, substitution)
			}}

			result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if logic.State() != domain.RoleTaskFailed ||
				logic.ReasonCode() != string(wantReason) ||
				len(result.Findings()) != 0 ||
				len(result.Evidence()) != 0 {
				t.Fatalf("substitution %q accepted evidence: role:%#v findings:%#v evidence:%#v",
					substitution, logic, result.Findings(), result.Evidence())
			}
		})
	}
}
func TestCoordinatorVerifierOwnedTargetMismatchForbidsRepairAndFallback(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			return coordinatorSubstitutedEvidenceOutcome(job, "different-run-target")
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if logic.State() != domain.RoleTaskFailed ||
		logic.ReasonCode() != string(AttemptConditionInternalInvariant) ||
		logic.ProviderUnusable() ||
		len(logic.Attempts()) != 1 ||
		len(logic.Attempts()[0].Invocations()) != 1 ||
		len(result.Findings()) != 0 ||
		len(result.Evidence()) != 0 {
		t.Fatalf("verifier-owned target mismatch escaped fail-closed handling: role:%#v findings:%#v evidence:%#v",
			logic, result.Findings(), result.Evidence())
	}
}

func TestCoordinatorEvidenceCancellationPreventsAcceptance(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		outcome := coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "cancelled verification",
			path:         "src/coordinator-cancelled-verification.go",
			quote:        "verified\n",
			targetBytes:  "verified\n",
			availability: evidence.ImmutableTargetAvailable,
		})
		cancel()
		return outcome
	}}
	result, err := coordinatorTestCoordinator(t, runtime, 1, receipt).Execute(
		ctx,
		coordinatorTestTarget(t),
		assignments,
		"",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if result.RunState() != domain.RunCancelled || logic.State() != domain.RoleTaskCancelled ||
		len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
		t.Fatalf("cancelled evidence result = run:%q role:%#v findings:%#v evidence:%#v",
			result.RunState(), logic, result.Findings(), result.Evidence())
	}
}

func TestCoordinatorFinalEvidenceReIDPreservesBoundProof(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		switch job.Role() {
		case domain.RoleLogic:
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "logic receipt",
				path:         "src/coordinator-logic-receipt.go",
				quote:        "logic\n",
				targetBytes:  "logic\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		case domain.RoleSecurity:
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityCritical,
				title:        "security receipt",
				path:         "src/coordinator-security-receipt.go",
				quote:        "security\n",
				targetBytes:  "security\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		default:
			return coordinatorSuccessOutcome(t, job)
		}
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	findings := result.Findings()
	groups := result.Evidence()
	if len(findings) != 2 || len(groups) != 2 ||
		findings[0].Role() != domain.RoleSecurity || findings[0].ID() != groups[0].FindingID() ||
		findings[1].Role() != domain.RoleLogic || findings[1].ID() != groups[1].FindingID() ||
		groups[0].findingProof().ID() != "F001" || groups[1].findingProof().ID() != "F001" ||
		!groups[0].matchesFinding(findings[0]) || !groups[1].matchesFinding(findings[1]) ||
		groups[1].validationProof.FindingID() != "F001" ||
		groups[1].Receipts()[0].Claim().TargetSHA256() != "sha256:"+coordinatorTestTargetSHA256 ||
		groups[0].Receipts()[0].Claim().Path().String() != "src/coordinator-security-receipt.go" ||
		groups[1].Receipts()[0].Claim().Path().String() != "src/coordinator-logic-receipt.go" {
		t.Fatalf("final finding/evidence association = findings:%#v groups:%#v", findings, groups)
	}
}
func TestCoordinatorRoutesReceiptLimitsAndCopiesCIPolicy(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	entered := make(chan struct{}, len(assignments))
	release := make(chan struct{})
	var mu sync.Mutex
	var jobs []InvocationJob
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		mu.Lock()
		jobs = append(jobs, job)
		mu.Unlock()
		entered <- struct{}{}
		<-release
		if job.Role() == domain.RoleLogic {
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "request changes",
				path:         "src/coordinator-request-changes.go",
				quote:        "request changes\n",
				targetBytes:  "request changes\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	policy := &domain.CIPolicy{RequestChangesFails: false, DegradedReviewFails: false, IncompleteReviewFails: false}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	target := coordinatorTestTarget(t)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), target, assignments, "", policy)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	for range assignments {
		<-entered
	}
	policy.RequestChangesFails = true
	close(release)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	if execution.result.Outcomes().CIDecision() != domain.CIPass {
		t.Fatalf("caller policy mutation changed CI decision to %q", execution.result.Outcomes().CIDecision())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(jobs) != len(assignments) {
		t.Fatalf("invocation count = %d, want %d", len(jobs), len(assignments))
	}
	for _, job := range jobs {
		if job.Target() != target {
			t.Fatalf("job %d target = %#v, want %#v", job.Ordinal(), job.Target(), target)
		}
		limits := job.Limits()
		if limits.Timeout() != time.Second {
			t.Fatalf("job %d limits = %#v, want primary receipt limits", job.Ordinal(), limits)
		}
	}
}

func TestCoordinatorRejectsPrecancelledContextBeforeIssuingIDs(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	ids := &coordinatorCountingIDs{}
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		t.Fatalf("pre-cancelled coordinator invoked job %d", job.Ordinal())
		return AttemptOutcome{}
	}}
	coordinator, err := NewCoordinator(
		coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		ids,
		runtime,
		len(assignments),
		receipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled coordinator error = %v, want context cancellation", err)
	}
	if calls := ids.Calls(); calls != 0 {
		t.Fatalf("pre-cancelled coordinator issued %d IDs", calls)
	}
}

func TestIndependentCoordinatorsOverlapByProviderIdentity(t *testing.T) {
	t.Run("disjoint providers overlap", func(t *testing.T) {
		firstAssignments, firstReceipt := coordinatorTestPlanInNamespace(t, "first.")
		secondAssignments, secondReceipt := coordinatorTestPlanInNamespace(t, "second.")
		entered := make(chan string, len(firstAssignments)+len(secondAssignments))
		release := make(chan struct{})
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			entered <- job.Route().ProviderInstance()
			<-release
			return coordinatorSuccessOutcome(t, job)
		}}
		processLimit := len(firstAssignments) + len(secondAssignments)
		first := coordinatorTestCoordinator(t, runtime, processLimit, firstReceipt)
		second := coordinatorTestCoordinator(t, runtime, processLimit, secondReceipt)
		done := make(chan coordinatorTestExecution, 2)
		go func() {
			result, err := first.Execute(context.Background(), coordinatorTestTarget(t), firstAssignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		go func() {
			result, err := second.Execute(context.Background(), coordinatorTestTarget(t), secondAssignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()

		seen := make(map[string]bool, 2)
		deadlockGuard := time.NewTimer(time.Second)
		defer deadlockGuard.Stop()
		for len(seen) < 2 {
			select {
			case provider := <-entered:
				switch {
				case strings.HasPrefix(provider, "first."):
					seen["first"] = true
				case strings.HasPrefix(provider, "second."):
					seen["second"] = true
				default:
					close(release)
					t.Fatalf("unexpected provider namespace %q", provider)
				}
			case <-deadlockGuard.C:
				close(release)
				t.Fatal("disjoint-provider coordinators did not overlap")
			}
		}
		close(release)
		for range 2 {
			execution := <-done
			if execution.err != nil {
				t.Fatal(execution.err)
			}
			if execution.result.RunState() != domain.RunCompleted {
				t.Fatalf("disjoint-provider run state = %q, want completed", execution.result.RunState())
			}
		}
	})

	t.Run("equal providers overlap across runs", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		entered := make(chan struct{}, len(assignments)*2)
		release := make(chan struct{})
		var mu sync.Mutex
		active := make(map[string]int, len(assignments))
		maximum := make(map[string]int, len(assignments))
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			provider := job.Route().ProviderInstance()
			mu.Lock()
			active[provider]++
			if active[provider] > maximum[provider] {
				maximum[provider] = active[provider]
			}
			mu.Unlock()
			entered <- struct{}{}
			<-release
			mu.Lock()
			active[provider]--
			mu.Unlock()
			return coordinatorSuccessOutcome(t, job)
		}}
		processLimit := len(assignments) * 2
		first := coordinatorTestCoordinator(t, runtime, processLimit, receipt)
		second := coordinatorTestCoordinator(t, runtime, processLimit, receipt)
		done := make(chan coordinatorTestExecution, 2)
		for _, coordinator := range []*Coordinator{first, second} {
			go func(coordinator *Coordinator) {
				result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
				done <- coordinatorTestExecution{result: result, err: err}
			}(coordinator)
		}
		for range processLimit {
			<-entered
		}
		close(release)
		for range 2 {
			execution := <-done
			if execution.err != nil {
				t.Fatal(execution.err)
			}
			if execution.result.RunState() != domain.RunCompleted {
				t.Fatalf("same-provider run state = %q, want completed", execution.result.RunState())
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if len(maximum) != len(assignments) {
			t.Fatalf("observed %d providers, want %d", len(maximum), len(assignments))
		}
		for provider, observed := range maximum {
			if observed != 2 {
				t.Fatalf("maximum concurrency for provider %q = %d, want 2", provider, observed)
			}
		}
	})
}
func TestCoordinatorCommitsEveryCollectedStoppingWaveFact(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	started := make(chan struct{}, len(assignments))
	release := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		started <- struct{}{}
		<-release
		switch job.Role() {
		case domain.RoleLogic:
			return coordinatorConditionOutcome(t, job, AttemptConditionInternalInvariant)
		case domain.RoleSecurity:
			return coordinatorConditionOutcome(t, job, AttemptConditionArtifactFailure)
		default:
			return coordinatorSuccessOutcome(t, job)
		}
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	for range assignments {
		<-started
	}
	close(release)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	result := execution.result
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	security := coordinatorRoleByRole(t, result, domain.RoleSecurity)
	if result.RunState() != domain.RunFailed ||
		logic.ReasonCode() != string(AttemptConditionInternalInvariant) ||
		security.ReasonCode() != string(AttemptConditionArtifactFailure) {
		t.Fatalf("stopping wave facts = run:%q logic:%#v security:%#v", result.RunState(), logic, security)
	}
	committed := make(map[AttemptCondition]bool)
	for _, event := range result.Trace() {
		if event.Kind() != CoordinatorEventInvocationCommitted {
			continue
		}
		condition, ok := event.Condition()
		if ok {
			committed[condition] = true
		}
	}
	if !committed[AttemptConditionInternalInvariant] || !committed[AttemptConditionArtifactFailure] {
		t.Fatalf("stopping wave trace lost collected conditions: %#v", result.Trace())
	}
}
func TestCoordinatorStoppingTraceIsCanonicalAcrossDeliveryOrder(t *testing.T) {
	run := func(first domain.Role) CoordinatorResult {
		assignments, receipt := coordinatorTestPlan(t)
		releases := make(map[domain.Role]chan struct{}, len(assignments))
		for _, assignment := range assignments {
			releases[assignment.Role()] = make(chan struct{})
		}
		started := make(chan domain.Role, len(assignments))
		collected := make(chan domain.Role, len(assignments))
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			started <- job.Role()
			<-releases[job.Role()]
			switch job.Role() {
			case domain.RoleLogic:
				return coordinatorConditionOutcome(t, job, AttemptConditionInternalInvariant)
			case domain.RoleSecurity:
				return coordinatorConditionOutcome(t, job, AttemptConditionArtifactFailure)
			default:
				return coordinatorSuccessOutcome(t, job)
			}
		}}
		coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
		coordinator.resultCollectedHook = func(job InvocationJob) {
			collected <- job.Role()
		}
		done := make(chan coordinatorTestExecution, 1)
		go func() {
			result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		for range assignments {
			<-started
		}

		second := domain.RoleSecurity
		if first == domain.RoleSecurity {
			second = domain.RoleLogic
		}
		close(releases[first])
		if got := <-collected; got != first {
			t.Fatalf("first collected role = %q, want %q", got, first)
		}
		close(releases[second])
		for role, release := range releases {
			if role != first && role != second {
				close(release)
			}
		}
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
		return execution.result
	}

	internalFirst := run(domain.RoleLogic)
	artifactFirst := run(domain.RoleSecurity)
	if !reflect.DeepEqual(internalFirst.Trace(), artifactFirst.Trace()) {
		t.Fatalf("stopping trace changed with delivery order:\ninternal-first=%#v\nartifact-first=%#v",
			internalFirst.Trace(), artifactFirst.Trace())
	}
	cancellationCount := 0
	for _, event := range internalFirst.Trace() {
		if event.Kind() != CoordinatorEventCancellationRequested {
			continue
		}
		cancellationCount++
		condition, ok := event.Condition()
		if !ok || condition != AttemptConditionInternalInvariant {
			t.Fatalf("canonical stopping condition = %q/%t, want %q",
				condition, ok, AttemptConditionInternalInvariant)
		}
	}
	if cancellationCount != 1 {
		t.Fatalf("canonical stopping cancellation events = %d, want 1", cancellationCount)
	}
}
func TestCoordinatorCancelsOutstandingInvocationsOnFirstProtectedResult(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	started := make(chan domain.Role, len(assignments))
	cancelled := make(chan domain.Role, len(assignments)-1)
	releaseSecurity := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
		started <- job.Role()
		if job.Role() == domain.RoleSecurity {
			<-releaseSecurity
			return coordinatorConditionOutcome(t, job, AttemptConditionSecurityViolation)
		}
		<-ctx.Done()
		cancelled <- job.Role()
		return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()

	for range assignments {
		<-started
	}
	close(releaseSecurity)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	for range len(assignments) - 1 {
		<-cancelled
	}
	if execution.result.RunState() != domain.RunCancelled {
		t.Fatalf("protected early stop = run:%q", execution.result.RunState())
	}
	security := coordinatorRoleByRole(t, execution.result, domain.RoleSecurity)
	if security.ReasonCode() != string(AttemptConditionSecurityViolation) {
		t.Fatalf("security result = %#v", security)
	}
	cancellationIndex, firstTerminalIndex := -1, -1
	for index, event := range execution.result.Trace() {
		switch event.Kind() {
		case CoordinatorEventCancellationRequested:
			if cancellationIndex < 0 {
				cancellationIndex = index
			}
		case CoordinatorEventRoleTerminal:
			if firstTerminalIndex < 0 {
				firstTerminalIndex = index
			}
		}
	}
	if cancellationIndex < 0 || firstTerminalIndex < 0 || cancellationIndex >= firstTerminalIndex {
		t.Fatalf("protected stop trace order = cancellation:%d first-terminal:%d trace:%#v",
			cancellationIndex, firstTerminalIndex, execution.result.Trace())
	}
}

func TestCoordinatorRechecksCancellationBeforeEachWaveCommit(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleSecurity {
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordinator.beforeOutcomeCommitHook = func(job InvocationJob) {
		if job.Role() == domain.RoleSecurity {
			cancel()
		}
	}

	result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	security := coordinatorRoleByRole(t, result, domain.RoleSecurity)
	if result.RunState() != domain.RunCancelled ||
		security.State() != domain.RoleTaskCancelled ||
		security.ReasonCode() != string(AttemptConditionCancelled) {
		t.Fatalf("commit-time cancellation = run:%q security:%#v", result.RunState(), security)
	}
	cancellationIndex, securityTerminalIndex := -1, -1
	for index, event := range result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued {
			t.Fatalf("commit-time cancellation queued follow-up work: %#v", event)
		}
		if event.Kind() == CoordinatorEventCancellationRequested && cancellationIndex < 0 {
			cancellationIndex = index
		}
		if event.Kind() == CoordinatorEventRoleTerminal {
			role, ok := event.Role()
			if ok && role == domain.RoleSecurity {
				securityTerminalIndex = index
			}
		}
	}
	if cancellationIndex < 0 || securityTerminalIndex < 0 || cancellationIndex >= securityTerminalIndex {
		t.Fatalf("commit-time cancellation trace order = cancellation:%d security-terminal:%d trace:%#v",
			cancellationIndex, securityTerminalIndex, result.Trace())
	}
}
func TestCoordinatorRunDeadlineAtCommitForbidsFollowup(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleSecurity {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderTimeout)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		return deadlineSource, func() {}
	}
	coordinator.beforeOutcomeCommitHook = func(job InvocationJob) {
		if job.Role() == domain.RoleSecurity {
			deadlineSource.expire()
		}
	}

	result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	security := coordinatorRoleByRole(t, result, domain.RoleSecurity)
	if result.RunState() != domain.RunFailed ||
		security.State() != domain.RoleTaskFailed ||
		security.ReasonCode() != string(AttemptConditionTimeout) {
		t.Fatalf("commit-time deadline = run:%q security:%#v", result.RunState(), security)
	}
	for _, event := range result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued {
			t.Fatalf("commit-time deadline queued follow-up work: %#v", event)
		}
	}
}

func TestCoordinatorWaveBarrierPrecedesEveryRuntimeStart(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	entered := make(chan domain.Role, len(assignments))
	release := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- job.Role()
		<-release
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	type readyObservation struct {
		jobs           int
		runtimeStarted bool
	}
	ready := make(chan readyObservation, 1)
	coordinator.waveReadyHook = func(jobs []InvocationJob) {
		observation := readyObservation{jobs: len(jobs)}
		select {
		case <-entered:
			observation.runtimeStarted = true
		default:
		}
		ready <- observation
	}
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()

	observation := <-ready
	alreadyObserved := 0
	if observation.runtimeStarted {
		alreadyObserved = 1
	}
	for index := alreadyObserved; index < len(assignments); index++ {
		<-entered
	}
	close(release)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	if observation.jobs != len(assignments) || observation.runtimeStarted {
		t.Fatalf("wave barrier observation = jobs:%d runtime-started:%t, want %d/false",
			observation.jobs, observation.runtimeStarted, len(assignments))
	}
	if execution.result.RunState() != domain.RunCompleted {
		t.Fatalf("wave barrier run state = %q, want %q", execution.result.RunState(), domain.RunCompleted)
	}
}

func TestCoordinatorRepairStartsOnlyAfterInitialWaveCompletes(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	logicInitialDone := make(chan struct{})
	peerInitialStarted := make(chan struct{})
	releasePeer := make(chan struct{})
	repairStarted := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		switch {
		case job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationInitial:
			close(logicInitialDone)
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		case job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationRepair:
			close(repairStarted)
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		case job.Role() == domain.RoleSecurity:
			close(peerInitialStarted)
			<-releasePeer
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	<-logicInitialDone
	<-peerInitialStarted
	select {
	case <-repairStarted:
		close(releasePeer)
		t.Fatal("repair started before every initial invocation completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(releasePeer)
	select {
	case <-repairStarted:
	case <-time.After(time.Second):
		t.Fatal("repair did not start after the initial wave completed")
	}
	if execution := <-done; execution.err != nil {
		t.Fatal(execution.err)
	}
}

func TestCoordinatorRunDeadlineBeforeWorkerCloseForcesFailedRun(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		return deadlineSource, func() {}
	}
	coordinator.beforeWorkersCloseLinearizationHook = deadlineSource.expire

	result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunState() != domain.RunFailed {
		t.Fatalf("pre-close deadline run state = %q, want %q", result.RunState(), domain.RunFailed)
	}
	for _, summary := range result.RoleSummaries() {
		if summary.State() != domain.RoleTaskSucceeded {
			t.Fatalf("pre-close deadline rewrote accepted role %q: %#v", summary.Role(), summary)
		}
	}
	cancellationIndex, closeIndex := -1, -1
	for index, event := range result.Trace() {
		switch event.Kind() {
		case CoordinatorEventCancellationRequested:
			condition, ok := event.Condition()
			if ok && condition == AttemptConditionTimeout {
				cancellationIndex = index
			}
		case CoordinatorEventWorkersCloseAuthorized:
			closeIndex = index
		}
	}
	if cancellationIndex < 0 || closeIndex < 0 || cancellationIndex >= closeIndex {
		t.Fatalf("pre-close deadline trace order = timeout:%d close:%d trace:%#v",
			cancellationIndex, closeIndex, result.Trace())
	}
}
func TestCoordinatorParentCancellationUpgradesPreCloseTimeout(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		return deadlineSource, func() {}
	}
	coordinator.beforeOutcomeCommitHook = func(job InvocationJob) {
		if job.Role() == domain.RoleSecurity {
			deadlineSource.expire()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordinator.beforeWorkersCloseLinearizationHook = cancel

	result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunState() != domain.RunCancelled {
		t.Fatalf("timeout/cancellation precedence run state = %q, want %q",
			result.RunState(), domain.RunCancelled)
	}
	var stopConditions []AttemptCondition
	closeIndex := -1
	for index, event := range result.Trace() {
		switch event.Kind() {
		case CoordinatorEventCancellationRequested:
			condition, ok := event.Condition()
			if ok {
				stopConditions = append(stopConditions, condition)
			}
		case CoordinatorEventWorkersCloseAuthorized:
			closeIndex = index
		}
	}
	want := []AttemptCondition{AttemptConditionTimeout, AttemptConditionCancelled}
	if !reflect.DeepEqual(stopConditions, want) || closeIndex < 0 {
		t.Fatalf("timeout/cancellation stop trace = conditions:%q close:%d, want %q and close",
			stopConditions, closeIndex, want)
	}
}
func TestCoordinatorIgnoresCancellationAfterWorkerCloseLinearization(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordinator.workersCloseAuthorizedHook = cancel

	result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunState() != domain.RunCompleted {
		t.Fatalf("post-authorization cancellation run state = %q, want %q",
			result.RunState(), domain.RunCompleted)
	}
	for _, event := range result.Trace() {
		if event.Kind() == CoordinatorEventCancellationRequested {
			t.Fatalf("post-authorization cancellation crossed the close gate: %#v", event)
		}
	}
}
func TestCoordinatorsShareProcessActiveWorkerLimit(t *testing.T) {
	firstAssignments, firstReceipt := coordinatorTestPlanInNamespace(t, "capacity.first.")
	secondAssignments, secondReceipt := coordinatorTestPlanInNamespace(t, "capacity.second.")
	entered := make(chan struct{}, len(firstAssignments)+len(secondAssignments))
	release := make(chan struct{})

	var mu sync.Mutex
	active, maximum := 0, 0
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return coordinatorSuccessOutcome(t, job)
	}}

	const processLimit = 2
	first := coordinatorTestCoordinator(t, runtime, processLimit, firstReceipt)
	second := coordinatorTestCoordinator(t, runtime, processLimit, secondReceipt)
	done := make(chan coordinatorTestExecution, 2)
	go func() {
		result, err := first.Execute(context.Background(), coordinatorTestTarget(t), firstAssignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	go func() {
		result, err := second.Execute(context.Background(), coordinatorTestTarget(t), secondAssignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()

	for range processLimit {
		<-entered
	}
	close(release)
	for range 2 {
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if maximum != processLimit {
		t.Fatalf("process-wide active worker maximum = %d, want %d", maximum, processLimit)
	}
}
func TestProcessWorkerCapacityAuthorityUsesOneMixedLimitPool(t *testing.T) {
	target := coordinatorTestTarget(t)
	limits, err := NewInvocationLimits(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newJob := func(role domain.Role, provider string, ordinal uint64) InvocationJob {
		job, err := NewInvocationJob(
			role,
			coordinatorTestRoute(t, provider),
			target,
			limits,
			coordinatorTypesAttemptID(t, int(ordinal)+70),
			domain.InvocationInitial,
			ordinal,
		)
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	wideJob := newJob(domain.RoleLogic, "mixed-wide", 1)
	narrowJob := newJob(domain.RoleSecurity, "mixed-narrow", 2)

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var mu sync.Mutex
	active, maximum := 0, 0
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return coordinatorSuccessOutcome(t, job)
	}}

	wide := newInvocationScheduler(context.Background(), runtime, 3, 1)
	narrow := newInvocationScheduler(context.Background(), runtime, 1, 1)
	if !wide.submit(wideJob) || !narrow.submit(narrowJob) {
		t.Fatal("mixed-limit scheduler rejected job")
	}
	<-entered
	select {
	case <-entered:
		t.Fatal("mixed capacity registrations used independent active pools")
	default:
	}
	close(release)
	<-wide.results
	<-narrow.results
	wide.close()
	narrow.close()

	mu.Lock()
	defer mu.Unlock()
	if maximum != 1 {
		t.Fatalf("mixed-limit process-wide maximum = %d, want 1", maximum)
	}
}

func TestCoordinatorProtectedConditionsPrecedeContextRaces(t *testing.T) {
	for _, cause := range []struct {
		condition AttemptCondition
		role      domain.Role
		runState  domain.RunState
	}{
		{AttemptConditionInternalInvariant, domain.RoleLogic, domain.RunFailed},
		{AttemptConditionArtifactFailure, domain.RoleLogic, domain.RunFailed},
		{AttemptConditionSecurityViolation, domain.RoleSecurity, domain.RunCancelled},
		{AttemptConditionMutationViolation, domain.RoleSecurity, domain.RunCancelled},
	} {
		for _, source := range []struct {
			name     string
			deadline bool
		}{
			{name: "parent-cancel"},
			{name: "run-deadline", deadline: true},
		} {
			for _, contextFirst := range []bool{false, true} {
				order := "cause-first"
				if contextFirst {
					order = "context-first"
				}
				t.Run(string(cause.condition)+"/"+source.name+"/"+order, func(t *testing.T) {
					result := coordinatorProtectedContextRaceResult(t, cause.condition, cause.role, source.deadline, contextFirst)
					origin := coordinatorRoleByRole(t, result, cause.role)
					if result.RunState() != cause.runState || origin.ReasonCode() != string(cause.condition) {
						t.Fatalf("protected result = run:%q origin:%#v", result.RunState(), origin)
					}
					for _, summary := range result.RoleSummaries() {
						if summary.Role() == cause.role || summary.State() == domain.RoleTaskSucceeded {
							continue
						}
						if source.deadline &&
							summary.State() == domain.RoleTaskFailed &&
							summary.ReasonCode() == string(AttemptConditionTimeout) {
							continue
						}
						if summary.State() != domain.RoleTaskCancelled || summary.ReasonCode() != string(AttemptConditionCancelled) {
							t.Fatalf("cancelled bystander %q = %#v", summary.Role(), summary)
						}
					}
					globalCause := false
					for _, event := range result.Trace() {
						if event.Kind() == CoordinatorEventRepairQueued {
							t.Fatalf("protected cancellation queued follow-up work: %#v", event)
						}
						if event.Kind() == CoordinatorEventCancellationRequested {
							condition, ok := event.Condition()
							globalCause = ok && condition == cause.condition
						}
					}
					if !globalCause {
						t.Fatalf("global stop did not retain protected condition %q", cause.condition)
					}
				})
			}
		}
	}
}

func TestCoordinatorRunDeadlinePreventsProviderFallback(t *testing.T) {
	assignments, receipt := coordinatorTestPlanWithInvocationTimeout(t, time.Minute)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	logicStarted := make(chan struct{}, 1)
	releaseLogic := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			logicStarted <- struct{}{}
			<-releaseLogic
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		return deadlineSource, func() {}
	}
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	<-logicStarted
	deadlineSource.expire()
	close(releaseLogic)
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	logic := coordinatorRoleByRole(t, execution.result, domain.RoleLogic)
	if logic.ReasonCode() != string(AttemptConditionTimeout) ||
		execution.result.RunState() != domain.RunFailed {
		t.Fatalf("deadline/provider race = run:%q logic:%#v", execution.result.RunState(), logic)
	}
	for _, event := range execution.result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued {
			t.Fatalf("deadline/provider race queued follow-up work: %#v", event)
		}
	}
}

func TestCoordinatorPostAdmissionFailureReturnsTerminalSnapshot(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	invoked := make(chan struct{}, 1)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, _ InvocationJob) AttemptOutcome {
		invoked <- struct{}{}
		return AttemptOutcome{}
	}}
	ids := &coordinatorFailingAttemptIDs{}
	coordinator, err := NewCoordinator(
		coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		ids,
		runtime,
		len(assignments),
		receipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
	if err == nil {
		t.Fatal("attempt identity failure returned nil error")
	}
	if result.RunState() != domain.RunFailed {
		t.Fatalf("aborted run state = %q, want failed", result.RunState())
	}
	trace := result.Trace()
	if len(trace) == 0 || trace[len(trace)-1].Kind() != CoordinatorEventRunTerminal {
		t.Fatalf("aborted trace is not terminal: %#v", trace)
	}
	for _, summary := range result.RoleSummaries() {
		if summary.State() != domain.RoleTaskCancelled {
			t.Fatalf("aborted role %q state = %q, want cancelled", summary.Role(), summary.State())
		}
	}
	select {
	case <-invoked:
		t.Fatal("post-admission identity failure invoked runtime")
	default:
	}
}

func TestCoordinatorRecordStateMachine(t *testing.T) {
	t.Run("illegal calls do not mutate trace", func(t *testing.T) {
		execution := coordinatorRecordExecution(t)
		if err := execution.record(CoordinatorEventAttemptQueued, domain.RoleLogic, nil, nil, nil, "", domain.RunState("")); err == nil {
			t.Fatal("record accepted a role event before run started")
		}
		if len(execution.trace) != 0 || execution.nextEvent != 0 {
			t.Fatalf("pre-start rejection mutated trace: %#v/%d", execution.trace, execution.nextEvent)
		}
		if err := execution.record(CoordinatorEventRunStarted, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
			t.Fatal(err)
		}
		if err := execution.record(CoordinatorEventRunStarted, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
			t.Fatal("record accepted duplicate run start")
		}
		if err := execution.record(CoordinatorEventWorkersCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
			t.Fatal("record authorized workers close before roles were terminal")
		}
		if err := execution.run.TransitionRole(domain.RoleLogic, domain.RoleTaskCancelled); err != nil {
			t.Fatal(err)
		}
		attempt := coordinatorRecordAttempt(t, domain.RoleLogic)
		condition := AttemptConditionCancelled
		if err := execution.record(
			CoordinatorEventRoleTerminal,
			domain.RoleLogic,
			attempt,
			nil,
			&condition,
			string(condition),
			domain.RunState(""),
		); err != nil {
			t.Fatal(err)
		}
		trace := append([]CoordinatorTraceEvent(nil), execution.trace...)
		nextEvent := execution.nextEvent
		if err := execution.record(CoordinatorEventAttemptQueued, domain.RoleLogic, nil, nil, nil, "", domain.RunState("")); err == nil {
			t.Fatal("record accepted a role event after its terminal event")
		}
		if !reflect.DeepEqual(execution.trace, trace) || execution.nextEvent != nextEvent {
			t.Fatalf("role-terminal rejection mutated trace: %#v/%d", execution.trace, execution.nextEvent)
		}
		if err := execution.record(CoordinatorEventRunTerminal, domain.Role(""), nil, nil, nil, "", domain.RunRunning); err == nil {
			t.Fatal("record accepted terminal before workers close and terminal run state")
		}
	})

	for _, closure := range []struct {
		name      string
		roleState domain.RoleTaskState
		runState  domain.RunState
	}{
		{name: "success", roleState: domain.RoleTaskSucceeded, runState: domain.RunCompleted},
		{name: "cancel", roleState: domain.RoleTaskCancelled, runState: domain.RunCancelled},
		{name: "failure", roleState: domain.RoleTaskFailed, runState: domain.RunFailed},
	} {
		t.Run(closure.name, func(t *testing.T) {
			execution := coordinatorRecordExecution(t)
			if err := execution.record(CoordinatorEventRunStarted, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
				t.Fatal(err)
			}
			for _, role := range domain.CoreRoleOrder() {
				if closure.roleState != domain.RoleTaskCancelled {
					if err := execution.run.TransitionRole(role, domain.RoleTaskPrimaryQueued); err != nil {
						t.Fatal(err)
					}
					if err := execution.run.TransitionRole(role, domain.RoleTaskPrimaryRunning); err != nil {
						t.Fatal(err)
					}
				}
				if err := execution.run.TransitionRole(role, closure.roleState); err != nil {
					t.Fatal(err)
				}
				attempt := coordinatorRecordAttempt(t, role)
				condition := AttemptConditionValidReview
				switch closure.roleState {
				case domain.RoleTaskCancelled:
					condition = AttemptConditionCancelled
				case domain.RoleTaskFailed:
					condition = AttemptConditionInternalInvariant
				}
				if err := execution.record(
					CoordinatorEventRoleTerminal,
					role,
					attempt,
					nil,
					&condition,
					string(condition),
					domain.RunState(""),
				); err != nil {
					t.Fatal(err)
				}
			}
			if err := execution.record(CoordinatorEventWorkersCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
				t.Fatal(err)
			}
			if err := execution.record(CoordinatorEventWorkersCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
				t.Fatal("record accepted duplicate workers close authorization")
			}
			if err := execution.run.Transition(closure.runState); err != nil {
				t.Fatal(err)
			}
			if err := execution.record(CoordinatorEventRunTerminal, domain.Role(""), nil, nil, nil, "", closure.runState); err != nil {
				t.Fatal(err)
			}
			trace := execution.trace
			if len(trace) != len(domain.CoreRoleOrder())+3 ||
				trace[0].Kind() != CoordinatorEventRunStarted ||
				trace[len(trace)-2].Kind() != CoordinatorEventWorkersCloseAuthorized ||
				trace[len(trace)-1].Kind() != CoordinatorEventRunTerminal {
				t.Fatalf("closure trace = %#v", trace)
			}
			if state, ok := trace[len(trace)-1].RunState(); !ok || state != closure.runState {
				t.Fatalf("terminal trace state = %q/%t, want %q", state, ok, closure.runState)
			}
			snapshot := append([]CoordinatorTraceEvent(nil), trace...)
			if err := execution.record(CoordinatorEventRunTerminal, domain.Role(""), nil, nil, nil, "", closure.runState); err == nil {
				t.Fatal("record accepted duplicate run terminal")
			}
			if err := execution.record(CoordinatorEventCancellationRequested, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
				t.Fatal("record accepted an event after run terminal")
			}
			if !reflect.DeepEqual(execution.trace, snapshot) {
				t.Fatalf("post-terminal rejection mutated trace: %#v", execution.trace)
			}
		})
	}
}

func TestCoordinatorTracePayloadMatrix(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	attemptID := job.AttemptID()
	purpose := domain.InvocationInitial
	valid := AttemptConditionValidReview
	invalidOutput := AttemptConditionInvalidProviderOutput
	providerUnavailable := AttemptConditionProviderUnavailable
	cancelled := AttemptConditionCancelled

	eventFor := func(kind CoordinatorEventKind) CoordinatorTraceEvent {
		event := CoordinatorTraceEvent{ordinal: 1, kind: kind}
		setAttempt := func() {
			event.role = domain.RoleLogic
			event.attemptID = attemptID
			event.hasAttempt = true
		}
		switch kind {
		case CoordinatorEventAttemptQueued:
			setAttempt()
		case CoordinatorEventInvocationDispatched:
			setAttempt()
			event.purpose, event.hasPurpose = purpose, true
		case CoordinatorEventInvocationCommitted:
			setAttempt()
			event.purpose, event.hasPurpose = purpose, true
			event.condition, event.hasCondition = valid, true
		case CoordinatorEventRepairQueued:
			setAttempt()
			event.purpose, event.hasPurpose = purpose, true
			event.reason = string(invalidOutput)
			event.reason = string(providerUnavailable)
		case CoordinatorEventRoleTerminal:
			setAttempt()
			event.condition, event.hasCondition = valid, true
			event.reason = string(valid)
		case CoordinatorEventCancellationRequested:
			event.condition, event.hasCondition = cancelled, true
			event.reason = string(cancelled)
		case CoordinatorEventRunTerminal:
			event.runState = domain.RunCompleted
		}
		return event
	}

	for _, kind := range []CoordinatorEventKind{
		CoordinatorEventRunStarted,
		CoordinatorEventAttemptQueued,
		CoordinatorEventInvocationDispatched,
		CoordinatorEventInvocationCommitted,
		CoordinatorEventRepairQueued,
		CoordinatorEventRoleTerminal,
		CoordinatorEventCancellationRequested,
		CoordinatorEventWorkersCloseAuthorized,
		CoordinatorEventRunTerminal,
	} {
		if err := eventFor(kind).validate(); err != nil {
			t.Errorf("valid %q event rejected: %v", kind, err)
		}
	}

	attemptlessTerminal := eventFor(CoordinatorEventRoleTerminal)
	attemptlessTerminal.hasAttempt = false
	attemptlessTerminal.attemptID = domain.AttemptID{}
	if err := attemptlessTerminal.validate(); err != nil {
		t.Fatalf("valid attemptless terminal event rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		kind   CoordinatorEventKind
		mutate func(*CoordinatorTraceEvent)
	}{
		{name: "run start role", kind: CoordinatorEventRunStarted, mutate: func(event *CoordinatorTraceEvent) {
			event.role = domain.RoleLogic
		}},
		{name: "attempt missing identity", kind: CoordinatorEventAttemptQueued, mutate: func(event *CoordinatorTraceEvent) {
			event.hasAttempt = false
		}},
		{name: "dispatch missing purpose", kind: CoordinatorEventInvocationDispatched, mutate: func(event *CoordinatorTraceEvent) {
			event.hasPurpose = false
			event.purpose = ""
		}},
		{name: "commit missing condition", kind: CoordinatorEventInvocationCommitted, mutate: func(event *CoordinatorTraceEvent) {
			event.hasCondition = false
			event.condition = ""
		}},
		{name: "repair missing reason", kind: CoordinatorEventRepairQueued, mutate: func(event *CoordinatorTraceEvent) {
			event.reason = ""
		}},
		{name: "terminal has purpose", kind: CoordinatorEventRoleTerminal, mutate: func(event *CoordinatorTraceEvent) {
			event.purpose, event.hasPurpose = purpose, true
		}},
		{name: "cancellation has role", kind: CoordinatorEventCancellationRequested, mutate: func(event *CoordinatorTraceEvent) {
			event.role = domain.RoleLogic
		}},
		{name: "workers close has condition", kind: CoordinatorEventWorkersCloseAuthorized, mutate: func(event *CoordinatorTraceEvent) {
			event.condition, event.hasCondition = cancelled, true
		}},
		{name: "run terminal missing state", kind: CoordinatorEventRunTerminal, mutate: func(event *CoordinatorTraceEvent) {
			event.runState = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := eventFor(test.kind)
			test.mutate(&event)
			if err := event.validate(); err == nil {
				t.Fatalf("malformed %q event was accepted: %#v", test.kind, event)
			}
		})
	}
}
func TestInvocationConfigurationAndDeadlineReductionIsFailClosed(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	invalid := coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
	scheduler := newInvocationScheduler(context.Background(), &coordinatorTestRuntime{}, 1, 1)
	defer scheduler.close()

	deadlineCtx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	for _, test := range []struct {
		name       string
		conditions []AttemptCondition
		want       AttemptCondition
	}{
		{
			name:       "release configuration outranks invalid output",
			conditions: []AttemptCondition{AttemptConditionInvalidProviderOutput, AttemptConditionConfigurationViolation},
			want:       AttemptConditionConfigurationViolation,
		},
		{
			name:       "release configuration survives deadline",
			conditions: []AttemptCondition{AttemptConditionInvalidProviderOutput, AttemptConditionConfigurationViolation},
			want:       AttemptConditionConfigurationViolation,
		},
		{
			name:       "deadline outranks invalid output",
			conditions: []AttemptCondition{AttemptConditionInvalidProviderOutput},
			want:       AttemptConditionTimeout,
		},
		{
			name:       "observed provider timeout survives invocation deadline",
			conditions: []AttemptCondition{AttemptConditionProviderTimeout},
			want:       AttemptConditionProviderTimeout,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.name != "release configuration outranks invalid output" {
				ctx = deadlineCtx
			}
			outcome := scheduler.reduceOutcome(job, invalid, ctx, test.conditions...)
			got, ok := outcome.Condition()
			if !ok || got != test.want {
				t.Fatalf("reduced condition = %q/%t, want %q", got, ok, test.want)
			}
		})
	}
}

func TestInvocationTimeoutProvenancePreservesProviderFactsAndStripsParentFacts(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	providerOutcome, err := NewProviderTimeoutAttemptOutcome(job, 750*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	invocationCtx, cancelInvocation := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelInvocation()
	providerScheduler := newInvocationScheduler(context.Background(), &coordinatorTestRuntime{}, 1, 1)
	preserved := providerScheduler.reduceOutcome(job, providerOutcome, invocationCtx, AttemptConditionProviderTimeout)
	providerScheduler.close()
	if _, ok := preserved.ProviderTimeoutFacts(); !ok {
		t.Fatal("provider-owned invocation deadline discarded timeout facts")
	}

	parentCtx, cancelParent := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelParent()
	parentScheduler := newInvocationScheduler(parentCtx, &coordinatorTestRuntime{}, 1, 1)
	stripped := parentScheduler.reduceOutcome(job, providerOutcome, parentCtx, AttemptConditionProviderTimeout)
	parentScheduler.close()
	condition, ok := stripped.Condition()
	if !ok || condition != AttemptConditionTimeout {
		t.Fatalf("parent timeout condition = %q/%t", condition, ok)
	}
	if _, ok := stripped.ProviderTimeoutFacts(); ok {
		t.Fatal("enclosing run timeout retained provider-specific timing facts")
	}
}

func TestInvocationAdmissionGatePrecedesRuntimeExecution(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	entered := make(chan struct{}, 1)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- struct{}{}
		return coordinatorSuccessOutcome(t, job)
	}}
	scheduler := newInvocationScheduler(context.Background(), runtime, 1, 1)
	start, accepted := scheduler.admit(job)
	if !accepted {
		t.Fatal("scheduler rejected admission")
	}
	select {
	case <-entered:
		t.Fatal("runtime executed before admission start gate")
	default:
	}
	start()
	<-entered
	result := <-scheduler.results
	scheduler.close()
	if !result.outcome.validFor(job) {
		t.Fatalf("admitted outcome is invalid for job: %#v", result)
	}
}

func TestInvocationEnclosingDeadlineAndProviderTimeoutRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		name    string
		runtime InvocationRuntime
		want    AttemptCondition
		parent  time.Duration
	}{
		{
			name: "provider observed timeout",
			runtime: &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
				providerCtx, cancel := context.WithTimeout(ctx, job.Limits().Timeout())
				defer cancel()
				<-providerCtx.Done()
				return coordinatorConditionOutcome(t, job, AttemptConditionProviderTimeout)
			}},
			want: AttemptConditionProviderTimeout,
		},
		{
			name: "enclosing run deadline",
			runtime: &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
				<-ctx.Done()
				return coordinatorConditionOutcome(t, job, AttemptConditionProviderTimeout)
			}},
			want:   AttemptConditionTimeout,
			parent: 25 * time.Millisecond,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits, err := NewInvocationLimits(40 * time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			job, err := NewInvocationJob(
				domain.RoleLogic,
				coordinatorTestRoute(t, "provider"),
				coordinatorTestTarget(t),
				limits,
				coordinatorTypesAttemptID(t, 42),
				domain.InvocationInitial,
				1,
			)
			if err != nil {
				t.Fatal(err)
			}
			parent := context.Background()
			cancelParent := func() {}
			if test.parent > 0 {
				parent, cancelParent = context.WithTimeout(parent, test.parent)
			}
			defer cancelParent()
			scheduler := newInvocationScheduler(parent, test.runtime, 1, 1)
			if !scheduler.submit(job) {
				t.Fatal("scheduler rejected job")
			}
			result := <-scheduler.results
			scheduler.close()
			condition, ok := result.outcome.Condition()
			if !ok || condition != test.want {
				t.Fatalf("deadline condition = %q/%t, want %q", condition, ok, test.want)
			}
		})
	}
}

func TestWorkerCapacityWaitingDoesNotConsumeProviderTimeout(t *testing.T) {
	limits, err := NewInvocationLimits(25 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	newJob := func(role domain.Role, provider string, ordinal uint64) InvocationJob {
		job, err := NewInvocationJob(
			role,
			coordinatorTestRoute(t, provider),
			coordinatorTestTarget(t),
			limits,
			coordinatorTypesAttemptID(t, int(ordinal)+50),
			domain.InvocationInitial,
			ordinal,
		)
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	first := newJob(domain.RoleLogic, "capacity-first", 1)
	second := newJob(domain.RoleSecurity, "capacity-second", 2)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Ordinal() == first.Ordinal() {
			close(firstEntered)
			<-releaseFirst
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	parent, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	scheduler := newInvocationScheduler(parent, runtime, 1, 2)
	if !scheduler.submit(first) {
		t.Fatal("scheduler rejected first job")
	}
	<-firstEntered
	if !scheduler.submit(second) {
		t.Fatal("scheduler rejected second job")
	}
	time.Sleep(60 * time.Millisecond)
	close(releaseFirst)
	for range 2 {
		result := <-scheduler.results
		if !result.outcome.Succeeded() {
			condition, _ := result.outcome.Condition()
			t.Fatalf("capacity waiting consumed job %d provider timeout: condition=%q", result.job.Ordinal(), condition)
		}
	}
	scheduler.close()
}
func TestCoordinatorOutcomeAxesKeepExhaustionAndFindingsIndependent(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		}
		if job.Role() == domain.RoleSecurity {
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "retained high",
				path:         "src/coordinator-retained-high.go",
				quote:        "retained\n",
				targetBytes:  "retained\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if result.RunState() != domain.RunFailed || !logic.Required() || logic.State() != domain.RoleTaskFailed ||
		len(result.Findings()) != 1 || result.Findings()[0].EvidenceState() != domain.EvidenceVerified ||
		len(result.Evidence()) != 1 || result.Evidence()[0].FindingID() != result.Findings()[0].ID() ||
		result.Outcomes().ContentVerdict() != domain.ContentRequestChanges ||
		result.Outcomes().CoverageStatus() != domain.CoverageIncomplete ||
		result.Outcomes().PublicationStatus() != domain.PublicationNotPublished ||
		result.Outcomes().CIDecision() != domain.CIFail {
		t.Fatalf("independent exhaustion/finding axes = run:%q logic:%#v findings:%#v evidence:%#v axes:%#v",
			result.RunState(), logic, result.Findings(), result.Evidence(), result.Outcomes())
	}
}

func TestCoordinatorOptionalDegradationAndFourInvocationBound(t *testing.T) {
	t.Run("optional degradation", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleMaintainability {
				return coordinatorIncompleteOutcome(t, job)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
		if result.RunState() != domain.RunCompleted || result.Outcomes().CoverageStatus() != domain.CoverageDegraded {
			t.Fatalf("optional incomplete result = run:%q coverage:%q", result.RunState(), result.Outcomes().CoverageStatus())
		}
	})

	t.Run("repair bound", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 2 {
			t.Fatalf("logic did not stop at the two-invocation provider+repair bound: %#v", logic)
		}
	})
}

func TestCoordinatorInvalidProperties(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	clock := coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)}
	ids := &coordinatorTestIDs{}
	if _, err := NewCoordinator(clock, ids, runtime, 0, receipt); err == nil {
		t.Fatal("NewCoordinator accepted a zero active-worker limit")
	}
	if _, err := NewCoordinator(clock, ids, runtime, 1, RunBudgetReceipt{}); err == nil {
		t.Fatal("NewCoordinator accepted an ineligible receipt")
	}
	if _, err := NewCoordinatorWithEvidencePolicy(clock, ids, runtime, 1, receipt, EvidencePolicy{}); err == nil {
		t.Fatal("NewCoordinatorWithEvidencePolicy accepted an invalid policy")
	}
	coordinator := coordinatorTestCoordinator(t, runtime, 1, receipt)
	if _, err := coordinator.Execute(context.Background(), domain.TargetIdentity{}, assignments, "", nil); err == nil {
		t.Fatal("Execute accepted an invalid target")
	}
	if _, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments[:len(assignments)-1], "", nil); err == nil {
		t.Fatal("Execute accepted assignments that do not match the receipt")
	}
}

type coordinatorTestExecution struct {
	result CoordinatorResult
	err    error
}

type coordinatorTestClock struct{ now time.Time }

func (clock coordinatorTestClock) Now() time.Time { return clock.now }

type coordinatorTestIDs struct {
	mu   sync.Mutex
	next uint64
}

func (ids *coordinatorTestIDs) newRaw() string {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return fmt.Sprintf("00000000-0000-7000-8000-%012x", ids.next)
}

func (ids *coordinatorTestIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_" + ids.newRaw())
}

func (ids *coordinatorTestIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_" + ids.newRaw())
}

func (ids *coordinatorTestIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_" + ids.newRaw())
}

type coordinatorFailingAttemptIDs struct {
	base coordinatorTestIDs
}

func (ids *coordinatorFailingAttemptIDs) NewSessionID(now time.Time) (domain.SessionID, error) {
	return ids.base.NewSessionID(now)
}

func (ids *coordinatorFailingAttemptIDs) NewRunID(now time.Time) (domain.RunID, error) {
	return ids.base.NewRunID(now)
}

func (*coordinatorFailingAttemptIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.AttemptID{}, errors.New("attempt identity unavailable")
}

type coordinatorCountingIDs struct {
	base  coordinatorTestIDs
	mu    sync.Mutex
	calls int
}

func (ids *coordinatorCountingIDs) recordCall() {
	ids.mu.Lock()
	ids.calls++
	ids.mu.Unlock()
}

func (ids *coordinatorCountingIDs) Calls() int {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	return ids.calls
}

func (ids *coordinatorCountingIDs) NewSessionID(now time.Time) (domain.SessionID, error) {
	ids.recordCall()
	return ids.base.NewSessionID(now)
}

func (ids *coordinatorCountingIDs) NewRunID(now time.Time) (domain.RunID, error) {
	ids.recordCall()
	return ids.base.NewRunID(now)
}

func (ids *coordinatorCountingIDs) NewAttemptID(now time.Time) (domain.AttemptID, error) {
	ids.recordCall()
	return ids.base.NewAttemptID(now)
}

type coordinatorTestRuntime struct {
	mu     sync.Mutex
	jobs   []InvocationJob
	invoke func(context.Context, InvocationJob) AttemptOutcome
}

type coordinatorDiagnosticSink struct {
	ports.RuntimeDiagnosticSink
	events []domain.RuntimeDiagnosticEventCode
	inputs []domain.RuntimeDiagnosticEventInput
	failOn domain.RuntimeDiagnosticEventCode
}

func (sink *coordinatorDiagnosticSink) Emit(ctx context.Context, draft domain.RuntimeDiagnosticEventDraft) (domain.RuntimeDiagnosticEvent, error) {
	code := draft.Input().Event
	sink.events = append(sink.events, code)
	sink.inputs = append(sink.inputs, draft.Input())
	if code == sink.failOn {
		return domain.RuntimeDiagnosticEvent{}, errors.New("injected diagnostic failure")
	}
	return sink.RuntimeDiagnosticSink.Emit(ctx, draft)
}

func coordinatorDiagnosticRoot(t *testing.T, assignments []Assignment) (domain.Run, ports.RuntimeDiagnosticOpenRequest) {
	t.Helper()
	now := time.Date(2026, 7, 23, 2, 3, 4, 0, time.UTC)
	ids := &coordinatorTestIDs{}
	sessionID, err := ids.NewSessionID(now)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := ids.NewRunID(now)
	if err != nil {
		t.Fatal(err)
	}
	tasks := make([]domain.RoleTask, 0, len(assignments))
	for _, assignment := range assignments {
		task, taskErr := domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.PrimaryRoute().ProviderInstance())
		if taskErr != nil {
			t.Fatal(taskErr)
		}
		tasks = append(tasks, task)
	}
	_, root, err := domain.NewReviewSession(sessionID, now, runID, coordinatorTestTarget(t), tasks)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewRuntimeDiagnosticOpenRequest(anchored, sessionID, runID, now)
	if err != nil {
		t.Fatal(err)
	}
	return root, request
}

func (runtime *coordinatorTestRuntime) Invoke(ctx context.Context, job InvocationJob) AttemptOutcome {
	runtime.mu.Lock()
	runtime.jobs = append(runtime.jobs, job)
	runtime.mu.Unlock()
	return runtime.invoke(ctx, job)
}

type coordinatorManualDeadlineContext struct {
	context.Context

	done chan struct{}
	once sync.Once
	mu   sync.RWMutex
	err  error
}

func newCoordinatorManualDeadlineContext(parent context.Context) *coordinatorManualDeadlineContext {
	return &coordinatorManualDeadlineContext{
		Context: parent,
		done:    make(chan struct{}),
	}
}

func (ctx *coordinatorManualDeadlineContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *coordinatorManualDeadlineContext) Err() error {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.err
}

func (ctx *coordinatorManualDeadlineContext) expire() {
	ctx.once.Do(func() {
		ctx.mu.Lock()
		ctx.err = context.DeadlineExceeded
		close(ctx.done)
		ctx.mu.Unlock()
	})
}

func coordinatorTestPlan(t *testing.T) ([]Assignment, RunBudgetReceipt) {
	t.Helper()
	return coordinatorTestPlanInNamespace(t, "")
}

func coordinatorTestPlanInNamespace(
	t *testing.T,
	namespace string,
) ([]Assignment, RunBudgetReceipt) {
	t.Helper()
	assignments := make([]Assignment, 0, len(domain.CoreRoleOrder()))
	budgets := make([]RoleBudget, 0, len(domain.CoreRoleOrder()))
	limits, err := NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range domain.CoreRoleOrder() {
		primary := coordinatorTestRoute(t, namespace+"primary."+string(role))
		primaryBudget, err := NewRouteBudget(primary, limits)
		if err != nil {
			t.Fatal(err)
		}
		assignment, err := NewScheduledAssignment(role, false, primary)
		if err != nil {
			t.Fatal(err)
		}
		roleBudget, err := NewRoleBudget(role, primaryBudget)
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
		budgets = append(budgets, roleBudget)
	}
	receipt, err := PreflightRunBudgetWithCapacity(budgets, DefaultHarnessCeilings(), len(assignments))
	if err != nil {
		t.Fatal(err)
	}
	return assignments, receipt
}
func coordinatorTestPlanWithInvocationTimeout(
	t *testing.T,
	timeout time.Duration,
) ([]Assignment, RunBudgetReceipt) {
	t.Helper()

	assignments, receipt := coordinatorTestPlan(t)
	limits, err := NewInvocationLimits(timeout)
	if err != nil {
		t.Fatal(err)
	}
	budgets := receipt.RoleBudgets()
	for index, budget := range budgets {
		primary, err := NewRouteBudget(budget.Primary().Route(), limits)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := NewRoleBudget(budget.Role(), primary)
		if err != nil {
			t.Fatal(err)
		}
		budgets[index] = updated
	}
	receipt, err = PreflightRunBudgetWithCapacity(budgets, receipt.Ceilings(), receipt.MaxActiveLanes())
	if err != nil {
		t.Fatal(err)
	}
	return assignments, receipt
}
func coordinatorTestRoute(t *testing.T, provider string) ports.ProviderRoute {
	t.Helper()
	route, err := ports.NewProviderRoute(provider)
	if err != nil {
		t.Fatal(err)
	}
	return route
}

const coordinatorTestTargetSHA256 = "1111111111111111111111111111111111111111111111111111111111111111"

func coordinatorTestTarget(t *testing.T) domain.TargetIdentity {
	t.Helper()
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind:   domain.TargetStdin,
		SHA256: coordinatorTestTargetSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func coordinatorTestCoordinator(t *testing.T, runtime InvocationRuntime, maxActive int, receipt RunBudgetReceipt) *Coordinator {
	t.Helper()
	capacityReceipt, err := PreflightRunBudgetWithCapacity(receipt.RoleBudgets(), receipt.Ceilings(), maxActive)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(
		coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		&coordinatorTestIDs{},
		runtime,
		maxActive,
		capacityReceipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func coordinatorTestExecute(
	t *testing.T,
	assignments []Assignment,
	receipt RunBudgetReceipt,
	runtime InvocationRuntime,
	maxActive int,
) CoordinatorResult {
	t.Helper()
	result, err := coordinatorTestCoordinator(t, runtime, maxActive, receipt).Execute(
		context.Background(), coordinatorTestTarget(t), assignments, "", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func coordinatorSuccessOutcome(_ *testing.T, job InvocationJob) AttemptOutcome {
	output, err := NewValidatedRoleOutput(
		job.Role(),
		job.Route().ProviderInstance(),
		job.Target(),
		nil,
		"complete",
		nil,
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	validation := domain.ValidationValid
	if job.Purpose() == domain.InvocationRepair {
		validation = domain.ValidationRepairedValid
	}
	if err := output.bindExtractionStates(domain.ParseValid, validation); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}

type coordinatorEvidenceFixtureInput struct {
	severity     domain.Severity
	title        string
	path         string
	lineStart    int
	lineEnd      int
	quote        string
	targetSHA256 string
	targetBytes  string
	availability evidence.ImmutableTargetAvailability
}

func coordinatorEvidenceOutcome(job InvocationJob, input coordinatorEvidenceFixtureInput) AttemptOutcome {
	review, groups, err := coordinatorVerifiedEvidenceFixture(
		job.Role(),
		job.Route().ProviderInstance(),
		input,
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	output, err := NewEvidenceValidatedRoleOutput(
		job.Role(),
		job.Route().ProviderInstance(),
		job.Target(),
		review.Findings(),
		review.Completeness(),
		review.Limitations(),
		groups,
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}

func coordinatorVerifiedEvidenceFixture(
	role domain.Role,
	provider string,
	input coordinatorEvidenceFixtureInput,
) (validation.ValidatedReview, []VerifiedFindingEvidence, error) {
	if input.lineStart == 0 {
		input.lineStart = 1
	}
	if input.lineEnd == 0 {
		input.lineEnd = input.lineStart
	}
	if input.targetSHA256 == "" {
		input.targetSHA256 = coordinatorTestTargetSHA256
	}
	if input.availability == "" {
		input.availability = evidence.ImmutableTargetAvailable
	}

	schemaID, err := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	if err != nil {
		return validation.ValidatedReview{}, nil, err
	}
	validator, err := validation.NewReviewValidator(bridgeSchemaValidator{}, schemaID)
	if err != nil {
		return validation.ValidatedReview{}, nil, err
	}
	raw := fmt.Sprintf(
		`{"schema_version":"mulgae-provider-review-output.v1","summary":"Coordinator evidence fixture.","completeness":"complete","limitations":[],"findings":[{"severity":%q,"title":%q,"description":"Coordinator evidence fixture description.","evidence":[{"current":{"path":%q,"side":"base","line_start":%d,"line_end":%d,"quote":%q}}],"recommendation":"Retain coordinator evidence proof.","confidence":"high"}]}`,
		string(input.severity),
		input.title,
		input.path,
		input.lineStart,
		input.lineEnd,
		input.quote,
	)
	review, repair, err := validator.Validate(context.Background(), []byte(raw), validation.ReviewValidationScope{
		TargetSHA256:     input.targetSHA256,
		Role:             role,
		ProviderInstance: provider,
	})
	if err != nil {
		return validation.ValidatedReview{}, nil, err
	}
	if repair != nil {
		return validation.ValidatedReview{}, nil, fmt.Errorf("unexpected repair plan")
	}
	verifier, err := evidence.NewVerifier(&bridgeImmutableReader{responses: map[string]bridgeReaderResponse{
		bridgeReaderKey(evidence.SideBase, input.path): {
			availability: input.availability,
			bytes:        []byte(input.targetBytes),
		},
	}})
	if err != nil {
		return validation.ValidatedReview{}, nil, err
	}
	groups, err := VerifyValidatedEvidence(context.Background(), verifier, review.EvidenceClaims())
	if err != nil {
		return validation.ValidatedReview{}, nil, err
	}
	return review, groups, nil
}
func coordinatorSubstitutedEvidenceOutcome(job InvocationJob, substitution string) AttemptOutcome {
	base := coordinatorEvidenceFixtureInput{
		severity:     domain.SeverityHigh,
		title:        "first review",
		path:         "src/coordinator-first-review.go",
		quote:        "first\n",
		targetBytes:  "first\n",
		availability: evidence.ImmutableTargetAvailable,
	}
	if substitution == "different-run-target" {
		base.targetSHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
		return coordinatorEvidenceOutcome(job, base)
	}

	outcome := coordinatorEvidenceOutcome(job, base)
	if !outcome.hasOutput || len(outcome.output.evidence) != 1 {
		return coordinatorInternalInvariantOutcome(job)
	}

	_, otherGroups, err := coordinatorVerifiedEvidenceFixture(
		job.Role(),
		job.Route().ProviderInstance(),
		coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "second review",
			path:         "src/coordinator-second-review.go",
			quote:        "second\n",
			targetBytes:  "second\n",
			availability: evidence.ImmutableTargetAvailable,
		},
	)
	if err != nil || len(otherGroups) != 1 || otherGroups[0].FindingID() != "F001" {
		return coordinatorInternalInvariantOutcome(job)
	}

	switch substitution {
	case "two-review-same-F001-swap":
		outcome.output.evidence[0] = otherGroups[0]
	case "path-mismatch":
		outcome.output.evidence[0].receipts[0] = otherGroups[0].Receipts()[0]
	case "range-mismatch":
		bridgeSetReceiptClaimInt(&outcome.output.evidence[0].receipts[0], "lineEnd", 2)
	case "quote-mismatch":
		bridgeSetReceiptClaimBytes(&outcome.output.evidence[0].receipts[0], "quote", []byte("second\n"))
	default:
		return coordinatorInternalInvariantOutcome(job)
	}
	return outcome
}

func coordinatorOutputOutcome(job InvocationJob, output ValidatedRoleOutput) AttemptOutcome {
	outcome, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return outcome
}

func coordinatorInternalInvariantOutcome(job InvocationJob) AttemptOutcome {
	condition := AttemptConditionInternalInvariant
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err != nil {
		return AttemptOutcome{}
	}
	return outcome
}

func coordinatorIncompleteOutcome(_ *testing.T, job InvocationJob) AttemptOutcome {
	output, err := NewValidatedRoleOutput(
		job.Role(),
		job.Route().ProviderInstance(),
		job.Target(),
		nil,
		"incomplete",
		[]string{"The provider could not inspect generated fixtures."},
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}

func coordinatorConditionOutcome(_ *testing.T, job InvocationJob, condition AttemptCondition) AttemptOutcome {
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return outcome
}

func coordinatorRoleByRole(t *testing.T, result CoordinatorResult, role domain.Role) CoordinatorRoleSummary {
	t.Helper()
	for _, summary := range result.RoleSummaries() {
		if summary.Role() == role {
			return summary
		}
	}
	t.Fatalf("result has no summary for role %q", role)
	return CoordinatorRoleSummary{}
}
func coordinatorProtectedContextRaceResult(
	t *testing.T,
	cause AttemptCondition,
	origin domain.Role,
	runDeadline, contextFirst bool,
) CoordinatorResult {
	t.Helper()

	assignments, receipt := coordinatorTestPlanWithInvocationTimeout(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var deadlineSource *coordinatorManualDeadlineContext
	originStarted := make(chan struct{}, 1)
	originCollected := make(chan struct{}, 1)
	releaseOrigin := make(chan struct{})
	var originInvoked atomic.Bool
	runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == origin {
			originStarted <- struct{}{}
			originInvoked.Store(true)
			if contextFirst {
				<-releaseOrigin
			}
			return coordinatorConditionOutcome(t, job, cause)
		}
		if !originInvoked.Load() {
			return coordinatorSuccessOutcome(t, job)
		}
		<-ctx.Done()
		return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, 1, receipt)
	coordinator.resultCollectedHook = func(job InvocationJob) {
		if job.Role() == origin {
			originCollected <- struct{}{}
		}
	}
	if runDeadline {
		deadlineSource = newCoordinatorManualDeadlineContext(ctx)
		coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
			return deadlineSource, func() {}
		}
	}
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()

	<-originStarted
	if contextFirst {
		if runDeadline {
			deadlineSource.expire()
		} else {
			cancel()
		}
		close(releaseOrigin)
	} else {
		<-originCollected
		if runDeadline {
			deadlineSource.expire()
		} else {
			cancel()
		}
	}
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	return execution.result
}

func coordinatorRecordExecution(t *testing.T) *coordinatorExecution {
	t.Helper()

	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	ids := &coordinatorTestIDs{}
	sessionID, err := ids.NewSessionID(now)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := ids.NewRunID(now)
	if err != nil {
		t.Fatal(err)
	}
	tasks := make([]domain.RoleTask, 0, len(domain.CoreRoleOrder()))
	for _, role := range domain.CoreRoleOrder() {
		task, err := domain.NewRoleTask(role, false, "provider."+string(role))
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	_, run, err := domain.NewReviewSession(sessionID, now, runID, coordinatorTestTarget(t), tasks)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.Transition(domain.RunRunning); err != nil {
		t.Fatal(err)
	}
	return &coordinatorExecution{
		run:           &run,
		terminalRoles: make(map[domain.Role]struct{}, len(tasks)),
	}
}

func coordinatorRecordAttempt(t *testing.T, role domain.Role) *coordinatorAttempt {
	t.Helper()
	ids := &coordinatorTestIDs{}
	attemptID, err := ids.NewAttemptID(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := domain.NewInvocation(1, domain.InvocationInitial)
	if err != nil {
		t.Fatal(err)
	}
	route := coordinatorTestRoute(t, "provider."+string(role))
	attempt, err := domain.NewAttempt(attemptID, route.ProviderInstance(), initial)
	if err != nil {
		t.Fatal(err)
	}
	return &coordinatorAttempt{route: route, attempt: attempt}
}

func coordinatorRandomCompletionResult(t *testing.T, assignments []Assignment, receipt RunBudgetReceipt, releaseOrder []domain.Role) CoordinatorResult {
	t.Helper()
	entered := make(chan domain.Role, len(assignments))
	delivered := make(chan domain.Role, len(assignments))
	releases := make(map[domain.Role]chan struct{}, len(assignments))
	for _, role := range domain.CoreRoleOrder() {
		releases[role] = make(chan struct{})
	}
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- job.Role()
		<-releases[job.Role()]
		return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        string(job.Role()),
			path:         "src/coordinator-" + string(job.Role()) + ".go",
			quote:        string(job.Role()) + "\n",
			targetBytes:  string(job.Role()) + "\n",
			availability: evidence.ImmutableTargetAvailable,
		})
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	coordinator.resultCollectedHook = func(job InvocationJob) {
		delivered <- job.Role()
	}
	done := make(chan coordinatorTestExecution, 1)
	go func() {
		result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
		done <- coordinatorTestExecution{result: result, err: err}
	}()
	for range assignments {
		<-entered
	}
	for _, role := range releaseOrder {
		close(releases[role])
		if deliveredRole := <-delivered; deliveredRole != role {
			t.Fatalf("invocation result delivery = %q, want %q", deliveredRole, role)
		}
	}
	execution := <-done
	if execution.err != nil {
		t.Fatal(execution.err)
	}
	return execution.result
}

func coordinatorTraceEventIndex(
	t *testing.T,
	result CoordinatorResult,
	kind CoordinatorEventKind,
	role domain.Role,
) int {
	t.Helper()
	for index, event := range result.Trace() {
		eventRole, hasRole := event.Role()
		if event.Kind() == kind && ((!role.Valid() && !hasRole) || (hasRole && eventRole == role)) {
			return index
		}
	}
	t.Fatalf("trace has no %q event for role %q", kind, role)
	return -1
}

func TestCoordinatorRoleSummaryCarriesProviderOutputTransport(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		return coordinatorStagedFileSuccessOutcome(job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, len(assignments))
	for _, summary := range result.RoleSummaries() {
		want := ports.ProviderOutputTransportStdout
		if summary.Role() == domain.RoleLogic {
			want = ports.ProviderOutputTransportStagedFile
		}
		if !summary.Valid() || summary.OutputTransport() != want {
			t.Fatalf("%q role summary transport = %q valid=%t, want %q", summary.Role(), summary.OutputTransport(), summary.Valid(), want)
		}
	}
}

func coordinatorStagedFileSuccessOutcome(job InvocationJob) AttemptOutcome {
	output, err := NewValidatedRoleOutput(
		job.Role(),
		job.Route().ProviderInstance(),
		job.Target(),
		nil,
		"complete",
		nil,
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	if err := output.bindExtractionStates(domain.ParseValid, domain.ValidationValid); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	if err := output.bindOutputTransport(ports.ProviderOutputTransportStagedFile); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}
