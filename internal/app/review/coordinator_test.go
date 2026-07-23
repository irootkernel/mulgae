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

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestCoordinatorScenarios(t *testing.T) {
	t.Run("same-key-serial", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, true, false)
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
		coordinator := coordinatorTestCoordinator(t, runtime, nil, 6, receipt)
		done := make(chan coordinatorTestExecution, 1)
		go func() {
			result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		<-entered
		close(release)
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
		mu.Lock()
		gotMaximum := maximum
		mu.Unlock()
		if gotMaximum != 1 || execution.result.RunState() != domain.RunCompleted {
			t.Fatalf("maximum/run state = %d/%q, want 1/%q", gotMaximum, execution.result.RunState(), domain.RunCompleted)
		}
	})

	t.Run("different-keys-concurrent", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, false)
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
		coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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

	t.Run("repair-before-fallback", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		var sequenceMu sync.Mutex
		var sequence []string
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic {
				sequenceMu.Lock()
				sequence = append(sequence, string(job.AttemptKind())+"/"+string(job.Purpose()))
				sequenceMu.Unlock()
			}
			if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.FallbackScheduled() || len(logic.Attempts()) != 2 || len(logic.Attempts()[0].Invocations()) != 2 {
			t.Fatalf("logic summary did not repair before fallback: %#v", logic)
		}
		sequenceMu.Lock()
		gotSequence := append([]string(nil), sequence...)
		sequenceMu.Unlock()
		wantSequence := []string{"primary/initial", "primary/repair", "fallback/initial"}
		if !reflect.DeepEqual(gotSequence, wantSequence) {
			t.Fatalf("logic invocation order = %q, want %q", gotSequence, wantSequence)
		}
		repairIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventRepairQueued, domain.RoleLogic)
		fallbackIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventFallbackQueued, domain.RoleLogic)
		closeIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventLanesCloseAuthorized, "")
		if !(repairIndex < fallbackIndex && fallbackIndex < closeIndex) {
			t.Fatalf("repair/fallback/close trace order = %d/%d/%d", repairIndex, fallbackIndex, closeIndex)
		}
	})

	t.Run("repair-success-no-fallback", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary && job.Purpose() == domain.InvocationInitial {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidEvidenceClaim)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.Repaired() || logic.FallbackScheduled() || len(logic.Attempts()) != 1 {
			t.Fatalf("logic repair/fallback = repaired:%t fallback:%t attempts:%d", logic.Repaired(), logic.FallbackScheduled(), len(logic.Attempts()))
		}
	})

	t.Run("repair-exhaustion-one-fallback", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		var mu sync.Mutex
		var sequence []string
		fallbackCalls := 0
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			mu.Lock()
			sequence = append(sequence, string(job.AttemptKind())+"/"+string(job.Purpose()))
			if job.AttemptKind() == AttemptKindFallback {
				fallbackCalls++
			}
			mu.Unlock()
			if job.AttemptKind() == AttemptKindPrimary {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			}
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		mu.Lock()
		calls := fallbackCalls
		gotSequence := append([]string(nil), sequence...)
		mu.Unlock()
		if calls != 1 || !logic.FallbackScheduled() || logic.State() != domain.RoleTaskFailed {
			t.Fatalf("fallback calls/state = %d/%t/%q, want 1/true/%q", calls, logic.FallbackScheduled(), logic.State(), domain.RoleTaskFailed)
		}
		wantSequence := []string{"primary/initial", "primary/repair", "fallback/initial"}
		if !reflect.DeepEqual(gotSequence, wantSequence) {
			t.Fatalf("exhaustion invocation order = %q, want %q", gotSequence, wantSequence)
		}
	})

	t.Run("valid-request-changes-no-fallback", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
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
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		if result.FallbackScheduled() || result.Outcomes().ContentVerdict() != domain.ContentRequestChanges {
			t.Fatalf("fallback/content = %t/%q", result.FallbackScheduled(), result.Outcomes().ContentVerdict())
		}
		callsMu.Lock()
		gotLogicCalls := logicCalls
		callsMu.Unlock()
		if gotLogicCalls != 1 {
			t.Fatalf("valid request-changes logic invocations = %d, want 1", gotLogicCalls)
		}
	})

	t.Run("security-dominates-shared-lane-fallback", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, true, true)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
				return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
			}
			if job.Role() == domain.RoleSecurity {
				return coordinatorConditionOutcome(t, job, AttemptConditionSecurityViolation)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		security := coordinatorRoleByRole(t, result, domain.RoleSecurity)
		if result.RunState() != domain.RunCancelled || result.FallbackScheduled() ||
			security.ReasonCode() != string(AttemptConditionSecurityViolation) {
			t.Fatalf("run/fallback/security reason = %q/%t/%q", result.RunState(), result.FallbackScheduled(), security.ReasonCode())
		}
		for _, event := range result.Trace() {
			if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
				t.Fatalf("global security cancellation queued follow-up work: %#v", event)
			}
		}
	})

	t.Run("user-cancel-kills-and-closes", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, false)
		started := make(chan struct{}, len(assignments))
		runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
			started <- struct{}{}
			<-ctx.Done()
			return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
		}}
		coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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

	t.Run("busy-fallback-lane-order", func(t *testing.T) {
		assignments, receipt := coordinatorTestSecurityFallbackSharesLogicLanePlan(t)
		repairEntered := make(chan struct{}, 1)
		fallbackEntered := make(chan struct{}, 1)
		releaseRepair := make(chan struct{})
		repairReturned := make(chan struct{})
		orderViolation := make(chan string, 1)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			switch {
			case job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationInitial:
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			case job.Role() == domain.RoleSecurity && job.AttemptKind() == AttemptKindPrimary:
				return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
			case job.Role() == domain.RoleLogic && job.Purpose() == domain.InvocationRepair:
				repairEntered <- struct{}{}
				<-releaseRepair
				close(repairReturned)
				return coordinatorSuccessOutcome(t, job)
			case job.Role() == domain.RoleSecurity && job.AttemptKind() == AttemptKindFallback:
				select {
				case <-repairReturned:
					fallbackEntered <- struct{}{}
					return coordinatorSuccessOutcome(t, job)
				default:
					orderViolation <- "security fallback bypassed the occupied logic repair lane"
					return coordinatorInternalInvariantOutcome(job)
				}
			default:
				return coordinatorSuccessOutcome(t, job)
			}
		}}
		coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
		done := make(chan coordinatorTestExecution, 1)
		go func() {
			result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
			done <- coordinatorTestExecution{result: result, err: err}
		}()
		<-repairEntered
		close(releaseRepair)
		execution := <-done
		if execution.err != nil {
			t.Fatal(execution.err)
		}
		select {
		case violation := <-orderViolation:
			t.Fatal(violation)
		default:
		}
		<-fallbackEntered
		security := coordinatorRoleByRole(t, execution.result, domain.RoleSecurity)
		if !security.FallbackScheduled() || security.State() != domain.RoleTaskSucceeded {
			t.Fatalf("security fallback did not complete after FIFO wait: %#v", security)
		}
	})

	t.Run("cross-process-lock-failure-typed", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			return coordinatorSuccessOutcome(t, job)
		}}
		locker := coordinatorFailingLocker{key: assignments[0].PrimaryRoute().ConcurrencyKey()}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, locker, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.FallbackScheduled() || len(logic.Attempts()) != 2 || logic.Attempts()[0].State() != domain.AttemptFailed ||
			logic.FailureClass() != domain.FailureProviderUnavailable || logic.ReasonCode() != string(AttemptConditionProviderUnavailable) {
			t.Fatalf("lock failure did not retain typed provider-unavailable terminal state: %#v", logic)
		}
		runtime.mu.Lock()
		invocations := len(runtime.jobs)
		runtime.mu.Unlock()
		if invocations != 0 {
			t.Fatalf("lock failure invoked runtime %d times", invocations)
		}
	})

	t.Run("dynamic-fallback-vs-lane-shutdown", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
				return coordinatorConditionOutcome(t, job, AttemptConditionTimeout)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.FallbackScheduled() || logic.State() != domain.RoleTaskSucceeded {
			t.Fatalf("dynamic fallback state = scheduled:%t state:%q", logic.FallbackScheduled(), logic.State())
		}
		fallbackIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventFallbackQueued, domain.RoleLogic)
		closeIndex := coordinatorTraceEventIndex(t, result, CoordinatorEventLanesCloseAuthorized, "")
		if fallbackIndex >= closeIndex {
			t.Fatalf("fallback was queued after lane close authorization: %d/%d", fallbackIndex, closeIndex)
		}
	})

	t.Run("random-completion-deterministic-aggregation", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, false)
		first := coordinatorRandomCompletionResult(t, assignments, receipt, domain.FixedRoleOrder())
		secondOrder := domain.FixedRoleOrder()
		for left, right := 0, len(secondOrder)-1; left < right; left, right = left+1, right-1 {
			secondOrder[left], secondOrder[right] = secondOrder[right], secondOrder[left]
		}
		second := coordinatorRandomCompletionResult(t, assignments, receipt, secondOrder)
		if !reflect.DeepEqual(first.Findings(), second.Findings()) || !reflect.DeepEqual(first.Trace(), second.Trace()) ||
			!reflect.DeepEqual(first.RoleSummaries(), second.RoleSummaries()) || first.Outcomes() != second.Outcomes() {
			t.Fatal("aggregation changed with lane completion order")
		}
	})
}

func TestCoordinatorExecuteRunPreservesSuppliedRootIdentity(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
		var fallbackProvider *string
		if fallback, ok := assignment.FallbackRoute(); ok {
			provider := fallback.ProviderInstance()
			fallbackProvider = &provider
		}
		task, taskErr := domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.PrimaryRoute().ProviderInstance(), fallbackProvider)
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
	result, err := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt).ExecuteRun(
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

func TestCoordinatorDiagnosticsPersistFailureBeforeFallback(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionProviderUnavailable,
		AttemptConditionTimeout,
		AttemptConditionAuthentication,
		AttemptConditionQuota,
		AttemptConditionRateLimit,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t, false, true)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
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
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, nil, len(assignments), receipt, diagnostics,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.ExecuteRun(context.Background(), &root, assignments, domain.SeverityHigh, nil); err != nil {
				t.Fatal(err)
			}
			want := []domain.RuntimeDiagnosticEventCode{
				domain.DiagnosticAttemptFailed,
				domain.DiagnosticFallbackEligible,
				domain.DiagnosticFallbackScheduled,
				domain.DiagnosticFallbackStarted,
			}
			position := 0
			for _, event := range diagnostics.events {
				if position < len(want) && event == want[position] {
					position++
				}
			}
			if position != len(want) {
				t.Fatalf("%s fallback diagnostic order = %v, missing suffix %v", condition, diagnostics.events, want[position:])
			}
		})
	}
}

func TestCoordinatorDiagnosticsPersistNonFallbackFailureBeforeRoleTerminal(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionUnrepairableProviderOutput,
		AttemptConditionUnrepairableEvidence,
		AttemptConditionSemanticContradiction,
		AttemptConditionConfigurationViolation,
	} {
		t.Run(string(condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t, false, false)
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
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, nil, len(assignments), receipt, diagnostics,
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
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
		coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, nil, len(assignments), receipt, diagnostics,
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

func TestCoordinatorDiagnosticFailureStopsBeforeFallbackScheduling(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, true)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
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
		coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, nil, len(assignments), receipt, diagnostics,
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
		if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindFallback {
			t.Fatal("fallback provider was scheduled after diagnostic persistence failure")
		}
	}
}

func TestCoordinatorDiagnosticsPersistInitiatingCauseBeforeFallbackProhibitionAndPeerCancellation(t *testing.T) {
	for _, test := range []struct {
		condition AttemptCondition
		state     domain.RunState
	}{
		{condition: AttemptConditionLoginRequired, state: domain.RunCancelled},
		{condition: AttemptConditionSecurityViolation, state: domain.RunCancelled},
		{condition: AttemptConditionMutationViolation, state: domain.RunCancelled},
		{condition: AttemptConditionCancelled, state: domain.RunCancelled},
		{condition: AttemptConditionArtifactFailure, state: domain.RunFailed},
		{condition: AttemptConditionInternalInvariant, state: domain.RunFailed},
	} {
		t.Run(string(test.condition), func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t, false, true)
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
				coordinatorTestClock{now: request.StartedAt()}, &coordinatorTestIDs{}, runtime, nil, len(assignments), receipt, diagnostics,
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
			failureIndex, prohibitedIndex, cancellationIndex := -1, -1, -1
			for index, input := range diagnostics.inputs {
				switch input.Event {
				case domain.DiagnosticAttemptFailed:
					if input.Failure == string(test.condition) && failureIndex < 0 {
						failureIndex = index
					}
				case domain.DiagnosticFallbackProhibited:
					if input.Failure == string(test.condition) && prohibitedIndex < 0 {
						prohibitedIndex = index
					}
				case domain.DiagnosticLaneCancelled:
					if cancellationIndex < 0 {
						cancellationIndex = index
					}
				}
			}
			if failureIndex < 0 || prohibitedIndex <= failureIndex || cancellationIndex >= 0 && cancellationIndex <= failureIndex {
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
			assignments, receipt := coordinatorTestPlan(t, false, true)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() == domain.RoleLogic {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorSuccessOutcome(t, job)
			}}
			result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if logic.FallbackScheduled() {
				t.Fatalf("%q scheduled fallback: %#v", condition, logic)
			}
			for _, event := range result.Trace() {
				if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
					t.Fatalf("%q scheduled follow-up event: %#v", condition, event)
				}
			}
			wantState := domain.RunFailed
			if condition == AttemptConditionLoginRequired ||
				condition == AttemptConditionSecurityViolation ||
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
	assignments, receipt := coordinatorTestPlan(t, false, false)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
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
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, 2, receipt)
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
		t.Fatalf("maximum active lanes = %d, want 2", gotMaximum)
	}
}

func TestCoordinatorResultDefensiveCopies(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, 6)
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
		assignments, receipt := coordinatorTestPlan(t, false, false)
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
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
		if len(result.Findings()) != 1 || result.Findings()[0].EvidenceState() != domain.EvidenceVerified ||
			len(result.Evidence()) != 1 || result.Evidence()[0].FindingID() != result.Findings()[0].ID() ||
			coordinatorRoleByRole(t, result, domain.RoleLogic).FallbackScheduled() {
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
			assignments, receipt := coordinatorTestPlan(t, false, true)
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
			result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
			logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
			if !logic.Required() || logic.State() != domain.RoleTaskFailed ||
				logic.ReasonCode() != string(AttemptConditionInvalidEvidenceClaim) ||
				!logic.FallbackScheduled() || len(logic.Attempts()) != 2 ||
				len(logic.Attempts()[0].Invocations()) != 2 || len(logic.Attempts()[1].Invocations()) != 2 ||
				len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
				t.Fatalf("unaccepted high evidence result = role:%#v findings:%#v evidence:%#v",
					logic, result.Findings(), result.Evidence())
			}
		})
	}

	t.Run("default policy accepts unverified low with exact state", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, false)
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
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
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
		assignments, receipt := coordinatorTestPlan(t, false, false)
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
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
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
			assignments, receipt := coordinatorTestPlan(t, false, false)
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
				nil,
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
				logic.FallbackScheduled() || len(logic.Attempts()) != 1 || len(logic.Attempts()[0].Invocations()) != 2 ||
				len(result.Findings()) != 0 || len(result.Evidence()) != 0 {
				t.Fatalf("custom policy result = role:%#v findings:%#v evidence:%#v",
					logic, result.Findings(), result.Evidence())
			}
		})
	}
}

func TestCoordinatorEvidenceInvariantFailsClosedWithoutFallback(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, true)
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
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if logic.State() != domain.RoleTaskFailed || logic.FailureClass() != domain.FailureInternal ||
		logic.ReasonCode() != string(AttemptConditionInternalInvariant) || logic.FallbackScheduled() ||
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
			assignments, receipt := coordinatorTestPlan(t, false, false)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Role() != domain.RoleLogic {
					return coordinatorSuccessOutcome(t, job)
				}
				return coordinatorSubstitutedEvidenceOutcome(job, substitution)
			}}

			result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
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
	assignments, receipt := coordinatorTestPlan(t, false, true)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			return coordinatorSubstitutedEvidenceOutcome(job, "different-run-target")
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
	logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
	if logic.State() != domain.RoleTaskFailed ||
		logic.ReasonCode() != string(AttemptConditionInternalInvariant) ||
		logic.FallbackScheduled() ||
		len(logic.Attempts()) != 1 ||
		len(logic.Attempts()[0].Invocations()) != 1 ||
		len(result.Findings()) != 0 ||
		len(result.Evidence()) != 0 {
		t.Fatalf("verifier-owned target mismatch escaped fail-closed handling: role:%#v findings:%#v evidence:%#v",
			logic, result.Findings(), result.Evidence())
	}
}

func TestCoordinatorEvidenceCancellationPreventsAcceptance(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	result, err := coordinatorTestCoordinator(t, runtime, nil, 1, receipt).Execute(
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
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
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
	assignments, receipt := coordinatorTestPlanWithLogicFallbackLimits(t)
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
		if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindPrimary {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}
		if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindFallback {
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{
				severity:     domain.SeverityHigh,
				title:        "request changes",
				path:         "src/coordinator-fallback-request-changes.go",
				quote:        "request changes\n",
				targetBytes:  "request changes\n",
				availability: evidence.ImmutableTargetAvailable,
			})
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	policy := &domain.CIPolicy{RequestChangesFails: false, DegradedReviewFails: false, IncompleteReviewFails: false}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
	if len(jobs) != len(assignments)+1 {
		t.Fatalf("invocation count = %d, want %d", len(jobs), len(assignments)+1)
	}
	for _, job := range jobs {
		if job.Target() != target {
			t.Fatalf("job %d target = %#v, want %#v", job.Ordinal(), job.Target(), target)
		}
		limits := job.Limits()
		if job.Role() == domain.RoleLogic && job.AttemptKind() == AttemptKindFallback {
			if limits.Timeout() != 2*time.Second || limits.MaxStdoutBytes() != 2 || limits.MaxStderrBytes() != 3 {
				t.Fatalf("fallback job %d limits = %#v, want fallback receipt limits", job.Ordinal(), limits)
			}
			continue
		}
		if limits.Timeout() != time.Second || limits.MaxStdoutBytes() != 1 || limits.MaxStderrBytes() != 1 {
			t.Fatalf("job %d limits = %#v, want primary receipt limits", job.Ordinal(), limits)
		}
	}
}

func TestCoordinatorRejectsPrecancelledContextBeforeIssuingIDs(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	ids := &coordinatorCountingIDs{}
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		t.Fatalf("pre-cancelled coordinator invoked job %d", job.Ordinal())
		return AttemptOutcome{}
	}}
	coordinator, err := NewCoordinator(
		coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		ids,
		runtime,
		nil,
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

func TestCoordinatorsRespectSharedLaneAuthorityAcrossRuns(t *testing.T) {
	t.Run("disjoint keys overlap", func(t *testing.T) {
		firstAssignments, firstReceipt := coordinatorTestPlanInNamespace(t, "first.", false, false)
		secondAssignments, secondReceipt := coordinatorTestPlanInNamespace(t, "second.", false, false)
		entered := make(chan string, len(firstAssignments)+len(secondAssignments))
		release := make(chan struct{})
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			entered <- job.Route().ProviderInstance()
			<-release
			return coordinatorSuccessOutcome(t, job)
		}}
		processLimit := len(firstAssignments) + len(secondAssignments)
		first := coordinatorTestCoordinator(t, runtime, nil, processLimit, firstReceipt)
		second := coordinatorTestCoordinator(t, runtime, nil, processLimit, secondReceipt)
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
				t.Fatal("disjoint-key coordinators did not overlap")
			}
		}
		close(release)
		for range 2 {
			execution := <-done
			if execution.err != nil {
				t.Fatal(execution.err)
			}
			if execution.result.RunState() != domain.RunCompleted {
				t.Fatalf("disjoint-key run state = %q, want completed", execution.result.RunState())
			}
		}
	})

	t.Run("equal keys remain serialized", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, false)
		entered := make(chan struct{}, len(assignments)*2)
		release := make(chan struct{})
		var mu sync.Mutex
		active := make(map[string]int, len(assignments))
		maximum := make(map[string]int, len(assignments))
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			key := job.Route().ConcurrencyKey().String()
			mu.Lock()
			active[key]++
			if active[key] > maximum[key] {
				maximum[key] = active[key]
			}
			mu.Unlock()
			entered <- struct{}{}
			<-release
			mu.Lock()
			active[key]--
			mu.Unlock()
			return coordinatorSuccessOutcome(t, job)
		}}
		first := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
		second := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
		done := make(chan coordinatorTestExecution, 2)
		for _, coordinator := range []*Coordinator{first, second} {
			go func(coordinator *Coordinator) {
				result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
				done <- coordinatorTestExecution{result: result, err: err}
			}(coordinator)
		}
		for range assignments {
			<-entered
		}
		close(release)
		for range 2 {
			execution := <-done
			if execution.err != nil {
				t.Fatal(execution.err)
			}
			if execution.result.RunState() != domain.RunCompleted {
				t.Fatalf("same-key run state = %q, want completed", execution.result.RunState())
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if len(maximum) != len(assignments) {
			t.Fatalf("observed %d keyed lanes, want %d", len(maximum), len(assignments))
		}
		for key, observed := range maximum {
			if observed != 1 {
				t.Fatalf("maximum concurrency for key %q = %d, want 1", key, observed)
			}
		}
	})
}
func TestCoordinatorCommitsEveryCollectedStoppingWaveFact(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
		assignments, receipt := coordinatorTestPlan(t, false, false)
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
		coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
	assignments, receipt := coordinatorTestPlan(t, false, true)
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
	if execution.result.RunState() != domain.RunCancelled || execution.result.FallbackScheduled() {
		t.Fatalf("protected early stop = run:%q fallback:%t",
			execution.result.RunState(), execution.result.FallbackScheduled())
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
	assignments, receipt := coordinatorTestPlan(t, false, true)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleSecurity {
			return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
		result.FallbackScheduled() ||
		security.State() != domain.RoleTaskCancelled ||
		security.ReasonCode() != string(AttemptConditionCancelled) {
		t.Fatalf("commit-time cancellation = run:%q fallback:%t security:%#v",
			result.RunState(), result.FallbackScheduled(), security)
	}
	cancellationIndex, securityTerminalIndex := -1, -1
	for index, event := range result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
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
	assignments, receipt := coordinatorTestPlan(t, false, true)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleSecurity {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
		result.FallbackScheduled() ||
		security.State() != domain.RoleTaskFailed ||
		security.ReasonCode() != string(AttemptConditionTimeout) {
		t.Fatalf("commit-time deadline = run:%q fallback:%t security:%#v",
			result.RunState(), result.FallbackScheduled(), security)
	}
	for _, event := range result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
			t.Fatalf("commit-time deadline queued follow-up work: %#v", event)
		}
	}
}

func TestCoordinatorWaveBarrierPrecedesEveryRuntimeStart(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	entered := make(chan domain.Role, len(assignments))
	release := make(chan struct{})
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- job.Role()
		<-release
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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

func TestCoordinatorRunDeadlineBeforeLaneCloseForcesFailedRun(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
	coordinator.runContextFactory = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		return deadlineSource, func() {}
	}
	coordinator.beforeLanesCloseLinearizationHook = deadlineSource.expire

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
		case CoordinatorEventLanesCloseAuthorized:
			closeIndex = index
		}
	}
	if cancellationIndex < 0 || closeIndex < 0 || cancellationIndex >= closeIndex {
		t.Fatalf("pre-close deadline trace order = timeout:%d close:%d trace:%#v",
			cancellationIndex, closeIndex, result.Trace())
	}
}
func TestCoordinatorParentCancellationUpgradesPreCloseTimeout(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	deadlineSource := newCoordinatorManualDeadlineContext(context.Background())
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
	coordinator.beforeLanesCloseLinearizationHook = cancel

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
		case CoordinatorEventLanesCloseAuthorized:
			closeIndex = index
		}
	}
	want := []AttemptCondition{AttemptConditionTimeout, AttemptConditionCancelled}
	if !reflect.DeepEqual(stopConditions, want) || closeIndex < 0 {
		t.Fatalf("timeout/cancellation stop trace = conditions:%q close:%d, want %q and close",
			stopConditions, closeIndex, want)
	}
}
func TestCoordinatorIgnoresCancellationAfterLaneCloseLinearization(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coordinator.lanesCloseAuthorizedHook = cancel

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
func TestCoordinatorsShareProcessActiveLaneLimit(t *testing.T) {
	firstAssignments, firstReceipt := coordinatorTestPlanInNamespace(t, "capacity.first.", false, false)
	secondAssignments, secondReceipt := coordinatorTestPlanInNamespace(t, "capacity.second.", false, false)
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
	first := coordinatorTestCoordinator(t, runtime, nil, processLimit, firstReceipt)
	second := coordinatorTestCoordinator(t, runtime, nil, processLimit, secondReceipt)
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
		t.Fatalf("process-wide active lane maximum = %d, want %d", maximum, processLimit)
	}
}
func TestProcessActiveLaneAuthorityUsesOneMixedLimitPool(t *testing.T) {
	target := coordinatorTestTarget(t)
	limits, err := NewInvocationLimits(time.Minute, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	newJob := func(role domain.Role, provider, lane string, ordinal uint64) InvocationJob {
		job, err := NewInvocationJob(
			role,
			AttemptKindPrimary,
			coordinatorTestRoute(t, provider, lane),
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
	wideJob := newJob(domain.RoleLogic, "mixed-wide", "mixed-wide", 1)
	narrowJob := newJob(domain.RoleSecurity, "mixed-narrow", "mixed-narrow", 2)

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

	wide := newLaneScheduler(context.Background(), runtime, nil, 3, 1)
	narrow := newLaneScheduler(context.Background(), runtime, nil, 1, 1)
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
						if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
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
	assignments, receipt := coordinatorTestPlanWithInvocationTimeout(t, false, true, time.Minute)
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
	if logic.FallbackScheduled() || logic.ReasonCode() != string(AttemptConditionTimeout) ||
		execution.result.RunState() != domain.RunFailed {
		t.Fatalf("deadline/provider race = run:%q logic:%#v", execution.result.RunState(), logic)
	}
	for _, event := range execution.result.Trace() {
		if event.Kind() == CoordinatorEventRepairQueued || event.Kind() == CoordinatorEventFallbackQueued {
			t.Fatalf("deadline/provider race queued follow-up work: %#v", event)
		}
	}
}

func TestCoordinatorPostAdmissionFailureReturnsTerminalSnapshot(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
		nil,
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
		if err := execution.record(CoordinatorEventLanesCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
			t.Fatal("record authorized lanes close before roles were terminal")
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
			t.Fatal("record accepted terminal before lanes close and terminal run state")
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
			for _, role := range domain.FixedRoleOrder() {
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
			if err := execution.record(CoordinatorEventLanesCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err != nil {
				t.Fatal(err)
			}
			if err := execution.record(CoordinatorEventLanesCloseAuthorized, domain.Role(""), nil, nil, nil, "", domain.RunState("")); err == nil {
				t.Fatal("record accepted duplicate lanes close authorization")
			}
			if err := execution.run.Transition(closure.runState); err != nil {
				t.Fatal(err)
			}
			if err := execution.record(CoordinatorEventRunTerminal, domain.Role(""), nil, nil, nil, "", closure.runState); err != nil {
				t.Fatal(err)
			}
			trace := execution.trace
			if len(trace) != len(domain.FixedRoleOrder())+3 ||
				trace[0].Kind() != CoordinatorEventRunStarted ||
				trace[len(trace)-2].Kind() != CoordinatorEventLanesCloseAuthorized ||
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
	lane := job.Route().ConcurrencyKey()
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
			event.attemptKind = AttemptKindPrimary
			event.lane = lane
			event.hasLane = true
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
		case CoordinatorEventFallbackQueued:
			setAttempt()
			event.condition, event.hasCondition = providerUnavailable, true
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
		CoordinatorEventFallbackQueued,
		CoordinatorEventRoleTerminal,
		CoordinatorEventCancellationRequested,
		CoordinatorEventLanesCloseAuthorized,
		CoordinatorEventRunTerminal,
	} {
		if err := eventFor(kind).validate(); err != nil {
			t.Errorf("valid %q event rejected: %v", kind, err)
		}
	}

	attemptlessTerminal := eventFor(CoordinatorEventRoleTerminal)
	attemptlessTerminal.hasAttempt = false
	attemptlessTerminal.attemptID = domain.AttemptID{}
	attemptlessTerminal.attemptKind = ""
	attemptlessTerminal.hasLane = false
	attemptlessTerminal.lane = ports.ConcurrencyKey{}
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
		{name: "fallback mismatched reason", kind: CoordinatorEventFallbackQueued, mutate: func(event *CoordinatorTraceEvent) {
			event.reason = string(AttemptConditionTimeout)
		}},
		{name: "terminal has purpose", kind: CoordinatorEventRoleTerminal, mutate: func(event *CoordinatorTraceEvent) {
			event.purpose, event.hasPurpose = purpose, true
		}},
		{name: "cancellation has role", kind: CoordinatorEventCancellationRequested, mutate: func(event *CoordinatorTraceEvent) {
			event.role = domain.RoleLogic
		}},
		{name: "lanes close has condition", kind: CoordinatorEventLanesCloseAuthorized, mutate: func(event *CoordinatorTraceEvent) {
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
func TestLaneReducerPreservesHigherPriorityReleaseFacts(t *testing.T) {
	key, err := ports.ParseConcurrencyKey("lane")
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []AttemptCondition{
		AttemptConditionSecurityViolation,
		AttemptConditionMutationViolation,
		AttemptConditionArtifactFailure,
		AttemptConditionInternalInvariant,
	} {
		t.Run(string(condition), func(t *testing.T) {
			job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, invocation InvocationJob) AttemptOutcome {
				return coordinatorConditionOutcome(t, invocation, condition)
			}}
			scheduler := newLaneScheduler(
				context.Background(),
				runtime,
				coordinatorReleaseFailLocker{key: key},
				1,
				1,
			)
			if !scheduler.submit(job) {
				t.Fatal("scheduler rejected job")
			}
			result := <-scheduler.results
			scheduler.close()
			got, ok := result.outcome.Condition()
			if !ok || got != condition {
				t.Fatalf("release failure reduced %q to %q/%t", condition, got, ok)
			}
		})
	}
}
func TestLaneConfigurationAndDeadlineReductionIsFailClosed(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	invalid := coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
	scheduler := newLaneScheduler(context.Background(), &coordinatorTestRuntime{}, nil, 1, 1)
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

func TestLaneRejectsTypedNilLeaseWithoutInvocation(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	invoked := make(chan struct{}, 1)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, _ InvocationJob) AttemptOutcome {
		invoked <- struct{}{}
		return AttemptOutcome{}
	}}
	scheduler := newLaneScheduler(context.Background(), runtime, coordinatorTypedNilLeaseLocker{}, 1, 1)
	if !scheduler.submit(job) {
		t.Fatal("scheduler rejected job")
	}
	result := <-scheduler.results
	scheduler.close()
	condition, ok := result.outcome.Condition()
	if !ok || condition != AttemptConditionInternalInvariant {
		t.Fatalf("typed-nil lease condition = %q/%t, want internal invariant", condition, ok)
	}
	select {
	case <-invoked:
		t.Fatal("typed-nil lease reached invocation runtime")
	default:
	}
}

func TestLaneRejectsWrongKeyLeaseWithoutInvocation(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	otherKey, err := ports.ParseConcurrencyKey("other-lane")
	if err != nil {
		t.Fatal(err)
	}
	lease := &coordinatorWrongKeyLease{key: otherKey}
	invoked := make(chan struct{}, 1)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		invoked <- struct{}{}
		return coordinatorSuccessOutcome(t, job)
	}}
	scheduler := newLaneScheduler(context.Background(), runtime, coordinatorWrongKeyLocker{lease: lease}, 1, 1)
	if !scheduler.submit(job) {
		t.Fatal("scheduler rejected job")
	}
	result := <-scheduler.results
	scheduler.close()
	condition, ok := result.outcome.Condition()
	if !ok || condition != AttemptConditionInternalInvariant {
		t.Fatalf("wrong-key lease condition = %q/%t, want internal invariant", condition, ok)
	}
	select {
	case <-invoked:
		t.Fatal("wrong-key lease reached invocation runtime")
	default:
	}
	if releases := lease.releaseCount(); releases != 1 {
		t.Fatalf("wrong-key lease releases = %d, want 1", releases)
	}
}
func TestLaneAcquisitionConditionUsesClosedFailureClass(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want AttemptCondition
	}{
		{
			name: "unavailable",
			err:  coordinatorLaneAcquisitionError{class: ports.LaneAcquisitionUnavailable},
			want: AttemptConditionProviderUnavailable,
		},
		{
			name: "configuration",
			err:  coordinatorLaneAcquisitionError{class: ports.LaneAcquisitionConfiguration},
			want: AttemptConditionConfigurationViolation,
		},
		{
			name: "security",
			err:  coordinatorLaneAcquisitionError{class: ports.LaneAcquisitionSecurity},
			want: AttemptConditionSecurityViolation,
		},
		{
			name: "internal",
			err:  coordinatorLaneAcquisitionError{class: ports.LaneAcquisitionInternal},
			want: AttemptConditionInternalInvariant,
		},
		{
			name: "unknown",
			err:  errors.New("unclassified lane error"),
			want: AttemptConditionInternalInvariant,
		},
		{
			name: "cancelled",
			err:  context.Canceled,
			want: AttemptConditionCancelled,
		},
		{
			name: "timeout",
			err:  context.DeadlineExceeded,
			want: AttemptConditionTimeout,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := laneAcquisitionCondition(test.err); got != test.want {
				t.Fatalf("laneAcquisitionCondition() = %q, want %q", got, test.want)
			}
		})
	}
}
func TestLaneAdmissionGatePrecedesRuntimeExecution(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	entered := make(chan struct{}, 1)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		entered <- struct{}{}
		return coordinatorSuccessOutcome(t, job)
	}}
	scheduler := newLaneScheduler(context.Background(), runtime, nil, 1, 1)
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

func TestLaneInvocationDeadlineBoundsLockAndRuntime(t *testing.T) {
	for _, test := range []struct {
		name    string
		locker  ports.LaneLocker
		runtime InvocationRuntime
	}{
		{
			name:   "lock",
			locker: coordinatorContextBlockingLocker{},
			runtime: &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				t.Fatalf("lock timeout reached runtime for job %d", job.Ordinal())
				return AttemptOutcome{}
			}},
		},
		{
			name: "runtime",
			runtime: &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
				<-ctx.Done()
				return coordinatorConditionOutcome(t, job, AttemptConditionCancelled)
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits, err := NewInvocationLimits(100*time.Millisecond, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			job, err := NewInvocationJob(
				domain.RoleLogic,
				AttemptKindPrimary,
				coordinatorTestRoute(t, "provider", "deadline-lane"),
				coordinatorTestTarget(t),
				limits,
				coordinatorTypesAttemptID(t, 42),
				domain.InvocationInitial,
				1,
			)
			if err != nil {
				t.Fatal(err)
			}
			scheduler := newLaneScheduler(context.Background(), test.runtime, test.locker, 1, 1)
			if !scheduler.submit(job) {
				t.Fatal("scheduler rejected job")
			}
			result := <-scheduler.results
			scheduler.close()
			condition, ok := result.outcome.Condition()
			if !ok || condition != AttemptConditionTimeout {
				t.Fatalf("deadline condition = %q/%t, want timeout", condition, ok)
			}
		})
	}
}
func TestCoordinatorOutcomeAxesKeepExhaustionAndFindingsIndependent(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
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
	result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
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
		assignments, receipt := coordinatorTestPlan(t, false, false)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleMaintainability {
				return coordinatorIncompleteOutcome(t, job)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
		if result.RunState() != domain.RunCompleted || result.Outcomes().CoverageStatus() != domain.CoverageDegraded {
			t.Fatalf("optional incomplete result = run:%q coverage:%q", result.RunState(), result.Outcomes().CoverageStatus())
		}
	})

	t.Run("primary and fallback repair bound", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t, false, true)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() == domain.RoleLogic {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			}
			return coordinatorSuccessOutcome(t, job)
		}}
		result := coordinatorTestExecute(t, assignments, receipt, runtime, nil, len(assignments))
		logic := coordinatorRoleByRole(t, result, domain.RoleLogic)
		if !logic.FallbackScheduled() || len(logic.Attempts()) != 2 ||
			len(logic.Attempts()[0].Invocations()) != 2 || len(logic.Attempts()[1].Invocations()) != 2 {
			t.Fatalf("logic did not stop at primary+fallback four-invocation bound: %#v", logic)
		}
	})
}

func TestCoordinatorInvalidProperties(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t, false, false)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	clock := coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)}
	ids := &coordinatorTestIDs{}
	if _, err := NewCoordinator(clock, ids, runtime, nil, 0, receipt); err == nil {
		t.Fatal("NewCoordinator accepted a zero active-lane limit")
	}
	if _, err := NewCoordinator(clock, ids, runtime, nil, 1, RunBudgetReceipt{}); err == nil {
		t.Fatal("NewCoordinator accepted an ineligible receipt")
	}
	if _, err := NewCoordinatorWithEvidencePolicy(clock, ids, runtime, nil, 1, receipt, EvidencePolicy{}); err == nil {
		t.Fatal("NewCoordinatorWithEvidencePolicy accepted an invalid policy")
	}
	coordinator := coordinatorTestCoordinator(t, runtime, nil, 1, receipt)
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
		var fallbackProvider *string
		if fallback, ok := assignment.FallbackRoute(); ok {
			provider := fallback.ProviderInstance()
			fallbackProvider = &provider
		}
		task, taskErr := domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.PrimaryRoute().ProviderInstance(), fallbackProvider)
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

type coordinatorFailingLocker struct{ key ports.ConcurrencyKey }

func (locker coordinatorFailingLocker) Acquire(context.Context, ports.ConcurrencyKey) (ports.LaneLease, error) {
	return nil, coordinatorLaneAcquisitionError{class: ports.LaneAcquisitionUnavailable}
}

type coordinatorLaneAcquisitionError struct {
	class ports.LaneAcquisitionFailureClass
}

func (err coordinatorLaneAcquisitionError) Error() string {
	return "cross-process lock acquisition failed"
}

func (err coordinatorLaneAcquisitionError) LaneAcquisitionFailureClass() ports.LaneAcquisitionFailureClass {
	return err.class
}

type coordinatorReleaseFailLocker struct{ key ports.ConcurrencyKey }

func (locker coordinatorReleaseFailLocker) Acquire(context.Context, ports.ConcurrencyKey) (ports.LaneLease, error) {
	return &coordinatorTestLease{key: locker.key, releaseErr: errors.New("release failed")}, nil
}

type coordinatorTypedNilLeaseLocker struct{}

func (coordinatorTypedNilLeaseLocker) Acquire(context.Context, ports.ConcurrencyKey) (ports.LaneLease, error) {
	var lease *coordinatorTestLease
	return lease, nil
}

type coordinatorContextBlockingLocker struct{}

func (coordinatorContextBlockingLocker) Acquire(ctx context.Context, _ ports.ConcurrencyKey) (ports.LaneLease, error) {
	<-ctx.Done()
	return nil, ctx.Err()
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

type coordinatorTestLease struct {
	key        ports.ConcurrencyKey
	releaseErr error
}

func (lease *coordinatorTestLease) Key() ports.ConcurrencyKey { return lease.key }

func (lease *coordinatorTestLease) Release() error { return lease.releaseErr }

type coordinatorWrongKeyLocker struct {
	lease *coordinatorWrongKeyLease
}

func (locker coordinatorWrongKeyLocker) Acquire(context.Context, ports.ConcurrencyKey) (ports.LaneLease, error) {
	return locker.lease, nil
}

type coordinatorWrongKeyLease struct {
	key ports.ConcurrencyKey

	mu       sync.Mutex
	releases int
}

func (lease *coordinatorWrongKeyLease) Key() ports.ConcurrencyKey {
	return lease.key
}

func (lease *coordinatorWrongKeyLease) Release() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.releases++
	return nil
}

func (lease *coordinatorWrongKeyLease) releaseCount() int {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.releases
}

func coordinatorTestPlan(t *testing.T, sameLane, logicFallback bool) ([]Assignment, RunBudgetReceipt) {
	t.Helper()
	return coordinatorTestPlanInNamespace(t, "", sameLane, logicFallback)
}

func coordinatorTestPlanInNamespace(
	t *testing.T,
	namespace string,
	sameLane, logicFallback bool,
) ([]Assignment, RunBudgetReceipt) {
	t.Helper()
	assignments := make([]Assignment, 0, len(domain.FixedRoleOrder()))
	budgets := make([]RoleBudget, 0, len(domain.FixedRoleOrder()))
	limits, err := NewInvocationLimits(time.Second, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range domain.FixedRoleOrder() {
		lane := namespace + "lane-" + string(role)
		if sameLane {
			lane = namespace + "shared"
		}
		primary := coordinatorTestRoute(t, namespace+"primary."+string(role), lane)
		primaryBudget, err := NewRouteBudget(primary, limits)
		if err != nil {
			t.Fatal(err)
		}
		var fallbackRoute *ports.ProviderRoute
		var fallbackBudget *RouteBudget
		if logicFallback && role == domain.RoleLogic {
			fallback := coordinatorTestRoute(t, namespace+"fallback.logic", namespace+"fallback-logic")
			fallbackRoute = &fallback
			budget, err := NewRouteBudget(fallback, limits)
			if err != nil {
				t.Fatal(err)
			}
			fallbackBudget = &budget
		}
		assignment, err := NewScheduledAssignment(role, false, primary, fallbackRoute)
		if err != nil {
			t.Fatal(err)
		}
		roleBudget, err := NewRoleBudget(role, primaryBudget, fallbackBudget)
		if err != nil {
			t.Fatal(err)
		}
		assignments = append(assignments, assignment)
		budgets = append(budgets, roleBudget)
	}
	receipt, err := PreflightRunBudget(budgets, DefaultHarnessCeilings())
	if err != nil {
		t.Fatal(err)
	}
	return assignments, receipt
}
func coordinatorTestPlanWithInvocationTimeout(
	t *testing.T,
	sameLane, logicFallback bool,
	timeout time.Duration,
) ([]Assignment, RunBudgetReceipt) {
	t.Helper()

	assignments, receipt := coordinatorTestPlan(t, sameLane, logicFallback)
	limits, err := NewInvocationLimits(timeout, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	budgets := receipt.RoleBudgets()
	for index, budget := range budgets {
		primary, err := NewRouteBudget(budget.Primary().Route(), limits)
		if err != nil {
			t.Fatal(err)
		}
		var fallbackBudget *RouteBudget
		if fallback, ok := budget.Fallback(); ok {
			updatedFallback, err := NewRouteBudget(fallback.Route(), limits)
			if err != nil {
				t.Fatal(err)
			}
			fallbackBudget = &updatedFallback
		}
		updated, err := NewRoleBudget(budget.Role(), primary, fallbackBudget)
		if err != nil {
			t.Fatal(err)
		}
		budgets[index] = updated
	}
	receipt, err = PreflightRunBudget(budgets, receipt.Ceilings())
	if err != nil {
		t.Fatal(err)
	}
	return assignments, receipt
}
func coordinatorTestPlanWithLogicFallbackLimits(t *testing.T) ([]Assignment, RunBudgetReceipt) {
	t.Helper()

	assignments, receipt := coordinatorTestPlan(t, false, true)
	budgets := receipt.RoleBudgets()
	for index, budget := range budgets {
		if budget.Role() != domain.RoleLogic {
			continue
		}
		fallback, ok := budget.Fallback()
		if !ok {
			t.Fatal("logic fallback budget is missing")
		}
		limits, err := NewInvocationLimits(2*time.Second, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		updatedFallback, err := NewRouteBudget(fallback.Route(), limits)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := NewRoleBudget(domain.RoleLogic, budget.Primary(), &updatedFallback)
		if err != nil {
			t.Fatal(err)
		}
		budgets[index] = updated
		break
	}
	updatedReceipt, err := PreflightRunBudget(budgets, receipt.Ceilings())
	if err != nil {
		t.Fatal(err)
	}
	return assignments, updatedReceipt
}
func coordinatorTestSecurityFallbackSharesLogicLanePlan(t *testing.T) ([]Assignment, RunBudgetReceipt) {
	t.Helper()

	assignments, receipt := coordinatorTestPlan(t, false, false)
	budgets := receipt.RoleBudgets()
	var logicRoute ports.ProviderRoute
	for _, assignment := range assignments {
		if assignment.Role() == domain.RoleLogic {
			logicRoute = assignment.PrimaryRoute()
			break
		}
	}
	for index, assignment := range assignments {
		if assignment.Role() != domain.RoleSecurity {
			continue
		}
		fallback := coordinatorTestRoute(t, "fallback.security", logicRoute.ConcurrencyKey().String())
		updated, err := NewScheduledAssignment(domain.RoleSecurity, assignment.Required(), assignment.PrimaryRoute(), &fallback)
		if err != nil {
			t.Fatal(err)
		}
		assignments[index] = updated
		for budgetIndex, budget := range budgets {
			if budget.Role() != domain.RoleSecurity {
				continue
			}
			fallbackBudget, err := NewRouteBudget(fallback, budget.Primary().Limits())
			if err != nil {
				t.Fatal(err)
			}
			updatedBudget, err := NewRoleBudget(domain.RoleSecurity, budget.Primary(), &fallbackBudget)
			if err != nil {
				t.Fatal(err)
			}
			budgets[budgetIndex] = updatedBudget
			break
		}
		break
	}
	updatedReceipt, err := PreflightRunBudget(budgets, receipt.Ceilings())
	if err != nil {
		t.Fatal(err)
	}
	return assignments, updatedReceipt
}

func coordinatorTestRoute(t *testing.T, provider, lane string) ports.ProviderRoute {
	t.Helper()
	key, err := ports.ParseConcurrencyKey(lane)
	if err != nil {
		t.Fatal(err)
	}
	route, err := ports.NewProviderRoute(provider, key)
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

func coordinatorTestCoordinator(t *testing.T, runtime InvocationRuntime, locker ports.LaneLocker, maxActive int, receipt RunBudgetReceipt) *Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(
		coordinatorTestClock{now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		&coordinatorTestIDs{},
		runtime,
		locker,
		maxActive,
		receipt,
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
	locker ports.LaneLocker,
	maxActive int,
) CoordinatorResult {
	t.Helper()
	result, err := coordinatorTestCoordinator(t, runtime, locker, maxActive, receipt).Execute(
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
		`{"schema_version":"kar-provider-review-output.v2","summary":"Coordinator evidence fixture.","completeness":"complete","limitations":[],"findings":[{"severity":%q,"title":%q,"description":"Coordinator evidence fixture description.","evidence":[{"current":{"path":%q,"side":"base","line_start":%d,"line_end":%d,"quote":%q}}],"recommendation":"Retain coordinator evidence proof.","confidence":"high"}]}`,
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

	assignments, receipt := coordinatorTestPlanWithInvocationTimeout(t, true, false, time.Minute)
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, 1, receipt)
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
	tasks := make([]domain.RoleTask, 0, len(domain.FixedRoleOrder()))
	for _, role := range domain.FixedRoleOrder() {
		task, err := domain.NewRoleTask(role, false, "provider."+string(role), nil)
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
	route := coordinatorTestRoute(t, "provider."+string(role), "record-"+string(role))
	attempt, err := domain.NewAttempt(attemptID, route.ProviderInstance(), initial)
	if err != nil {
		t.Fatal(err)
	}
	return &coordinatorAttempt{kind: AttemptKindPrimary, route: route, attempt: attempt}
}

func coordinatorRandomCompletionResult(t *testing.T, assignments []Assignment, receipt RunBudgetReceipt, releaseOrder []domain.Role) CoordinatorResult {
	t.Helper()
	entered := make(chan domain.Role, len(assignments))
	delivered := make(chan domain.Role, len(assignments))
	releases := make(map[domain.Role]chan struct{}, len(assignments))
	for _, role := range domain.FixedRoleOrder() {
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
	coordinator := coordinatorTestCoordinator(t, runtime, nil, len(assignments), receipt)
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
			t.Fatalf("lane result delivery = %q, want %q", deliveredRole, role)
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
