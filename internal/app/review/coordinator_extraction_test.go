package review

import (
	"context"
	"sync"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const coordinatorExtractionReport = "# review\n\nProse only.\n"

func coordinatorReportsOnlyOutcome(t *testing.T, job InvocationJob) AttemptOutcome {
	t.Helper()
	output, err := NewReportsOnlyValidatedRoleOutput(
		job.Role(), job.Route().ProviderInstance(), job.Target(), []byte(coordinatorExtractionReport),
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}

func coordinatorExtractedOutcome(t *testing.T, job InvocationJob) AttemptOutcome {
	t.Helper()
	output, err := NewValidatedRoleOutput(
		job.Role(), job.Route().ProviderInstance(), job.Target(), nil, "complete", nil,
	)
	if err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	if err := output.bindReportMarkdown([]byte(coordinatorExtractionReport), false); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	if err := output.bindOutputTransport(ports.ProviderOutputTransportStdout); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	if err := output.bindExtractionStates(domain.ParseValid, domain.ValidationValid); err != nil {
		return coordinatorInternalInvariantOutcome(job)
	}
	return coordinatorOutputOutcome(job, output)
}

func coordinatorExtractionExecute(
	t *testing.T,
	assignments []Assignment,
	receipt RunBudgetReceipt,
	runtime InvocationRuntime,
	admit bool,
) CoordinatorResult {
	t.Helper()
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	if admit {
		if err := coordinator.AdmitStructuredExtraction(); err != nil {
			t.Fatal(err)
		}
	}
	result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func coordinatorRoleSummary(t *testing.T, result CoordinatorResult, role domain.Role) CoordinatorRoleSummary {
	t.Helper()
	for _, summary := range result.RoleSummaries() {
		if summary.Role() == role {
			return summary
		}
	}
	t.Fatalf("role %q is absent from the coordinator result", role)
	return CoordinatorRoleSummary{}
}

func TestCoordinatorStructuredExtraction(t *testing.T) {
	t.Run("upgrades-a-reports-only-role-on-the-same-attempt", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var mu sync.Mutex
		var purposes []domain.InvocationPurpose
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			mu.Lock()
			purposes = append(purposes, job.Purpose())
			mu.Unlock()
			if job.Purpose() == domain.InvocationExtract {
				return coordinatorExtractedOutcome(t, job)
			}
			return coordinatorReportsOnlyOutcome(t, job)
		}}

		result := coordinatorExtractionExecute(t, assignments, receipt, runtime, true)
		summary := coordinatorRoleSummary(t, result, domain.RoleLogic)
		if summary.State() != domain.RoleTaskSucceeded || summary.ReportsOnly() {
			t.Fatalf("logic summary = state %q reportsOnly=%t", summary.State(), summary.ReportsOnly())
		}
		if len(summary.Attempts()) != 1 {
			t.Fatalf("attempt count = %d, want exactly one attempt per role", len(summary.Attempts()))
		}
		attempt := summary.Attempts()[0]
		if len(attempt.Invocations()) != 2 {
			t.Fatalf("invocation count = %d, want initial plus the extraction trailer", len(attempt.Invocations()))
		}
		if attempt.ParseState() != domain.ParseValid || attempt.ValidationState() != domain.ValidationValid {
			t.Fatalf("attempt extraction states = %q/%q", attempt.ParseState(), attempt.ValidationState())
		}
		mu.Lock()
		defer mu.Unlock()
		want := []domain.InvocationPurpose{domain.InvocationInitial, domain.InvocationExtract}
		if len(purposes) != len(want) || purposes[0] != want[0] || purposes[1] != want[1] {
			t.Fatalf("logic invocation purposes = %#v, want %#v", purposes, want)
		}
	})

	t.Run("failed-extraction-keeps-the-accepted-reports-only-role", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			if job.Purpose() == domain.InvocationExtract {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidProviderOutput)
			}
			return coordinatorReportsOnlyOutcome(t, job)
		}}

		result := coordinatorExtractionExecute(t, assignments, receipt, runtime, true)
		summary := coordinatorRoleSummary(t, result, domain.RoleLogic)
		if summary.State() != domain.RoleTaskSucceeded || !summary.ReportsOnly() || !summary.Valid() {
			t.Fatalf("logic summary = state %q reportsOnly=%t valid=%t",
				summary.State(), summary.ReportsOnly(), summary.Valid())
		}
		for _, other := range result.RoleSummaries() {
			if other.State() != domain.RoleTaskSucceeded {
				t.Fatalf("role %q = %q, a failed extraction must not stop peer roles", other.Role(), other.State())
			}
		}
	})

	t.Run("skips-a-role-that-already-returned-structured-findings", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var mu sync.Mutex
		extractions := 0
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Purpose() == domain.InvocationExtract {
				mu.Lock()
				extractions++
				mu.Unlock()
			}
			return coordinatorSuccessOutcome(t, job)
		}}

		coordinatorExtractionExecute(t, assignments, receipt, runtime, true)
		mu.Lock()
		defer mu.Unlock()
		if extractions != 0 {
			t.Fatalf("extraction invocations = %d, want none for structured roles", extractions)
		}
	})

	t.Run("skips-a-role-that-already-spent-its-second-invocation", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var mu sync.Mutex
		var logicPurposes []domain.InvocationPurpose
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Role() != domain.RoleLogic {
				return coordinatorSuccessOutcome(t, job)
			}
			mu.Lock()
			logicPurposes = append(logicPurposes, job.Purpose())
			mu.Unlock()
			if job.Purpose() == domain.InvocationInitial {
				return coordinatorConditionOutcome(t, job, AttemptConditionInvalidEvidenceClaim)
			}
			return coordinatorReportsOnlyOutcome(t, job)
		}}

		result := coordinatorExtractionExecute(t, assignments, receipt, runtime, true)
		summary := coordinatorRoleSummary(t, result, domain.RoleLogic)
		if !summary.ReportsOnly() {
			t.Fatal("a role that spent its second invocation on repair must stay reports-only")
		}
		mu.Lock()
		defer mu.Unlock()
		for _, purpose := range logicPurposes {
			if purpose == domain.InvocationExtract {
				t.Fatalf("logic purposes = %#v, want no extraction after repair", logicPurposes)
			}
		}
	})

	t.Run("is-not-scheduled-without-admission", func(t *testing.T) {
		assignments, receipt := coordinatorTestPlan(t)
		var mu sync.Mutex
		extractions := 0
		runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
			if job.Purpose() == domain.InvocationExtract {
				mu.Lock()
				extractions++
				mu.Unlock()
			}
			return coordinatorReportsOnlyOutcome(t, job)
		}}

		result := coordinatorExtractionExecute(t, assignments, receipt, runtime, false)
		mu.Lock()
		defer mu.Unlock()
		if extractions != 0 {
			t.Fatalf("extraction invocations = %d, want none when extraction is not admitted", extractions)
		}
		if !coordinatorRoleSummary(t, result, domain.RoleLogic).ReportsOnly() {
			t.Fatal("logic must stay reports-only without extraction")
		}
	})
}

func TestCoordinatorAdmitStructuredExtractionIsOneShot(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	if err := coordinator.AdmitStructuredExtraction(); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AdmitStructuredExtraction(); err == nil {
		t.Fatal("structured extraction admission must be one-shot")
	}
}

// A protected failure observed during extraction keeps its canonical precedence.
// Security, mutation, artifact, configuration, and internal failures never
// authorize publication, so a trailer must not launder one into role success.
func TestCoordinatorExtractionProtectedFailuresKeepAuthority(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionSecurityViolation,
		AttemptConditionMutationViolation,
		AttemptConditionArtifactFailure,
		AttemptConditionConfigurationViolation,
		AttemptConditionInternalInvariant,
	} {
		t.Run(string(condition), func(t *testing.T) {
			if extractionOutcomeIsBounded(extractionProbeJob(t), condition) {
				t.Fatalf("condition %q must not be absorbed by an extraction trailer", condition)
			}
			assignments, receipt := coordinatorTestPlan(t)
			runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
				if job.Purpose() == domain.InvocationExtract {
					return coordinatorConditionOutcome(t, job, condition)
				}
				return coordinatorReportsOnlyOutcome(t, job)
			}}

			result := coordinatorExtractionExecute(t, assignments, receipt, runtime, true)
			// The logic role accepted a prose report and then saw the protected
			// failure on its trailer. It must not be projected as a success.
			summary := coordinatorRoleSummary(t, result, domain.RoleLogic)
			if summary.State() == domain.RoleTaskSucceeded {
				t.Fatalf("condition %q left the logic role succeeded: %#v", condition, summary)
			}
		})
	}
}

// An ordinary transcription failure stays bounded so the accepted report still
// publishes. This is the boundary the protected classes sit above.
func TestCoordinatorExtractionBoundedFailuresAreAbsorbed(t *testing.T) {
	for _, condition := range []AttemptCondition{
		AttemptConditionInvalidProviderOutput,
		AttemptConditionUnrepairableEvidence,
		AttemptConditionProviderTimeout,
		AttemptConditionProviderUnavailable,
	} {
		t.Run(string(condition), func(t *testing.T) {
			if !extractionOutcomeIsBounded(extractionProbeJob(t), condition) {
				t.Fatalf("condition %q must be absorbed by an extraction trailer", condition)
			}
		})
	}
}

func extractionProbeJob(t *testing.T) InvocationJob {
	t.Helper()
	job := coordinatorTypesJob(t, domain.RoleLogic, "fake.logic", 1)
	job.purpose = domain.InvocationExtract
	return job
}

// The run-scoped policy is frozen when execution starts, so a later caller can
// neither change what a running run does nor race its policy read.
func TestCoordinatorAdmitStructuredExtractionRejectedAfterExecution(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, len(assignments), receipt)
	if _, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AdmitStructuredExtraction(); err == nil {
		t.Fatal("structured extraction must not be admitted after execution started")
	}
}
