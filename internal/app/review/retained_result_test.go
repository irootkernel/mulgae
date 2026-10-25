package review

import (
	"context"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestCoordinatorRetainsAcceptedFindingWhenPeerFails(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	for i, assignment := range assignments {
		if assignment.Role() == domain.RoleSecurity {
			required, err := NewScheduledAssignment(assignment.Role(), true, assignment.PrimaryRoute())
			if err != nil {
				t.Fatal(err)
			}
			assignments[i] = required
		}
	}
	runtime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() == domain.RoleLogic {
			return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{severity: domain.SeverityHigh, title: "Retained accepted finding", path: "src/accepted.go", quote: "accepted\n", targetBytes: "accepted\n", availability: evidence.ImmutableTargetAvailable})
		}
		if job.Role() == domain.RoleSecurity {
			return coordinatorConditionOutcome(t, job, AttemptConditionProviderUnavailable)
		}
		return coordinatorSuccessOutcome(t, job)
	}}
	coordinator := coordinatorTestCoordinator(t, runtime, 1, receipt)
	result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunState() != domain.RunFailed || len(result.Findings()) != 1 || len(result.Evidence()) != 1 || result.Findings()[0].ID() != "F001" || result.Findings()[0].Title() != "Retained accepted finding" || result.Findings()[0].EvidenceState() != domain.EvidenceVerified || !result.Evidence()[0].matchesFinding(result.Findings()[0]) {
		t.Fatalf("terminal result lost accepted finding/receipt: %#v", result)
	}
	axes := result.Outcomes()
	if axes.ContentVerdict() != domain.ContentRequestChanges || axes.CoverageStatus() != domain.CoverageIncomplete || axes.PublicationStatus() != domain.PublicationNotPublished {
		t.Fatalf("failure axes = %#v, want request_changes/incomplete/not_published", axes)
	}
	trace := result.Trace()
	if len(trace) == 0 || trace[len(trace)-1].Kind() != CoordinatorEventRunTerminal {
		t.Fatal("failed result trace is not terminal")
	}
	copy := result.Findings()
	copy[0] = domain.Finding{}
	if result.Findings()[0].ID() != "F001" {
		t.Fatal("terminal finding getter aliases caller storage")
	}
}
