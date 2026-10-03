package review

import (
	"context"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type coordinatorLiveReader struct{ target ports.LiveSourceTarget }

func (coordinatorLiveReader) Root() ports.AnchoredRoot { return ports.AnchoredRoot{} }
func (coordinatorLiveReader) RevalidateExecution(context.Context) (ports.ProjectBindingObservation, error) {
	return ports.ProjectBindingObservation{}, nil
}
func (reader coordinatorLiveReader) List(context.Context, domain.LiveSourceSide) ([]ports.SafeRelativePath, error) {
	path, _ := ports.NewSafeRelativePath("source.go")
	return []ports.SafeRelativePath{path}, nil
}
func (reader coordinatorLiveReader) Target() ports.LiveSourceTarget { return reader.target }
func (reader coordinatorLiveReader) Read(_ context.Context, side domain.LiveSourceSide, path ports.SafeRelativePath) (ports.LiveSourceFile, error) {
	if side != domain.LiveSourceWorktree || path.String() != "source.go" {
		return ports.LiveSourceFile{}, fmt.Errorf("unexpected live read")
	}
	return ports.NewLiveSourceFile(path, []byte("observed\n"), "text/plain")
}
func (coordinatorLiveReader) Close() error { return nil }

func TestCoordinatorLiveEvidencePreservesSelectionAndRejectsCapturedProof(t *testing.T) {
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	runTarget, err := identity.RunTarget()
	if err != nil {
		t.Fatal(err)
	}
	assignments, budget := coordinatorTestPlan(t)
	runtime := &coordinatorTestRuntime{invoke: func(ctx context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
		validator, _ := validation.NewReviewValidator(bridgeSchemaValidator{}, schemaID)
		raw := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"Live observation.","completeness":"complete","limitations":[],"findings":[{"severity":"high","title":"Observed defect","description":"The observed source demonstrates the defect.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the defect.","confidence":"high"}]}`)
		validated, plan, err := validator.Validate(ctx, raw, validation.ReviewValidationScope{LiveSource: identity, Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()})
		if err != nil || plan != nil {
			t.Errorf("validation: %v", err)
			return coordinatorInternalInvariantOutcome(job)
		}
		verifier, _ := evidence.NewLiveVerifier(coordinatorLiveReader{target})
		groups, err := VerifyValidatedEvidence(ctx, verifier, validated.EvidenceClaims())
		if err != nil {
			t.Error(err)
			return coordinatorInternalInvariantOutcome(job)
		}
		if coordinatorEvidenceBindingCondition(validated.Findings(), groups, runTarget.SourceIdentitySHA256()) == AttemptConditionValidReview {
			t.Error("live proof satisfied captured binding")
		}
		output, err := NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), groups)
		if err != nil {
			t.Error(err)
			return coordinatorInternalInvariantOutcome(job)
		}
		return coordinatorOutputOutcome(job, output)
	}}
	result, err := coordinatorTestCoordinator(t, runtime, 1, budget).Execute(context.Background(), runTarget, assignments, "", nil)
	if err != nil || result.RunState() != domain.RunCompleted || "sha256:"+result.SourceIdentitySHA256() != identity.SHA256() || len(result.Findings()) != 1 || result.Findings()[0].EvidenceState() != domain.EvidenceVerified {
		t.Fatalf("live coordination: %#v, %v", result, err)
	}
	item := result.Evidence()[0].Receipts()[0]
	if item.Claim().TargetSHA256() != "" || item.Claim().SourceIdentitySHA256() != identity.SHA256() {
		t.Fatal("coordinator changed identity kind")
	}
	capturedRuntime := &coordinatorTestRuntime{invoke: func(_ context.Context, job InvocationJob) AttemptOutcome {
		if job.Role() != domain.RoleLogic {
			return coordinatorSuccessOutcome(t, job)
		}
		return coordinatorEvidenceOutcome(job, coordinatorEvidenceFixtureInput{severity: domain.SeverityHigh, title: "captured proof", path: "source.go", quote: "observed\n", targetBytes: "observed\n", targetSHA256: runTarget.SourceIdentitySHA256()})
	}}
	rejected, err := coordinatorTestCoordinator(t, capturedRuntime, 1, budget).Execute(context.Background(), runTarget, assignments, "", nil)
	if err != nil || len(rejected.Findings()) != 0 || coordinatorRoleByRole(t, rejected, domain.RoleLogic).ReasonCode() != string(AttemptConditionInternalInvariant) {
		t.Fatalf("captured proof was not rejected as an invariant failure: %#v, %v", rejected, err)
	}
}
