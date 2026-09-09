package review

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

type preparationRuntime struct {
	prepare func(context.Context, []InvocationJob) error
	invoke  func(InvocationJob) AttemptOutcome
}

func (runtime *preparationRuntime) PrepareInitial(ctx context.Context, jobs []InvocationJob) error {
	return runtime.prepare(ctx, jobs)
}
func (runtime *preparationRuntime) Invoke(_ context.Context, job InvocationJob) AttemptOutcome {
	return runtime.invoke(job)
}

func TestCoordinatorPreparesAllInitialInputsBeforeDispatch(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "prepared"
		if reject {
			name = "preparation-failed"
		}
		t.Run(name, func(t *testing.T) {
			assignments, receipt := coordinatorTestPlan(t)
			prepared := make(map[domain.AttemptID]bool)
			preparationErr := errors.New("initial input unavailable")
			runtime := &preparationRuntime{
				prepare: func(_ context.Context, jobs []InvocationJob) error {
					if len(jobs) != len(assignments) {
						t.Fatalf("prepared %d jobs for %d assignments", len(jobs), len(assignments))
					}
					for _, job := range jobs {
						prepared[job.AttemptID()] = true
					}
					if reject {
						return preparationErr
					}
					return nil
				},
				invoke: func(job InvocationJob) AttemptOutcome {
					if reject || len(prepared) != len(assignments) || !prepared[job.AttemptID()] {
						t.Error("provider dispatched without complete initial preparation")
					}
					return coordinatorSuccessOutcome(t, job)
				},
			}
			coordinator := coordinatorTestCoordinator(t, runtime, 1, receipt)
			result, err := coordinator.Execute(context.Background(), coordinatorTestTarget(t), assignments, "", nil)
			if reject {
				if !errors.Is(err, preparationErr) {
					t.Fatalf("error = %v", err)
				}
				if result.RunState() != domain.RunFailed {
					t.Fatalf("preparation failure run state = %q, want %q", result.RunState(), domain.RunFailed)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCoordinatorPreservesCancellationDuringInitialPreparation(t *testing.T) {
	assignments, receipt := coordinatorTestPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	invocations := 0
	runtime := &preparationRuntime{
		prepare: func(prepareCtx context.Context, _ []InvocationJob) error {
			cancel()
			<-prepareCtx.Done()
			return prepareCtx.Err()
		},
		invoke: func(InvocationJob) AttemptOutcome {
			invocations++
			return AttemptOutcome{}
		},
	}
	coordinator := coordinatorTestCoordinator(t, runtime, 1, receipt)
	result, err := coordinator.Execute(ctx, coordinatorTestTarget(t), assignments, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preparation cancellation error = %v", err)
	}
	if invocations != 0 || result.RunState() != domain.RunCancelled {
		t.Fatalf("preparation cancellation = invocations:%d run:%q", invocations, result.RunState())
	}
	for _, summary := range result.RoleSummaries() {
		if summary.State() != domain.RoleTaskCancelled || summary.FailureClass() != domain.FailureCancelled || summary.ReasonCode() != string(AttemptConditionCancelled) {
			t.Fatalf("preparation cancellation role = %#v", summary)
		}
	}
}

func TestInitialInputFreezeRetainsQueuedPromptAndOwnsBytes(t *testing.T) {
	runtime, job, material := providerRuntimeExplicitFixture(t, nil)
	runtime.source = explicitRuntimePromptSource{material: material}
	if err := runtime.PrepareInitial(context.Background(), []InvocationJob{job}); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), material.Target...)
	material.Target[0] ^= 1
	frozen := runtime.DrainInitialInputsForRun(job.RunID())
	if len(frozen) != 1 || !bytes.Equal(frozen[0].Target(), original) || frozen[0].AttemptID() != job.AttemptID() {
		t.Fatal("queued input was missing, aliased, or rebound")
	}
	if len(runtime.DrainInitialInputsForRun(job.RunID())) != 0 {
		t.Fatal("drain retained ownership")
	}
	if len(runtime.DrainRuntimeArtifactsForRun(job.RunID())) != 0 {
		t.Fatal("preparation fabricated an invocation artifact")
	}
}

func TestPreparedInitialInputSharesImmutableTargetWithInventory(t *testing.T) {
	runtime, job, material := providerRuntimeExplicitFixture(t, nil)
	material.CapturedArchive = []byte("captured archive")
	runtime.source = explicitRuntimePromptSource{material: material}
	if err := runtime.PrepareInitial(context.Background(), []InvocationJob{job}); err != nil {
		t.Fatal(err)
	}
	input := runtime.preparedInitial[job.AttemptID()]
	invoked, ok := runtime.initialMaterial(job)
	if !ok {
		t.Fatal("prepared input absent")
	}
	if err := runtime.recordRuntimeArtifact(job, invoked); err != nil {
		t.Fatal(err)
	}
	inventory := runtime.inventory[captureKey{job.AttemptID(), invocationSequence(job.Purpose())}]
	if &input.material.Target[0] != &inventory.target[0] || &input.material.CapturedArchive[0] != &inventory.capturedArchive[0] {
		t.Fatal("prepared and invoked inventories duplicated immutable target material")
	}
	external := runtime.DrainRuntimeArtifactsForRun(job.RunID())
	target := external[0].Target()
	archive := external[0].CapturedArchive()
	target[0] ^= 1
	archive[0] ^= 1
	if bytes.Equal(target, input.material.Target) || bytes.Equal(archive, input.material.CapturedArchive) {
		t.Fatal("public getter mutated frozen content")
	}
	if &external[0].target[0] != &input.material.Target[0] {
		t.Fatal("drain copied immutable target")
	}
}
