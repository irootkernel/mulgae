package review

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/irootkernel/mulgae/internal/domain"
)

type preparedInitialInput struct {
	job      InvocationJob
	material RuntimePrompt
}

// PrepareInitial freezes every initial prompt before provider dispatch. These
// inputs remain separate from invocation artifacts: preparation is not execution.
func (runtime *ProviderInvocationRuntime) PrepareInitial(ctx context.Context, jobs []InvocationJob) error {
	return runtime.prepareInitial(ctx, jobs, func(job InvocationJob) (RuntimePrompt, error) {
		return runtime.source.Prompt(ctx, job, nil)
	})
}

func (runtime *ProviderInvocationRuntime) prepareInitial(ctx context.Context, jobs []InvocationJob, compose func(InvocationJob) (RuntimePrompt, error)) error {
	if runtime == nil || ctx == nil {
		return fmt.Errorf("initial inputs: missing runtime or context")
	}
	inputs := make(map[domain.AttemptID]preparedInitialInput, len(jobs))
	var frozenTarget, frozenArchive []byte
	frozen := false
	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if job.Purpose() != domain.InvocationInitial {
			return fmt.Errorf("initial inputs: non-initial job")
		}
		if _, exists := inputs[job.AttemptID()]; exists {
			return fmt.Errorf("initial inputs: duplicate attempt")
		}
		material, err := compose(job)
		if err != nil {
			return err
		}
		if err := material.Prompt.Validate(); err != nil {
			return err
		}
		if sha256Identifier(material.Target) != "sha256:"+job.Target().SHA256() {
			return fmt.Errorf("initial inputs: target mismatch")
		}
		if !frozen {
			frozenTarget = append([]byte(nil), material.Target...)
			frozenArchive = append([]byte(nil), material.CapturedArchive...)
			frozen = true
		} else if !bytes.Equal(frozenTarget, material.Target) || !bytes.Equal(frozenArchive, material.CapturedArchive) {
			return fmt.Errorf("initial inputs: captured material differs between roles")
		}
		material.Target, material.CapturedArchive = frozenTarget, frozenArchive
		material.AdapterParameters = cloneAdapterParameters(material.AdapterParameters)
		material.frozenTarget = true
		inputs[job.AttemptID()] = preparedInitialInput{job: job, material: material}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for attempt := range inputs {
		if _, exists := runtime.preparedInitial[attempt]; exists {
			return fmt.Errorf("initial inputs: attempt already prepared")
		}
	}
	if runtime.preparedInitial == nil {
		runtime.preparedInitial = make(map[domain.AttemptID]preparedInitialInput)
	}
	for attempt, input := range inputs {
		runtime.preparedInitial[attempt] = input
	}
	return nil
}

func (runtime *ProviderInvocationRuntime) initialMaterial(job InvocationJob) (RuntimePrompt, bool) {
	if job.Purpose() != domain.InvocationInitial {
		return RuntimePrompt{}, false
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	input, ok := runtime.preparedInitial[job.AttemptID()]
	if !ok || input.job.RunID() != job.RunID() {
		return RuntimePrompt{}, false
	}
	material, _ := (explicitRuntimePromptSource{material: input.material}).Prompt(context.Background(), job, nil)
	return material, true
}

// DrainInitialInputsForRun returns frozen replay material, including inputs for
// roles cancelled while queued, and releases its in-memory ownership.
func (runtime *ProviderInvocationRuntime) DrainInitialInputsForRun(runID domain.RunID) []RuntimeArtifactInventory {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([]RuntimeArtifactInventory, 0)
	for attempt, input := range runtime.preparedInitial {
		if input.job.RunID() != runID {
			continue
		}
		result = append(result, initialArtifactInventory(input.job, input.material))
		delete(runtime.preparedInitial, attempt)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AttemptID().String() < result[j].AttemptID().String() })
	return result
}

func (runtime exactReplayInvocationRuntime) PrepareInitial(ctx context.Context, jobs []InvocationJob) error {
	source, ok := runtime.runtime.source.(ExactReplayPromptSource)
	if !ok {
		return fmt.Errorf("initial inputs: exact replay source unavailable")
	}
	return runtime.runtime.prepareInitial(ctx, jobs, func(job InvocationJob) (RuntimePrompt, error) {
		return source.ExactReplayPrompt(ctx, job, cloneExactReplayInput(runtime.input))
	})
}

// DiscardInitialInputsForRun releases prepared ownership without materializing
// replay inventories when the run no longer needs them.
func (runtime *ProviderInvocationRuntime) DiscardInitialInputsForRun(runID domain.RunID) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for attempt, input := range runtime.preparedInitial {
		if input.job.RunID() == runID {
			delete(runtime.preparedInitial, attempt)
		}
	}
}
