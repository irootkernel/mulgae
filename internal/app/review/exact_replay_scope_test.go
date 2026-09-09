package review

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/domain"
)

type exactReplayScopeSource struct{ explicitRuntimePromptSource }

func (source exactReplayScopeSource) ExactReplayPrompt(ctx context.Context, job InvocationJob, _ ExactReplayInput) (RuntimePrompt, error) {
	return source.Prompt(ctx, job, nil)
}

func TestExactReplayRetainsOriginalScopeAndRejectsForeignScope(t *testing.T) {
	for _, scenario := range []string{"original scope", "foreign scope", "missing scope", "ordinary invocation"} {
		t.Run(scenario, func(t *testing.T) {
			provider := &recordingReviewProvider{responses: []reviewProviderResponse{{stdout: []byte("Accepted review.")}}}
			runtime, original, material := providerRuntimeExplicitFixture(t, provider)
			runtime.source = exactReplayScopeSource{explicitRuntimePromptSource{material: material}}
			childID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000099")
			if err != nil {
				t.Fatal(err)
			}
			child, err := newCoordinatorInvocationJob(original.SessionID(), childID, original.Role(), original.Route(), original.Target(), original.Limits(), coordinatorTypesAttemptID(t, 99), domain.InvocationInitial, 1)
			if err != nil {
				t.Fatal(err)
			}
			sourceRunID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000098")
			if err != nil {
				t.Fatal(err)
			}
			scope := material.Prompt.Scope()
			input := ExactReplayInput{SourceRunID: sourceRunID, SourceAttemptID: coordinatorTypesAttemptID(t, 98), SourceScope: scope.FrameScope().String(), Role: original.Role(), SourceProviderInstance: original.Route().ProviderInstance(), Stdin: material.Prompt.Stdin(), CompleteStdinSHA256: material.Prompt.CompleteStdinSHA256(), SourceInvocationID: scope.SourceInvocationID().String(), SourceExecutionInvocationID: scope.ExecutionInvocationID().String(), TemplateID: material.Prompt.TrustedTemplate().ID(), TemplateVersion: material.Prompt.TrustedTemplate().Version(), TemplateSHA256: material.Prompt.TrustedTemplate().SHA256(), AdapterProfile: material.AdapterProfile, AdapterParameters: material.AdapterParameters}
			if scenario == "foreign scope" {
				input.SourceScope = strings.Replace(input.SourceScope, original.RunID().String(), childID.String(), 1)
			}
			if scenario == "missing scope" {
				input.SourceScope = ""
			}
			var outcome AttemptOutcome
			if scenario == "ordinary invocation" {
				outcome = runtime.Invoke(context.Background(), child)
			} else {
				outcome = runtime.InvokeExactReplay(context.Background(), child, input)
			}
			if scenario == "original scope" {
				if !outcome.Succeeded() || len(provider.invocations) != 1 {
					t.Fatalf("original frame scope was not replayed: %+v", outcome)
				}
				if prompt.CompleteStdinSHA256(provider.invocations[0].Packet().Bytes()) != input.CompleteStdinSHA256 {
					t.Fatal("exact replay changed stdin")
				}
			} else {
				condition, ok := outcome.Condition()
				if !ok || condition != AttemptConditionConfigurationViolation || len(provider.invocations) != 0 {
					t.Fatalf("foreign frame scope reached provider: %+v calls=%d", outcome, len(provider.invocations))
				}
			}
		})
	}
}
