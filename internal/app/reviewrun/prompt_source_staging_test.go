package reviewrun

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
)

// TestChildDeltaAndRecomposeStageWhenLocatorPresent pins the child-composition
// contract: the exported constructor child workflows call binds the adapter
// locator, so the delta and recomposed-rerun launches that share this authority
// state their own destination, while the plain constructor stays on stdout and
// exact replay rebinds its source destination. Prompt and DeltaPrompt use one
// composer, so composing it once proves both launches.
func TestChildDeltaAndRecomposeStageWhenLocatorPresent(t *testing.T) {
	t.Parallel()

	templates, err := LoadDefaultTemplateSet(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInput(reviewRunPatchTarget(t), nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	locator := providerOutputStagingLocator(&stagingObservedProviderFake{})
	staged, err := NewProductionPromptSourceWithStaging(input, templates, &childStagingPromptIssuer{}, reviewRunRoleTask, locator)
	if err != nil {
		t.Fatal(err)
	}
	stdoutOnly, err := NewProductionPromptSource(input, templates, &childStagingPromptIssuer{}, reviewRunRoleTask)
	if err != nil {
		t.Fatal(err)
	}
	base, err := templates.ComposeRootReview(domain.RoleLogic, nil)
	if err != nil {
		t.Fatal(err)
	}
	initialJob := reviewRunStagedJob(t, "zcode-logic", domain.InvocationInitial, 1)
	retryJob := reviewRunStagedJob(t, "zcode-logic", domain.InvocationRetry, 2)
	repairJob := reviewRunStagedJob(t, "zcode-logic", domain.InvocationRepair, 2)

	for _, test := range []struct {
		name string
		job  review.InvocationJob
	}{
		{name: "initial launch", job: initialJob},
		{name: "retry launch", job: retryJob},
		{name: "repair launch", job: repairJob},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination, resolved := review.ResolveStagedOutputDestination(locator, test.job)
			if !resolved {
				t.Fatal("staging locator resolved no destination for the child launch")
			}
			composed, composeErr := staged.composeOutputDestination(base, test.job)
			if composeErr != nil {
				t.Fatal(composeErr)
			}
			manifest := composed.TrustedLayerManifest()
			last := manifest[len(manifest)-1]
			layer, layerErr := review.OutputDestinationTrustedLayer(destination)
			if layerErr != nil {
				t.Fatal(layerErr)
			}
			if last.ID() != review.OutputDestinationTrustedLayerID || last.SHA256() != layer.SHA256() {
				t.Fatalf("last trusted layer = %q/%s, want %q", last.ID(), last.SHA256(), review.OutputDestinationTrustedLayerID)
			}
			if !bytes.Contains(composed.Bytes(), []byte(destination.AbsolutePath())) {
				t.Fatalf("child launch template does not state %q", destination.AbsolutePath())
			}
			// The stdout constructor child workflows used before staging must keep
			// every launch on the stdout transport.
			untouched, untouchedErr := stdoutOnly.composeOutputDestination(base, test.job)
			if untouchedErr != nil {
				t.Fatal(untouchedErr)
			}
			if untouched.SHA256() != base.SHA256() {
				t.Fatal("stdout prompt authority composed an output destination")
			}
		})
	}

	// Exact replay preserves every stored frame but replaces the source launch's
	// disposed staging path with the destination for the new attempt.
	t.Run("exact replay", func(t *testing.T) {
		sourceTemplate, composeErr := staged.composeOutputDestination(base, initialJob)
		if composeErr != nil {
			t.Fatal(composeErr)
		}
		stored := childStagingStoredPacket(t, sourceTemplate, input.Target().Bytes())
		manifest, manifestErr := sourceTemplate.TrustedLayerManifestJSON()
		if manifestErr != nil {
			t.Fatal(manifestErr)
		}
		newAttemptID, parseErr := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000006")
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		replayJob, jobErr := review.NewInvocationJob(
			initialJob.Role(), initialJob.Route(), initialJob.Target(), initialJob.Limits(),
			newAttemptID, domain.InvocationInitial, 1,
		)
		if jobErr != nil {
			t.Fatal(jobErr)
		}
		sourceDestination, sourceStaged := review.ResolveStagedOutputDestination(locator, initialJob)
		newDestination, newStaged := review.ResolveStagedOutputDestination(locator, replayJob)
		if !sourceStaged || !newStaged || sourceDestination == newDestination {
			t.Fatal("test setup did not produce distinct staged destinations")
		}
		replayed, replayErr := staged.ExactReplayPrompt(context.Background(), replayJob, review.ExactReplayInput{
			SourceRunID: childStagingRunID(t), SourceAttemptID: initialJob.AttemptID(),
			SourceProviderInstance: initialJob.Route().ProviderInstance(),
			Stdin:                  stored.Stdin(), CompleteStdinSHA256: stored.CompleteStdinSHA256(),
			SourceInvocationID:          stored.Scope().SourceInvocationID().String(),
			SourceExecutionInvocationID: stored.Scope().ExecutionInvocationID().String(),
			TemplateID:                  sourceTemplate.ID(), TemplateVersion: sourceTemplate.Version(), TemplateSHA256: sourceTemplate.SHA256(),
			Role: initialJob.Role(), AdapterProfile: "root-review", AdapterParameters: map[string]string{prompt.TrustedLayerManifestAdapterParameter: manifest},
		})
		if replayErr != nil {
			t.Fatalf("ExactReplayPrompt() error = %v", replayErr)
		}
		if bytes.Equal(replayed.Prompt.Stdin(), stored.Stdin()) ||
			bytes.Contains(replayed.Prompt.Stdin(), []byte(sourceDestination.AbsolutePath())) ||
			!bytes.Contains(replayed.Prompt.Stdin(), []byte(newDestination.AbsolutePath())) {
			t.Fatal("exact replay did not replace only the staged destination")
		}
		marker := []byte("\nMulgae-FRAMES/1\n")
		storedFrames := stored.Stdin()[bytes.Index(stored.Stdin(), marker):]
		replayedFrames := replayed.Prompt.Stdin()[bytes.Index(replayed.Prompt.Stdin(), marker):]
		if !bytes.Equal(replayedFrames, storedFrames) {
			t.Fatal("exact replay changed stored framed source authority")
		}
		wantManifest, manifestErr := replayed.Prompt.TrustedTemplate().TrustedLayerManifestJSON()
		if manifestErr != nil {
			t.Fatal(manifestErr)
		}
		if replayed.AdapterParameters[prompt.TrustedLayerManifestAdapterParameter] != wantManifest {
			t.Fatal("exact replay adapter manifest does not match rebound template")
		}
	})
}

func childStagingStoredPacket(t *testing.T, template prompt.TrustedTemplate, target []byte) prompt.CompiledPrompt {
	t.Helper()
	compiler, err := prompt.NewCompiler(template, &childStagingPromptIssuer{})
	if err != nil {
		t.Fatal(err)
	}
	roleTask, err := reviewRunRoleTask()
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := prompt.NewScopeCoordinates(sessionID, childStagingRunID(t), roleTask, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(target)})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func childStagingRunID(t *testing.T) domain.RunID {
	t.Helper()
	runID, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000005")
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

// childStagingPromptIssuer mints one fresh identity per call so a replay can
// prove it received a new execution identity for the same stored packet.
type childStagingPromptIssuer struct{ issued int }

func (issuer *childStagingPromptIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	issuer.issued++
	return prompt.ParseSourceInvocationID(fmt.Sprintf("i_019f5a09-5eec-7001-8001-%012d", issuer.issued))
}

func (issuer *childStagingPromptIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	issuer.issued++
	return prompt.ParseExecutionInvocationID(fmt.Sprintf("019f5a09-5eec-7001-8001-%012d", 900000+issuer.issued))
}
