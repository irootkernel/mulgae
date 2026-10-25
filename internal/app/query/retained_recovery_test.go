package query

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// M_test=1: TASK-065 and contracts retain stored-input authority, not replay issuance.
func TestRecoveryStagedBindingWithoutReplayIssuer(t *testing.T) {
	for _, change := range []string{"destination only", "base template", "output contract", "adapter parameter"} {
		t.Run(change, func(t *testing.T) {
			document, blobs := queryRecoveryFixture(t)
			input := &document.Attempts[1].InitialPrompt
			stdin := blobs[input.Stdin.SHA256]
			boundary := strings.Index(string(stdin), "\nMulgae-FRAMES/1\n")
			base, err := prompt.NewTrustedTemplate(input.TemplateID, input.TemplateVersion, stdin[:boundary])
			if err != nil {
				t.Fatal(err)
			}
			oldDestination, _ := ports.NewStagedOutputDestination("/private/tmp/recovery-old", "role-report.md")
			original, err := review.ComposeRootReviewOutputDestination(base, oldDestination)
			if err != nil {
				t.Fatal(err)
			}
			bind := func(template, previous prompt.TrustedTemplate, suffix string) {
				t.Helper()
				stored := blobs[input.Stdin.SHA256]
				if _, err := prompt.ParseStdin(previous, stored); err != nil {
					t.Fatal(err)
				}
				boundary := strings.Index(string(stored), "\nMulgae-FRAMES/1\n")
				if boundary < 0 {
					t.Fatal("fixed prompt lacks frame boundary")
				}
				// Synthetic stored input only: preserve the entire framed suffix.
				rebound := append(template.Bytes(), stored[boundary:]...)
				if _, err := prompt.ParseStdin(template, rebound); err != nil {
					t.Fatal(err)
				}
				manifest, err := template.TrustedLayerManifestJSON()
				if err != nil {
					t.Fatal(err)
				}
				input.Stdin = recovery.AddBlob(blobs, rebound)
				input.TemplateID, input.TemplateVersion = template.ID(), template.Version()
				input.TemplateSHA256 = "sha256:" + template.SHA256()
				input.ExecutionInvocationID = "019f5a09-5eec-7002-8001-" + suffix
				input.AdapterParameters[prompt.TrustedLayerManifestAdapterParameter] = manifest
			}
			bind(original, base, "000000000041")
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			observation, _ := ports.NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP0None, nil, nil, 1)
			store := &queryStore{observation: observation}
			parent := installQueryRecovery(t, store, root, document, blobs)
			hash := recovery.Digest(queryRecoveryJSON(t, document))
			document.Source = &recovery.Source{Kind: "failed_run_recovery", RunID: parent.RunID().String(), RecoveryManifestSHA256: &hash, AttemptID: document.Attempts[1].AttemptID, ReplayMode: "exact"}
			document.RunID = "r_019f5a09-5eec-7001-8001-000000000012"
			document.RunType = domain.RunTypeRerun
			document.Attempts, document.Roles = document.Attempts[1:], document.Roles[1:]
			document.Attempts[0].AttemptID = "a_019f5a09-5eec-7001-8001-000000000023"
			document.Roles[0].AttemptID = document.Attempts[0].AttemptID
			input = &document.Attempts[0].InitialPrompt
			newDestination, _ := ports.NewStagedOutputDestination("/private/tmp/recovery-new", "role-report.md")
			rebound, err := review.RebindRootReviewOutputDestination(original, newDestination)
			if err != nil {
				t.Fatal(err)
			}
			if change == "base template" {
				changed, _ := prompt.NewTrustedTemplate(base.ID(), base.Version(), []byte("Changed review instructions."))
				rebound, err = review.ComposeRootReviewOutputDestination(changed, newDestination)
			} else if change == "output contract" {
				first, _ := prompt.NewTrustedLayer("review:original-template", "1", base.Bytes())
				output, _ := review.OutputDestinationTrustedLayer(newDestination)
				invalid, _ := prompt.NewTrustedLayer(output.ID(), output.Version(), append(output.Bytes(), []byte("\nExtra instructions.")...))
				rebound, err = prompt.ComposeTrustedTemplate(original.ID(), original.Version(), first, invalid)
			}
			if err != nil {
				t.Fatal(err)
			}
			bind(rebound, original, "000000000042")
			if change == "adapter parameter" {
				input.AdapterParameters["model"] = "changed"
			}
			child := installQueryRecovery(t, store, root, document, blobs)
			validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			service := mustQueryService(t, store, validator, nil)
			_, err = service.ReadFailedRunRecovery(context.Background(), child)
			if change == "destination only" && err != nil || change != "destination only" && err == nil {
				t.Fatalf("staged exact replay %s: %v", change, err)
			}
		})
	}
}
