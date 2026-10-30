package query

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func TestCommittedAttemptSelectionReachesRetainedInitialPromptGuard(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" {
			continue
		}
		for _, mutation := range []string{"repair", "absent", "ambiguous"} {
			t.Run(mutation, func(t *testing.T) {
				store, run := historicalQueryStore(t, c)
				attempt, err := domain.ParseAttemptID(c.Attempts[0].AttemptID)
				if err != nil {
					t.Fatal(err)
				}
				service := mustQueryService(t, store, validator, nil)
				original, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
				if err != nil {
					t.Fatal(err)
				}
				historicalAttempt(t, original, c.Attempts[0], c.Artifacts())
				snapshot := store.snapshotsByRun[c.RunID]
				identity := func(s string) string { return s }
				entries := queryRuntimeFixtureEntries(t, snapshot, store.auxiliaryArtifacts, identity, bytes.Clone)
				path := c.SessionID + "/" + c.RunID + "/target/target-manifest.json"
				var target artifactwire.RuntimeTargetManifest
				if err := json.Unmarshal(entries[path].bytes, &target); err != nil {
					t.Fatal(err)
				}
				index := -1
				for i, selected := range target.SelectedReplayPrompts {
					if selected.AttemptID == attempt.String() {
						index = i
					}
				}
				if index < 0 {
					t.Fatal("fixed initial selection absent")
				}
				want := "selected replay prompt is absent or invalid"
				switch mutation {
				case "repair":
					target.SelectedReplayPrompts[index].Sequence = 2
					target.SelectedReplayPrompts[index].Purpose = "repair"
				case "absent":
					target.SelectedReplayPrompts = append(target.SelectedReplayPrompts[:index], target.SelectedReplayPrompts[index+1:]...)
				case "ambiguous":
					target.SelectedReplayPrompts = append(target.SelectedReplayPrompts, target.SelectedReplayPrompts[index])
					want = "selected replay prompt is ambiguous"
				}
				raw, err := json.Marshal(target)
				if err != nil {
					t.Fatal(err)
				}
				entries[path].bytes = raw
				retainedQueryRebind(t, entries, c.SessionID+"/"+c.RunID+"/")
				updated, observation, artifacts := retainedQuerySnapshot(t, run, snapshot, store.auxiliaryArtifacts, entries, domain.OperationalExitCode(c.Expected.Exit))
				store.snapshotsByRun[c.RunID] = updated
				store.observationsByRun[c.RunID] = observation
				store.auxiliaryArtifacts = artifacts
				_, err = service.ReadCommittedAttempt(context.Background(), run, attempt)
				historicalReason(t, err, want)
			})
		}
		return
	}
	t.Fatal("fixed initial prompt source absent")
}

func TestCommittedAttemptRetainsRepairedAndFailedInitialSelections(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" {
			continue
		}
		for _, mode := range []string{"repaired initial", "repaired repair refusal", "failed initial"} {
			t.Run(mode, func(t *testing.T) {
				store, run := historicalQueryStore(t, c)
				snapshot := store.snapshotsByRun[c.RunID]
				prefix := c.SessionID + "/" + c.RunID + "/"
				entries := queryRuntimeFixtureEntries(t, snapshot, store.auxiliaryArtifacts, func(s string) string { return s }, bytes.Clone)
				manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
				if err != nil {
					t.Fatal(err)
				}
				final, err := decodeFinalDTO(snapshot.Final().Bytes())
				if err != nil {
					t.Fatal(err)
				}
				var target artifactwire.RuntimeTargetManifest
				if err := json.Unmarshal(entries[prefix+"target/target-manifest.json"].bytes, &target); err != nil {
					t.Fatal(err)
				}
				selected := 0
				exit := domain.ExitCommittedCIRejected
				if mode == "failed initial" {
					selected = 1 // The security attempt has no findings to reassign.
					a := &manifest.Attempts[selected]
					a.State, a.ParseState, a.ValidationState = "failed", "not_started", "not_started"
					reason := "provider_output_missing"
					role := &final.RoleOutcomes[selected]
					role.Outcome, role.FailureReason = "failed", &reason
					role.Limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
					manifest.State, manifest.CoverageStatus, final.CoverageStatus = "failed", "incomplete", "incomplete"
					manifest.CIReasonCodes, final.CIReasonCodes = []string{"request_changes_threshold", "required_role_incomplete"}, []string{"request_changes_threshold", "required_role_incomplete"}
					final.Limitations = []string{"Required review coverage is incomplete."}
					manifest.RoleReports = manifest.RoleReports[:1]
					id := a.AttemptID
					manifest.Failures = []manifestFailureDTO{{Class: string(domain.FailureInvalidOutput), Stage: "review", ReasonCode: reason, AttemptID: &id}}
					exit = domain.ExitIncompleteCoverage
					manifest.ExitCode = int(exit)
				} else {
					// Real, distinct repair inventory: a second framed invocation,
					// manifest and stdin, all support-indexed. Initial remains selected.
					manifest.Attempts[0].InvocationCount = 2
					manifest.Attempts[0].ValidationState = "repaired_valid"
					final.Validation.Status = "repaired_valid"
					initial := target.SelectedReplayPrompts[0].Artifact.Path
					var wire artifactwire.RuntimePromptManifest
					if err := json.Unmarshal(entries[initial].bytes, &wire); err != nil {
						t.Fatal(err)
					}
					template, err := prompt.NewTrustedTemplate("retained-repair", "1", []byte("Repair only allowed fields."))
					if err != nil {
						t.Fatal(err)
					}
					compiler, err := prompt.NewCompiler(template, recoveryIssuer{"000000000041"})
					if err != nil {
						t.Fatal(err)
					}
					attempt, err := domain.ParseAttemptID(manifest.Attempts[0].AttemptID)
					if err != nil {
						t.Fatal(err)
					}
					task, err := prompt.ParseRoleTaskID("rt_" + strings.TrimPrefix(attempt.String(), "a_"))
					if err != nil {
						t.Fatal(err)
					}
					scope, err := prompt.NewScopeCoordinates(run.SessionID(), run.RunID(), task, attempt)
					if err != nil {
						t.Fatal(err)
					}
					prior := prompt.NewPayload([]byte("malformed provider output"))
					compiled, err := compiler.Compile(prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(entries[target.Target.Path].bytes), PriorProviderOutput: &prior})
					if err != nil {
						t.Fatal(err)
					}
					repairPath := strings.Replace(initial, "001-initial", "002-repair", 1)
					stdinPath := strings.TrimSuffix(repairPath, ".manifest.json") + ".stdin"
					wire.Stdin = artifactwire.ArtifactIdentity{Path: stdinPath, SHA256: querySHA(compiled.Stdin())}
					wire.CompleteStdinSHA256 = compiled.CompleteStdinSHA256()
					wire.TemplateID, wire.TemplateVersion, wire.TemplateSHA256 = template.ID(), template.Version(), "sha256:"+template.SHA256()
					wire.SourceInvocationID, wire.ExecutionInvocationID, wire.Scope = compiled.Scope().SourceInvocationID().String(), compiled.Scope().ExecutionInvocationID().String(), compiled.Scope().FrameScope().String()
					raw, err := json.Marshal(wire)
					if err != nil {
						t.Fatal(err)
					}
					entries[repairPath] = &queryRuntimeFixtureEntry{bytes: raw}
					entries[stdinPath] = &queryRuntimeFixtureEntry{bytes: compiled.Stdin()}
					ref := artifactwire.ArtifactIdentity{Path: repairPath, SHA256: querySHA(raw)}
					target.Prompts = append(target.Prompts, ref)
					if len(target.Prompts) != 3 || bytes.Equal(entries[wire.Stdin.Path].bytes, entries[strings.Replace(stdinPath, "002-repair", "001-initial", 1)].bytes) {
						t.Fatal("repair inventory is not distinct")
					}
					var index artifactwire.SupportIndex
					indexPath := prefix + "support/index.json"
					if err := json.Unmarshal(entries[indexPath].bytes, &index); err != nil {
						t.Fatal(err)
					}
					index.Artifacts = append(index.Artifacts, ref, wire.Stdin)
					sort.Slice(index.Artifacts, func(i, j int) bool { return index.Artifacts[i].Path < index.Artifacts[j].Path })
					raw, err = json.Marshal(index)
					if err != nil {
						t.Fatal(err)
					}
					entries[indexPath].bytes = append(raw, '\n')
					if mode == "repaired repair refusal" {
						target.SelectedReplayPrompts[0] = artifactwire.SelectedReplayPrompt{AttemptID: attempt.String(), Sequence: 2, Purpose: "repair", Artifact: ref}
					}
				}
				for path, value := range map[string]any{prefix + "manifest.json": manifest, snapshot.Final().Identity().Path().String(): final, prefix + "target/target-manifest.json": target} {
					raw, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					entries[path].bytes = append(raw, '\n')
				}
				retainedQueryRebind(t, entries, prefix)
				updated, observation, artifacts := retainedQuerySnapshot(t, run, snapshot, store.auxiliaryArtifacts, entries, exit)
				store.snapshotsByRun[c.RunID], store.observationsByRun[c.RunID], store.auxiliaryArtifacts = updated, observation, artifacts
				service := mustQueryService(t, store, validator, nil)
				if _, err := service.ReadCommitted(context.Background(), run); err != nil {
					t.Fatalf("valid surrounding committed input: %v", err)
				}
				attempt, err := domain.ParseAttemptID(manifest.Attempts[selected].AttemptID)
				if err != nil {
					t.Fatal(err)
				}
				got, err := service.ReadCommittedAttempt(context.Background(), run, attempt)
				if mode == "repaired repair refusal" {
					historicalReason(t, err, "selected replay prompt is absent or invalid")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				historicalAttempt(t, got, c.Attempts[selected], c.Artifacts())
			})
		}
		return
	}
	t.Fatal("fixed ordinary input absent")
}
