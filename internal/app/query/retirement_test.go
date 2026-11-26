package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func liveZCodeRetirementFixture(t *testing.T) (finalDTO, manifestDTO) {
	t.Helper()
	finalBytes, err := os.ReadFile("../../builtin/assets/examples/review-artifact.v3.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile("../../builtin/assets/examples/run-manifest.v3.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	final, err := decodeFinalDTO(finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	final.Target.LiveSource.NoChange = false
	final.Target.LiveSource.Changes = []evidence.LiveSourceChange{{Kind: "included", After: "README.md"}}
	provider := queryProductionFinalDTO().Provenance.Production.Providers[0]
	provider.Family, provider.Instance = "zcode", "zcode-documentation"
	final.Provenance.LiveProduction.Providers = []productionProviderDTO{provider}
	for index := range final.RoleOutcomes {
		final.RoleOutcomes[index].Outcome = "succeeded"
	}
	manifest.Attempts = []manifestAttemptDTO{{ProviderInstance: provider.Instance}}
	if _, err := validateLivePublicationBinding(final, manifest); err != nil {
		t.Fatalf("live binding fixture: %v", err)
	}
	return final, manifest
}

func TestRetiredFamiliesRejectedEvenWithValidatedCurrentLiveBinding(t *testing.T) {
	final, manifest := liveZCodeRetirementFixture(t)
	if finalRecordRetired(final, manifest) {
		t.Fatal("active live ZCode instance was retired")
	}
	for name, mutate := range map[string]func(*finalDTO, *manifestDTO){
		"Kimi attempt":           func(_ *finalDTO, m *manifestDTO) { m.Attempts[0].ProviderInstance = "KIMI-logic" },
		"Kimi live provenance":   func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction.Providers[0].Family = "kimi" },
		"Cursor attempt":         func(_ *finalDTO, m *manifestDTO) { m.Attempts[0].ProviderInstance = "cursor-logic" },
		"Cursor live provenance": func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction.Providers[0].Family = "cursor" },
		"Codex attempt":          func(_ *finalDTO, m *manifestDTO) { m.Attempts[0].ProviderInstance = "codex-primary-logic" },
		"Codex live provenance":  func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction.Providers[0].Family = "codex" },
		"AGY attempt":            func(_ *finalDTO, m *manifestDTO) { m.Attempts[0].ProviderInstance = "agy-documentation" },
		"AGY live provenance":    func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction.Providers[0].Family = "agy" },
	} {
		t.Run(name, func(t *testing.T) {
			f, m := liveZCodeRetirementFixture(t)
			mutate(&f, &m)
			if !finalRecordRetired(f, m) {
				t.Fatal("retired provider escaped retirement")
			}
		})
	}
}

func TestCommittedProviderRetirementRejectsRetiredFamiliesUnconditionally(t *testing.T) {
	run, _, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	for _, live := range []bool{false, true} {
		for _, family := range []string{"kimi", "cursor", "codex", "agy"} {
			final, manifest := liveZCodeRetirementFixture(t)
			final.Provenance.LiveProduction.Providers[0].Family = family
			final.Provenance.LiveProduction.Providers[0].Instance = family + "-documentation"
			body, err := json.Marshal(final)
			if err != nil {
				t.Fatal(err)
			}
			review := CommittedReview{runType: domain.RunTypeReview, finalBytes: body}
			if live {
				value, err := validateLivePublicationBinding(final, manifest)
				if err != nil {
					t.Fatal(err)
				}
				review.liveSource = &value
			}
			readContext := (&Service{}).newReadContext()
			retired, err := readContext.committedRetired(context.Background(), readContext.adoptReview(run, review))
			if err != nil || !retired {
				t.Fatalf("family=%s live=%t retired=%t err=%v, want retired=true", family, live, retired, err)
			}
		}
	}
}

func TestRetiredProviderInstanceUsesFamilyBoundaries(t *testing.T) {
	for _, value := range []string{"kimi", "KIMI-logic", "cursor", "CURSOR-logic", "codex", "codex-primary-security", "agy.security", "agy_profile"} {
		if !retiredProviderInstance(value) {
			t.Errorf("retired provider instance %q was not recognized", value)
		}
	}
	for _, value := range []string{"zcode", "grok-logic", "kimiko", "cursorx", "codexx", "agyx"} {
		if retiredProviderInstance(value) {
			t.Errorf("supported or unrelated provider instance %q was retired", value)
		}
	}
}

func retiredProductionFixture(t *testing.T, family string) (*Service, *queryStore, ports.PublicationRun) {
	t.Helper()
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	production := queryProductionFinalDTO()
	production.Provenance.Production.Providers[0].Family = family
	final.Mulgae = production.Mulgae
	final.Provenance.Production = production.Provenance.Production
	finalBytes, err := json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(snapshot.Final().Identity().ReviewID(), snapshot.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest.FinalReview.SHA256 = finalIdentity.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	retiredSnapshot, err := ports.NewCommittedPublicationSnapshot(finalArtifact, mustQueryArtifact(t, snapshot.Manifest().Path(), manifestBytes), snapshot.LineageEdge(), snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	observation := queryP2Observation(t, run, retiredSnapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	store := &queryStore{resolved: run, observation: observation, snapshot: retiredSnapshot}
	service := mustQueryService(t, store, &queryValidator{}, nil)
	return service, store, run
}

func TestReadCommittedRejectsRetiredProductionProvider(t *testing.T) {
	for _, family := range []string{"kimi", "cursor", "codex", "agy"} {
		service, _, run := retiredProductionFixture(t, family)
		_, err := service.ReadCommitted(context.Background(), run)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != retiredProviderArtifactReason {
			t.Fatalf("%s artifact failure = %#v, want %q", family, err, retiredProviderArtifactReason)
		}
		if !IsRetiredProviderArtifact(err) {
			t.Fatalf("%s IsRetiredProviderArtifact(%v) = false, want true", family, err)
		}
		_, statusErr := service.ReadRunStatus(context.Background(), run)
		if !IsRetiredProviderArtifact(statusErr) {
			t.Fatalf("%s ReadRunStatus failure = %#v, want retired_provider_artifact", family, statusErr)
		}
	}
}

func TestIsRetiredProviderArtifact(t *testing.T) {
	retired := typedFailure("query.read_committed", domain.FailureArtifact, RetiredProviderArtifactReason, nil)
	nested := typedFailure("query.read_status", domain.FailureArtifact, "failed-run recovery source is invalid", retired)
	other := typedFailure("query.read_committed", domain.FailureArtifact, "corrupt manifest", nil)
	wrongClass := typedFailure("query.read_committed", domain.FailureConfiguration, RetiredProviderArtifactReason, nil)

	if !IsRetiredProviderArtifact(retired) ||
		!IsRetiredProviderArtifact(nested) ||
		!IsRetiredProviderArtifact(fmt.Errorf("wrap: %w", retired)) ||
		!IsRetiredProviderArtifact(errors.Join(other, retired)) {
		t.Fatal("IsRetiredProviderArtifact missed a typed retired-provider artifact failure")
	}
	if IsRetiredProviderArtifact(nil) ||
		IsRetiredProviderArtifact(other) ||
		IsRetiredProviderArtifact(wrongClass) ||
		IsRetiredProviderArtifact(errors.New(RetiredProviderArtifactReason)) {
		t.Fatal("IsRetiredProviderArtifact matched a non-retired or untyped error")
	}
}

func TestCurrentLiveZCodeStillRejectsRetiredSourceLineage(t *testing.T) {
	for _, family := range []string{"agy", "codex", "kimi", "cursor"} {
		service, store, sourceRun := retiredProductionFixture(t, family)
		currentID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bb")
		if err != nil {
			t.Fatal(err)
		}
		currentRun, err := ports.NewPublicationRun(sourceRun.Root(), sourceRun.SessionID(), currentID)
		if err != nil {
			t.Fatal(err)
		}
		final, manifest := liveZCodeRetirementFixture(t)
		sourceID := sourceRun.RunID().String()
		final.ImmutableLineage.SourceRunID = &sourceID
		live, err := validateLivePublicationBinding(final, manifest)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(final)
		if err != nil {
			t.Fatal(err)
		}
		review := CommittedReview{liveSource: &live, runType: domain.RunTypeReview, finalBytes: body}
		readContext := service.newReadContext()
		retired, err := readContext.committedRetired(context.Background(), readContext.adoptReview(currentRun, review))
		var failure *domain.Failure
		if !retired && (!errors.As(err, &failure) || failure.Reason() != retiredProviderArtifactReason) {
			t.Fatalf("%s source lineage escaped retirement: retired=%t err=%v", family, retired, err)
		}
		if store.resolveCalls != 1 {
			t.Fatalf("lineage was not resolved: %d", store.resolveCalls)
		}
	}
}

// adoptReview registers an already-verified review for run when only the
// retirement predicate is exercised.
func (context *readContext) adoptReview(run ports.PublicationRun, review CommittedReview) *contextRun {
	node := &contextRun{run: run, stage: readCommittedStage, review: review, hasReview: true}
	context.byRun[run.RunID().String()] = node
	context.order = append(context.order, node)
	return node
}

func historicalCaseByID(t *testing.T, id string) historical.Case {
	t.Helper()
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("historical corpus fixture %q is absent", id)
	return historical.Case{}
}

func TestReadRunStatusRejectsTransitiveAndCompositeRetiredLineage(t *testing.T) {
	validator := mustSharedQueryTestValidator(t)

	t.Run("active child of retired parent", func(t *testing.T) {
		c := historicalCaseByID(t, "rerun-exact")
		for _, family := range []string{"kimi", "cursor", "codex", "agy"} {
			t.Run(family, func(t *testing.T) {
				store, childRun := historicalQueryStore(t, c)
				childSnapshot := store.snapshotsByRun[c.RunID]
				childFinal, err := decodeFinalDTO(childSnapshot.Final().Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if childFinal.ImmutableLineage.SourceRunID == nil {
					t.Fatal("rerun-exact fixture omitted SourceRunID")
				}
				parentRunID := *childFinal.ImmutableLineage.SourceRunID
				parentRun, ok := store.resolutionsByRun[parentRunID]
				if !ok {
					t.Fatalf("rerun-exact parent run %s absent from store", parentRunID)
				}
				parentSnapshot := store.snapshotsByRun[parentRunID]
				parentFinal, err := decodeFinalDTO(parentSnapshot.Final().Bytes())
				if err != nil {
					t.Fatal(err)
				}
				parentManifest, err := decodeManifestDTO(parentSnapshot.Manifest().Bytes())
				if err != nil {
					t.Fatal(err)
				}
				// Retire the parent run's provider identity while keeping the child run itself active.
				for i := range parentFinal.RoleOutcomes {
					if parentFinal.RoleOutcomes[i].ProviderInstance != nil {
						retired := family + "-logic"
						parentFinal.RoleOutcomes[i].ProviderInstance = &retired
					}
				}
				for i := range parentManifest.Attempts {
					parentManifest.Attempts[i].ProviderInstance = family + "-logic"
				}
				for i := range parentManifest.RoleReports {
					parentManifest.RoleReports[i].ProviderInstance = family + "-logic"
				}
				parentFinalBytes, err := json.Marshal(parentFinal)
				if err != nil {
					t.Fatal(err)
				}
				parentFinalID, err := ports.NewFinalReviewIdentity(
					parentSnapshot.Final().Identity().ReviewID(),
					parentSnapshot.Final().Identity().Path(),
					querySHA(parentFinalBytes),
				)
				if err != nil {
					t.Fatal(err)
				}
				parentFinalArt, err := ports.NewFinalReviewArtifact(parentFinalID, parentFinalBytes)
				if err != nil {
					t.Fatal(err)
				}
				parentManifest.FinalReview.SHA256 = parentFinalID.SHA256()
				parentManifest.RecoveryJournal.ExpectedFinal.SHA256 = parentFinalID.SHA256()
				parentManifestBytes, err := json.Marshal(parentManifest)
				if err != nil {
					t.Fatal(err)
				}
				retiredParentSnap, err := ports.NewCommittedPublicationSnapshot(
					parentFinalArt,
					mustQueryArtifact(t, parentSnapshot.Manifest().Path(), parentManifestBytes),
					parentSnapshot.LineageEdge(),
					parentSnapshot.Epoch(),
				)
				if err != nil {
					t.Fatal(err)
				}
				store.snapshotsByRun[parentRunID] = retiredParentSnap
				store.observationsByRun[parentRunID] = queryP2Observation(
					t, parentRun, retiredParentSnap, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1,
				)

				service := mustQueryService(t, store, validator, nil)
				// Confirm verifySnapshot alone admits the active-provider child,
				// so rejection comes from statusWithin's committedRetired walk.
				rc := service.newReadContext()
				node, err := rc.ensureRun(context.Background(), childRun, readStatusStage)
				if err != nil {
					t.Fatalf("ensureRun: %v", err)
				}
				if err := rc.verifySnapshot(context.Background(), node); err != nil {
					t.Fatalf("verifySnapshot unexpectedly rejected active child: %v", err)
				}

				_, statusErr := service.ReadRunStatus(context.Background(), childRun)
				var failure *domain.Failure
				if !errors.As(statusErr, &failure) || failure.Class() != domain.FailureArtifact ||
					failure.Reason() != RetiredProviderArtifactReason {
					t.Fatalf("%s child ReadRunStatus = %#v, want FailureArtifact(%q)", family, statusErr, RetiredProviderArtifactReason)
				}
				if store.resolveCalls == 0 {
					t.Fatal("ReadRunStatus did not resolve parent lineage")
				}
			})
		}
	})

	t.Run("composite with retired source lineage", func(t *testing.T) {
		mixedCase := historicalCaseByID(t, "composite-mixed-v1")
		mixedStore, mixedRun := historicalQueryStore(t, mixedCase)
		mixedService := mustQueryService(t, mixedStore, validator, nil)
		rc := mixedService.newReadContext()
		node, err := rc.ensureRun(context.Background(), mixedRun, readStatusStage)
		if err != nil {
			t.Fatalf("ensureRun: %v", err)
		}
		if err := rc.verifySnapshot(context.Background(), node); err != nil {
			t.Fatalf("verifySnapshot unexpectedly rejected composite-mixed-v1: %v", err)
		}
		_, statusErr := mixedService.ReadRunStatus(context.Background(), mixedRun)
		var failure *domain.Failure
		if !errors.As(statusErr, &failure) || failure.Class() != domain.FailureArtifact ||
			failure.Reason() != RetiredProviderArtifactReason {
			t.Fatalf("composite-mixed-v1 ReadRunStatus = %#v, want FailureArtifact(%q)", statusErr, RetiredProviderArtifactReason)
		}

		copiedCase := historicalCaseByID(t, "composite-copied-v1")
		copiedStore, copiedRun := historicalQueryStore(t, copiedCase)
		snapshot := copiedStore.snapshotsByRun[copiedCase.RunID]
		identity := func(s string) string { return s }
		entries := queryRuntimeFixtureEntries(t, snapshot, copiedStore.auxiliaryArtifacts, identity, bytes.Clone)
		prefix := copiedCase.SessionID + "/" + copiedCase.RunID + "/"
		path := prefix + compositesupport.DocumentPath
		var doc compositesupport.Document
		if err := json.Unmarshal(entries[path].bytes, &doc); err != nil {
			t.Fatal(err)
		}
		doc.Sources[0].ProviderIdentities = append(doc.Sources[0].ProviderIdentities, "codex-retired")
		sort.Strings(doc.Sources[0].ProviderIdentities)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		entries[path].bytes = append(raw, '\n')
		retainedQueryRebind(t, entries, prefix)
		updated, observation, artifacts := retainedQuerySnapshot(t, copiedRun, snapshot, copiedStore.auxiliaryArtifacts, entries, domain.OperationalExitCode(copiedCase.Expected.Exit))
		copiedStore.snapshotsByRun[copiedCase.RunID] = updated
		copiedStore.observationsByRun[copiedCase.RunID] = observation
		copiedStore.auxiliaryArtifacts = artifacts
		copiedService := mustQueryService(t, copiedStore, validator, nil)
		rc2 := copiedService.newReadContext()
		node2, err := rc2.ensureRun(context.Background(), copiedRun, readStatusStage)
		if err != nil {
			t.Fatalf("ensureRun: %v", err)
		}
		if err := rc2.verifySnapshot(context.Background(), node2); err != nil {
			t.Fatalf("verifySnapshot unexpectedly rejected active-role composite: %v", err)
		}
		_, copiedStatusErr := copiedService.ReadRunStatus(context.Background(), copiedRun)
		if !errors.As(copiedStatusErr, &failure) || failure.Class() != domain.FailureArtifact ||
			failure.Reason() != RetiredProviderArtifactReason {
			t.Fatalf("active-role composite ReadRunStatus = %#v, want FailureArtifact(%q)", copiedStatusErr, RetiredProviderArtifactReason)
		}
	})
}

func TestReadRunStatusAllowsActiveRunWithUnavailableFailedRunRecoverySource(t *testing.T) {
	c := historicalCaseByID(t, "recovery-child-v2")
	store, childRun := historicalQueryStore(t, c)
	childSnapshot := store.snapshotsByRun[c.RunID]
	childFinal, err := decodeFinalDTO(childSnapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if childFinal.ImmutableLineage.SourceRunID == nil || childFinal.ImmutableLineage.SourceKind != "failed_run_recovery" {
		t.Fatalf("recovery-child-v2 lineage = %+v, want failed_run_recovery source", childFinal.ImmutableLineage)
	}
	sourceRunID := *childFinal.ImmutableLineage.SourceRunID
	sourceRun, ok := store.resolutionsByRun[sourceRunID]
	if !ok {
		t.Fatalf("recovery-child-v2 source run %s absent from resolutionsByRun", sourceRunID)
	}
	// Remove the source run's recovery manifest while keeping the run resolvable
	// so recovery.Read returns recovery.ErrUnavailable.
	recoveryPath, err := recovery.ManifestPath(sourceRun)
	if err != nil {
		t.Fatal(err)
	}
	if _, existed := store.auxiliaryArtifacts[recoveryPath.String()]; !existed {
		t.Fatalf("expected recovery manifest at %s in fixture", recoveryPath.String())
	}
	delete(store.auxiliaryArtifacts, recoveryPath.String())

	service := mustQueryService(t, store, mustSharedQueryTestValidator(t), nil)
	status, err := service.ReadRunStatus(context.Background(), childRun)
	if err != nil {
		t.Fatalf("ReadRunStatus with unavailable failed_run_recovery source failed: %v", err)
	}
	if status.PublicationStatus() != domain.PublicationCommitted {
		t.Fatalf("publication status = %s, want committed", status.PublicationStatus())
	}
	if store.resolveCalls == 0 || store.auxiliaryReadsByRun[sourceRunID] == 0 {
		t.Fatalf("expected recovery lineage probe: resolveCalls=%d sourceAuxReads=%d", store.resolveCalls, store.auxiliaryReadsByRun[sourceRunID])
	}
}
