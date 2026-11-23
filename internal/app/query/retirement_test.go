package query

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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
