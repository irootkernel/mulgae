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

func liveAgyRetirementFixture(t *testing.T) (finalDTO, manifestDTO) {
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
	provider.Family, provider.Instance = "agy", "agy-documentation"
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

func TestAgyRetirementRequiresValidatedCurrentLiveBinding(t *testing.T) {
	final, manifest := liveAgyRetirementFixture(t)
	if finalRecordRetired(final, manifest) {
		t.Fatal("current live AGY instance was retired")
	}
	for name, mutate := range map[string]func(*finalDTO, *manifestDTO){
		"old final":                     func(f *finalDTO, _ *manifestDTO) { f.SchemaVersion = "mulgae-review-artifact.v1" },
		"old manifest":                  func(_ *finalDTO, m *manifestDTO) { m.SchemaVersion = "mulgae-run-manifest.v1" },
		"reused v3 without live source": func(f *finalDTO, _ *manifestDTO) { f.Target.LiveSource = nil },
		"source binding":                func(_ *finalDTO, m *manifestDTO) { m.Target.SourceIdentitySHA256 = "" },
		"support binding":               func(_ *finalDTO, m *manifestDTO) { m.CompositeIdentity.SupportIndex = nil },
		"captured authority":            func(_ *finalDTO, m *manifestDTO) { m.Target.ContentSHA256 = querySHA([]byte("old")) },
		"role outcome":                  func(f *finalDTO, _ *manifestDTO) { f.RoleOutcomes[0].Outcome = "not_applicable" },
		"Kimi attempt":                  func(_ *finalDTO, m *manifestDTO) { m.Attempts[0].ProviderInstance = "KIMI-logic" },
		"Kimi live provenance":          func(f *finalDTO, _ *manifestDTO) { f.Provenance.LiveProduction.Providers[0].Family = "kimi" },
	} {
		t.Run(name, func(t *testing.T) {
			f, m := liveAgyRetirementFixture(t)
			mutate(&f, &m)
			if !finalRecordRetired(f, m) {
				t.Fatal("historical, malformed, or Kimi provider escaped retirement")
			}
		})
	}
}

func TestCommittedProviderRetirementUsesValidatedLiveContext(t *testing.T) {
	run, _, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	for _, live := range []bool{false, true} {
		for _, family := range []string{"agy", "kimi"} {
			final, manifest := liveAgyRetirementFixture(t)
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
			retired, err := (&Service{}).committedArtifactRetired(context.Background(), run, review, map[string]struct{}{})
			if err != nil || retired != (!live || family == "kimi") {
				t.Fatalf("family=%s live=%t retired=%t err=%v", family, live, retired, err)
			}
		}
	}
}

func TestRetiredProviderInstanceUsesFamilyBoundaries(t *testing.T) {
	for _, value := range []string{"kimi", "KIMI-logic", "agy.security", "agy_profile"} {
		if !retiredProviderInstance(value) {
			t.Errorf("retired provider instance %q was not recognized", value)
		}
	}
	for _, value := range []string{"zcode", "grok-logic", "codex-primary-security", "kimiko", "agyx"} {
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
	for _, family := range []string{"kimi", "agy"} {
		service, _, run := retiredProductionFixture(t, family)
		_, err := service.ReadCommitted(context.Background(), run)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != retiredProviderArtifactReason {
			t.Fatalf("%s artifact failure = %#v, want %q", family, err, retiredProviderArtifactReason)
		}
	}
}

func TestCurrentLiveAgyStillRejectsRetiredSourceLineage(t *testing.T) {
	for _, family := range []string{"agy", "kimi"} {
		service, store, sourceRun := retiredProductionFixture(t, family)
		currentID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bb")
		if err != nil {
			t.Fatal(err)
		}
		currentRun, err := ports.NewPublicationRun(sourceRun.Root(), sourceRun.SessionID(), currentID)
		if err != nil {
			t.Fatal(err)
		}
		final, manifest := liveAgyRetirementFixture(t)
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
		retired, err := service.committedArtifactRetired(context.Background(), currentRun, review, map[string]struct{}{})
		var failure *domain.Failure
		if !retired && (!errors.As(err, &failure) || failure.Reason() != retiredProviderArtifactReason) {
			t.Fatalf("%s source lineage escaped retirement: retired=%t err=%v", family, retired, err)
		}
		if store.resolveCalls != 1 {
			t.Fatalf("lineage was not resolved: %d", store.resolveCalls)
		}
	}
}
