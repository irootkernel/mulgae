package query

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

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

func TestReadCommittedRejectsRetiredProductionProvider(t *testing.T) {
	run, snapshot, _ := queryCommittedFixture(t, domain.ExitCommittedCIRejected)
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	production := queryProductionFinalDTO()
	production.Provenance.Production.Providers[0].Family = "kimi"
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
	service := mustQueryService(t, &queryStore{observation: observation, snapshot: retiredSnapshot}, &queryValidator{}, nil)
	_, err = service.ReadCommitted(context.Background(), run)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != retiredProviderArtifactReason {
		t.Fatalf("retired artifact failure = %#v, want %q", err, retiredProviderArtifactReason)
	}
}
