//go:build darwin && arm64

package publication

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

func publicationWireGoldenOutputs(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	encode := func(name string, value any) {
		raw, err := marshalCanonical(value)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = string(raw)
	}
	bundle := func(name string, b PublicationBundle) {
		result[name+"/final"] = string(b.Final().Bytes())
		result[name+"/manifest"] = string(b.Manifest().Bytes())
		result[name+"/journal"] = string(b.Journal().Bytes())
		result[name+"/status"] = string(b.Status().Bytes())
		result[name+"/lineage"] = string(b.LineageEdge().Bytes())
		result[name+"/epoch"] = string(b.Epoch().Record().Bytes())
		for _, artifact := range b.Excerpts() {
			value := string(artifact.Bytes())
			if !utf8.Valid(artifact.Bytes()) {
				value = "binary-hex:" + hex.EncodeToString(artifact.Bytes())
			}
			result[name+"/support/"+artifact.Path().String()] = value
		}
	}
	for _, c := range []struct {
		name      string
		candidate PreparedCandidate
	}{{"captured-findings", publicationTestCandidate(t, true)}, {"captured-empty", publicationTestCandidate(t, false)}, {"followup", publicationFollowupGoldenCandidate(t)}} {
		b, err := c.candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
		if err != nil {
			t.Fatal(err)
		}
		bundle(c.name, b)
	}
	bundle("live-empty", publicationLiveGoldenBundle(t, livePublicationNoChange(t)))
	bundle("live-findings", publicationLiveGoldenBundle(t, livePublicationChangedFixture(t)))
	c := publicationCompositeGoldenCandidate(t)
	b, err := c.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatal(err)
	}
	bundle("composite", b)
	identity := artifactIdentityWire{Path: "café é 한글 <&>\r\n", SHA256: "sha256:literal"}
	restart := restartStateWire{SessionID: "session", RunID: "run", ExpectedStaged: identity, ExpectedFinal: identity, ValidatedCandidateSHA256: "candidate", StoreEpoch: 42, NormalExit: 4, ManifestPath: "manifest", LineageEdgePath: "lineage", EpochPath: "epoch"}
	for _, state := range []domain.PersistedJournalState{domain.JournalCollecting, domain.JournalContentValidated, domain.JournalFinalStaged, domain.JournalFinalFileInstalled, domain.JournalManifestCommitted, domain.JournalCompleted} {
		restart.PersistedJournalState = string(state)
		encode("journal/"+string(state), publicationJournalWire{SchemaVersion: publicationJournalV1, RestartState: restart})
		for _, authority := range []domain.PublicationAuthority{domain.PublicationAuthorityNone, domain.PublicationAuthorityP0, domain.PublicationAuthorityP1, domain.PublicationAuthorityP2} {
			encode("status/"+string(state)+"/"+string(authority), publicationStatusWire{SchemaVersion: publicationStatusV1, PublicationStatus: "committed", PublicationAuthority: string(authority), RestartState: restart})
		}
	}
	for _, reasons := range [][]string{nil, {}, {"missing_final", "candidate_mismatch"}} {
		encode("corruption/"+stringMustJSON(reasons), publicationCorruptionDiagnosticWire{SchemaVersion: "mulgae-publication-corruption.v1", SessionID: "session", RunID: "run", ObservationEpoch: 42, ReasonCodes: reasons})
	}
	// Exercise custom selection with optional fields both absent and present.
	for _, present := range []bool{false, true} {
		role := compositeRoleWire{Role: "logic", ValidFindingIDs: []string{}}
		finding := compositeFindingWire{ID: "F001", Title: "café é 한글 <&>\r\n", Source: compositeFindingSourceWire{RunID: "run", AttemptID: "attempt", FindingID: "F007"}}
		composition := compositeCompositionWire{Fingerprint: "fingerprint", RootRunID: "run", Sources: []compositeSourceWire{}}
		if present {
			role.SourceReviewID = "review"
			role.SourceRecoveryManifestSHA256 = "recovery"
			role.SourceKind = "recovery"
			finding.Source.ReviewID = "review"
			finding.Source.RecoveryManifestSHA256 = "recovery"
			finding.Source.SourceKind = "recovery"
			composition.RootReviewID = "review"
			composition.RootRecoveryManifestSHA256 = "recovery"
			composition.RootSourceKind = "recovery"
			composition.Sources = []compositeSourceWire{{Role: "logic", ReviewID: "review", RecoveryManifestSHA256: "recovery", SourceKind: "recovery"}}
		}
		encode("custom-role/"+stringMustJSON(present), role)
		encode("custom-finding/"+stringMustJSON(present), finding)
		encode("composition/"+stringMustJSON(present), composition)
	}
	return result
}
func stringMustJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
func TestPublicationWireGoldenCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m2-publication-wire.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	actual := publicationWireGoldenOutputs(t)
	if len(actual) != len(want) {
		t.Fatalf("member count %d want %d", len(actual), len(want))
	}
	for name, expected := range want {
		t.Run(name, func(t *testing.T) {
			if got, ok := actual[name]; !ok || !reflect.DeepEqual(got, expected) {
				t.Fatalf("bytes=%q;want %q", got, expected)
			}
		})
	}
}
