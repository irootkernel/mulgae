package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type publicationTestValidator struct {
	ids    []ports.AssetID
	bytes  [][]byte
	reject bool
}

func (validator *publicationTestValidator) Validate(_ context.Context, id ports.AssetID, bytes []byte) error {
	validator.ids = append(validator.ids, id)
	validator.bytes = append(validator.bytes, append([]byte(nil), bytes...))
	if validator.reject {
		return errors.New("schema rejected bytes")
	}
	return nil
}

func TestPreparedCandidateBuildDeterministicPublicationBundle(t *testing.T) {
	t.Parallel()
	candidate := publicationTestCandidate(t, true)
	reviewID := publicationTestReviewID(t)
	validator := &publicationTestValidator{}
	first, err := candidate.Build(context.Background(), validator, reviewID, publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !first.Valid() {
		t.Fatal("built bundle is invalid")
	}
	if got, want := assetIDStrings(validator.ids), []string{finalReviewSchemaAsset, runManifestSchemaAsset}; !reflect.DeepEqual(got, want) {
		t.Fatalf("validator schema IDs = %#v, want %#v", got, want)
	}
	if len(validator.bytes) != 2 || !bytes.Equal(validator.bytes[0], first.Final().Bytes()) || !bytes.Equal(validator.bytes[1], first.Manifest().Bytes()) {
		t.Fatal("validator did not receive exact final and manifest bytes")
	}

	second, err := candidate.Build(context.Background(), &publicationTestValidator{}, reviewID, publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if !bytes.Equal(first.Final().Bytes(), second.Final().Bytes()) || !bytes.Equal(first.Manifest().Bytes(), second.Manifest().Bytes()) ||
		!bytes.Equal(first.LineageEdge().Bytes(), second.LineageEdge().Bytes()) || !bytes.Equal(first.Epoch().Record().Bytes(), second.Epoch().Record().Bytes()) ||
		!bytes.Equal(first.Journal().Bytes(), second.Journal().Bytes()) || !bytes.Equal(first.Status().Bytes(), second.Status().Bytes()) {
		t.Fatal("identical inputs produced non-deterministic publication bytes")
	}
	if !sameImmutableArtifact(first.StagedFinal(), second.StagedFinal()) ||
		len(first.Excerpts()) != len(second.Excerpts()) {
		t.Fatal("identical inputs produced non-deterministic staged final or excerpt cardinality")
	}
	for index := range first.Excerpts() {
		if !sameImmutableArtifact(first.Excerpts()[index], second.Excerpts()[index]) {
			t.Fatalf("identical inputs produced non-deterministic excerpt %d", index)
		}
	}

	prefix := "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	if got, want := first.Final().Identity().Path().String(), prefix+"/review_019f596a-d174-7321-b920-c2d312c82cc2.json"; got != want {
		t.Fatalf("final path = %q, want %q", got, want)
	}
	if got, want := first.StagedFinal().Path().String(), prefix+"/publication/staged/review_019f596a-d174-7321-b920-c2d312c82cc2.json.tmp"; got != want {
		t.Fatalf("staged path = %q, want %q", got, want)
	}
	if got, want := first.LineageEdge().Path().String(), "store/lineage-edges/e_019f596a-d174-7321-b920-c2d312c82cc2.json"; got != want {
		t.Fatalf("edge path = %q, want %q", got, want)
	}
	if got, want := first.Epoch().Record().Path().String(), "store/epochs/epoch_00000000000000000042.json"; got != want {
		t.Fatalf("epoch path = %q, want %q", got, want)
	}
	if got := len(first.Excerpts()); got != 3 {
		t.Fatalf("support artifact count = %d, want excerpt, normalized finding, and support index", got)
	} else {
		if got, want := first.Excerpts()[0].Path().String(), prefix+"/excerpts/F001_1.md"; got != want {
			t.Fatalf("excerpt path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[1].Path().String(), prefix+"/excerpts/F001.json"; got != want {
			t.Fatalf("normalized finding path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[2].Path().String(), prefix+"/support/index.json"; got != want {
			t.Fatalf("support index path = %q, want %q", got, want)
		}
	}

	var final finalReviewWire
	if err := unmarshalExact(first.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if final.PublicationStatus != "committed" || final.ImmutableLineage.ParentRunID != nil || final.ImmutableLineage.SourceRunID != nil ||
		final.ImmutableLineage.SourceReviewID != nil || final.ImmutableLineage.SourceFindingRef != nil || final.ImmutableLineage.ReplayMode != nil {
		t.Fatal("final root publication lineage is not exact")
	}
	if final.ImmutableLineage.LineageEdgePath != first.LineageEdge().Path().String() || final.ImmutableLineage.LineageEdgeSHA256 != first.LineageEdge().SHA256() {
		t.Fatal("final lineage edge binding is not exact")
	}
	if got := final.Findings[0].Evidence[0]; got.Source.SessionID != final.SessionID || got.Source.RunID != final.RunID ||
		got.Source.ReviewID != final.ReviewID || got.Source.FindingID != "F001" || got.Source.SourceTargetSHA256 != final.Target.ContentSHA256 ||
		got.Current.TargetSHA256 != final.Target.ContentSHA256 || got.Current.Verification != "verified" {
		t.Fatalf("final evidence provenance is inconsistent: %#v", got)
	}
	if bytes.Contains(bytes.ToLower(first.Final().Bytes()), []byte("organizational approval")) {
		t.Fatal("final artifact includes organizational approval text")
	}

	var manifest runManifestWire
	if err := unmarshalExact(first.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.PersistedJournalState != "manifest_committed" || manifest.DurableObservationClass != "P2_COMMITTED" ||
		manifest.DerivedPublicationStatus != "committed" || manifest.PublicationAuthority != "P2" || manifest.ExitCode != 1 {
		t.Fatalf("manifest P2 state is inconsistent: %#v", manifest)
	}
	if manifest.FinalReview.SHA256 != first.Final().Identity().SHA256() || manifest.CompositeIdentity.LineageEdge.SHA256 != first.LineageEdge().SHA256() ||
		manifest.CompositeIdentity.Epoch.Path != first.Epoch().Record().Path().String() {
		t.Fatal("manifest composite binding is inconsistent")
	}

	var epoch publicationEpochWire
	if err := unmarshalExact(first.Epoch().Record().Bytes(), &epoch); err != nil {
		t.Fatal(err)
	}
	if epoch.Manifest.SHA256 != first.Manifest().SHA256() || epoch.LineageEdge.SHA256 != first.LineageEdge().SHA256() ||
		epoch.FinalReview.SHA256 != first.Final().Identity().SHA256() {
		t.Fatal("epoch does not bind exact immutable composite hashes")
	}

	var journal publicationJournalWire
	if err := unmarshalExact(first.Journal().Bytes(), &journal); err != nil {
		t.Fatal(err)
	}
	if journal.PersistedJournalState != "manifest_committed" || journal.StoreEpoch != 42 || journal.NormalExit != 1 ||
		journal.ExpectedStaged.Path != first.StagedFinal().Path().String() || journal.ExpectedFinal.SHA256 != first.Final().Identity().SHA256() ||
		journal.ManifestPath != first.Manifest().Path().String() || journal.LineageEdgePath != first.LineageEdge().Path().String() ||
		journal.EpochPath != first.Epoch().Record().Path().String() {
		t.Fatalf("journal restart material is inconsistent: %#v", journal)
	}

	finalBytes := first.Final().Bytes()
	finalBytes[0] = '!'
	if first.Final().Bytes()[0] == '!' {
		t.Fatal("final bytes are not defensively copied")
	}
	journalBytes := first.Journal().Bytes()
	journalBytes[0] = '!'
	if first.Journal().Bytes()[0] == '!' {
		t.Fatal("journal bytes are not defensively copied")
	}
}
func TestPublicationBundleBindsCanonicalSupportIndex(t *testing.T) {
	t.Parallel()

	bundle, err := publicationRuntimeCandidate(t).Build(
		context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	indexPath := bundle.Excerpts()[len(bundle.Excerpts())-1].Path()
	if got, want := indexPath.String(), bundle.Manifest().Path().String()[:0]+
		"s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json"; got != want {
		t.Fatalf("support index path = %q, want canonical %q", got, want)
	}
	if manifest.CompositeIdentity.SupportIndex.Path != indexPath.String() ||
		manifest.CompositeIdentity.SupportIndex.SHA256 != bundle.Excerpts()[len(bundle.Excerpts())-1].SHA256() {
		t.Fatal("manifest does not bind the exact support index")
	}
	var index runSupportIndexWire
	if err := unmarshalExact(bundle.Excerpts()[len(bundle.Excerpts())-1].Bytes(), &index); err != nil {
		t.Fatal(err)
	}
	if index.SchemaVersion != "kar-run-support-index.v1" || len(index.Artifacts) == 0 {
		t.Fatalf("support index is not canonical runtime inventory: %#v", index)
	}
	for _, artifact := range index.Artifacts {
		if artifact.Path == indexPath.String() {
			t.Fatal("support index recursively inventories itself")
		}
	}
}
func TestRepairedAttemptSelectsInitialReplayPrompt(t *testing.T) {
	t.Parallel()

	candidate := publicationRuntimeCandidate(t)
	appendPublicationRuntimeRepairInvocation(t, &candidate)
	bundle, err := candidate.Build(
		context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	var targetManifest *runtimeTargetManifestWire
	for _, artifact := range bundle.Excerpts() {
		var candidateManifest runtimeTargetManifestWire
		if err := unmarshalExact(artifact.Bytes(), &candidateManifest); err == nil &&
			candidateManifest.SchemaVersion == "kar-runtime-target-manifest.v1" {
			targetManifest = &candidateManifest
			break
		}
	}
	if targetManifest == nil {
		t.Fatal("runtime target manifest is absent")
	}
	if got, want := len(targetManifest.Prompts), 3; got != want {
		t.Fatalf("runtime prompt inventory count = %d, want %d", got, want)
	}
	var selected *selectedReplayPromptWire
	for index := range targetManifest.SelectedReplayPrompts {
		candidateSelection := &targetManifest.SelectedReplayPrompts[index]
		if candidateSelection.AttemptID != candidate.roles[0].attempts[0].id.String() {
			continue
		}
		if selected != nil {
			t.Fatal("successful repaired attempt has ambiguous replay prompts")
		}
		selected = candidateSelection
	}
	if selected == nil {
		t.Fatal("successful repaired attempt has no replay prompt")
	}
	if selected.Sequence != 1 || selected.Purpose != "initial" {
		t.Fatalf("selected replay prompt = %#v, want successful attempt initial prompt", selected)
	}
}

func TestFailedAttemptRetainsInitialReplayPrompt(t *testing.T) {
	t.Parallel()

	candidate := publicationRuntimeCandidate(t)
	attempt := &candidate.roles[0].attempts[0]
	attempt.state = domain.AttemptFailed
	artifacts, err := candidate.buildRuntimeArtifacts()
	if err != nil {
		t.Fatalf("buildRuntimeArtifacts() error = %v", err)
	}
	var targetManifest runtimeTargetManifestWire
	found := false
	for _, artifact := range artifacts {
		var decoded runtimeTargetManifestWire
		if err := unmarshalExact(artifact.Bytes(), &decoded); err == nil &&
			decoded.SchemaVersion == "kar-runtime-target-manifest.v1" {
			targetManifest = decoded
			found = true
			break
		}
	}
	if !found {
		t.Fatal("runtime target manifest is absent")
	}
	matches := 0
	for _, selected := range targetManifest.SelectedReplayPrompts {
		if selected.AttemptID == attempt.id.String() {
			matches++
			if selected.Sequence != 1 || selected.Purpose != "initial" {
				t.Fatalf("failed attempt replay prompt = %#v", selected)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("failed attempt replay selections = %d, want 1", matches)
	}
}

func TestPreparedCandidateBuildRejectsSchemaFailure(t *testing.T) {
	t.Parallel()
	validator := &publicationTestValidator{reject: true}
	_, err := publicationTestCandidate(t, false).Build(context.Background(), validator, publicationTestReviewID(t), publicationTestTime(), 1)
	if err == nil {
		t.Fatal("Build accepted validator rejection")
	}
	if got, want := assetIDStrings(validator.ids), []string{finalReviewSchemaAsset}; !reflect.DeepEqual(got, want) {
		t.Fatalf("validator schema IDs after rejection = %#v, want %#v", got, want)
	}
}

func unmarshalExact(bytes []byte, value any) error {
	return json.Unmarshal(bytes, value)
}

func assetIDStrings(ids []ports.AssetID) []string {
	values := make([]string, len(ids))
	for index, id := range ids {
		values[index] = id.String()
	}
	return values
}
