package publication

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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
	if got := len(first.Excerpts()); got != 5 {
		t.Fatalf("support artifact count = %d, want excerpt, normalized finding, role reports, and support index", got)
	} else {
		if got, want := first.Excerpts()[0].Path().String(), prefix+"/excerpts/F001_1.md"; got != want {
			t.Fatalf("excerpt path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[1].Path().String(), prefix+"/excerpts/F001.json"; got != want {
			t.Fatalf("normalized finding path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[2].Path().String(), prefix+"/role-reports/logic.md"; got != want {
			t.Fatalf("logic role report path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[3].Path().String(), prefix+"/role-reports/security.md"; got != want {
			t.Fatalf("security role report path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[4].Path().String(), prefix+"/support/index.json"; got != want {
			t.Fatalf("support index path = %q, want %q", got, want)
		}
	}

	var final finalReviewWire
	if err := unmarshalExact(first.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if final.StructuredExtractionStatus != string(domain.StructuredExtractionStructured) {
		t.Fatalf("structured_extraction_status = %q", final.StructuredExtractionStatus)
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
	if final.Provenance.Production == nil {
		t.Fatal("final artifact omits production provenance")
	}
	production := final.Provenance.Production
	if production.BuildProduct != "mulgae" || production.BuildVersion != "0.1.0" ||
		production.BuildCommit != "0123456789abcdef" || !production.ObjectivePresent ||
		production.ObjectiveSHA256 == nil || production.SnapshotManifestSHA256 == "" ||
		production.WorkspaceTerminalReceipt != sha256Identifier([]byte("workspace-terminal")) || len(production.Providers) != 2 {
		t.Fatalf("final production provenance is incomplete: %#v", production)
	}
	for _, provider := range production.Providers {
		if provider.Family == "" || provider.Instance == "" || provider.Version == "" ||
			provider.Executable == "" || provider.ExecutableSHA256 == "" ||
			provider.Launcher == "" || provider.LauncherSHA256 == "" ||
			provider.ProfileGeneration == "" || provider.AdapterProfile == "" ||
			len(provider.QualificationReceiptIDs) == 0 || len(provider.PacketTransportReceiptIDs) == 0 ||
			provider.NamespaceTerminalReceipt == "" {
			t.Fatalf("final provider provenance is incomplete: %#v", provider)
		}
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
	if manifest.StructuredExtractionStatus != string(domain.StructuredExtractionStructured) || len(manifest.RoleReports) != 2 {
		t.Fatalf("manifest role reports = %#v structured=%q", manifest.RoleReports, manifest.StructuredExtractionStatus)
	}
	if manifest.RoleReports[0].Role != "logic" || manifest.RoleReports[0].Path != "role-reports/logic.md" ||
		manifest.RoleReports[0].ContentType != "text/markdown" ||
		manifest.RoleReports[0].ProviderInstance == "" || manifest.RoleReports[0].AttemptID == "" ||
		manifest.RoleReports[1].Role != "security" || manifest.RoleReports[1].Path != "role-reports/security.md" ||
		manifest.RoleReports[1].ContentType != "text/markdown" ||
		manifest.RoleReports[1].ProviderInstance == "" || manifest.RoleReports[1].AttemptID == "" {
		t.Fatalf("manifest role report identities = %#v", manifest.RoleReports)
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

func TestFinalArtifactV3SerializesVerifiedVisualEvidence(t *testing.T) {
	t.Parallel()
	candidate := publicationTestCandidate(t, true)
	candidate.findings[0].evidence[0].visual = &preparedVisualEvidence{
		path: "design-specs/home.png", sha256: "sha256:" + strings.Repeat("d", 64),
		x: 24, y: 120, width: 320, height: 48,
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var final finalReviewWire
	if err := unmarshalExact(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if final.SchemaVersion != "mulgae-review-artifact.v1" {
		t.Fatalf("schema version = %q", final.SchemaVersion)
	}
	visual := final.Findings[0].Evidence[0].Visual
	if visual == nil || visual.Path != "design-specs/home.png" || visual.SHA256 != "sha256:"+strings.Repeat("d", 64) ||
		visual.BBox != (visualBoundingBoxWire{X: 24, Y: 120, Width: 320, Height: 48}) || visual.Verification != "verified" {
		t.Fatalf("serialized visual evidence = %#v", visual)
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
	if index.SchemaVersion != "mulgae-run-support-index.v1" || len(index.Artifacts) == 0 {
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
			candidateManifest.SchemaVersion == "mulgae-runtime-target-manifest.v1" {
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
			decoded.SchemaVersion == "mulgae-runtime-target-manifest.v1" {
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

func TestRuntimeArtifactsPersistCapturedReviewArchive(t *testing.T) {
	t.Parallel()
	candidate := publicationRuntimeCandidate(t)
	target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(nil, "policy")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				candidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), archive...)
			}
		}
	}
	artifacts, err := candidate.buildRuntimeArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	var manifest runtimeTargetManifestWire
	foundArchive := false
	foundBlob := false
	for _, artifact := range artifacts {
		if artifact.Path().String() == candidate.sessionID.String()+"/"+candidate.runID.String()+"/target/captured-review.json" {
			foundArchive = bytes.Contains(artifact.Bytes(), []byte(`"schema_version":"mulgae-captured-review-archive.v2"`)) &&
				!bytes.Contains(artifact.Bytes(), []byte(`"bytes"`))
		}
		if strings.Contains(artifact.Path().String(), "/target/blobs/sha256-") {
			foundBlob = true
		}
		var decoded runtimeTargetManifestWire
		if unmarshalExact(artifact.Bytes(), &decoded) == nil && decoded.SchemaVersion == "mulgae-runtime-target-manifest.v1" {
			manifest = decoded
		}
	}
	if !foundArchive || !foundBlob || manifest.CapturedArchive == nil || manifest.CapturedArchive.Path == "" || manifest.CapturedArchive.SHA256 == "" {
		t.Fatal("captured review archive was not persisted and manifest-bound")
	}
}

func TestPublicationBundleAcceptsDeduplicatedLargeCapture(t *testing.T) {
	contents := bytes.Repeat([]byte("x"), 1<<20)
	files := make([]ports.WorkspaceSnapshotFile, 8)
	for index := range files {
		path, err := ports.NewSafeRelativePath(fmt.Sprintf("fixtures/copy-%02d.txt", index))
		if err != nil {
			t.Fatal(err)
		}
		files[index], err = ports.NewWorkspaceSnapshotFile(path, contents, sha256Identifier(contents))
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, "deduplicated-large-capture")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive) >= 2<<20 {
		t.Fatalf("deduplicated runtime bundle size = %d", len(archive))
	}

	candidate := publicationRuntimeCandidate(t)
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				candidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), archive...)
			}
		}
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationBundleSize(bundle, 8<<20); err != nil {
		t.Fatalf("deduplicated capture exceeded publication member limit: %v", err)
	}
	var capturedBlobCount int
	for _, artifact := range bundle.Excerpts() {
		if strings.Contains(artifact.Path().String(), "/target/blobs/sha256-") {
			capturedBlobCount++
		}
	}
	if capturedBlobCount != 2 {
		t.Fatalf("captured blob count = %d, want target plus one shared source blob", capturedBlobCount)
	}
}

func TestRuntimeArtifactsPersistAndBindArtistInputs(t *testing.T) {
	t.Parallel()
	candidate := publicationRuntimeCandidate(t)
	target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
	if err != nil {
		t.Fatal(err)
	}
	briefPath, _ := ports.NewSafeRelativePath("docs/roadmap.md")
	briefBytes := bytes.Repeat([]byte("Check visual hierarchy.\n"), 400_000)
	if int64(len(briefBytes)) <= ports.PublicationStructuredMemberMaxBytes {
		t.Fatal("artist brief fixture does not exceed the structured member limit")
	}
	brief, err := ports.NewWorkspaceSnapshotFile(briefPath, briefBytes, sha256Identifier(briefBytes))
	if err != nil {
		t.Fatal(err)
	}
	visualBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	visualPath, _ := ports.NewSafeRelativePath("design-specs/current.png")
	visual, err := ports.NewWorkspaceVisualAsset(visualPath, visualBytes, sha256Identifier(visualBytes), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	files := []ports.WorkspaceSnapshotFile{visual, brief}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, "artist-publication-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	artistContext, err := json.Marshal(capturedArtistInputWire{
		SchemaVersion: "mulgae-artist-inputs.v1", Status: "ready", TaskPath: "docs/roadmap.md", Task: string(briefBytes),
		VisualAssets: []capturedArtistVisualWire{{Path: "current/" + visual.Path().String(), SHA256: visual.SHA256(), MediaType: visual.MediaType()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, artistContext, true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				candidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), archive...)
			}
		}
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublicationBundleSize(bundle, ports.PublicationStructuredMemberMaxBytes); err != nil {
		t.Fatalf("source-sized artist input was capped as a structured member: %v", err)
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	var manifest runtimeTargetManifestWire
	var index runSupportIndexWire
	foundBrief, foundVisuals := false, false
	indexed := map[string]bool{}
	for _, artifact := range bundle.Excerpts() {
		switch artifact.Path().String() {
		case prefix + "inputs/artist-brief.md":
			foundBrief = bytes.Equal(artifact.Bytes(), briefBytes)
		case prefix + "inputs/artist-visual-assets.json":
			foundVisuals = bytes.Contains(artifact.Bytes(), []byte(visual.SHA256()))
		case prefix + "target/target-manifest.json":
			if err := json.Unmarshal(artifact.Bytes(), &manifest); err != nil {
				t.Fatal(err)
			}
		case prefix + "support/index.json":
			if err := json.Unmarshal(artifact.Bytes(), &index); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, identity := range index.Artifacts {
		indexed[identity.Path] = true
	}
	if !foundBrief || !foundVisuals || manifest.ArtistBrief == nil || manifest.ArtistVisualAssets == nil ||
		!indexed[prefix+"inputs/artist-brief.md"] || !indexed[prefix+"inputs/artist-visual-assets.json"] {
		t.Fatalf("artist artifacts are not fully bound: brief=%t visuals=%t manifest=%#v index=%#v", foundBrief, foundVisuals, manifest, index)
	}
	restored, err := ports.UnmarshalCapturedReviewMaterial(archive)
	var restoredInputs capturedArtistInputWire
	if err == nil {
		err = json.Unmarshal(restored.ProjectContext(), &restoredInputs)
	}
	if err != nil || restoredInputs.Task != string(briefBytes) {
		t.Fatalf("captured archive lost exact artist input: %v", err)
	}
}

func TestRuntimeArtifactsPublishAutomaticMissingBriefVisualsWithoutBriefArtifact(t *testing.T) {
	candidate := publicationRuntimeCandidate(t)
	target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
	if err != nil {
		t.Fatal(err)
	}
	visualBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	visualPath, _ := ports.NewSafeRelativePath("design-specs/changed.png")
	visual, err := ports.NewWorkspaceVisualAsset(visualPath, visualBytes, sha256Identifier(visualBytes), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest([]ports.WorkspaceSnapshotFile{visual}, "artist-missing-brief-publication-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: {visual},
	})
	if err != nil {
		t.Fatal(err)
	}
	artistContext, err := json.Marshal(capturedArtistInputWire{
		SchemaVersion: "mulgae-artist-inputs.v1", Status: "missing", TaskPath: "docs/missing.md",
		VisualAssets: []capturedArtistVisualWire{{Path: "current/" + visual.Path().String(), SHA256: visual.SHA256(), MediaType: visual.MediaType()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, artistContext, true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				candidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), archive...)
			}
		}
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatal(err)
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	var manifest runtimeTargetManifestWire
	var index runSupportIndexWire
	foundVisuals, foundBrief := false, false
	for _, artifact := range bundle.Excerpts() {
		switch artifact.Path().String() {
		case prefix + "inputs/artist-brief.md":
			foundBrief = true
		case prefix + "inputs/artist-visual-assets.json":
			foundVisuals = bytes.Contains(artifact.Bytes(), []byte(visual.SHA256()))
		case prefix + "target/target-manifest.json":
			if err := json.Unmarshal(artifact.Bytes(), &manifest); err != nil {
				t.Fatal(err)
			}
		case prefix + "support/index.json":
			if err := json.Unmarshal(artifact.Bytes(), &index); err != nil {
				t.Fatal(err)
			}
		}
	}
	indexed := make(map[string]bool, len(index.Artifacts))
	for _, identity := range index.Artifacts {
		indexed[identity.Path] = true
	}
	if foundBrief || !foundVisuals || manifest.ArtistBrief != nil || manifest.ArtistVisualAssets == nil ||
		indexed[prefix+"inputs/artist-brief.md"] || !indexed[prefix+"inputs/artist-visual-assets.json"] {
		t.Fatalf("missing-brief artist artifacts = brief:%t visuals:%t manifest:%#v index:%#v", foundBrief, foundVisuals, manifest, index)
	}

	unqualifiedContext, err := json.Marshal(capturedArtistInputWire{
		SchemaVersion: "mulgae-artist-inputs.v1", Status: "missing", TaskPath: "docs/missing.md",
		VisualAssets: []capturedArtistVisualWire{{Path: visual.Path().String(), SHA256: visual.SHA256(), MediaType: visual.MediaType()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	unqualifiedMaterial, err := ports.NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, unqualifiedContext, true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	unqualifiedArchive, err := ports.MarshalCapturedReviewMaterial(unqualifiedMaterial)
	if err != nil {
		t.Fatal(err)
	}
	unqualifiedCandidate := publicationRuntimeCandidate(t)
	for roleIndex := range unqualifiedCandidate.roles {
		for attemptIndex := range unqualifiedCandidate.roles[roleIndex].attempts {
			for invocationIndex := range unqualifiedCandidate.roles[roleIndex].attempts[attemptIndex].invocations {
				unqualifiedCandidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), unqualifiedArchive...)
			}
		}
	}
	if _, err := unqualifiedCandidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42); err == nil {
		t.Fatalf("side-unqualified artist visual returned %v", err)
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
func TestFinalProductionProvenanceRejectsEachMutatedField(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var baseline finalReviewWire
	if err := unmarshalExact(bundle.Final().Bytes(), &baseline); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*finalReviewWire)
	}{
		{"build product", func(f *finalReviewWire) { f.Provenance.Production.BuildProduct = "" }},
		{"build version", func(f *finalReviewWire) { f.Provenance.Production.BuildVersion = "9.9.9" }},
		{"build commit", func(f *finalReviewWire) { f.Provenance.Production.BuildCommit = "other" }},
		{"objective presence", func(f *finalReviewWire) { f.Provenance.Production.ObjectivePresent = false }},
		{"objective digest", func(f *finalReviewWire) { value := ""; f.Provenance.Production.ObjectiveSHA256 = &value }},
		{"snapshot digest", func(f *finalReviewWire) { f.Provenance.Production.SnapshotManifestSHA256 = "" }},
		{"workspace receipt", func(f *finalReviewWire) { f.Provenance.Production.WorkspaceTerminalReceipt = "" }},
		{"family", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Family = "" }},
		{"instance", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Instance = "" }},
		{"provider version", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Version = "" }},
		{"executable", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Executable = "" }},
		{"executable digest", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].ExecutableSHA256 = "" }},
		{"launcher", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].Launcher = "" }},
		{"launcher digest", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].LauncherSHA256 = "" }},
		{"profile generation", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].ProfileGeneration = "" }},
		{"adapter profile", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].AdapterProfile = "" }},
		{"qualification receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].QualificationReceiptIDs[0] = "" }},
		{"packet receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].PacketTransportReceiptIDs[0] = "" }},
		{"namespace receipt", func(f *finalReviewWire) { f.Provenance.Production.Providers[0].NamespaceTerminalReceipt = "" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			final := baseline
			final.Provenance.Production = cloneProductionWire(baseline.Provenance.Production)
			test.mutate(&final)
			if err := validateFinalProductionProvenance(final); err == nil {
				t.Fatal("reader accepted mutated production provenance")
			}
		})
	}
}

func TestManifestRoleReportRecordsTransport(t *testing.T) {
	t.Parallel()

	stdoutOnly := publicationTestCandidate(t, false).ValidatedCandidateSHA256()
	candidate := publicationTestCandidate(t, false)
	candidate.roles[1].outputTransport = ports.ProviderOutputTransportStagedFile
	if digest := candidate.ValidatedCandidateSHA256(); digest == "" || digest == stdoutOnly {
		t.Fatalf("validated candidate identity = %q, want a value bound to the role output transport", digest)
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !bundle.Valid() {
		t.Fatal("bundle with mixed role-report transports failed its semantic reopen")
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.RoleReports) != 2 ||
		manifest.RoleReports[0].Transport != string(ports.ProviderOutputTransportStdout) ||
		manifest.RoleReports[1].Transport != string(ports.ProviderOutputTransportStagedFile) {
		t.Fatalf("manifest role report transports = %#v", manifest.RoleReports)
	}

	snapshot, err := ports.NewCommittedPublicationSnapshot(
		bundle.Final(), bundle.Manifest(), bundle.LineageEdge(), bundle.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := ProjectCommittedRoleReports(snapshot)
	if err != nil {
		t.Fatalf("ProjectCommittedRoleReports() error = %v", err)
	}
	if len(reports) != 2 ||
		reports[0].Transport != string(ports.ProviderOutputTransportStdout) ||
		reports[1].Transport != string(ports.ProviderOutputTransportStagedFile) {
		t.Fatalf("committed role report transports = %#v", reports)
	}
}

func TestManifestRoleReportsRejectUnknownTransport(t *testing.T) {
	t.Parallel()

	candidate := publicationTestCandidate(t, false)
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationTestReviewID(t), publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var manifest runManifestWire
	if err := unmarshalExact(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	if err := unmarshalExact(bundle.Final().Bytes(), &final); err != nil {
		t.Fatal(err)
	}
	if err := validateManifestRoleReports(manifest, final); err != nil {
		t.Fatalf("committed role reports rejected before tampering: %v", err)
	}
	for _, transport := range []string{"carrier_pigeon", "STDOUT", ""} {
		tampered := manifest
		tampered.RoleReports = append([]manifestRoleReportWire(nil), manifest.RoleReports...)
		tampered.RoleReports[0].Transport = transport
		if err := validateManifestRoleReports(tampered, final); err == nil {
			t.Fatalf("reader accepted role report transport %q", transport)
		}
	}

	emitted := bundle.Manifest().Bytes()
	stripped := bytes.Replace(emitted, []byte(`,"transport":"stdout"`), nil, 1)
	if bytes.Equal(stripped, emitted) {
		t.Fatal("manifest did not emit a canonical role-report transport")
	}
	var decoded runManifestWire
	if err := unmarshalCanonicalPublicationRecord(stripped, &decoded, "committed manifest"); err == nil {
		t.Fatal("reader accepted a manifest whose role report omits transport")
	}
}

func cloneProductionWire(value *productionProvenanceWire) *productionProvenanceWire {
	result := *value
	if value.ObjectiveSHA256 != nil {
		objective := *value.ObjectiveSHA256
		result.ObjectiveSHA256 = &objective
	}
	result.Providers = append([]productionProviderWire(nil), value.Providers...)
	for index := range result.Providers {
		result.Providers[index].QualificationReceiptIDs = append([]string(nil), value.Providers[index].QualificationReceiptIDs...)
		result.Providers[index].PacketTransportReceiptIDs = append([]string(nil), value.Providers[index].PacketTransportReceiptIDs...)
	}
	return &result
}
