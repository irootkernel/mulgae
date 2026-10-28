package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	candidate := retainedLiveCandidate(t, true)
	candidate.target.live.provenance.HasObjective = true
	candidate.target.live.provenance.ObjectiveSHA256 = sha256Identifier([]byte("objective"))
	reviewID := publicationTestReviewID(t)
	validator := &publicationTestValidator{}
	first, err := candidate.Build(context.Background(), validator, reviewID, publicationTestTime(), 42)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !first.Valid() {
		t.Fatal("built bundle is invalid")
	}
	if got, want := assetIDStrings(validator.ids), []string{strings.Replace(finalReviewSchemaAsset, ".v1.", ".v4.", 1), strings.Replace(runManifestSchemaAsset, ".v1.", ".v4.", 1)}; !reflect.DeepEqual(got, want) {
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
	if got := len(first.Excerpts()); got != 6 {
		t.Fatalf("support artifact count = %d, want excerpt, normalized finding, role reports, live source, and support index", got)
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
		if got, want := first.Excerpts()[4].Path().String(), prefix+"/source/source.json"; got != want {
			t.Fatalf("live source path = %q, want %q", got, want)
		}
		if got, want := first.Excerpts()[5].Path().String(), prefix+"/support/index.json"; got != want {
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
		final.ImmutableLineage.SourceReviewID != nil || final.ImmutableLineage.SourceAttemptID != nil || final.ImmutableLineage.SourceFindingRef != nil || final.ImmutableLineage.ReplayMode != nil {
		t.Fatal("final root publication lineage is not exact")
	}
	if final.ImmutableLineage.LineageEdgePath != first.LineageEdge().Path().String() || final.ImmutableLineage.LineageEdgeSHA256 != first.LineageEdge().SHA256() {
		t.Fatal("final lineage edge binding is not exact")
	}
	if got := final.Findings[0].Evidence[0]; got.Source.SessionID != final.SessionID || got.Source.RunID != final.RunID ||
		got.Source.ReviewID != final.ReviewID || got.Source.FindingID != "F001" || got.Source.SourceTargetSHA256 != "" || got.Source.SourceIdentitySHA256 != final.Target.LiveSource.SourceIdentitySHA256 ||
		got.Current.TargetSHA256 != "" || got.Current.SourceIdentitySHA256 != final.Target.LiveSource.SourceIdentitySHA256 || got.Current.Verification != "verified" {
		t.Fatalf("final evidence provenance is inconsistent: %#v", got)
	}
	if final.Provenance.LiveProduction == nil || final.Provenance.Production != nil {
		t.Fatal("final artifact omits production provenance")
	}
	production := final.Provenance.LiveProduction
	if production.BuildProduct != "mulgae" || production.BuildVersion != "0.1.0" ||
		production.BuildCommit != "0123456789abcdef" || !production.ObjectivePresent ||
		production.ObjectiveSHA256 == nil || production.SourceIdentitySHA256 != candidate.target.sha256 ||
		production.SourceTerminalReceipt != "source-terminal:v1:"+sha256Identifier([]byte("workspace-terminal")) || len(production.Providers) != 2 {
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

func TestFinalArtifactV4SerializesVerifiedVisualEvidence(t *testing.T) {
	t.Parallel()
	candidate := retainedLiveCandidate(t, true)
	candidate.findings[0].evidence[0].visual = &preparedVisualEvidence{
		path: "design-specs/home.png", sha256: "sha256:" + strings.Repeat("d", 64),
		x: 24, y: 120, width: 320, height: 48,
	}
	// Trusted serializer input, without claiming admission of an unbound image.
	// The original tuple literals remain; live binary admission is tested through
	// the source/verifier integrations and unchanged live golden builders.
	paths, err := publicationPaths(candidate.SessionID(), candidate.RunID(), publicationTestReviewID(t), 42)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := candidate.buildLineageEdge(paths, publicationTestReviewID(t))
	if err != nil {
		t.Fatal(err)
	}
	created, err := canonicalTime(publicationTestTime())
	if err != nil {
		t.Fatal(err)
	}
	finalBytes, err := candidate.buildFinalBytes(publicationTestReviewID(t), created, edge)
	if err != nil {
		t.Fatal(err)
	}
	var final finalReviewWire
	if err := unmarshalExact(finalBytes, &final); err != nil {
		t.Fatal(err)
	}
	if final.SchemaVersion != "mulgae-review-artifact.v4" {
		t.Fatalf("schema version = %q", final.SchemaVersion)
	}
	visual := final.Findings[0].Evidence[0].Visual
	if visual == nil || visual.Path != "design-specs/home.png" || visual.SHA256 != "sha256:"+strings.Repeat("d", 64) ||
		visual.BBox != (visualBoundingBoxWire{X: 24, Y: 120, Width: 320, Height: 48}) || visual.Verification != "verified" {
		t.Fatalf("serialized visual evidence = %#v", visual)
	}
}

func TestPreparedCandidateBuildRejectsSchemaFailure(t *testing.T) {
	t.Parallel()
	validator := &publicationTestValidator{reject: true}
	_, err := retainedLiveCandidate(t, false).Build(context.Background(), validator, publicationTestReviewID(t), publicationTestTime(), 1)
	if err == nil {
		t.Fatal("Build accepted validator rejection")
	}
	if got, want := assetIDStrings(validator.ids), []string{strings.Replace(finalReviewSchemaAsset, ".v1.", ".v4.", 1)}; !reflect.DeepEqual(got, want) {
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
