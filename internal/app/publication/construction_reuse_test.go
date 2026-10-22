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

// publicationErrorChainText concatenates every error message in the chain,
// including errors.Join branches, so assertions can pin the selected
// concrete cause beneath the redacted diagnostic classification.
func publicationErrorChainText(err error) string {
	var builder strings.Builder
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		builder.WriteString(current.Error())
		builder.WriteString("\n")
		if nested, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range nested.Unwrap() {
				visit(child)
			}
			return
		}
		visit(errors.Unwrap(current))
	}
	visit(err)
	return builder.String()
}

// publicationIssuedReviewID returns a fixed issued review ID that differs
// from the fixed preflight dummy ID used by publishCandidate.
func publicationIssuedReviewID(t *testing.T) domain.ReviewID {
	t.Helper()
	id, err := domain.ParseReviewID("019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

const publicationPreflightDummyID = "019f596a-d174-7321-b920-c2d312c82cc2"

func publicationCapturedNoChangeCandidate(t *testing.T) PreparedCandidate {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetGit, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		RepositoryID: "repository:test", BaseObjectID: strings.Repeat("a", 40),
		HeadObjectID: strings.Repeat("b", 40), HeadTreeObjectID: strings.Repeat("c", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := PrepareNoChangeCandidate(sessionID, runID, target,
		[]domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, NoChangeProvenance{
			BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "0123456789abcdef",
			SnapshotManifestSHA256:   "sha256:" + strings.Repeat("a", 64),
			WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64),
		})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

// publicationCapturedArchiveMaterial builds one valid captured review
// material whose split archive manifest differs from every other fixture
// built with a different visual path.
func publicationCapturedArchiveMaterial(t *testing.T, visualPath string) []byte {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("reviewed line\n"))
	if err != nil {
		t.Fatal(err)
	}
	visualBytes := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}
	path, err := ports.NewSafeRelativePath(visualPath)
	if err != nil {
		t.Fatal(err)
	}
	visual, err := ports.NewWorkspaceVisualAsset(path, visualBytes, sha256Identifier(visualBytes), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	files := []ports.WorkspaceSnapshotFile{visual}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, "publication-reuse-precedence")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: files,
	})
	if err != nil {
		t.Fatal(err)
	}
	artistContext, err := json.Marshal(capturedArtistInputWire{
		SchemaVersion: "mulgae-artist-inputs.v1", Status: "missing", TaskPath: "docs/missing.md",
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
	return archive
}

// publicationRetainedCaptureMismatchCandidate binds one valid archive into
// every runtime inventory and a different valid archive as retained capture
// material, so Build reaches the retained-capture comparison.
func publicationRetainedCaptureMismatchCandidate(t *testing.T) PreparedCandidate {
	t.Helper()
	candidate := publicationRuntimeCandidate(t)
	runtimeArchive := publicationCapturedArchiveMaterial(t, "design-specs/current.png")
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				candidate.roles[roleIndex].attempts[attemptIndex].invocations[invocationIndex].runtime.capturedArchive = append([]byte(nil), runtimeArchive...)
			}
		}
	}
	retainedArchive := publicationCapturedArchiveMaterial(t, "design-specs/other.png")
	bound, err := candidate.WithCapturedMaterial(retainedArchive)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.Valid() {
		t.Fatal("retained-capture mismatch fixture is invalid")
	}
	return bound
}

// TestBuildCapturedPrecedenceOnForceablePairs pins the historical builder's
// error selection for the two captured-branch defects that remain forceable
// past candidate validation. The combined defect selects the runtime
// divergence error because runtime artifacts are built before capture
// support.
func TestBuildCapturedPrecedenceOnForceablePairs(t *testing.T) {
	t.Parallel()

	requireCause := func(t *testing.T, err error, phase domain.RuntimeDiagnosticPhase, want string, forbidden string) {
		t.Helper()
		if err == nil {
			t.Fatalf("Build accepted a defective candidate, want %q", want)
		}
		chain := publicationErrorChainText(err)
		if !strings.Contains(chain, want) {
			t.Fatalf("Build error chain = %q, want %q", chain, want)
		}
		if forbidden != "" && strings.Contains(chain, forbidden) {
			t.Fatalf("Build error chain = %q, must not select %q", chain, forbidden)
		}
		diagnostic, ok := FailureDiagnosticFromError(err)
		if phase == "" {
			if ok {
				t.Fatalf("unwrapped capture error carried diagnostic %#v", diagnostic)
			}
			return
		}
		if !ok || diagnostic.Phase() != phase || diagnostic.Cause() != domain.DiagnosticCausePublicationSerializationFailed {
			t.Fatalf("diagnostic = %#v (%t), want phase %q serialization failure", diagnostic, ok, phase)
		}
	}

	t.Run("divergent runtime targets", func(t *testing.T) {
		t.Parallel()
		candidate := publicationRuntimeCandidate(t)
		candidate.roles[1].attempts[0].invocations[0].runtime.target = []byte("divergent target\n")
		if !candidate.Valid() {
			t.Fatal("divergent target fixture is invalid")
		}
		_, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationIssuedReviewID(t), publicationTestTime(), 1)
		requireCause(t, err, domain.DiagnosticPhasePublicationPersistence, "runtime target bytes diverge", "")
	})

	t.Run("retained capture mismatch", func(t *testing.T) {
		t.Parallel()
		candidate := publicationRetainedCaptureMismatchCandidate(t)
		_, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationIssuedReviewID(t), publicationTestTime(), 1)
		requireCause(t, err, "", "retained capture differs from runtime capture", "")
	})

	t.Run("combined selects runtime divergence", func(t *testing.T) {
		t.Parallel()
		candidate := publicationRetainedCaptureMismatchCandidate(t)
		candidate.roles[1].attempts[0].invocations[0].runtime.target = []byte("divergent target\n")
		if !candidate.Valid() {
			t.Fatal("combined fixture is invalid")
		}
		_, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationIssuedReviewID(t), publicationTestTime(), 1)
		requireCause(t, err, domain.DiagnosticPhasePublicationPersistence, "runtime target bytes diverge", "retained capture differs from runtime capture")
	})
}

// TestRoleReportSkipRulesListSupportWithoutManifestEntry pins the support
// listing and manifest skip rules for a role that carries a non-empty report
// and zero attempts: the report artifact and support index retain it while
// the manifest omits it. The white-box role is injectable only here because
// validateNoChange does not constrain report markdown.
func TestRoleReportSkipRulesListSupportWithoutManifestEntry(t *testing.T) {
	t.Parallel()

	candidate := publicationCapturedNoChangeCandidate(t)
	candidate.roles[0].reportMarkdown = []byte("# Logic report\n\nRetained without attempts.\n")
	if !candidate.Valid() {
		t.Fatal("zero-attempts report fixture is invalid")
	}
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationIssuedReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	reportPath := prefix + "role-reports/" + string(candidate.roles[0].role) + ".md"
	var listed bool
	for _, artifact := range bundle.SupportArtifacts() {
		if artifact.Path().String() == reportPath {
			listed = bytes.Equal(artifact.Bytes(), candidate.roles[0].reportMarkdown)
		}
	}
	if !listed {
		t.Fatalf("support listing omitted the zero-attempts role report %q", reportPath)
	}
	var index runSupportIndexWire
	for _, artifact := range bundle.SupportArtifacts() {
		if artifact.Path().String() == prefix+"support/index.json" {
			if err := json.Unmarshal(artifact.Bytes(), &index); err != nil {
				t.Fatal(err)
			}
		}
	}
	var indexed bool
	for _, identity := range index.Artifacts {
		if identity.Path == reportPath {
			indexed = true
		}
	}
	if !indexed {
		t.Fatal("support index omitted the zero-attempts role report")
	}
	var manifest runManifestWire
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, report := range manifest.RoleReports {
		if report.Role == string(candidate.roles[0].role) {
			t.Fatal("manifest listed the zero-attempts role report")
		}
	}
}

// TestLiveBoundMembersCarryIssuedIDNotDummy verifies that every
// review-ID-dependent member binds the issued review ID and no member still
// carries the preflight dummy ID.
func TestLiveBoundMembersCarryIssuedIDNotDummy(t *testing.T) {
	t.Parallel()

	dummy := []byte(publicationPreflightDummyID)
	issued := publicationIssuedReviewID(t)
	memberBytes := func(bundle PublicationBundle) [][]byte {
		members := [][]byte{
			bundle.Final().Bytes(), bundle.Manifest().Bytes(), bundle.LineageEdge().Bytes(),
			bundle.Epoch().Record().Bytes(), bundle.Journal().Bytes(), bundle.Status().Bytes(),
		}
		for _, artifact := range bundle.SupportArtifacts() {
			members = append(members, artifact.Bytes())
		}
		return members
	}

	t.Run("live no change", func(t *testing.T) {
		t.Parallel()
		builder, err := newLivePublicationBuilder(livePublicationNoChange(t))
		if err != nil {
			t.Fatal(err)
		}
		preflightID, err := domain.ParseReviewID(publicationPreflightDummyID)
		if err != nil {
			t.Fatal(err)
		}
		preflight, err := builder.bind(context.Background(), &publicationTestValidator{}, preflightID, publicationTestTime(), 1)
		if err != nil {
			t.Fatalf("preflight binding error = %v", err)
		}
		if !bytes.Contains(preflight.Final().Bytes(), dummy) {
			t.Fatal("preflight fixture does not actually carry the dummy review ID")
		}
		bundle, err := builder.bind(context.Background(), &publicationTestValidator{}, issued, publicationTestTime(), 1)
		if err != nil {
			t.Fatalf("issued binding error = %v", err)
		}
		if bundle.Final().Identity().ReviewID() != issued {
			t.Fatal("final identity does not bind the issued review ID")
		}
		if got := bundle.Final().Identity().Path().String(); !strings.HasSuffix(got, "/review_"+issued.String()+".json") {
			t.Fatalf("final path = %q, want issued review ID suffix", got)
		}
		if got := bundle.LineageEdge().Path().String(); got != "store/lineage-edges/e_"+issued.String()+".json" {
			t.Fatalf("lineage edge path = %q, want issued edge identity", got)
		}
		for index, data := range memberBytes(bundle) {
			if bytes.Contains(data, dummy) {
				t.Fatalf("member %d carries the preflight dummy review ID", index)
			}
		}
	})

	t.Run("captured findings bind normalized evidence", func(t *testing.T) {
		t.Parallel()
		candidate := publicationTestCandidate(t, true)
		bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, issued, publicationTestTime(), 1)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
		normalizedPath := prefix + "excerpts/F001.json"
		var normalized []byte
		for _, artifact := range bundle.SupportArtifacts() {
			if artifact.Path().String() == normalizedPath {
				normalized = artifact.Bytes()
			}
		}
		if normalized == nil {
			t.Fatalf("normalized finding excerpt %q absent", normalizedPath)
		}
		var finding finalFindingWire
		if err := json.Unmarshal(normalized, &finding); err != nil {
			t.Fatal(err)
		}
		if len(finding.Evidence) == 0 || finding.Evidence[0].Source.ReviewID != issued.String() {
			t.Fatalf("normalized evidence source review ID = %q, want issued %q", finding.Evidence[0].Source.ReviewID, issued.String())
		}
		other, err := domain.ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
		if err != nil {
			t.Fatal(err)
		}
		otherBundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, other, publicationTestTime(), 1)
		if err != nil {
			t.Fatalf("Build(other) error = %v", err)
		}
		if bytes.Equal(bundle.SupportArtifacts()[len(bundle.SupportArtifacts())-1].Bytes(), otherBundle.SupportArtifacts()[len(otherBundle.SupportArtifacts())-1].Bytes()) {
			t.Fatal("support index digests did not bind the issued review ID")
		}
	})
}

// TestManifestRoleReportsFromIdentitiesMatchHistoricalWires proves the
// bind-side wire derivation, which reuses the constructed report identities,
// equals manifestRoleReports() for the same candidate: identical wires for
// published reports and the same omission of a zero-attempts report.
func TestManifestRoleReportsFromIdentitiesMatchHistoricalWires(t *testing.T) {
	t.Parallel()

	zeroAttempts := publicationCapturedNoChangeCandidate(t)
	zeroAttempts.roles[0].reportMarkdown = []byte("# Logic report\n\nRetained without attempts.\n")
	for _, test := range []struct {
		name      string
		candidate PreparedCandidate
		wantCount int
	}{
		{"published reports", publicationTestCandidate(t, true), 2},
		{"zero attempts report omitted", zeroAttempts, 0},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reports, err := test.candidate.buildRoleReports()
			if err != nil {
				t.Fatal(err)
			}
			identities := test.candidate.roleReportIdentities(reports)
			if len(identities) != len(reports) {
				t.Fatalf("identities = %d, want one per constructed report (%d)", len(identities), len(reports))
			}
			want := test.candidate.manifestRoleReports()
			got := test.candidate.manifestRoleReportsFromIdentities(identities)
			if len(want) != test.wantCount || !reflect.DeepEqual(got, want) {
				t.Fatalf("derived wires = %+v, want %+v", got, want)
			}
		})
	}
}
