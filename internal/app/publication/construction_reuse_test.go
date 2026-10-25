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
		candidate := retainedLiveCandidate(t, true)
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

	zeroAttempts := retainedLiveCandidate(t, false)
	for i := range zeroAttempts.roles {
		zeroAttempts.roles[i].attempts = nil
	}
	// Direct report serializer input; no invalid live candidate is admitted.
	zeroAttempts.roles[0].reportMarkdown = []byte("# Logic report\n\nRetained without attempts.\n")
	for _, test := range []struct {
		name      string
		candidate PreparedCandidate
		wantCount int
	}{
		{"published reports", retainedLiveCandidate(t, true), 2},
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
