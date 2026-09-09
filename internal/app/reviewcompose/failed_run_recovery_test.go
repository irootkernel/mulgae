package reviewcompose

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestComposeFailedRootBindsManifestAndPreservesAcceptedRoles(t *testing.T) {
	root, security, docs := compositionFixtures(t)
	root.ReviewID = domain.ReviewID{}
	root.RecoveryManifestSHA256 = testDigest
	for _, child := range []*Source{&security, &docs} {
		child.SourceReviewID = domain.ReviewID{}
		child.SourceRecoveryManifestSHA256 = root.RecoveryManifestSHA256
	}
	reader := sourceReader{root.RunID: root, security.RunID: security, docs.RunID: docs}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{docs.RunID, security.RunID}}
	first, err := service.Compose(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Compose(context.Background(), request)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("same mapping changed: %v", err)
	}
	if first.RootReviewID.String() != "" || first.RootRecoveryManifestSHA256 != testDigest || first.Roles[0].SourceRunID != root.RunID || first.Roles[0].SourceRecoveryManifestSHA256 != testDigest {
		t.Fatal("accepted root authority was replaced")
	}
	if _, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}}); err == nil {
		t.Fatal("missing selected role was accepted")
	}
	root.RecoveryManifestSHA256 = "sha256:" + strings.Repeat("b", 64)
	reader[root.RunID] = root
	if _, err := service.Compose(context.Background(), request); err == nil {
		t.Fatal("mismatched recovery manifest was accepted")
	}
	security.SourceRecoveryManifestSHA256 = root.RecoveryManifestSHA256
	docs.SourceRecoveryManifestSHA256 = root.RecoveryManifestSHA256
	reader[security.RunID] = security
	reader[docs.RunID] = docs
	changed, err := service.Compose(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == changed.Fingerprint {
		t.Fatal("manifest identity did not affect composition identity")
	}
}

func TestComposeFollowsRepeatedFailedRecoveryRerun(t *testing.T) {
	root, security, _ := compositionFixtures(t)
	root.Roles = root.Roles[:2]
	root.Attempts = root.Attempts[:2]
	root.ReviewID = domain.ReviewID{}
	root.RecoveryManifestSHA256 = testDigest
	intermediate := security
	intermediate.RunID = runID(t, "04")
	intermediate.ReviewID = domain.ReviewID{}
	intermediate.RecoveryManifestSHA256 = "sha256:" + strings.Repeat("b", 64)
	intermediate.SourceReviewID = domain.ReviewID{}
	intermediate.SourceRecoveryManifestSHA256 = root.RecoveryManifestSHA256
	intermediate.Coverage = domain.CoverageIncomplete
	intermediate.Roles = append([]Role(nil), security.Roles...)
	intermediate.Roles[0].Outcome = "failed"
	intermediate.Roles[0].FindingIDs = nil
	intermediate.RoleReports = nil
	intermediate.Findings = nil
	intermediate.Attempts = append([]Attempt(nil), security.Attempts...)
	intermediate.Attempts[0].State = domain.AttemptFailed
	security.SourceRunID = intermediate.RunID
	security.SourceReviewID = domain.ReviewID{}
	security.SourceRecoveryManifestSHA256 = intermediate.RecoveryManifestSHA256
	security.SourceAttemptID = intermediate.Roles[0].AttemptID
	reader := sourceReader{root.RunID: root, intermediate.RunID: intermediate, security.RunID: security}
	service, _ := NewService(reader)
	if _, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}}); err != nil {
		t.Fatal(err)
	}
	intermediate.RecoveryManifestSHA256 = "sha256:" + strings.Repeat("c", 64)
	reader[intermediate.RunID] = intermediate
	_, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}})
	wantReason(t, err, domain.CompositeLineageMismatch)
	intermediate.RecoveryManifestSHA256 = security.SourceRecoveryManifestSHA256
	reader[intermediate.RunID] = intermediate
	if _, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{intermediate.RunID}}); err == nil {
		t.Fatal("failed intermediate was treated as recovered")
	}
}

func TestComposeBoundsRecoveryLineageAt128Links(t *testing.T) {
	for _, links := range []int{128, 129} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			root, security, _ := compositionFixtures(t)
			root.Roles, root.Attempts = root.Roles[:2], root.Attempts[:2]
			root.ReviewID = domain.ReviewID{}
			root.RecoveryManifestSHA256 = testDigest
			reader := &countingLineageReader{sources: sourceReader{root.RunID: root}}
			parent := root
			for index := 1; index <= links; index++ {
				child := security
				id, err := domain.ParseRunID(fmt.Sprintf("r_019f596a-cfe4-7c9c-b82e-%012x", index))
				if err != nil {
					t.Fatal(err)
				}
				child.RunID = id
				child.SourceRunID, child.SourceReviewID, child.SourceRecoveryManifestSHA256 = parent.RunID, parent.ReviewID, parent.RecoveryManifestSHA256
				child.SourceAttemptID = failedAttemptFor(parent, domain.RoleSecurity)
				if index < links {
					child.ReviewID = domain.ReviewID{}
					child.RecoveryManifestSHA256 = fmt.Sprintf("sha256:%064x", index)
					child.Coverage = domain.CoverageIncomplete
					child.Roles = append([]Role(nil), security.Roles...)
					child.Roles[0].Outcome, child.Roles[0].FindingIDs = "failed", nil
					child.RoleReports, child.Findings = nil, nil
					child.Attempts = append([]Attempt(nil), security.Attempts...)
					child.Attempts[0].State = domain.AttemptFailed
				}
				reader.sources[child.RunID] = child
				parent = child
			}
			service, err := NewService(reader)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{parent.RunID}})
			if links == 128 {
				if err != nil {
					t.Fatalf("128-link lineage rejected: %v", err)
				}
			} else {
				wantReason(t, err, domain.CompositeLineageMismatch)
			}
			if reader.reads > 130 {
				t.Fatalf("lineage traversal exceeded bounded reads: %d", reader.reads)
			}
		})
	}
}

type countingLineageReader struct {
	sources sourceReader
	reads   int
}

func (reader *countingLineageReader) ReadCompositionSource(ctx context.Context, id domain.RunID) (Source, error) {
	reader.reads++
	return reader.sources.ReadCompositionSource(ctx, id)
}
