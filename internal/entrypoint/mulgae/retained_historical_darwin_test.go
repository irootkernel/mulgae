//go:build darwin && arm64

package mulgae

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func retainedWriteMember(t *testing.T, root, path string, raw []byte) {
	t.Helper()
	destination := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationFrozenPublicationP0P1RecoveryKeepsExactBytes(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := historicalValidator(t)
	seen := 0
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" && c.ID != "composite-legacy-v1" && c.ID != "composite-copied-v1" && c.ID != "composite-copied-v2" {
			continue
		}
		for _, state := range []domain.PersistedJournalState{domain.JournalFinalStaged, domain.JournalFinalFileInstalled} {
			t.Run(c.ID+"/"+string(state), func(t *testing.T) {
				f := newHistoricalConsumer(t, c, validator)
				files := c.Artifacts()
				prefix := c.SessionID + "/" + c.RunID + "/"
				var journal artifactwire.PublicationJournal
				if err := json.Unmarshal(files[prefix+artifactwire.JournalPath], &journal); err != nil {
					t.Fatal(err)
				}
				finalPath := journal.ExpectedFinal.Path
				// Real persisted transaction input, assembled from frozen members.
				// No composite-review producer or success stub participates.
				for name, source := range map[string]string{"manifest": journal.ManifestPath, "lineage-edge": journal.LineageEdgePath, "epoch": journal.EpochPath} {
					retainedWriteMember(t, f.root.String(), artifactwire.PreparedCompositePath(c.SessionID, c.RunID, name), files[source])
				}
				retainedWriteMember(t, f.root.String(), prefix+artifactwire.ValidatedCandidatePath, files[finalPath])
				if state == domain.JournalFinalStaged {
					retainedWriteMember(t, f.root.String(), journal.ExpectedStaged.Path, files[finalPath])
					if err := os.Remove(filepath.Join(f.root.String(), finalPath)); err != nil {
						t.Fatal(err)
					}
				}
				for _, path := range []string{journal.ManifestPath, journal.LineageEdgePath, journal.EpochPath, prefix + artifactwire.StatusPath} {
					if err := os.Remove(filepath.Join(f.root.String(), path)); err != nil {
						t.Fatal(err)
					}
				}
				journal.PersistedJournalState = string(state)
				raw, err := json.Marshal(journal)
				if err != nil {
					t.Fatal(err)
				}
				retainedWriteMember(t, f.root.String(), prefix+artifactwire.JournalPath, append(raw, '\n'))
				if _, err := f.queries.ReadCommitted(context.Background(), f.run); err == nil {
					t.Fatal("interrupted P0/P1 exposed readable final")
				}
				result, err := f.publisher.Recover(context.Background(), f.run)
				if err != nil || result.Decision().Authority() != domain.PublicationAuthorityP2 {
					t.Fatalf("frozen recovery: %v", err)
				}
				after, err := f.queries.ReadCommitted(context.Background(), f.run)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(after.FinalBytes(), files[finalPath]) || !bytes.Equal(after.ManifestBytes(), files[prefix+artifactwire.ManifestPath]) {
					t.Fatal("recovery changed immutable historical members")
				}
				for _, expected := range c.Attempts {
					if expected.Reason != "" {
						continue
					}
					id, err := domain.ParseAttemptID(expected.AttemptID)
					if err != nil {
						t.Fatal(err)
					}
					manifest, ok := result.PromptManifestArtifact(id, 1)
					if !ok || manifest.Path().String() != expected.PromptManifestPath || manifest.SHA256() != expected.PromptManifestSHA256 {
						t.Fatal("recovered P2 lost verified prompt identity")
					}
				}
				for _, path := range []string{journal.LineageEdgePath, journal.EpochPath, prefix + artifactwire.StatusPath, prefix + artifactwire.JournalPath} {
					got, err := os.ReadFile(filepath.Join(f.root.String(), path))
					if err != nil || !bytes.Equal(got, files[path]) {
						t.Fatalf("recovery changed fixed member %s: %v", path, err)
					}
				}
			})
		}
		seen++
	}
	if seen != 4 {
		t.Fatalf("frozen recovery families=%d, want 4", seen)
	}
}

func TestIntegrationInterruptedCopiedSupportNeverExposesFinal(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := historicalValidator(t)
	for _, c := range corpus.Cases {
		if c.ID != "composite-copied-v1" {
			continue
		}
		files := c.Artifacts()
		prefix := c.SessionID + "/" + c.RunID + "/"
		// The six original cases are interruptions before the first journal/P2
		// transaction. Prefix copies remain P0 irrespective of their content.
		// publishCandidate pins the support index before candidate persistence.
		// after-1 interrupts that first auxiliary write, before the candidate;
		// after-0 interrupts candidate persistence; after-2..5 add each member.
		order := []string{"target/target.bytes", "target/target-manifest.json", "role-reports/logic.md", "support/composite.json"}
		for after := 0; after < 6; after++ {
			t.Run(fmt.Sprintf("after-%d", after), func(t *testing.T) {
				rootPath, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				root, err := ports.NewAnchoredRoot(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				session, err := domain.ParseSessionID(c.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				id, err := domain.ParseRunID(c.RunID)
				if err != nil {
					t.Fatal(err)
				}
				run, err := ports.NewPublicationRun(root, session, id)
				if err != nil {
					t.Fatal(err)
				}
				retainedWriteMember(t, rootPath, prefix+artifactwire.SupportIndexPath, files[prefix+artifactwire.SupportIndexPath])
				if after != 1 {
					retainedWriteMember(t, rootPath, prefix+artifactwire.ValidatedCandidatePath, files[prefix+"review_"+c.ReviewID+".json"])
				}
				copied := 0
				if after > 1 {
					copied = after - 1
				}
				for _, relative := range order[:copied] {
					raw, ok := files[prefix+relative]
					if !ok {
						t.Fatalf("fixed partial-copy member absent: %s", relative)
					}
					retainedWriteMember(t, rootPath, prefix+relative, raw)
				}
				store, err := filesystem.NewPublicationStore(validator, historicalClock{time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}, historicalIDs{}, filesystem.NewSecureWriter())
				if err != nil {
					t.Fatal(err)
				}
				queries, err := query.NewService(store, validator, nil, 8<<20)
				if err != nil {
					t.Fatal(err)
				}
				_, err = queries.ReadCommitted(context.Background(), run)
				historicalArtifactFailure(t, err, "committed review is unavailable without P2 authority")
				if _, err := os.Stat(filepath.Join(rootPath, prefix+"review_"+c.ReviewID+".json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("partial copies installed a final")
				}
			})
		}
		return
	}
	t.Fatal("fixed copied-support input absent")
}

type retainedLiveLockIDs struct{}

func (retainedLiveLockIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ParseReviewID("019f596a-d176-7321-b920-c2d312c82cc2")
}

func TestIntegrationLivePublicationLockBelongsToArtifactRoot(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(project, "artifacts")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publication.PrepareLiveNoChangeCandidate(session, run, target, []domain.Role{domain.RoleLogic}, domain.SeverityHigh, publication.LiveProductionProvenance{BuildProduct: "mulgae", BuildVersion: "test", BuildCommit: "test", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:sha256:" + historicalRawHash([]byte("closed"))})
	if err != nil {
		t.Fatal(err)
	}
	validator := historicalValidator(t)
	clock := historicalClock{time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}
	store, err := filesystem.NewPublicationStore(validator, clock, retainedLiveLockIDs{}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	service, err := publication.NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishLiveNext(context.Background(), root, candidate)
	if err != nil || result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("live lock exercise did not publish: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, "store/locks/store.lock")); err != nil {
		t.Fatalf("artifact-root lock: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(project, "store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("project-root store created: %v", err)
	}
}

func TestIntegrationFrozenMixedEvidenceReadContentKeepsUnavailableDistinct(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := historicalValidator(t)
	for _, c := range corpus.Cases {
		if c.ID != "composite-mixed-v1" {
			continue
		}
		for _, mutation := range []string{"unchanged", "missing", "corrupt"} {
			t.Run(mutation, func(t *testing.T) {
				f := newHistoricalConsumer(t, c, validator)
				ctx := context.Background()
				committed, err := f.queries.ReadCommitted(ctx, f.run)
				if err != nil {
					t.Fatal(err)
				}
				claims := committed.Findings()[0].Evidence()
				if len(claims) != 2 || claims[0].CopiedAvailability() != "verified" || claims[0].Verification() != evidence.ReceiptVerified || claims[1].CopiedAvailability() != "evidence_unavailable" || claims[1].Verification() != evidence.ReceiptUnverifiable {
					t.Fatal("copied availability or verification changed")
				}
				binding, err := domain.ParseProjectBinding("sha256:" + historicalRawHash([]byte("report fixture binding")))
				if err != nil {
					t.Fatal(err)
				}
				if mutation != "unchanged" {
					path := filepath.Join(f.root.String(), c.SessionID, c.RunID, compositesupport.ExcerptPath("F001", 0))
					if mutation == "missing" {
						err = os.Remove(path)
					} else {
						err = os.WriteFile(path, []byte("corrupt copied quote\n"), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.reports.Render(ctx, f.run); err == nil {
						t.Fatal("broken bound quote became historical absence")
					}
					if _, err := appreport.ReadContent(ctx, f.queries, f.run, binding, "", query.ContentContinuation{}); err == nil {
						t.Fatal("read-report accepted broken bound quote")
					}
					return
				}
				chunk, err := appreport.ReadContent(ctx, f.queries, f.run, binding, "", query.ContentContinuation{})
				if err != nil {
					t.Fatal(err)
				}
				if chunk.Encoding != "utf8" || chunk.NextOffset != nil || !bytes.Contains([]byte(chunk.Content), []byte("available copied quote")) || !bytes.Contains([]byte(chunk.Content), []byte("evidence_unavailable")) || bytes.Contains([]byte(chunk.Content), []byte("historical absent quote")) {
					t.Fatal("read-report changed mixed evidence representation or continuation")
				}
				_, err = f.queries.ReadEvidence(ctx, f.run, binding, "F001", committed.TargetSHA256(), 1, query.ContentContinuation{})
				historicalArtifactFailure(t, err, "evidence_unavailable")
			})
		}
		return
	}
	t.Fatal("fixed mixed evidence input absent")
}
