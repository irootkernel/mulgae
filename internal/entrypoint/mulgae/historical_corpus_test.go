//go:build darwin && arm64

package mulgae

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

type historicalClock struct{ now time.Time }

func (c historicalClock) Now() time.Time { return c.now }

type historicalIDs struct{}

func (historicalIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ReviewID{}, fmt.Errorf("historical corpus cannot create a review")
}
func (historicalIDs) NewRequestID(time.Time) (string, error) {
	return "i_019f5a09-5eec-7001-8001-000000000001", nil
}
func historicalRawHash(raw []byte) string { sum := sha256.Sum256(raw); return fmt.Sprintf("%x", sum) }

type historicalConsumer struct {
	project, root ports.AnchoredRoot
	run           ports.PublicationRun
	queries       *query.Service
	reports       *report.Service
	exports       RedactedExportService
	publisher     *publication.Service
	cleanup       *filesystem.CleanupStore
	validator     *jsonschema.Validator
	clock         historicalClock
}

func historicalValidator(t *testing.T) *jsonschema.Validator {
	t.Helper()
	// The adapter retains compiled schemas only; validation state is call-local.
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func newHistoricalConsumer(t *testing.T, c historical.Case, validator *jsonschema.Validator) *historicalConsumer {
	t.Helper()
	projectPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(projectPath, "artifacts")
	if err := os.Mkdir(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.Materialize(rootPath); err != nil {
		t.Fatal(err)
	}
	project, err := ports.NewAnchoredRoot(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := historicalClock{now: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}
	ids := historicalIDs{}
	writer := filesystem.NewSecureWriter()
	store, err := filesystem.NewPublicationStore(validator, clock, ids, writer)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := query.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := report.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := filesystem.NewExportInstaller(writer)
	if err != nil {
		t.Fatal(err)
	}
	exports, err := NewRedactedExportService(queries, installer, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := publication.NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := filesystem.NewCleanupStore(root, store, clock)
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
	return &historicalConsumer{project, root, run, queries, reports, exports, publisher, cleanup, validator, clock}
}
func historicalArtifactFailure(t *testing.T, err error, reason string) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != reason {
		t.Fatalf("failure=%v; want artifact reason %q", err, reason)
	}
}
func historicalExport(t *testing.T, f *historicalConsumer, c historical.Case) ([]byte, error) {
	t.Helper()
	result, err := f.exports.ExportRedactedRun(context.Background(), RedactedExportRequest{ProjectRoot: f.project, ArtifactRoot: f.root, RunID: c.RunID, OutputPath: "export.zip", Redacted: true})
	if err != nil {
		return nil, err
	}
	if !result.Redacted {
		t.Fatal("export lost redaction")
	}
	raw, err := os.ReadFile(filepath.Join(f.project.String(), result.BundleURI))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"evidence.json": true, "findings.json": true, "redaction.json": true, "review.json": true, "run.json": true, "schemas.json": true}
	if len(zr.File) != len(allowed) {
		t.Fatalf("unexpected export inventory: %d", len(zr.File))
	}
	for _, file := range zr.File {
		if !allowed[file.Name] {
			t.Fatalf("private composite copy exported: %s", file.Name)
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if c.Family == "composite" && file.Name == "evidence.json" {
			var evidence []json.RawMessage
			if err := json.Unmarshal(content, &evidence); err != nil || len(evidence) != 0 {
				t.Fatalf("private evidence exported: %s", content)
			}
		}
	}
	return raw, nil
}
func TestIntegrationHistoricalCorpusConsumers(t *testing.T) {
	validator := historicalValidator(t)
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			f := newHistoricalConsumer(t, c, validator)
			ctx := context.Background()
			_, err := f.queries.ReadCommitted(ctx, f.run)
			reason := c.Expected.ReadReason
			if c.Expected.NativeReadReason != "" {
				reason = c.Expected.NativeReadReason
			}
			if c.Family == "failed-recovery" {
				reason = "committed review is unavailable without P2 authority"
			}
			if reason != "" {
				if c.Family == "failed-recovery" && c.Expected.RecoveryReason == "" {
					view, err := NewPublicationQueryService(f.queries).ReadRunStatus(ctx, f.run)
					if err != nil {
						t.Fatal(err)
					}
					if view.HasAxes || view.HasFinalArtifact || view.FinalArtifactURI != "" || !view.FailedRunRecovery.Available {
						t.Fatal("CLI status granted final authority to recovery")
					}
				}
				historicalArtifactFailure(t, err, reason)
				if _, err := f.reports.Render(ctx, f.run); err == nil {
					t.Fatal("rejected source rendered a report")
				}
				if _, err := historicalExport(t, f, c); err == nil {
					t.Fatal("rejected source installed an export")
				}
				if _, err := os.Stat(filepath.Join(f.project.String(), "export.zip")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected source left export: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			view, err := NewPublicationQueryService(f.queries).ReadRunStatus(ctx, f.run)
			if err != nil {
				t.Fatal(err)
			}
			if !view.HasAxes || !view.HasFinalArtifact || view.RunID != c.RunID || view.SessionID != c.SessionID || string(view.PublicationState) != c.Expected.Publication || string(view.ContentVerdict) != c.Expected.Content || string(view.CoverageStatus) != c.Expected.Coverage || string(view.CIDecision) != c.Expected.CI || view.FinalArtifactURI != ".mulgae/"+c.SessionID+"/"+c.RunID+"/review_"+c.ReviewID+".json" {
				t.Fatal("CLI status projection changed")
			}
			rendered, err := NewPublicationReportService(f.reports).Render(ctx, f.run)
			if err != nil {
				t.Fatal(err)
			}
			if rendered.RunID != c.RunID || len(rendered.SourceIDs) != 5 || rendered.SourceIDs[0] != "report:review:"+c.ReviewID {
				t.Fatal("CLI report identity changed")
			}
			if c.Expected.Report == "" || "sha256:"+historicalRawHash(rendered.Markdown) != c.Expected.Report {
				t.Fatal("frozen report bytes changed")
			}
			exported, err := historicalExport(t, f, c)
			if err != nil {
				t.Fatal(err)
			}
			if c.Expected.ExportSHA256 == "" || "sha256:"+historicalRawHash(exported) != c.Expected.ExportSHA256 {
				t.Fatal("frozen export bytes changed")
			}
			if c.ID == "composite-mixed-v1" {
				if !bytes.Contains(rendered.Markdown, []byte("available copied quote")) || !bytes.Contains(rendered.Markdown, []byte("evidence_unavailable")) || bytes.Contains(rendered.Markdown, []byte("historical absent quote")) {
					t.Fatal("unavailable evidence lost its distinct result")
				}
			}
			if c.Expected.RuntimeReason != "" {
				reason := c.Expected.RuntimeReason
				if c.Expected.NativeRuntimeReason != "" {
					reason = c.Expected.NativeRuntimeReason
				}
				_, err := f.queries.ReadRuntimeTarget(ctx, f.run)
				historicalArtifactFailure(t, err, reason)
			}
			if c.Expected.ArchiveSHA256 != "" {
				target, err := f.queries.ReadRuntimeTarget(ctx, f.run)
				if err != nil {
					t.Fatal(err)
				}
				if "sha256:"+historicalRawHash(target.CapturedArchive()) != c.Expected.ArchiveSHA256 {
					t.Fatal("reconstructed archive bytes changed")
				}
			}
		})
	}
}
func TestIntegrationHistoricalCorpusRecovery(t *testing.T) {
	validator := historicalValidator(t)
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if len(c.Controls) > 0 || c.Expected.ReadReason != "" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			f := newHistoricalConsumer(t, c, validator)
			ctx := context.Background()
			if c.Family == "failed-recovery" {
				snapshot, err := f.queries.ReadFailedRunRecovery(ctx, f.run)
				if err != nil {
					t.Fatal(err)
				}
				if !snapshot.Status().Available {
					t.Fatal("failed source lost recovery inventory")
				}
				if _, err := f.queries.ReadCommitted(ctx, f.run); err == nil {
					t.Fatal("failed recovery gained P2")
				}
				return
			}
			committed, err := f.queries.ReadCommitted(ctx, f.run)
			if err != nil {
				t.Fatal(err)
			}
			beforeFinal, beforeManifest := committed.FinalBytes(), committed.ManifestBytes()
			// Losing the mutable status is an interruption; immutable P2 authority stays.
			if err := os.Remove(filepath.Join(f.root.String(), c.SessionID, c.RunID, "status.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := f.publisher.Recover(ctx, f.run); err != nil {
				t.Fatal(err)
			}
			after, err := f.queries.ReadCommitted(ctx, f.run)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeFinal, after.FinalBytes()) || !bytes.Equal(beforeManifest, after.ManifestBytes()) {
				t.Fatal("recovery rewrote immutable historical publication")
			}
		})
	}
}
func TestIntegrationHistoricalCorpusCleanup(t *testing.T) {
	validator := historicalValidator(t)
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			f := newHistoricalConsumer(t, c, validator)
			ctx := context.Background()
			snapshot, err := f.cleanup.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Policy = clean.Policy{RetentionAgeSeconds: 1}
			policyBytes, err := json.Marshal(snapshot.Policy)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.InputPolicySHA256 = "sha256:" + historicalRawHash(policyBytes)
			plan, err := clean.Plan(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, decision := range plan.RunDecisions {
				if decision.RunID != c.RunID {
					continue
				}
				for _, reason := range decision.Reasons {
					if string(reason) == c.Expected.Cleanup {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("retention outcome changed: %+v", plan.RunDecisions)
			}
			if c.Family == "failed-recovery" && c.Expected.RecoveryReason == "" {
				service, err := clean.NewService(f.clock, f.validator, f.cleanup)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.Run(ctx, clean.Request{All: true}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.queries.ReadFailedRunRecovery(ctx, f.run); err != nil {
					t.Fatal("cleanup removed failed recovery", err)
				}
			}
			if c.ID == "composite-copied-v1" || c.ID == "composite-copied-v2" {
				snapshot.Policy.ExplicitKeepRunIDs = []string{c.RunID}
				policyBytes, err := json.Marshal(snapshot.Policy)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.InputPolicySHA256 = "sha256:" + historicalRawHash(policyBytes)
				plan, err := clean.Plan(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				// Execute the real native plan. Every deleted source must be selected by it.
				err = f.cleanup.WithCleanupTransaction(ctx, func(tx clean.CleanupTransaction) error { return tx.PersistDryRunPlan(ctx, plan) })
				if err != nil {
					t.Fatal(err)
				}
				apply, err := clean.ApplyPlan(plan)
				if err != nil {
					t.Fatal(err)
				}
				if err := clean.ExecuteApply(ctx, f.cleanup, apply); err != nil {
					t.Fatal(err)
				}
				deleted := false
				for _, action := range plan.OrderedActions {
					if action.RunID != c.RunID {
						deleted = true
						if _, err := os.Stat(filepath.Join(f.root.String(), c.SessionID, action.RunID)); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("selected source remains: %v", err)
						}
					}
				}
				if !deleted {
					t.Fatal("source-cleanup scenario did not delete a source")
				}
				if _, err := f.queries.ReadCommitted(ctx, f.run); err != nil {
					t.Fatal(err)
				}
				rendered, err := f.reports.Render(ctx, f.run)
				if err != nil {
					t.Fatal(err)
				}
				if "sha256:"+historicalRawHash(rendered.Bytes()) != c.Expected.Report {
					t.Fatal("source cleanup changed report bytes")
				}
				exported, err := historicalExport(t, f, c)
				if err != nil {
					t.Fatal(err)
				}
				if "sha256:"+historicalRawHash(exported) != c.Expected.ExportSHA256 {
					t.Fatal("source cleanup changed export bytes")
				}
			}
		})
	}
}
