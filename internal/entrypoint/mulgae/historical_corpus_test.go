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
	"reflect"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/app/publication"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/report"
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

const historicalRequirementsDisclosure = "# Requirements assessment\n\n" +
	"- **Availability:** `unavailable`\n" +
	"- **Selected requirements:** `unavailable`\n" +
	"- **Admitted provider assessments:** `unavailable`\n\n"

func historicalReportBeforeRequirementsDisclosure(raw []byte) ([]byte, bool) {
	const coverage = "# Role coverage\n\n"
	boundary := []byte(historicalRequirementsDisclosure + coverage)
	if bytes.Count(raw, []byte("# Requirements assessment\n\n")) != 1 || bytes.Count(raw, boundary) != 1 {
		return nil, false
	}
	return bytes.Replace(raw, boundary, []byte(coverage), 1), true
}

func TestHistoricalReportDisclosureRetainsExactFrozenBody(t *testing.T) {
	legacy := []byte("# Outcome axes\n\nlegacy outcome\n\n# Role coverage\n\nlegacy role and finding\n")
	current := bytes.Replace(legacy, []byte("# Role coverage\n\n"), []byte(historicalRequirementsDisclosure+"# Role coverage\n\n"), 1)
	projected, ok := historicalReportBeforeRequirementsDisclosure(current)
	if !ok || !bytes.Equal(projected, legacy) {
		t.Fatal("exact current disclosure did not preserve every frozen report byte")
	}
	for name, invalid := range map[string][]byte{
		"missing":       legacy,
		"availability":  bytes.Replace(current, []byte("`unavailable`"), []byte("`not_requested`"), 1),
		"unknown_count": bytes.Replace(current, []byte("Selected requirements:** `unavailable`"), []byte("Selected requirements:** `0`"), 1),
		"duplicate":     append([]byte(historicalRequirementsDisclosure), current...),
		"moved":         append(append([]byte(nil), legacy...), []byte(historicalRequirementsDisclosure)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := historicalReportBeforeRequirementsDisclosure(invalid); ok {
				t.Fatal("invalid current disclosure passed the frozen-body boundary")
			}
		})
	}
	tampered := bytes.Replace(current, []byte("legacy role and finding"), []byte("changed role and finding"), 1)
	projected, ok = historicalReportBeforeRequirementsDisclosure(tampered)
	if !ok || historicalRawHash(projected) == historicalRawHash(legacy) {
		t.Fatal("current disclosure projection hid a change to the frozen report body")
	}
}

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
	_, validator := mustSharedFoundationAssets(t)
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

func TestIntegrationPreExistingProjectMigrationAndHistoryCoexistence(t *testing.T) {
	shared, err := os.ReadFile("testdata/coordination-upgrade/project-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile("testdata/coordination-upgrade/local-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		data   []byte
		digest string
	}{
		{shared, "42013c6fc559b4d7e27e2dba461c93ffe00d5d9e47577f4b110f39d0bbf6ef51"},
		{private, "8ce37893102db46fb2bdebf729dd3f116e3bf4adfbee2d98918fa7a77115aa15"},
	} {
		parts := bytes.SplitN(input.data, []byte("\n"), 4)
		if len(parts) != 4 || historicalRawHash(parts[3]) != input.digest {
			t.Fatal("released configuration fixture lost exact source provenance")
		}
	}
	baseline, err := adapterconfig.DecodeSplit(shared, private)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := historicalValidator(t)
	for _, selected := range []struct{ id, intent string }{
		{"ordinary-v2", "legacy"}, {"composite-copied-v1", "owned"}, {"failed-recovery", "borrowed"}, {"ordinary-v2", "unknown"},
	} {
		t.Run(selected.id+"/"+selected.intent, func(t *testing.T) {
			var current *historical.Case
			for i := range corpus.Cases {
				if corpus.Cases[i].ID == selected.id {
					current = &corpus.Cases[i]
					break
				}
			}
			if current == nil {
				t.Fatalf("missing frozen historical case %s", selected.id)
			}
			f := newHistoricalConsumer(t, *current, validator)
			ctx := context.Background()
			config := baseline
			config.Project.Name = "retained-custom-project"
			config.NativeUser.Home = t.TempDir()
			config.Providers.ZCode.AppBundle = filepath.Join(t.TempDir(), "ZCode.app")
			config.Providers.ZCode.Timeout = "7m"
			config.Providers.Grok = &adapterconfig.GrokProviderConfig{
				Executable: filepath.Join(t.TempDir(), "grok"), Timeout: "9m",
			}
			config.Roles.Documentation.PrimaryProvider = "grok"
			projectData, localData, err := adapterconfig.EncodeSplit(config)
			if err != nil {
				t.Fatal(err)
			}
			configRoot := filepath.Join(f.project.String(), ".mulgae")
			if err := os.Mkdir(configRoot, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string][]byte{"config.yaml": projectData, "local.yaml": localData} {
				if err := os.WriteFile(filepath.Join(configRoot, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// The frozen corpus has independent producer provenance. In particular,
			// failed recovery is retained evidence, never executable retry authority.
			beforeView, err := NewPublicationQueryService(f.queries).ReadRunStatus(ctx, f.run)
			if err != nil {
				t.Fatal(err)
			}
			if beforeView.RunID != current.RunID || beforeView.SessionID != current.SessionID {
				t.Fatal("historical identities changed")
			}
			if current.Family == "failed-recovery" {
				if !beforeView.FailedRunRecovery.Available || beforeView.HasFinalArtifact {
					t.Fatal("historical retry evidence gained publication authority")
				}
			} else if !beforeView.HasFinalArtifact || !beforeView.HasAxes {
				t.Fatal("historical P2 lost authority")
			}
			type retained struct {
				raw  []byte
				mode os.FileMode
			}
			before := map[string]retained{}
			remember := func(path string) {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = retained{raw, info.Mode()}
			}
			if err := filepath.WalkDir(f.root.String(), func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					remember(path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			remember(filepath.Join(configRoot, "config.yaml"))
			remember(filepath.Join(configRoot, "local.yaml"))
			initial, err := f.cleanup.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var keep []string
			for _, run := range initial.Runs {
				keep = append(keep, run.RunID)
			}
			session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
			protected, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
			eligible, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bb")
			seedClock := historicalClock{now: f.clock.Now().Add(-48 * time.Hour)}
			factory, err := filesystem.NewDiagnosticStoreFactory(filesystem.NewSecureWriter(), seedClock)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []domain.RunID{protected, eligible} {
				request, err := ports.NewRuntimeDiagnosticOpenRequest(f.root, session, id, seedClock.Now())
				if err != nil {
					t.Fatal(err)
				}
				sink, err := factory.Open(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				completed := seedClock.Now().Add(time.Second)
				status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
					SessionID: session, RunID: id, State: domain.RunFailed, StartedAt: seedClock.Now(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true,
					SelectedRoles: []domain.Role{domain.RoleTesting}, RolePathTotal: 1, RolePathFailed: 1,
					TerminalCause: domain.DiagnosticCausePublicationInstallationFailed, TerminalPhase: domain.DiagnosticPhasePublicationInstallation,
				})
				if err != nil {
					t.Fatal(err)
				}
				finalize, err := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunFailed, domain.DiagnosticCausePublicationInstallationFailed, status)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := sink.Finalize(ctx, finalize); err != nil {
					t.Fatal(err)
				}
			}
			name := "haepari-lock-intent-v2.json"
			if selected.intent == "borrowed" {
				name = "haepari-lock-intent-v3.json"
			}
			raw, err := os.ReadFile(filepath.Join("../../adapters/filesystem/testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if selected.intent == "unknown" {
				fields = map[string]json.RawMessage{"schema_version": json.RawMessage(`"future-unknown"`)}
			} else if selected.intent == "legacy" {
				fields["schema_version"] = json.RawMessage(`"mulgae-haepari-lock-intent.v1"`)
				delete(fields, "local_drain_state")
			} else {
				fields["local_drain_state"] = json.RawMessage(`"unverified"`)
			}
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			protectedPath := filepath.Join(f.root.String(), "diagnostics", session.String(), protected.String())
			intentPath := filepath.Join(protectedPath, "haepari-lock.json")
			if err := os.WriteFile(intentPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			remember(intentPath)
			if selected.intent != "unknown" {
				record, found, err := filesystem.NewCoordinationIntentStore().LoadIntent(ctx, f.root, session, protected)
				if err != nil || !found || (selected.intent == "legacy" && record.LocalDrainState != "") ||
					(selected.intent != "legacy" && record.LocalDrainState != ports.ReviewLocalDrainUnverified) {
					t.Fatalf("prior lock intent is not meaningful: %+v / %t / %v", record, found, err)
				}
			}
			snapshot, err := f.cleanup.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Policy = clean.Policy{RetentionAgeSeconds: 1, ExplicitKeepRunIDs: keep}
			policy, err := json.Marshal(snapshot.Policy)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.InputPolicySHA256 = "sha256:" + historicalRawHash(policy)
			plan, err := clean.Plan(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			protectedSelected, eligibleSelected := false, false
			for _, action := range plan.OrderedActions {
				if action.RunID == protected.String() {
					protectedSelected = true
				}
				if action.RunID == eligible.String() {
					eligibleSelected = true
				}
			}
			if protectedSelected || !eligibleSelected {
				t.Fatalf("unsafe or vacuous cleanup plan: %+v", plan.RunDecisions)
			}
			if err := f.cleanup.WithCleanupTransaction(ctx, func(tx clean.CleanupTransaction) error { return tx.PersistDryRunPlan(ctx, plan) }); err != nil {
				t.Fatal(err)
			}
			apply, err := clean.ApplyPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := clean.ExecuteApply(ctx, f.cleanup, apply); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(f.root.String(), "diagnostics", session.String(), eligible.String())); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("eligible diagnostic was not removed: %v", err)
			}
			for path, want := range before {
				raw, err := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(raw, want.raw) || info.Mode() != want.mode {
					t.Fatalf("cleanup changed retained input %s: %v / %v", path, err, statErr)
				}
			}
			afterView, err := NewPublicationQueryService(f.queries).ReadRunStatus(ctx, f.run)
			if err != nil || !reflect.DeepEqual(beforeView, afterView) {
				t.Fatalf("historical results/recovery changed: %+v / %v", afterView, err)
			}
			afterProject, err := os.ReadFile(filepath.Join(configRoot, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			afterLocal, err := os.ReadFile(filepath.Join(configRoot, "local.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := adapterconfig.DecodeSplit(afterProject, afterLocal)
			if err != nil || !reflect.DeepEqual(decoded, config) {
				t.Fatalf("custom routing/timeouts/credential bindings changed: %+v / %v", decoded, err)
			}
			// Unsupported future input refuses admission without rewriting either file.
			future := bytes.Replace(afterProject, []byte("version: 5"), []byte("version: 999"), 1)
			if bytes.Equal(future, afterProject) {
				t.Fatal("future-version fixture did not change the version")
			}
			if _, err := adapterconfig.DecodeSplit(future, afterLocal); err == nil {
				t.Fatal("unsupported prior configuration was silently migrated")
			}
		})
	}
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
			if c.ID == "composite-mixed-v1" {
				reason = "retired_provider_artifact"
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
			frozenBody, disclosureValid := historicalReportBeforeRequirementsDisclosure(rendered.Markdown)
			if !disclosureValid || c.Expected.Report == "" || "sha256:"+historicalRawHash(frozenBody) != c.Expected.Report {
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
		if len(c.Controls) > 0 || c.Expected.ReadReason != "" || c.ID == "composite-mixed-v1" {
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
				frozenBody, disclosureValid := historicalReportBeforeRequirementsDisclosure(rendered.Bytes())
				if !disclosureValid || "sha256:"+historicalRawHash(frozenBody) != c.Expected.Report {
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
