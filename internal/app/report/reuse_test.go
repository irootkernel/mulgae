package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const reportReuseTargetSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// reportEvidenceFinalMutation expands the fixture finding to count evidence
// items with distinct canonical paths and claim-bound excerpt digests.
func reportEvidenceFinalMutation(t *testing.T, count int) func(string) string {
	t.Helper()
	return func(value string) string {
		var document map[string]any
		if err := json.Unmarshal([]byte(value), &document); err != nil {
			t.Fatal(err)
		}
		session := document["session_id"].(string)
		run := document["run_id"].(string)
		review := document["review_id"].(string)
		finding := document["findings"].([]any)[0].(map[string]any)
		source := finding["evidence"].([]any)[0].(map[string]any)["source"].(map[string]any)
		sourceExcerptSHA256 := source["source_excerpt_sha256"].(string)
		items := make([]any, 0, count)
		for i := 0; i < count; i++ {
			path := "internal/example.go"
			if count > 1 {
				path = fmt.Sprintf("internal/example-%d.go", i)
			}
			quote := "line one\nline two"
			items = append(items, map[string]any{
				"source":  map[string]any{"session_id": session, "run_id": run, "review_id": review, "finding_id": "F001", "source_target_sha256": reportReuseTargetSHA256, "source_excerpt_sha256": sourceExcerptSHA256},
				"current": map[string]any{"target_sha256": reportReuseTargetSHA256, "side": "worktree", "path": path, "line_start": 1, "line_end": 2, "quote": quote, "current_excerpt_sha256": reportCurrentExcerptDigest(t, reportReuseTargetSHA256, "worktree", path, 1, 2, []byte(quote)), "verification": "verified"},
			})
		}
		// Canonical evidence order is keyed by the current-excerpt digest
		// before the path, so sort the generated items the same way.
		sort.Slice(items, func(i, j int) bool {
			left, right := items[i].(map[string]any)["current"].(map[string]any), items[j].(map[string]any)["current"].(map[string]any)
			if left["current_excerpt_sha256"] != right["current_excerpt_sha256"] {
				return left["current_excerpt_sha256"].(string) < right["current_excerpt_sha256"].(string)
			}
			return left["path"].(string) < right["path"].(string)
		})
		finding["evidence"] = items
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
}

// reportSupportIndexMutation binds a support index to the fixture manifest.
func reportSupportIndexMutation(path, sha256Value string) func(string) string {
	return func(value string) string {
		bound := `"support_index":{"path":` + strconv.Quote(path) + `,"sha256":` + strconv.Quote(sha256Value) + `},"manifest":`
		return strings.Replace(value, `"composite_identity":{"manifest":`, `"composite_identity":{`+bound, 1)
	}
}

// reportEvidenceServiceFixture builds a committed fixture whose finding has
// count evidence items, each with a retained excerpt artifact listed in a
// manifest-bound v1 support index.
func reportEvidenceServiceFixture(t *testing.T, count int) (ports.PublicationRun, query.CommittedReview, *query.Service, *reportQueryStore) {
	t.Helper()
	prefix := "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	support := map[string]ports.ImmutablePublicationArtifact{}
	identities := ""
	for i := 0; i < count; i++ {
		path := prefix + fmt.Sprintf("/excerpts/F001_%d.md", i+1)
		artifact := reportArtifact(t, reportPath(t, path), []byte("line one\nline two"))
		support[path] = artifact
		if identities != "" {
			identities += ","
		}
		identities += fmt.Sprintf(`{"path":%q,"sha256":%q}`, path, artifact.SHA256())
	}
	indexPath := prefix + "/support/index.json"
	index := reportArtifact(t, reportPath(t, indexPath), []byte(`{"schema_version":"mulgae-run-support-index.v1","artifacts":[`+identities+`]}`))
	support[indexPath] = index
	run, service, store := reportCommittedPartsFixture(t, reportEvidenceFinalMutation(t, count), reportSupportIndexMutation(indexPath, index.SHA256()))
	store.auxiliaryArtifacts = support
	review, err := service.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("evidence fixture committed read: %v", err)
	}
	return run, review, service, store
}

type perIndexExcerptReader struct {
	review query.CommittedReview
	errs   map[int]error
}

func (reader *perIndexExcerptReader) ReadCommitted(context.Context, ports.PublicationRun) (query.CommittedReview, error) {
	return reader.review, nil
}

func (reader *perIndexExcerptReader) RenderExcerptAt(_ context.Context, _ ports.PublicationRun, _, _ string, index int) ([]byte, error) {
	if err, ok := reader.errs[index]; ok {
		return nil, err
	}
	return []byte("line one\nline two"), nil
}

func (reader *perIndexExcerptReader) WithVerifiedSnapshot(ctx context.Context, _ ports.PublicationRun, use func(context.Context, query.ContentReader) error) error {
	return use(ctx, reader)
}

// TestRenderMixedExcerptFailuresKeepFatalOverPartial pins the partial-error
// contract: a readiness-class excerpt failure may render its state field, but
// a fatal excerpt failure anywhere in the finding still fails the render, and
// no partial report is returned.
func TestRenderMixedExcerptFailuresKeepFatalOverPartial(t *testing.T) {
	readiness, err := domain.NewFailure(renderStage, domain.FailureProviderUnavailable, "current evidence is stale", nil)
	if err != nil {
		t.Fatal(err)
	}
	fatal, err := domain.NewFailure(renderStage, domain.FailureArtifact, "committed excerpt artifact does not match the finding", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, review, _, _ := reportEvidenceServiceFixture(t, 2)
	for name, errs := range map[string]map[int]error{
		"readiness first, fatal second": {1: readiness, 2: fatal},
		"fatal first, readiness second": {1: fatal, 2: readiness},
	} {
		t.Run(name, func(t *testing.T) {
			rendered, renderErr := mustReportService(t, &perIndexExcerptReader{review: review, errs: errs}).Render(context.Background(), mustReuseRun(t))
			if !errors.Is(renderErr, fatal) {
				t.Fatalf("Render() error = %v, want the fatal excerpt failure", renderErr)
			}
			if len(rendered.Bytes()) != 0 {
				t.Fatalf("Render() returned partial markdown: %s", rendered.Bytes())
			}
		})
	}
}

func mustReuseRun(t *testing.T) ports.PublicationRun {
	t.Helper()
	run, err := ports.NewPublicationRun(reuseRoot(t), mustReuseSessionID(t), mustReuseRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba"))
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func mustReuseRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	runID, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

func mustReuseSessionID(t *testing.T) domain.SessionID {
	t.Helper()
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func reuseRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/private/report-test")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestReportRenderRejectsRetiredProviderReview preserves today's behavior
// where the legacy render fails before producing markdown: a retired provider
// family in the requested publication is rejected while its committed
// snapshot loads, and an acceptable requested publication is still rejected
// when the retirement walk resolves a retired ancestor. These are
// behavior-preservation regressions, not failing-first reuse tests.
func TestReportRenderRejectsRetiredProviderReview(t *testing.T) {
	t.Run("root-level retired family", func(t *testing.T) {
		retire := func(value string) string {
			return strings.ReplaceAll(value, "logic-provider", "kimi-logic")
		}
		run, service, _ := reportCommittedPartsFixture(t, retire, retire)
		_, err := mustReportOpener(t, service).Render(context.Background(), run)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != "retired_provider_artifact" {
			t.Fatalf("root-level retired render error = %v, want artifact retired_provider_artifact", err)
		}
	})
	t.Run("resolved ancestor retired", func(t *testing.T) {
		rootRun := mustReuseRun(t)
		ancestorID := "r_019f596a-cfe4-7c9c-b82e-7149158243bc"
		rebase := func(value string) string {
			return strings.ReplaceAll(value, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", ancestorID)
		}
		retire := func(value string) string {
			return strings.ReplaceAll(rebase(value), "logic-provider", "kimi-logic")
		}
		_, _, ancestorStore := reportCommittedPartsFixture(t, retire, retire)
		lineage := `"parent_run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243bb","source_run_id":` + strconv.Quote(ancestorID) + `,"source_review_id":"019f596a-d174-7321-b920-c2d312c82cc3","source_finding_ref":"F001","replay_mode":null`
		outcome := `"followup_outcome":{"resolution":"partially_resolved","rationale":"verified resolution","evidence":[{"source":{"session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":` + strconv.Quote(ancestorID) + `,"review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001","source_target_sha256":` + strconv.Quote(reportReuseTargetSHA256) + `,"source_excerpt_sha256":` + strconv.Quote(reportSHA([]byte("historical source excerpt"))) + `},"current":{"target_sha256":` + strconv.Quote(reportReuseTargetSHA256) + `,"side":"worktree","path":"internal/example.go","line_start":1,"line_end":2,"quote":"line one\nline two","current_excerpt_sha256":` + strconv.Quote(reportCurrentExcerptDigest(t, reportReuseTargetSHA256, "worktree", "internal/example.go", 1, 2, []byte("line one\nline two"))) + `,"verification":"verified"}}]},`
		finalFollowup := func(value string) string {
			value = strings.ReplaceAll(value, `"run_type":"review"`, `"run_type":"followup"`)
			value = strings.Replace(value, `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`, lineage, 1)
			value = strings.Replace(value, `"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","review_id":"019f596a-d174-7321-b920-c2d312c82cc2","finding_id":"F001"`, `"run_id":`+strconv.Quote(ancestorID)+`,"review_id":"019f596a-d174-7321-b920-c2d312c82cc3","finding_id":"F001"`, 1)
			return strings.Replace(value, `"target":{"content_sha256"`, outcome+`"target":{"content_sha256"`, 1)
		}
		manifestFollowup := func(value string) string {
			value = strings.ReplaceAll(value, `"run_type":"review"`, `"run_type":"followup"`)
			value = strings.Replace(value, `"parent_run_id":null,"source_run_id":null,"source_review_id":null,"source_finding_ref":null,"replay_mode":null`, lineage, 1)
			return strings.Replace(value, `"target":{"manifest_path"`, outcome+`"target":{"manifest_path"`, 1)
		}
		run, service, store := reportCommittedPartsFixture(t, finalFollowup, manifestFollowup)
		store.observationsByRun = map[string]ports.PublicationObservation{ancestorID: ancestorStore.observation}
		store.snapshotsByRun = map[string]ports.CommittedPublicationSnapshot{ancestorID: ancestorStore.snapshot}
		ancestorRun, err := ports.NewPublicationRun(rootRun.Root(), rootRun.SessionID(), mustReuseRunID(t, ancestorID))
		if err != nil {
			t.Fatal(err)
		}
		store.resolutionsByRun = map[string]ports.PublicationRun{ancestorID: ancestorRun}
		_, err = mustReportOpener(t, service).Render(context.Background(), run)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact || failure.Reason() != "retired_provider_artifact" {
			t.Fatalf("ancestor-retired render error = %v, want artifact retired_provider_artifact", err)
		}
		for _, observed := range store.observeOrder {
			if observed == ancestorID {
				return
			}
		}
		t.Fatalf("retirement walk never resolved ancestor %s: %v", ancestorID, store.observeOrder)
	})
}

// TestReportRenderSingleSupportPassPerRender is the failing-first reuse
// regression for the legacy render path over the query service: one render
// performs one whole-support traversal (one support-index read) plus one
// digest-bound read per served excerpt, with one snapshot read and a single
// final P2 re-observation.
func TestReportRenderSingleSupportPassPerRender(t *testing.T) {
	run, _, service, store := reportEvidenceServiceFixture(t, 3)
	store.observeCalls, store.snapshotReads, store.auxiliaryReads = 0, 0, 0
	store.auxiliaryRequests = nil
	rendered, err := mustReportOpener(t, service).Render(context.Background(), run)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(rendered.Bytes()) == 0 {
		t.Fatal("Render() produced no markdown")
	}
	indexReads := 0
	excerptReads := 0
	for _, request := range store.auxiliaryRequests {
		switch {
		case strings.HasSuffix(request.Path().String(), "/support/index.json"):
			indexReads++
		case strings.Contains(request.Path().String(), "/excerpts/F001_"):
			excerptReads++
		}
	}
	if indexReads != 1 {
		t.Fatalf("whole-support traversals = %d, want 1", indexReads)
	}
	if excerptReads != 3 {
		t.Fatalf("served excerpt reads = %d, want 3", excerptReads)
	}
	if store.observeCalls != 2 {
		t.Fatalf("ObserveRun calls = %d, want 2 (initial observation + final confirmation)", store.observeCalls)
	}
	if store.snapshotReads != 1 {
		t.Fatalf("snapshot reads = %d, want 1", store.snapshotReads)
	}
}

// mustReportOpener builds the renderer over a real snapshot opener, so the
// legacy render path is exercised exactly as composition wires it.
func mustReportOpener(t *testing.T, opener SnapshotOpener) *Service {
	t.Helper()
	service, err := NewService(opener)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// TestWithVerifiedSnapshotConfirmsBeforeReturning pins the report-opener
// final confirmation: the unmutated render succeeds, and a publication
// identity change armed after the snapshot read, visible only to that
// confirmation, fails the render without returning markdown.
func TestWithVerifiedSnapshotConfirmsBeforeReturning(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		run, _, service, _ := reportEvidenceServiceFixture(t, 3)
		rendered, err := mustReportOpener(t, service).Render(context.Background(), run)
		if err != nil {
			t.Fatalf("stable render = %v", err)
		}
		if len(rendered.Bytes()) == 0 {
			t.Fatal("stable render produced no markdown")
		}
	})
	t.Run("identity changed after snapshot", func(t *testing.T) {
		run, _, service, store := reportEvidenceServiceFixture(t, 3)
		store.afterSnapshot = func() {
			store.afterSnapshot = nil
			store.observation = reportEpochTwoObservation(t, store)
		}
		rendered, err := mustReportOpener(t, service).Render(context.Background(), run)
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
			t.Fatalf("changed publication rendered: %v (%d bytes)", err, len(rendered.Bytes()))
		}
		if len(rendered.Bytes()) != 0 {
			t.Fatalf("failed render returned markdown: %d bytes", len(rendered.Bytes()))
		}
	})
}

// reportEpochTwoObservation re-observes the fixture publication at epoch two.
func reportEpochTwoObservation(t *testing.T, store *reportQueryStore) ports.PublicationObservation {
	t.Helper()
	epochRecord, err := ports.NewImmutablePublicationArtifact(
		store.snapshot.Epoch().Record().Path(),
		store.snapshot.Epoch().Record().SHA256(),
		store.snapshot.Epoch().Record().Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(2, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ports.NewCommittedPublicationSnapshot(store.snapshot.Final(), store.snapshot.Manifest(), store.snapshot.LineageEdge(), epoch)
	if err != nil {
		t.Fatal(err)
	}
	return reportObservationFor(t, changed, 2)
}

func reportObservationFor(t *testing.T, snapshot ports.CommittedPublicationSnapshot, epoch uint64) ports.PublicationObservation {
	t.Helper()
	finalPath := snapshot.Final().Identity().Path().String()
	cut := strings.LastIndex(finalPath, "/review_")
	if cut < 0 {
		t.Fatal("fixture final path has no canonical review suffix")
	}
	prefix := finalPath[:cut]
	journal, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationJournal, reportPath(t, prefix+"/publication/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := ports.NewMissingMutablePublicationDocument(ports.MutablePublicationStatus, reportPath(t, prefix+"/status.json"))
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewPublicationRecoveryMaterialWithCommittedSnapshot(snapshot.Final(), journal, status, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	exit := domain.ExitIncompleteCoverage
	observation, err := ports.NewPublicationObservationWithRecovery(domain.JournalCompleted, domain.DurableObservationP2Committed, &exit, nil, epoch, material)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}
