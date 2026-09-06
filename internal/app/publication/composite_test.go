//go:build darwin && arm64

package publication

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
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	appreport "github.com/irootkernel/mulgae/internal/app/report"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type compositeTestIDs struct{ reviewID domain.ReviewID }

func (ids compositeTestIDs) NewReviewID(time.Time) (domain.ReviewID, error) { return ids.reviewID, nil }

type compositeStatusConflictStore struct {
	*filesystem.PublicationStore
	conflicted bool
}

type compositeInterruptedStore struct {
	*filesystem.PublicationStore
	after  int
	writes int
}

func (store *compositeInterruptedStore) PersistValidatedCandidate(ctx context.Context, request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	result, err := store.PublicationStore.PersistValidatedCandidate(ctx, request)
	if err == nil && store.after == 0 {
		return ports.PersistValidatedCandidateResult{}, errors.New("interrupted after candidate installation")
	}
	return result, err
}

func (store *compositeInterruptedStore) PersistAuxiliaryArtifact(ctx context.Context, request ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	result, err := store.PublicationStore.PersistAuxiliaryArtifact(ctx, request)
	store.writes++
	if err == nil && store.writes == store.after {
		return ports.PersistAuxiliaryArtifactResult{}, errors.New("interrupted after support installation")
	}
	return result, err
}

func TestCompositePublicationResumesUnjournaledCandidate(t *testing.T) {
	for _, after := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprintf("after-%d", after), func(t *testing.T) {
			testCompositeLifecycle(t, "", after)
		})
	}
}

func (store *compositeStatusConflictStore) ReplaceMutable(ctx context.Context, request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	if request.Document() == ports.MutablePublicationStatus && !store.conflicted {
		store.conflicted = true
		return ports.MutableReplaceResult{}, ports.ErrMutableCASConflict
	}
	return store.PublicationStore.ReplaceMutable(ctx, request)
}

func TestCompositeCandidateBuildsSelfContainedSchemaValidBundle(t *testing.T) {
	testCompositeLifecycle(t, "")
}

func TestCompositeGitTargetsRemainReadableAndRecoverable(t *testing.T) {
	for _, mode := range []domain.GitTargetMode{domain.GitTargetDiff, domain.GitTargetStage, domain.GitTargetDirty} {
		t.Run(string(mode), func(t *testing.T) { testCompositeLifecycle(t, mode) })
	}
}

func testCompositeLifecycle(t *testing.T, mode domain.GitTargetMode, interruptAfter ...int) {
	t.Helper()
	targetBytes := []byte("diff --git a/a.go b/a.go\n")
	targetInput := domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: bareSHA256(targetBytes)}
	if mode != "" {
		targetInput.Kind = domain.TargetGit
		targetInput.RepositoryID = "fixture"
		targetInput.BaseObjectID = "1111111111111111111111111111111111111111"
		targetInput.HeadObjectID = "2222222222222222222222222222222222222222"
		targetInput.HeadTreeObjectID = "3333333333333333333333333333333333333333"
		targetInput.IndexTreeObjectID = "4444444444444444444444444444444444444444"
		targetInput.GitMode = mode
	}
	target, err := domain.NewTargetIdentity(targetInput)
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("cause: %T %v", cause, cause)
		}
		t.Fatal(err)
	}
	root, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	sourceRun, _ := domain.ParseRunID("r_019f596a-cfe5-7c9c-b82e-7149158243ba")
	rootReview, _ := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	sourceReview, _ := domain.ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
	attempt, _ := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	coordinate, _ := domain.NewCompositionSource(domain.RoleLogic, sourceRun, sourceReview, attempt)
	fingerprint, _ := domain.NewCompositionFingerprint(root, []domain.CompositionSource{coordinate})
	runID, _ := fingerprint.RunID()
	report := []byte("# Logic\n\nNo findings.\n")
	input := CompositeCandidateInput{SessionID: session, RunID: runID, Fingerprint: fingerprint, RootRunID: root, RootReviewID: rootReview, Target: target, TargetBytes: targetBytes, Threshold: domain.SeverityHigh, ContentVerdict: domain.ContentFindingsPresent, CoverageStatus: domain.CoverageComplete, ExtractionStatus: domain.StructuredExtractionStructured, CIDecision: domain.CIPass, CIReasonCodes: []string{"policy_evaluated"}}
	input.Sources = []CompositeSourceInput{{Kind: "recovery", Role: domain.RoleLogic, RunID: sourceRun, ReviewID: sourceReview, AttemptID: attempt, RoleReportSHA256: sha256Identifier(report)}}
	input.Roles = []CompositeRoleInput{{Role: domain.RoleLogic, Required: true, Outcome: "completed", AttemptID: attempt, ProviderInstance: "codex-primary", SourceRunID: sourceRun, SourceReviewID: sourceReview, ValidFindingIDs: []string{"F001"}}}
	input.Findings = []CompositeFindingInput{{ID: "F001", Fingerprint: sha256Identifier([]byte("logic finding")), Role: domain.RoleLogic, Severity: domain.SeverityLow, Title: "Logic finding", Description: "A source finding retained by composition.", Recommendation: "Address the source finding.", Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen, SourceRunID: sourceRun, SourceReviewID: sourceReview, SourceAttemptID: attempt, SourceFindingID: "F007"}}
	input.RoleReports = []CompositeRoleReportInput{{Role: domain.RoleLogic, AttemptID: attempt, ProviderInstance: "codex-primary", SHA256: sha256Identifier(report), Bytes: report, SourceRunID: sourceRun}}
	candidate, err := PrepareCompositeCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	reviewID, _ := domain.ParseReviewID("019f596a-d176-7321-b920-c2d312c82cc2")
	recorder := &publicationTestValidator{}
	bundle, err := candidate.Build(context.Background(), recorder, reviewID, time.Date(2026, 7, 13, 3, 10, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), recorder.ids[0], recorder.bytes[0]); err != nil {
		t.Fatalf("final schema: %v\n%s", err, recorder.bytes[0])
	}
	if err := validator.Validate(context.Background(), recorder.ids[1], recorder.bytes[1]); err != nil {
		t.Fatalf("manifest schema: %v\n%s", err, recorder.bytes[1])
	}
	for _, test := range []struct {
		name   string
		index  int
		mutate func(map[string]any)
	}{
		{"degraded run", 1, func(value map[string]any) { value["state"] = "degraded" }},
		{"empty role report", 1, func(value map[string]any) {
			value["role_reports"].([]any)[0].(map[string]any)["byte_length"] = 0
		}},
		{"not applicable role", 0, func(value map[string]any) {
			value["role_outcomes"].([]any)[0].(map[string]any)["outcome"] = "not_applicable"
		}},
	} {
		var value map[string]any
		if err := json.Unmarshal(recorder.bytes[test.index], &value); err != nil {
			t.Fatal(err)
		}
		test.mutate(value)
		invalid, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := validator.Validate(context.Background(), recorder.ids[test.index], invalid); err == nil {
			t.Errorf("composite schema accepted unpublishable %s", test.name)
		}
	}
	if !bundle.Valid() {
		t.Fatal("composite bundle is invalid")
	}
	if got := len(bundle.SupportArtifacts()); got != 4 {
		t.Fatalf("support artifact count = %d", got)
	}
	rootPath := filepath.Join(t.TempDir(), ".mulgae")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootScope, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceReportPath := filepath.Join(rootPath, session.String(), sourceRun.String(), "role-reports", "logic.md")
	if err := os.MkdirAll(filepath.Dir(sourceReportPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceReportPath, report, 0o600); err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: time.Date(2026, 7, 13, 3, 10, 0, 0, time.UTC)}
	store, err := filesystem.NewPublicationStore(validator, clock, compositeTestIDs{reviewID: reviewID}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	faultStore := &compositeStatusConflictStore{PublicationStore: store}
	if len(interruptAfter) != 0 {
		interrupted := &compositeInterruptedStore{PublicationStore: store, after: interruptAfter[0]}
		firstService, err := NewService(interrupted, validator, clock, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := firstService.PublishCompositeNext(context.Background(), rootScope, candidate); err == nil {
			t.Fatal("interrupted publication succeeded")
		}
		changed := input
		changed.CIDecision = domain.CIFail
		mismatched, err := PrepareCompositeCandidate(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := firstService.PublishCompositeNext(context.Background(), rootScope, mismatched); err == nil {
			t.Fatal("unjournaled candidate accepted different composition inputs")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := firstService.PublishCompositeNext(cancelled, rootScope, candidate); err == nil {
			t.Fatal("cancelled replay succeeded")
		}
		if interruptAfter[0] > 0 {
			support := bundle.SupportArtifacts()[0]
			path := filepath.Join(rootPath, support.Path().String())
			if err := os.WriteFile(path, []byte("conflicting support"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := firstService.PublishCompositeNext(context.Background(), rootScope, candidate); err == nil {
				t.Fatal("replay accepted conflicting support bytes")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			targetPath := filepath.Join(t.TempDir(), "outside-support")
			if err := os.WriteFile(targetPath, support.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(targetPath, path); err != nil {
				t.Fatal(err)
			}
			if _, err := firstService.PublishCompositeNext(context.Background(), rootScope, candidate); err == nil {
				t.Fatal("replay followed a support symlink")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, support.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		clock.now = clock.now.Add(time.Hour)
		nextID, _ := domain.ParseReviewID("019f596a-d177-7321-b920-c2d312c82cc2")
		store, err = filesystem.NewPublicationStore(validator, clock, compositeTestIDs{reviewID: nextID}, filesystem.NewSecureWriter())
		if err != nil {
			t.Fatal(err)
		}
		faultStore.PublicationStore = store
	}
	service, err := NewService(faultStore, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishCompositeNext(context.Background(), rootScope, candidate)
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("cause: %T %v", cause, cause)
		}
		t.Fatal(err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("authority = %s", result.Decision().Authority())
	}
	if !faultStore.conflicted {
		t.Fatal("publication did not exercise post-commit status recovery")
	}
	if _, err := os.Stat(filepath.Join(rootPath, session.String(), runID.String(), "status.json")); err != nil {
		t.Fatalf("recovered composite status: %v", err)
	}
	retried, err := service.PublishCompositeNext(context.Background(), rootScope, candidate)
	if err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	firstFinal, _ := result.Final()
	if len(interruptAfter) != 0 && firstFinal != bundle.Final().Identity() {
		t.Fatal("replay changed the persisted review ID, creation time, or final bytes")
	}
	retryFinal, _ := retried.Final()
	if retryFinal != firstFinal || retried.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("exact retry did not converge to the same P2 final")
	}
	alteredInput := input
	alteredInput.CIDecision = domain.CIFail
	altered, err := PrepareCompositeCandidate(alteredInput)
	if err != nil {
		t.Fatal(err)
	}
	if altered.ValidatedCandidateSHA256() == candidate.ValidatedCandidateSHA256() {
		t.Fatal("candidate binding ignored a changed effective outcome")
	}
	if _, err := service.PublishCompositeNext(context.Background(), rootScope, altered); err == nil {
		t.Fatal("same composition identity accepted a different effective outcome")
	}
	run, err := ports.NewPublicationRun(rootScope, session, runID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := service.Recover(context.Background(), run)
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("recovery cause: %T %v", cause, cause)
		}
		t.Fatalf("recover committed composite: %v", err)
	}
	recoveredFinal, ok := recovered.Final()
	if !ok || recoveredFinal != firstFinal || recovered.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("recovery changed committed composite authority")
	}
	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := queries.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if committed.RunType() != domain.RunTypeComposite || len(committed.RoleReports()) != 1 {
		t.Fatal("composite query projection is incomplete")
	}
	runtimeTarget, err := queries.ReadRuntimeTarget(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if string(runtimeTarget.Bytes()) != string(targetBytes) || runtimeTarget.Identity() != target {
		t.Fatal("composite target bytes changed")
	}
	content, err := queries.ReadCommittedRoleReport(context.Background(), run, committed.RoleReports()[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(report) {
		t.Fatal("composite role report changed")
	}
	status, err := queries.ReadRunStatus(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if status.Authority() != domain.PublicationAuthorityP2 || len(status.RoleReportURIs()) != 1 {
		t.Fatal("composite status projection is incomplete")
	}
	findings, err := queries.ListFindings(context.Background(), run, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID() != "F001" || findings[0].Role() != domain.RoleLogic {
		t.Fatal("composite findings projection is incomplete")
	}
	reports, err := appreport.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	rendered, renderErr := reports.Render(context.Background(), run)
	if err := renderErr; err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("report cause: %T %v", cause, cause)
		}
		t.Fatalf("composite report: %v", err)
	}
	if !bytes.Contains(rendered.Bytes(), []byte("2026-07-13T03:10:00Z")) {
		t.Fatal("composite report omitted its committed creation timestamp")
	}
	unchanged, err := os.ReadFile(sourceReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(report) {
		t.Fatal("source role report was mutated by composite publication")
	}
	if err := os.RemoveAll(filepath.Join(rootPath, session.String(), sourceRun.String())); err != nil {
		t.Fatal(err)
	}
	afterCleanup, err := queries.ReadCommitted(context.Background(), run)
	if err != nil {
		t.Fatalf("composite after source cleanup: %v", err)
	}
	if _, err := queries.ReadCommittedRoleReport(context.Background(), run, afterCleanup.RoleReports()[0]); err != nil {
		t.Fatalf("self-contained report after source cleanup: %v", err)
	}
}

func bareSHA256(value []byte) string { return sha256Identifier(value)[len("sha256:"):] }
