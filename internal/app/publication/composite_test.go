//go:build darwin && arm64

package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

const compositeRecoveryManifestSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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

func (store *compositeInterruptedStore) ReplaceMutable(ctx context.Context, request ports.MutableReplaceRequest) (ports.MutableReplaceResult, error) {
	result, err := store.PublicationStore.ReplaceMutable(ctx, request)
	if err == nil && store.after == -1 && request.Document() == ports.MutablePublicationJournal {
		os.Exit(73)
	}
	return result, err
}

func (store *compositeInterruptedStore) InstallFinal(ctx context.Context, request ports.InstallFinalRequest) (ports.InstallFinalResult, error) {
	result, err := store.PublicationStore.InstallFinal(ctx, request)
	if err == nil && store.after == -2 {
		os.Exit(73)
	}
	return result, err
}

func TestCompositePublicationResumesJournaledCandidate(t *testing.T) {
	for _, test := range []struct {
		name  string
		after int
	}{{"journal", -1}, {"final", -2}} {
		t.Run(test.name, func(t *testing.T) {
			t.Run("recover", func(t *testing.T) { testCompositeLifecycle(t, "", true, test.after) })
			t.Run("repeat", func(t *testing.T) { testCompositeLifecycle(t, "", false, test.after) })
		})
	}
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
			testCompositeLifecycle(t, "", false, after)
		})
	}
}

func TestCompositePublicationResumesUnjournaledRecoveryV2Candidate(t *testing.T) {
	for _, after := range []int{0, 1} {
		t.Run(fmt.Sprintf("after-%d", after), func(t *testing.T) {
			testCompositeLifecycleWithRecoveryRoot(t, "", false, compositeRecoveryManifestSHA256, after)
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
	testCompositeLifecycle(t, "", false)
}

func TestCompositeGitTargetsRemainReadableAndRecoverable(t *testing.T) {
	for _, mode := range []domain.GitTargetMode{domain.GitTargetDiff, domain.GitTargetStage, domain.GitTargetDirty} {
		t.Run(string(mode), func(t *testing.T) { testCompositeLifecycle(t, mode, false) })
	}
}

func testCompositeLifecycle(t *testing.T, mode domain.GitTargetMode, recoverFirst bool, interruptAfter ...int) {
	testCompositeLifecycleWithRecoveryRoot(t, mode, recoverFirst, "", interruptAfter...)
}

func testCompositeLifecycleWithRecoveryRoot(t *testing.T, mode domain.GitTargetMode, recoverFirst bool, rootRecoveryManifestSHA256 string, interruptAfter ...int) {
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
	var fingerprint domain.CompositionFingerprint
	if rootRecoveryManifestSHA256 == "" {
		fingerprint, err = domain.NewCompositionFingerprint(root, []domain.CompositionSource{coordinate})
	} else {
		rootReview = domain.ReviewID{}
		recoveryRoot, recoveryErr := domain.NewRecoverySourceReference(root, rootRecoveryManifestSHA256)
		if recoveryErr != nil {
			t.Fatal(recoveryErr)
		}
		fingerprint, err = domain.NewRecoveryCompositionFingerprint(recoveryRoot, []domain.CompositionSource{coordinate})
	}
	if err != nil {
		t.Fatal(err)
	}
	runID, _ := fingerprint.RunID()
	report := []byte("# Logic\n\nNo findings.\n")
	input := CompositeCandidateInput{SessionID: session, RunID: runID, Fingerprint: fingerprint, RootRunID: root, RootReviewID: rootReview, RootRecoveryManifestSHA256: rootRecoveryManifestSHA256, Target: target, TargetBytes: targetBytes, Threshold: domain.SeverityHigh, ContentVerdict: domain.ContentFindingsPresent, CoverageStatus: domain.CoverageComplete, ExtractionStatus: domain.StructuredExtractionStructured, CIDecision: domain.CIPass, CIReasonCodes: []string{"policy_evaluated"}}
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
	wantFinalSchemaVersion := "mulgae-composite-review-artifact.v1"
	wantManifestSchemaVersion := "mulgae-composite-run-manifest.v1"
	if rootRecoveryManifestSHA256 != "" {
		wantFinalSchemaVersion = "mulgae-composite-review-artifact.v2"
		wantManifestSchemaVersion = "mulgae-composite-run-manifest.v2"
	}
	var finalEnvelope struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(bundle.Final().Bytes(), &finalEnvelope); err != nil {
		t.Fatal(err)
	}
	if finalEnvelope.SchemaVersion != wantFinalSchemaVersion {
		t.Fatalf("built final schema version = %q, want %q", finalEnvelope.SchemaVersion, wantFinalSchemaVersion)
	}
	var manifestEnvelope struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(bundle.Manifest().Bytes(), &manifestEnvelope); err != nil {
		t.Fatal(err)
	}
	if manifestEnvelope.SchemaVersion != wantManifestSchemaVersion {
		t.Fatalf("built manifest schema version = %q, want %q", manifestEnvelope.SchemaVersion, wantManifestSchemaVersion)
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
	checkCompositeVersionPairs(t, bundle)
	if got := len(bundle.SupportArtifacts()); got != 4 {
		t.Fatalf("support artifact count = %d", got)
	}
	var rootPath string
	if len(interruptAfter) != 0 && interruptAfter[0] < 0 {
		rootPath = os.Getenv("MULGAE_TEST_COMPOSITE_INTERRUPT_ROOT")
	}
	if rootPath == "" {
		rootPath = filepath.Join(t.TempDir(), ".mulgae")
	}
	if err := os.MkdirAll(rootPath, 0o700); err != nil {
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
		if interruptAfter[0] < 0 && os.Getenv("MULGAE_TEST_COMPOSITE_INTERRUPT_ROOT") == "" {
			command := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
			command.Env = append(os.Environ(), "MULGAE_TEST_COMPOSITE_INTERRUPT_ROOT="+rootPath)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("publication child exit = %v, want interruption: %s", err, output)
			}
		} else {
			if _, err := firstService.PublishCompositeNext(context.Background(), rootScope, candidate); err == nil {
				t.Fatal("interrupted publication succeeded")
			}
		}
		if interruptAfter[0] >= 0 {
			run, err := ports.NewPublicationRun(rootScope, session, runID)
			if err != nil {
				t.Fatal(err)
			}
			candidatePath, err := ports.ValidatedCandidatePath(run)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := os.ReadFile(filepath.Join(rootPath, candidatePath.String()))
			if err != nil {
				t.Fatalf("persisted candidate: %v", err)
			}
			if !bytes.Equal(persisted, bundle.Final().Bytes()) || sha256Identifier(persisted) != bundle.Final().Identity().SHA256() {
				t.Fatal("persisted candidate bytes or digest differ from the built final")
			}
			var persistedEnvelope struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal(persisted, &persistedEnvelope); err != nil {
				t.Fatalf("persisted candidate JSON: %v", err)
			}
			if persistedEnvelope.SchemaVersion != wantFinalSchemaVersion {
				t.Fatalf("persisted candidate schema version = %q, want %q", persistedEnvelope.SchemaVersion, wantFinalSchemaVersion)
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
	if len(interruptAfter) != 0 && interruptAfter[0] < 0 {
		journalPath := filepath.Join(rootPath, session.String(), runID.String(), "publication", "journal.json")
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		changed := input
		changed.CIDecision = domain.CIFail
		mismatched, err := PrepareCompositeCandidate(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.PublishCompositeNext(context.Background(), rootScope, mismatched); err == nil {
			t.Fatal("journaled candidate accepted different composition inputs")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := service.PublishCompositeNext(cancelled, rootScope, candidate); err == nil {
			t.Fatal("cancelled journaled replay succeeded")
		}
		after, err := os.ReadFile(journalPath)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected replay changed the persisted journal")
		}
	}
	if recoverFirst {
		run, err := ports.NewPublicationRun(rootScope, session, runID)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := service.Recover(context.Background(), run)
		if err != nil {
			t.Fatalf("recover interrupted composite: %v", err)
		}
		final, ok := recovered.Final()
		if !ok || final != bundle.Final().Identity() || recovered.Decision().Authority() != domain.PublicationAuthorityP2 {
			t.Fatal("recovery changed the journaled candidate identity or omitted P2")
		}
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
	if !bytes.Contains(rendered.Bytes(), []byte("**Reason codes:** `policy_evaluated`")) {
		t.Fatal("composite report omitted committed CI reason codes")
	}
	for _, absent := range []string{"aggregation.json", "validation/final-validation.json"} {
		if bytes.Contains(rendered.Bytes(), []byte(absent)) {
			t.Fatalf("composite report advertised absent artifact %s", absent)
		}
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

func checkCompositeVersionPairs(t *testing.T, original PublicationBundle) {
	t.Helper()
	for _, pair := range []struct{ final, manifest string }{{"v1", "v1"}, {"v2", "v2"}, {"v1", "v2"}, {"v2", "v1"}} {
		t.Run("versions-"+pair.final+"-"+pair.manifest, func(t *testing.T) {
			bundle := original
			var final, manifest, epoch map[string]any
			for _, item := range []struct {
				raw   []byte
				value *map[string]any
			}{{bundle.final.Bytes(), &final}, {bundle.manifest.Bytes(), &manifest}, {bundle.epoch.Record().Bytes(), &epoch}} {
				if err := json.Unmarshal(item.raw, item.value); err != nil {
					t.Fatal(err)
				}
			}
			final["schema_version"] = "mulgae-composite-review-artifact." + pair.final
			finalBytes, err := marshalCanonical(final)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := ports.NewFinalReviewIdentity(bundle.final.Identity().ReviewID(), bundle.final.Identity().Path(), sha256Identifier(finalBytes))
			if err != nil {
				t.Fatal(err)
			}
			bundle.final, err = ports.NewFinalReviewArtifact(identity, finalBytes)
			if err != nil {
				t.Fatal(err)
			}
			bundle.staged, err = immutableArtifact(bundle.staged.Path(), finalBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest["schema_version"] = "mulgae-composite-run-manifest." + pair.manifest
			manifest["final_review"].(map[string]any)["sha256"] = identity.SHA256()
			manifestBytes, err := marshalCanonical(manifest)
			if err != nil {
				t.Fatal(err)
			}
			bundle.manifest, err = immutableArtifact(bundle.manifest.Path(), manifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			epoch["manifest"].(map[string]any)["sha256"] = bundle.manifest.SHA256()
			epoch["final_review"].(map[string]any)["sha256"] = identity.SHA256()
			epochBytes, err := marshalCanonical(epoch)
			if err != nil {
				t.Fatal(err)
			}
			record, err := immutableArtifact(bundle.epoch.Record().Path(), epochBytes)
			if err != nil {
				t.Fatal(err)
			}
			bundle.epoch, err = ports.NewPublicationEpoch(bundle.epoch.Value(), record)
			if err != nil {
				t.Fatal(err)
			}
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			session, err := domain.ParseSessionID(final["session_id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			runID, err := domain.ParseRunID(final["run_id"].(string))
			if err != nil {
				t.Fatal(err)
			}
			run, err := ports.NewPublicationRun(root, session, runID)
			if err != nil {
				t.Fatal(err)
			}
			matching := pair.final == pair.manifest
			if err := validateCompositeBundleSemantics(bundle); (err == nil) != matching {
				t.Errorf("bundle pair accepted=%t, want %t: %v", err == nil, matching, err)
			}
			if _, err := validateCompositeMaterial(run, bundle.final, bundle.manifest, bundle.lineageEdge, bundle.epoch); (err == nil) != matching {
				t.Errorf("material pair accepted=%t, want %t: %v", err == nil, matching, err)
			}
		})
	}
}
