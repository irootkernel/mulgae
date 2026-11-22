//go:build darwin && arm64

package publication

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	appquery "github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type livePublicationRuntime struct {
	source  ports.LiveSourceReader
	schema  *jsonschema.Validator
	calls   int
	testing *testing.T
}

func (runtime *livePublicationRuntime) Invoke(ctx context.Context, job review.InvocationJob) review.AttemptOutcome {
	runtime.calls++
	findings := "[]"
	if job.Role() == domain.RoleLogic {
		findings = `[{"severity":"high","title":"Observed defect","description":"The original source contains the cited statement.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the statement.","confidence":"high"}]`
	}
	identity, err := evidence.NewLiveSourceIdentity(runtime.source.Target())
	if err != nil {
		runtime.testing.Fatal(err)
	}
	schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, _ := validation.NewReviewValidator(runtime.schema, schemaID)
	raw := []byte(fmt.Sprintf(`{"schema_version":"mulgae-provider-review-output.v1","summary":"A live observation.","completeness":"complete","limitations":[],"findings":%s}`, findings))
	validated, plan, err := validator.Validate(ctx, raw, validation.ReviewValidationScope{LiveSource: identity, Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()})
	if err != nil || plan != nil {
		runtime.testing.Fatalf("validate live fixture: %v", err)
	}
	verifier, err := evidence.NewLiveVerifier(runtime.source)
	if err != nil {
		runtime.testing.Fatal(err)
	}
	groups, err := review.VerifyValidatedEvidence(ctx, verifier, validated.EvidenceClaims())
	if err != nil {
		runtime.testing.Fatal(err)
	}
	output, err := review.NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), groups)
	if err != nil {
		runtime.testing.Fatal(err)
	}
	outcome, err := review.NewAttemptOutcome(job, &output, nil)
	if err != nil {
		runtime.testing.Fatal(err)
	}
	return outcome
}

func livePublicationChangedInput(t *testing.T, source ports.LiveSourceReader, schema *jsonschema.Validator) (LiveCandidateInput, *livePublicationRuntime) {
	t.Helper()
	identity, err := evidence.NewLiveSourceIdentity(source.Target())
	if err != nil {
		t.Fatal(err)
	}
	target, _ := identity.RunTarget()
	var assignments []review.Assignment
	var budgets []review.RoleBudget
	for i, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		route, _ := ports.NewProviderRoute([]string{"zcode-logic", "grok-security"}[i])
		assignment, _ := review.NewScheduledAssignment(role, true, route)
		assignments = append(assignments, assignment)
		limits, _ := review.NewInvocationLimits(time.Second)
		routeBudget, _ := review.NewRouteBudget(route, limits)
		budget, _ := review.NewRoleBudget(role, routeBudget)
		budgets = append(budgets, budget)
	}
	budget, err := review.PreflightRunBudgetWithCapacity(budgets, review.DefaultHarnessCeilings(), 1)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &livePublicationRuntime{source: source, schema: schema, testing: t}
	coordinator, err := review.NewCoordinator(publicationServiceClock{now: publicationTestTime()}, &failedRecoveryIDs{}, runtime, 1, budget)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(context.Background(), target, assignments, domain.SeverityHigh, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := evidence.NewLiveVerifier(source)
	imagePath, _ := ports.NewSafeRelativePath("diagram.png")
	image, err := verifier.VerifyBinary(context.Background(), evidence.SideWorktree, imagePath, sha256Identifier([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0}))
	if err != nil {
		t.Fatal(err)
	}
	return LiveCandidateInput{Result: result, Target: source.Target(), SeverityThreshold: domain.SeverityHigh, BinaryEvidence: []evidence.LiveBinaryReceipt{image}, Provenance: LiveProductionProvenance{BuildProduct: "mulgae", BuildVersion: "0.1.0", BuildCommit: "0123456789abcdef", SourceIdentitySHA256: identity.SHA256(), SourceTerminalReceipt: "source-terminal:v1:" + sha256Identifier([]byte("closed source")), Providers: retainedProviderProvenance()}}, runtime
}

func TestLiveCandidateAdmissionRejectsSourceAndNoChangeMixing(t *testing.T) {
	rootPath := t.TempDir()
	for path, data := range map[string][]byte{"source.go": []byte("observed\n"), "diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0}} {
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	schema := mustSharedPublicationTestValidator(t)
	input, _ := livePublicationChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(input)
	if err != nil || !candidate.Valid() {
		t.Fatalf("valid changed input: %v", err)
	}
	empty := livePublicationEmptyTarget(t)
	bad := input
	bad.Target, bad.BinaryEvidence = empty, nil
	bad.Provenance.Providers = nil
	if _, err := PrepareLiveCandidate(bad); err == nil {
		t.Fatal("changed preparation accepted an empty selection")
	}
	headSelector, _ := ports.NewLiveSourceSelector(domain.LiveSourceHead, "")
	headOID, _ := ports.ParseGitObjectID(strings.Repeat("a", 40))
	other, err := ports.NewLiveSourceTarget(headSelector, ports.GitObjectID{}, headOID, false, input.Target.Changes())
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(other)
	bad = input
	bad.Target, bad.BinaryEvidence = other, nil
	bad.Provenance.SourceIdentitySHA256 = identity.SHA256()
	if _, err := prepareLiveSource(bad.Target, bad.Provenance, bad.BinaryEvidence); err != nil {
		t.Fatalf("independently valid alternate source: %v", err)
	}
	if _, err := PrepareLiveCandidate(bad); err == nil {
		t.Fatal("published a coordinator result under another source identity")
	}
	for name, target := range map[string]ports.LiveSourceTarget{"changed selection": input.Target, "providers on empty selection": empty} {
		t.Run(name, func(t *testing.T) {
			provenance := input.Provenance
			if !target.NoChange() {
				provenance.Providers = nil
			}
			if _, err := PrepareLiveNoChangeCandidate(candidate.SessionID(), candidate.RunID(), target, []domain.Role{domain.RoleLogic, domain.RoleSecurity}, domain.SeverityHigh, provenance); err == nil {
				t.Fatal("no-change preparation accepted selected changes or providers")
			}
		})
	}
	candidate.candidate.findings[0].evidence[0].visual = &preparedVisualEvidence{path: "diagram.png", sha256: input.BinaryEvidence[0].FileSHA256(), width: 1, height: 1}
	if _, err := candidate.Build(context.Background(), schema, publicationTestReviewID(t), publicationTestTime(), 1); err != nil {
		t.Fatalf("visual bound to selected raster: %v", err)
	}
	candidate.candidate.target.live.binary = nil
	if _, err := candidate.Build(context.Background(), schema, publicationTestReviewID(t), publicationTestTime(), 1); err == nil {
		t.Fatal("published visual evidence without retained selected raster")
	}
}

func TestIntegrationLivePublicationRetainsEvidenceAndRecoversExactP1(t *testing.T) {
	ctx := context.Background()
	fixtureRoot := os.Getenv("MULGAE_TEST_LIVE_PUBLICATION_ROOT")
	child := fixtureRoot != ""
	if !child {
		fixtureRoot = t.TempDir()
		if err := os.Mkdir(filepath.Join(fixtureRoot, "source"), 0700); err != nil {
			t.Fatal(err)
		}
		for path, data := range map[string][]byte{"source.go": []byte("observed\n"), "diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0}, "unused.txt": []byte("not retained\n")} {
			if err := os.WriteFile(filepath.Join(fixtureRoot, "source", path), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	sourceRoot, _ := ports.NewAnchoredRoot(filepath.Join(fixtureRoot, "source"))
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	source, err := opener.OpenLiveSource(ctx, sourceRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	schema := mustSharedPublicationTestValidator(t)
	input, runtime := livePublicationChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Build(ctx, schema, publicationTestReviewID(t), publicationTestTime(), 1); err != nil {
		t.Fatalf("build live bundle: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(fixtureRoot, "artifacts")
	if err := os.MkdirAll(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	clock := publicationServiceClock{now: publicationTestTime()}
	reviewID := publicationTestReviewID(t)
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	if child {
		interrupted, _ := NewService(&compositeInterruptedStore{PublicationStore: store, after: -2}, schema, clock, 8<<20)
		_, err := interrupted.PublishLiveNext(ctx, root, candidate)
		t.Fatalf("expected process interruption after final installation: %v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIntegrationLivePublicationRetainsEvidenceAndRecoversExactP1$")
	command.Env = append(os.Environ(), "MULGAE_TEST_LIVE_PUBLICATION_ROOT="+fixtureRoot)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("interrupted publisher: %v\n%s", err, output)
	}
	// Both the provider and original source are unavailable during recovery/read.
	if err := os.RemoveAll(sourceRoot.String()); err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(store, schema, clock, 8<<20)
	run, _ := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	result, err := service.Recover(ctx, run)
	if err != nil {
		t.Fatalf("recover live P1: %v", err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatal("live recovery omitted P2")
	}
	bundle, err := candidate.Build(ctx, schema, reviewID, clock.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	final, ok := result.Final()
	if !ok || final != bundle.Final().Identity() {
		t.Fatal("recovery changed final identity")
	}
	queries, _ := appquery.NewService(store, schema, nil, 8<<20)
	committed, err := queries.ReadCommitted(ctx, run)
	if err != nil {
		t.Fatalf("read live P2: %v", err)
	}
	if committed.TargetSHA256() != "" || committed.SourceIdentitySHA256() != candidate.candidate.target.live.identity.SHA256() || !bytes.Equal(committed.FinalBytes(), bundle.Final().Bytes()) || !bytes.Equal(committed.ManifestBytes(), bundle.Manifest().Bytes()) {
		t.Fatal("live read changed immutable identity")
	}
	binding, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("d", 64))
	if len(committed.RoleReports()) != 2 {
		t.Fatal("live publication lost retained role reports")
	}
	for _, report := range committed.RoleReports() {
		chunk, err := queries.ReadReport(ctx, run, binding, report.Role(), appquery.ContentContinuation{}, nil)
		want := "# " + report.Role() + " review\n\nStructured provider review accepted.\n"
		if err != nil || chunk.Content != want || chunk.MediaType != "text/markdown" || chunk.Role != report.Role() {
			t.Fatalf("offline live role report: %+v %v", chunk, err)
		}
	}
	inspection, err := queries.Inspect(ctx, run, binding, appquery.InspectionRequest{QueryKind: "inspect", Limit: 1})
	if err != nil {
		t.Fatalf("inspect live: %v", err)
	}
	if inspection.CaptureAvailability != "not_captured" || inspection.Receipt.SchemaVersion != appquery.LiveInspectionReceiptVersion || inspection.TargetSHA256 != "" || inspection.SourceIdentitySHA256 != committed.SourceIdentitySHA256() || inspection.FindingCount != 1 {
		t.Fatal("inspection made captured claims")
	}
	chunk, err := queries.ReadSourceEvidence(ctx, run, binding, "F001", committed.SourceIdentitySHA256(), 0, appquery.ContentContinuation{})
	if err != nil || chunk.Content != "observed\n" {
		t.Fatalf("stored text: %+v %v", chunk, err)
	}
	image, err := queries.ReadSourceImage(ctx, run, binding, committed.SourceIdentitySHA256(), "worktree", "diagram.png", appquery.ContentContinuation{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(image.Content)
	if image.Encoding != "base64" || image.MediaType != "image/png" || !bytes.Equal(body, []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}) {
		t.Fatal("binary observation decoded as text or changed")
	}
	if _, err := queries.ReadRuntimeTarget(ctx, run); !errors.Is(err, appquery.ErrSourceReplayUnavailable) {
		t.Fatalf("source replay: %v", err)
	}
	if _, err := queries.ReadCommittedAttempt(ctx, run, candidate.candidate.roles[0].attempts[0].id); !errors.Is(err, appquery.ErrSourceReplayUnavailable) {
		t.Fatalf("source attempt replay: %v", err)
	}
	artifact, err := queries.ReadSourceImageArtifact(ctx, run, committed.FinalSHA256(), committed.SourceIdentitySHA256(), "worktree", "diagram.png")
	if err != nil || !bytes.Equal(artifact.Bytes(), body) {
		t.Fatalf("offline source image artifact: %v", err)
	}
	wrongDigest := "sha256:" + strings.Repeat("e", 64)
	for name, digests := range map[string][2]string{
		"final":  {wrongDigest, committed.SourceIdentitySHA256()},
		"source": {committed.FinalSHA256(), wrongDigest},
	} {
		t.Run("image identity/"+name, func(t *testing.T) {
			if _, err := queries.ReadSourceImageArtifact(ctx, run, digests[0], digests[1], "worktree", "diagram.png"); !errors.Is(err, appquery.ErrPublicationReceiptMismatch) {
				t.Fatalf("rebound image identity: %v", err)
			}
		})
	}
	if _, err := queries.ReadEvidence(ctx, run, binding, "F001", committed.SourceIdentitySHA256(), 0, appquery.ContentContinuation{}); !errors.Is(err, appquery.ErrCursorMismatch) {
		t.Fatalf("captured reader accepted live evidence: %v", err)
	}
	if _, err := queries.ReadSourceEvidence(ctx, run, binding, "F001", wrongDigest, 0, appquery.ContentContinuation{}); !errors.Is(err, appquery.ErrCursorMismatch) {
		t.Fatalf("rebound source evidence: %v", err)
	}
	for name, selection := range map[string][2]string{"side": {"index", "diagram.png"}, "path": {"worktree", "missing.png"}} {
		t.Run("unavailable image/"+name, func(t *testing.T) {
			_, err := queries.ReadSourceImage(ctx, run, binding, committed.SourceIdentitySHA256(), selection[0], selection[1], appquery.ContentContinuation{})
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
				t.Fatalf("unavailable image lost typed failure: %v", err)
			}
			_, err = queries.ReadSourceImageArtifact(ctx, run, committed.FinalSHA256(), committed.SourceIdentitySHA256(), selection[0], selection[1])
			if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
				t.Fatalf("unavailable image artifact lost typed failure: %v", err)
			}
		})
	}
	if runtime.calls != 2 {
		t.Fatal("recovery/read invoked a provider")
	}
	if _, err := service.PublishLiveNext(ctx, root, candidate); err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("repeat cause: %T %v", cause, cause)
		}
		t.Fatalf("exact candidate repetition: %v", err)
	}
	if _, err := service.Recover(ctx, run); err != nil {
		t.Fatalf("completed recovery: %v", err)
	}
	for _, artifact := range bundle.SupportArtifacts() {
		kind, _ := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), artifact.Path())
		if kind == ports.RunSupportArtifactCapturedBlob || kind == ports.RunSupportArtifactCapturedArchive || bytes.Contains(artifact.Bytes(), []byte("not retained")) {
			t.Fatal("publication archived unselected source")
		}
		if kind != ports.RunSupportArtifactLiveSource && kind != ports.RunSupportArtifactSourceImage && kind != ports.RunSupportArtifactExcerpt && kind != ports.RunSupportArtifactRoleReport {
			continue
		}
		t.Run("damaged-"+artifact.Path().String(), func(t *testing.T) {
			path := filepath.Join(root.String(), filepath.FromSlash(artifact.Path().String()))
			if err := os.WriteFile(path, []byte("damaged retained evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := queries.ReadCommitted(ctx, run); err == nil {
				t.Fatal("read accepted damaged retained support")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := queries.ReadCommitted(ctx, run); err == nil {
				t.Fatal("read accepted missing retained support")
			}
			if err := os.WriteFile(path, artifact.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := queries.ReadCommitted(ctx, run); err != nil {
				t.Fatalf("restored support is unreadable: %v", err)
			}
		})
	}
}

func TestIntegrationLiveCleanupRetainsCorruptIndexedSupport(t *testing.T) {
	for _, test := range []struct {
		name   string
		kind   ports.RunSupportArtifactKind
		remove bool
	}{
		{name: "healthy"},
		{name: "modified excerpt", kind: ports.RunSupportArtifactExcerpt},
		{name: "missing excerpt", kind: ports.RunSupportArtifactExcerpt, remove: true},
		{name: "modified index", kind: ports.RunSupportArtifactSupportIndex},
		{name: "missing index", kind: ports.RunSupportArtifactSupportIndex, remove: true},
		{name: "modified image", kind: ports.RunSupportArtifactSourceImage},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sourcePath := t.TempDir()
			for name, data := range map[string][]byte{"source.go": []byte("observed\n"), "diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0}} {
				if err := os.WriteFile(filepath.Join(sourcePath, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			sourceRoot, _ := ports.NewAnchoredRoot(sourcePath)
			opener, _ := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			source, err := opener.OpenLiveSource(ctx, sourceRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			schema := mustSharedPublicationTestValidator(t)
			input, _ := livePublicationChangedInput(t, source, schema)
			candidate, err := PrepareLiveCandidate(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(t.TempDir())
			clock := publicationServiceClock{now: publicationTestTime()}
			store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{publicationTestReviewID(t)}, filesystem.NewSecureWriter())
			if err != nil {
				t.Fatal(err)
			}
			publisher, _ := NewService(store, schema, clock, 8<<20)
			published, err := publisher.PublishLiveNext(ctx, root, candidate)
			if err != nil {
				t.Fatal(err)
			}
			cleanupClock := publicationServiceClock{now: clock.now.Add(24 * time.Hour)}
			cleanup, _ := filesystem.NewCleanupStore(root, store, cleanupClock)
			cleaner, _ := clean.NewService(cleanupClock, schema, cleanup)
			before, err := cleaner.Run(ctx, clean.Request{All: true, DryRun: true})
			if err != nil || before.AffectedRunCount != 1 {
				t.Fatalf("healthy cleanup eligibility = %d: %v", before.AffectedRunCount, err)
			}
			corrupt := test.kind != ""
			if corrupt {
				found := false
				for _, artifact := range published.PersistedRunSupportArtifacts() {
					kind, _ := ports.ClassifyRunSupportArtifactPath(candidate.SessionID(), candidate.RunID(), artifact.Path())
					if kind != test.kind {
						continue
					}
					path := filepath.Join(root.String(), artifact.Path().String())
					if test.remove {
						err = os.Remove(path)
					} else {
						err = os.WriteFile(path, []byte("ADVERSARIAL TAMPER\n"), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					found = true
					break
				}
				if !found {
					t.Fatalf("published support kind %s absent", test.kind)
				}
			}
			snapshot, err := cleanup.Observe(ctx)
			if err != nil || len(snapshot.Runs) != 1 || snapshot.Runs[0].Corrupt != corrupt {
				t.Fatalf("cleanup observation = %#v: %v", snapshot.Runs, err)
			}
			result, err := cleaner.Run(ctx, clean.Request{All: true})
			if err != nil || (result.AffectedRunCount == 0) != corrupt {
				t.Fatalf("destructive cleanup = %d: %v", result.AffectedRunCount, err)
			}
			_, err = os.Stat(filepath.Join(root.String(), candidate.SessionID().String(), candidate.RunID().String()))
			if corrupt && err != nil || !corrupt && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("run retention after cleanup: %v", err)
			}
		})
	}
}

func TestIntegrationLiveNoChangePublishesP2WithoutProviderOrCaptureWork(t *testing.T) {
	ctx := context.Background()
	schema := mustSharedPublicationTestValidator(t)
	candidate := livePublicationNoChange(t)
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{publicationTestReviewID(t)}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(store, schema, clock, 8<<20)
	result, err := service.PublishLiveNext(ctx, root, candidate)
	if err != nil || result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("publish live no-change: %v", err)
	}
	run, _ := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	queries, _ := appquery.NewService(store, schema, nil, 8<<20)
	committed, err := queries.ReadCommitted(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	live, ok := committed.LiveSource()
	if !ok || !live.NoChange || len(committed.Findings()) != 0 || len(committed.RoleReports()) != 0 || len(committed.Attempts()) != 0 || committed.CoverageStatus() != domain.CoverageComplete {
		t.Fatal("no-change result requires provider work or loses complete coverage")
	}
	attempt, _ := domain.ParseAttemptID("a_018f0d1a-0000-7000-8000-000000000003")
	if _, err := queries.ReadCommittedAttempt(ctx, run, attempt); !errors.Is(err, appquery.ErrSourceReplayUnavailable) {
		t.Fatalf("no-change attempt replay: %v", err)
	}
	if _, err := service.Recover(ctx, run); err != nil {
		t.Fatalf("recover live no-change: %v", err)
	}
	if _, err := service.PublishLiveNext(ctx, root, candidate); err != nil {
		t.Fatalf("repeat live no-change: %v", err)
	}
}

type liveTimeoutPublicationRuntime struct {
	source   ports.LiveSourceReader
	schema   *jsonschema.Validator
	scenario string
	t        *testing.T
}

func (runtime *liveTimeoutPublicationRuntime) Invoke(ctx context.Context, job review.InvocationJob) review.AttemptOutcome {
	fail := func(format string, args ...any) review.AttemptOutcome {
		runtime.t.Errorf(format, args...)
		cond := review.AttemptConditionInternalInvariant
		outcome, _ := review.NewAttemptOutcome(job, nil, &cond)
		return outcome
	}
	if (runtime.scenario == "required-role-provider-timeout" && job.Role() == domain.RoleLogic) ||
		(runtime.scenario == "non-required-role-provider-timeout" && job.Role() == domain.RoleSecurity) {
		outcome, err := review.NewProviderTimeoutAttemptOutcome(job, 10*time.Millisecond)
		if err != nil {
			return fail("provider timeout outcome: %v", err)
		}
		return outcome
	}
	if runtime.scenario == "run-deadline-during-extraction" && job.Role() == domain.RoleSecurity {
		if job.Purpose() == domain.InvocationInitial {
			output, err := review.NewReportsOnlyValidatedRoleOutput(
				job.Role(), job.Route().ProviderInstance(), job.Target(),
				[]byte("# Security prose report\n\nAccepted before extraction deadline.\n"),
			)
			if err != nil {
				return fail("reports-only output: %v", err)
			}
			outcome, err := review.NewAttemptOutcome(job, &output, nil)
			if err != nil {
				return fail("reports-only outcome: %v", err)
			}
			return outcome
		}
		// Block until the real coordinator run deadline expires.
		<-ctx.Done()
		cond := review.AttemptConditionTimeout
		outcome, err := review.NewAttemptOutcome(job, nil, &cond)
		if err != nil {
			return fail("timeout outcome: %v", err)
		}
		return outcome
	}

	findings := "[]"
	if job.Role() == domain.RoleLogic {
		findings = `[{"severity":"high","title":"Observed defect","description":"The original source contains the cited statement.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"recommendation":"Correct the statement.","confidence":"high"}]`
	}
	identity, err := evidence.NewLiveSourceIdentity(runtime.source.Target())
	if err != nil {
		return fail("live identity: %v", err)
	}
	schemaID, _ := ports.ParseAssetID(validation.ProviderReviewSchemaID)
	validator, _ := validation.NewReviewValidator(runtime.schema, schemaID)
	raw := []byte(fmt.Sprintf(`{"schema_version":"mulgae-provider-review-output.v1","summary":"A live observation.","completeness":"complete","limitations":[],"findings":%s}`, findings))
	validated, plan, err := validator.Validate(ctx, raw, validation.ReviewValidationScope{LiveSource: identity, Role: job.Role(), ProviderInstance: job.Route().ProviderInstance()})
	if err != nil || plan != nil {
		return fail("validate live timeout fixture: %v", err)
	}
	verifier, err := evidence.NewLiveVerifier(runtime.source)
	if err != nil {
		return fail("live verifier: %v", err)
	}
	groups, err := review.VerifyValidatedEvidence(ctx, verifier, validated.EvidenceClaims())
	if err != nil {
		return fail("verify evidence: %v", err)
	}
	output, err := review.NewEvidenceValidatedRoleOutput(job.Role(), job.Route().ProviderInstance(), job.Target(), validated.Findings(), validated.Completeness(), validated.Limitations(), groups)
	if err != nil {
		return fail("role output: %v", err)
	}
	outcome, err := review.NewAttemptOutcome(job, &output, nil)
	if err != nil {
		return fail("attempt outcome: %v", err)
	}
	return outcome
}

func TestIntegrationLivePublicationTimeoutScenarios(t *testing.T) {
	schema := mustSharedPublicationTestValidator(t)
	rawReq := []byte(`{"schema_version":"mulgae-requirements-input.v1","requirements":[{"id":"R1","text":"Logic obligation","acceptance_criteria":["checked"],"owner_role":"logic"},{"id":"R2","text":"Security obligation","acceptance_criteria":["checked"],"owner_role":"security"}]}`)
	roles := []domain.Role{domain.RoleLogic, domain.RoleSecurity}
	reqInput, err := validation.DecodeRequirementsInput(rawReq, roles)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name               string
		wantRunState       domain.RunState
		wantCoverage       domain.CoverageStatus
		wantTimedOutRole   domain.Role
		wantRetainedReport domain.Role
		wantReportCount    int
		wantOmittedReqID   string
		wantEvaluatedCount int
	}{
		{
			name:               "required-role-provider-timeout",
			wantRunState:       domain.RunFailed,
			wantCoverage:       domain.CoverageIncomplete,
			wantTimedOutRole:   domain.RoleLogic,
			wantRetainedReport: domain.RoleSecurity,
			wantReportCount:    1,
			wantOmittedReqID:   "R1",
			wantEvaluatedCount: 1,
		},
		{
			name:               "non-required-role-provider-timeout",
			wantRunState:       domain.RunFailed,
			wantCoverage:       domain.CoverageIncomplete,
			wantTimedOutRole:   domain.RoleSecurity,
			wantRetainedReport: domain.RoleLogic,
			wantReportCount:    1,
			wantOmittedReqID:   "R2",
			wantEvaluatedCount: 1,
		},
		{
			name:               "run-deadline-during-extraction",
			wantRunState:       domain.RunCompleted,
			wantCoverage:       domain.CoverageComplete,
			wantRetainedReport: domain.RoleSecurity,
			wantReportCount:    2,
			wantEvaluatedCount: 1,
			wantOmittedReqID:   "R2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			sourcePath := t.TempDir()
			if err := os.WriteFile(filepath.Join(sourcePath, "source.go"), []byte("observed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			sourceRoot, _ := ports.NewAnchoredRoot(sourcePath)
			opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			source, err := opener.OpenLiveSource(ctx, sourceRoot, selector)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()

			identity, err := evidence.NewLiveSourceIdentity(source.Target())
			if err != nil {
				t.Fatal(err)
			}
			target, err := identity.RunTarget()
			if err != nil {
				t.Fatal(err)
			}

			var assignments []review.Assignment
			var budgets []review.RoleBudget
			limits, err := review.NewInvocationLimits(10 * time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			for i, role := range roles {
				route, _ := ports.NewProviderRoute([]string{"zcode-logic", "grok-security"}[i])
				required := role == domain.RoleLogic
				assignment, err := review.NewScheduledAssignment(role, required, route)
				if err != nil {
					t.Fatal(err)
				}
				assignments = append(assignments, assignment)
				routeBudget, _ := review.NewRouteBudget(route, limits)
				budget, _ := review.NewRoleBudget(role, routeBudget)
				budgets = append(budgets, budget)
			}
			receipt, err := review.PreflightRunBudgetWithCapacity(budgets, review.DefaultHarnessCeilings(), len(roles))
			if err != nil {
				t.Fatal(err)
			}
			rt := &liveTimeoutPublicationRuntime{source: source, schema: schema, scenario: tc.name, t: t}
			coordinator, err := review.NewCoordinator(publicationServiceClock{now: publicationTestTime()}, &failedRecoveryIDs{}, rt, len(roles), receipt)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "run-deadline-during-extraction" {
				if err := coordinator.AdmitStructuredExtraction(); err != nil {
					t.Fatal(err)
				}
			}
			result, err := coordinator.Execute(ctx, target, assignments, domain.SeverityHigh, nil)
			if err != nil {
				t.Fatalf("coordinator execute (%s): %v", tc.name, err)
			}
			if result.RunState() != tc.wantRunState {
				t.Fatalf("run state = %q, want %q", result.RunState(), tc.wantRunState)
			}

			// Decode one verified answer for the succeeding structured role; omit the timed-out or prose-only role.
			verifier, err := evidence.NewLiveVerifier(source)
			if err != nil {
				t.Fatal(err)
			}
			var answers []validation.ValidatedRequirementAnswer
			switch tc.name {
			case "required-role-provider-timeout":
				secSection := []byte(`{"schema_version":"mulgae-provider-requirements.v1","assessments":[{"requirement_id":"R2","verdict":"met","rationale":"Verified on source.go.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"examined_scope":"source.go","limitations":[],"reason":""}]}`)
				decoded, decErr := validation.DecodeProviderRequirements(ctx, secSection, reqInput.Requirements(), domain.RoleSecurity, identity, verifier, nil, "requirements.json", reqInput.SHA256())
				if decErr != nil {
					t.Fatal(decErr)
				}
				answers = decoded.Answers
			default:
				logicSection := []byte(`{"schema_version":"mulgae-provider-requirements.v1","assessments":[{"requirement_id":"R1","verdict":"met","rationale":"Verified on source.go.","evidence":[{"current":{"path":"source.go","side":"worktree","line_start":1,"line_end":1,"quote":"observed\n"}}],"examined_scope":"source.go","limitations":[],"reason":""}]}`)
				decoded, decErr := validation.DecodeProviderRequirements(ctx, logicSection, reqInput.Requirements(), domain.RoleLogic, identity, verifier, nil, "requirements.json", reqInput.SHA256())
				if decErr != nil {
					t.Fatal(decErr)
				}
				answers = decoded.Answers
			}
			reqResults, err := validation.NormalizeRequirements(reqInput, answers, nil, identity.SHA256(), false)
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}

			candidate, err := PrepareLiveCandidate(LiveCandidateInput{
				Result:            result,
				Target:            source.Target(),
				SeverityThreshold: domain.SeverityHigh,
				Provenance: LiveProductionProvenance{
					BuildProduct:          "mulgae",
					BuildVersion:          "0.1.0",
					BuildCommit:           "0123456789abcdef",
					SourceIdentitySHA256:  identity.SHA256(),
					SourceTerminalReceipt: "source-terminal:v1:" + sha256Identifier([]byte("closed source")),
					Providers:             retainedProviderProvenance(),
				},
			})
			if err != nil {
				t.Fatalf("PrepareLiveCandidate (%s): %v", tc.name, err)
			}
			candidate, err = WithRequirements(candidate, reqResults)
			if err != nil {
				t.Fatalf("WithRequirements (%s): %v", tc.name, err)
			}

			artifactRoot, _ := ports.NewAnchoredRoot(t.TempDir())
			clock := publicationServiceClock{now: publicationTestTime()}
			store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{publicationTestReviewID(t)}, filesystem.NewSecureWriter())
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(store, schema, clock, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			published, err := service.PublishLiveNext(ctx, artifactRoot, candidate)
			if err != nil {
				t.Fatalf("PublishLiveNext (%s): %v", tc.name, err)
			}
			if published.Decision().Authority() != domain.PublicationAuthorityP2 {
				t.Fatalf("authority = %q, want P2", published.Decision().Authority())
			}

			runRef, _ := ports.NewPublicationRun(artifactRoot, candidate.SessionID(), candidate.RunID())
			queries, _ := appquery.NewService(store, schema, nil, 8<<20)
			committed, err := queries.ReadCommitted(ctx, runRef)
			if err != nil {
				t.Fatalf("ReadCommitted (%s): %v", tc.name, err)
			}
			if committed.CoverageStatus() != tc.wantCoverage {
				t.Fatalf("coverage = %q, want %q", committed.CoverageStatus(), tc.wantCoverage)
			}
			if len(committed.RoleReports()) != tc.wantReportCount {
				t.Fatalf("role reports = %d, want %d", len(committed.RoleReports()), tc.wantReportCount)
			}
			binding, _ := domain.ParseProjectBinding("sha256:" + strings.Repeat("d", 64))
			reportChunk, err := queries.ReadReport(ctx, runRef, binding, string(tc.wantRetainedReport), appquery.ContentContinuation{}, nil)
			if err != nil || len(reportChunk.Content) == 0 {
				t.Fatalf("ReadReport(%s): %+v %v", tc.wantRetainedReport, reportChunk, err)
			}
			if tc.name == "run-deadline-during-extraction" && !strings.Contains(reportChunk.Content, "Accepted before extraction deadline.") {
				t.Fatalf("security report lost accepted prose body: %q", reportChunk.Content)
			}
			if tc.wantTimedOutRole != "" {
				foundTimedOut := false
				for _, att := range committed.Attempts() {
					if att.Role() == tc.wantTimedOutRole {
						foundTimedOut = true
						if att.State() != domain.AttemptTimedOut {
							t.Fatalf("timed-out role %q committed attempt state = %q, want timed_out", tc.wantTimedOutRole, att.State())
						}
					}
				}
				if !foundTimedOut {
					t.Fatalf("missing timed-out attempt for role %q", tc.wantTimedOutRole)
				}
				for _, summary := range result.RoleSummaries() {
					if summary.Role() == tc.wantTimedOutRole {
						if summary.FailureClass() != domain.FailureTimeout || summary.Attempts()[0].State() != domain.AttemptTimedOut || summary.Attempts()[0].FailureClass() != domain.FailureTimeout {
							t.Fatalf("timed-out role %q coordinator summary = %+v, want timed_out/timeout", tc.wantTimedOutRole, summary)
						}
					}
				}
			}
			inspection, err := queries.Inspect(ctx, runRef, binding, appquery.InspectionRequest{QueryKind: "inspect", RequirementsLimit: 10})
			if err != nil {
				t.Fatalf("Inspect (%s): %v", tc.name, err)
			}
			if inspection.Requirements == nil || *inspection.Requirements.EvaluatedCount != tc.wantEvaluatedCount {
				t.Fatalf("requirements inspection = %+v, want evaluated=%d", inspection.Requirements, tc.wantEvaluatedCount)
			}
			foundOmitted := false
			for _, item := range inspection.Requirements.Items {
				if item.RequirementID == tc.wantOmittedReqID {
					foundOmitted = true
					if item.Origin != domain.AssessmentDerived || item.Reason != domain.AssessmentAnswerOmitted {
						t.Fatalf("requirement %s = origin:%q reason:%q, want derived/answer_omitted", item.RequirementID, item.Origin, item.Reason)
					}
				}
			}
			if !foundOmitted {
				t.Fatalf("missing requirement %s in inspection", tc.wantOmittedReqID)
			}
		})
	}
}
