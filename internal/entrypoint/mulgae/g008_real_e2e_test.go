package mulgae

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app"
	appdelta "github.com/irootkernel/mulgae/internal/app/delta"
	appexport "github.com/irootkernel/mulgae/internal/app/export"
	appfollowup "github.com/irootkernel/mulgae/internal/app/followup"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestIntegrationG008RealCompositionApplicationChildWorkflows(t *testing.T) {
	fixture := newG008RealE2EFixture(t)
	root := fixture.executeAndPublishRoot(t)
	before := fixture.inventorySnapshot(t)
	rootRun, err := fixture.queries.ResolveRun(context.Background(), fixture.root, root.RunID)
	if err != nil {
		t.Fatal(err)
	}
	rootCommitted, err := fixture.queries.ReadCommitted(context.Background(), rootRun)
	if err != nil {
		t.Fatal(err)
	}
	rootTarget, err := fixture.queries.ReadRuntimeTarget(context.Background(), rootRun)
	if err != nil {
		t.Fatal(err)
	}
	rootAttempt, err := fixture.queries.ReadCommittedAttempt(context.Background(), rootRun, root.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	rootFinding, err := fixture.queries.ReadCommittedFindingSource(context.Background(), rootRun, "F001")
	if err != nil {
		t.Fatal(err)
	}
	rootLineage := rootCommitted.Lineage()
	if _, present := rootLineage.ParentRunID(); present {
		t.Fatalf("root lineage has a parent: %#v", rootLineage)
	}
	if _, present := rootLineage.SourceRunID(); present {
		t.Fatalf("root lineage has a source run: %#v", rootLineage)
	}
	if _, present := rootLineage.SourceReviewID(); present {
		t.Fatalf("root lineage has a source review: %#v", rootLineage)
	}
	if _, present := rootLineage.SourceFindingRef(); present {
		t.Fatalf("root lineage has a source finding: %#v", rootLineage)
	}
	if _, present := rootLineage.ReplayMode(); present {
		t.Fatalf("root lineage has a replay mode: %#v", rootLineage)
	}
	if strings.TrimPrefix(rootCommitted.FinalSHA256(), "sha256:") != g008RealTargetHash(rootCommitted.FinalBytes()) ||
		strings.TrimPrefix(rootCommitted.ManifestSHA256(), "sha256:") != g008RealTargetHash(rootCommitted.ManifestBytes()) ||
		rootTarget.Identity().SHA256() != g008RealTargetHash(rootTarget.Bytes()) {
		t.Fatal("root committed source byte hashes do not bind the queried artifacts")
	}
	deltaSource, err := root.Sources.ReadSource(context.Background(), root.RunID)
	if err != nil {
		t.Fatal(err)
	}
	followupSource, err := root.Sources.ReadFollowupSource(context.Background(), root.RunID, "F001")
	if err != nil {
		t.Fatal(err)
	}
	rerunSource, err := root.Sources.ReadRerunSource(context.Background(), root.RunID, root.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if deltaSource.SessionID != root.SessionID || deltaSource.RunID != root.RunID || deltaSource.ReviewID != root.ReviewID ||
		deltaSource.Target.Identity() != rootTarget.Identity() || string(deltaSource.Target.Bytes()) != string(rootTarget.Bytes()) ||
		deltaSource.FinalSHA256 != strings.TrimPrefix(rootCommitted.FinalSHA256(), "sha256:") ||
		deltaSource.ManifestSHA256 != strings.TrimPrefix(rootCommitted.ManifestSHA256(), "sha256:") ||
		!followupSource.P2Verified || followupSource.SessionID != root.SessionID || followupSource.RunID != root.RunID ||
		followupSource.ReviewID != root.ReviewID || followupSource.Finding.ID != "F001" ||
		followupSource.Target != rootTarget.Identity() || rerunSource.RunID != root.RunID ||
		rerunSource.ReviewID != root.ReviewID || rerunSource.AttemptID != root.AttemptID ||
		rerunSource.Target.Identity != rootTarget.Identity() || string(rerunSource.Target.Bytes) != string(rootTarget.Bytes()) ||
		rerunSource.Prompt.CompleteStdinSHA256 != rootAttempt.Prompt().CompleteStdinSHA256() {
		t.Fatal("root P2 source projections do not retain exact lineage, target, and replay authority")
	}
	resolver, err := NewG008RequestResolver(fixture.root, fixture.queries, filesystem.NewRunSelector(fixture.root), bytes.NewBufferString("current.patch"))
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := NewG008Dependencies(G008Composition{
		Root: fixture.root, Queries: fixture.queries, RequestResolver: resolver, Clock: fixture.clock, IDs: fixture.ids, PublicationAuthority: fixture.store,
		ExportInstaller: mustG008RealExportInstaller(t, fixture),
		Online: &G008OnlineAuthority{
			FollowupTargetCapturer: g008RealFollowupCapturer{}, DeltaTargetCapturer: g008RealDeltaCapturer{target: fixture.deltaTarget}, DeltaComparator: g008RealComparator{},
			ChildExecutor: fixture.childExecutor, FollowupExecutor: fixture.followupExecutor, RerunAssignments: fixture.assignments[:1],
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewApplication(Dependencies{
		Clock: fixture.clock, RequestIDGenerator: fixture.ids, RequestResolver: dependencies.RequestResolver, Catalog: builtin.NewCatalog(), JSONSchemaValidator: fixture.validator,
		SecureWriter: fixture.writer, TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(),
		FollowupRuns: dependencies.FollowupRuns, DeltaRuns: dependencies.DeltaRuns, Reruns: dependencies.Reruns, Exports: dependencies.Exports,
	})
	if err != nil {
		t.Fatal(err)
	}
	childWorkflows := make(map[string]string, 4)
	recomposeChildren := make(map[string]struct{})
	for _, test := range []struct {
		name string
		argv []string
		exit app.ExitCode
	}{
		{name: "followup", argv: []string{"followup", "--run", root.RunID.String(), "--finding", "F001", "--patch", "current.patch"}, exit: app.ExitCodePolicy},
		{name: "delta", argv: []string{"delta", "--since-run", root.RunID.String(), "--dirty", "--roles", "logic,security"}, exit: app.ExitCodePolicy},
		{name: "exact rerun", argv: []string{"rerun", "--run", root.RunID.String(), "--attempt", root.AttemptID.String(), "--replay", "exact"}, exit: app.ExitCodePolicy},
		{name: "recomposed rerun", argv: []string{"rerun", "--run", root.RunID.String(), "--attempt", root.AttemptID.String(), "--replay", "recompose"}, exit: app.ExitCodePolicy},
	} {
		fixture.provider.mu.Lock()
		fixture.provider.securityLowFinding = test.name == "delta"
		fixture.provider.mu.Unlock()
		result := application.Run(context.Background(), test.argv, fixture.root.String())
		if result.ExitCode() != test.exit {
			t.Fatalf("%v exit=%d, want %d; stdout=%q stderr=%q", test.argv, result.ExitCode(), test.exit, result.Stdout(), result.Stderr())
		}
		firstLine := strings.SplitN(strings.TrimSpace(string(result.Stdout())), "\n", 2)[0]
		separator := strings.LastIndex(firstLine, " ")
		if separator < 0 {
			t.Fatalf("%v omitted child run ID: %q", test.argv, firstLine)
		}
		runID := firstLine[separator+1:]
		if _, err := domain.ParseRunID(runID); err != nil {
			t.Fatalf("%v returned invalid child run ID %q: %v", test.argv, runID, err)
		}
		if runID == root.RunID.String() {
			t.Fatalf("%v reused root run ID %q", test.argv, runID)
		}
		childWorkflows[runID] = test.name
		if test.name == "recomposed rerun" {
			recomposeChildren[runID] = struct{}{}
		}
	}
	if len(childWorkflows) != 4 {
		t.Fatalf("child workflow identities=%#v, want four distinct runs", childWorkflows)
	}
	after := fixture.inventorySnapshot(t)
	if len(after) <= len(before) {
		t.Fatal("child workflows did not install P2 artifacts")
	}
	for _, entry := range before {
		found := false
		for _, candidate := range after {
			if candidate.Path == entry.Path && candidate.SHA256 == entry.SHA256 && candidate.Bytes == entry.Bytes {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("root inventory entry changed: %#v", entry)
		}
	}
	transcript := fixture.provider.Transcript()
	if len(transcript) != 12 {
		t.Fatalf("provider calls=%d, want root(6), followup initial/repair(2), delta(2), exact rerun(1), recompose rerun(1)", len(transcript))
	}
	wantPurposes := []string{
		"initial", "initial", "initial", "initial", "initial", "initial",
		"initial", "repair",
		"initial", "initial",
		"initial", "initial",
	}
	for index, want := range wantPurposes {
		if string(transcript[index].Purpose) != want || transcript[index].AttemptID.String() == "" || transcript[index].StdinSHA256 == "" {
			t.Fatalf("transcript[%d]=%#v, want purpose %q with actual identity", index, transcript[index], want)
		}
	}
	if transcript[1].AttemptID == root.AttemptID || transcript[6].AttemptID == root.AttemptID ||
		transcript[10].AttemptID == root.AttemptID || transcript[11].AttemptID == root.AttemptID {
		t.Fatal("security, followup, exact replay child, or recomposed replay child reused the root logic attempt identity")
	}
	if transcript[6].AttemptID != transcript[7].AttemptID {
		t.Fatal("followup repair did not retain its initial attempt identity")
	}
	if transcript[10].StdinSHA256 != transcript[0].StdinSHA256 {
		t.Fatal("exact replay child did not invoke the persisted source prompt exactly once")
	}
	if transcript[11].StdinSHA256 == transcript[0].StdinSHA256 {
		t.Fatal("recomposed replay child reused the persisted source prompt")
	}

	// Every returned child is a new P2 publication. Resolve the IDs from their
	// immutable run directories rather than relying on a scripted result value.
	candidates, _, err := filesystem.NewRunSelector(fixture.root).Enumerate(context.Background(), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("P2 run count=%d, want root plus four children", len(candidates))
	}
	for _, candidate := range candidates {
		run, err := fixture.queries.ResolveRun(context.Background(), fixture.root, candidate.RunID)
		if err != nil {
			t.Fatal(err)
		}
		committed, err := fixture.queries.ReadCommitted(context.Background(), run)
		if err != nil {
			for cause := err; cause != nil; cause = errors.Unwrap(cause) {
				t.Logf("run %s committed read cause: %v", candidate.RunID, cause)
			}
			t.Fatalf("run %s committed read: %v", candidate.RunID, err)
		}
		if strings.TrimPrefix(committed.FinalSHA256(), "sha256:") != g008RealTargetHash(committed.FinalBytes()) ||
			strings.TrimPrefix(committed.ManifestSHA256(), "sha256:") != g008RealTargetHash(committed.ManifestBytes()) {
			t.Fatalf("run %s committed final or manifest bytes do not match their P2 identities", candidate.RunID)
		}
		workflow, child := childWorkflows[candidate.RunID.String()]
		if child {
			lineage := committed.Lineage()
			parentRunID, hasParent := lineage.ParentRunID()
			sourceRunID, hasSource := lineage.SourceRunID()
			sourceReviewID, hasReview := lineage.SourceReviewID()
			if parentRunID != root.RunID || sourceRunID != root.RunID || sourceReviewID != root.ReviewID ||
				!hasParent || !hasSource || !hasReview ||
				committed.RunID() == root.RunID || committed.ReviewID() == root.ReviewID || committed.SessionID() != root.SessionID {
				t.Fatalf("%s child identity/lineage = committed=%#v lineage=%#v", workflow, committed, lineage)
			}
			switch workflow {
			case "followup":
				if committed.ContentVerdict() != domain.ContentRequestChanges || committed.CIDecision() != domain.CIFail {
					t.Fatalf("followup child axes = (%q, %q), want request_changes/failed", committed.ContentVerdict(), committed.CIDecision())
				}
				outcome, ok := committed.FollowupOutcome()
				sourceFindingRef, hasFinding := lineage.SourceFindingRef()
				if !ok || !hasFinding || sourceFindingRef != "F001" {
					t.Fatalf("followup outcome/lineage = %#v/%#v", outcome, lineage)
				}
				if _, hasReplay := lineage.ReplayMode(); hasReplay {
					t.Fatalf("followup lineage unexpectedly has replay authority: %#v", lineage)
				}
				evidence := outcome.Evidence()
				if len(evidence) != 1 || evidence[0].SourceSessionID() != root.SessionID ||
					evidence[0].SourceRunID() != root.RunID || evidence[0].SourceReviewID() != root.ReviewID ||
					evidence[0].SourceFindingID() != "F001" ||
					evidence[0].SourceTargetSHA256() != "sha256:"+rootTarget.Identity().SHA256() ||
					evidence[0].SourceExcerptSHA256() != "sha256:"+g008RealTargetHash(rootFinding.Excerpt()) ||
					evidence[0].TargetSHA256() != committed.TargetSHA256() ||
					strings.TrimPrefix(evidence[0].TargetSHA256(), "sha256:") == rootTarget.Identity().SHA256() {
					t.Fatalf("followup evidence is not bound to distinct immutable source/current targets: %#v", evidence)
				}
				projection, err := (p2ExportProjectionReader{committed: committed}).ReadCommittedProjection(context.Background(), appexport.ExportSource{
					SessionID: committed.SessionID().String(), RunID: committed.RunID().String(), ReviewID: committed.ReviewID().String(),
				})
				if err != nil {
					t.Fatalf("followup export projection: %v", err)
				}
				if projection.RunID != committed.RunID().String() ||
					projection.ReviewID != committed.ReviewID().String() ||
					projection.RunManifest.ArtifactPath != committed.ManifestPath().String() ||
					projection.ReviewArtifact.ArtifactPath != committed.FinalPath().String() ||
					projection.SourceIdentity.RunID != root.RunID.String() ||
					projection.SourceIdentity.ReviewID != root.ReviewID.String() ||
					projection.SourceIdentity.RunID == projection.RunID ||
					projection.SourceIdentity.ReviewID == projection.ReviewID ||
					len(projection.Evidence) != 0 ||
					projection.SourceIdentity.FindingID != "" ||
					projection.SourceIdentity.SourceExcerptSHA256 != "" ||
					projection.SourceIdentity.SourceTargetSHA256 != evidence[0].SourceTargetSHA256() ||
					projection.CurrentIdentity.TargetSHA256 != evidence[0].TargetSHA256() ||
					projection.CurrentIdentity.CurrentExcerptSHA256 == "" ||
					projection.CurrentIdentity.CurrentExcerptSHA256 != evidence[0].CurrentExcerptSHA256() {
					t.Fatalf("followup export identities/evidence = %#v", projection)
				}
				exportResult, err := dependencies.Exports.ExportRedactedRun(context.Background(), RedactedExportRequest{
					ProjectRoot: fixture.root, RunID: committed.RunID().String(), OutputPath: "exports/followup.zip", Redacted: true,
				})
				if err != nil {
					t.Fatalf("export followup: %v", err)
				}
				manifestBytes, err := os.ReadFile(filepath.Join(fixture.root.String(), exportResult.ExportManifestURI))
				if err != nil {
					t.Fatalf("read followup manifest: %v", err)
				}
				var manifest appexport.ExportManifest
				if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
					t.Fatalf("decode followup manifest: %v", err)
				}
				if !exportResult.Redacted ||
					manifest.ImmutableSource.RunID != projection.RunID ||
					manifest.ImmutableSource.ReviewID != projection.ReviewID ||
					manifest.SourceIdentity != projection.SourceIdentity ||
					manifest.CurrentIdentity != projection.CurrentIdentity {
					t.Fatalf("followup export = result %#v manifest %#v", exportResult, manifest)
				}
			case "delta":
				if committed.ContentVerdict() != domain.ContentRequestChanges || committed.CIDecision() != domain.CIFail ||
					strings.TrimPrefix(committed.TargetSHA256(), "sha256:") == rootTarget.Identity().SHA256() {
					t.Fatalf("delta child semantics = committed=%#v lineage=%#v", committed, lineage)
				}
				if len(committed.Findings()) != 1 || committed.Findings()[0].Role() != domain.RoleLogic {
					t.Fatalf("delta retained non-authoritative optional finding: %#v", committed.Findings())
				}
				if _, hasFinding := lineage.SourceFindingRef(); hasFinding {
					t.Fatalf("delta lineage unexpectedly has a finding: %#v", lineage)
				}
				if _, hasReplay := lineage.ReplayMode(); hasReplay {
					t.Fatalf("delta lineage unexpectedly has replay authority: %#v", lineage)
				}
			case "exact rerun", "recomposed rerun":
				if committed.CoverageStatus() != domain.CoverageComplete && workflow == "exact rerun" {
					t.Fatalf("exact rerun child coverage = %q, want complete selected-role coverage", committed.CoverageStatus())
				}
				wantMode := query.ReplayModeExact
				if workflow == "recomposed rerun" {
					wantMode = query.ReplayModeRecompose
				}
				replayMode, hasReplay := lineage.ReplayMode()
				if !hasReplay || replayMode != wantMode ||
					strings.TrimPrefix(committed.TargetSHA256(), "sha256:") != rootTarget.Identity().SHA256() {
					t.Fatalf("%s replay lineage/target = committed=%#v lineage=%#v", workflow, committed, lineage)
				}
				if _, hasFinding := lineage.SourceFindingRef(); hasFinding {
					t.Fatalf("%s replay lineage unexpectedly has a finding: %#v", workflow, lineage)
				}
				attempt, err := fixture.queries.ResolveCommittedAttempt(context.Background(), run, domain.RoleLogic, fixture.assignments[0].ProviderInstance())
				if err != nil {
					t.Fatalf("%s child prompt receipt: %v", workflow, err)
				}
				receipt := attempt.Prompt()
				if attempt.AttemptID() == root.AttemptID || attempt.RunID() != committed.RunID() || receipt.Role() != domain.RoleLogic ||
					receipt.ManifestPath().String() == "" || receipt.ManifestSHA256() == "" || receipt.ExecutionInvocationID() == "" {
					t.Fatalf("%s child persisted prompt receipt = %#v", workflow, attempt)
				}
				if workflow == "exact rerun" && (receipt.CompleteStdinSHA256() != rootAttempt.Prompt().CompleteStdinSHA256() ||
					string(receipt.Stdin()) != string(rootAttempt.Prompt().Stdin()) ||
					receipt.SourceInvocationID() != rootAttempt.Prompt().SourceInvocationID() ||
					receipt.ExecutionInvocationID() == rootAttempt.Prompt().ExecutionInvocationID()) {
					t.Fatalf("exact rerun did not preserve root attempt %s replay authority", root.AttemptID)
				}
			}
		}
		if _, recompose := recomposeChildren[candidate.RunID.String()]; recompose {
			roles := committed.Roles()
			if committed.CoverageStatus() != domain.CoverageComplete || len(roles) != 1 || roles[0].Name() != domain.RoleLogic {
				t.Fatalf("recompose child coverage/roles = (%q, %#v), want complete with one logic role", committed.CoverageStatus(), roles)
			}
		}
		if committed.FinalPath().String() == "" || committed.ManifestPath().String() == "" || committed.LineageEdgePath().String() == "" {
			t.Fatalf("run %s lacks real P2 receipt URIs", candidate.RunID)
		}
	}
	rootAfter, err := fixture.queries.ReadCommitted(context.Background(), rootRun)
	if err != nil {
		t.Fatal(err)
	}
	rootTargetAfter, err := fixture.queries.ReadRuntimeTarget(context.Background(), rootRun)
	if err != nil {
		t.Fatal(err)
	}
	if rootAfter.FinalSHA256() != rootCommitted.FinalSHA256() || rootAfter.ManifestSHA256() != rootCommitted.ManifestSHA256() ||
		rootAfter.TargetSHA256() != rootCommitted.TargetSHA256() || string(rootTargetAfter.Bytes()) != string(rootTarget.Bytes()) ||
		rootTargetAfter.Identity() != rootTarget.Identity() {
		t.Fatal("child workflows mutated root committed artifacts or target inventory")
	}
}

func mustG008RealExportInstaller(t *testing.T, fixture *g008RealE2EFixture) *filesystem.ExportInstaller {
	t.Helper()
	installer, err := filesystem.NewExportInstaller(fixture.writer)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}

type g008RealFollowupCapturer struct{}

func (g008RealFollowupCapturer) CaptureFollowupTarget(context.Context, appfollowup.Target) (appfollowup.CurrentTarget, error) {
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: domain.TargetPatch, SHA256: g008RealTargetHash([]byte("queueFallback(task)"))})
	if err != nil {
		return appfollowup.CurrentTarget{}, err
	}
	return appfollowup.CurrentTarget{Identity: identity, Bytes: []byte("queueFallback(task)")}, nil
}

type g008RealDeltaCapturer struct{ target appdelta.ImmutableTarget }

func (capturer g008RealDeltaCapturer) CaptureTarget(context.Context, appdelta.TargetRequest) (appdelta.ImmutableTarget, error) {
	return capturer.target, nil
}

type g008RealComparator struct{}

func (g008RealComparator) Compare(context.Context, appdelta.ImmutableTarget, appdelta.ImmutableTarget) (appdelta.Delta, error) {
	return appdelta.Delta{Bytes: []byte("A/B")}, nil
}
func g008RealTargetHash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
