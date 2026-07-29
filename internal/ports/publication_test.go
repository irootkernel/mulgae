package ports

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestPublicationContractsValidateAndDefensivelyCopy(t *testing.T) {
	t.Parallel()

	run := publicationTestRun(t)
	wrongRoot, err := NewAnchoredRoot("/tmp/mulgae-publication-contract-wrong-root")
	if err != nil {
		t.Fatal(err)
	}
	finalBytes := []byte(`{"schema_version":"mulgae-review-artifact.v1"}`)
	final := publicationTestFinal(t, finalBytes)
	issued := publicationTestIssued(t, final)
	binding, err := NewIssuedFinalBinding(issued, final)
	if err != nil {
		t.Fatal(err)
	}
	otherReviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc3")
	if err != nil {
		t.Fatal(err)
	}
	otherIssued, err := NewIssuedReviewID(otherReviewID, final.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewIssuedFinalBinding(otherIssued, final); err == nil {
		t.Error("issued-final binding accepted mismatched ReviewIDs")
	}
	stagedPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-d174-7321-b920-c2d312c82cc2.json.tmp")

	issue, err := NewIssueReviewIDRequest(run, final.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	if issue.Run() != run || issue.ValidatedCandidateSHA256() != final.SHA256() {
		t.Fatalf("issue request = %#v", issue)
	}
	if _, err := NewObserveRunRequest(run, 0); err == nil {
		t.Error("zero observation cap accepted")
	}
	observe, err := NewObserveRunRequest(run, 1024)
	if err != nil || observe.MaxReadBytes() != 1024 {
		t.Fatalf("observe request = %#v, %v", observe, err)
	}

	stored := domain.ExitCommittedPass
	if _, err := NewPublicationObservation(
		domain.JournalCollecting,
		domain.DurableObservationP2Committed,
		&stored,
		nil,
		1,
	); err == nil {
		t.Error("P2 observation without atomically observed mutable material accepted")
	}
	if _, err := NewPublicationObservation(domain.JournalCollecting, domain.DurableObservationP2Committed, &stored, nil, 0); err == nil {
		t.Error("zero observation epoch accepted")
	}

	sourceIDs := []string{"validated_candidate"}
	stageRequest, err := NewStageFinalRequest(run, stagedPath, binding, strings.NewReader(string(finalBytes)), int64(len(finalBytes)), sourceIDs, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	adoptFinalArtifact, err := NewFinalReviewArtifact(final, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	adoptRequest, err := NewAdoptStagedFinalRequest(
		run,
		stagedPath,
		binding,
		adoptFinalArtifact,
		int64(len(finalBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if adoptRequest.Run() != run || adoptRequest.StagedPath() != stagedPath ||
		adoptRequest.IssuedReviewID() != issued ||
		adoptRequest.Final().Identity() != final ||
		adoptRequest.MaxBytes() != int64(len(finalBytes)) {
		t.Fatalf("adopt staged final request = %#v", adoptRequest)
	}
	if _, err := NewAdoptStagedFinalRequest(
		run,
		stagedPath,
		binding,
		adoptFinalArtifact,
		int64(len(finalBytes))-1,
	); err == nil {
		t.Error("undersized staged adoption cap accepted")
	}
	otherFinalBytes := []byte(`{"schema_version":"mulgae-review-artifact.v1","different":true}`)
	otherFinalIdentity, err := NewFinalReviewIdentity(
		final.ReviewID(),
		final.Path(),
		sha256Identifier(otherFinalBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	otherFinalArtifact, err := NewFinalReviewArtifact(otherFinalIdentity, otherFinalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdoptStagedFinalRequest(
		run,
		stagedPath,
		binding,
		otherFinalArtifact,
		int64(len(otherFinalBytes)),
	); err == nil {
		t.Error("staged adoption accepted final bytes outside the issued-final binding")
	}
	sourceIDs[0] = "mutated"
	if got := stageRequest.SourceIDs(); len(got) != 1 || got[0] != "validated_candidate" {
		t.Fatalf("stage request retained caller source IDs: %#v", got)
	}
	copiedSourceIDs := stageRequest.SourceIDs()
	copiedSourceIDs[0] = "mutated"
	if got := stageRequest.SourceIDs(); got[0] != "validated_candidate" {
		t.Fatalf("stage request accessor leaked source IDs: %#v", got)
	}
	if _, err := NewStageFinalRequest(run, stagedPath, binding, nil, 1, []string{"validated_candidate"}, func(error) {}); err == nil {
		t.Error("nil stage reader accepted")
	}
	if _, err := NewStageFinalRequest(run, stagedPath, binding, strings.NewReader("final"), 1, []string{"validated_candidate"}, nil); err == nil {
		t.Error("nil stage abort callback accepted")
	}
	if _, err := NewStageFinalRequest(run, final.Path(), binding, strings.NewReader("final"), 1, []string{"validated_candidate"}, func(error) {}); err == nil {
		t.Error("stage request at final path accepted")
	}
	lengthBoundStageRequest, err := NewStageFinalRequestWithExpectedByteLength(
		run,
		stagedPath,
		binding,
		strings.NewReader(string(finalBytes)),
		int64(len(finalBytes)),
		int64(len(finalBytes)),
		[]string{"validated_candidate"},
		func(error) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if byteLength, present := lengthBoundStageRequest.ExpectedByteLength(); !present || byteLength != int64(len(finalBytes)) {
		t.Fatalf("length-bound stage request = (%d, %t)", byteLength, present)
	}
	stagedReceipt := publicationTestReceipt(t, stagedPath, finalBytes)
	wrongRootStagedReceipt, err := NewSecureWriteReceipt(
		wrongRoot,
		stagedPath,
		final.SHA256(),
		int64(len(finalBytes)),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStageFinalResultForRequest(lengthBoundStageRequest, wrongRootStagedReceipt, StageFinalDurable); err == nil {
		t.Error("request-bound staged result accepted a receipt from another root")
	}
	wrongLengthStagedReceipt, err := NewSecureWriteReceipt(
		run.Root(),
		stagedPath,
		final.SHA256(),
		int64(len(finalBytes)+1),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStageFinalResultForRequest(lengthBoundStageRequest, wrongLengthStagedReceipt, StageFinalDurable); err == nil {
		t.Error("length-bound staged result accepted a mismatched receipt length")
	}
	lengthBoundStaged, err := NewStageFinalResultForRequest(lengthBoundStageRequest, stagedReceipt, StageFinalDurable)
	if err != nil {
		t.Fatal(err)
	}
	lengthBoundInstallRequest, err := NewInstallFinalRequest(run, lengthBoundStaged)
	if err != nil {
		t.Fatal(err)
	}
	wrongLengthInstalledReceipt, err := NewSecureWriteReceipt(
		run.Root(),
		final.Path(),
		final.SHA256(),
		int64(len(finalBytes)+1),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstallFinalResultForRequest(lengthBoundInstallRequest, wrongLengthInstalledReceipt, InstallFinalDurable); err == nil {
		t.Error("length-bound install result accepted a mismatched receipt length")
	}

	staged, err := NewStageFinalResult(stagedPath, final, stagedReceipt, StageFinalUndurable)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Durability() != StageFinalUndurable || staged.Receipt().Destination() != stagedPath {
		t.Fatalf("staged result = %#v", staged)
	}
	if _, err := NewInstallFinalRequest(run, staged); err == nil {
		t.Error("installation accepted an undurable staged final")
	}
	durableStaged, err := NewStageFinalResult(stagedPath, final, stagedReceipt, StageFinalDurable)
	if err != nil {
		t.Fatal(err)
	}
	installRequest, err := NewInstallFinalRequest(run, durableStaged)
	if err != nil {
		t.Fatal(err)
	}
	if installRequest.Staged().Final() != final {
		t.Fatalf("install request = %#v", installRequest)
	}
	nonCanonicalStagedPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/other.json.tmp")
	nonCanonicalStaged, err := NewStageFinalResult(
		nonCanonicalStagedPath,
		final,
		publicationTestReceipt(t, nonCanonicalStagedPath, finalBytes),
		StageFinalDurable,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstallFinalRequest(run, nonCanonicalStaged); err == nil {
		t.Error("installation accepted a noncanonical staged path")
	}
	installedReceipt := publicationTestReceipt(t, final.Path(), finalBytes)
	wrongRootInstalledReceipt, err := NewSecureWriteReceipt(
		wrongRoot,
		final.Path(),
		final.SHA256(),
		int64(len(finalBytes)),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewInstallFinalResultForRequest(installRequest, wrongRootInstalledReceipt, InstallFinalDurable); err == nil {
		t.Error("request-bound install result accepted a receipt from another root")
	}
	installed, err := NewInstallFinalResult(final, installedReceipt, InstallFinalUndurable)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Durability() != InstallFinalUndurable || installed.Final() != final {
		t.Fatalf("installed result = %#v", installed)
	}

	statusPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json")
	replacement := []byte(`{"state":"completed"}`)
	replace, err := NewMutableReplaceRequest(run, MutablePublicationStatus, statusPath, ExpectMutableAbsent(), replacement, sha256Identifier(replacement))
	if err != nil {
		t.Fatal(err)
	}
	replacement[0] = '!'
	if got := string(replace.Replacement()); got != `{"state":"completed"}` {
		t.Fatalf("replace request retained caller bytes %q", got)
	}
	copiedReplacement := replace.Replacement()
	copiedReplacement[0] = '!'
	if got := string(replace.Replacement()); got != `{"state":"completed"}` {
		t.Fatalf("replace request accessor leaked bytes %q", got)
	}
	oldHash := sha256Identifier([]byte("old-status"))
	expectHash, err := ExpectMutableSHA256(oldHash)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := expectHash.ExpectedSHA256(); !ok || got != oldHash || expectHash.MustBeAbsent() {
		t.Fatalf("hash expectation = (%q, %t, %t)", got, ok, expectHash.MustBeAbsent())
	}
	if _, err := NewMutableReplaceRequest(run, MutablePublicationStatus, statusPath, MutableCASExpectation{}, []byte("next"), sha256Identifier([]byte("next"))); err == nil {
		t.Error("zero CAS expectation accepted")
	}
	replaceReceipt := publicationTestReceipt(t, statusPath, []byte(`{"state":"completed"}`))
	replaced, err := NewMutableReplaceResult(replace, replaceReceipt, MutableReplaceUndurable)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Durability() != MutableReplaceUndurable {
		t.Fatalf("replace result = %#v", replaced)
	}
	if _, err := NewMutableReplaceResult(
		replace,
		publicationTestReceipt(t, statusPath, []byte(`{"state":"different"}`)),
		MutableReplaceDurable,
	); err == nil {
		t.Error("mutable replacement result accepted a receipt for different bytes")
	}

	manifestBytes := []byte(`{"schema_version":"mulgae-run-manifest.v1"}`)
	lineageBytes := []byte(`{"schema_version":"mulgae-lineage-edge.v1"}`)
	epochBytes := []byte(`{"schema_version":"mulgae-publication-epoch.v1"}`)
	manifestPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json")
	lineagePath := publicationTestPath(t, "store/lineage-edges/e_019f596a-d174-7321-b920-c2d312c82cc2.json")
	epochPath := publicationTestPath(t, "store/epochs/epoch_00000000000000000001.json")
	manifest := publicationTestArtifact(t, manifestPath, manifestBytes)
	lineage := publicationTestArtifact(t, lineagePath, lineageBytes)
	epochRecord := publicationTestArtifact(t, epochPath, epochBytes)
	epoch, err := NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublicationEpoch(0, epochRecord); err == nil {
		t.Error("zero composite epoch accepted")
	}
	commit, err := NewCommitCompositeRequest(run, final, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Epoch().Value() != 1 || string(commit.Manifest().Bytes()) != string(manifestBytes) {
		t.Fatalf("commit request = %#v", commit)
	}
	if _, err := NewCommitCompositeRequest(run, final, manifest, manifest, epoch); err == nil {
		t.Error("duplicate composite member path accepted")
	}
	memberReceipts := []SecureWriteReceipt{
		publicationTestReceipt(t, manifestPath, manifestBytes),
		publicationTestReceipt(t, lineagePath, lineageBytes),
	}
	partialCommit, err := NewCompositeCommitResult(CompositeMembersInstalled, memberReceipts)
	if err != nil {
		t.Fatal(err)
	}
	memberReceipts[0] = SecureWriteReceipt{}
	if got := partialCommit.Receipts(); len(got) != 2 || got[0].Destination() != manifestPath {
		t.Fatalf("composite result retained caller receipts: %#v", got)
	}
	manifestOnly, err := NewCompositeCommitResult(CompositeManifestInstalled, []SecureWriteReceipt{
		publicationTestReceipt(t, manifestPath, manifestBytes),
	})
	if err != nil || !manifestOnly.Valid() || manifestOnly.Phase() != CompositeManifestInstalled {
		t.Fatalf("manifest-only composite result = (%#v, %v)", manifestOnly, err)
	}
	if _, err := NewCompositeCommitResult(CompositeCommittedDurable, partialCommit.Receipts()); err == nil {
		t.Error("durable composite with no epoch receipt accepted")
	}
	committed, err := NewCompositeCommitResult(CompositeEpochInstalledUndurable, []SecureWriteReceipt{
		publicationTestReceipt(t, manifestPath, manifestBytes),
		publicationTestReceipt(t, lineagePath, lineageBytes),
		publicationTestReceipt(t, epochPath, epochBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if committed.Phase() != CompositeEpochInstalledUndurable {
		t.Fatalf("composite result = %#v", committed)
	}

	finalArtifact, err := NewFinalReviewArtifact(final, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	finalBytes[0] = '!'
	if got := string(finalArtifact.Bytes()); got != `{"schema_version":"mulgae-review-artifact.v1"}` {
		t.Fatalf("final artifact retained caller bytes %q", got)
	}
	snapshot, err := NewCommittedPublicationSnapshot(finalArtifact, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Valid() || snapshot.Epoch().Value() != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	read, err := NewReadCommittedSnapshotRequest(run, 4096)
	if err != nil || read.MaxReadBytes() != 4096 {
		t.Fatalf("snapshot request = %#v, %v", read, err)
	}

	diagnosticBytes := []byte(`{"schema_version":"mulgae-publication-corruption.v1","session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","observation_epoch":1,"reason_codes":["artifact_mismatch"]}`)
	diagnosticPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/recovery/diagnostics/publication-corrupt_1.json")
	diagnostic := publicationTestArtifact(t, diagnosticPath, diagnosticBytes)
	reasons := []string{"artifact_mismatch"}
	diagnosticRequest, err := NewCorruptionDiagnosticRequest(
		run,
		publicationTestCorruptionCAS(t, 1, reasons),
		diagnostic,
	)
	if err != nil {
		t.Fatal(err)
	}
	reasons[0] = "mutated"
	if got := diagnosticRequest.ReasonCodes(); len(got) != 1 || got[0] != "artifact_mismatch" {
		t.Fatalf("diagnostic request retained caller reason codes: %#v", got)
	}
	diagnosticResult, err := NewCorruptionDiagnosticResult(diagnostic, publicationTestReceipt(t, diagnosticPath, diagnosticBytes), CorruptionDiagnosticUndurable)
	if err != nil {
		t.Fatal(err)
	}
	if diagnosticResult.Durability() != CorruptionDiagnosticUndurable {
		t.Fatalf("diagnostic result = %#v", diagnosticResult)
	}
	wrongLengthDiagnosticReceipt, err := NewSecureWriteReceipt(
		run.Root(),
		diagnosticPath,
		diagnostic.SHA256(),
		int64(len(diagnostic.Bytes())+1),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCorruptionDiagnosticResult(diagnostic, wrongLengthDiagnosticReceipt, CorruptionDiagnosticDurable); err == nil {
		t.Error("diagnostic result accepted a mismatched receipt length")
	}
	if _, err := NewCorruptionDiagnosticResultForRequest(
		diagnosticRequest,
		publicationTestReceipt(t, diagnosticPath, diagnosticBytes),
		CorruptionDiagnosticDurable,
	); err != nil {
		t.Fatalf("request-bound diagnostic result = %v", err)
	}
	wrongRootDiagnosticReceipt, err := NewSecureWriteReceipt(
		wrongRoot,
		diagnosticPath,
		diagnostic.SHA256(),
		int64(len(diagnosticBytes)),
		"publication",
		[]string{"validated_candidate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCorruptionDiagnosticResultForRequest(
		diagnosticRequest,
		wrongRootDiagnosticReceipt,
		CorruptionDiagnosticDurable,
	); err == nil {
		t.Error("request-bound diagnostic result accepted a receipt from another root")
	}
}

func TestCorruptionObservationCASSupportsHighHintP0None(t *testing.T) {
	t.Parallel()

	observation, err := NewPublicationObservation(
		domain.JournalCompleted,
		domain.DurableObservationP0None,
		nil,
		nil,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := NewCorruptionObservationCAS(observation)
	if err != nil {
		t.Fatal(err)
	}
	if got := cas.ReasonCodes(); len(got) != 1 || got[0] != "missing_required_durable_effect" {
		t.Fatalf("high-hint P0_NONE reasons = %#v", got)
	}
	if !cas.Matches(observation) {
		t.Fatal("high-hint P0_NONE CAS did not match its observation")
	}
}

func TestPublicationContractsFailClosedOnInvalidScopeIdentityAndOutcome(t *testing.T) {
	t.Parallel()

	root, err := NewAnchoredRoot("/tmp/mulgae-publication-contract")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublicationRun(root, domain.SessionID{}, domain.RunID{}); err == nil {
		t.Error("zero domain IDs accepted")
	}
	run := publicationTestRun(t)
	finalBytes := []byte("final")
	finalPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-d174-7321-b920-c2d312c82cc2.json")
	reviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFinalReviewIdentity(reviewID, finalPath, "sha256:not-a-hash"); err == nil {
		t.Error("malformed final SHA-256 accepted")
	}
	final := publicationTestFinal(t, finalBytes)
	issued := publicationTestIssued(t, final)
	binding, err := NewIssuedFinalBinding(issued, final)
	if err != nil {
		t.Fatal(err)
	}
	wrongPathFinal, err := NewFinalReviewIdentity(reviewID, publicationTestPath(t, "wrong-review.json"), final.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	wrongBinding, err := NewIssuedFinalBinding(issued, wrongPathFinal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStageFinalRequest(run, publicationTestPath(t, "stage.tmp"), wrongBinding, strings.NewReader("final"), 16, []string{"validated_candidate"}, func(error) {}); err == nil {
		t.Error("non-canonical final path accepted")
	}
	if _, err := NewImmutablePublicationArtifact(final.Path(), sha256Identifier([]byte("other")), finalBytes); err == nil {
		t.Error("artifact hash mismatch accepted")
	}
	if _, err := NewStageFinalRequest(run, publicationTestPath(t, "stage.tmp"), binding, strings.NewReader("x"), 0, []string{"validated_candidate"}, func(error) {}); err == nil {
		t.Error("zero stage cap accepted")
	}
	if _, err := NewCorruptionDiagnosticRequest(run, CorruptionObservationCAS{}, publicationTestArtifact(t, publicationTestPath(t, "diagnostic.json"), []byte("diagnostic"))); err == nil {
		t.Error("invalid diagnostic reason accepted")
	}
	if _, err := NewCompositeCommitResult("unknown", nil); err == nil {
		t.Error("unknown composite phase accepted")
	}
	if _, err := NewReadCommittedSnapshotRequest(run, 0); err == nil {
		t.Error("zero committed snapshot cap accepted")
	}
}
func TestPublicationRequestsRejectCrossNamespaceDestinations(t *testing.T) {
	t.Parallel()

	run := publicationTestRun(t)
	final := publicationTestFinal(t, []byte(`{"schema_version":"mulgae-review-artifact.v1"}`))
	issued := publicationTestIssued(t, final)
	binding, err := NewIssuedFinalBinding(issued, final)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStageFinalRequest(
		run,
		publicationTestPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/status.json"),
		binding,
		strings.NewReader("final"),
		16,
		[]string{"validated_candidate"},
		func(error) {},
	); err == nil {
		t.Error("stage request targeting mutable namespace accepted")
	}

	replacement := []byte(`{"state":"completed"}`)
	for _, path := range []SafeRelativePath{
		final.Path(),
		publicationTestPath(t, "store/locks/store.lock"),
		publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243bb/status.json"),
	} {
		if _, err := NewMutableReplaceRequest(
			run,
			MutablePublicationStatus,
			path,
			ExpectMutableAbsent(),
			replacement,
			sha256Identifier(replacement),
		); err == nil {
			t.Errorf("mutable replacement accepted non-status target %q", path.String())
		}
	}

	manifest := publicationTestArtifact(
		t,
		publicationTestPath(t, "wrong-manifest.json"),
		[]byte(`{"schema_version":"mulgae-run-manifest.v1"}`),
	)
	lineage := publicationTestArtifact(
		t,
		publicationTestPath(t, "wrong-lineage.json"),
		[]byte(`{"schema_version":"mulgae-lineage-edge.v1"}`),
	)
	epochRecord := publicationTestArtifact(
		t,
		publicationTestPath(t, "wrong-epoch.json"),
		[]byte(`{"schema_version":"mulgae-publication-epoch.v1"}`),
	)
	epoch, err := NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCommitCompositeRequest(run, final, manifest, lineage, epoch); err == nil {
		t.Error("composite request accepted non-canonical immutable destinations")
	}

	diagnostic := publicationTestArtifact(
		t,
		publicationTestPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/recovery/diagnostics/publication-corrupt_1.json"),
		[]byte(`{"schema_version":"mulgae-publication-corruption.v1","session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","observation_epoch":2,"reason_codes":["artifact_mismatch"]}`),
	)
	if _, err := NewCorruptionDiagnosticRequest(run, publicationTestCorruptionCAS(t, 1, []string{"artifact_mismatch"}), diagnostic); err == nil {
		t.Error("diagnostic payload with mismatched epoch accepted")
	}
	duplicateDiagnostic := publicationTestArtifact(
		t,
		publicationTestPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/recovery/diagnostics/publication-corrupt_1.json"),
		[]byte(`{"schema_version":"mulgae-publication-corruption.v1","schema_version":"mulgae-publication-corruption.v1","session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","observation_epoch":1,"reason_codes":["artifact_mismatch"]}`),
	)
	if _, err := NewCorruptionDiagnosticRequest(run, publicationTestCorruptionCAS(t, 1, []string{"artifact_mismatch"}), duplicateDiagnostic); err == nil {
		t.Error("diagnostic payload with duplicate keys accepted")
	}
}

func TestPublicationObservationRecoveryMaterialContracts(t *testing.T) {
	t.Parallel()

	finalBytes := []byte(`{"schema_version":"mulgae-review-artifact.v1","state":"final"}`)
	final := publicationTestFinal(t, finalBytes)
	finalArtifact, err := NewFinalReviewArtifact(final, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	journalBytes := []byte(`{"persisted_journal_state":"content_validated"}`)
	journalPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/journal.json")
	journal, err := NewObservedMutablePublicationDocument(
		MutablePublicationJournal,
		journalPath,
		sha256Identifier(journalBytes),
		journalBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	statusBytes := []byte(`{"publication_status":"not_published"}`)
	statusPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json")
	status, err := NewObservedMutablePublicationDocument(
		MutablePublicationStatus,
		statusPath,
		sha256Identifier(statusBytes),
		statusBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	stagedPath := publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-d174-7321-b920-c2d312c82cc2.json.tmp")
	run := publicationTestRun(t)
	manifest := publicationTestArtifact(t, publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json"), []byte("manifest"))
	lineage := publicationTestArtifact(t, publicationTestPath(t, "store/lineage-edges/e_019f596a-d174-7321-b920-c2d312c82cc2.json"), []byte("lineage"))
	epochRecord := publicationTestArtifact(t, publicationTestPath(t, "store/epochs/epoch_00000000000000000001.json"), []byte("epoch"))
	epoch, err := NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	composite, err := NewCommitCompositeRequest(run, final, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	stagedManifest := publicationTestArtifact(t, prepare.StagedManifestPath(), manifest.Bytes())
	stagedLineage := publicationTestArtifact(t, prepare.StagedLineageEdgePath(), lineage.Bytes())
	stagedEpoch := publicationTestArtifact(t, prepare.StagedEpochPath(), epoch.Record().Bytes())
	prepared, err := NewPreparedComposite(prepare, stagedManifest, stagedLineage, stagedEpoch, []SecureWriteReceipt{
		publicationTestReceipt(t, stagedManifest.Path(), stagedManifest.Bytes()),
		publicationTestReceipt(t, stagedLineage.Path(), stagedLineage.Bytes()),
		publicationTestReceipt(t, stagedEpoch.Path(), stagedEpoch.Bytes()),
	}, CompositePreparationDurable)
	if err != nil {
		t.Fatal(err)
	}
	restageMaterial, err := NewPublicationRecoveryMaterialWithPrepared(finalArtifact, nil, journal, &status, finalArtifact, prepared)
	if err != nil {
		t.Fatal(err)
	}
	stagedMaterial, err := NewPublicationRecoveryMaterialWithPrepared(finalArtifact, &stagedPath, journal, &status, finalArtifact, prepared)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewCommittedPublicationSnapshot(finalArtifact, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	p2Material, err := NewPublicationRecoveryMaterialWithCommittedSnapshot(finalArtifact, journal, status, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	missingJournal, err := NewMissingMutablePublicationDocument(
		MutablePublicationJournal,
		journalPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	missingStatus, err := NewMissingMutablePublicationDocument(
		MutablePublicationStatus,
		statusPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	missingP2Material, err := NewPublicationRecoveryMaterialWithCommittedSnapshot(
		finalArtifact,
		missingJournal,
		missingStatus,
		snapshot,
	)
	if err != nil {
		t.Fatal(err)
	}
	p2Exit := domain.ExitCommittedPass
	if _, err := NewPublicationObservationWithRecovery(
		domain.JournalCompleted,
		domain.DurableObservationP2Committed,
		&p2Exit,
		nil,
		1,
		missingP2Material,
	); err != nil {
		t.Fatalf("P2 observation rejected atomically missing mutable records: %v", err)
	}
	materialWithoutStatus, err := newPublicationRecoveryMaterial(finalArtifact, nil, journal, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := materialWithoutStatus.Status(); ok {
		t.Error("recovery material claimed an absent status")
	}
	if _, err := NewPublicationObservationWithRecovery(
		domain.JournalCompleted,
		domain.DurableObservationP2Committed,
		&p2Exit,
		nil,
		1,
		materialWithoutStatus,
	); err == nil {
		t.Error("P2 observation accepted omitted mutable status material")
	}

	if journal.Document() != MutablePublicationJournal || journal.Path() != journalPath || journal.SHA256() != sha256Identifier(journalBytes) || !journal.Valid() {
		t.Fatalf("journal accessor = %#v", journal)
	}
	if got := restageMaterial.Final(); got.Identity() != final || !got.Valid() {
		t.Fatalf("final accessor = %#v", got)
	}
	if _, ok := restageMaterial.StagedPath(); ok {
		t.Error("restage material claimed a staged path")
	}
	if got := restageMaterial.Journal(); got.Document() != MutablePublicationJournal || got.Path() != journalPath {
		t.Fatalf("journal accessor = %#v", got)
	}
	if got, ok := restageMaterial.Status(); !ok || got.Document() != MutablePublicationStatus || got.Path() != statusPath {
		t.Fatalf("status accessor = (%#v, %t)", got, ok)
	}
	if got, ok := stagedMaterial.StagedPath(); !ok || got != stagedPath {
		t.Fatalf("staged path accessor = (%#v, %t)", got, ok)
	}
	journalSHA := journal.SHA256()
	statusSHA := status.SHA256()

	finalBytes[0] = '!'
	journalBytes[0] = '!'
	statusBytes[0] = '!'
	if got := string(restageMaterial.Final().Bytes()); got != `{"schema_version":"mulgae-review-artifact.v1","state":"final"}` {
		t.Fatalf("recovery material retained final bytes %q", got)
	}
	if got := string(restageMaterial.Journal().Bytes()); got != `{"persisted_journal_state":"content_validated"}` {
		t.Fatalf("recovery material retained journal bytes %q", got)
	}
	recoveredStatus, ok := restageMaterial.Status()
	if !ok {
		t.Fatal("recovery material omitted status")
	}
	if got := string(recoveredStatus.Bytes()); got != `{"publication_status":"not_published"}` {
		t.Fatalf("recovery material retained status bytes %q", got)
	}
	if got := restageMaterial.Journal().SHA256(); got != journalSHA {
		t.Fatalf("recovery material changed journal hash %q", got)
	}
	if got, _ := restageMaterial.Status(); got.SHA256() != statusSHA {
		t.Fatalf("recovery material changed status hash %q", got.SHA256())
	}
	finalCopy := restageMaterial.Final().Bytes()
	journalCopy := restageMaterial.Journal().Bytes()
	statusCopy := recoveredStatus.Bytes()
	finalCopy[0] = '!'
	journalCopy[0] = '!'
	statusCopy[0] = '!'
	if got := string(restageMaterial.Final().Bytes()); got != `{"schema_version":"mulgae-review-artifact.v1","state":"final"}` {
		t.Fatalf("recovery material leaked final bytes %q", got)
	}
	if got := string(restageMaterial.Journal().Bytes()); got != `{"persisted_journal_state":"content_validated"}` {
		t.Fatalf("recovery material leaked journal bytes %q", got)
	}
	if got, _ := restageMaterial.Status(); string(got.Bytes()) != `{"publication_status":"not_published"}` {
		t.Fatalf("recovery material leaked status bytes %q", got.Bytes())
	}

	if _, err := NewObservedMutablePublicationDocument(
		MutablePublicationJournal,
		journalPath,
		sha256Identifier([]byte("original")),
		[]byte("tampered"),
	); err == nil {
		t.Error("tampered observed-document hash accepted")
	}
	if _, err := NewObservedMutablePublicationDocument(
		MutablePublicationJournal,
		journalPath,
		sha256Identifier(nil),
		nil,
	); err == nil {
		t.Error("empty observed-document bytes accepted")
	}
	emptyStatus, err := NewObservedMutablePublicationDocument(
		MutablePublicationStatus,
		statusPath,
		sha256Identifier(nil),
		nil,
	)
	if err != nil || !emptyStatus.Valid() {
		t.Fatalf("empty mutable status must remain observable for safe P2 reconstruction: %v", err)
	}
	if _, err := NewObservedMutablePublicationDocument(
		MutablePublicationDocument("unknown"),
		journalPath,
		sha256Identifier([]byte("journal")),
		[]byte("journal"),
	); err == nil {
		t.Error("unknown observed document kind accepted")
	}
	sameFinalPath := final.Path()
	if _, err := newPublicationRecoveryMaterial(finalArtifact, &sameFinalPath, journal, &status); err == nil {
		t.Error("recovery material accepted staged path equal to final path")
	}
	if _, err := newPublicationRecoveryMaterial(finalArtifact, nil, status, &status); err == nil {
		t.Error("recovery material accepted a status as its journal")
	}
	if _, err := newPublicationRecoveryMaterial(finalArtifact, nil, journal, &journal); err == nil {
		t.Error("recovery material accepted a journal as its status")
	}

	cases := []struct {
		name             string
		journalState     domain.PersistedJournalState
		observation      domain.DurableObservationClass
		requiresMaterial bool
	}{
		{"p0_staged_collecting", domain.JournalCollecting, domain.DurableObservationP0Staged, true},
		{"p0_staged_content_validated", domain.JournalContentValidated, domain.DurableObservationP0Staged, true},
		{"p0_staged_final_staged", domain.JournalFinalStaged, domain.DurableObservationP0Staged, true},
		{"p0_staged_final_file_installed", domain.JournalFinalFileInstalled, domain.DurableObservationP0Staged, true},
		{"p0_staged_manifest_committed", domain.JournalManifestCommitted, domain.DurableObservationP0Staged, true},
		{"p0_staged_completed", domain.JournalCompleted, domain.DurableObservationP0Staged, true},
		{"p1_installed_collecting", domain.JournalCollecting, domain.DurableObservationP1Installed, true},
		{"p1_installed_content_validated", domain.JournalContentValidated, domain.DurableObservationP1Installed, true},
		{"p1_installed_final_staged", domain.JournalFinalStaged, domain.DurableObservationP1Installed, true},
		{"p1_installed_final_file_installed", domain.JournalFinalFileInstalled, domain.DurableObservationP1Installed, true},
		{"p1_installed_manifest_committed", domain.JournalManifestCommitted, domain.DurableObservationP1Installed, true},
		{"p1_installed_completed", domain.JournalCompleted, domain.DurableObservationP1Installed, true},
		{"p0_none_collecting", domain.JournalCollecting, domain.DurableObservationP0None, false},
		{"p0_none_content_validated", domain.JournalContentValidated, domain.DurableObservationP0None, true},
		{"p0_none_final_staged", domain.JournalFinalStaged, domain.DurableObservationP0None, true},
		{"p0_none_final_file_installed", domain.JournalFinalFileInstalled, domain.DurableObservationP0None, false},
		{"p0_none_manifest_committed", domain.JournalManifestCommitted, domain.DurableObservationP0None, false},
		{"p0_none_completed", domain.JournalCompleted, domain.DurableObservationP0None, false},
		{"p2_collecting", domain.JournalCollecting, domain.DurableObservationP2Committed, true},
		{"p2_content_validated", domain.JournalContentValidated, domain.DurableObservationP2Committed, true},
		{"p2_final_staged", domain.JournalFinalStaged, domain.DurableObservationP2Committed, true},
		{"p2_final_file_installed", domain.JournalFinalFileInstalled, domain.DurableObservationP2Committed, true},
		{"p2_manifest_committed", domain.JournalManifestCommitted, domain.DurableObservationP2Committed, true},
		{"p2_completed", domain.JournalCompleted, domain.DurableObservationP2Committed, true},
		{"ambiguous_collecting", domain.JournalCollecting, domain.DurableObservationAmbiguousOrMismatch, false},
		{"ambiguous_content_validated", domain.JournalContentValidated, domain.DurableObservationAmbiguousOrMismatch, false},
		{"ambiguous_final_staged", domain.JournalFinalStaged, domain.DurableObservationAmbiguousOrMismatch, false},
		{"ambiguous_final_file_installed", domain.JournalFinalFileInstalled, domain.DurableObservationAmbiguousOrMismatch, false},
		{"ambiguous_manifest_committed", domain.JournalManifestCommitted, domain.DurableObservationAmbiguousOrMismatch, false},
		{"ambiguous_completed", domain.JournalCompleted, domain.DurableObservationAmbiguousOrMismatch, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			storedNormalExit, ambiguityReasons := publicationObservationInput(testCase.observation)
			withoutMaterial, withoutMaterialErr := NewPublicationObservation(
				testCase.journalState,
				testCase.observation,
				storedNormalExit,
				ambiguityReasons,
				1,
			)
			if got := withoutMaterialErr == nil; got != !testCase.requiresMaterial {
				t.Fatalf("no-material observation accepted = %t, want %t: %v", got, !testCase.requiresMaterial, withoutMaterialErr)
			}
			if withoutMaterialErr == nil {
				if _, ok := withoutMaterial.RecoveryMaterial(); ok {
					t.Error("no-material observation exposed recovery material")
				}
			}

			material := restageMaterial
			if testCase.observation == domain.DurableObservationP0Staged {
				material = stagedMaterial
			}
			if testCase.observation == domain.DurableObservationP2Committed {
				material = p2Material
			}
			withMaterial, withMaterialErr := NewPublicationObservationWithRecovery(
				testCase.journalState,
				testCase.observation,
				storedNormalExit,
				ambiguityReasons,
				1,
				material,
			)
			if got := withMaterialErr == nil; got != testCase.requiresMaterial {
				t.Fatalf("material observation accepted = %t, want %t: %v", got, testCase.requiresMaterial, withMaterialErr)
			}
			if withMaterialErr == nil {
				recovered, ok := withMaterial.RecoveryMaterial()
				if !ok || !recovered.Valid() || recovered.Final().Identity() != final {
					t.Fatalf("recovery material = (%#v, %t)", recovered, ok)
				}
				recoveredJournal := recovered.Journal().Bytes()
				recoveredJournal[0] = '!'
				recoveredAgain, ok := withMaterial.RecoveryMaterial()
				if !ok || string(recoveredAgain.Journal().Bytes()) != `{"persisted_journal_state":"content_validated"}` {
					t.Fatalf("observation recovery accessor leaked journal bytes = (%#v, %t)", recoveredAgain, ok)
				}
			}
		})
	}

	if _, err := NewPublicationObservationWithRecovery(
		domain.JournalFinalStaged,
		domain.DurableObservationP0Staged,
		nil,
		nil,
		1,
		restageMaterial,
	); err == nil {
		t.Error("P0 staged observation accepted material without a staged path")
	}
	if _, err := NewPublicationObservationWithRecovery(
		domain.JournalFinalFileInstalled,
		domain.DurableObservationP1Installed,
		nil,
		nil,
		1,
		stagedMaterial,
	); err == nil {
		t.Error("P1 installed observation accepted a staged path")
	}
	if _, err := NewPublicationObservationWithRecovery(
		domain.JournalContentValidated,
		domain.DurableObservationP0None,
		nil,
		nil,
		1,
		stagedMaterial,
	); err == nil {
		t.Error("P0 none restage observation accepted a staged path")
	}
}

func publicationObservationInput(
	observation domain.DurableObservationClass,
) (*domain.OperationalExitCode, []string) {
	switch observation {
	case domain.DurableObservationP2Committed:
		storedNormalExit := domain.ExitCommittedPass
		return &storedNormalExit, nil
	case domain.DurableObservationAmbiguousOrMismatch:
		return nil, []string{"artifact_mismatch"}
	default:
		return nil, nil
	}
}
func TestPreparedPublicationPortContracts(t *testing.T) {
	t.Parallel()

	run := publicationTestRun(t)
	finalBytes := []byte(`{"schema_version":"mulgae-review-artifact.v1"}`)
	final := publicationTestFinal(t, finalBytes)
	finalArtifact, err := NewFinalReviewArtifact(final, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewPersistValidatedCandidateRequest(run, finalArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := candidate.Path().String(), run.SessionID().String()+"/"+run.RunID().String()+"/validation/final-candidate.json"; got != want {
		t.Fatalf("candidate path = %q, want %q", got, want)
	}
	candidateBytes := candidate.Candidate().Bytes()
	candidateBytes[0] = '!'
	if got := string(candidate.Candidate().Bytes()); got != string(finalBytes) {
		t.Fatalf("candidate accessor leaked bytes %q", got)
	}
	candidateReceipt := publicationTestReceipt(t, candidate.Path(), finalArtifact.Bytes())
	if _, err := NewPersistValidatedCandidateResult(finalArtifact, candidate.Path(), candidateReceipt, ValidatedCandidateUndurable); err != nil {
		t.Fatal(err)
	}

	excerpt := publicationTestArtifact(t, publicationTestPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/excerpts/F001.json"), []byte("excerpt"))
	if _, err := NewPersistAuxiliaryArtifactRequest(run, excerpt); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistAuxiliaryArtifactRequest(run, publicationTestArtifact(t, final.Path(), []byte("not excerpt"))); err == nil {
		t.Fatal("non-excerpt auxiliary artifact accepted")
	}
	exactRead, err := NewReadAuxiliaryArtifactRequest(run, excerpt.Path(), excerpt.SHA256(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := exactRead.ExpectedSHA256(); !ok || got != excerpt.SHA256() {
		t.Fatalf("exact read hash = (%q, %t), want (%q, true)", got, ok, excerpt.SHA256())
	}
	pathOnlyRead, err := NewReadAuxiliaryArtifactRequest(run, excerpt.Path(), "", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := pathOnlyRead.ExpectedSHA256(); ok || got != "" {
		t.Fatalf("path-only read hash = (%q, %t), want (empty, false)", got, ok)
	}
	if _, err := NewReadAuxiliaryArtifactRequest(run, excerpt.Path(), "sha256:INVALID", 1024); err == nil {
		t.Fatal("invalid non-empty read hash accepted")
	}

	manifest := publicationTestArtifact(t, publicationTestPath(t, run.SessionID().String()+"/"+run.RunID().String()+"/manifest.json"), []byte("manifest"))
	lineage := publicationTestArtifact(t, publicationTestPath(t, "store/lineage-edges/e_019f596a-d174-7321-b920-c2d312c82cc2.json"), []byte("lineage"))
	epochRecord := publicationTestArtifact(t, publicationTestPath(t, "store/epochs/epoch_00000000000000000001.json"), []byte("epoch"))
	epoch, err := NewPublicationEpoch(1, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	composite, err := NewCommitCompositeRequest(run, final, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := prepare.StagedManifestPath().String(), run.SessionID().String()+"/"+run.RunID().String()+"/publication/staged/manifest.json.tmp"; got != want {
		t.Fatalf("staged manifest path = %q, want %q", got, want)
	}
	stagedManifest := publicationTestArtifact(t, prepare.StagedManifestPath(), manifest.Bytes())
	stagedLineage := publicationTestArtifact(t, prepare.StagedLineageEdgePath(), lineage.Bytes())
	stagedEpoch := publicationTestArtifact(t, prepare.StagedEpochPath(), epoch.Record().Bytes())
	prepared, err := NewPreparedComposite(prepare, stagedManifest, stagedLineage, stagedEpoch, []SecureWriteReceipt{
		publicationTestReceipt(t, stagedManifest.Path(), stagedManifest.Bytes()),
		publicationTestReceipt(t, stagedLineage.Path(), stagedLineage.Bytes()),
		publicationTestReceipt(t, stagedEpoch.Path(), stagedEpoch.Bytes()),
	}, CompositePreparationUndurable)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Valid() || prepared.Durability() != CompositePreparationUndurable {
		t.Fatalf("prepared composite = %#v", prepared)
	}
}
func TestPublicationStoreInterfaceIsSegregated(t *testing.T) {
	var _ PublicationStore = publicationStoreContractFake{}
	var _ AuxiliaryArtifactStore = publicationStoreContractFake{}
}
func TestClassifyRunSupportArtifactPathRequiresCanonicalSupportIndex(t *testing.T) {
	t.Parallel()

	run := publicationTestRun(t)
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	cases := []struct {
		name  string
		path  string
		valid bool
	}{
		{"canonical", prefix + "support/index.json", true},
		{"wrong name", prefix + "support/index.v1.json", false},
		{"nested", prefix + "support/nested/index.json", false},
		{"wrong root", "other/" + run.RunID().String() + "/support/index.json", false},
		{"prompt lookalike", prefix + "prompts/support/index.json", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path, err := NewSafeRelativePath(test.path)
			if err != nil {
				t.Fatal(err)
			}
			kind, err := ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
			if test.valid {
				if err != nil || kind != RunSupportArtifactSupportIndex {
					t.Fatalf("ClassifyRunSupportArtifactPath(%q) = %q, %v", test.path, kind, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ClassifyRunSupportArtifactPath(%q) accepted %q", test.path, kind)
			}
		})
	}
}

func TestClassifyRunSupportArtifactPathAcceptsCanonicalArtistInputs(t *testing.T) {
	t.Parallel()
	run := publicationTestRun(t)
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/inputs/"
	for _, test := range []struct {
		path string
		kind RunSupportArtifactKind
	}{
		{prefix + "artist-brief.md", RunSupportArtifactArtistBrief},
		{prefix + "artist-visual-assets.json", RunSupportArtifactArtistVisuals},
	} {
		path, err := NewSafeRelativePath(test.path)
		if err != nil {
			t.Fatal(err)
		}
		kind, err := ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
		if err != nil || kind != test.kind {
			t.Fatalf("ClassifyRunSupportArtifactPath(%q) = %q, %v", test.path, kind, err)
		}
	}
}

type publicationStoreContractFake struct{}

func (publicationStoreContractFake) IssueReviewID(context.Context, IssueReviewIDRequest) (IssuedReviewID, error) {
	return IssuedReviewID{}, nil
}

func (publicationStoreContractFake) ResolveRun(context.Context, ResolvePublicationRunRequest) (PublicationRun, error) {
	return PublicationRun{}, nil
}

func (publicationStoreContractFake) ObserveRun(context.Context, ObserveRunRequest) (PublicationObservation, error) {
	return PublicationObservation{}, nil
}
func (publicationStoreContractFake) PersistValidatedCandidate(context.Context, PersistValidatedCandidateRequest) (PersistValidatedCandidateResult, error) {
	return PersistValidatedCandidateResult{}, nil
}

func (publicationStoreContractFake) PersistAuxiliaryArtifact(context.Context, PersistAuxiliaryArtifactRequest) (PersistAuxiliaryArtifactResult, error) {
	return PersistAuxiliaryArtifactResult{}, nil
}

func (publicationStoreContractFake) ReadAuxiliaryArtifact(context.Context, ReadAuxiliaryArtifactRequest) (ImmutablePublicationArtifact, error) {
	return ImmutablePublicationArtifact{}, nil
}

func (publicationStoreContractFake) PrepareComposite(context.Context, PrepareCompositeRequest) (PreparedComposite, error) {
	return PreparedComposite{}, nil
}

func (publicationStoreContractFake) StageFinal(context.Context, StageFinalRequest) (StageFinalResult, error) {
	return StageFinalResult{}, nil
}
func (publicationStoreContractFake) AdoptStagedFinal(context.Context, AdoptStagedFinalRequest) (StageFinalResult, error) {
	return StageFinalResult{}, nil
}

func (publicationStoreContractFake) InstallFinal(context.Context, InstallFinalRequest) (InstallFinalResult, error) {
	return InstallFinalResult{}, nil
}

func (publicationStoreContractFake) ReplaceMutable(context.Context, MutableReplaceRequest) (MutableReplaceResult, error) {
	return MutableReplaceResult{}, nil
}

func (publicationStoreContractFake) CommitPreparedComposite(context.Context, PreparedComposite) (CompositeCommitResult, error) {
	return CompositeCommitResult{}, nil
}

func (publicationStoreContractFake) ReadCommittedSnapshot(context.Context, ReadCommittedSnapshotRequest) (CommittedPublicationSnapshot, error) {
	return CommittedPublicationSnapshot{}, nil
}

func (publicationStoreContractFake) WriteCorruptionDiagnostic(context.Context, CorruptionDiagnosticRequest) (CorruptionDiagnosticResult, error) {
	return CorruptionDiagnosticResult{}, nil
}

func publicationTestRun(t *testing.T) PublicationRun {
	t.Helper()
	root, err := NewAnchoredRoot("/tmp/mulgae-publication-contract")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	run, err := NewPublicationRun(root, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func publicationTestFinal(t *testing.T, bytes []byte) FinalReviewIdentity {
	t.Helper()
	reviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewFinalReviewIdentity(
		reviewID,
		publicationTestPath(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-d174-7321-b920-c2d312c82cc2.json"),
		sha256Identifier(bytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func publicationTestIssued(t *testing.T, final FinalReviewIdentity) IssuedReviewID {
	t.Helper()
	issued, err := NewIssuedReviewID(final.ReviewID(), final.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
func publicationTestPath(t *testing.T, value string) SafeRelativePath {
	t.Helper()
	path, err := NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func publicationTestArtifact(t *testing.T, path SafeRelativePath, bytes []byte) ImmutablePublicationArtifact {
	t.Helper()
	artifact, err := NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func publicationTestReceipt(t *testing.T, path SafeRelativePath, bytes []byte) SecureWriteReceipt {
	t.Helper()
	receipt, err := NewSecureWriteReceipt(publicationTestRun(t).Root(), path, sha256Identifier(bytes), int64(len(bytes)), "publication", []string{"validated_candidate"})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func publicationTestCorruptionCAS(t *testing.T, epoch uint64, reasons []string) CorruptionObservationCAS {
	t.Helper()
	observation, err := NewPublicationObservation(
		domain.JournalCollecting,
		domain.DurableObservationAmbiguousOrMismatch,
		nil,
		reasons,
		epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := NewCorruptionObservationCAS(observation)
	if err != nil {
		t.Fatal(err)
	}
	return cas
}
