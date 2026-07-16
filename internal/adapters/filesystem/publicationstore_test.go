//go:build darwin && arm64

package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

func TestPublicationJournalWireRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot("/tmp/kar-publication-store-test")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, session, runID)
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	reviewID := "019f596a-d174-7321-b920-c2d312c82cc2"
	prefix := session.String() + "/" + runID.String()
	journalPath := mustPublicationSafePath(prefix + "/publication/journal.json")
	valid := fmt.Sprintf(`{"schema_version":"kar-publication-journal.v1","session_id":%q,"run_id":%q,"persisted_journal_state":"final_staged","expected_staged":{"path":%q,"sha256":%q},"expected_final":{"path":%q,"sha256":%q},"validated_candidate_sha256":%q,"store_epoch":7,"normal_exit":0,"manifest_path":%q,"lineage_edge_path":%q,"epoch_path":%q}`,
		session.String(), runID.String(), prefix+"/publication/staged/review_"+reviewID+".json.tmp", hash,
		prefix+"/review_"+reviewID+".json", hash, hash, prefix+"/manifest.json", "store/lineage-edges/e_"+reviewID+".json", "store/epochs/epoch_00000000000000000007.json")
	if _, facts, err := parsePublicationJournal(run, journalPath, []byte(valid)); err != nil {
		t.Fatalf("valid journal rejected: %v", err)
	} else if facts.validatedCandidateSHA256 != hash {
		t.Fatalf("validated candidate hash = %q, want %q", facts.validatedCandidateSHA256, hash)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"schema_version":`, `"unknown":true,"schema_version":`, 1),
		strings.Replace(valid, `"schema_version":`, `"schema_version":"kar-publication-journal.v1","schema_version":`, 1),
		valid + " {}",
	} {
		if _, _, err := parsePublicationJournal(run, journalPath, []byte(raw)); err == nil {
			t.Fatalf("invalid strict journal accepted: %s", raw)
		}
	}
}
func TestPublicationStorePersistsCandidateAndAuxiliaryArtifacts(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	ctx := context.Background()

	candidateRequest, err := ports.NewPersistValidatedCandidateRequest(fixture.run, fixture.final)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.store.PersistValidatedCandidate(ctx, candidateRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.Valid() || candidate.Durability() != ports.ValidatedCandidateDurable {
		t.Fatalf("candidate result = %#v", candidate)
	}
	assertPrivateRegularFile(t, filepath.Join(fixture.root, candidate.Path().String()))
	assertPrivateDirectory(t, filepath.Join(fixture.root, fixture.run.SessionID().String(), fixture.run.RunID().String(), "validation"))
	if _, err := fixture.store.PersistValidatedCandidate(ctx, candidateRequest); err == nil {
		t.Fatal("candidate collision was accepted")
	}
	if got, err := os.ReadFile(filepath.Join(fixture.root, candidate.Path().String())); err != nil || !bytes.Equal(got, fixture.final.Bytes()) {
		t.Fatalf("candidate collision replaced durable bytes = %q, %v", got, err)
	}

	excerptPath := mustRelativePath(t, fixture.run.SessionID().String()+"/"+fixture.run.RunID().String()+"/excerpts/F001.json")
	excerptBytes := []byte(`{"finding":"F001","excerpt":"exact"}`)
	excerpt, err := ports.NewImmutablePublicationArtifact(excerptPath, publicationSHA256(excerptBytes), excerptBytes)
	if err != nil {
		t.Fatal(err)
	}
	persistRequest, err := ports.NewPersistAuxiliaryArtifactRequest(fixture.run, excerpt)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := fixture.store.PersistAuxiliaryArtifact(ctx, persistRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Valid() || persisted.Durability() != ports.AuxiliaryArtifactDurable {
		t.Fatalf("auxiliary result = %#v", persisted)
	}
	assertPrivateRegularFile(t, filepath.Join(fixture.root, excerptPath.String()))
	assertPrivateDirectory(t, filepath.Join(fixture.root, fixture.run.SessionID().String(), fixture.run.RunID().String(), "excerpts"))
	readRequest, err := ports.NewReadAuxiliaryArtifactRequest(fixture.run, excerptPath, excerpt.SHA256(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	read, err := fixture.store.ReadAuxiliaryArtifact(ctx, readRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read.Bytes(), excerptBytes) {
		t.Fatalf("auxiliary bytes = %q, want %q", read.Bytes(), excerptBytes)
	}
	if _, err := fixture.store.PersistAuxiliaryArtifact(ctx, persistRequest); err == nil {
		t.Fatal("auxiliary collision was accepted")
	}
	if err := os.WriteFile(filepath.Join(fixture.root, excerptPath.String()), []byte(`{"tampered":true}`), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReadAuxiliaryArtifact(ctx, readRequest); err == nil {
		t.Fatal("tampered auxiliary artifact was accepted")
	}
}
func TestPublicationStoreReadAuxiliaryArtifactDistinguishesAbsenceAndCorruption(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	path := mustRelativePath(t, fixture.run.SessionID().String()+"/"+fixture.run.RunID().String()+"/excerpts/F001.json")
	expectedBytes := []byte(`{"finding":"F001","excerpt":"expected"}`)
	artifact, err := ports.NewImmutablePublicationArtifact(path, publicationSHA256(expectedBytes), expectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewReadAuxiliaryArtifactRequest(fixture.run, path, artifact.SHA256(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReadAuxiliaryArtifact(context.Background(), request); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("canonical absent auxiliary error = %v, want fs.ErrNotExist", err)
	}
	persist, err := ports.NewPersistAuxiliaryArtifactRequest(fixture.run, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.PersistAuxiliaryArtifact(context.Background(), persist); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, path.String()), []byte(`{"finding":"F001","excerpt":"tampered"}`), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReadAuxiliaryArtifact(context.Background(), request); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("auxiliary hash corruption error = %v, want non-absence failure", err)
	}
	artifactPath := filepath.Join(fixture.root, path.String())
	if err := os.Remove(artifactPath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(fixture.root, "outside-excerpt.json")
	if err := os.WriteFile(outside, expectedBytes, privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, artifactPath); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReadAuxiliaryArtifact(context.Background(), request); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("auxiliary path/type corruption error = %v, want non-absence failure", err)
	}
}
func TestPublicationStoreRejectsReadCapsAboveAdapterLimit(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	if _, err := readPublicationFile(
		fixture.run.Root(),
		fixture.final.Identity().Path(),
		publicationMaximumReadBytes+1,
	); err == nil {
		t.Fatal("publication read accepted a cap above the adapter maximum")
	}
}

func TestPublicationStoreCorruptionDiagnosticIsDurablyIdempotent(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	fixture.writeJournal(t, domain.JournalCompleted)
	observation := fixture.observe(t)
	reasons := observation.ClassifierInput().AmbiguityReasons()
	if observation.ClassifierInput().Observation() != domain.DurableObservationAmbiguousOrMismatch ||
		len(reasons) != 1 {
		t.Fatalf("corruption observation = %#v", observation)
	}
	path := mustRelativePath(
		t,
		fmt.Sprintf(
			"%s/%s/recovery/diagnostics/publication-corrupt_%d.json",
			fixture.run.SessionID().String(),
			fixture.run.RunID().String(),
			observation.StoreEpoch(),
		),
	)
	payload := []byte(fmt.Sprintf(
		`{"schema_version":"kar-publication-corruption.v1","session_id":%q,"run_id":%q,"observation_epoch":%d,"reason_codes":[%q]}`,
		fixture.run.SessionID().String(),
		fixture.run.RunID().String(),
		observation.StoreEpoch(),
		reasons[0],
	))
	artifact, err := ports.NewImmutablePublicationArtifact(path, publicationSHA256(payload), payload)
	if err != nil {
		t.Fatal(err)
	}
	observationCAS, err := ports.NewCorruptionObservationCAS(observation)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewCorruptionDiagnosticRequest(
		fixture.run,
		observationCAS,
		artifact,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.store.WriteCorruptionDiagnostic(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.store.WriteCorruptionDiagnostic(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Valid() || !second.Valid() ||
		first.Durability() != ports.CorruptionDiagnosticDurable ||
		second.Durability() != ports.CorruptionDiagnosticDurable ||
		first.Diagnostic().SHA256() != second.Diagnostic().SHA256() {
		t.Fatal("idempotent diagnostic did not retain one durable identity")
	}
	if err := os.Remove(filepath.Join(fixture.root, publicationJournalPath(fixture.run).String())); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.WriteCorruptionDiagnostic(context.Background(), request); !errors.Is(err, ports.ErrCorruptionObservationStale) {
		t.Fatalf("stale diagnostic write error = %v", err)
	}

	tamperedBytes := []byte(fmt.Sprintf(
		`{"schema_version":"kar-publication-corruption.v1","session_id":%q,"run_id":%q,"observation_epoch":%d,"reason_codes":["other"]}`,
		fixture.run.SessionID().String(),
		fixture.run.RunID().String(),
		observation.StoreEpoch(),
	))
	tampered, err := ports.NewImmutablePublicationArtifact(path, publicationSHA256(tamperedBytes), tamperedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ports.NewCorruptionDiagnosticRequest(
		fixture.run,
		observationCAS,
		tampered,
	); err == nil {
		t.Fatal("diagnostic payload not bound to observed reasons")
	}
}
func TestPublicationStoreRejectsStagedFinalIdentitySubstitution(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	otherReviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc3")
	if err != nil {
		t.Fatal(err)
	}
	substitutedBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-review-artifact.v2","session_id":%q,"run_id":%q,"review_id":%q}`,
		fixture.run.SessionID().String(), fixture.run.RunID().String(), otherReviewID.String()))
	substitutedFinal, err := ports.NewFinalReviewIdentity(
		fixture.final.Identity().ReviewID(),
		fixture.final.Identity().Path(),
		publicationSHA256(substitutedBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ports.NewIssuedReviewID(substitutedFinal.ReviewID(), substitutedFinal.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewIssuedFinalBinding(issued, substitutedFinal)
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewStageFinalRequest(
		fixture.run,
		fixture.stagedPath,
		binding,
		bytes.NewReader(substitutedBytes),
		1<<20,
		[]string{"validated_candidate"},
		func(error) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.StageFinal(context.Background(), request); err == nil {
		t.Fatal("staged final identity substitution was accepted")
	}
}
func TestPublicationStoreRejectsMismatchedStagedStreamBeforeInstall(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	issued, err := ports.NewIssuedReviewID(
		fixture.final.Identity().ReviewID(),
		fixture.final.Identity().SHA256(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewIssuedFinalBinding(issued, fixture.final.Identity())
	if err != nil {
		t.Fatal(err)
	}
	streamed := append(fixture.final.Bytes(), ' ')
	aborts := 0
	request, err := ports.NewStageFinalRequest(
		fixture.run,
		fixture.stagedPath,
		binding,
		bytes.NewReader(streamed),
		1<<20,
		[]string{"validated_candidate"},
		func(error) { aborts++ },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.StageFinal(context.Background(), request); err == nil {
		t.Fatal("mismatched staged stream was accepted")
	}
	if aborts != 1 {
		t.Fatalf("mismatched staged stream aborts = %d, want 1", aborts)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, fixture.stagedPath.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched staged stream installed canonical path: %v", err)
	}
}

func TestPublicationStoreClassifiesSecretRejectionAsSecurity(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	issued, err := ports.NewIssuedReviewID(
		fixture.final.Identity().ReviewID(),
		fixture.final.Identity().SHA256(),
	)
	if err != nil {
		t.Fatal(err)
	}
	secret := "KKACHI_PUBLICATION_SECRET_password=value_91dc0f2a"
	binding, err := ports.NewIssuedFinalBinding(issued, fixture.final.Identity())
	if err != nil {
		t.Fatal(err)
	}
	var abortCause error
	request, err := ports.NewStageFinalRequest(
		fixture.run,
		fixture.stagedPath,
		binding,
		strings.NewReader(secret),
		int64(len(secret)),
		[]string{"validated_candidate"},
		func(cause error) { abortCause = cause },
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.store.StageFinal(context.Background(), request)
	var classified interface {
		PublicationFailureClass() domain.FailureClass
	}
	if !errors.Is(err, ErrSecretDetected) || !errors.As(err, &classified) ||
		classified.PublicationFailureClass() != domain.FailureSecurityPolicy {
		t.Fatalf("secret rejection = %v, class carrier = %#v", err, classified)
	}
	if result.Valid() || abortCause == nil ||
		strings.Contains(abortCause.Error(), secret) || strings.Contains(err.Error(), secret) {
		t.Fatal("secret rejection exposed triggering bytes, omitted abort cause, or returned a receipt")
	}
}

func TestPublicationStoreSeparatesValidatedCandidateAndFinalHashes(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	candidateHash := publicationSHA256([]byte("validated semantic candidate before ReviewID issuance"))
	if candidateHash == fixture.final.Identity().SHA256() {
		t.Fatal("test requires distinct candidate and final hashes")
	}
	issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), candidateHash)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
	if err != nil {
		t.Fatal(err)
	}
	if !staged.Valid() || staged.Final() != fixture.final.Identity() {
		t.Fatal("staged final did not retain the post-issuance final identity")
	}
}

func TestPublicationStorePreparesCommitsAndRecoversFromDisk(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	ctx := context.Background()
	persistPublicationCandidate(t, fixture)

	prepared, err := fixture.store.PrepareComposite(ctx, fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Valid() || prepared.Durability() != ports.CompositePreparationDurable {
		t.Fatalf("prepared composite = %#v", prepared)
	}
	for _, path := range []ports.SafeRelativePath{
		prepared.StagedManifest().Path(),
		prepared.StagedLineageEdge().Path(),
		prepared.StagedEpoch().Path(),
	} {
		assertPrivateRegularFile(t, filepath.Join(fixture.root, path.String()))
	}
	assertPrivateDirectory(t, filepath.Join(fixture.root, fixture.run.SessionID().String(), fixture.run.RunID().String(), "publication", "staged"))

	fixture.writeJournal(t, domain.JournalContentValidated)
	observeP0None := fixture.observe(t)
	if observeP0None.ClassifierInput().Observation() != domain.DurableObservationP0None {
		t.Fatalf("content-validated observation = %q", observeP0None.ClassifierInput().Observation())
	}
	assertRecoveryMaterial(t, fixture, observeP0None, false)
	if next := fixture.observe(t); next.ClassifierInput().Observation() != observeP0None.ClassifierInput().Observation() || next.ClassifierInput().JournalState() != observeP0None.ClassifierInput().JournalState() || next.StoreEpoch() != observeP0None.StoreEpoch() {
		t.Fatal("P0_NONE observation was not idempotent")
	}

	issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
	if err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.store.StageFinal(ctx, mustStageFinalRequest(t, fixture, issued))
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeJournal(t, domain.JournalFinalStaged)
	observeP0 := fixture.observe(t)
	if observeP0.ClassifierInput().Observation() != domain.DurableObservationP0Staged {
		t.Fatalf("staged observation = %q", observeP0.ClassifierInput().Observation())
	}
	assertRecoveryMaterial(t, fixture, observeP0, true)
	binding, err := ports.NewIssuedFinalBinding(issued, fixture.final.Identity())
	if err != nil {
		t.Fatal(err)
	}
	adoptRequest, err := ports.NewAdoptStagedFinalRequest(
		fixture.run,
		fixture.stagedPath,
		binding,
		fixture.final,
		int64(len(fixture.final.Bytes())),
	)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := fixture.store.AdoptStagedFinal(ctx, adoptRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !adopted.Valid() || adopted.Durability() != ports.StageFinalDurable ||
		adopted.StagedPath() != staged.StagedPath() ||
		adopted.Final() != staged.Final() {
		t.Fatalf("adopted staged final = %#v", adopted)
	}

	installed, err := fixture.store.InstallFinal(ctx, mustPublicationInstallRequest(t, fixture.run, adopted))
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Valid() {
		t.Fatal("install result is invalid")
	}
	fixture.writeJournal(t, domain.JournalFinalFileInstalled)
	observeP1 := fixture.observe(t)
	if observeP1.ClassifierInput().Observation() != domain.DurableObservationP1Installed {
		t.Fatalf("installed observation = %q", observeP1.ClassifierInput().Observation())
	}
	assertRecoveryMaterial(t, fixture, observeP1, false)

	committed, err := fixture.store.CommitPreparedComposite(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Valid() || committed.Phase() != ports.CompositeCommittedDurable {
		t.Fatalf("commit result = %#v", committed)
	}
	for _, path := range []ports.SafeRelativePath{
		prepared.StagedManifest().Path(),
		prepared.StagedLineageEdge().Path(),
		prepared.StagedEpoch().Path(),
	} {
		if _, err := os.Lstat(filepath.Join(fixture.root, path.String())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("moved staged source remains at %q: %v", path, err)
		}
	}
	observeP2 := fixture.observe(t)
	if observeP2.ClassifierInput().Observation() != domain.DurableObservationP2Committed {
		t.Fatalf("P2 observation = %q", observeP2.ClassifierInput().Observation())
	}
	if next := fixture.observe(t); next.ClassifierInput().Observation() != observeP2.ClassifierInput().Observation() || next.ClassifierInput().JournalState() != observeP2.ClassifierInput().JournalState() || next.StoreEpoch() != observeP2.StoreEpoch() {
		t.Fatal("P2 observation was not idempotent")
	}
	journalPath := publicationJournalPath(fixture.run)
	if err := os.Remove(filepath.Join(fixture.root, journalPath.String())); err != nil {
		t.Fatal(err)
	}
	missingJournal := fixture.observe(t)
	if missingJournal.ClassifierInput().Observation() != domain.DurableObservationP2Committed {
		t.Fatalf("missing-journal P2 observation = %q", missingJournal.ClassifierInput().Observation())
	}
	missingMaterial, ok := missingJournal.RecoveryMaterial()
	if !ok || missingMaterial.Journal().Present() {
		t.Fatal("missing mutable journal revoked P2 or was reported present")
	}
	writePrivatePublicationTestFile(
		t,
		fixture.writer,
		fixture.run.Root(),
		journalPath,
		[]byte("{"),
	)
	malformedJournal := fixture.observe(t)
	if malformedJournal.ClassifierInput().Observation() != domain.DurableObservationP2Committed {
		t.Fatalf("malformed-journal P2 observation = %q", malformedJournal.ClassifierInput().Observation())
	}
	malformedMaterial, ok := malformedJournal.RecoveryMaterial()
	if !ok || !malformedMaterial.Journal().Present() ||
		!bytes.Equal(malformedMaterial.Journal().Bytes(), []byte("{")) {
		t.Fatal("malformed mutable journal was not retained for P2 CAS reconstruction")
	}
	if err := os.Remove(filepath.Join(fixture.root, journalPath.String())); err != nil {
		t.Fatal(err)
	}
	unreadableJournalTarget := filepath.Join(fixture.root, "unreadable-journal.json")
	if err := os.WriteFile(unreadableJournalTarget, []byte(`{"outside":true}`), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unreadableJournalTarget, filepath.Join(fixture.root, journalPath.String())); err != nil {
		t.Fatal(err)
	}
	unreadableJournal := fixture.observe(t)
	if unreadableJournal.ClassifierInput().Observation() != domain.DurableObservationP2Committed {
		t.Fatalf("unreadable-journal P2 observation = %q", unreadableJournal.ClassifierInput().Observation())
	}
	unreadableJournalMaterial, ok := unreadableJournal.RecoveryMaterial()
	if !ok || unreadableJournalMaterial.Journal().Present() {
		t.Fatal("unreadable mutable journal was not retained as missing P2 repair material")
	}
	replacement := []byte(`{"replacement":true}`)
	replaceRequest, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		journalPath,
		ports.ExpectMutableAbsent(),
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReplaceMutable(context.Background(), replaceRequest); err == nil {
		t.Fatal("unreadable journal was treated as safely absent for mutable replacement")
	}
	if err := os.Remove(filepath.Join(fixture.root, journalPath.String())); err != nil {
		t.Fatal(err)
	}
	statusPath := publicationStatusPath(fixture.run)
	unreadableStatusTarget := filepath.Join(fixture.root, "unreadable-status.json")
	if err := os.WriteFile(unreadableStatusTarget, []byte(`{"outside":true}`), privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unreadableStatusTarget, filepath.Join(fixture.root, statusPath.String())); err != nil {
		t.Fatal(err)
	}
	unreadableStatus := fixture.observe(t)
	if unreadableStatus.ClassifierInput().Observation() != domain.DurableObservationP2Committed {
		t.Fatalf("unreadable-status P2 observation = %q", unreadableStatus.ClassifierInput().Observation())
	}
	unreadableStatusMaterial, ok := unreadableStatus.RecoveryMaterial()
	status, hasStatus := unreadableStatusMaterial.Status()
	if !ok || !hasStatus || status.Present() {
		t.Fatal("unreadable mutable status was not retained as missing P2 repair material")
	}
	snapshotRequest, err := ports.NewReadCommittedSnapshotRequest(fixture.run, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.store.ReadCommittedSnapshot(ctx, snapshotRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Valid() || !bytes.Equal(snapshot.Final().Bytes(), fixture.final.Bytes()) ||
		!bytes.Equal(snapshot.Manifest().Bytes(), fixture.composite.Manifest().Bytes()) ||
		!bytes.Equal(snapshot.LineageEdge().Bytes(), fixture.composite.LineageEdge().Bytes()) ||
		!bytes.Equal(snapshot.Epoch().Record().Bytes(), fixture.composite.Epoch().Record().Bytes()) {
		t.Fatal("P2 snapshot did not preserve every verified durable member")
	}
}
func TestPublicationStoreResumesExactPersistedCompositeMembers(t *testing.T) {
	t.Run("manifest-only", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)

		renames := 0
		fixture.store.operations.renameatxNp = func(sourceDirectory int, sourceName string, targetDirectory int, targetName string, flags uint32) error {
			renames++
			if renames == 2 {
				return errors.New("injected lineage move failure")
			}
			return unix.RenameatxNp(sourceDirectory, sourceName, targetDirectory, targetName, flags)
		}
		result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
		if err == nil || !result.Valid() || result.Phase() != ports.CompositeManifestInstalled {
			t.Fatalf("manifest-only result = (%#v, %v)", result, err)
		}

		observation := fixture.observe(t)
		if observation.ClassifierInput().Observation() != domain.DurableObservationP1Installed {
			t.Fatalf("manifest-only observation = %q", observation.ClassifierInput().Observation())
		}
		material, ok := observation.RecoveryMaterial()
		if !ok {
			t.Fatal("manifest-only recovery material is absent")
		}
		recovered, ok := material.PreparedComposite()
		if !ok {
			t.Fatal("manifest-only prepared bytes are absent")
		}
		fixture.store.operations.renameatxNp = nil
		result, err = fixture.store.CommitPreparedComposite(context.Background(), recovered)
		if err != nil || !result.Valid() || result.Phase() != ports.CompositeCommittedDurable {
			t.Fatalf("manifest-only resume = (%#v, %v)", result, err)
		}
		if got := fixture.observe(t).ClassifierInput().Observation(); got != domain.DurableObservationP2Committed {
			t.Fatalf("manifest-only resumed observation = %q", got)
		}
	})

	t.Run("manifest-and-lineage", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)

		fixture.store.operations.fsync = func(int) error {
			return errors.New("injected member durability failure")
		}
		result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
		if err == nil || !result.Valid() || result.Phase() != ports.CompositeMembersInstalled {
			t.Fatalf("members-installed result = (%#v, %v)", result, err)
		}
		observation := fixture.observe(t)
		if observation.ClassifierInput().Observation() != domain.DurableObservationP1Installed {
			t.Fatalf("members-installed observation = %q", observation.ClassifierInput().Observation())
		}
		material, ok := observation.RecoveryMaterial()
		if !ok {
			t.Fatal("members-installed recovery material is absent")
		}
		recovered, ok := material.PreparedComposite()
		if !ok {
			t.Fatal("members-installed prepared bytes are absent")
		}
		fixture.store.operations.fsync = nil
		result, err = fixture.store.CommitPreparedComposite(context.Background(), recovered)
		if err != nil || !result.Valid() || result.Phase() != ports.CompositeCommittedDurable {
			t.Fatalf("members-installed resume = (%#v, %v)", result, err)
		}
	})

	t.Run("epoch-visible-but-undurable", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)

		syncs := 0
		fixture.store.operations.fsync = func(int) error {
			syncs++
			if syncs >= 4 {
				return errors.New("injected epoch durability failure")
			}
			return nil
		}
		result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
		if err == nil || !result.Valid() || result.Phase() != ports.CompositeEpochInstalledUndurable {
			t.Fatalf("epoch-undurable result = (%#v, %v)", result, err)
		}
		observation := fixture.observe(t)
		if observation.ClassifierInput().Observation() == domain.DurableObservationP2Committed {
			t.Fatal("visible epoch was promoted to P2 without durable adoption")
		}
		material, ok := observation.RecoveryMaterial()
		if !ok {
			t.Fatal("epoch-undurable recovery material is absent")
		}
		recovered, ok := material.PreparedComposite()
		if !ok {
			t.Fatal("epoch-undurable prepared bytes are absent")
		}
		fixture.store.operations.fsync = nil
		result, err = fixture.store.CommitPreparedComposite(context.Background(), recovered)
		if err != nil || !result.Valid() || result.Phase() != ports.CompositeCommittedDurable {
			t.Fatalf("epoch-undurable resume = (%#v, %v)", result, err)
		}
		if got := fixture.observe(t).ClassifierInput().Observation(); got != domain.DurableObservationP2Committed {
			t.Fatalf("epoch-undurable resumed observation = %q", got)
		}
	})
}

func TestPublicationStorePrepareCompositeReturnsPartialReceiptsAndResumes(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		t.Run(fmt.Sprintf("fail-member-%d", failAt), func(t *testing.T) {
			fixture := newPublicationStoreFixture(t)
			persistPublicationCandidate(t, fixture)
			failing := &failNthPublicationWriter{delegate: fixture.writer, failAt: failAt}
			fixture.store.writer = failing
			prepared, err := fixture.store.PrepareComposite(context.Background(), fixture.prepare)
			if err == nil || prepared.Valid() {
				t.Fatalf("partial preparation = (%#v, %v)", prepared, err)
			}
			var partial *PartialCompositePreparationError
			if !errors.As(err, &partial) || len(partial.Receipts()) != failAt-1 {
				t.Fatalf("partial receipts = %#v, error %v", partial, err)
			}
			fixture.store.writer = fixture.writer
			prepared, err = fixture.store.PrepareComposite(context.Background(), fixture.prepare)
			if err != nil || !prepared.Valid() ||
				prepared.Durability() != ports.CompositePreparationDurable ||
				len(prepared.Receipts()) != 3 {
				t.Fatalf("resumed preparation = (%#v, %v)", prepared, err)
			}
		})
	}
}

func TestPublicationStoreRejectsRecoveryAmbiguityAndDestinationCollision(t *testing.T) {
	t.Run("partial prepared composite", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		if err := os.Remove(filepath.Join(fixture.root, prepared.StagedEpoch().Path().String())); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousObservation(t, fixture.observe(t))
	})
	t.Run("non-prefix composite destinations", func(t *testing.T) {
		for _, testCase := range []struct {
			name    string
			members []int
		}{
			{name: "lineage-only", members: []int{1}},
			{name: "epoch-only", members: []int{2}},
			{name: "manifest-epoch-gap", members: []int{0, 2}},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				fixture, _ := preparedRecoveryFixture(t)
				installPublicationFinal(t, fixture)
				fixture.writeJournal(t, domain.JournalFinalFileInstalled)
				destinations := []ports.ImmutablePublicationArtifact{
					fixture.composite.Manifest(),
					fixture.composite.LineageEdge(),
					fixture.composite.Epoch().Record(),
				}
				for _, index := range testCase.members {
					destination := destinations[index]
					writePrivatePublicationTestFile(
						t,
						fixture.writer,
						fixture.run.Root(),
						destination.Path(),
						destination.Bytes(),
					)
				}
				assertAmbiguousReason(t, fixture.observe(t), "partial_composite")
			})
		}
	})
	t.Run("unjournaled prepared composite", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		persistPublicationCandidate(t, fixture)
		if _, err := fixture.store.PrepareComposite(context.Background(), fixture.prepare); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousObservation(t, fixture.observe(t))
	})
	t.Run("mismatched prepared composite", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.root, prepared.StagedEpoch().Path().String()), []byte(`{"schema_version":"wrong"}`), privateFileMode); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "prepared_composite_mismatch")
	})
	t.Run("tampered candidate bytes", func(t *testing.T) {
		fixture, _ := preparedRecoveryFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.root, candidatePath.String()), []byte(`{"schema_version":"wrong"}`), privateFileMode); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "candidate_mismatch")
	})
	t.Run("missing validated candidate", func(t *testing.T) {
		fixture, _ := preparedRecoveryFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(fixture.root, candidatePath.String())); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "candidate_missing")
	})
	t.Run("symlink candidate", func(t *testing.T) {
		fixture, _ := preparedRecoveryFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(fixture.root, "outside")
		if err := os.WriteFile(target, fixture.final.Bytes(), privateFileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(fixture.root, candidatePath.String())); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(fixture.root, candidatePath.String())); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousObservation(t, fixture.observe(t))
	})
	t.Run("symlink candidate directory", func(t *testing.T) {
		fixture, _ := preparedRecoveryFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(fixture.root, candidatePath.String())
		validationDirectory := filepath.Dir(candidate)
		if err := os.Remove(candidate); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(validationDirectory); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, filepath.Base(candidate)), fixture.final.Bytes(), privateFileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, validationDirectory); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "candidate_unsafe")
	})
	t.Run("nonregular candidate", func(t *testing.T) {
		fixture, _ := preparedRecoveryFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(fixture.root, candidatePath.String())
		if err := os.Remove(candidate); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(candidate, privateFileMode); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousObservation(t, fixture.observe(t))
	})
	t.Run("wrong mode prepared member", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		if err := os.Chmod(filepath.Join(fixture.root, prepared.StagedManifest().Path().String()), 0o644); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousObservation(t, fixture.observe(t))
	})
	t.Run("missing P2 epoch", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)
		if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
			t.Fatal(err)
		}
		fixture.writeJournal(t, domain.JournalManifestCommitted)
		if err := os.Remove(filepath.Join(fixture.root, fixture.composite.Epoch().Record().Path().String())); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "prepared_missing")
	})
	t.Run("tampered P2 manifest", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)
		if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.root, fixture.composite.Manifest().Path().String()), []byte(`{"schema_version":"wrong"}`), privateFileMode); err != nil {
			t.Fatal(err)
		}
		assertAmbiguousReason(t, fixture.observe(t), "composite_mismatch")
	})
	t.Run("destination collision", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.writeJournal(t, domain.JournalFinalFileInstalled)
		writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), fixture.composite.Manifest().Path(), []byte(`{"existing":true}`))
		if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err == nil {
			t.Fatal("prepared composite destination collision was accepted")
		}
		if _, err := os.Lstat(filepath.Join(fixture.root, prepared.StagedManifest().Path().String())); err != nil {
			t.Fatalf("collision consumed staged manifest: %v", err)
		}
	})
}

func TestPublicationStoreReportsInjectedUndurableCandidateAndPreparation(t *testing.T) {
	t.Run("candidate", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		fixture.observe(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		parts, _, err := splitDestination(candidatePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.writer.EnsurePrivateDir(fixture.run.Root(), parentPath(parts)); err != nil {
			t.Fatal(err)
		}
		injectPublicationPostInstallSyncFailure(fixture.writer, safeBasename(candidatePath))
		request, err := ports.NewPersistValidatedCandidateRequest(fixture.run, fixture.final)
		if err != nil {
			t.Fatal(err)
		}
		result, err := fixture.store.PersistValidatedCandidate(context.Background(), request)
		if err == nil || !result.Valid() || result.Durability() != ports.ValidatedCandidateUndurable {
			t.Fatalf("candidate undurable result = (%#v, %v)", result, err)
		}
		assertPublicationReceipt(
			t,
			result.Receipt(),
			fixture.run.Root(),
			candidatePath,
			fixture.final.Identity().SHA256(),
			len(fixture.final.Bytes()),
			"publication_validated_candidate",
			[]string{"publication_validated_candidate"},
		)
	})
	t.Run("candidate post-install verification", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		candidatePath, err := ports.ValidatedCandidatePath(fixture.run)
		if err != nil {
			t.Fatal(err)
		}
		operations := fixture.writer.operationSet()
		operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
			if err := unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
				return err
			}
			if newName != safeBasename(candidatePath) {
				return nil
			}
			return os.WriteFile(
				filepath.Join(fixture.root, candidatePath.String()),
				[]byte(`{"tampered":true}`),
				privateFileMode,
			)
		}
		fixture.writer.operations = operations
		request, err := ports.NewPersistValidatedCandidateRequest(fixture.run, fixture.final)
		if err != nil {
			t.Fatal(err)
		}
		result, err := fixture.store.PersistValidatedCandidate(context.Background(), request)
		if err == nil || result.Valid() {
			t.Fatalf("candidate post-install verification result = (%#v, %v), want invalid result and error", result, err)
		}
		if _, statErr := os.Lstat(filepath.Join(fixture.root, candidatePath.String())); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("tampered candidate cleanup = %v, want absent", statErr)
		}
	})
	t.Run("auxiliary post-install verification", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		path := mustRelativePath(
			t,
			fixture.run.SessionID().String()+"/"+fixture.run.RunID().String()+"/excerpts/injected.json",
		)
		payload := []byte(`{"excerpt":"clean"}`)
		artifact, err := ports.NewImmutablePublicationArtifact(
			path,
			publicationSHA256(payload),
			payload,
		)
		if err != nil {
			t.Fatal(err)
		}
		operations := fixture.writer.operationSet()
		operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
			if err := unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
				return err
			}
			if newName != safeBasename(path) {
				return nil
			}
			return os.WriteFile(
				filepath.Join(fixture.root, path.String()),
				[]byte(`{"excerpt":"tampered"}`),
				privateFileMode,
			)
		}
		fixture.writer.operations = operations
		request, err := ports.NewPersistAuxiliaryArtifactRequest(fixture.run, artifact)
		if err != nil {
			t.Fatal(err)
		}
		result, err := fixture.store.PersistAuxiliaryArtifact(context.Background(), request)
		if err == nil || result.Valid() {
			t.Fatalf("auxiliary post-install verification result = (%#v, %v), want invalid result and error", result, err)
		}
		if _, statErr := os.Lstat(filepath.Join(fixture.root, path.String())); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("tampered auxiliary cleanup = %v, want absent", statErr)
		}
	})
	t.Run("prepared composite", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		persistPublicationCandidate(t, fixture)
		stagedParts, _, err := splitDestination(fixture.prepare.StagedManifestPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.writer.EnsurePrivateDir(fixture.run.Root(), parentPath(stagedParts)); err != nil {
			t.Fatal(err)
		}
		injectPublicationPostInstallSyncFailure(fixture.writer, safeBasename(fixture.prepare.StagedManifestPath()))
		result, err := fixture.store.PrepareComposite(context.Background(), fixture.prepare)
		if err == nil || !result.Valid() || result.Durability() != ports.CompositePreparationUndurable {
			t.Fatalf("preparation undurable result = (%#v, %v)", result, err)
		}
		preparedArtifacts := []ports.ImmutablePublicationArtifact{
			result.StagedManifest(),
			result.StagedLineageEdge(),
			result.StagedEpoch(),
		}
		preparedChannels := []string{
			"publication_prepared_manifest",
			"publication_prepared_lineage_edge",
			"publication_prepared_epoch",
		}
		for index, receipt := range result.Receipts() {
			assertPublicationReceipt(
				t,
				receipt,
				fixture.run.Root(),
				preparedArtifacts[index].Path(),
				preparedArtifacts[index].SHA256(),
				len(preparedArtifacts[index].Bytes()),
				preparedChannels[index],
				[]string{preparedChannels[index]},
			)
		}
	})
	t.Run("composite members", func(t *testing.T) {
		fixture, prepared := preparedRecoveryFixture(t)
		installPublicationFinal(t, fixture)
		fixture.store.operations.fsync = func(int) error {
			return errors.New("injected composite directory sync failure")
		}
		result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
		if err == nil || !result.Valid() || result.Phase() != ports.CompositeMembersInstalled {
			t.Fatalf("members-undurable result = (%#v, %v)", result, err)
		}
		compositeArtifacts := []ports.ImmutablePublicationArtifact{
			fixture.composite.Manifest(),
			fixture.composite.LineageEdge(),
		}
		compositeChannels := []string{"publication_manifest", "publication_lineage_edge"}
		compositeSources := []string{"publication_prepared_manifest", "publication_prepared_lineage_edge"}
		for index, receipt := range result.Receipts() {
			assertPublicationReceipt(
				t,
				receipt,
				fixture.run.Root(),
				compositeArtifacts[index].Path(),
				compositeArtifacts[index].SHA256(),
				len(compositeArtifacts[index].Bytes()),
				compositeChannels[index],
				[]string{compositeSources[index]},
			)
		}
	})
}
func TestPublicationStoreFinalInstallIsNoReplaceAndReportsSyncUncertainty(t *testing.T) {
	t.Run("no replace", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		persistPublicationCandidate(t, fixture)
		issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
		if err != nil {
			t.Fatal(err)
		}
		staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
		if err != nil {
			t.Fatal(err)
		}
		prior := []byte(`{"prior":"immutable"}`)
		writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), fixture.final.Identity().Path(), prior)
		if _, err := fixture.store.InstallFinal(context.Background(), mustPublicationInstallRequest(t, fixture.run, staged)); err == nil {
			t.Fatal("final destination collision was accepted")
		}
		if got, err := os.ReadFile(filepath.Join(fixture.root, fixture.final.Identity().Path().String())); err != nil || !bytes.Equal(got, prior) {
			t.Fatalf("final collision replaced existing bytes = %q, %v", got, err)
		}
		assertPrivateRegularFile(t, filepath.Join(fixture.root, staged.StagedPath().String()))
	})
	t.Run("post-install sync", func(t *testing.T) {
		fixture := newPublicationStoreFixture(t)
		persistPublicationCandidate(t, fixture)
		issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
		if err != nil {
			t.Fatal(err)
		}
		staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
		if err != nil {
			t.Fatal(err)
		}
		fixture.store.operations.fsync = func(int) error {
			return errors.New("injected final install directory sync failure")
		}
		result, err := fixture.store.InstallFinal(context.Background(), mustPublicationInstallRequest(t, fixture.run, staged))
		if err == nil || !result.Valid() || result.Durability() != ports.InstallFinalUndurable {
			t.Fatalf("final-install undurable result = (%#v, %v)", result, err)
		}
		assertPublicationReceipt(
			t,
			result.Receipt(),
			fixture.run.Root(),
			fixture.final.Identity().Path(),
			fixture.final.Identity().SHA256(),
			len(fixture.final.Bytes()),
			"publication_final_install",
			[]string{"validated_candidate"},
		)
		if got, readErr := os.ReadFile(filepath.Join(fixture.root, fixture.final.Identity().Path().String())); readErr != nil || !bytes.Equal(got, fixture.final.Bytes()) {
			t.Fatalf("undurable final bytes = %q, %v", got, readErr)
		}
		if _, statErr := os.Lstat(filepath.Join(fixture.root, staged.StagedPath().String())); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("undurable install retained staged source: %v", statErr)
		}
	})
}
func TestPublicationStoreMutableCASRemainsFailClosed(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	replacement := []byte(`{"journal":"first"}`)
	request, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		publicationJournalPath(fixture.run),
		ports.ExpectMutableAbsent(),
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReplaceMutable(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReplaceMutable(context.Background(), request); err == nil {
		t.Fatal("mutable CAS accepted a stale absence expectation")
	}
	wrongExpected, err := ports.ExpectMutableSHA256(publicationSHA256([]byte(`{"journal":"other"}`)))
	if err != nil {
		t.Fatal(err)
	}
	next := []byte(`{"journal":"second"}`)
	mismatch, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		publicationJournalPath(fixture.run),
		wrongExpected,
		next,
		publicationSHA256(next),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ReplaceMutable(context.Background(), mismatch); err == nil {
		t.Fatal("mutable CAS accepted a mismatched hash expectation")
	}
	if got, err := os.ReadFile(filepath.Join(fixture.root, publicationJournalPath(fixture.run).String())); err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("mismatched mutable CAS changed bytes = %q, %v", got, err)
	}
}
func TestPublicationStoreSerializesConcurrentMutableCAS(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	replacement := []byte(`{"journal":"contended"}`)
	request, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		publicationJournalPath(fixture.run),
		ports.ExpectMutableAbsent(),
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := fixture.store.ReplaceMutable(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("contended mutable CAS results = (%v, %v), want exactly one success", first, second)
	}
}
func TestPublicationStoreFinalInstallRollsBackOnDestinationNamespaceSwap(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	persistPublicationCandidate(t, fixture)
	issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
	if err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
	if err != nil {
		t.Fatal(err)
	}
	runDirectory := filepath.Join(fixture.root, fixture.run.SessionID().String(), fixture.run.RunID().String())
	detached := filepath.Join(fixture.root, "detached-final-install")
	swapped := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
			return err
		}
		if swapped || flags != unix.RENAME_EXCL || destinationName != safeBasename(fixture.final.Identity().Path()) {
			return nil
		}
		swapped = true
		if err := os.Rename(runDirectory, detached); err != nil {
			return err
		}
		return os.Mkdir(runDirectory, privateDirectoryMode)
	}
	result, err := fixture.store.InstallFinal(context.Background(), mustPublicationInstallRequest(t, fixture.run, staged))
	if err == nil || result.Valid() {
		t.Fatalf("namespace-swapped final install = (%#v, %v), want no receipt", result, err)
	}
	if _, err := os.Lstat(filepath.Join(detached, "publication", "staged", safeBasename(staged.StagedPath()))); err != nil {
		t.Fatalf("exact rollback did not restore staged final: %v", err)
	}
}

func TestPublicationStoreMutableSwapRestoresInterveningPrior(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	path := publicationJournalPath(fixture.run)
	prior := []byte(`{"journal":"prior"}`)
	writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), path, prior)
	expected, err := ports.ExpectMutableSHA256(publicationSHA256(prior))
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte(`{"journal":"replacement"}`)
	request, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		path,
		expected,
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	intervening := []byte(`{"journal":"intervening"}`)
	injected := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if !injected && flags == unix.RENAME_SWAP && destinationName == safeBasename(path) {
			injected = true
			if err := os.WriteFile(filepath.Join(fixture.root, path.String()), intervening, privateFileMode); err != nil {
				return err
			}
		}
		return unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags)
	}
	result, err := fixture.store.ReplaceMutable(context.Background(), request)
	if err == nil || result.Valid() || !errors.Is(err, ports.ErrMutableCASConflict) {
		t.Fatalf("intervened mutable CAS = (%#v, %v), want conflict without receipt", result, err)
	}
	if got, err := os.ReadFile(filepath.Join(fixture.root, path.String())); err != nil || !bytes.Equal(got, intervening) {
		t.Fatalf("intervening prior was not restored exactly: %q, %v", got, err)
	}
}

func TestPublicationStoreCompositeRebindsSourceImmediatelyBeforeMove(t *testing.T) {
	fixture, prepared := preparedRecoveryFixture(t)
	installPublicationFinal(t, fixture)
	fixture.writeJournal(t, domain.JournalFinalFileInstalled)
	tampered := []byte(`{"schema_version":"tampered"}`)
	injected := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
			return err
		}
		if !injected && destinationName == safeBasename(fixture.composite.Manifest().Path()) {
			injected = true
			return os.WriteFile(
				filepath.Join(fixture.root, prepared.StagedLineageEdge().Path().String()),
				tampered,
				privateFileMode,
			)
		}
		return nil
	}
	result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
	if err == nil || !result.Valid() || result.Phase() != ports.CompositeManifestInstalled {
		t.Fatalf("rebound composite move = (%#v, %v), want manifest-only result", result, err)
	}
	if got, err := os.ReadFile(filepath.Join(fixture.root, prepared.StagedLineageEdge().Path().String())); err != nil || !bytes.Equal(got, tampered) {
		t.Fatalf("tampered lineage source was moved: %q, %v", got, err)
	}
}

func TestPublicationStoreP2RejectsAnyPreparedMember(t *testing.T) {
	for _, member := range []string{"manifest", "lineage", "epoch"} {
		t.Run(member, func(t *testing.T) {
			fixture, prepared := preparedRecoveryFixture(t)
			installPublicationFinal(t, fixture)
			fixture.writeJournal(t, domain.JournalFinalFileInstalled)
			if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
				t.Fatal(err)
			}
			var path ports.SafeRelativePath
			switch member {
			case "manifest":
				path = prepared.StagedManifest().Path()
			case "lineage":
				path = prepared.StagedLineageEdge().Path()
			default:
				path = prepared.StagedEpoch().Path()
			}
			writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), path, []byte(`{"prepared":true}`))
			assertAmbiguousObservation(t, fixture.observe(t))
			if _, err := fixture.store.PrepareComposite(context.Background(), fixture.prepare); err == nil {
				t.Fatal("post-P2 preparation was accepted")
			}
		})
	}
}

func TestPublicationStoreP2RejectsSymlinkAndModeMutationsForEveryImmutableMember(t *testing.T) {
	members := []struct {
		name string
		path func(publicationStoreTestFixture) ports.SafeRelativePath
	}{
		{name: "final", path: func(fixture publicationStoreTestFixture) ports.SafeRelativePath {
			return fixture.final.Identity().Path()
		}},
		{name: "manifest", path: func(fixture publicationStoreTestFixture) ports.SafeRelativePath {
			return fixture.composite.Manifest().Path()
		}},
		{name: "lineage", path: func(fixture publicationStoreTestFixture) ports.SafeRelativePath {
			return fixture.composite.LineageEdge().Path()
		}},
		{name: "epoch", path: func(fixture publicationStoreTestFixture) ports.SafeRelativePath {
			return fixture.composite.Epoch().Record().Path()
		}},
	}
	for _, mutation := range []string{"symlink", "mode"} {
		for _, member := range members {
			t.Run(mutation+"/"+member.name, func(t *testing.T) {
				fixture, prepared := preparedRecoveryFixture(t)
				installPublicationFinal(t, fixture)
				fixture.writeJournal(t, domain.JournalFinalFileInstalled)
				if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(fixture.root, member.path(fixture).String())
				switch mutation {
				case "symlink":
					attacker := filepath.Join(fixture.root, "p2-attacker-"+member.name)
					if err := os.WriteFile(attacker, []byte("attacker"), privateFileMode); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(attacker, path); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				observeRequest, err := ports.NewObserveRunRequest(fixture.run, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				observation, observeErr := fixture.store.ObserveRun(context.Background(), observeRequest)
				if observeErr == nil && observation.Valid() &&
					observation.ClassifierInput().Observation() == domain.DurableObservationP2Committed {
					t.Fatal("mutated immutable member retained P2 authority")
				}
				snapshotRequest, err := ports.NewReadCommittedSnapshotRequest(fixture.run, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, snapshotErr := fixture.store.ReadCommittedSnapshot(context.Background(), snapshotRequest)
				if snapshotErr == nil || snapshot.Valid() {
					t.Fatalf("mutated immutable member exposed snapshot = (%#v, %v)", snapshot, snapshotErr)
				}
			})
		}
	}
}

func TestPublicationStorePropagatesOperationalImmutableValidatorErrors(t *testing.T) {
	fixture, prepared := preparedRecoveryFixture(t)
	installPublicationFinal(t, fixture)
	fixture.writeJournal(t, domain.JournalFinalFileInstalled)
	if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("validator runtime unavailable")
	fixture.store.validator = publicationStoreErrorValidator{err: sentinel}
	request, err := ports.NewObserveRunRequest(fixture.run, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := fixture.store.ObserveRun(context.Background(), request)
	if !errors.Is(err, sentinel) || observation.Valid() {
		t.Fatalf("operational validator error = (%#v, %v), want propagated error", observation, err)
	}
}
func TestPublicationStoreTreatsDocumentValidatorErrorsAsCorruption(t *testing.T) {
	fixture, prepared := preparedRecoveryFixture(t)
	installPublicationFinal(t, fixture)
	fixture.writeJournal(t, domain.JournalFinalFileInstalled)
	if _, err := fixture.store.CommitPreparedComposite(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	fixture.store.validator = publicationStoreDocumentValidator{}
	request, err := ports.NewObserveRunRequest(fixture.run, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := fixture.store.ObserveRun(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	assertAmbiguousObservation(t, observation)
}
func TestPublicationStoreFinalInstallRollsBackOnRootNamespaceSwap(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	persistPublicationCandidate(t, fixture)
	issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
	if err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
	if err != nil {
		t.Fatal(err)
	}
	detached := fixture.root + "-detached-root"
	t.Cleanup(func() { _ = os.RemoveAll(detached) })
	swapped := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
			return err
		}
		if swapped || flags != unix.RENAME_EXCL || destinationName != safeBasename(fixture.final.Identity().Path()) {
			return nil
		}
		swapped = true
		if err := os.Rename(fixture.root, detached); err != nil {
			return err
		}
		return os.Mkdir(fixture.root, privateDirectoryMode)
	}
	result, err := fixture.store.InstallFinal(context.Background(), mustPublicationInstallRequest(t, fixture.run, staged))
	if err == nil || result.Valid() {
		t.Fatalf("root-swapped final install = (%#v, %v), want no receipt", result, err)
	}
	if _, err := os.Lstat(filepath.Join(detached, staged.StagedPath().String())); err != nil {
		t.Fatalf("root-swap rollback did not restore staged final: %v", err)
	}
}

func TestPublicationStoreAbsentMutableCASRollsBackNamespaceSwap(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	path := publicationJournalPath(fixture.run)
	replacement := []byte(`{"journal":"replacement"}`)
	request, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		path,
		ports.ExpectMutableAbsent(),
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(filepath.Join(fixture.root, path.String()))
	detached := directory + "-detached-absent"
	t.Cleanup(func() { _ = os.RemoveAll(detached) })
	swapped := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
			return err
		}
		if swapped || flags != unix.RENAME_EXCL || destinationName != safeBasename(path) {
			return nil
		}
		swapped = true
		if err := os.Rename(directory, detached); err != nil {
			return err
		}
		return os.Mkdir(directory, privateDirectoryMode)
	}
	result, err := fixture.store.ReplaceMutable(context.Background(), request)
	if err == nil || result.Valid() {
		t.Fatalf("absent CAS namespace swap = (%#v, %v), want no receipt", result, err)
	}
	if _, err := os.Lstat(filepath.Join(detached, safeBasename(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent CAS rollback retained replacement: %v", err)
	}
}

func TestPublicationStoreExistingMutableCASRollsBackNamespaceSwap(t *testing.T) {
	fixture := newPublicationStoreFixture(t)
	path := publicationJournalPath(fixture.run)
	prior := []byte(`{"journal":"prior"}`)
	writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), path, prior)
	expected, err := ports.ExpectMutableSHA256(publicationSHA256(prior))
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte(`{"journal":"replacement"}`)
	request, err := ports.NewMutableReplaceRequest(
		fixture.run,
		ports.MutablePublicationJournal,
		path,
		expected,
		replacement,
		publicationSHA256(replacement),
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(filepath.Join(fixture.root, path.String()))
	detached := directory + "-detached-existing"
	t.Cleanup(func() { _ = os.RemoveAll(detached) })
	swapped := false
	fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
		if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
			return err
		}
		if swapped || flags != unix.RENAME_SWAP || destinationName != safeBasename(path) {
			return nil
		}
		swapped = true
		if err := os.Rename(directory, detached); err != nil {
			return err
		}
		return os.Mkdir(directory, privateDirectoryMode)
	}
	result, err := fixture.store.ReplaceMutable(context.Background(), request)
	if err == nil || result.Valid() {
		t.Fatalf("existing CAS namespace swap = (%#v, %v), want no receipt", result, err)
	}
	if got, err := os.ReadFile(filepath.Join(detached, safeBasename(path))); err != nil || !bytes.Equal(got, prior) {
		t.Fatalf("existing CAS rollback did not restore prior: %q, %v", got, err)
	}
}

func TestPublicationStoreCompositeTargetNamespaceSwapsWithholdAuthority(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		target func(publicationStoreTestFixture) ports.ImmutablePublicationArtifact
		phase  ports.CompositeCommitPhase
	}{
		{
			name: "manifest",
			target: func(fixture publicationStoreTestFixture) ports.ImmutablePublicationArtifact {
				return fixture.composite.Manifest()
			},
		},
		{
			name: "lineage",
			target: func(fixture publicationStoreTestFixture) ports.ImmutablePublicationArtifact {
				return fixture.composite.LineageEdge()
			},
			phase: ports.CompositeManifestInstalled,
		},
		{
			name: "epoch",
			target: func(fixture publicationStoreTestFixture) ports.ImmutablePublicationArtifact {
				return fixture.composite.Epoch().Record()
			},
			phase: ports.CompositeMembersInstalled,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture, prepared := preparedRecoveryFixture(t)
			installPublicationFinal(t, fixture)
			fixture.writeJournal(t, domain.JournalFinalFileInstalled)
			target := testCase.target(fixture)
			directory := filepath.Dir(filepath.Join(fixture.root, target.Path().String()))
			detached := directory + "-detached-" + testCase.name
			t.Cleanup(func() { _ = os.RemoveAll(detached) })
			swapped := false
			fixture.store.operations.renameatxNp = func(sourceFD int, sourceName string, destinationFD int, destinationName string, flags uint32) error {
				if err := unix.RenameatxNp(sourceFD, sourceName, destinationFD, destinationName, flags); err != nil {
					return err
				}
				if swapped || flags != unix.RENAME_EXCL || destinationName != safeBasename(target.Path()) {
					return nil
				}
				swapped = true
				if err := os.Rename(directory, detached); err != nil {
					return err
				}
				return os.Mkdir(directory, privateDirectoryMode)
			}
			result, err := fixture.store.CommitPreparedComposite(context.Background(), prepared)
			if err == nil {
				t.Fatal("target namespace swap was accepted")
			}
			if testCase.phase == "" {
				if result.Valid() {
					t.Fatalf("manifest target swap returned false receipt: %#v", result)
				}
			} else if !result.Valid() || result.Phase() != testCase.phase {
				t.Fatalf("%s target swap result = %#v, want phase %q", testCase.name, result, testCase.phase)
			}
			observation := fixture.observe(t)
			if observation.ClassifierInput().Observation() == domain.DurableObservationP2Committed {
				t.Fatalf("%s target swap granted P2 authority", testCase.name)
			}
		})
	}
}

type failNthPublicationWriter struct {
	delegate ports.SecureFileWriter
	failAt   int
	writes   int
}

func (writer *failNthPublicationWriter) EnsurePrivateDir(root ports.AnchoredRoot, path ports.SafeRelativePath) error {
	return writer.delegate.EnsurePrivateDir(root, path)
}

func (writer *failNthPublicationWriter) Write(
	ctx context.Context,
	request ports.SecureWriteRequest,
) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	writer.writes++
	if writer.writes == writer.failAt {
		return ports.SecureWriteReceipt{}, nil, errors.New("injected preparation write failure")
	}
	return writer.delegate.Write(ctx, request)
}

type publicationStoreTestFixture struct {
	root       string
	run        ports.PublicationRun
	store      *PublicationStore
	writer     *SecureWriter
	final      ports.FinalReviewArtifact
	composite  ports.CommitCompositeRequest
	prepare    ports.PrepareCompositeRequest
	stagedPath ports.SafeRelativePath
}

func newPublicationStoreFixture(t *testing.T) publicationStoreTestFixture {
	t.Helper()
	root := privateTempRoot(t)
	writer := NewSecureWriter()
	store, err := NewPublicationStore(publicationStoreTestValidator{}, publicationStoreTestClock{}, publicationStoreTestIDs{}, writer)
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	reviewID, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(mustRoot(t, root), session, runID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := session.String() + "/" + runID.String()
	finalPath := mustRelativePath(t, prefix+"/review_"+reviewID.String()+".json")
	finalBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-review-artifact.v2","session_id":%q,"run_id":%q,"review_id":%q}`, session.String(), runID.String(), reviewID.String()))
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, finalPath, publicationSHA256(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	lineagePath := mustRelativePath(t, "store/lineage-edges/e_"+reviewID.String()+".json")
	lineageBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-lineage-edge.v1","edge_id":"edge-1","child":{"session_id":%q,"run_id":%q,"review_id":%q}}`, session.String(), runID.String(), reviewID.String()))
	lineage, err := ports.NewImmutablePublicationArtifact(lineagePath, publicationSHA256(lineageBytes), lineageBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := publicationManifestPath(run)
	epochPath := mustRelativePath(t, "store/epochs/epoch_00000000000000000007.json")
	manifestBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-run-manifest.v2","session_id":%q,"run_id":%q,"publication_status":"committed","durable_observation_class":"P2_COMMITTED","derived_publication_status":"committed","publication_authority":"P2","final_review":{"review_id":%q,"path":%q,"sha256":%q},"immutable_lineage":{"lineage_edge_path":%q,"lineage_edge_sha256":%q},"composite_identity":{"manifest":{"path":%q},"lineage_edge":{"path":%q,"sha256":%q},"epoch":{"path":%q}},"exit_code":0}`,
		session.String(), runID.String(), reviewID.String(), finalPath.String(), finalIdentity.SHA256(), lineagePath.String(), lineage.SHA256(), manifestPath.String(), lineagePath.String(), lineage.SHA256(), epochPath.String()))
	manifest, err := ports.NewImmutablePublicationArtifact(manifestPath, publicationSHA256(manifestBytes), manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	epochBytes := []byte(fmt.Sprintf(`{"schema_version":"kar-publication-epoch.v1","store_epoch":7,"manifest":{"path":%q,"sha256":%q},"lineage_edge":{"path":%q,"sha256":%q},"final_review":{"path":%q,"sha256":%q}}`,
		manifestPath.String(), manifest.SHA256(), lineagePath.String(), lineage.SHA256(), finalPath.String(), finalIdentity.SHA256()))
	epochRecord, err := ports.NewImmutablePublicationArtifact(epochPath, publicationSHA256(epochBytes), epochBytes)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(7, epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	composite, err := ports.NewCommitCompositeRequest(run, finalIdentity, manifest, lineage, epoch)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	return publicationStoreTestFixture{
		root: root, run: run, store: store, writer: writer, final: final, composite: composite, prepare: prepare,
		stagedPath: mustRelativePath(t, prefix+"/publication/staged/review_"+reviewID.String()+".json.tmp"),
	}
}

func (fixture publicationStoreTestFixture) writeJournal(t *testing.T, state domain.PersistedJournalState) {
	t.Helper()
	bytes := []byte(fmt.Sprintf(`{"schema_version":"kar-publication-journal.v1","session_id":%q,"run_id":%q,"persisted_journal_state":%q,"expected_staged":{"path":%q,"sha256":%q},"expected_final":{"path":%q,"sha256":%q},"validated_candidate_sha256":%q,"store_epoch":7,"normal_exit":0,"manifest_path":%q,"lineage_edge_path":%q,"epoch_path":%q}`,
		fixture.run.SessionID().String(), fixture.run.RunID().String(), state, fixture.stagedPath.String(), fixture.final.Identity().SHA256(),
		fixture.final.Identity().Path().String(), fixture.final.Identity().SHA256(), fixture.final.Identity().SHA256(),
		fixture.composite.Manifest().Path().String(), fixture.composite.LineageEdge().Path().String(), fixture.composite.Epoch().Record().Path().String()))
	writePrivatePublicationTestFile(t, fixture.writer, fixture.run.Root(), publicationJournalPath(fixture.run), bytes)
}

func (fixture publicationStoreTestFixture) observe(t *testing.T) ports.PublicationObservation {
	t.Helper()
	request, err := ports.NewObserveRunRequest(fixture.run, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := fixture.store.ObserveRun(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func preparedRecoveryFixture(t *testing.T) (publicationStoreTestFixture, ports.PreparedComposite) {
	t.Helper()
	fixture := newPublicationStoreFixture(t)
	persistPublicationCandidate(t, fixture)
	prepared, err := fixture.store.PrepareComposite(context.Background(), fixture.prepare)
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeJournal(t, domain.JournalContentValidated)
	return fixture, prepared
}

func persistPublicationCandidate(t *testing.T, fixture publicationStoreTestFixture) {
	t.Helper()
	request, err := ports.NewPersistValidatedCandidateRequest(fixture.run, fixture.final)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.PersistValidatedCandidate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func installPublicationFinal(t *testing.T, fixture publicationStoreTestFixture) {
	t.Helper()
	issued, err := ports.NewIssuedReviewID(fixture.final.Identity().ReviewID(), fixture.final.Identity().SHA256())
	if err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.store.StageFinal(context.Background(), mustStageFinalRequest(t, fixture, issued))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.InstallFinal(context.Background(), mustPublicationInstallRequest(t, fixture.run, staged)); err != nil {
		t.Fatal(err)
	}
}

func mustStageFinalRequest(t *testing.T, fixture publicationStoreTestFixture, issued ports.IssuedReviewID) ports.StageFinalRequest {
	t.Helper()
	binding, err := ports.NewIssuedFinalBinding(issued, fixture.final.Identity())
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewStageFinalRequest(
		fixture.run,
		fixture.stagedPath,
		binding,
		bytes.NewReader(fixture.final.Bytes()),
		1<<20,
		[]string{"validated_candidate"},
		func(error) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
func mustPublicationInstallRequest(t *testing.T, run ports.PublicationRun, staged ports.StageFinalResult) ports.InstallFinalRequest {
	t.Helper()
	request, err := ports.NewInstallFinalRequest(run, staged)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func assertRecoveryMaterial(t *testing.T, fixture publicationStoreTestFixture, observation ports.PublicationObservation, staged bool) {
	t.Helper()
	material, ok := observation.RecoveryMaterial()
	if !ok {
		t.Fatal("recovery material is absent")
	}
	if !material.Valid() || material.Final().Identity() != fixture.final.Identity() || !bytes.Equal(material.Final().Bytes(), fixture.final.Bytes()) {
		t.Fatal("recovery final is not the exact persisted candidate")
	}
	candidate, ok := material.ValidatedCandidate()
	if !ok || !candidate.Valid() || candidate.Identity() != fixture.final.Identity() || !bytes.Equal(candidate.Bytes(), fixture.final.Bytes()) {
		t.Fatal("validated candidate is not exact durable bytes")
	}
	prepared, ok := material.PreparedComposite()
	if !ok || !prepared.Valid() ||
		!bytes.Equal(prepared.StagedManifest().Bytes(), fixture.composite.Manifest().Bytes()) ||
		!bytes.Equal(prepared.StagedLineageEdge().Bytes(), fixture.composite.LineageEdge().Bytes()) ||
		!bytes.Equal(prepared.StagedEpoch().Bytes(), fixture.composite.Epoch().Record().Bytes()) {
		t.Fatal("prepared composite is not exact durable bytes")
	}
	stagedPath, gotStaged := material.StagedPath()
	if gotStaged != staged {
		t.Fatalf("staged path presence = %t, want %t", gotStaged, staged)
	}
	if gotStaged && stagedPath != fixture.stagedPath {
		t.Fatalf("staged path = %q, want %q", stagedPath, fixture.stagedPath)
	}
}

func assertAmbiguousObservation(t *testing.T, observation ports.PublicationObservation) {
	t.Helper()
	if observation.ClassifierInput().Observation() != domain.DurableObservationAmbiguousOrMismatch {
		t.Fatalf("observation = %q, want ambiguity", observation.ClassifierInput().Observation())
	}
	if _, ok := observation.RecoveryMaterial(); ok {
		t.Fatal("ambiguity exposed recovery bytes")
	}
}
func assertAmbiguousReason(t *testing.T, observation ports.PublicationObservation, want string) {
	t.Helper()
	assertAmbiguousObservation(t, observation)
	for _, reason := range observation.ClassifierInput().AmbiguityReasons() {
		if reason == want {
			return
		}
	}
	t.Fatalf("ambiguity reasons = %q, want %q", observation.ClassifierInput().AmbiguityReasons(), want)
}

func writePrivatePublicationTestFile(t *testing.T, writer *SecureWriter, root ports.AnchoredRoot, path ports.SafeRelativePath, data []byte) {
	t.Helper()
	parts, _, err := splitDestination(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 0 {
		if err := writer.EnsurePrivateDir(root, parentPath(parts)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root.String(), path.String()), data, privateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root.String(), path.String()), privateFileMode); err != nil {
		t.Fatal(err)
	}
}

func assertPublicationReceipt(
	t *testing.T,
	receipt ports.SecureWriteReceipt,
	root ports.AnchoredRoot,
	path ports.SafeRelativePath,
	sha256 string,
	byteLength int,
	channel string,
	expectedSources []string,
) {
	t.Helper()
	sources := receipt.SourceIDs()
	sourcesMatch := len(sources) == len(expectedSources)
	if sourcesMatch {
		for index := range sources {
			if sources[index] != expectedSources[index] {
				sourcesMatch = false
				break
			}
		}
	}
	if receipt.Root() != root || receipt.Destination() != path ||
		receipt.SHA256() != sha256 || receipt.ByteLength() != int64(byteLength) ||
		receipt.Channel() != channel || !sourcesMatch {
		t.Fatalf(
			"receipt = root %q path %q sha %q length %d channel %q sources %q",
			receipt.Root(),
			receipt.Destination(),
			receipt.SHA256(),
			receipt.ByteLength(),
			receipt.Channel(),
			receipt.SourceIDs(),
		)
	}
}
func injectPublicationPostInstallSyncFailure(writer *SecureWriter, targetName string) {
	operations := writer.operationSet()
	rename := operations.renameatxNp
	installed := false
	failed := false
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		if err := rename(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if newName == targetName {
			installed = true
		}
		return nil
	}
	operations.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if installed && !failed && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			failed = true
			return errors.New("injected directory sync failure")
		}
		return unix.Fsync(fd)
	}
	writer.operations = operations
}

type publicationStoreTestValidator struct{}

func (publicationStoreTestValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return nil
}

type publicationStoreErrorValidator struct {
	err error
}

func (validator publicationStoreErrorValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return validator.err
}

type publicationStoreDocumentValidator struct{}

func (publicationStoreDocumentValidator) Validate(context.Context, ports.AssetID, []byte) error {
	return publicationStoreDocumentViolation{}
}

type publicationStoreDocumentViolation struct{}

func (publicationStoreDocumentViolation) Error() string { return "document rejected" }

func (publicationStoreDocumentViolation) DocumentViolation() bool { return true }

type publicationStoreTestClock struct{}

func (publicationStoreTestClock) Now() time.Time { return time.Unix(0, 0).UTC() }

type publicationStoreTestIDs struct{}

func (publicationStoreTestIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82cc2")
}
