//go:build darwin && arm64

package publication

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/jsonschema"
	appquery "github.com/irootkernel/kkachi-agent-review/internal/app/query"
	appreport "github.com/irootkernel/kkachi-agent-review/internal/app/report"
	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type publicationIntegrationIDs struct{ reviewID domain.ReviewID }

func (ids publicationIntegrationIDs) NewReviewID(time.Time) (domain.ReviewID, error) {
	return ids.reviewID, nil
}

func TestIntegrationPublicationFilesystemQueryReportAndRecovery(t *testing.T) {
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), ".kar")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	candidate := publicationTestCandidate(t, true)
	if _, err := candidate.Build(ctx, validator, publicationTestReviewID(t), publicationTestTime(), 1); err != nil {
		t.Fatalf("real-schema candidate build: %v", err)
	}
	store, err := filesystem.NewPublicationStore(
		validator,
		clock,
		publicationIntegrationIDs{reviewID: publicationTestReviewID(t)},
		filesystem.NewSecureWriter(),
	)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}

	published, err := publisher.Publish(ctx, root, candidate, 1)
	if err != nil {
		t.Fatal(err)
	}
	if published.Decision().Authority() != domain.PublicationAuthorityP2 ||
		published.Decision().Status() != domain.PublicationCommitted ||
		published.Exit().Code() != domain.ExitCommittedCIRejected {
		t.Fatalf("published result = (%q, %q, %d)", published.Decision().Authority(), published.Decision().Status(), published.Exit().Code())
	}
	finalIdentity, ok := published.Final()
	if !ok {
		t.Fatal("published result omitted final identity")
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}

	queries, err := appquery.NewService(store, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := queries.ResolveRun(ctx, root, candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != run {
		t.Fatalf("resolved run = %#v, want %#v", resolved, run)
	}
	status, err := queries.ReadRunStatus(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if status.PublicationStatus() != domain.PublicationCommitted {
		t.Fatalf("status publication = %q", status.PublicationStatus())
	}
	statusFinal, ok := status.FinalPath()
	if !ok || statusFinal != finalIdentity.Path() {
		t.Fatal("committed status omitted the authoritative final path")
	}
	findings, err := queries.ListFindings(ctx, run, domain.SeverityLow)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID() != "F001" {
		t.Fatalf("findings = %#v", findings)
	}
	excerpt, err := queries.RenderExcerpt(ctx, run, "F001", candidate.target.sha256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(excerpt, []byte("reviewed line\n")) {
		t.Fatalf("excerpt = %q", excerpt)
	}
	reports, err := appreport.NewService(queries)
	if err != nil {
		t.Fatal(err)
	}
	report, err := reports.Render(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(report.Bytes(), []byte("F001")) || bytes.Contains(bytes.ToLower(report.Bytes()), []byte("organizational approval")) {
		t.Fatal("report does not agree with committed findings or implies approval")
	}

	snapshot, ok := published.Snapshot()
	if !ok {
		t.Fatal("published result omitted P2 snapshot")
	}
	immutable := []ports.SafeRelativePath{
		snapshot.Final().Identity().Path(),
		snapshot.Manifest().Path(),
		snapshot.LineageEdge().Path(),
		snapshot.Epoch().Record().Path(),
	}
	before := readPublicationIntegrationFiles(t, rootPath, immutable)

	paths, err := publicationPaths(run.SessionID(), run.RunID(), finalIdentity.ReviewID(), snapshot.Epoch().Value())
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(rootPath, filepath.FromSlash(paths.journal.String()))
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestCommitted, err := journalForState(
		PublicationDocument{path: paths.journal, sha256: sha256Identifier(journalBytes), bytes: journalBytes},
		domain.JournalManifestCommitted,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, manifestCommitted.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(rootPath, filepath.FromSlash(paths.status.String()))
	if err := os.Remove(statusPath); err != nil {
		t.Fatal(err)
	}
	syncPublicationIntegrationPath(t, journalPath)
	syncPublicationIntegrationDirectory(t, filepath.Dir(statusPath))
	restartedStore, err := filesystem.NewPublicationStore(
		validator,
		clock,
		publicationIntegrationIDs{reviewID: publicationTestReviewID(t)},
		filesystem.NewSecureWriter(),
	)
	if err != nil {
		t.Fatal(err)
	}
	restartedPublisher, err := NewService(restartedStore, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	restartedQueries, err := appquery.NewService(restartedStore, validator, nil, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	restartedReports, err := appreport.NewService(restartedQueries)
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := restartedPublisher.Recover(ctx, run)
	if err != nil {
		t.Fatalf("recover error chain = %q", publicationIntegrationErrorChain(err))
	}
	if recovered.Decision().Authority() != domain.PublicationAuthorityP2 || recovered.Exit().Code() != domain.ExitCommittedCIRejected {
		t.Fatalf("recovered result = (%q, %d)", recovered.Decision().Authority(), recovered.Exit().Code())
	}
	assertPublicationIntegrationFilesEqual(t, rootPath, immutable, before)
	expectedStatus, expectedJournal, err := completedRecoveryDocuments(run, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicationIntegrationFile(t, rootPath, expectedStatus.Path(), expectedStatus.Bytes(), 0o600)
	assertPublicationIntegrationFile(t, rootPath, expectedJournal.Path(), expectedJournal.Bytes(), 0o600)
	restartedResolved, err := restartedQueries.ResolveRun(ctx, root, candidate.RunID())
	if err != nil || restartedResolved != run {
		t.Fatalf("restarted resolve = (%#v, %v), want authoritative run", restartedResolved, err)
	}
	restartedStatus, err := restartedQueries.ReadRunStatus(ctx, run)
	if err != nil || restartedStatus.PublicationStatus() != domain.PublicationCommitted {
		t.Fatalf("restarted status = (%#v, %v), want committed", restartedStatus, err)
	}
	restartedFindings, err := restartedQueries.ListFindings(ctx, run, domain.SeverityLow)
	if err != nil || len(restartedFindings) != 1 || restartedFindings[0].ID() != "F001" {
		t.Fatalf("restarted findings = (%#v, %v)", restartedFindings, err)
	}
	restartedExcerpt, err := restartedQueries.RenderExcerpt(ctx, run, "F001", candidate.target.sha256)
	if err != nil || !bytes.Equal(restartedExcerpt, []byte("reviewed line\n")) {
		t.Fatalf("restarted excerpt = (%q, %v)", restartedExcerpt, err)
	}
	restartedReport, err := restartedReports.Render(ctx, run)
	if err != nil || !bytes.Contains(restartedReport.Bytes(), []byte("F001")) {
		t.Fatalf("restarted report = (%q, %v)", restartedReport.Bytes(), err)
	}

	if _, err := restartedPublisher.Recover(ctx, run); err != nil {
		t.Fatal(err)
	}
	assertPublicationIntegrationFilesEqual(t, rootPath, immutable, before)
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	syncPublicationIntegrationDirectory(t, filepath.Dir(journalPath))
	missingJournalRecovery, err := restartedPublisher.Recover(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	if missingJournalRecovery.Decision().Authority() != domain.PublicationAuthorityP2 ||
		missingJournalRecovery.Exit().Code() != domain.ExitCommittedCIRejected {
		t.Fatalf(
			"missing-journal recovery = (%q, %d)",
			missingJournalRecovery.Decision().Authority(),
			missingJournalRecovery.Exit().Code(),
		)
	}
	assertPublicationIntegrationFile(t, rootPath, expectedJournal.Path(), expectedJournal.Bytes(), 0o600)
	assertPublicationIntegrationFilesEqual(t, rootPath, immutable, before)
	if err := os.WriteFile(journalPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	syncPublicationIntegrationPath(t, journalPath)
	if _, err := restartedPublisher.Recover(ctx, run); err != nil {
		t.Fatal(err)
	}
	assertPublicationIntegrationFile(t, rootPath, expectedJournal.Path(), expectedJournal.Bytes(), 0o600)
	assertPublicationIntegrationFilesEqual(t, rootPath, immutable, before)
	if err := os.WriteFile(statusPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	syncPublicationIntegrationPath(t, statusPath)
	if _, err := restartedPublisher.Recover(ctx, run); err != nil {
		t.Fatal(err)
	}
	assertPublicationIntegrationFile(t, rootPath, expectedStatus.Path(), expectedStatus.Bytes(), 0o600)
	assertPublicationIntegrationFilesEqual(t, rootPath, immutable, before)
}

func TestIntegrationPublicationFilesystemRecoversP0StagedToP2(t *testing.T) {
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), ".kar")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	reviewID := publicationTestReviewID(t)
	candidate := publicationTestCandidate(t, true)
	store, err := filesystem.NewPublicationStore(
		validator,
		clock,
		publicationIntegrationIDs{reviewID: reviewID},
		filesystem.NewSecureWriter(),
	)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewService(store, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	issueRequest, err := ports.NewIssueReviewIDRequest(
		run,
		candidate.ValidatedCandidateSHA256(),
	)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.IssueReviewID(ctx, issueRequest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := candidate.Build(ctx, validator, issued.ReviewID(), clock.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	persistRequest, err := ports.NewPersistValidatedCandidateRequest(run, bundle.Final())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PersistValidatedCandidate(ctx, persistRequest); err != nil {
		t.Fatal(err)
	}
	for _, support := range bundle.SupportArtifacts() {
		request, err := ports.NewPersistRunSupportArtifactRequest(run, support)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PersistAuxiliaryArtifact(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	composite, err := ports.NewCommitCompositeRequest(
		run,
		bundle.Final().Identity(),
		bundle.Manifest(),
		bundle.LineageEdge(),
		bundle.Epoch(),
	)
	if err != nil {
		t.Fatal(err)
	}
	prepareRequest, err := ports.NewPrepareCompositeRequest(composite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareComposite(ctx, prepareRequest); err != nil {
		t.Fatal(err)
	}
	stagedPath, err := canonicalStagedFinalPath(run, bundle.Final().Identity())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.NewIssuedFinalBinding(issued, bundle.Final().Identity())
	if err != nil {
		t.Fatal(err)
	}
	stageRequest, err := ports.NewStageFinalRequest(
		run,
		stagedPath,
		binding,
		bytes.NewReader(bundle.Final().Bytes()),
		8<<20,
		[]string{"validated_candidate"},
		func(error) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageFinal(ctx, stageRequest); err != nil {
		t.Fatal(err)
	}
	stagedJournal, err := journalForState(bundle.Journal(), domain.JournalFinalStaged)
	if err != nil {
		t.Fatal(err)
	}
	if uncertain, err := publisher.replaceJournal(
		ctx,
		run,
		stagedJournal,
		ports.ExpectMutableAbsent(),
	); err != nil || uncertain {
		t.Fatalf("persist staged journal = uncertain %t, error %v", uncertain, err)
	}

	recovered, err := publisher.Recover(ctx, run)
	if err != nil {
		t.Fatalf("recover error chain = %q", publicationIntegrationErrorChain(err))
	}
	if recovered.Decision().Authority() != domain.PublicationAuthorityP2 ||
		recovered.Decision().Status() != domain.PublicationCommitted ||
		recovered.Exit().Code() != domain.ExitCommittedCIRejected {
		t.Fatalf(
			"P0 recovery = (%q, %q, %d)",
			recovered.Decision().Authority(),
			recovered.Decision().Status(),
			recovered.Exit().Code(),
		)
	}
	if _, err := os.Lstat(filepath.Join(rootPath, stagedPath.String())); !os.IsNotExist(err) {
		t.Fatalf("P0 staged path remains after recovery: %v", err)
	}
	snapshot, ok := recovered.Snapshot()
	if !ok || !snapshot.Valid() ||
		!bytes.Equal(snapshot.Final().Bytes(), bundle.Final().Bytes()) ||
		!bytes.Equal(snapshot.Manifest().Bytes(), bundle.Manifest().Bytes()) ||
		!bytes.Equal(snapshot.LineageEdge().Bytes(), bundle.LineageEdge().Bytes()) ||
		!bytes.Equal(snapshot.Epoch().Record().Bytes(), bundle.Epoch().Record().Bytes()) {
		t.Fatal("P0 recovery did not preserve the exact persisted composite")
	}
}

func readPublicationIntegrationFiles(t *testing.T, root string, paths []ports.SafeRelativePath) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte, len(paths))
	for _, path := range paths {
		bytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path.String())))
		if err != nil {
			t.Fatal(err)
		}
		files[path.String()] = bytes
	}
	return files
}

func assertPublicationIntegrationFilesEqual(t *testing.T, root string, paths []ports.SafeRelativePath, want map[string][]byte) {
	t.Helper()
	for _, path := range paths {
		actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path.String())))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, want[path.String()]) {
			t.Fatalf("immutable publication member %q changed during recovery", path.String())
		}
	}
}

func assertPublicationIntegrationFile(t *testing.T, root string, path ports.SafeRelativePath, want []byte, mode os.FileMode) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path.String()))
	actual, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("mutable publication record %q differs after recovery", path.String())
	}
	info, err := os.Lstat(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("publication record %q mode = %s, want regular %s", path.String(), info.Mode(), mode)
	}
}

func syncPublicationIntegrationPath(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	syncPublicationIntegrationDirectory(t, filepath.Dir(path))
}

func syncPublicationIntegrationDirectory(t *testing.T, path string) {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
}

func publicationIntegrationErrorChain(err error) []string {
	var chain []string
	for err != nil {
		chain = append(chain, err.Error())
		err = errors.Unwrap(err)
	}
	return chain
}
