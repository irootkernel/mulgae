//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestMCPReviewArgumentsReuseCanonicalCLIGrammar(t *testing.T) {
	arguments, err := mcpReviewArguments(mcpentry.RunReviewInput{
		Target:    mcpentry.ReviewTarget{Kind: "diff", Value: "origin/main...HEAD"},
		Objective: "Review the boundary.", Roles: []string{"logic", "security"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"review", "--diff", "origin/main...HEAD", "--objective", "Review the boundary.", "--roles", "logic,security"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("review arguments = %q, want %q", arguments, want)
	}
	if _, err := mcpReviewArguments(mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "stdin"}}); err == nil {
		t.Fatal("MCP review arguments accepted transport stdin as a review target")
	}
}

func TestMCPBackendClassifiesCanonicalReviewGrammarRejection(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	backend, err := newMCPBackend(
		projectRoot, artifactRoot, &mulgaeentry.Application{}, &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector(),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.RunReview(context.Background(), "i_019f596a-cf80-7c67-b265-f37053d51ccf", mcpentry.RunReviewInput{
		Target: mcpentry.ReviewTarget{Kind: "workspace"}, Objective: "\n",
	})
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
		t.Fatalf("review grammar failure = %v", err)
	}
}

func TestMCPPreflightSummaryOmitsUnboundedFileInventory(t *testing.T) {
	files := make([]mulgaeentry.ReviewPreflightFile, 10_000)
	for index := range files {
		files[index] = mulgaeentry.ReviewPreflightFile{Path: "private/source/path.go", Size: 4096}
	}
	data, err := summarizeMCPPreflight(mulgaeentry.ReviewPreflightResult{
		Status: "eligible", FileSets: []mulgaeentry.ReviewPreflightFileSet{{
			ID:             "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PolicyIdentity: "policy", Files: files,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	sets := data["file_sets"].([]any)
	if len(encoded) > 4096 || bytes.Contains(encoded, []byte("private/source")) ||
		sets[0].(map[string]any)["file_count"] != 10_000 || sets[0].(map[string]any)["total_bytes"] != int64(40_960_000) {
		t.Fatalf("preflight summary = %s", encoded)
	}
}

func TestMCPBackendListsAndReadsOnlyVerifiedPublicViews(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	runPath := filepath.Join(artifactRoot.String(), sessionID.String(), runID.String())
	if err := os.MkdirAll(runPath, 0o700); err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(artifactRoot, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{
		run: run,
		status: mulgaeentry.RunStatusView{
			SessionID: sessionID.String(), RunID: runID.String(), RunState: domain.RunCompleted, HasRunState: true,
			PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionReconstructCompletedStatus,
			FinalArtifactURI: ".mulgae/" + sessionID.String() + "/" + runID.String() + "/review_test.json", HasFinalArtifact: true,
			ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete, CIDecision: domain.CIPass, HasAxes: true,
		},
		findings: mulgaeentry.FindingsView{
			RunID: runID.String(), ReviewArtifactURI: ".mulgae/review_test.json",
			TargetSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Findings:     []mulgaeentry.FindingView{{ID: "F001", Severity: domain.SeverityHigh, Title: "Boundary regression"}},
		},
	}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}

	listed, err := backend.ListRuns(context.Background(), mcpentry.ListRunsInput{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	runs := listed["runs"].([]any)
	if len(runs) != 1 || runs[0].(map[string]any)["run_id"] != runID.String() || listed["omitted_count"] != 0 {
		t.Fatalf("listed runs = %#v", listed)
	}
	status, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil || status["final_artifact_uri"] == nil || status["ci_decision"] != string(domain.CIPass) ||
		status["report_resource_uri"] != mustMCPReportResourceURI(t, runID.String()) {
		t.Fatalf("run status = %#v, %v", status, err)
	}
	findings, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{RunID: runID.String(), MinimumSeverity: "high"})
	if err != nil || findings["finding_count"] != 1 || findings["minimum_severity"] != "high" {
		t.Fatalf("findings = %#v, %v", findings, err)
	}
	rows := findings["findings"].([]any)
	if rows[0].(map[string]any)["evidence_resource_uri"] != mustMCPEvidenceResourceURI(
		t, runID.String(), "F001", queries.findings.TargetSHA256,
	) {
		t.Fatalf("finding resource link = %#v", rows[0])
	}
	queries.findings.Findings[0].ID = "F1000"
	if _, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{RunID: runID.String(), MinimumSeverity: "high"}); err != nil {
		t.Fatalf("four-digit finding sequence was rejected: %v", err)
	}
}

func TestMCPBackendRejectsMalformedPublicProjections(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err := os.MkdirAll(filepath.Join(artifactRoot.String(), sessionID.String(), runID.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(artifactRoot, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{
		run: run,
		status: mulgaeentry.RunStatusView{
			SessionID: sessionID.String(), RunID: runID.String(), RunState: domain.RunCompleted, HasRunState: true,
			PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionNone,
			FinalArtifactURI: ".mulgae/review.json", HasFinalArtifact: true,
			ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete, CIDecision: domain.CIPass, HasAxes: true,
		},
		findings: mulgaeentry.FindingsView{
			RunID: runID.String(), ReviewArtifactURI: ".mulgae/review.json",
			TargetSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Findings:     []mulgaeentry.FindingView{{ID: "F001", Severity: domain.SeverityLow, Title: "Below threshold"}},
		},
	}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}

	listed, err := backend.ListRuns(context.Background(), mcpentry.ListRunsInput{Limit: 20})
	if err != nil || len(listed["runs"].([]any)) != 0 || listed["omitted_count"] != 1 {
		t.Fatalf("malformed list projection = %#v, %v", listed, err)
	}
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); err == nil {
		t.Fatal("get_run accepted an invalid publication/recovery pair")
	}
	if _, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{
		RunID: runID.String(), MinimumSeverity: "high",
	}); err == nil {
		t.Fatal("list_findings accepted a finding below the requested threshold")
	}
}

func TestMCPBackendReturnsVerifiedReportAndEvidenceContent(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	run, err := ports.NewPublicationRun(artifactRoot, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	targetSHA256 := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reportBytes := []byte(strings.Repeat("a", mcpentry.MaxResourceChunkBytes-1) + "가\nrest")
	evidenceBytes := bytes.Repeat([]byte{0x00, 0xff, 0x7f}, mcpentry.MaxResourceChunkBytes/3+10)
	queries := &mcpQueryFake{run: run, excerpt: evidenceBytes}
	reports := &mcpReportFake{rendered: mulgaeentry.RenderedReport{Markdown: reportBytes, RunID: runID.String()}}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, reports, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}

	reportURI := mustMCPReportResourceURI(t, runID.String())
	reportRequest, err := mcpentry.ParseResourceURI(reportURI)
	if err != nil {
		t.Fatal(err)
	}
	report, err := backend.ReadResource(context.Background(), reportRequest)
	if err != nil || report.MIMEType != "text/markdown" || !report.Text || !bytes.Equal(report.Bytes, reportBytes) {
		t.Fatalf("report content = %#v, %v", report, err)
	}

	evidenceURI := mustMCPEvidenceResourceURI(t, runID.String(), "F001", targetSHA256)
	evidenceRequest, err := mcpentry.ParseResourceURI(evidenceURI)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := backend.ReadResource(context.Background(), evidenceRequest)
	if err != nil || evidence.MIMEType != "application/octet-stream" || evidence.Text || !bytes.Equal(evidence.Bytes, evidenceBytes) {
		t.Fatalf("evidence content = %#v, %v", evidence, err)
	}
	if queries.excerptTarget != targetSHA256 || queries.excerptFinding != "F001" {
		t.Fatalf("excerpt verification inputs = %q/%q", queries.excerptFinding, queries.excerptTarget)
	}
}

func TestMCPBackendGetRunFallsBackOnlyToSafeDiagnosticStatus(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	now := time.Date(2026, time.August, 14, 5, 0, 0, 0, time.UTC)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed, StartedAt: now, UpdatedAt: now.Add(time.Second),
		CompletedAt: now.Add(time.Second), HasCompletedAt: true, SelectedRoles: []domain.Role{domain.RoleTesting},
		RolePathTotal: 1, RolePathFailed: 1, LastSequence: 3, TerminalCause: domain.DiagnosticCauseProviderSpawnFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	diagnostics := &mcpDiagnosticQueryFake{status: status}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, diagnostics, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	projected, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil || projected["kind"] != "diagnostic_status_read" || projected["run_id"] != runID.String() || diagnostics.calls != 1 {
		t.Fatalf("diagnostic get_run = %#v, %v; calls = %d", projected, err, diagnostics.calls)
	}

	publicationCorrupt := errors.Join(ports.ErrPublicationRunNotFound, errors.New("publication corrupt"))
	queries.resolveErr = publicationCorrupt
	diagnostics.calls = 0
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); !errors.Is(err, publicationCorrupt) {
		t.Fatalf("non-not-found publication error = %v", err)
	}
	if diagnostics.calls != 0 {
		t.Fatalf("diagnostic fallback calls = %d, want 0", diagnostics.calls)
	}

	singleJoinedNotFound := errors.Join(fmt.Errorf("publication lookup: %w", ports.ErrPublicationRunNotFound))
	wrappedNotFound, err := domain.NewFailure("query.resolve_run", domain.FailureArtifact, "publication run resolution failed", singleJoinedNotFound)
	if err != nil {
		t.Fatal(err)
	}
	queries.resolveErr = wrappedNotFound
	diagnostics.calls = 0
	projected, err = backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil || projected["kind"] != "diagnostic_status_read" || diagnostics.calls != 1 {
		t.Fatalf("single-joined not-found fallback = %#v, %v; calls = %d", projected, err, diagnostics.calls)
	}
}

func TestMCPBackendGetRunReportsUnavailableDiagnosticIdentity(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	backend, err := newMCPBackend(
		projectRoot, artifactRoot, &mulgaeentry.Application{},
		&mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound},
		&mcpDiagnosticQueryFake{err: ports.ErrRuntimeDiagnosticRunNotFound},
		&mcpReportFake{}, filesystem.NewRunSelector(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); !errors.Is(err, mcpentry.ErrRunStatusUnavailable) {
		t.Fatalf("missing diagnostic status error = %v", err)
	}
	backend.diagnostics = &mcpDiagnosticQueryFake{err: errors.Join(ports.ErrRuntimeDiagnosticRunNotFound, errors.New("diagnostic corrupt"))}
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); err == nil || errors.Is(err, mcpentry.ErrRunStatusUnavailable) {
		t.Fatalf("ambiguous diagnostic status error = %v", err)
	}
	now := time.Date(2026, time.August, 14, 5, 0, 0, 0, time.UTC)
	running, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunRunning, StartedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	backend.diagnostics = &mcpDiagnosticQueryFake{status: running}
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); !errors.Is(err, mcpentry.ErrRunStatusUnavailable) {
		t.Fatalf("running diagnostic status error = %v, want %v", err, mcpentry.ErrRunStatusUnavailable)
	}
}

func TestMCPBackendGetRunPreservesSoleDiagnosticCancellation(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	backend, err := newMCPBackend(
		projectRoot, artifactRoot, &mulgaeentry.Application{},
		&mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound},
		&mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, cancellation := range []error{context.Canceled, context.DeadlineExceeded, fmt.Errorf("query: %w", context.Canceled)} {
		backend.diagnostics = &mcpDiagnosticQueryFake{err: cancellation}
		_, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
		var failure *domain.Failure
		if !errors.Is(err, cancellation) || errors.As(err, &failure) {
			t.Fatalf("diagnostic cancellation = %v, want unwrapped %v", err, cancellation)
		}
	}
	backend.diagnostics = &mcpDiagnosticQueryFake{err: errors.Join(context.Canceled, errors.New("diagnostic corrupt"))}
	_, err = backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureArtifact {
		t.Fatalf("joined diagnostic cancellation = %v, want artifact failure", err)
	}
}

func mustMCPReportResourceURI(t *testing.T, runID string) string {
	t.Helper()
	uri, err := mcpentry.NewReportResourceURI(runID)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

func mustMCPEvidenceResourceURI(t *testing.T, runID, findingID, targetSHA256 string) string {
	t.Helper()
	uri, err := mcpentry.NewEvidenceResourceURI(runID, findingID, targetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

type mcpQueryFake struct {
	run            ports.PublicationRun
	resolveErr     error
	status         mulgaeentry.RunStatusView
	findings       mulgaeentry.FindingsView
	excerpt        []byte
	excerptErr     error
	excerptFinding string
	excerptTarget  string
}

type mcpDiagnosticQueryFake struct {
	status ports.RuntimeDiagnosticRunStatus
	err    error
	calls  int
}

func (fake *mcpDiagnosticQueryFake) ReadRunStatus(context.Context, ports.AnchoredRoot, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.calls++
	return fake.status, fake.err
}

type mcpReportFake struct {
	rendered mulgaeentry.RenderedReport
	err      error
}

func (fake *mcpReportFake) Render(context.Context, ports.PublicationRun) (mulgaeentry.RenderedReport, error) {
	return fake.rendered, fake.err
}

func (fake *mcpQueryFake) ResolveRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error) {
	return fake.run, fake.resolveErr
}

func (fake *mcpQueryFake) ReadRunStatus(context.Context, ports.PublicationRun) (mulgaeentry.RunStatusView, error) {
	return fake.status, nil
}

func (fake *mcpQueryFake) ListFindings(context.Context, ports.PublicationRun, domain.Severity) (mulgaeentry.FindingsView, error) {
	return fake.findings, nil
}

func (fake *mcpQueryFake) RenderExcerpt(_ context.Context, _ ports.PublicationRun, findingID, targetSHA256 string) ([]byte, error) {
	fake.excerptFinding, fake.excerptTarget = findingID, targetSHA256
	return append([]byte(nil), fake.excerpt...), fake.excerptErr
}

func mustMCPRoot(t *testing.T, value string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(value)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustMCPSessionID(t *testing.T, value string) domain.SessionID {
	t.Helper()
	id, err := domain.ParseSessionID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustMCPRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	id, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
