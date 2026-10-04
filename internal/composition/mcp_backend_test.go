//go:build darwin && arm64

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/builtin"
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

func TestMCPCompositeStatusAndFindingsAgreeWithCLI(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	if err := os.Mkdir(artifactRoot.String(), 0o700); err != nil {
		t.Fatal(err)
	}
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cf83-7c67-b265-f37053d51ccf")
	reviewID := "019f596a-d174-7321-b920-c2d312c82cc2"
	prefix := ".mulgae/" + sessionID.String() + "/" + runID.String() + "/"
	statusView := mulgaeentry.RunStatusView{FailedRunRecovery: recovery.UnavailableStatus("source_not_retained"),
		SessionID: sessionID.String(), RunID: runID.String(), RunState: domain.RunCompleted, HasRunState: true,
		PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionReconstructCompletedStatus,
		FinalArtifactURI: prefix + "review_" + reviewID + ".json", HasFinalArtifact: true,
		ContentVerdict: domain.ContentRequestChanges, CoverageStatus: domain.CoverageComplete, CIDecision: domain.CIFail, HasAxes: true,
		RoleReportURIs: []mulgaeentry.RoleReportURI{{Role: string(domain.RoleLogic), URI: prefix + "role-reports/logic.md"}},
	}
	findingsView := mcpFixtureFindings{
		RunID: runID.String(), ReviewArtifactURI: statusView.FinalArtifactURI, TargetSHA256: "sha256:" + strings.Repeat("a", 64),
		Findings: []mcpFixtureFinding{{ID: "F001", Severity: domain.SeverityHigh, Title: "Composite boundary", HasEvidence: false}},
	}
	queries := &mcpMultiQueryFake{
		root: artifactRoot, sessionID: sessionID,
		statuses: map[domain.RunID]mulgaeentry.RunStatusView{runID: statusView},
		findings: map[domain.RunID]mcpFixtureFindings{runID: findingsView},
	}
	application := newMCPTestApplication(t, queries)
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, application, queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}

	cliStatus := application.Run(context.Background(), []string{"status", "--run", runID.String(), "--output", "json"}, projectRoot.String())
	var cliStatusEnvelope struct {
		Result map[string]any `json:"result"`
	}
	if cliStatus.ExitCode() != 0 || json.Unmarshal(cliStatus.Stdout(), &cliStatusEnvelope) != nil {
		t.Fatalf("CLI composite status = exit %d stdout %q stderr %q", cliStatus.ExitCode(), cliStatus.Stdout(), cliStatus.Stderr())
	}
	mcpStatus, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"run_id", "run_state", "publication_status", "recovery_action", "final_artifact_uri", "content_verdict", "coverage_status", "ci_decision", "role_report_uris"} {
		if !reflect.DeepEqual(cliStatusEnvelope.Result[key], mcpStatus[key]) {
			t.Fatalf("composite status %s drifted: CLI=%#v MCP=%#v", key, cliStatusEnvelope.Result[key], mcpStatus[key])
		}
	}

	cliFindings := application.Run(context.Background(), []string{"findings", "--run", runID.String(), "--severity", "low", "--output", "json"}, projectRoot.String())
	var cliFindingsEnvelope struct {
		Result map[string]any `json:"result"`
	}
	if cliFindings.ExitCode() != 0 || json.Unmarshal(cliFindings.Stdout(), &cliFindingsEnvelope) != nil {
		t.Fatalf("CLI composite findings = exit %d stdout %q stderr %q", cliFindings.ExitCode(), cliFindings.Stdout(), cliFindings.Stderr())
	}
	mcpFindings, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{RunID: runID.String(), MinimumSeverity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if cliFindingsEnvelope.Result["run_id"] != mcpFindings["run_id"] ||
		cliFindingsEnvelope.Result["review_artifact_uri"] != mcpFindings["review_artifact_uri"] ||
		cliFindingsEnvelope.Result["finding_count"] != float64(mcpFindings["finding_count"].(int)) {
		t.Fatalf("composite findings drifted: CLI=%#v MCP=%#v", cliFindingsEnvelope.Result, mcpFindings)
	}
	rows := mcpFindings["findings"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["evidence_resource_uri"] != nil {
		t.Fatalf("composite MCP evidence projection = %#v", rows)
	}
}

type mcpTestClock struct{}

func (mcpTestClock) Now() time.Time { return time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC) }

type mcpTestRequestIDs struct{}

func (mcpTestRequestIDs) NewRequestID(time.Time) (string, error) {
	return "i_019f596a-cf80-7c67-b265-f37053d51ccf", nil
}

type mcpReviewRunFake struct {
	result mulgaeentry.ReviewRunResult
	calls  int
}

func (fake *mcpReviewRunFake) StartReviewRun(context.Context, mulgaeentry.ReviewRequest, ports.AnchoredRoot) (mulgaeentry.ReviewRunResult, error) {
	fake.calls++
	return fake.result, nil
}

func newMCPTestApplication(t *testing.T, queries mulgaeentry.PublicationQueryService) *mulgaeentry.Application {
	return newMCPTestApplicationWithReviewRuns(t, queries, nil)
}

func newMCPTestApplicationWithReviewRuns(
	t *testing.T,
	queries mulgaeentry.PublicationQueryService,
	reviewRuns mulgaeentry.ReviewRunService,
) *mulgaeentry.Application {
	t.Helper()
	catalog := builtin.NewCatalog()
	validator, err := jsonschema.New(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gittarget.New(gittarget.NewExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	application, err := mulgaeentry.NewApplication(mulgaeentry.Dependencies{
		Clock: mcpTestClock{}, RequestIDGenerator: mcpTestRequestIDs{}, Catalog: catalog, JSONSchemaValidator: validator,
		SecureWriter: filesystem.NewSecureWriter(), TrustedProjectReader: reader, EnvironmentInspector: environment.NewInspector(),
		ReviewRuns: reviewRuns, ProjectContexts: inspectionContexts(),
		PublicationQueries: queries, PublicationReports: &mcpReportFake{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func TestMCPBackendRejectsReplacedStartupRootBeforeReviewDispatch(t *testing.T) {
	fixture := canonicalTestTempDir(t)
	projectPath := filepath.Join(fixture, "project")
	if err := os.Mkdir(projectPath, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/git", "-C", projectPath, "init", "--quiet")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, raw)
	}
	projectRoot := mustMCPRoot(t, projectPath)
	artifactRoot := mustMCPRoot(t, filepath.Join(projectPath, ".mulgae"))
	reviewRuns := &mcpReviewRunFake{}
	queries := &mcpQueryFake{}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, newMCPTestApplicationWithReviewRuns(t, queries, reviewRuns), queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	backend.projectContexts, err = query.NewProjectContextService(gittarget.ProjectBindingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	backend.contextLease, err = backend.projectContexts.Open(context.Background(), projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.contextLease.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := backend.GetContext(context.Background()); err != nil {
		t.Fatalf("startup lease was not initially valid: %v", err)
	}
	if err := os.Rename(projectPath, filepath.Join(fixture, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(projectPath, 0700); err != nil {
		t.Fatal(err)
	}
	for _, execute := range []func(context.Context, string, mcpentry.RunReviewInput) (mcpentry.BackendResult, error){backend.RunReview, backend.PreflightReview} {
		result, err := execute(context.Background(), "i_019f596a-cf80-7c67-b265-f37053d51ccf", mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "workspace"}})
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || result.Data != nil {
			t.Fatalf("replaced startup root admission: result=%#v err=%v", result, err)
		}
	}
	if reviewRuns.calls != 0 {
		t.Fatalf("stale startup lease dispatched %d reviews", reviewRuns.calls)
	}
}

func TestMCPBackendClassifiesCanonicalReviewGrammarRejection(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	backend, err := newMCPBoundTestBackend(
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

func TestMCPBackendRunReviewPreservesCommittedProviderReasons(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactPath := filepath.Join(projectRoot.String(), ".mulgae")
	if err := os.Mkdir(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	artifactRoot := mustMCPRoot(t, artifactPath)
	const sessionID = "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	const runID = "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	reasonCodes := []string{"provider_protocol_event_decode_failed", "provider_output_decode_failed"}
	reasons := make([]domain.ExitReason, len(reasonCodes))
	for index, reasonCode := range reasonCodes {
		var err error
		reasons[index], err = domain.NewExitReason(domain.ExitIncompleteCoverage, reasonCode)
		if err != nil {
			t.Fatal(err)
		}
	}
	exitInput, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := domain.ReduceOperationalExit(exitInput)
	if err != nil {
		t.Fatal(err)
	}
	prefix := ".mulgae/" + sessionID + "/" + runID + "/"
	reviewRuns := &mcpReviewRunFake{result: mulgaeentry.NewReviewRunResult(
		sessionID, runID, prefix+"manifest.json", prefix+"review_test.json", decision,
	)}
	application := newMCPTestApplicationWithReviewRuns(t, &mcpQueryFake{}, reviewRuns)
	backend, err := newMCPBoundTestBackend(
		projectRoot, artifactRoot, application, &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector(),
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := backend.RunReview(context.Background(), "i_019f596a-cf80-7c67-b265-f37053d51ccf", mcpentry.RunReviewInput{
		Target: mcpentry.ReviewTarget{Kind: "workspace"}, Roles: []string{"logic", "security"},
	})
	if err != nil {
		t.Fatal(err)
	}
	projected, ok := result.Data["reasons"].([]any)
	if !ok || len(projected) != len(reasonCodes) {
		t.Fatalf("MCP review reasons = %#v", result.Data["reasons"])
	}
	for index, reasonCode := range reasonCodes {
		row, ok := projected[index].(map[string]any)
		if !ok || row["code"] != reasonCode || row["exit_code"] != int(domain.ExitIncompleteCoverage) {
			t.Fatalf("MCP review reason %d = %#v", index, projected[index])
		}
	}
	if result.Data["terminal_exit_code"] != int(domain.ExitIncompleteCoverage) || reviewRuns.calls != 1 {
		t.Fatalf("MCP review result = %#v, calls = %d", result, reviewRuns.calls)
	}
}

func TestMCPPreflightSummaryOmitsUnboundedFileInventory(t *testing.T) {
	reads := make([]mulgaeentry.ReviewPreflightRead, 10_000)
	for index := range reads {
		reads[index] = mulgaeentry.ReviewPreflightRead{Side: "index", Path: "private/source/path.go"}
	}
	data, err := summarizeMCPPreflight(mulgaeentry.ReviewPreflightResult{Status: "eligible", ReadPlan: reads, Target: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 4096 || bytes.Contains(encoded, []byte("private/source")) || data["read_count"] != 10_000 {
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
		status: mulgaeentry.RunStatusView{FailedRunRecovery: recovery.UnavailableStatus("source_not_retained"),
			SessionID: sessionID.String(), RunID: runID.String(), RunState: domain.RunCompleted, HasRunState: true,
			PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionReconstructCompletedStatus,
			FinalArtifactURI: ".mulgae/" + sessionID.String() + "/" + runID.String() + "/review_test.json", HasFinalArtifact: true,
			ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete, CIDecision: domain.CIPass, HasAxes: true,
		},
		findings: mcpFixtureFindings{
			RunID: runID.String(), ReviewArtifactURI: ".mulgae/review_test.json",
			TargetSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Findings:     []mcpFixtureFinding{{ID: "F001", Severity: domain.SeverityHigh, Title: "Boundary regression", HasEvidence: true}},
		},
	}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
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
		status: mulgaeentry.RunStatusView{FailedRunRecovery: recovery.UnavailableStatus("source_not_retained"),
			SessionID: sessionID.String(), RunID: runID.String(), RunState: domain.RunCompleted, HasRunState: true,
			PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionNone,
			FinalArtifactURI: ".mulgae/review.json", HasFinalArtifact: true,
			ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete, CIDecision: domain.CIPass, HasAxes: true,
		},
		findings: mcpFixtureFindings{
			RunID: runID.String(), ReviewArtifactURI: ".mulgae/review.json",
			TargetSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Findings:     []mcpFixtureFinding{{ID: "F001", Severity: domain.SeverityLow, Title: "Below threshold"}},
		},
	}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
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
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, &mcpDiagnosticQueryFake{}, reports, filesystem.NewRunSelector())
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
		DiagnosticSummary: mustMCPBackendDiagnosticSummary(t), HasDiagnosticSummary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	diagnostics := &mcpDiagnosticQueryFake{status: status}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, diagnostics, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	projected, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil || projected["kind"] != "diagnostic_status_read" || projected["run_id"] != runID.String() || diagnostics.calls != 1 ||
		projected["diagnostic_summary"].(map[string]any)["invariant_id"] != ports.ProviderObservationInvariantRejected {
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

func TestMCPBackendGetRunMergesSessionBoundDiagnosticSummary(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	run, err := ports.NewPublicationRun(artifactRoot, sessionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{run: run, status: mulgaeentry.RunStatusView{
		FailedRunRecovery: recovery.UnavailableStatus("source_not_retained"), SessionID: sessionID.String(), RunID: runID.String(),
		RunState: domain.RunFailed, HasRunState: true, PublicationState: domain.PublicationNotPublished,
		RecoveryAction: domain.RecoveryActionResumeCollection,
	}}
	now := time.Date(2026, time.August, 14, 5, 0, 0, 0, time.UTC)
	diagnosticStatus, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed, StartedAt: now, UpdatedAt: now,
		CompletedAt: now, HasCompletedAt: true, DiagnosticSummary: mustMCPBackendDiagnosticSummary(t), HasDiagnosticSummary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := &mcpDiagnosticQueryFake{status: diagnosticStatus}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, diagnostics, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	projected, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()})
	if err != nil || diagnostics.calls != 0 || diagnostics.sessionCalls != 1 ||
		diagnostics.sessionID != sessionID || diagnostics.runID != runID ||
		projected["diagnostic_summary"].(map[string]any)["provider_session_fingerprint"] != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("publication get_run = %#v, %v; scan=%d direct=%d session=%s run=%s", projected, err, diagnostics.calls, diagnostics.sessionCalls, diagnostics.sessionID, diagnostics.runID)
	}
	diagnostics.err = errors.New("diagnostic status corrupt")
	if _, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: runID.String()}); err == nil {
		t.Fatal("publication get_run swallowed a direct diagnostic error")
	}
}

func mustMCPBackendDiagnosticSummary(t *testing.T) ports.RuntimeDiagnosticSummary {
	t.Helper()
	summary, err := ports.NewRuntimeDiagnosticSummary(ports.RuntimeDiagnosticSummaryInput{
		InvariantID: ports.ProviderObservationInvariantRejected, Component: "provider_registry", Phase: "provider_observation",
		Provider: "zcode_default", ProtocolTerminal: "failed",
		ProviderSessionFingerprint: "sha256:" + strings.Repeat("a", 64),
		ProviderTurnFingerprint:    "sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestMCPBackendGetRunReportsUnavailableDiagnosticIdentity(t *testing.T) {
	projectRoot := mustMCPRoot(t, canonicalTestTempDir(t))
	artifactRoot := mustMCPRoot(t, filepath.Join(projectRoot.String(), ".mulgae"))
	sessionID := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	backend, err := newMCPBoundTestBackend(
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
	backend, err := newMCPBoundTestBackend(
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
	findings       mcpFixtureFindings
	excerpt        []byte
	excerptErr     error
	excerptFinding string
	excerptTarget  string
}

type mcpMultiQueryFake struct {
	root      ports.AnchoredRoot
	sessionID domain.SessionID
	statuses  map[domain.RunID]mulgaeentry.RunStatusView
	findings  map[domain.RunID]mcpFixtureFindings
}

func (fake *mcpMultiQueryFake) ResolveRun(_ context.Context, root ports.AnchoredRoot, runID domain.RunID) (ports.PublicationRun, error) {
	if root != fake.root {
		return ports.PublicationRun{}, errors.New("root mismatch")
	}
	return ports.NewPublicationRun(root, fake.sessionID, runID)
}

func (fake *mcpMultiQueryFake) ReadRunStatus(_ context.Context, run ports.PublicationRun) (mulgaeentry.RunStatusView, error) {
	status, ok := fake.statuses[run.RunID()]
	if !ok {
		return mulgaeentry.RunStatusView{FailedRunRecovery: recovery.UnavailableStatus("source_not_retained")}, errors.New("status unavailable")
	}
	return status, nil
}

func (fake *mcpMultiQueryFake) ListFindings(_ context.Context, run ports.PublicationRun, _ domain.Severity) (mcpFixtureFindings, error) {
	findings, ok := fake.findings[run.RunID()]
	if !ok {
		return mcpFixtureFindings{}, errors.New("findings unavailable")
	}
	return findings, nil
}

func (*mcpMultiQueryFake) RenderExcerpt(context.Context, ports.PublicationRun, string, string) ([]byte, error) {
	return nil, nil
}

type mcpDiagnosticQueryFake struct {
	status       ports.RuntimeDiagnosticRunStatus
	err          error
	calls        int
	sessionCalls int
	sessionID    domain.SessionID
	runID        domain.RunID
}

func (fake *mcpDiagnosticQueryFake) ReadRunStatus(context.Context, ports.AnchoredRoot, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.calls++
	return fake.status, fake.err
}

func (fake *mcpDiagnosticQueryFake) ReadSessionRunStatus(_ context.Context, _ ports.AnchoredRoot, sessionID domain.SessionID, runID domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.sessionCalls++
	fake.sessionID, fake.runID = sessionID, runID
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

func (fake *mcpQueryFake) ListFindings(context.Context, ports.PublicationRun, domain.Severity) (mcpFixtureFindings, error) {
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

func TestMCPBackendRejectsGitAdoptionAfterFailedStartup(t *testing.T) {
	projectPath := canonicalTestTempDir(t)
	projectRoot := mustMCPRoot(t, projectPath)
	artifactRoot := mustMCPRoot(t, filepath.Join(projectPath, ".mulgae"))
	reviews := &mcpReviewRunFake{}
	queries := &mcpQueryFake{}
	backend, err := newMCPBoundTestBackend(projectRoot, artifactRoot, newMCPTestApplicationWithReviewRuns(t, queries, reviews), queries, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	backend.projectContexts, err = query.NewProjectContextService(gittarget.ProjectBindingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	backend.contextLease, backend.contextError = backend.projectContexts.Open(context.Background(), projectRoot)
	if backend.contextLease != nil || backend.contextError == nil {
		t.Fatal("fixture unexpectedly acquired startup binding")
	}
	command := exec.Command("/usr/bin/git", "-C", projectPath, "init", "--quiet")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, raw)
	}
	if _, err := backend.GetContext(context.Background()); err == nil {
		t.Fatal("failed startup context was retargeted")
	}
	for _, execute := range []func(context.Context, string, mcpentry.RunReviewInput) (mcpentry.BackendResult, error){backend.RunReview, backend.PreflightReview} {
		result, err := execute(context.Background(), "i_019f596a-cf80-7c67-b265-f37053d51ccf", mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "workspace"}})
		var failure *domain.Failure
		if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || result.Data != nil {
			t.Errorf("failed startup admission: result=%#v err=%v", result, err)
		}
	}
	if reviews.calls != 0 {
		t.Fatalf("failed startup dispatched %d reviews", reviews.calls)
	}
}

func TestMCPBackendNonGitStartupRootRemainsBound(t *testing.T) {
	for _, change := range []string{"same", "new-file", "git-created", "root-replaced", "closed", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			fixture := canonicalTestTempDir(t)
			projectPath := filepath.Join(fixture, "project")
			if err := os.Mkdir(projectPath, 0700); err != nil {
				t.Fatal(err)
			}
			root := mustMCPRoot(t, projectPath)
			lease, err := gittarget.OpenUnboundWorkspaceRoot(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			})
			backend := &mcpBackend{projectRoot: root, workspaceLease: lease, contextError: errors.New("startup Git context unavailable")}
			ctx := context.Background()
			switch change {
			case "new-file":
				if err := os.WriteFile(filepath.Join(projectPath, "source.txt"), []byte("current source"), 0600); err != nil {
					t.Fatal(err)
				}
			case "git-created":
				command := exec.Command("/usr/bin/git", "-C", projectPath, "init", "--quiet")
				if raw, err := command.CombinedOutput(); err != nil {
					t.Fatalf("git fixture: %v %s", err, raw)
				}
			case "root-replaced":
				if err := os.Rename(projectPath, filepath.Join(fixture, "original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(projectPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = backend.checkReviewProject(ctx, nil)
			if change == "same" || change == "new-file" {
				if err != nil {
					t.Fatalf("valid non-Git root rejected: %v", err)
				}
				return
			}
			var failure *domain.Failure
			want := domain.FailureSecurityPolicy
			if change == "cancelled" {
				want = domain.FailureCancelled
			}
			if !errors.As(err, &failure) || failure.Class() != want {
				t.Fatalf("changed non-Git startup root admitted: %v", err)
			}
		})
	}
}
