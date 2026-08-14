//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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
		projectRoot, artifactRoot, &mulgaeentry.Application{}, &mcpQueryFake{}, filesystem.NewRunSelector(),
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
			Findings: []mulgaeentry.FindingView{{ID: "F001", Severity: domain.SeverityHigh, Title: "Boundary regression"}},
		},
	}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, filesystem.NewRunSelector())
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
	if err != nil || status["final_artifact_uri"] == nil || status["ci_decision"] != string(domain.CIPass) {
		t.Fatalf("run status = %#v, %v", status, err)
	}
	findings, err := backend.ListFindings(context.Background(), mcpentry.ListFindingsInput{RunID: runID.String(), MinimumSeverity: "high"})
	if err != nil || findings["finding_count"] != 1 || findings["minimum_severity"] != "high" {
		t.Fatalf("findings = %#v, %v", findings, err)
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
			Findings: []mulgaeentry.FindingView{{ID: "F001", Severity: domain.SeverityLow, Title: "Below threshold"}},
		},
	}
	backend, err := newMCPBackend(projectRoot, artifactRoot, &mulgaeentry.Application{}, queries, filesystem.NewRunSelector())
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

type mcpQueryFake struct {
	run      ports.PublicationRun
	status   mulgaeentry.RunStatusView
	findings mulgaeentry.FindingsView
}

func (fake *mcpQueryFake) ResolveRun(context.Context, ports.AnchoredRoot, domain.RunID) (ports.PublicationRun, error) {
	return fake.run, nil
}

func (fake *mcpQueryFake) ReadRunStatus(context.Context, ports.PublicationRun) (mulgaeentry.RunStatusView, error) {
	return fake.status, nil
}

func (fake *mcpQueryFake) ListFindings(context.Context, ports.PublicationRun, domain.Severity) (mulgaeentry.FindingsView, error) {
	return fake.findings, nil
}

func (fake *mcpQueryFake) RenderExcerpt(context.Context, ports.PublicationRun, string, string) ([]byte, error) {
	return nil, nil
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
