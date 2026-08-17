//go:build darwin && arm64

package e2e

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

const (
	extractionProseReport = "# security review\n\nThe staged constant is renamed without updating its consumers.\n"
	// A syntactically valid transcription whose quote does not match the target.
	// Its severity sits below validation.evidence.require_verified_for, so it is
	// admitted on the direct structured path but must be rejected here.
	extractionUnverifiableOutput = `{"schema_version":"mulgae-provider-review-output.v1","summary":"One unverifiable claim.","completeness":"complete","limitations":[],"findings":[{"severity":"info","title":"Quote does not match the target","description":"The transcription claims bytes the captured target does not contain.","evidence":[{"current":{"path":"review.go","side":"index","line_start":3,"line_end":3,"quote":"const state = \"never-written\"\n"}}],"recommendation":"Reject the transcription.","confidence":"high"}]}`

	extractionWireOutput = `{"schema_version":"mulgae-provider-review-output.v1","summary":"One transcribed defect.","completeness":"complete","limitations":[],"findings":[{"severity":"info","title":"Renamed constant is transcribed from the accepted report","description":"The accepted role report claims the staged constant changed.","evidence":[{"current":{"path":"review.go","side":"index","line_start":3,"line_end":3,"quote":"const state = \"after\"\n"}}],"recommendation":"Confirm the consumers of the renamed constant.","confidence":"high"}]}`
)

// extractionProject installs a single-role AGY project whose fake provider
// answers reviewOutput first and trailerOutput to the extraction trailer.
func extractionProject(t *testing.T, reviewOutput, trailerOutput string) (string, string, []string) {
	t.Helper()
	root := repositoryRoot(t)
	binary := buildMulgaeBinary(t, root)
	project := canonicalTestTempDir(t)
	initializeReviewGitRepository(t, project)
	runTestCommand(t, project, "git", "add", "review.go")

	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	agyExecutable := filepath.Join(providerDirectory, "agy")
	logPath := filepath.Join(canonicalTestTempDir(t), "agy-observations.jsonl")
	buildFakeAGYWithSequencedReviewOutput(t, root, agyExecutable, logPath, reviewOutput, trailerOutput)

	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "agy", "--roles", "security", "--agy-executable", agyExecutable)
	if initialized.exitCode != 0 {
		t.Fatalf("initialize extraction project: exit=%d stdout=%q stderr=%q",
			initialized.exitCode, initialized.stdout, initialized.stderr)
	}
	return binary, project, environment
}

func extractionReview(t *testing.T, binary, project string, environment []string) commandEnvelope {
	t.Helper()
	review := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--roles", "security", "--output", "json")
	var envelope commandEnvelope
	if err := json.Unmarshal(review.stdout, &envelope); err != nil {
		t.Fatalf("decode extraction review envelope: %v: %q", err, review.stdout)
	}
	if review.exitCode != 0 || len(review.stderr) != 0 || envelope.Exit.Kind != "success" ||
		envelope.Result.ReviewArtifactURI == nil || envelope.Result.RunManifestURI == nil {
		dumpRuntimeDiagnostics(t, project, envelope)
		t.Fatalf("extraction review = exit %d envelope %#v stderr %q", review.exitCode, envelope, review.stderr)
	}
	return envelope
}

type extractionFinalReview struct {
	StructuredExtractionStatus string `json:"structured_extraction_status"`
	ContentVerdict             string `json:"content_verdict"`
	Findings                   []struct {
		ID       string `json:"id"`
		Role     string `json:"role"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	} `json:"findings"`
}

func readExtractionFinalReview(t *testing.T, project string, envelope commandEnvelope) extractionFinalReview {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(project, *envelope.Result.ReviewArtifactURI))
	if err != nil {
		t.Fatalf("read final review: %v", err)
	}
	var final extractionFinalReview
	if err := json.Unmarshal(raw, &final); err != nil {
		t.Fatalf("decode final review: %v", err)
	}
	return final
}

func extractionCandidatePaths(t *testing.T, project string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(project, ".mulgae", "s_*", "r_*", "attempts", "a_*", "candidate.extracted.*.json"))
	if err != nil {
		t.Fatalf("glob extracted candidates: %v", err)
	}
	return matches
}

// A role that returns prose is transcribed into committed structured findings,
// while the published role report stays the accepted prose byte for byte.
func TestIntegrationStructuredExtractionPublishesFindingsFromProseReport(t *testing.T) {
	binary, project, environment := extractionProject(t, extractionProseReport, extractionWireOutput)
	envelope := extractionReview(t, binary, project, environment)

	final := readExtractionFinalReview(t, project, envelope)
	if final.StructuredExtractionStatus != "structured" {
		t.Fatalf("structured_extraction_status = %q, want structured", final.StructuredExtractionStatus)
	}
	if len(final.Findings) != 1 || final.Findings[0].Role != "security" {
		t.Fatalf("committed findings = %#v, want one security finding", final.Findings)
	}
	assertPublishedRoleReports(t, project, envelope, map[string]publishedRoleReport{
		"security": {transport: "stdout", providerInstance: "agy-security", content: extractionProseReport},
	})
	if candidates := extractionCandidatePaths(t, project); len(candidates) != 1 {
		t.Fatalf("extracted candidate artifacts = %#v, want exactly one", candidates)
	}
	stdout, err := filepath.Glob(filepath.Join(project, ".mulgae", "s_*", "r_*", "attempts", "a_*", "invocations", "002-extract", "stdout.raw"))
	if err != nil || len(stdout) != 1 {
		t.Fatalf("extraction invocation streams = %#v, err=%v", stdout, err)
	}
	prompts, err := filepath.Glob(filepath.Join(project, ".mulgae", "s_*", "r_*", "prompts", "a_*", "002-extract.stdin"))
	if err != nil || len(prompts) != 1 {
		t.Fatalf("extraction prompt artifacts = %#v, err=%v", prompts, err)
	}
}

// A failed extraction must never fail a review that would otherwise publish.
func TestIntegrationStructuredExtractionFailureStaysReportsOnlyAndPublishes(t *testing.T) {
	binary, project, environment := extractionProject(t, extractionProseReport, extractionProseReport)
	envelope := extractionReview(t, binary, project, environment)

	final := readExtractionFinalReview(t, project, envelope)
	if final.StructuredExtractionStatus != "reports_only" {
		t.Fatalf("structured_extraction_status = %q, want reports_only", final.StructuredExtractionStatus)
	}
	if len(final.Findings) != 0 {
		t.Fatalf("committed findings = %#v, want none", final.Findings)
	}
	assertPublishedRoleReports(t, project, envelope, map[string]publishedRoleReport{
		"security": {transport: "stdout", providerInstance: "agy-security", content: extractionProseReport},
	})
	if candidates := extractionCandidatePaths(t, project); len(candidates) != 0 {
		t.Fatalf("failed extraction persisted candidates = %#v, want none", candidates)
	}
}

// Extraction shares the one second invocation repair competes for, so the
// projected role path and its ceilings are unchanged. This is the regression
// guard for keeping mulgae-review-preflight.v3 and mulgae-command-result.v4.
func TestIntegrationStructuredExtractionDoesNotWidenPreflightBudget(t *testing.T) {
	binary, project, environment := extractionProject(t, extractionProseReport, extractionWireOutput)
	preflight := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--stage", "--roles", "security", "--preflight", "--output", "json")
	if preflight.exitCode != 0 || len(preflight.stderr) != 0 {
		t.Fatalf("preflight = exit %d stdout %q stderr %q", preflight.exitCode, preflight.stdout, preflight.stderr)
	}
	var envelope struct {
		Result struct {
			Preflight struct {
				Budget struct {
					TotalInvocations int `json:"total_invocations"`
					Ceilings         struct {
						MaxInvocationsPerRole int `json:"max_invocations_per_role"`
						MaxInvocationsPerRun  int `json:"max_invocations_per_run"`
					} `json:"ceilings"`
					RolePaths []struct {
						Role            string `json:"role"`
						InvocationCount int    `json:"invocation_count"`
						TransitionCount int    `json:"transition_count"`
					} `json:"role_paths"`
				} `json:"budget"`
			} `json:"preflight"`
		} `json:"result"`
	}
	if err := json.Unmarshal(preflight.stdout, &envelope); err != nil {
		t.Fatalf("decode preflight envelope: %v: %q", err, preflight.stdout)
	}
	budget := envelope.Result.Preflight.Budget
	if budget.Ceilings.MaxInvocationsPerRole != 2 || budget.Ceilings.MaxInvocationsPerRun > 14 {
		t.Fatalf("preflight ceilings = %#v, want the unchanged two-invocation envelope", budget.Ceilings)
	}
	if len(budget.RolePaths) != 1 || budget.RolePaths[0].InvocationCount != 2 || budget.RolePaths[0].TransitionCount != 1 {
		t.Fatalf("preflight role paths = %#v, want one two-invocation path", budget.RolePaths)
	}
}

// Mulgae cannot prove a transcribed finding restates a claim the accepted report
// made, so it publishes one only when it verified that finding against the
// immutable target. An unverifiable transcription is rejected whole, at any
// severity, and the review still publishes with its accepted prose report.
func TestIntegrationStructuredExtractionRejectsUnverifiableFinding(t *testing.T) {
	binary, project, environment := extractionProject(t, extractionProseReport, extractionUnverifiableOutput)
	envelope := extractionReview(t, binary, project, environment)

	final := readExtractionFinalReview(t, project, envelope)
	if final.StructuredExtractionStatus != "reports_only" {
		t.Fatalf("structured_extraction_status = %q, want reports_only", final.StructuredExtractionStatus)
	}
	if len(final.Findings) != 0 {
		t.Fatalf("committed findings = %#v, want none from an unverifiable transcription", final.Findings)
	}
	assertPublishedRoleReports(t, project, envelope, map[string]publishedRoleReport{
		"security": {transport: "stdout", providerInstance: "agy-security", content: extractionProseReport},
	})
}
