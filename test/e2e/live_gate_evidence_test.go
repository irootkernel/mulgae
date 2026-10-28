//go:build darwin && arm64 && live_e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func recordLiveGateAttempt(t *testing.T, environment liveE2EEnvironment, scenario string, attempt, maximum int, arguments []string, phase string, envelope *liveCommandEnvelope, published *livePublishedRun) {
	t.Helper()
	directory := os.Getenv("MULGAE_E2E_FUNCTIONAL_EVIDENCE_DIR")
	if directory == "" {
		return
	}
	canonical, err := filepath.EvalSymlinks(directory)
	info, statErr := os.Lstat(directory)
	if err != nil || statErr != nil || !filepath.IsAbs(directory) || canonical != directory || !info.IsDir() || info.Mode().Perm() != 0o700 || strings.ContainsAny(scenario, "/\\") {
		t.Fatal("live gate evidence requires an existing canonical private directory")
	}
	binary, err := os.ReadFile(environment.binary)
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{"scenario": scenario, "attempt": attempt, "maximum_attempts": maximum, "phase": phase, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "binary_sha256": liveArtifactSHA256(binary), "arguments_sha256": liveArtifactSHA256(request)}
	if envelope != nil {
		evidence["exit_code"], evidence["exit_kind"] = envelope.Exit.Code, envelope.Exit.Kind
		evidence["session_id"], evidence["run_id"] = envelope.Result.SessionID, envelope.Result.RunID
		reasons := []map[string]any{}
		for _, reason := range envelope.Reasons {
			reasons = append(reasons, map[string]any{"category": reason.Category, "code": reason.Code, "retryable": reason.Retryable})
		}
		evidence["reasons"] = reasons
	}
	if published != nil {
		evidence["review_id"] = published.review.ReviewID
		evidence["source_identity_sha256"] = published.manifest.Target.SourceIdentitySHA256
		evidence["attempts"], evidence["failures"] = published.manifest.Attempts, published.manifest.Failures
		evidence["coverage_status"], evidence["structured_extraction_status"] = published.manifest.CoverageStatus, published.manifest.StructuredExtractionState
		evidence["publication_authority"], evidence["publication_status"] = published.manifest.PublicationAuthority, published.manifest.PublicationStatus
		evidence["role_report_count"], evidence["finding_count"] = len(published.manifest.RoleReports), len(published.review.Findings)
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, fmt.Sprintf("%s-%d-%s.json", scenario, attempt, phase))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(append(raw, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("live gate evidence write failed")
	}
}

func TestLiveGateEvidenceKeepsFailedAttemptWithoutPrivateProse(t *testing.T) {
	t.Setenv("MULGAE_E2E_FUNCTIONAL_EVIDENCE_DIR", "")
	recordLiveGateAttempt(t, liveE2EEnvironment{binary: "not-an-executable"}, "disabled", 1, 2, nil, "started", nil, nil)
	directory := canonicalTestTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MULGAE_E2E_FUNCTIONAL_EVIDENCE_DIR", directory)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment := liveE2EEnvironment{binary: binary}
	arguments := []string{"review", "--objective", "PRIVATE_REQUEST_PROSE"}
	failed := liveCommandEnvelope{}
	failed.Exit.Code, failed.Exit.Kind = 7, "readiness"
	failed.Reasons = []liveReason{{Category: "readiness", Code: "provider_qualification_failed", Message: "PRIVATE_DIAGNOSTIC_PROSE", Retryable: true}}
	recordLiveGateAttempt(t, environment, "fixture", 1, 2, arguments, "started", nil, nil)
	recordLiveGateAttempt(t, environment, "fixture", 1, 2, arguments, "terminal", &failed, nil)
	recordLiveGateAttempt(t, environment, "fixture", 2, 2, arguments, "started", nil, nil)
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 3 {
		t.Fatal("failed first attempt was overwritten or omitted")
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil || strings.Contains(string(raw), "PRIVATE_") {
			t.Fatal("request or diagnostic prose entered compact gate evidence")
		}
	}
	raw, err := os.ReadFile(filepath.Join(directory, "fixture-1-terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var terminal map[string]any
	if json.Unmarshal(raw, &terminal) != nil || terminal["exit_code"] != float64(7) || terminal["reasons"].([]any)[0].(map[string]any)["code"] != "provider_qualification_failed" {
		t.Fatal("real exit or typed failed-attempt outcome was lost")
	}
}
