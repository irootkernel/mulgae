package mcpentry

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	testMCPRunID        = "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	testMCPSessionID    = "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	testMCPTargetSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestParseResourceURIAdmitsOnlyCanonicalSelectors(t *testing.T) {
	reportURI, err := NewReportResourceURI(testMCPRunID)
	if err != nil {
		t.Fatal(err)
	}
	evidenceURI, err := NewEvidenceResourceURI(testMCPRunID, "F001", testMCPTargetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{reportURI, reportURI + "?offset=16384", evidenceURI, evidenceURI + "&offset=16384"} {
		request, err := ParseResourceURI(uri)
		if err != nil || request.URI() != uri || request.RunID() != testMCPRunID {
			t.Fatalf("ParseResourceURI(%q) = %#v, %v", uri, request, err)
		}
	}

	invalidURIs := []string{
		"",
		reportURI + "?offset=0",
		reportURI + "?offset=01",
		reportURI + "?unknown=true",
		reportURI + "#fragment",
		"mulgae://runs/%72_019f596a-cfe4-7c9c-b82e-7149158243ba/report",
		strings.Replace(evidenceURI, "sha256%3Aaaaaaaaa", "sha256%3AAAAAAAAA", 1),
	}
	for _, uri := range invalidURIs {
		if _, err := ParseResourceURI(uri); err == nil {
			t.Fatalf("invalid resource URI was accepted: %q", uri)
		}
	}
}

func TestProjectResourceOwnsCanonicalTextAndBinaryChunking(t *testing.T) {
	reportBytes := []byte(strings.Repeat("a", MaxResourceChunkBytes-1) + "가\nrest")
	reportURI, err := NewReportResourceURI(testMCPRunID)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest, err := ParseResourceURI(reportURI)
	if err != nil {
		t.Fatal(err)
	}
	first, err := projectResource(firstRequest, ResourceContent{MIMEType: "text/markdown", Bytes: reportBytes, Text: true})
	if err != nil || len(first.Text) > MaxResourceChunkBytes || !strings.HasSuffix(first.Text, "a") {
		t.Fatalf("first report chunk = %#v, %v", first, err)
	}
	nextReport, ok := first.Meta["io.mulgae/nextURI"].(string)
	if !ok || nextReport == "" {
		t.Fatalf("report continuation = %#v", first.Meta)
	}
	secondRequest, err := ParseResourceURI(nextReport)
	if err != nil {
		t.Fatal(err)
	}
	second, err := projectResource(secondRequest, ResourceContent{MIMEType: "text/markdown", Bytes: reportBytes, Text: true})
	if err != nil || first.Text+second.Text != string(reportBytes) || second.Meta["io.mulgae/nextURI"] != nil {
		t.Fatalf("second report chunk = %#v, %v", second, err)
	}
	invalidOffset, err := ParseResourceURI(reportURI + "?offset=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projectResource(invalidOffset, ResourceContent{MIMEType: "text/markdown", Bytes: reportBytes, Text: true}); err == nil {
		t.Fatal("unissued report continuation was accepted")
	}

	evidenceBytes := bytes.Repeat([]byte{0x00, 0xff, 0x7f}, MaxResourceChunkBytes/3+10)
	evidenceURI, err := NewEvidenceResourceURI(testMCPRunID, "F001", testMCPTargetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRequest, err := ParseResourceURI(evidenceURI)
	if err != nil {
		t.Fatal(err)
	}
	firstEvidence, err := projectResource(evidenceRequest, ResourceContent{MIMEType: "application/octet-stream", Bytes: evidenceBytes})
	if err != nil || len(firstEvidence.Blob) != MaxResourceChunkBytes {
		t.Fatalf("first evidence chunk = %#v, %v", firstEvidence, err)
	}
	nextEvidence := firstEvidence.Meta["io.mulgae/nextURI"].(string)
	secondEvidenceRequest, err := ParseResourceURI(nextEvidence)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, err := projectResource(secondEvidenceRequest, ResourceContent{MIMEType: "application/octet-stream", Bytes: evidenceBytes})
	combined := append(append([]byte(nil), firstEvidence.Blob...), secondEvidence.Blob...)
	if err != nil || !bytes.Equal(combined, evidenceBytes) || secondEvidence.Meta["io.mulgae/nextURI"] != nil {
		t.Fatalf("evidence continuation = %#v, %v", secondEvidence.Meta, err)
	}
}

func TestProjectRunStatusValidatesPublicationPolicyAndPublicShape(t *testing.T) {
	sessionID, err := domain.ParseSessionID(testMCPSessionID)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID(testMCPRunID)
	if err != nil {
		t.Fatal(err)
	}
	status := RunStatusProjection{
		SessionID: testMCPSessionID, RunID: testMCPRunID,
		RunState: domain.RunCompleted, HasRunState: true,
		PublicationState: domain.PublicationCommitted, RecoveryAction: domain.RecoveryActionReconstructCompletedStatus,
		FinalArtifactURI: ".mulgae/" + testMCPSessionID + "/" + testMCPRunID + "/review.json", HasFinalArtifact: true,
		ContentVerdict: domain.ContentNoFindings, CoverageStatus: domain.CoverageComplete,
		CIDecision: domain.CIPass, HasAxes: true,
		RoleReports: []RoleReportProjection{{
			Role: string(domain.RoleLogic),
			URI:  ".mulgae/" + testMCPSessionID + "/" + testMCPRunID + "/role-reports/logic.md",
		}},
	}
	projected, err := ProjectRunStatus(status, sessionID, runID)
	if err != nil || projected["kind"] != "status_read" || projected["run_id"] != testMCPRunID || projected["report_resource_uri"] == nil {
		t.Fatalf("run status projection = %#v, %v", projected, err)
	}
	status.RecoveryAction = domain.RecoveryActionNone
	if _, err := ProjectRunStatus(status, sessionID, runID); err == nil {
		t.Fatal("invalid publication/recovery pair was accepted")
	}
}

func TestProjectDiagnosticRunStatusIsBoundedAndHasNoPublicationAuthority(t *testing.T) {
	sessionID, err := domain.ParseSessionID(testMCPSessionID)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID(testMCPRunID)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, time.August, 14, 5, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed,
		StartedAt: startedAt, UpdatedAt: completedAt, CompletedAt: completedAt, HasCompletedAt: true,
		SelectedRoles: []domain.Role{domain.RoleSecurity}, RolePathTotal: 1, RolePathFailed: 1,
		LastSequence: 7, TerminalCause: domain.DiagnosticCauseProviderSpawnFailed, DroppedEvents: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectDiagnosticRunStatus(status, sessionID, runID)
	if err != nil || projected["kind"] != "diagnostic_status_read" || projected["diagnostic_only"] != true ||
		projected["publication_authority"] != false || projected["publication_status"] != nil ||
		projected["final_artifact_uri"] != nil || projected["report_resource_uri"] != nil ||
		projected["recovery_action"] != "rerun_review" || projected["terminal_cause"] != string(domain.DiagnosticCauseProviderSpawnFailed) {
		t.Fatalf("diagnostic run status projection = %#v, %v", projected, err)
	}
	if _, err := ProjectDiagnosticRunStatus(status, sessionID, mustProjectionRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243bb")); err == nil {
		t.Fatal("diagnostic projection accepted a mismatched run identity")
	}
	p2URI, err := ports.NewSafeRelativePath("s/r/final.json")
	if err != nil {
		t.Fatal(err)
	}
	statusWithP2, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: sessionID, RunID: runID, State: domain.RunFailed,
		StartedAt: startedAt, UpdatedAt: completedAt, CompletedAt: completedAt, HasCompletedAt: true,
		P2URI: p2URI, HasP2URI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProjectDiagnosticRunStatus(statusWithP2, sessionID, runID); err == nil {
		t.Fatal("diagnostic-only projection accepted an installed P2 URI")
	}
}

func mustProjectionRunID(t *testing.T, value string) domain.RunID {
	t.Helper()
	runID, err := domain.ParseRunID(value)
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

func TestProjectFindingsValidatesSelectedPublicRows(t *testing.T) {
	view := FindingsProjection{
		RunID: testMCPRunID, MinimumSeverity: domain.SeverityHigh,
		TargetSHA256: testMCPTargetSHA256, ReviewArtifactURI: ".mulgae/review.json",
		Findings: []FindingProjection{{ID: "F001", Severity: domain.SeverityHigh, Title: "Boundary regression"}},
	}
	projected, err := ProjectFindings(view)
	if err != nil || projected["finding_count"] != 1 {
		t.Fatalf("findings projection = %#v, %v", projected, err)
	}
	rows := projected["findings"].([]any)
	if rows[0].(map[string]any)["evidence_resource_uri"] == "" {
		t.Fatalf("finding resource URI = %#v", rows[0])
	}
	view.Findings[0].Severity = domain.SeverityLow
	if _, err := ProjectFindings(view); err == nil {
		t.Fatal("finding below the selected threshold was accepted")
	}
}
