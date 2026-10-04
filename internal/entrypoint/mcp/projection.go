package mcpentry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// RoleReportProjection is one verified role report identity in a run status.
type RoleReportProjection struct {
	Role string
	URI  string
}

// RunStatusProjection is the typed input to the MCP public run-status shape.
type RunStatusProjection struct {
	FailedRunRecovery    recovery.Status
	SessionID            string
	RunID                string
	RunState             domain.RunState
	HasRunState          bool
	PublicationState     domain.PublicationStatus
	RecoveryAction       domain.RecoveryAction
	FinalArtifactURI     string
	HasFinalArtifact     bool
	ContentVerdict       domain.ContentVerdict
	CoverageStatus       domain.CoverageStatus
	CIDecision           domain.CIDecision
	HasAxes              bool
	RoleReports          []RoleReportProjection
	DiagnosticSummary    ports.RuntimeDiagnosticSummary
	HasDiagnosticSummary bool
}

// ProjectRunStatus validates and renders one bounded MCP run-status object.
func ProjectRunStatus(status RunStatusProjection, expectedSessionID domain.SessionID, expectedRunID domain.RunID) (map[string]any, error) {
	sessionID, sessionErr := domain.ParseSessionID(status.SessionID)
	runID, runErr := domain.ParseRunID(status.RunID)
	if sessionErr != nil || runErr != nil || sessionID != expectedSessionID || runID != expectedRunID ||
		!status.PublicationState.Valid() || !status.RecoveryAction.Valid() || status.PublicationState == domain.PublicationCorrupt ||
		!domain.PublicationRecoveryCompatible(status.PublicationState, status.RecoveryAction) {
		return nil, fmt.Errorf("MCP run status projection is invalid")
	}
	if err := status.FailedRunRecovery.ValidateFor(runID); err != nil {
		return nil, err
	}
	if status.FailedRunRecovery.Available && (status.PublicationState != domain.PublicationNotPublished || !status.HasRunState || status.RunState != domain.RunFailed && status.RunState != domain.RunCancelled) {
		return nil, fmt.Errorf("MCP recovery status has inconsistent terminal state")
	}
	if status.PublicationState == domain.PublicationCommitted &&
		status.RunState != domain.RunCompleted && status.RunState != domain.RunDegraded && status.RunState != domain.RunFailed {
		return nil, fmt.Errorf("MCP committed run status state is invalid")
	}
	if status.HasRunState != (status.RunState != "") || status.HasRunState && !status.RunState.Valid() ||
		status.HasFinalArtifact != (status.FinalArtifactURI != "") ||
		status.HasAxes != (status.ContentVerdict != "" && status.CoverageStatus != "" && status.CIDecision != "") ||
		status.HasDiagnosticSummary != status.DiagnosticSummary.Valid() {
		return nil, fmt.Errorf("MCP run status projection is inconsistent")
	}
	if status.HasFinalArtifact {
		path, err := ports.NewSafeRelativePath(status.FinalArtifactURI)
		if err != nil || path.String() != status.FinalArtifactURI || !strings.HasPrefix(status.FinalArtifactURI, ".mulgae/") {
			return nil, fmt.Errorf("MCP run status artifact URI is invalid")
		}
	}
	if status.HasAxes && (!status.ContentVerdict.Valid() || !status.CoverageStatus.Valid() || !status.CIDecision.Valid()) {
		return nil, fmt.Errorf("MCP run status outcome is invalid")
	}
	if status.PublicationState == domain.PublicationCommitted {
		if !status.HasRunState || !status.HasFinalArtifact || !status.HasAxes {
			return nil, fmt.Errorf("MCP committed run status is incomplete")
		}
	} else if status.HasFinalArtifact || status.HasAxes || len(status.RoleReports) != 0 {
		return nil, fmt.Errorf("MCP non-committed run status exposed committed fields")
	}
	data := map[string]any{
		"failed_run_recovery": status.FailedRunRecovery,
		"kind":                "status_read",
		"session_id":          status.SessionID, "run_id": status.RunID,
		"publication_status": string(status.PublicationState), "recovery_action": string(status.RecoveryAction),
	}
	if status.PublicationState == domain.PublicationCommitted {
		data["report_resource_uri"] = reportResourceURI(status.RunID, 0)
	} else {
		data["report_resource_uri"] = nil
	}
	if status.HasRunState {
		data["run_state"] = string(status.RunState)
	} else {
		data["run_state"] = nil
	}
	if status.HasFinalArtifact {
		data["final_artifact_uri"] = status.FinalArtifactURI
	} else {
		data["final_artifact_uri"] = nil
	}
	if status.HasAxes {
		data["content_verdict"] = string(status.ContentVerdict)
		data["coverage_status"] = string(status.CoverageStatus)
		data["ci_decision"] = string(status.CIDecision)
	} else {
		data["content_verdict"], data["coverage_status"], data["ci_decision"] = nil, nil, nil
	}
	roleReports := make([]any, 0, len(status.RoleReports))
	rolePrefix := ".mulgae/" + sessionID.String() + "/" + runID.String() + "/role-reports/"
	seenRoles := make(map[string]struct{}, len(status.RoleReports))
	for _, report := range status.RoleReports {
		role := domain.Role(report.Role)
		if !role.Valid() || report.URI != rolePrefix+report.Role+".md" {
			return nil, fmt.Errorf("MCP run status role report URI is invalid")
		}
		if _, duplicate := seenRoles[report.Role]; duplicate {
			return nil, fmt.Errorf("MCP run status role report URI is duplicated")
		}
		seenRoles[report.Role] = struct{}{}
		roleReports = append(roleReports, map[string]any{"role": report.Role, "uri": report.URI})
	}
	data["role_report_uris"] = roleReports
	if status.HasDiagnosticSummary {
		data["diagnostic_summary"] = projectRuntimeDiagnosticSummary(status.DiagnosticSummary)
	}
	return data, nil
}

func projectRuntimeDiagnosticSummary(summary ports.RuntimeDiagnosticSummary) map[string]any {
	data := map[string]any{"component": summary.Component(), "phase": summary.Phase()}
	for key, value := range map[string]string{
		"invariant_id": summary.InvariantID(), "provider_instance": summary.Provider(),
		"attempt_id": summary.AttemptID().String(), "invocation_id": summary.InvocationID(),
		"protocol_terminal": summary.ProtocolTerminal(), "provider_session_fingerprint": summary.ProviderSessionFingerprint(),
		"provider_turn_fingerprint": summary.ProviderTurnFingerprint(),
	} {
		if value != "" {
			data[key] = value
		}
	}
	return data
}

// ProjectDiagnosticRunStatus validates and renders the bounded status of an
// unpublished run. It deliberately carries no publication authority or paths.
func ProjectDiagnosticRunStatus(status ports.RuntimeDiagnosticRunStatus, expectedSessionID domain.SessionID, expectedRunID domain.RunID) (map[string]any, error) {
	if status.SessionID() != expectedSessionID || status.RunID() != expectedRunID ||
		!status.State().Valid() || status.StartedAt().IsZero() || status.UpdatedAt().Before(status.StartedAt()) ||
		status.StartedAt().Location() != time.UTC || status.UpdatedAt().Location() != time.UTC || len(status.SelectedRoles()) > 7 {
		return nil, fmt.Errorf("MCP diagnostic run status projection is invalid")
	}
	if _, installed := status.P2URI(); installed {
		return nil, fmt.Errorf("MCP diagnostic run status has publication authority")
	}
	completedAt, hasCompletedAt := status.CompletedAt()
	if (status.State() == domain.RunPending || status.State() == domain.RunRunning) && !hasCompletedAt {
		return nil, ErrRunStatusUnavailable
	}
	if status.State() != domain.RunFailed && status.State() != domain.RunCancelled || !hasCompletedAt ||
		completedAt.IsZero() || completedAt.Location() != time.UTC || completedAt.Before(status.UpdatedAt()) {
		return nil, fmt.Errorf("MCP diagnostic run completion is invalid")
	}
	roles := status.SelectedRoles()
	selectedRoles := make([]string, 0, len(roles))
	for _, role := range roles {
		if !role.Valid() {
			return nil, fmt.Errorf("MCP diagnostic run role is invalid")
		}
		selectedRoles = append(selectedRoles, string(role))
	}
	total, completed, failed := status.RolePathCounts()
	if total < 0 || completed < 0 || failed < 0 || completed+failed > total {
		return nil, fmt.Errorf("MCP diagnostic run role-path counts are invalid")
	}
	var terminalCause, terminalPhase any
	if cause := status.TerminalCause(); cause != "" {
		if !cause.Valid() {
			return nil, fmt.Errorf("MCP diagnostic run terminal cause is invalid")
		}
		terminalCause = string(cause)
	}
	if phase := status.TerminalPhase(); phase != "" {
		if !phase.Valid() || terminalCause == nil {
			return nil, fmt.Errorf("MCP diagnostic run terminal phase is invalid")
		}
		terminalPhase = string(phase)
	}
	data := map[string]any{
		"failed_run_recovery": recovery.UnavailableStatus("source_not_retained"),
		"kind":                "diagnostic_status_read", "session_id": status.SessionID().String(), "run_id": status.RunID().String(),
		"run_state": string(status.State()), "publication_status": nil, "recovery_action": "none",
		"final_artifact_uri": nil, "report_resource_uri": nil, "content_verdict": nil, "coverage_status": nil, "ci_decision": nil,
		"role_report_uris": []any{}, "started_at": status.StartedAt().Format(time.RFC3339Nano),
		"updated_at": status.UpdatedAt().Format(time.RFC3339Nano), "completed_at": completedAt.Format(time.RFC3339Nano),
		"selected_roles": selectedRoles, "role_path_total": total, "role_path_completed": completed, "role_path_failed": failed,
		"last_seq": status.LastSequence(), "terminal_cause": terminalCause, "terminal_phase": terminalPhase,
		"dropped_events": status.DroppedEvents(), "diagnostic_only": true, "publication_authority": false,
	}
	if summary, ok := status.DiagnosticSummary(); ok {
		data["diagnostic_summary"] = projectRuntimeDiagnosticSummary(summary)
	}
	return data, nil
}

// ProjectInspection preserves the query owner's page and receipt without a
// second publication read. JSON numbers retain their exact integer spelling.
func ProjectInspection(page query.Inspection, runID, minimum, kind string) (map[string]any, error) {
	if page.RunID != runID || page.ReturnedCount != len(page.Findings) || page.FindingCount < page.ReturnedCount || len(page.Findings) > query.MaxFindingPageSize || kind != "inspect" && kind != "findings" {
		return nil, fmt.Errorf("MCP inspection projection is invalid")
	}
	for _, finding := range page.Findings {
		if !validFindingID(finding.ID) || !domain.Severity(finding.Severity).Valid() || domain.Severity(finding.Severity).Rank() < domain.Severity(minimum).Rank() || finding.Title == "" || strings.ContainsAny(finding.Title, "\x00\r\n") {
			return nil, fmt.Errorf("MCP finding projection is invalid")
		}
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err = decoder.Decode(&data); err != nil {
		return nil, err
	}
	data["finding_count"], data["returned_count"] = page.FindingCount, page.ReturnedCount
	data["kind"] = "review_inspected"
	if kind == "findings" {
		data["kind"] = "findings_listed"
	}
	return data, nil
}
