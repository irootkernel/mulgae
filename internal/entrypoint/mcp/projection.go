package mcpentry

import (
	"fmt"
	"strings"

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
	SessionID        string
	RunID            string
	RunState         domain.RunState
	HasRunState      bool
	PublicationState domain.PublicationStatus
	RecoveryAction   domain.RecoveryAction
	FinalArtifactURI string
	HasFinalArtifact bool
	ContentVerdict   domain.ContentVerdict
	CoverageStatus   domain.CoverageStatus
	CIDecision       domain.CIDecision
	HasAxes          bool
	RoleReports      []RoleReportProjection
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
	if status.PublicationState == domain.PublicationCommitted &&
		status.RunState != domain.RunCompleted && status.RunState != domain.RunDegraded && status.RunState != domain.RunFailed {
		return nil, fmt.Errorf("MCP committed run status state is invalid")
	}
	if status.HasRunState != (status.RunState != "") || status.HasRunState && !status.RunState.Valid() ||
		status.HasFinalArtifact != (status.FinalArtifactURI != "") ||
		status.HasAxes != (status.ContentVerdict != "" && status.CoverageStatus != "" && status.CIDecision != "") {
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
		"session_id": status.SessionID, "run_id": status.RunID,
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
	return data, nil
}

// FindingProjection is one verified finding summary selected by application policy.
type FindingProjection struct {
	ID       string
	Severity domain.Severity
	Title    string
}

// FindingsProjection is the typed input to the bounded MCP finding result.
type FindingsProjection struct {
	RunID             string
	MinimumSeverity   domain.Severity
	TargetSHA256      string
	ReviewArtifactURI string
	Findings          []FindingProjection
}

// ProjectFindings validates and renders one bounded MCP finding result.
func ProjectFindings(view FindingsProjection) (map[string]any, error) {
	if _, err := domain.ParseRunID(view.RunID); err != nil || !validSHA256(view.TargetSHA256) || len(view.Findings) > 1000 {
		return nil, fmt.Errorf("MCP findings projection is invalid")
	}
	artifactPath, err := ports.NewSafeRelativePath(view.ReviewArtifactURI)
	if err != nil || artifactPath.String() != view.ReviewArtifactURI || !strings.HasPrefix(view.ReviewArtifactURI, ".mulgae/") {
		return nil, fmt.Errorf("MCP findings projection is invalid")
	}
	if view.MinimumSeverity != "" && !view.MinimumSeverity.Valid() {
		return nil, fmt.Errorf("MCP finding severity is invalid")
	}
	findings := make([]any, 0, len(view.Findings))
	for _, finding := range view.Findings {
		if !validFindingID(finding.ID) || !finding.Severity.Valid() || finding.Severity.Rank() < view.MinimumSeverity.Rank() ||
			finding.Title == "" || strings.ContainsAny(finding.Title, "\x00\r\n") {
			return nil, fmt.Errorf("MCP finding projection is invalid")
		}
		evidenceURI, err := NewEvidenceResourceURI(view.RunID, finding.ID, view.TargetSHA256)
		if err != nil {
			return nil, fmt.Errorf("MCP finding resource URI is invalid")
		}
		findings = append(findings, map[string]any{
			"id": finding.ID, "severity": string(finding.Severity), "title": finding.Title,
			"evidence_resource_uri": evidenceURI,
		})
	}
	return map[string]any{
		"run_id": view.RunID, "minimum_severity": string(view.MinimumSeverity),
		"target_sha256": view.TargetSHA256, "finding_count": len(findings),
		"findings": findings, "review_artifact_uri": view.ReviewArtifactURI,
	}, nil
}
