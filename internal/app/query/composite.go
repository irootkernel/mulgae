package query

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type compositeFinalDTO struct {
	SchemaVersion              string                  `json:"schema_version"`
	SessionID                  string                  `json:"session_id"`
	RunID                      string                  `json:"run_id"`
	ReviewID                   string                  `json:"review_id"`
	RunType                    string                  `json:"run_type"`
	CreatedAt                  string                  `json:"created_at"`
	Target                     finalTargetDTO          `json:"target"`
	ContentVerdict             string                  `json:"content_verdict"`
	CoverageStatus             string                  `json:"coverage_status"`
	StructuredExtractionStatus string                  `json:"structured_extraction_status"`
	PublicationStatus          string                  `json:"publication_status"`
	CIDecision                 string                  `json:"ci_decision"`
	CIReasonCodes              []string                `json:"ci_reason_codes"`
	SeverityThreshold          severityThresholdDTO    `json:"severity_threshold"`
	RoleOutcomes               []compositeRoleDTO      `json:"role_outcomes"`
	Findings                   []compositeFindingDTO   `json:"findings"`
	Limitations                []string                `json:"limitations"`
	ReviewComposition          compositeCompositionDTO `json:"review_composition"`
}
type compositeRoleDTO struct {
	Role             string   `json:"role"`
	Required         bool     `json:"required"`
	Outcome          string   `json:"outcome"`
	AttemptID        string   `json:"attempt_id"`
	ProviderInstance string   `json:"provider_instance"`
	ValidFindingIDs  []string `json:"valid_finding_ids"`
	SourceRunID      string   `json:"source_run_id"`
	SourceReviewID   string   `json:"source_review_id"`
}
type compositeFindingDTO struct {
	ID             string                    `json:"id"`
	Fingerprint    string                    `json:"fingerprint"`
	Role           string                    `json:"role"`
	Severity       string                    `json:"severity"`
	Title          string                    `json:"title"`
	Description    string                    `json:"description"`
	Recommendation string                    `json:"recommendation"`
	Confidence     string                    `json:"confidence"`
	Lifecycle      string                    `json:"lifecycle"`
	Source         compositeFindingSourceDTO `json:"source"`
}
type compositeFindingSourceDTO struct {
	RunID     string `json:"run_id"`
	ReviewID  string `json:"review_id"`
	AttemptID string `json:"attempt_id"`
	FindingID string `json:"finding_id"`
}
type compositeCompositionDTO struct {
	Fingerprint  string               `json:"fingerprint"`
	RootRunID    string               `json:"root_run_id"`
	RootReviewID string               `json:"root_review_id"`
	Sources      []compositeSourceDTO `json:"sources"`
}
type compositeSourceDTO struct {
	Kind             string `json:"kind"`
	Role             string `json:"role"`
	RunID            string `json:"run_id"`
	ReviewID         string `json:"review_id"`
	AttemptID        string `json:"attempt_id"`
	RoleReportSHA256 string `json:"role_report_sha256"`
}
type compositeManifestDTO struct {
	SchemaVersion              string                     `json:"schema_version"`
	SessionID                  string                     `json:"session_id"`
	RunID                      string                     `json:"run_id"`
	RunType                    string                     `json:"run_type"`
	State                      string                     `json:"state"`
	Sealed                     bool                       `json:"sealed"`
	CreatedAt                  string                     `json:"created_at"`
	CompletedAt                string                     `json:"completed_at"`
	Target                     manifestTargetDTO          `json:"target"`
	ImmutableLineage           lineageDTO                 `json:"immutable_lineage"`
	ReviewComposition          compositeCompositionDTO    `json:"review_composition"`
	SelectedRoles              []string                   `json:"selected_roles"`
	RequiredRoles              []string                   `json:"required_roles"`
	ContentVerdict             string                     `json:"content_verdict"`
	CoverageStatus             string                     `json:"coverage_status"`
	StructuredExtractionStatus string                     `json:"structured_extraction_status"`
	PublicationStatus          string                     `json:"publication_status"`
	CIDecision                 string                     `json:"ci_decision"`
	CIReasonCodes              []string                   `json:"ci_reason_codes"`
	PersistedJournalState      string                     `json:"persisted_journal_state"`
	DurableObservationClass    string                     `json:"durable_observation_class"`
	DerivedPublicationStatus   string                     `json:"derived_publication_status"`
	PublicationAuthority       string                     `json:"publication_authority"`
	RecoveryJournal            recoveryJournalDTO         `json:"recovery_journal"`
	CompositeIdentity          compositeIdentityDTO       `json:"composite_identity"`
	RecoveryAction             string                     `json:"recovery_action"`
	FinalReview                *finalReviewDTO            `json:"final_review"`
	RoleReports                []compositeManifestRoleDTO `json:"role_reports"`
	ExitCode                   int                        `json:"exit_code"`
}
type compositeManifestRoleDTO struct {
	Role        string `json:"role"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	ByteLength  int    `json:"byte_length"`
	AttemptID   string `json:"attempt_id"`
	SourceRunID string `json:"source_run_id"`
}

func buildCompositeCommittedReview(run ports.PublicationRun, decision domain.PublicationDecision, snapshot ports.CommittedPublicationSnapshot, final compositeFinalDTO, manifest compositeManifestDTO) (CommittedReview, error) {
	if final.SchemaVersion != "mulgae-composite-review-artifact.v1" || manifest.SchemaVersion != "mulgae-composite-run-manifest.v1" || final.RunType != string(domain.RunTypeComposite) || manifest.RunType != final.RunType || final.SessionID != run.SessionID().String() || final.RunID != run.RunID().String() || manifest.SessionID != final.SessionID || manifest.RunID != final.RunID || !manifest.Sealed || manifest.State != string(domain.RunCompleted) || manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) || manifest.PublicationStatus != string(domain.PublicationCommitted) {
		return CommittedReview{}, fmt.Errorf("composite identity or authority is invalid")
	}
	reviewID, err := domain.ParseReviewID(final.ReviewID)
	if err != nil || reviewID != snapshot.Final().Identity().ReviewID() {
		return CommittedReview{}, fmt.Errorf("composite review identity is invalid")
	}
	if manifest.FinalReview == nil || manifest.FinalReview.Path != snapshot.Final().Identity().Path().String() || manifest.FinalReview.SHA256 != snapshot.Final().Identity().SHA256() || manifest.CompositeIdentity.Manifest == nil || manifest.CompositeIdentity.Manifest.Path != snapshot.Manifest().Path().String() || manifest.CompositeIdentity.LineageEdge == nil || manifest.CompositeIdentity.LineageEdge.SHA256 != snapshot.LineageEdge().SHA256() || manifest.CompositeIdentity.Epoch == nil || manifest.CompositeIdentity.Epoch.Path != snapshot.Epoch().Record().Path().String() || manifest.CompositeIdentity.SupportIndex == nil || !validSHA256(manifest.CompositeIdentity.SupportIndex.SHA256) {
		return CommittedReview{}, fmt.Errorf("composite immutable binding is invalid")
	}
	content := domain.ContentVerdict(final.ContentVerdict)
	coverage := domain.CoverageStatus(final.CoverageStatus)
	extraction := domain.StructuredExtractionStatus(final.StructuredExtractionStatus)
	ci := domain.CIDecision(final.CIDecision)
	threshold := domain.Severity(final.SeverityThreshold.RequestChangesAtOrAbove)
	if !content.Valid() || coverage != domain.CoverageComplete || !extraction.Valid() || !ci.Valid() || !threshold.Valid() || final.Target.ContentSHA256 != manifest.Target.ContentSHA256 || !validSHA256(final.Target.ContentSHA256) {
		return CommittedReview{}, fmt.Errorf("composite axes or target are invalid")
	}
	roles := make([]Role, len(final.RoleOutcomes))
	providers := make(map[string]string, len(roles))
	for i, item := range final.RoleOutcomes {
		role := domain.Role(item.Role)
		if !role.Valid() || item.Outcome != "completed" && item.Outcome != "degraded" {
			return CommittedReview{}, fmt.Errorf("composite role is invalid")
		}
		if _, err := domain.ParseAttemptID(item.AttemptID); err != nil {
			return CommittedReview{}, err
		}
		roles[i] = Role{role: role, required: item.Required, outcome: item.Outcome, attemptID: item.AttemptID, providerInstance: item.ProviderInstance, selectedVia: "primary", findingIDs: append([]string(nil), item.ValidFindingIDs...)}
		providers[item.Role] = item.ProviderInstance
	}
	findings := make([]Finding, len(final.Findings))
	for i, item := range final.Findings {
		role := domain.Role(item.Role)
		severity := domain.Severity(item.Severity)
		confidence := domain.Confidence(item.Confidence)
		lifecycle := domain.FindingLifecycle(item.Lifecycle)
		if !role.Valid() || providers[item.Role] == "" || !severity.Valid() || !confidence.Valid() || !lifecycle.Valid() {
			return CommittedReview{}, fmt.Errorf("composite finding is invalid")
		}
		findings[i] = Finding{id: item.ID, fingerprint: item.Fingerprint, role: role, providerInstance: providers[item.Role], severity: severity, title: item.Title, description: item.Description, recommendation: item.Recommendation, confidence: confidence, lifecycle: lifecycle}
	}
	reports := make([]RoleReport, len(manifest.RoleReports))
	for i, item := range manifest.RoleReports {
		provider := providers[item.Role]
		if provider == "" || !validSHA256(item.SHA256) || item.ByteLength <= 0 {
			return CommittedReview{}, fmt.Errorf("composite role report is invalid")
		}
		reports[i] = RoleReport{role: item.Role, path: item.Path, sha256: item.SHA256, byteLength: item.ByteLength, providerInstance: provider, attemptID: item.AttemptID, contentType: "text/markdown"}
	}
	return CommittedReview{sessionID: run.SessionID(), runID: run.RunID(), reviewID: reviewID, runType: domain.RunTypeComposite, runState: domain.RunCompleted, finalPath: snapshot.Final().Identity().Path(), finalSHA256: snapshot.Final().Identity().SHA256(), manifestPath: snapshot.Manifest().Path(), manifestSHA256: snapshot.Manifest().SHA256(), lineageEdgePath: snapshot.LineageEdge().Path(), lineageEdgeSHA: snapshot.LineageEdge().SHA256(), epoch: snapshot.Epoch().Value(), epochPath: snapshot.Epoch().Record().Path(), targetSHA256: final.Target.ContentSHA256, severityThreshold: threshold, content: content, coverage: coverage, extraction: extraction, publication: domain.PublicationCommitted, ci: ci, roles: roles, roleReports: reports, findings: findings, finalBytes: snapshot.Final().Bytes(), manifestBytes: snapshot.Manifest().Bytes(), lineage: CommittedLineage{}}, nil
}
