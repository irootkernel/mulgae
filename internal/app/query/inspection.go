package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// InspectionRequest selects one publication and a page within its canonical order.
type InspectionRequest struct {
	QueryKind                  string
	MinimumSeverity            domain.Severity
	Limit                      int
	Cursor                     string
	ExpectedPublicationReceipt string
}

type FindingEvidenceReference struct {
	Index        int    `json:"index"`
	URI          string `json:"uri"`
	Availability string `json:"availability"`
}

type FindingSummary struct {
	ID                  string                     `json:"id"`
	Fingerprint         string                     `json:"fingerprint"`
	Role                string                     `json:"role"`
	Provider            string                     `json:"provider"`
	Severity            string                     `json:"severity"`
	Title               string                     `json:"title"`
	Confidence          string                     `json:"confidence"`
	Lifecycle           string                     `json:"lifecycle"`
	DetailURI           string                     `json:"detail_uri"`
	EvidenceResourceURI *string                    `json:"evidence_resource_uri"`
	Evidence            []FindingEvidenceReference `json:"evidence"`
}

type InspectionRoleReport struct {
	Role       string `json:"role"`
	URI        string `json:"uri"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byte_length"`
}

// Inspection contains only values derived from the same verified observation.
// Diagnostic-only observations never carry a publication receipt or content references.
type Inspection struct {
	FailedRunRecovery          recovery.Status          `json:"failed_run_recovery"`
	SessionID                  string                   `json:"session_id"`
	RunID                      string                   `json:"run_id"`
	ReviewID                   string                   `json:"review_id"`
	RunType                    string                   `json:"run_type"`
	RunState                   string                   `json:"run_state"`
	PublicationState           string                   `json:"publication_state"`
	PublicationAuthority       string                   `json:"publication_authority"`
	RecoveryAction             string                   `json:"recovery_action"`
	ContentVerdict             string                   `json:"content_verdict"`
	CoverageStatus             string                   `json:"coverage_status"`
	StructuredExtractionStatus string                   `json:"structured_extraction_status"`
	CIDecision                 string                   `json:"ci_decision"`
	TargetSHA256               string                   `json:"target_sha256"`
	ReviewArtifactURI          string                   `json:"review_artifact_uri"`
	PublicationReceipt         string                   `json:"publication_receipt"`
	Receipt                    *InspectionReceipt       `json:"receipt"`
	CaptureIdentity            string                   `json:"capture_identity"`
	CaptureAvailability        string                   `json:"capture_availability"`
	Capabilities               VerifiedReadCapabilities `json:"capabilities"`
	RoleReports                []InspectionRoleReport   `json:"role_reports"`
	MinimumSeverity            string                   `json:"minimum_severity"`
	FindingCount               int                      `json:"finding_count"`
	ReturnedCount              int                      `json:"returned_count"`
	Findings                   []FindingSummary         `json:"findings"`
	NextCursor                 string                   `json:"next_cursor"`
	DiagnosticOnly             bool                     `json:"diagnostic_only"`
}

func (request InspectionRequest) validate() (InspectionRequest, error) {
	if request.QueryKind != "inspect" && request.QueryKind != "findings" {
		return request, ErrCursorInvalid
	}
	if request.MinimumSeverity == "" {
		request.MinimumSeverity = domain.SeverityLow
	}
	if request.MinimumSeverity == domain.SeverityInfo || !request.MinimumSeverity.Valid() {
		return request, ErrCursorInvalid
	}
	limit, err := FindingPageLimit(request.Limit)
	if err != nil {
		return request, err
	}
	request.Limit = limit
	if len(request.Cursor) > 4096 || request.ExpectedPublicationReceipt != "" && !readDigestValid(request.ExpectedPublicationReceipt) {
		return request, ErrCursorInvalid
	}
	return request, nil
}

// Inspect verifies one committed snapshot, its support, and its final P2 observation.
// The caller retains and revalidates the descriptor lease that supplied binding.
func (service *Service) Inspect(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, request InspectionRequest) (Inspection, error) {
	request, err := request.validate()
	if err != nil {
		return Inspection{}, err
	}
	if !binding.Valid() {
		return Inspection{}, ErrCursorInvalid
	}
	observation, err := service.observe(ctx, run, "query.inspect")
	if err != nil {
		return Inspection{}, err
	}
	if observation.decision.Status() != domain.PublicationCommitted {
		status, err := service.ReadRunStatus(ctx, run)
		if err != nil {
			return Inspection{}, err
		}
		if status.PublicationStatus() == domain.PublicationCommitted {
			return Inspection{}, typedFailure("query.inspect", domain.FailureArtifact, "publication changed during inspection", nil)
		}
		if request.QueryKind != "inspect" || request.Cursor != "" || request.ExpectedPublicationReceipt != "" {
			return Inspection{}, typedFailure("query.inspect", domain.FailureArtifact, "committed findings are unavailable", nil)
		}
		state, _ := status.RunState()
		return Inspection{FailedRunRecovery: status.FailedRunRecovery(), SessionID: run.SessionID().String(), RunID: run.RunID().String(), RunState: string(state), PublicationState: string(status.PublicationStatus()), PublicationAuthority: string(status.Authority()), RecoveryAction: string(status.RecoveryAction()), DiagnosticOnly: true, Findings: []FindingSummary{}, RoleReports: []InspectionRoleReport{}, MinimumSeverity: string(request.MinimumSeverity), Capabilities: ImplementedReadCapabilities()}, nil
	}
	review, receipt, support, err := service.inspectCommitted(ctx, run, binding, observation)
	if err != nil {
		return Inspection{}, err
	}
	identity, err := receipt.Identity()
	if err != nil {
		return Inspection{}, typedFailure("query.inspect", domain.FailureArtifact, "publication receipt is invalid", err)
	}
	if request.ExpectedPublicationReceipt != "" && request.ExpectedPublicationReceipt != identity.String() {
		return Inspection{}, ErrPublicationReceiptMismatch
	}
	scope := FindingPageScope{binding.String(), identity.String(), run.RunID().String(), request.QueryKind, string(request.MinimumSeverity), request.Limit}
	var offset uint64
	if request.Cursor != "" {
		offset, err = DecodeFindingCursor(request.Cursor, scope)
		if err != nil {
			return Inspection{}, err
		}
	}
	filtered := make([]Finding, 0)
	for _, finding := range review.findings {
		if finding.Severity().Rank() >= request.MinimumSeverity.Rank() {
			filtered = append(filtered, finding)
		}
	}
	if request.Cursor != "" && offset >= uint64(len(filtered)) {
		return Inspection{}, ErrCursorInvalid
	}
	end := min(offset+uint64(request.Limit), uint64(len(filtered)))
	result := Inspection{FailedRunRecovery: recovery.UnavailableStatus("published_review"), SessionID: review.SessionID().String(), RunID: review.RunID().String(), ReviewID: review.ReviewID().String(), RunType: string(review.RunType()), RunState: string(review.RunState()), PublicationState: string(domain.PublicationCommitted), PublicationAuthority: string(domain.PublicationAuthorityP2), RecoveryAction: string(observation.decision.Action()), ContentVerdict: string(review.ContentVerdict()), CoverageStatus: string(review.CoverageStatus()), StructuredExtractionStatus: string(review.StructuredExtractionStatus()), CIDecision: string(review.CIDecision()), TargetSHA256: review.TargetSHA256(), ReviewArtifactURI: ".mulgae/" + review.FinalPath().String(), PublicationReceipt: identity.String(), Receipt: &receipt, CaptureIdentity: receipt.CaptureIdentity, CaptureAvailability: receipt.CaptureAvailability, Capabilities: ImplementedReadCapabilities(), MinimumSeverity: string(request.MinimumSeverity), FindingCount: len(filtered), Findings: make([]FindingSummary, 0, end-offset), RoleReports: []InspectionRoleReport{}}
	for _, report := range review.RoleReports() {
		result.RoleReports = append(result.RoleReports, InspectionRoleReport{report.Role(), ".mulgae/" + run.SessionID().String() + "/" + run.RunID().String() + "/" + report.Path(), report.SHA256(), report.ByteLength()})
	}
	for _, finding := range filtered[offset:end] {
		summary := FindingSummary{ID: finding.ID(), Fingerprint: finding.Fingerprint(), Role: string(finding.Role()), Provider: finding.ProviderInstance(), Severity: string(finding.Severity()), Title: finding.Title(), Confidence: string(finding.Confidence()), Lifecycle: string(finding.Lifecycle()), DetailURI: FindingDetailURI(run.RunID().String(), finding.ID(), binding.String(), identity.String(), "", 0), Evidence: []FindingEvidenceReference{}}
		for i, item := range finding.Evidence() {
			reference := FindingEvidenceReference{Index: i, Availability: "evidence_unavailable"}
			path, pathErr := excerptArtifactPath(run, finding.ID(), i+1)
			if pathErr != nil {
				return Inspection{}, pathErr
			}
			if _, present := support[path.String()]; present {
				if _, err := service.readCommittedFindingExcerpt(ctx, run, review, finding.ID(), i+1, item, support); err != nil {
					return Inspection{}, err
				}
				if i == 0 {
					reference.URI = "mulgae://runs/" + run.RunID().String() + "/findings/" + finding.ID() + "/evidence?target_sha256=" + url.QueryEscape(review.TargetSHA256())
					reference.Availability = "verified"
				}
			}
			if i == 0 && reference.URI != "" {
				uri := reference.URI
				summary.EvidenceResourceURI = &uri
			}
			summary.Evidence = append(summary.Evidence, reference)
		}
		result.Findings = append(result.Findings, summary)
	}
	result.ReturnedCount = len(result.Findings)
	if end < uint64(len(filtered)) {
		result.NextCursor, err = EncodeFindingCursor(scope, end)
		if err != nil {
			return Inspection{}, err
		}
	}
	if err := service.confirmStableP2Observation(ctx, run, observation, "query.inspect"); err != nil {
		return Inspection{}, err
	}
	return result, nil
}

func (service *Service) inspectCommitted(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, observation observedRun) (CommittedReview, InspectionReceipt, map[string]string, error) {
	review, err := service.readCommittedSnapshot(ctx, run, observation, "query.inspect")
	if err != nil {
		return CommittedReview{}, InspectionReceipt{}, nil, err
	}
	retired, err := service.committedArtifactRetired(ctx, run, review, make(map[string]struct{}))
	if err != nil {
		return CommittedReview{}, InspectionReceipt{}, nil, err
	}
	if retired {
		return CommittedReview{}, InspectionReceipt{}, nil, typedFailure("query.inspect", domain.FailureArtifact, retiredProviderArtifactReason, nil)
	}
	if _, err = service.projectStatusRoleReportURIs(ctx, run, review, observation); err != nil {
		return CommittedReview{}, InspectionReceipt{}, nil, err
	}
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return CommittedReview{}, InspectionReceipt{}, nil, err
	}
	var envelope struct {
		CompositeIdentity struct {
			SupportIndex *artifactIdentityDTO `json:"support_index"`
		} `json:"composite_identity"`
	}
	if err = json.Unmarshal(review.ManifestBytes(), &envelope); err != nil || envelope.CompositeIdentity.SupportIndex == nil {
		return CommittedReview{}, InspectionReceipt{}, nil, typedFailure("query.inspect", domain.FailureArtifact, "support index binding is absent", err)
	}
	receipt := InspectionReceipt{SchemaVersion: InspectionReceiptVersion, ProjectBinding: binding.String(), SessionID: review.SessionID().String(), RunID: review.RunID().String(), ReviewID: review.ReviewID().String(), RunType: string(review.RunType()), TargetSHA256: review.TargetSHA256(), FinalSHA256: review.FinalSHA256(), ManifestSHA256: review.ManifestSHA256(), SupportSHA256: envelope.CompositeIdentity.SupportIndex.SHA256, LineageSHA256: review.LineageEdgeSHA256(), Epoch: review.Epoch(), CaptureAvailability: "capture_identity_unavailable"}
	path, _ := ports.NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/target/capture-manifest.json")
	if _, ok := index[path.String()]; ok {
		artifact, readErr := service.readIndexedRuntimeArtifact(ctx, run, review, index, path)
		if readErr != nil {
			return CommittedReview{}, InspectionReceipt{}, nil, readErr
		}
		manifest, decodeErr := capture.DecodeCaptureManifest(artifact.Bytes())
		if decodeErr != nil {
			return CommittedReview{}, InspectionReceipt{}, nil, typedFailure("query.inspect", domain.FailureArtifact, "capture manifest is invalid", decodeErr)
		}
		identity, identityErr := manifest.Identity()
		if identityErr != nil {
			return CommittedReview{}, InspectionReceipt{}, nil, identityErr
		}
		// readRuntimeSupportIndex already rebuilt and verified the complete capture.
		receipt.CaptureIdentity, receipt.CaptureAvailability = identity.String(), "verified"
	}
	return review, receipt, index, nil
}

func FindingDetailURI(runID, findingID, binding, receipt, digest string, offset int64) string {
	uri := "mulgae://runs/" + runID + "/findings/" + findingID + "/detail"
	fields := []string{}
	for _, field := range [][2]string{{"project_binding", binding}, {"publication_receipt", receipt}, {"content_sha256", digest}} {
		if field[1] != "" {
			fields = append(fields, field[0]+"="+url.QueryEscape(field[1]))
		}
	}
	if offset != 0 {
		fields = append(fields, "offset="+strconv.FormatInt(offset, 10))
	}
	for i, field := range fields {
		if i == 0 {
			uri += "?"
		} else {
			uri += "&"
		}
		uri += field
	}
	return uri
}

// ReadFinding returns canonical complete finding JSON through bounded chunks.
func (service *Service) ReadFinding(ctx context.Context, run ports.PublicationRun, binding domain.ProjectBinding, findingID string, continuation ContentContinuation) (ContentChunk, error) {
	if !binding.Valid() || !validFindingID(findingID) {
		return ContentChunk{}, ErrCursorInvalid
	}
	if err := continuation.Validate(); err != nil {
		return ContentChunk{}, err
	}
	observation, err := service.observe(ctx, run, "query.read_finding")
	if err != nil {
		return ContentChunk{}, err
	}
	review, receipt, support, err := service.inspectCommitted(ctx, run, binding, observation)
	if err != nil {
		return ContentChunk{}, err
	}
	identity, err := receipt.Identity()
	if err != nil {
		return ContentChunk{}, err
	}
	for _, finding := range review.Findings() {
		if finding.ID() != findingID {
			continue
		}
		for i, item := range finding.Evidence() {
			path, err := excerptArtifactPath(run, findingID, i+1)
			if err != nil {
				return ContentChunk{}, err
			}
			if _, present := support[path.String()]; present {
				if _, err := service.readCommittedFindingExcerpt(ctx, run, review, findingID, i+1, item, support); err != nil {
					return ContentChunk{}, err
				}
			}
		}
	}
	var body struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err = json.Unmarshal(review.FinalBytes(), &body); err != nil {
		return ContentChunk{}, err
	}
	for _, raw := range body.Findings {
		var finding struct {
			ID string `json:"id"`
		}
		if err = json.Unmarshal(raw, &finding); err != nil {
			return ContentChunk{}, err
		}
		if finding.ID != findingID {
			continue
		}
		var canonical bytes.Buffer
		if err = json.Compact(&canonical, raw); err != nil {
			return ContentChunk{}, err
		}
		chunk, err := NewContentChunk(canonical.Bytes(), "application/json", true, identity, continuation)
		if err != nil {
			return ContentChunk{}, err
		}
		chunk.RunID, chunk.FindingID = run.RunID().String(), findingID
		if err = service.confirmStableP2Observation(ctx, run, observation, "query.read_finding"); err != nil {
			return ContentChunk{}, err
		}
		return chunk, nil
	}
	return ContentChunk{}, typedFailure("query.read_finding", domain.FailureArtifact, "finding is not bound to the requested run", fmt.Errorf("finding absent"))
}
