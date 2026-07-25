package report

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	coreapp "github.com/irootkernel/kkachi-agent-review/internal/app"
	appevidence "github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/query"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	reportAggregationPath     = "aggregation.json"
	reportFinalValidationPath = "validation/final-validation.json"
)

type reportFinalDTO struct {
	SchemaVersion     string                    `json:"schema_version"`
	SessionID         string                    `json:"session_id"`
	RunID             string                    `json:"run_id"`
	ReviewID          string                    `json:"review_id"`
	RunType           string                    `json:"run_type"`
	CreatedAt         string                    `json:"created_at"`
	KAR               reportKARDTO              `json:"kar"`
	ImmutableLineage  reportLineageDTO          `json:"immutable_lineage"`
	FollowupOutcome   *reportFollowupOutcomeDTO `json:"followup_outcome"`
	Target            reportTargetDTO           `json:"target"`
	Validation        reportValidationDTO       `json:"validation"`
	ContentVerdict    string                    `json:"content_verdict"`
	CoverageStatus    string                    `json:"coverage_status"`
	PublicationStatus string                    `json:"publication_status"`
	CIDecision        string                    `json:"ci_decision"`
	CIReasonCodes     []string                  `json:"ci_reason_codes"`
	SeverityThreshold reportSeverityDTO         `json:"severity_threshold"`
	RoleOutcomes      []reportRoleDTO           `json:"role_outcomes"`
	Findings          []reportFindingDTO        `json:"findings"`
	Limitations       []string                  `json:"limitations"`
	Provenance        reportProvenanceDTO       `json:"provenance"`
}
type reportFollowupOutcomeDTO struct {
	Resolution string              `json:"resolution"`
	Rationale  string              `json:"rationale"`
	Evidence   []reportEvidenceDTO `json:"evidence"`
}

type reportKARDTO struct {
	Version string  `json:"version"`
	Commit  *string `json:"commit"`
}

type reportLineageDTO struct {
	ParentRunID      *string `json:"parent_run_id"`
	SourceRunID      *string `json:"source_run_id"`
	SourceReviewID   *string `json:"source_review_id"`
	SourceFindingRef *string `json:"source_finding_ref"`
	ReplayMode       *string `json:"replay_mode"`
	LineageEdgePath  string  `json:"lineage_edge_path"`
	LineageEdgeSHA   string  `json:"lineage_edge_sha256"`
}

type reportTargetDTO struct {
	ContentSHA256 string  `json:"content_sha256"`
	ManifestPath  string  `json:"manifest_path"`
	BaseOID       *string `json:"base_oid"`
	HeadOID       *string `json:"head_oid"`
}

type reportValidationDTO struct {
	Status             string `json:"status"`
	SchemaValidation   string `json:"schema_validation"`
	SemanticValidation string `json:"semantic_validation"`
	EvidenceValidation string `json:"evidence_validation"`
}

type reportSeverityDTO struct {
	RequestChangesAtOrAbove string `json:"request_changes_at_or_above"`
	PolicySource            string `json:"policy_source"`
}

type reportRoleDTO struct {
	Role             string   `json:"role"`
	Required         bool     `json:"required"`
	Outcome          string   `json:"outcome"`
	AttemptID        *string  `json:"attempt_id"`
	ProviderInstance *string  `json:"provider_instance"`
	SelectedVia      *string  `json:"selected_via"`
	ValidFindingIDs  []string `json:"valid_finding_ids"`
	FailureReason    *string  `json:"failure_reason"`
	Limitations      []string `json:"limitations"`
}

type reportFindingDTO struct {
	ID               string              `json:"id"`
	Fingerprint      string              `json:"fingerprint"`
	Role             string              `json:"role"`
	ProviderInstance string              `json:"provider_instance"`
	Severity         string              `json:"severity"`
	Title            string              `json:"title"`
	Description      string              `json:"description"`
	Evidence         []reportEvidenceDTO `json:"evidence"`
	Recommendation   string              `json:"recommendation"`
	Confidence       string              `json:"confidence"`
	Lifecycle        string              `json:"lifecycle"`
}

type reportEvidenceDTO struct {
	Source  reportSourceEvidenceDTO  `json:"source"`
	Current reportCurrentEvidenceDTO `json:"current"`
	Visual  *reportVisualEvidenceDTO `json:"visual,omitempty"`
}

type reportVisualEvidenceDTO struct {
	Path         string              `json:"path"`
	SHA256       string              `json:"sha256"`
	BBox         reportVisualBBoxDTO `json:"bbox"`
	Verification string              `json:"verification"`
}

type reportVisualBBoxDTO struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type reportSourceEvidenceDTO struct {
	SessionID           string `json:"session_id"`
	RunID               string `json:"run_id"`
	ReviewID            string `json:"review_id"`
	FindingID           string `json:"finding_id"`
	SourceTargetSHA256  string `json:"source_target_sha256"`
	SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
}

type reportCurrentEvidenceDTO struct {
	TargetSHA256         string `json:"target_sha256"`
	Side                 string `json:"side"`
	Path                 string `json:"path"`
	LineStart            int    `json:"line_start"`
	LineEnd              int    `json:"line_end"`
	Quote                string `json:"quote"`
	CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
	Verification         string `json:"verification"`
}

type reportProvenanceDTO struct {
	AggregationPath     string                         `json:"aggregation_path"`
	FinalValidationPath string                         `json:"final_validation_path"`
	ManifestPath        string                         `json:"manifest_path"`
	Production          *reportProductionProvenanceDTO `json:"production,omitempty"`
}
type reportProductionProvenanceDTO struct {
	BuildProduct             string                        `json:"build_product"`
	BuildVersion             string                        `json:"build_version"`
	BuildCommit              string                        `json:"build_commit"`
	ObjectiveSHA256          *string                       `json:"objective_sha256"`
	ObjectivePresent         bool                          `json:"objective_present"`
	SnapshotManifestSHA256   string                        `json:"snapshot_manifest_sha256"`
	WorkspaceTerminalReceipt string                        `json:"workspace_terminal_receipt"`
	Providers                []reportProductionProviderDTO `json:"providers"`
}
type reportProductionProviderDTO struct {
	Family                    string   `json:"family"`
	Instance                  string   `json:"instance"`
	Version                   string   `json:"version"`
	Executable                string   `json:"executable"`
	ExecutableSHA256          string   `json:"executable_sha256"`
	Launcher                  string   `json:"launcher"`
	LauncherSHA256            string   `json:"launcher_sha256"`
	ProfileGeneration         string   `json:"profile_generation"`
	AdapterProfile            string   `json:"adapter_profile"`
	QualificationReceiptIDs   []string `json:"qualification_receipt_ids"`
	PacketTransportReceiptIDs []string `json:"packet_transport_receipt_ids"`
	NamespaceTerminalReceipt  string   `json:"namespace_terminal_receipt"`
}

func decodeReportFinal(raw []byte) (reportFinalDTO, error) {
	var value reportFinalDTO
	if err := decodeReportStrictObject(raw, &value); err != nil {
		return reportFinalDTO{}, fmt.Errorf("final review JSON: %w", err)
	}
	return value, nil
}

func decodeReportStrictObject(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("contains invalid UTF-8")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("is empty")
	}
	scanner := json.NewDecoder(bytes.NewReader(raw))
	scanner.UseNumber()
	token, err := scanner.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("must be a non-null JSON object")
	}
	if err := consumeReportJSONObject(scanner); err != nil {
		return err
	}
	if _, err := scanner.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("contains trailing JSON value")
		}
		return fmt.Errorf("contains trailing data: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("contains trailing JSON value")
		}
		return fmt.Errorf("contains trailing data: %w", err)
	}
	return nil
}

func consumeReportJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("contains duplicate object key %q", key)
		}
		seen[key] = struct{}{}
		if err := consumeReportJSONValue(decoder); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != json.Delim('}') {
		return fmt.Errorf("object is not terminated")
	}
	return nil
}

func consumeReportJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeReportJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeReportJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("array is not terminated")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func (final reportFinalDTO) consistentWith(review query.CommittedReview) error {
	if final.SchemaVersion != "kar-review-artifact.v3" ||
		final.SessionID != review.SessionID().String() ||
		final.RunID != review.RunID().String() ||
		final.ReviewID != review.ReviewID().String() ||
		final.Target.ContentSHA256 != review.TargetSHA256() ||
		final.ImmutableLineage.LineageEdgePath != review.LineageEdgePath().String() ||
		final.ImmutableLineage.LineageEdgeSHA != review.LineageEdgeSHA256() ||
		final.ContentVerdict != string(review.ContentVerdict()) ||
		final.CoverageStatus != string(review.CoverageStatus()) ||
		final.PublicationStatus != string(review.PublicationStatus()) ||
		final.CIDecision != string(review.CIDecision()) {
		return fmt.Errorf("final fields do not match the committed query view")
	}
	if err := final.consistentFollowupOutcome(review); err != nil {
		return fmt.Errorf("followup outcome does not match the committed query view: %w", err)
	}
	if _, err := canonicalReportProvenance(final.Provenance, review); err != nil {
		return fmt.Errorf("final provenance does not match the committed query view: %w", err)
	}
	if err := validateReportProductionProvenance(final); err != nil {
		return fmt.Errorf("final production provenance is invalid: %w", err)
	}

	roles := review.Roles()
	if len(final.RoleOutcomes) != len(roles) {
		return fmt.Errorf("role count does not match the committed query view")
	}
	for index, role := range roles {
		value := final.RoleOutcomes[index]
		attemptID, hasAttempt := role.AttemptID()
		provider, hasProvider := role.ProviderInstance()
		selectedVia, hasSelection := role.SelectedVia()
		failureReason, hasFailure := role.FailureReason()
		if value.Role != string(role.Name()) || value.Required != role.Required() || value.Outcome != role.Outcome() ||
			!sameReportOptionalString(value.AttemptID, attemptID.String(), hasAttempt) ||
			!sameReportOptionalString(value.ProviderInstance, provider, hasProvider) ||
			!sameReportOptionalString(value.SelectedVia, selectedVia, hasSelection) ||
			!sameReportOptionalString(value.FailureReason, failureReason, hasFailure) ||
			!sameReportStrings(value.ValidFindingIDs, role.ValidFindingIDs()) ||
			!sameReportStrings(value.Limitations, role.Limitations()) {
			return fmt.Errorf("role %d does not match the committed query view", index)
		}
	}

	findings := review.Findings()
	if len(final.Findings) != len(findings) {
		return fmt.Errorf("finding count does not match the committed query view")
	}
	for index, finding := range findings {
		value := final.Findings[index]
		if value.ID != finding.ID() || value.Fingerprint != finding.Fingerprint() || value.Role != string(finding.Role()) ||
			value.ProviderInstance != finding.ProviderInstance() || value.Severity != string(finding.Severity()) ||
			value.Title != finding.Title() || value.Description != finding.Description() ||
			value.Recommendation != finding.Recommendation() || value.Confidence != string(finding.Confidence()) ||
			value.Lifecycle != string(finding.Lifecycle()) {
			return fmt.Errorf("finding %d does not match the committed query view", index)
		}
		evidence := finding.Evidence()
		items, err := canonicalReportEvidenceItems(value.Evidence)
		if err != nil {
			return fmt.Errorf("finding %d evidence is invalid: %w", index, err)
		}
		if len(evidence) != len(items) {
			return fmt.Errorf("finding %d evidence count does not match the committed query view", index)
		}
		for evidenceIndex, claim := range evidence {
			item := items[evidenceIndex]
			if !sameReportEvidence(item, claim) {
				return fmt.Errorf("finding %d evidence %d does not match the committed query view", index, evidenceIndex+1)
			}
		}
	}
	return nil
}
func (final reportFinalDTO) consistentFollowupOutcome(review query.CommittedReview) error {
	outcome, present := review.FollowupOutcome()
	if !present {
		if final.FollowupOutcome != nil {
			return errors.New("non-followup final has a followup outcome")
		}
		return nil
	}
	if final.FollowupOutcome == nil || final.FollowupOutcome.Resolution != string(outcome.Resolution()) ||
		final.FollowupOutcome.Rationale != outcome.Rationale() {
		return errors.New("resolution or rationale differs")
	}
	evidence := outcome.Evidence()
	if len(final.FollowupOutcome.Evidence) != len(evidence) {
		return errors.New("evidence count differs")
	}
	for index, item := range evidence {
		value := final.FollowupOutcome.Evidence[index]
		if value.Source.SessionID != item.SourceSessionID().String() ||
			value.Source.RunID != item.SourceRunID().String() ||
			value.Source.ReviewID != item.SourceReviewID().String() ||
			value.Source.FindingID != item.SourceFindingID() ||
			value.Source.SourceTargetSHA256 != item.SourceTargetSHA256() ||
			value.Source.SourceExcerptSHA256 != item.SourceExcerptSHA256() ||
			value.Current.TargetSHA256 != item.TargetSHA256() ||
			value.Current.Side != string(item.Side()) ||
			value.Current.Path != item.Path().String() ||
			value.Current.LineStart != item.LineStart() ||
			value.Current.LineEnd != item.LineEnd() ||
			value.Current.Quote != item.Quote() ||
			value.Current.CurrentExcerptSHA256 != item.CurrentExcerptSHA256() ||
			value.Current.Verification != string(item.Verification()) {
			return fmt.Errorf("evidence %d differs", index)
		}
	}
	return nil
}

func sameReportOptionalString(value *string, expected string, exists bool) bool {
	if value == nil {
		return !exists
	}
	return exists && *value == expected
}

func sameReportStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
func canonicalReportProvenance(
	provenance reportProvenanceDTO,
	review query.CommittedReview,
) (reportProvenanceDTO, error) {
	aggregation, err := canonicalReportProvenancePath(review, provenance.AggregationPath)
	if err != nil {
		return reportProvenanceDTO{}, fmt.Errorf("aggregation path: %w", err)
	}
	expectedAggregation, err := canonicalReportProvenancePath(review, reportAggregationPath)
	if err != nil {
		return reportProvenanceDTO{}, fmt.Errorf("expected aggregation path: %w", err)
	}
	if aggregation != expectedAggregation {
		return reportProvenanceDTO{}, fmt.Errorf("aggregation path is not the canonical committed reference")
	}

	finalValidation, err := canonicalReportProvenancePath(review, provenance.FinalValidationPath)
	if err != nil {
		return reportProvenanceDTO{}, fmt.Errorf("final validation path: %w", err)
	}
	expectedFinalValidation, err := canonicalReportProvenancePath(review, reportFinalValidationPath)
	if err != nil {
		return reportProvenanceDTO{}, fmt.Errorf("expected final validation path: %w", err)
	}
	if finalValidation != expectedFinalValidation {
		return reportProvenanceDTO{}, fmt.Errorf("final validation path is not the canonical committed reference")
	}

	manifest, err := canonicalReportProvenancePath(review, provenance.ManifestPath)
	if err != nil {
		return reportProvenanceDTO{}, fmt.Errorf("manifest path: %w", err)
	}
	if manifest != review.ManifestPath().String() {
		return reportProvenanceDTO{}, fmt.Errorf("manifest path does not match the committed snapshot")
	}

	return reportProvenanceDTO{
		AggregationPath:     aggregation,
		FinalValidationPath: finalValidation,
		ManifestPath:        manifest,
	}, nil
}
func validateReportProductionProvenance(final reportFinalDTO) error {
	production := final.Provenance.Production
	if final.RunType != "review" {
		if production != nil {
			return errors.New("child final review cannot contain production provenance")
		}
		return nil
	}
	if production == nil {
		return nil
	}
	if final.Target.ContentSHA256 == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return errors.New("no-change final review cannot contain production provenance")
	}
	if production.ObjectivePresent != (production.ObjectiveSHA256 != nil) {
		return errors.New("objective presence does not match identity")
	}
	if !reportSafeText(production.BuildProduct, 128) || !reportSafeText(production.BuildVersion, 128) ||
		!reportSafeText(production.BuildCommit, 128) || !validReportSHA256(production.SnapshotManifestSHA256) ||
		!validReportReceiptID(production.WorkspaceTerminalReceipt) || len(production.Providers) == 0 {
		return errors.New("build, snapshot, workspace, or providers are incomplete")
	}
	if production.ObjectiveSHA256 != nil && !validReportSHA256(*production.ObjectiveSHA256) {
		return errors.New("objective identity is invalid")
	}
	if production.BuildVersion != final.KAR.Version || !sameReportOptionalString(final.KAR.Commit, production.BuildCommit, true) {
		return errors.New("build metadata does not match KAR")
	}
	for index, provider := range production.Providers {
		if !reportSafeText(provider.Family, 64) || !validReportProviderInstance(provider.Instance) ||
			!reportSafeText(provider.Version, 128) || !reportSafeText(provider.Executable, 1024) ||
			!validReportSHA256(provider.ExecutableSHA256) || !reportSafeText(provider.ProfileGeneration, 256) ||
			!reportSafeText(provider.AdapterProfile, 256) || !validReportReceiptID(provider.NamespaceTerminalReceipt) ||
			len(provider.QualificationReceiptIDs) == 0 || len(provider.PacketTransportReceiptIDs) == 0 {
			return fmt.Errorf("provider %d is incomplete", index)
		}
		if (provider.Launcher == "") != (provider.LauncherSHA256 == "") ||
			provider.Launcher != "" && (!reportSafeText(provider.Launcher, 1024) || !validReportSHA256(provider.LauncherSHA256)) {
			return fmt.Errorf("provider %d launcher identity is invalid", index)
		}
		key := provider.Family + "\x00" + provider.Instance
		if index > 0 && key <= production.Providers[index-1].Family+"\x00"+production.Providers[index-1].Instance {
			return errors.New("providers are duplicated or unordered")
		}
		for _, receipts := range [][]string{provider.QualificationReceiptIDs, provider.PacketTransportReceiptIDs} {
			for receiptIndex, receipt := range receipts {
				if !validReportReceiptID(receipt) {
					return errors.New("provider receipt identity is invalid")
				}
				if receiptIndex > 0 && receipts[receiptIndex-1] >= receipt {
					return errors.New("provider receipt identities are not ordered")
				}
			}
		}
	}
	return nil
}

func reportSafeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	return true
}
func validReportProviderInstance(value string) bool {
	if !reportSafeText(value, 128) || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validReportSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validReportReceiptID(value string) bool {
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || len(value) != separator+1+64 {
		return false
	}
	for _, character := range value[:separator] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != ':' && character != '-' {
			return false
		}
	}
	for _, character := range value[separator+1:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func canonicalReportProvenancePath(review query.CommittedReview, value string) (string, error) {
	relative, err := ports.NewSafeRelativePath(value)
	if err != nil {
		return "", err
	}
	canonical, err := ports.NewSafeRelativePath(
		review.SessionID().String() + "/" + review.RunID().String() + "/" + relative.String(),
	)
	if err != nil {
		return "", err
	}
	return canonical.String(), nil
}

func renderMarkdown(
	ctx context.Context,
	reader CommittedReader,
	run ports.PublicationRun,
	review query.CommittedReview,
	final reportFinalDTO,
) ([]byte, error) {
	if err := final.consistentWith(review); err != nil {
		return nil, reportFailure(domain.FailureArtifact, "committed final report data is inconsistent", err)
	}
	provenance, err := canonicalReportProvenance(final.Provenance, review)
	if err != nil {
		return nil, reportFailure(domain.FailureArtifact, "committed final provenance is invalid", err)
	}

	var output strings.Builder

	writeHeading(&output, "Run summary")
	writeField(&output, "Session ID", review.SessionID().String())
	writeField(&output, "Run ID", review.RunID().String())
	writeField(&output, "Review ID", review.ReviewID().String())
	writeField(&output, "Run type", final.RunType)
	writeField(&output, "Run state", string(review.RunState()))
	writeField(&output, "Created at", final.CreatedAt)
	writeField(&output, "Committed source", "P2 verified query snapshot")
	writeBlankLine(&output)

	writeHeading(&output, "Target and lineage")
	writeField(&output, "Target SHA-256", review.TargetSHA256())
	writeField(&output, "Target manifest", final.Target.ManifestPath)
	writeOptionalField(&output, "Base object ID", final.Target.BaseOID)
	writeOptionalField(&output, "Head object ID", final.Target.HeadOID)
	writeOptionalField(&output, "Parent run ID", final.ImmutableLineage.ParentRunID)
	writeOptionalField(&output, "Source run ID", final.ImmutableLineage.SourceRunID)
	writeOptionalField(&output, "Source review ID", final.ImmutableLineage.SourceReviewID)
	writeOptionalField(&output, "Source finding reference", final.ImmutableLineage.SourceFindingRef)
	writeOptionalField(&output, "Replay mode", final.ImmutableLineage.ReplayMode)
	writeField(&output, "Lineage edge path", review.LineageEdgePath().String())
	writeField(&output, "Lineage edge SHA-256", review.LineageEdgeSHA256())
	writeBlankLine(&output)

	writeHeading(&output, "Outcome axes")
	writeField(&output, "Content verdict", string(review.ContentVerdict()))
	writeField(&output, "Coverage status", string(review.CoverageStatus()))
	writeField(&output, "Publication status", string(review.PublicationStatus()))
	writeField(&output, "CI decision", string(review.CIDecision()))
	writeBlankLine(&output)
	if outcome, present := review.FollowupOutcome(); present {
		writeHeading(&output, "Follow-up outcome")
		writeField(&output, "Resolution", string(outcome.Resolution()))
		writeTextBlock(&output, "Rationale", outcome.Rationale())
		for index, evidence := range outcome.Evidence() {
			writeSubheading(&output, fmt.Sprintf("Evidence %d", index+1))
			writeField(&output, "Source session ID", evidence.SourceSessionID().String())
			writeField(&output, "Source run ID", evidence.SourceRunID().String())
			writeField(&output, "Source review ID", evidence.SourceReviewID().String())
			writeField(&output, "Source finding ID", evidence.SourceFindingID())
			writeField(&output, "Source target SHA-256", evidence.SourceTargetSHA256())
			writeField(&output, "Source excerpt SHA-256", evidence.SourceExcerptSHA256())
			writeField(&output, "Current excerpt SHA-256", evidence.CurrentExcerptSHA256())
			writeField(&output, "Current target SHA-256", evidence.TargetSHA256())
			writeField(&output, "Current side", string(evidence.Side()))
			writeField(&output, "Current path", evidence.Path().String())
			writeField(&output, "Current lines", fmt.Sprintf("%d-%d", evidence.LineStart(), evidence.LineEnd()))
			writeField(&output, "Committed verification", string(evidence.Verification()))
			writeTextBlock(&output, "Current quote", evidence.Quote())
		}
		writeBlankLine(&output)
	}

	writeHeading(&output, "Role coverage")
	for _, role := range review.Roles() {
		writeField(&output, "Role", string(role.Name()))
		writeField(&output, "Required", fmt.Sprintf("%t", role.Required()))
		writeField(&output, "Outcome", role.Outcome())
		if attemptID, ok := role.AttemptID(); ok {
			writeField(&output, "Attempt ID", attemptID.String())
		} else {
			writeField(&output, "Attempt ID", "absent")
		}
		if provider, ok := role.ProviderInstance(); ok {
			writeField(&output, "Provider instance", provider)
		} else {
			writeField(&output, "Provider instance", "absent")
		}
		if selection, ok := role.SelectedVia(); ok {
			writeField(&output, "Selection", selection)
		} else {
			writeField(&output, "Selection", "absent")
		}
		writeField(&output, "Finding IDs", reportList(role.ValidFindingIDs()))
		if failure, ok := role.FailureReason(); ok {
			writeField(&output, "Failure reason", failure)
		} else {
			writeField(&output, "Failure reason", "none")
		}
		writeField(&output, "Limitations", reportList(role.Limitations()))
		writeBlankLine(&output)
	}

	writeHeading(&output, "Validation and repair")
	writeField(&output, "Validation status", final.Validation.Status)
	writeField(&output, "Schema validation", final.Validation.SchemaValidation)
	writeField(&output, "Semantic validation", final.Validation.SemanticValidation)
	writeField(&output, "Evidence validation", final.Validation.EvidenceValidation)
	writeBlankLine(&output)

	writeHeading(&output, "Findings by severity")
	findings := review.Findings()
	if len(findings) == 0 {
		writeText(&output, "No committed findings.")
		writeBlankLine(&output)
	}
	for _, finding := range findings {
		if err := reportContextFailure(ctx); err != nil {
			return nil, err
		}
		claims := finding.Evidence()
		if len(claims) == 0 || len(claims) > 20 {
			return nil, reportFailure(domain.FailureArtifact, "committed finding evidence count is invalid", nil)
		}

		writeSubheading(&output, finding.ID()+" — "+finding.Title())
		writeField(&output, "Severity", string(finding.Severity()))
		writeField(&output, "Confidence", string(finding.Confidence()))
		writeField(&output, "Lifecycle", string(finding.Lifecycle()))
		writeField(&output, "Role", string(finding.Role()))
		writeField(&output, "Provider instance", finding.ProviderInstance())
		writeField(&output, "Fingerprint", finding.Fingerprint())
		writeTextBlock(&output, "Explanation", finding.Description())
		writeTextBlock(&output, "Recommendation", finding.Recommendation())
		for evidenceIndex, item := range claims {
			writeText(&output, fmt.Sprintf("Evidence %d:", evidenceIndex+1))
			writeField(&output, "Source session ID", item.SourceSessionID().String())
			writeField(&output, "Source run ID", item.SourceRunID().String())
			writeField(&output, "Source review ID", item.SourceReviewID().String())
			writeField(&output, "Source finding ID", item.SourceFindingID())
			writeField(&output, "Source target SHA-256", item.SourceTargetSHA256())
			writeField(&output, "Source excerpt SHA-256", item.SourceExcerptSHA256())
			writeField(&output, "Current excerpt SHA-256", item.CurrentExcerptSHA256())
			writeField(&output, "Current target SHA-256", item.TargetSHA256())
			writeField(&output, "Current side", string(item.Side()))
			writeField(&output, "Current path", item.Path().String())
			writeField(&output, "Current lines", fmt.Sprintf("%d-%d", item.LineStart(), item.LineEnd()))
			writeField(&output, "Committed verification", string(item.Verification()))

			excerpt, err := renderEvidenceExcerpt(ctx, reader, run, finding.ID(), review.TargetSHA256(), evidenceIndex+1)
			failure := reduceReportFailure(err)
			if err != nil && failure.rank > 4 {
				return nil, err
			}
			if contextErr := reportContextFailure(ctx); contextErr != nil {
				return nil, contextErr
			}
			if err == nil {
				if !utf8.Valid(excerpt) {
					return nil, reportFailure(domain.FailureInternal, "verified excerpt is not valid UTF-8", nil)
				}
				if !reportExcerptMatchesCurrentIdentity(excerpt, item) {
					return nil, reportFailure(domain.FailureArtifact, "verified excerpt does not match the committed current excerpt identity", nil)
				}
				writeVerifiedExcerpt(&output, excerpt)
			} else if failure.readiness {
				writeField(&output, "Re-read verification state", failure.state)
			} else {
				return nil, err
			}
		}
		writeBlankLine(&output)
	}

	writeHeading(&output, "Limitations/degradation")
	writeField(&output, "Review limitations", reportList(final.Limitations))
	writeField(&output, "Coverage status", string(review.CoverageStatus()))
	for _, role := range review.Roles() {
		if role.Outcome() == "degraded" || role.Outcome() == "failed" || len(role.Limitations()) > 0 {
			writeField(&output, "Role "+string(role.Name())+" limitations", reportList(role.Limitations()))
		}
	}
	writeBlankLine(&output)

	writeHeading(&output, "Artifact references")
	writeField(&output, "Final artifact path", review.FinalPath().String())
	writeField(&output, "Final artifact SHA-256", review.FinalSHA256())
	writeField(&output, "Manifest path", review.ManifestPath().String())
	writeField(&output, "Manifest SHA-256", review.ManifestSHA256())
	writeField(&output, "Lineage edge path", review.LineageEdgePath().String())
	writeField(&output, "Lineage edge SHA-256", review.LineageEdgeSHA256())
	writeField(&output, "Publication epoch", fmt.Sprintf("%d", review.Epoch()))
	writeField(&output, "Epoch record path", review.EpochPath().String())
	writeField(&output, "Canonical aggregation artifact reference", provenance.AggregationPath)
	writeField(&output, "Canonical final validation artifact reference", provenance.FinalValidationPath)
	writeField(&output, "Verified provenance manifest", provenance.ManifestPath)
	writeBlankLine(&output)

	writeHeading(&output, "Provider/runtime provenance")
	writeField(&output, "KAR version", final.KAR.Version)
	writeOptionalField(&output, "KAR commit", final.KAR.Commit)
	for _, role := range review.Roles() {
		if provider, ok := role.ProviderInstance(); ok {
			writeField(&output, "Role provider", string(role.Name())+": "+provider)
		} else {
			writeField(&output, "Role provider", string(role.Name())+": absent")
		}
		if attemptID, ok := role.AttemptID(); ok {
			writeField(&output, "Role attempt", string(role.Name())+": "+attemptID.String())
		} else {
			writeField(&output, "Role attempt", string(role.Name())+": absent")
		}
		if selection, ok := role.SelectedVia(); ok {
			writeField(&output, "Role selection", string(role.Name())+": "+selection)
		} else {
			writeField(&output, "Role selection", string(role.Name())+": absent")
		}
	}
	writeBlankLine(&output)

	writeHeading(&output, "CI interpretation")
	writeField(&output, "CI decision", string(review.CIDecision()))
	writeField(&output, "Reason codes", reportList(final.CIReasonCodes))
	writeField(&output, "Request-changes threshold", final.SeverityThreshold.RequestChangesAtOrAbove)
	writeField(&output, "Policy source", final.SeverityThreshold.PolicySource)
	writeText(&output, "This report records committed review data and does not make organizational decisions.")

	rendered := []byte(output.String())
	if !utf8.Valid(rendered) || bytes.Contains(rendered, []byte{'\r'}) || len(rendered) == 0 || rendered[len(rendered)-1] != '\n' {
		return nil, reportFailure(domain.FailureInternal, "rendered report violates the UTF-8 LF contract", nil)
	}
	return rendered, nil
}
func renderEvidenceExcerpt(
	ctx context.Context,
	reader CommittedReader,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
	evidenceIndex int,
) ([]byte, error) {
	return reader.RenderExcerptAt(ctx, run, findingID, targetSHA256, evidenceIndex)
}

func canonicalReportEvidenceItems(items []reportEvidenceDTO) ([]reportEvidenceDTO, error) {
	if len(items) == 0 || len(items) > 20 {
		return nil, fmt.Errorf("evidence count must be between 1 and 20")
	}
	ordered := append([]reportEvidenceDTO(nil), items...)
	for _, item := range ordered {
		claim, err := appevidence.NewCurrentClaim(appevidence.CurrentClaimInput{
			TargetSHA256: item.Current.TargetSHA256,
			Side:         appevidence.Side(item.Current.Side),
			Path:         item.Current.Path,
			LineStart:    item.Current.LineStart,
			LineEnd:      item.Current.LineEnd,
			Quote:        item.Current.Quote,
		})
		if err != nil {
			return nil, fmt.Errorf("current evidence is invalid: %w", err)
		}
		currentExcerptSHA256, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
		if err != nil || currentExcerptSHA256 != item.Current.CurrentExcerptSHA256 {
			return nil, fmt.Errorf("current excerpt identity is invalid")
		}
	}
	sort.Slice(ordered, func(left, right int) bool {
		return canonicalReportEvidenceKey(ordered[left]) < canonicalReportEvidenceKey(ordered[right])
	})
	for index := range items {
		if canonicalReportEvidenceKey(items[index]) != canonicalReportEvidenceKey(ordered[index]) {
			return nil, fmt.Errorf("evidence order is not canonical")
		}
	}
	for index := 1; index < len(ordered); index++ {
		if canonicalReportEvidenceKey(ordered[index-1]) == canonicalReportEvidenceKey(ordered[index]) {
			return nil, fmt.Errorf("evidence tuple is duplicated")
		}
	}
	return ordered, nil
}

func canonicalReportEvidenceKey(item reportEvidenceDTO) string {
	fields := []string{
		item.Source.SessionID,
		item.Source.RunID,
		item.Source.ReviewID,
		item.Source.FindingID,
		item.Source.SourceTargetSHA256,
		item.Source.SourceExcerptSHA256,
		item.Current.CurrentExcerptSHA256,
		item.Current.TargetSHA256,
		item.Current.Side,
		item.Current.Path,
		strconv.Itoa(item.Current.LineStart),
		strconv.Itoa(item.Current.LineEnd),
		item.Current.Verification,
	}
	var key strings.Builder
	for _, field := range fields {
		key.WriteString(strconv.Itoa(len(field)))
		key.WriteByte(':')
		key.WriteString(field)
		key.WriteByte('|')
	}
	return key.String()
}

func sameReportEvidence(item reportEvidenceDTO, claim query.Evidence) bool {
	return item.Source.SessionID == claim.SourceSessionID().String() &&
		item.Source.RunID == claim.SourceRunID().String() &&
		item.Source.ReviewID == claim.SourceReviewID().String() &&
		item.Source.FindingID == claim.SourceFindingID() &&
		item.Source.SourceTargetSHA256 == claim.SourceTargetSHA256() &&
		item.Source.SourceExcerptSHA256 == claim.SourceExcerptSHA256() &&
		item.Current.TargetSHA256 == claim.TargetSHA256() &&
		item.Current.CurrentExcerptSHA256 == claim.CurrentExcerptSHA256() &&
		item.Current.Side == string(claim.Side()) &&
		item.Current.Path == claim.Path().String() &&
		item.Current.LineStart == claim.LineStart() &&
		item.Current.LineEnd == claim.LineEnd() &&
		item.Current.Verification == string(claim.Verification())
}

type reportFailureSelection struct {
	rank      int
	state     string
	readiness bool
}

type reportFailureCandidate struct {
	class     domain.FailureClass
	state     string
	readiness bool
}

func reduceReportFailure(err error) reportFailureSelection {
	if err == nil {
		return reportFailureSelection{rank: -1}
	}

	candidates := make([]reportFailureCandidate, 0, 4)
	var visit func(error, bool)
	visit = func(current error, classifiedByAncestor bool) {
		if current == nil {
			return
		}
		classified := false
		if failure, ok := current.(*domain.Failure); ok && failure != nil && failure.Class().Valid() {
			state, readiness := reportReadinessState(failure)
			candidates = append(candidates, reportFailureCandidate{
				class: failure.Class(), state: state, readiness: readiness,
			})
			classified = true
		}

		hasChildren := false
		switch unwrapped := current.(type) {
		case interface{ Unwrap() []error }:
			hasChildren = true
			for _, nested := range unwrapped.Unwrap() {
				visit(nested, classifiedByAncestor || classified)
			}
		case interface{ Unwrap() error }:
			if nested := unwrapped.Unwrap(); nested != nil {
				hasChildren = true
				visit(nested, classifiedByAncestor || classified)
			}
		}
		if hasChildren {
			return
		}
		if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
			candidates = append(candidates, reportFailureCandidate{class: domain.FailureCancelled})
			return
		}
		if !classified && !classifiedByAncestor {
			candidates = append(candidates, reportFailureCandidate{class: domain.FailureArtifact})
		}
	}
	visit(err, false)
	if len(candidates) == 0 {
		candidates = append(candidates, reportFailureCandidate{class: domain.FailureArtifact})
	}

	selection := reportFailureSelection{rank: -1}
	for _, candidate := range candidates {
		if rank := coreapp.FailurePrecedence(candidate.class); rank > selection.rank {
			selection.rank = rank
		}
	}
	for _, candidate := range candidates {
		if coreapp.FailurePrecedence(candidate.class) != selection.rank {
			continue
		}
		if candidate.class != domain.FailureProviderUnavailable || !candidate.readiness {
			selection.readiness = false
			return selection
		}
		if !selection.readiness {
			selection.state = candidate.state
			selection.readiness = true
			continue
		}
		if selection.state != candidate.state {
			selection.readiness = false
			return selection
		}
	}
	return selection
}

func reportReadinessState(failure *domain.Failure) (string, bool) {
	if failure == nil || failure.Class() != domain.FailureProviderUnavailable {
		return "", false
	}
	switch failure.Reason() {
	case "current evidence is stale":
		return "stale", true
	case "current evidence is invalid":
		return "invalid", true
	case "current evidence is unavailable", "current evidence is unverifiable":
		return "unverifiable", true
	default:
		return "", false
	}
}

func reportExcerptMatchesCurrentIdentity(excerpt []byte, item query.Evidence) bool {
	claim, err := appevidence.NewCurrentClaim(appevidence.CurrentClaimInput{
		TargetSHA256: item.TargetSHA256(),
		Side:         item.Side(),
		Path:         item.Path().String(),
		LineStart:    item.LineStart(),
		LineEnd:      item.LineEnd(),
		Quote:        string(excerpt),
	})
	if err != nil {
		return false
	}
	digest, err := claim.ExcerptSHA256(excerpt)
	return err == nil && digest == item.CurrentExcerptSHA256()
}

func writeHeading(output *strings.Builder, title string) {
	output.WriteString("# ")
	output.WriteString(reportPlain(title))
	output.WriteString("\n\n")
}

func writeSubheading(output *strings.Builder, title string) {
	output.WriteString("## ")
	output.WriteString(reportCode(title))
	output.WriteString("\n\n")
}

func writeField(output *strings.Builder, name, value string) {
	output.WriteString("- **")
	output.WriteString(reportPlain(name))
	output.WriteString(":** ")
	output.WriteString(reportCode(value))
	output.WriteString("\n")
}

func writeOptionalField(output *strings.Builder, name string, value *string) {
	if value == nil {
		writeField(output, name, "none")
		return
	}
	writeField(output, name, *value)
}

func writeText(output *strings.Builder, value string) {
	output.WriteString(reportPlain(value))
	output.WriteString("\n")
}

func writeTextBlock(output *strings.Builder, name, value string) {
	output.WriteString("- **")
	output.WriteString(reportPlain(name))
	output.WriteString(":**\n")
	writeFencedText(output, value)
}

func writeFencedText(output *strings.Builder, value string) {
	value = reportLF(value)
	fence := strings.Repeat("`", maxBacktickRun(value)+1)
	if len(fence) < 3 {
		fence = "```"
	}
	output.WriteString(fence)
	output.WriteString("text\n")
	output.WriteString(value)
	if !strings.HasSuffix(value, "\n") {
		output.WriteString("\n")
	}
	output.WriteString(fence)
	output.WriteString("\n")
}
func writeVerifiedExcerpt(output *strings.Builder, excerpt []byte) {
	if bytes.Contains(excerpt, []byte{'\r'}) || !bytes.HasSuffix(excerpt, []byte{'\n'}) {
		writeText(output, "Verified excerpt (base64, exact bytes):")
		writeBase64FencedText(output, excerpt)
		return
	}
	writeText(output, "Verified excerpt:")
	writeExactFencedText(output, string(excerpt))
}

func writeExactFencedText(output *strings.Builder, value string) {
	fence := strings.Repeat("`", maxBacktickRun(value)+1)
	if len(fence) < 3 {
		fence = "```"
	}
	output.WriteString(fence)
	output.WriteString("text\n")
	output.WriteString(value)
	output.WriteString(fence)
	output.WriteString("\n")
}
func writeBase64FencedText(output *strings.Builder, value []byte) {
	output.WriteString("```base64\n")
	output.WriteString(base64.StdEncoding.EncodeToString(value))
	output.WriteString("\n```\n")
}

func writeBlankLine(output *strings.Builder) {
	if output.Len() > 0 {
		output.WriteString("\n")
	}
}

func reportPlain(value string) string {
	value = html.EscapeString(reportLF(value))
	return strings.ReplaceAll(value, "\n", "\\n")
}

func reportCode(value string) string {
	value = strings.ReplaceAll(reportLF(value), "\n", "\\n")
	delimiter := strings.Repeat("`", maxBacktickRun(value)+1)
	return delimiter + value + delimiter
}

func reportLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func reportList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	values = append([]string(nil), values...)
	for index := range values {
		values[index] = strings.ReplaceAll(reportLF(values[index]), "\n", "\\n")
	}
	return strings.Join(values, ", ")
}

func maxBacktickRun(value string) int {
	maximum := 0
	current := 0
	for _, character := range value {
		if character == '`' {
			current++
			if current > maximum {
				maximum = current
			}
			continue
		}
		current = 0
	}
	return maximum
}
