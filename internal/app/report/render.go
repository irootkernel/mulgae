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
	"strings"
	"unicode/utf8"

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
	SchemaVersion     string              `json:"schema_version"`
	SessionID         string              `json:"session_id"`
	RunID             string              `json:"run_id"`
	ReviewID          string              `json:"review_id"`
	RunType           string              `json:"run_type"`
	CreatedAt         string              `json:"created_at"`
	KAR               reportKARDTO        `json:"kar"`
	ImmutableLineage  reportLineageDTO    `json:"immutable_lineage"`
	Target            reportTargetDTO     `json:"target"`
	Validation        reportValidationDTO `json:"validation"`
	ContentVerdict    string              `json:"content_verdict"`
	CoverageStatus    string              `json:"coverage_status"`
	PublicationStatus string              `json:"publication_status"`
	CIDecision        string              `json:"ci_decision"`
	CIReasonCodes     []string            `json:"ci_reason_codes"`
	SeverityThreshold reportSeverityDTO   `json:"severity_threshold"`
	RoleOutcomes      []reportRoleDTO     `json:"role_outcomes"`
	Findings          []reportFindingDTO  `json:"findings"`
	Limitations       []string            `json:"limitations"`
	Provenance        reportProvenanceDTO `json:"provenance"`
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
	TargetSHA256 string `json:"target_sha256"`
	Side         string `json:"side"`
	Path         string `json:"path"`
	LineStart    int    `json:"line_start"`
	LineEnd      int    `json:"line_end"`
	Quote        string `json:"quote"`
	Verification string `json:"verification"`
}

type reportProvenanceDTO struct {
	AggregationPath     string `json:"aggregation_path"`
	FinalValidationPath string `json:"final_validation_path"`
	ManifestPath        string `json:"manifest_path"`
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
	if final.SchemaVersion != "kar-review-artifact.v2" ||
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
	if _, err := canonicalReportProvenance(final.Provenance, review); err != nil {
		return fmt.Errorf("final provenance does not match the committed query view: %w", err)
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
		if len(evidence) != 1 || len(value.Evidence) != 1 {
			return fmt.Errorf("finding %d must have exactly one evidence item", index)
		}
		claim := evidence[0]
		item := value.Evidence[0]
		if item.Source.SessionID != claim.SourceSessionID().String() ||
			item.Source.RunID != claim.SourceRunID().String() ||
			item.Source.ReviewID != claim.SourceReviewID().String() ||
			item.Source.FindingID != claim.SourceFindingID() ||
			item.Source.SourceTargetSHA256 != claim.SourceTargetSHA256() ||
			item.Source.SourceExcerptSHA256 != claim.SourceExcerptSHA256() ||
			item.Current.TargetSHA256 != claim.TargetSHA256() ||
			item.Current.Side != string(claim.Side()) ||
			item.Current.Path != claim.Path().String() ||
			item.Current.LineStart != claim.LineStart() ||
			item.Current.LineEnd != claim.LineEnd() ||
			item.Current.Verification != string(claim.Verification()) {
			return fmt.Errorf("finding %d evidence does not match the committed query view", index)
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
		if len(claims) != 1 {
			return nil, reportFailure(domain.FailureArtifact, "committed finding must have exactly one evidence item", nil)
		}
		evidence := claims[0]

		writeSubheading(&output, finding.ID()+" — "+finding.Title())
		writeField(&output, "Severity", string(finding.Severity()))
		writeField(&output, "Confidence", string(finding.Confidence()))
		writeField(&output, "Lifecycle", string(finding.Lifecycle()))
		writeField(&output, "Role", string(finding.Role()))
		writeField(&output, "Provider instance", finding.ProviderInstance())
		writeField(&output, "Fingerprint", finding.Fingerprint())
		writeTextBlock(&output, "Explanation", finding.Description())
		writeTextBlock(&output, "Recommendation", finding.Recommendation())
		writeText(&output, "Evidence 1:")
		writeField(&output, "Source session ID", evidence.SourceSessionID().String())
		writeField(&output, "Source run ID", evidence.SourceRunID().String())
		writeField(&output, "Source review ID", evidence.SourceReviewID().String())
		writeField(&output, "Source finding ID", evidence.SourceFindingID())
		writeField(&output, "Source target SHA-256", evidence.SourceTargetSHA256())
		writeField(&output, "Source excerpt SHA-256", evidence.SourceExcerptSHA256())
		writeField(&output, "Current target SHA-256", evidence.TargetSHA256())
		writeField(&output, "Current side", string(evidence.Side()))
		writeField(&output, "Current path", evidence.Path().String())
		writeField(&output, "Current lines", fmt.Sprintf("%d-%d", evidence.LineStart(), evidence.LineEnd()))
		writeField(&output, "Committed verification", string(evidence.Verification()))

		excerpt, err := reader.RenderExcerpt(ctx, run, finding.ID(), review.TargetSHA256())
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
			if !reportExcerptMatchesSourceIdentity(excerpt, evidence) {
				return nil, reportFailure(domain.FailureArtifact, "verified excerpt does not match the committed source excerpt identity", nil)
			}
			writeVerifiedExcerpt(&output, excerpt)
		} else if failure.readiness {
			writeField(&output, "Re-read verification state", failure.state)
		} else {
			return nil, err
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
		if rank := reportFailurePrecedence(candidate.class); rank > selection.rank {
			selection.rank = rank
		}
	}
	for _, candidate := range candidates {
		if reportFailurePrecedence(candidate.class) != selection.rank {
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

func reportFailurePrecedence(class domain.FailureClass) int {
	switch class {
	case domain.FailureInternal:
		return 7
	case domain.FailureArtifact:
		return 6
	case domain.FailureSecurityPolicy:
		return 5
	case domain.FailureCancelled:
		return 4
	case domain.FailureConfiguration:
		return 3
	case domain.FailureProviderUnavailable,
		domain.FailureTimeout,
		domain.FailureAuthentication,
		domain.FailureQuota,
		domain.FailureRateLimit:
		return 2
	case domain.FailureInvalidOutput:
		return 1
	default:
		return 0
	}
}
func reportExcerptMatchesSourceIdentity(excerpt []byte, item query.Evidence) bool {
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
	return err == nil && digest == item.SourceExcerptSHA256()
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
