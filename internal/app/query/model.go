// Package query exposes committed publication data to status, findings, excerpt,
// and report consumers. It never grants publication authority itself.
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// SchemaValidator validates final publication records against their consumer-owned
// embedded schema asset.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// CommittedReview is a defensive read view of a semantically verified P2 final
// review. Exact final and manifest bytes remain available only as copies.
type CommittedReview struct {
	sessionID       domain.SessionID
	runID           domain.RunID
	reviewID        domain.ReviewID
	runState        domain.RunState
	finalPath       ports.SafeRelativePath
	finalSHA256     string
	manifestPath    ports.SafeRelativePath
	manifestSHA256  string
	lineageEdgePath ports.SafeRelativePath
	lineageEdgeSHA  string
	epoch           uint64
	epochPath       ports.SafeRelativePath
	targetSHA256    string
	content         domain.ContentVerdict
	coverage        domain.CoverageStatus
	publication     domain.PublicationStatus
	ci              domain.CIDecision
	followupOutcome *FollowupOutcome
	roles           []Role
	findings        []Finding
	finalBytes      []byte
	manifestBytes   []byte
}

// SessionID returns the committed review's session identity.
func (review CommittedReview) SessionID() domain.SessionID { return review.sessionID }

// RunID returns the committed review's run identity.
func (review CommittedReview) RunID() domain.RunID { return review.runID }

// ReviewID returns the publisher-issued review identity.
func (review CommittedReview) ReviewID() domain.ReviewID { return review.reviewID }

// RunState returns the terminal run state recorded in the committed manifest.
func (review CommittedReview) RunState() domain.RunState { return review.runState }

// FinalPath returns the authoritative P2 final artifact path.
func (review CommittedReview) FinalPath() ports.SafeRelativePath { return review.finalPath }

// FinalSHA256 returns the authoritative P2 final artifact digest.
func (review CommittedReview) FinalSHA256() string { return review.finalSHA256 }

// ManifestPath returns the immutable committed manifest path.
func (review CommittedReview) ManifestPath() ports.SafeRelativePath { return review.manifestPath }

// ManifestSHA256 returns the immutable committed manifest digest.
func (review CommittedReview) ManifestSHA256() string { return review.manifestSHA256 }

// LineageEdgePath returns the immutable lineage edge path bound by the final.
func (review CommittedReview) LineageEdgePath() ports.SafeRelativePath { return review.lineageEdgePath }

// LineageEdgeSHA256 returns the immutable lineage edge digest bound by the final.
func (review CommittedReview) LineageEdgeSHA256() string { return review.lineageEdgeSHA }

// Epoch returns the positive immutable publication epoch.
func (review CommittedReview) Epoch() uint64 { return review.epoch }

// EpochPath returns the immutable epoch record path bound by the manifest.
func (review CommittedReview) EpochPath() ports.SafeRelativePath { return review.epochPath }

// TargetSHA256 returns the canonical current target digest bound by the final.
func (review CommittedReview) TargetSHA256() string { return review.targetSHA256 }

// ContentVerdict returns the independent committed content axis.
func (review CommittedReview) ContentVerdict() domain.ContentVerdict { return review.content }

// CoverageStatus returns the independent committed coverage axis.
func (review CommittedReview) CoverageStatus() domain.CoverageStatus { return review.coverage }

// PublicationStatus returns the committed publication axis.
func (review CommittedReview) PublicationStatus() domain.PublicationStatus { return review.publication }

// CIDecision returns the independent committed CI axis.
func (review CommittedReview) CIDecision() domain.CIDecision { return review.ci }

// FollowupOutcome returns the committed followup resolution only for followup
// reviews. Its rationale and evidence are validated final/manifest data.
func (review CommittedReview) FollowupOutcome() (FollowupOutcome, bool) {
	if review.followupOutcome == nil {
		return FollowupOutcome{}, false
	}
	return cloneFollowupOutcome(*review.followupOutcome), true
}

// Roles returns caller-owned role views in final artifact order.
func (review CommittedReview) Roles() []Role { return cloneRoles(review.roles) }

// Findings returns caller-owned finding views in final artifact order.
func (review CommittedReview) Findings() []Finding { return cloneFindings(review.findings) }

// FinalBytes returns a caller-owned copy of the exact final artifact bytes.
func (review CommittedReview) FinalBytes() []byte { return cloneBytes(review.finalBytes) }

// ManifestBytes returns a caller-owned copy of the exact committed manifest bytes.
func (review CommittedReview) ManifestBytes() []byte { return cloneBytes(review.manifestBytes) }

// FollowupOutcome is the immutable committed resolution for a followup review.
type FollowupOutcome struct {
	resolution domain.FollowupResolution
	rationale  string
	evidence   []FollowupEvidence
}

// Resolution returns the validator-owned followup resolution.
func (outcome FollowupOutcome) Resolution() domain.FollowupResolution { return outcome.resolution }

// Rationale returns the committed followup rationale.
func (outcome FollowupOutcome) Rationale() string { return outcome.rationale }

// Evidence returns caller-owned committed followup evidence in final order.
func (outcome FollowupOutcome) Evidence() []FollowupEvidence {
	return cloneFollowupEvidence(outcome.evidence)
}

// FollowupEvidence is one immutable committed followup evidence claim.
type FollowupEvidence struct {
	sourceSessionID     domain.SessionID
	sourceRunID         domain.RunID
	sourceReviewID      domain.ReviewID
	sourceFindingID     string
	sourceTargetSHA256  string
	sourceExcerptSHA256 string
	targetSHA256        string
	side                evidence.Side
	path                ports.SafeRelativePath
	lineStart           int
	lineEnd             int
	quote               string
	verification        evidence.ReceiptStatus
}

func (item FollowupEvidence) SourceSessionID() domain.SessionID { return item.sourceSessionID }
func (item FollowupEvidence) SourceRunID() domain.RunID         { return item.sourceRunID }
func (item FollowupEvidence) SourceReviewID() domain.ReviewID   { return item.sourceReviewID }
func (item FollowupEvidence) SourceFindingID() string           { return item.sourceFindingID }
func (item FollowupEvidence) SourceTargetSHA256() string        { return item.sourceTargetSHA256 }
func (item FollowupEvidence) SourceExcerptSHA256() string       { return item.sourceExcerptSHA256 }
func (item FollowupEvidence) TargetSHA256() string              { return item.targetSHA256 }
func (item FollowupEvidence) Side() evidence.Side               { return item.side }
func (item FollowupEvidence) Path() ports.SafeRelativePath      { return item.path }
func (item FollowupEvidence) LineStart() int                    { return item.lineStart }
func (item FollowupEvidence) LineEnd() int                      { return item.lineEnd }
func (item FollowupEvidence) Quote() string                     { return item.quote }
func (item FollowupEvidence) Verification() evidence.ReceiptStatus {
	return item.verification
}

// RuntimeTarget is the immutable target material reconstructed from a committed
// P2 target manifest. Its bytes and identity are returned as defensive copies.
type RuntimeTarget struct {
	identity domain.TargetIdentity
	bytes    []byte
}

func (target RuntimeTarget) Identity() domain.TargetIdentity { return target.identity }
func (target RuntimeTarget) Bytes() []byte                   { return cloneBytes(target.bytes) }

// RuntimePrompt is exact persisted replay material from one initial invocation.
type RuntimePrompt struct {
	stdin                 []byte
	stdinSHA256           string
	completeStdinSHA256   string
	manifestPath          ports.SafeRelativePath
	manifestSHA256        string
	templateID            string
	templateVersion       string
	templateSHA256        string
	sourceInvocationID    string
	executionInvocationID string
	scope                 string
	role                  domain.Role
	adapterProfile        string
	adapterParameters     map[string]string
}

func (prompt RuntimePrompt) Stdin() []byte                        { return cloneBytes(prompt.stdin) }
func (prompt RuntimePrompt) StdinSHA256() string                  { return prompt.stdinSHA256 }
func (prompt RuntimePrompt) CompleteStdinSHA256() string          { return prompt.completeStdinSHA256 }
func (prompt RuntimePrompt) ManifestPath() ports.SafeRelativePath { return prompt.manifestPath }
func (prompt RuntimePrompt) ManifestSHA256() string               { return prompt.manifestSHA256 }
func (prompt RuntimePrompt) TemplateID() string                   { return prompt.templateID }
func (prompt RuntimePrompt) TemplateVersion() string              { return prompt.templateVersion }
func (prompt RuntimePrompt) TemplateSHA256() string               { return prompt.templateSHA256 }
func (prompt RuntimePrompt) SourceInvocationID() string           { return prompt.sourceInvocationID }
func (prompt RuntimePrompt) ExecutionInvocationID() string        { return prompt.executionInvocationID }
func (prompt RuntimePrompt) Scope() string                        { return prompt.scope }
func (prompt RuntimePrompt) Role() domain.Role                    { return prompt.role }
func (prompt RuntimePrompt) AdapterProfile() string               { return prompt.adapterProfile }
func (prompt RuntimePrompt) AdapterParameters() map[string]string {
	result := make(map[string]string, len(prompt.adapterParameters))
	for key, value := range prompt.adapterParameters {
		result[key] = value
	}
	return result
}

// CommittedAttempt is the unique P2-bound source projection for one attempt.
type CommittedAttempt struct {
	sessionID domain.SessionID
	runID     domain.RunID
	reviewID  domain.ReviewID
	attemptID domain.AttemptID
	role      domain.Role
	provider  string
	target    RuntimeTarget
	prompt    RuntimePrompt
}

func (attempt CommittedAttempt) SessionID() domain.SessionID { return attempt.sessionID }
func (attempt CommittedAttempt) RunID() domain.RunID         { return attempt.runID }
func (attempt CommittedAttempt) ReviewID() domain.ReviewID   { return attempt.reviewID }
func (attempt CommittedAttempt) AttemptID() domain.AttemptID { return attempt.attemptID }
func (attempt CommittedAttempt) Role() domain.Role           { return attempt.role }
func (attempt CommittedAttempt) Provider() string            { return attempt.provider }
func (attempt CommittedAttempt) Target() RuntimeTarget {
	return RuntimeTarget{identity: attempt.target.identity, bytes: cloneBytes(attempt.target.bytes)}
}
func (attempt CommittedAttempt) Prompt() RuntimePrompt {
	return RuntimePrompt{
		stdin: cloneBytes(attempt.prompt.stdin), stdinSHA256: attempt.prompt.stdinSHA256,
		completeStdinSHA256: attempt.prompt.completeStdinSHA256, manifestPath: attempt.prompt.manifestPath,
		manifestSHA256: attempt.prompt.manifestSHA256, templateID: attempt.prompt.templateID, templateVersion: attempt.prompt.templateVersion,
		templateSHA256: attempt.prompt.templateSHA256, sourceInvocationID: attempt.prompt.sourceInvocationID,
		executionInvocationID: attempt.prompt.executionInvocationID, scope: attempt.prompt.scope, role: attempt.prompt.role,
		adapterProfile: attempt.prompt.adapterProfile, adapterParameters: attempt.prompt.AdapterParameters(),
	}
}

// CommittedFindingSource contains the exact P2 support artifacts bound to a
// committed finding. All byte accessors return defensive copies.
type CommittedFindingSource struct {
	review     CommittedReview
	finding    Finding
	normalized []byte
	excerpt    []byte
}

func (source CommittedFindingSource) Review() CommittedReview { return source.review }
func (source CommittedFindingSource) Finding() Finding        { return source.finding }
func (source CommittedFindingSource) Normalized() []byte      { return cloneBytes(source.normalized) }
func (source CommittedFindingSource) Excerpt() []byte         { return cloneBytes(source.excerpt) }

type runtimeTargetManifestDTO struct {
	SchemaVersion         string                    `json:"schema_version"`
	Target                artifactIdentityDTO       `json:"target"`
	TargetKind            string                    `json:"target_kind"`
	RepositoryID          string                    `json:"repository_id"`
	BaseObjectID          string                    `json:"base_object_id"`
	HeadObjectID          string                    `json:"head_object_id"`
	HeadTreeObjectID      string                    `json:"head_tree_object_id"`
	IndexTreeObjectID     string                    `json:"index_tree_object_id"`
	Prompts               []artifactIdentityDTO     `json:"prompts"`
	SelectedReplayPrompts []selectedReplayPromptDTO `json:"selected_replay_prompts"`
}

type selectedReplayPromptDTO struct {
	AttemptID string              `json:"attempt_id"`
	Sequence  uint64              `json:"sequence"`
	Purpose   string              `json:"purpose"`
	Artifact  artifactIdentityDTO `json:"artifact"`
}

type runtimePromptManifestDTO struct {
	SchemaVersion         string              `json:"schema_version"`
	Target                artifactIdentityDTO `json:"target"`
	Stdin                 artifactIdentityDTO `json:"stdin"`
	CompleteStdinSHA256   string              `json:"complete_stdin_sha256"`
	TemplateID            string              `json:"template_id"`
	TemplateVersion       string              `json:"template_version"`
	TemplateSHA256        string              `json:"template_sha256"`
	SourceInvocationID    string              `json:"source_invocation_id"`
	ExecutionInvocationID string              `json:"execution_invocation_id"`
	Scope                 string              `json:"scope"`
	Role                  string              `json:"role"`
	AdapterProfile        string              `json:"adapter_profile"`
	AdapterParameters     map[string]string   `json:"adapter_parameters"`
}

// Role is the report-facing summary for one selected role.
type Role struct {
	role             domain.Role
	required         bool
	outcome          string
	attemptID        string
	providerInstance string
	selectedVia      string
	findingIDs       []string
	failureReason    string
	limitations      []string
}

// Name returns the fixed KAR role.
func (role Role) Name() domain.Role { return role.role }

// Required reports whether the role was required for coverage.
func (role Role) Required() bool { return role.required }

// Outcome returns completed, degraded, failed, or skipped as serialized.
func (role Role) Outcome() string { return role.outcome }

// AttemptID returns the selected terminal attempt ID, when one exists.
func (role Role) AttemptID() (domain.AttemptID, bool) {
	if role.attemptID == "" {
		return domain.AttemptID{}, false
	}
	attemptID, err := domain.ParseAttemptID(role.attemptID)
	return attemptID, err == nil
}

// ProviderInstance returns the selected provider instance, when one exists.
func (role Role) ProviderInstance() (string, bool) {
	return role.providerInstance, role.providerInstance != ""
}

// SelectedVia returns primary or fallback, when one exists.
func (role Role) SelectedVia() (string, bool) { return role.selectedVia, role.selectedVia != "" }

// ValidFindingIDs returns a caller-owned copy of the role's finding references.
func (role Role) ValidFindingIDs() []string { return append([]string(nil), role.findingIDs...) }

// FailureReason returns the terminal failure reason, when one exists.
func (role Role) FailureReason() (string, bool) { return role.failureReason, role.failureReason != "" }

// Limitations returns a caller-owned copy of the role limitations.
func (role Role) Limitations() []string { return append([]string(nil), role.limitations...) }

// Finding is one immutable report-facing finding. Evidence carries claims only;
// callers must use RenderExcerpt to obtain freshly verified bytes.
type Finding struct {
	id               string
	fingerprint      string
	role             domain.Role
	providerInstance string
	severity         domain.Severity
	title            string
	description      string
	recommendation   string
	confidence       domain.Confidence
	lifecycle        domain.FindingLifecycle
	evidence         []Evidence
}

// ID returns the final deterministic finding ID.
func (finding Finding) ID() string { return finding.id }

// Fingerprint returns the canonical finding fingerprint digest.
func (finding Finding) Fingerprint() string { return finding.fingerprint }

// Role returns the producing fixed KAR role.
func (finding Finding) Role() domain.Role { return finding.role }

// ProviderInstance returns the producing provider instance.
func (finding Finding) ProviderInstance() string { return finding.providerInstance }

// Severity returns the normalized severity.
func (finding Finding) Severity() domain.Severity { return finding.severity }

// Title returns the concise finding title.
func (finding Finding) Title() string { return finding.title }

// Description returns the finding explanation.
func (finding Finding) Description() string { return finding.description }

// Recommendation returns the final recommendation.
func (finding Finding) Recommendation() string { return finding.recommendation }

// Confidence returns the normalized confidence.
func (finding Finding) Confidence() domain.Confidence { return finding.confidence }

// Lifecycle returns the final finding lifecycle.
func (finding Finding) Lifecycle() domain.FindingLifecycle { return finding.lifecycle }

// Evidence returns caller-owned evidence claim views in final artifact order.
func (finding Finding) Evidence() []Evidence { return cloneEvidence(finding.evidence) }

// Evidence binds one source identity to one current immutable-target claim.
type Evidence struct {
	sourceSessionID     domain.SessionID
	sourceRunID         domain.RunID
	sourceReviewID      domain.ReviewID
	sourceFindingID     string
	sourceTargetSHA256  string
	sourceExcerptSHA256 string
	targetSHA256        string
	side                evidence.Side
	path                ports.SafeRelativePath
	lineStart           int
	lineEnd             int
	quote               string
	verification        evidence.ReceiptStatus
}

// SourceSessionID returns the source review session identity.
func (item Evidence) SourceSessionID() domain.SessionID { return item.sourceSessionID }

// SourceRunID returns the source review run identity.
func (item Evidence) SourceRunID() domain.RunID { return item.sourceRunID }

// SourceReviewID returns the source review identity.
func (item Evidence) SourceReviewID() domain.ReviewID { return item.sourceReviewID }

// SourceFindingID returns the source finding reference.
func (item Evidence) SourceFindingID() string { return item.sourceFindingID }

// SourceTargetSHA256 returns the source immutable target digest.
func (item Evidence) SourceTargetSHA256() string { return item.sourceTargetSHA256 }

// SourceExcerptSHA256 returns the source excerpt digest.
func (item Evidence) SourceExcerptSHA256() string { return item.sourceExcerptSHA256 }

// TargetSHA256 returns the current immutable target digest.
func (item Evidence) TargetSHA256() string { return item.targetSHA256 }

// Side returns the claimed immutable target side.
func (item Evidence) Side() evidence.Side { return item.side }

// Path returns the logical target path.
func (item Evidence) Path() ports.SafeRelativePath { return item.path }

// LineStart returns the inclusive one-based first line.
func (item Evidence) LineStart() int { return item.lineStart }

// LineEnd returns the inclusive one-based final line.
func (item Evidence) LineEnd() int { return item.lineEnd }

// Verification returns the final serialized evidence verification state.
func (item Evidence) Verification() evidence.ReceiptStatus { return item.verification }

// RunStatus is the safe status projection of one observed run. Content and final
// artifact details are present only after an independent P2 committed read.
type RunStatus struct {
	sessionID    domain.SessionID
	runID        domain.RunID
	publication  domain.PublicationStatus
	authority    domain.PublicationAuthority
	action       domain.RecoveryAction
	runState     domain.RunState
	hasRunState  bool
	content      domain.ContentVerdict
	coverage     domain.CoverageStatus
	ci           domain.CIDecision
	hasAxes      bool
	finalPath    ports.SafeRelativePath
	hasFinalPath bool
}

// Status is the report-facing alias for one safe run status projection.
type Status = RunStatus

// SessionID returns the observed session identity.
func (status RunStatus) SessionID() domain.SessionID { return status.sessionID }

// RunID returns the observed run identity.
func (status RunStatus) RunID() domain.RunID { return status.runID }

// PublicationStatus returns the classifier-derived publication status.
func (status RunStatus) PublicationStatus() domain.PublicationStatus { return status.publication }

// Authority returns the classifier-derived durable authority.
func (status RunStatus) Authority() domain.PublicationAuthority { return status.authority }

// RecoveryAction returns the classifier-derived next recovery action.
func (status RunStatus) RecoveryAction() domain.RecoveryAction { return status.action }

// RunState returns a manifest-backed state only when a committed manifest was
// independently parsed and semantically verified.
func (status RunStatus) RunState() (domain.RunState, bool) {
	return status.runState, status.hasRunState
}

// ContentVerdict returns a committed final axis only when safely available.
func (status RunStatus) ContentVerdict() (domain.ContentVerdict, bool) {
	return status.content, status.hasAxes
}

// CoverageStatus returns a committed final axis only when safely available.
func (status RunStatus) CoverageStatus() (domain.CoverageStatus, bool) {
	return status.coverage, status.hasAxes
}

// CIDecision returns a committed final axis only when safely available.
func (status RunStatus) CIDecision() (domain.CIDecision, bool) { return status.ci, status.hasAxes }

// FinalPath returns a P2 final path only after the committed review passed all
// schema and semantic checks.
func (status RunStatus) FinalPath() (ports.SafeRelativePath, bool) {
	return status.finalPath, status.hasFinalPath
}

type finalDTO struct {
	SchemaVersion     string               `json:"schema_version"`
	SessionID         string               `json:"session_id"`
	RunID             string               `json:"run_id"`
	ReviewID          string               `json:"review_id"`
	RunType           string               `json:"run_type"`
	CreatedAt         string               `json:"created_at"`
	KAR               finalKARDTO          `json:"kar"`
	ImmutableLineage  lineageDTO           `json:"immutable_lineage"`
	FollowupOutcome   *followupOutcomeDTO  `json:"followup_outcome"`
	Target            finalTargetDTO       `json:"target"`
	Validation        finalValidationDTO   `json:"validation"`
	ContentVerdict    string               `json:"content_verdict"`
	CoverageStatus    string               `json:"coverage_status"`
	PublicationStatus string               `json:"publication_status"`
	CIDecision        string               `json:"ci_decision"`
	CIReasonCodes     []string             `json:"ci_reason_codes"`
	SeverityThreshold severityThresholdDTO `json:"severity_threshold"`
	RoleOutcomes      []finalRoleDTO       `json:"role_outcomes"`
	Findings          []finalFindingDTO    `json:"findings"`
	Limitations       []string             `json:"limitations"`
	Provenance        provenanceDTO        `json:"provenance"`
}

type followupOutcomeDTO struct {
	Resolution string             `json:"resolution"`
	Rationale  string             `json:"rationale"`
	Evidence   []finalEvidenceDTO `json:"evidence"`
}

type finalKARDTO struct {
	Version string  `json:"version"`
	Commit  *string `json:"commit"`
}

type lineageDTO struct {
	ParentRunID      *string `json:"parent_run_id"`
	SourceRunID      *string `json:"source_run_id"`
	SourceReviewID   *string `json:"source_review_id"`
	SourceFindingRef *string `json:"source_finding_ref"`
	ReplayMode       *string `json:"replay_mode"`
	LineageEdgePath  string  `json:"lineage_edge_path"`
	LineageEdgeSHA   string  `json:"lineage_edge_sha256"`
}

type finalTargetDTO struct {
	ContentSHA256 string  `json:"content_sha256"`
	ManifestPath  string  `json:"manifest_path"`
	BaseOID       *string `json:"base_oid"`
	HeadOID       *string `json:"head_oid"`
}

type finalValidationDTO struct {
	Status             string `json:"status"`
	SchemaValidation   string `json:"schema_validation"`
	SemanticValidation string `json:"semantic_validation"`
	EvidenceValidation string `json:"evidence_validation"`
}

type severityThresholdDTO struct {
	RequestChangesAtOrAbove string `json:"request_changes_at_or_above"`
	PolicySource            string `json:"policy_source"`
}

type finalRoleDTO struct {
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

type finalFindingDTO struct {
	ID               string             `json:"id"`
	Fingerprint      string             `json:"fingerprint"`
	Role             string             `json:"role"`
	ProviderInstance string             `json:"provider_instance"`
	Severity         string             `json:"severity"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Evidence         []finalEvidenceDTO `json:"evidence"`
	Recommendation   string             `json:"recommendation"`
	Confidence       string             `json:"confidence"`
	Lifecycle        string             `json:"lifecycle"`
}

type finalEvidenceDTO struct {
	Source  sourceEvidenceDTO  `json:"source"`
	Current currentEvidenceDTO `json:"current"`
}

type sourceEvidenceDTO struct {
	SessionID           string `json:"session_id"`
	RunID               string `json:"run_id"`
	ReviewID            string `json:"review_id"`
	FindingID           string `json:"finding_id"`
	SourceTargetSHA256  string `json:"source_target_sha256"`
	SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
}

type currentEvidenceDTO struct {
	TargetSHA256 string `json:"target_sha256"`
	Side         string `json:"side"`
	Path         string `json:"path"`
	LineStart    int    `json:"line_start"`
	LineEnd      int    `json:"line_end"`
	Quote        string `json:"quote"`
	Verification string `json:"verification"`
}

type provenanceDTO struct {
	AggregationPath     string `json:"aggregation_path"`
	FinalValidationPath string `json:"final_validation_path"`
	ManifestPath        string `json:"manifest_path"`
}

type manifestDTO struct {
	SchemaVersion            string               `json:"schema_version"`
	SessionID                string               `json:"session_id"`
	RunID                    string               `json:"run_id"`
	RunType                  string               `json:"run_type"`
	State                    string               `json:"state"`
	Sealed                   bool                 `json:"sealed"`
	CreatedAt                string               `json:"created_at"`
	StartedAt                *string              `json:"started_at"`
	CompletedAt              *string              `json:"completed_at"`
	KARVersion               string               `json:"kar_version"`
	ImmutableLineage         lineageDTO           `json:"immutable_lineage"`
	FollowupOutcome          *followupOutcomeDTO  `json:"followup_outcome"`
	Target                   manifestTargetDTO    `json:"target"`
	SelectedRoles            []string             `json:"selected_roles"`
	RequiredRoles            []string             `json:"required_roles"`
	Attempts                 []manifestAttemptDTO `json:"attempts"`
	ContentVerdict           string               `json:"content_verdict"`
	CoverageStatus           string               `json:"coverage_status"`
	PublicationStatus        string               `json:"publication_status"`
	CIDecision               string               `json:"ci_decision"`
	CIReasonCodes            []string             `json:"ci_reason_codes"`
	PersistedJournalState    string               `json:"persisted_journal_state"`
	DurableObservationClass  string               `json:"durable_observation_class"`
	DerivedPublicationStatus string               `json:"derived_publication_status"`
	PublicationAuthority     string               `json:"publication_authority"`
	RecoveryJournal          recoveryJournalDTO   `json:"recovery_journal"`
	CompositeIdentity        compositeIdentityDTO `json:"composite_identity"`
	RecoveryAction           string               `json:"recovery_action"`
	FinalReview              *finalReviewDTO      `json:"final_review"`
	Failures                 []manifestFailureDTO `json:"failures"`
	Warnings                 []string             `json:"warnings"`
	ExitCode                 int                  `json:"exit_code"`
}

type manifestTargetDTO struct {
	ManifestPath  string `json:"manifest_path"`
	ContentSHA256 string `json:"content_sha256"`
}

type manifestAttemptDTO struct {
	AttemptID        string `json:"attempt_id"`
	Role             string `json:"role"`
	ProviderInstance string `json:"provider_instance"`
	SelectedAs       string `json:"selected_as"`
	State            string `json:"state"`
	ParseState       string `json:"parse_state"`
	ValidationState  string `json:"validation_state"`
	Path             string `json:"path"`
	InvocationCount  int    `json:"invocation_count"`
}

type recoveryJournalDTO struct {
	ExpectedStaged           *artifactIdentityDTO `json:"expected_staged"`
	ExpectedFinal            *artifactIdentityDTO `json:"expected_final"`
	ValidatedCandidateSHA256 *string              `json:"validated_candidate_sha256"`
}

type artifactIdentityDTO struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type compositeIdentityDTO struct {
	Manifest     *pathPointerDTO      `json:"manifest"`
	LineageEdge  *artifactIdentityDTO `json:"lineage_edge"`
	Epoch        *pathPointerDTO      `json:"epoch"`
	SupportIndex *artifactIdentityDTO `json:"support_index"`
}

type pathPointerDTO struct {
	Path string `json:"path"`
}

type finalReviewDTO struct {
	ReviewID string `json:"review_id"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

type manifestFailureDTO struct {
	Class      string  `json:"class"`
	Stage      string  `json:"stage"`
	ReasonCode string  `json:"reason_code"`
	AttemptID  *string `json:"attempt_id"`
}

func decodeFinalDTO(raw []byte) (finalDTO, error) {
	var value finalDTO
	if err := decodeStrictDTO(raw, &value); err != nil {
		return finalDTO{}, fmt.Errorf("final review JSON: %w", err)
	}
	return value, nil
}

func decodeManifestDTO(raw []byte) (manifestDTO, error) {
	var value manifestDTO
	if err := decodeStrictDTO(raw, &value); err != nil {
		return manifestDTO{}, fmt.Errorf("run manifest JSON: %w", err)
	}
	return value, nil
}

func decodeStrictDTO(raw []byte, destination any) error {
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
	if err := consumeJSONObject(scanner); err != nil {
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

func consumeJSONObject(decoder *json.Decoder) error {
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
		if err := consumeJSONValue(decoder); err != nil {
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

func consumeJSONValue(decoder *json.Decoder) error {
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
		return consumeJSONObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
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

func cloneRoles(source []Role) []Role {
	if source == nil {
		return nil
	}
	result := make([]Role, len(source))
	for index, role := range source {
		result[index] = Role{
			role: role.role, required: role.required, outcome: role.outcome, attemptID: role.attemptID,
			providerInstance: role.providerInstance, selectedVia: role.selectedVia,
			findingIDs: append([]string(nil), role.findingIDs...), failureReason: role.failureReason,
			limitations: append([]string(nil), role.limitations...),
		}
	}
	return result
}

func cloneFindings(source []Finding) []Finding {
	if source == nil {
		return nil
	}
	result := make([]Finding, len(source))
	for index, finding := range source {
		result[index] = Finding{
			id: finding.id, fingerprint: finding.fingerprint, role: finding.role,
			providerInstance: finding.providerInstance, severity: finding.severity, title: finding.title,
			description: finding.description, recommendation: finding.recommendation,
			confidence: finding.confidence, lifecycle: finding.lifecycle, evidence: cloneEvidence(finding.evidence),
		}
	}
	return result
}

func cloneEvidence(source []Evidence) []Evidence {
	if source == nil {
		return nil
	}
	return append([]Evidence(nil), source...)
}
func cloneFollowupOutcome(source FollowupOutcome) FollowupOutcome {
	return FollowupOutcome{
		resolution: source.resolution,
		rationale:  source.rationale,
		evidence:   cloneFollowupEvidence(source.evidence),
	}
}

func cloneFollowupEvidence(source []FollowupEvidence) []FollowupEvidence {
	return append([]FollowupEvidence(nil), source...)
}

func cloneBytes(source []byte) []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source...)
}
