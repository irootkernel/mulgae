// Package export builds deterministic, redacted export packages from verified P2 projections.
package export

import "time"

const (
	manifestSchemaVersion = "kar-export-manifest.v1"
	secureWriterContract  = "kar-secure-writer/v1"
)

// VerifiedSourceProjection is the complete allowlisted input to an export. It
// intentionally has no raw provider output, target bytes, environment, or host
// path fields. Callers must construct it only after P2 semantic verification.
type VerifiedSourceProjection struct {
	SessionID       string
	RunID           string
	ReviewID        string
	RunManifest     ImmutableArtifactRef
	ReviewArtifact  ImmutableArtifactRef
	SchemaVersions  []string
	Review          Review
	Run             Run
	Findings        []Finding
	Evidence        []Evidence
	Redaction       RedactionManifest
	SourceIdentity  SourceIdentity
	CurrentIdentity CurrentIdentity
}

type ImmutableArtifactRef struct {
	ArtifactPath string `json:"artifact_path"`
	SHA256       string `json:"sha256"`
}

type Review struct {
	SchemaVersion  string `json:"schema_version"`
	ContentVerdict string `json:"content_verdict"`
	CoverageStatus string `json:"coverage_status"`
}

type Run struct {
	SchemaVersion string `json:"schema_version"`
	State         string `json:"state"`
}

// Finding is the normalized, safe finding representation included in an export.
type Finding struct {
	ID             string `json:"id"`
	Fingerprint    string `json:"fingerprint"`
	Role           string `json:"role"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Confidence     string `json:"confidence"`
	Lifecycle      string `json:"lifecycle"`
}

// Evidence holds only identity and reducer-owned verification fields.
type Evidence struct {
	FindingID           string `json:"finding_id"`
	SourceSessionID     string `json:"source_session_id"`
	SourceRunID         string `json:"source_run_id"`
	SourceReviewID      string `json:"source_review_id"`
	SourceFindingID     string `json:"source_finding_id"`
	SourceTargetSHA256  string `json:"source_target_sha256"`
	SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
	TargetSHA256        string `json:"target_sha256"`
	Path                string `json:"path"`
	Side                string `json:"side"`
	LineStart           int    `json:"line_start"`
	LineEnd             int    `json:"line_end"`
	Verification        string `json:"verification"`
}

type RedactionManifest struct {
	Policy  string   `json:"policy"`
	Dropped []string `json:"dropped"`
}

type SourceIdentity struct {
	SessionID           string `json:"session_id"`
	RunID               string `json:"run_id"`
	ReviewID            string `json:"review_id"`
	FindingID           string `json:"finding_id"`
	SourceTargetSHA256  string `json:"source_target_sha256"`
	SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
}

type CurrentIdentity struct {
	TargetSHA256 string `json:"target_sha256"`
	Path         string `json:"path"`
	Side         string `json:"side"`
	LineStart    int    `json:"line_start"`
	LineEnd      int    `json:"line_end"`
	Verification string `json:"verification"`
}

// BuildOptions identifies deterministic package construction. The manifest is
// bound only after a secure writer issues the bundle receipt.
type BuildOptions struct {
	ExportID  string
	CreatedAt time.Time
}

// Bundle contains caller-owned deterministic package bytes and member metadata.
type Bundle struct {
	Bytes   []byte
	Members []Member
}

type Member struct {
	Path            string `json:"member_path"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
	MediaType       string `json:"media_type"`
	RedactionStatus string `json:"redaction_status"`
}

// ExportManifest is the sidecar for a completed bundle. It is deliberately not
// a bundle member, preventing a bundle-hash self reference.
type ExportManifest struct {
	SchemaVersion   string              `json:"schema_version"`
	ExportID        string              `json:"export_id"`
	CreatedAt       time.Time           `json:"created_at"`
	ImmutableSource ImmutableSource     `json:"immutable_source"`
	SourceIdentity  SourceIdentity      `json:"source_identity"`
	CurrentIdentity CurrentIdentity     `json:"current_identity"`
	SecureWriter    SecureWriterReceipt `json:"secure_writer"`
	Bundle          BundleIdentity      `json:"bundle"`
	Members         []Member            `json:"members"`
}

type ImmutableSource struct {
	SessionID         string               `json:"session_id"`
	RunID             string               `json:"run_id"`
	ReviewID          string               `json:"review_id"`
	RunManifestRef    ImmutableArtifactRef `json:"run_manifest_ref"`
	ReviewArtifactRef ImmutableArtifactRef `json:"review_artifact_ref"`
}

type SecureWriterReceipt struct {
	Contract            string              `json:"contract"`
	ScanBeforeWrite     bool                `json:"scan_before_write"`
	RedactionPolicy     string              `json:"redaction_policy"`
	RedactionStatus     string              `json:"redaction_status"`
	SecretBlockEvidence SecretBlockEvidence `json:"secret_block_evidence"`
	ReceiptSHA256       string              `json:"receipt_sha256"`
}

type SecretBlockEvidence struct {
	ScanStatus                  string `json:"scan_status"`
	OnDetection                 string `json:"on_detection"`
	SecretPersisted             bool   `json:"secret_persisted"`
	BlockedContentHashPersisted bool   `json:"blocked_content_hash_persisted"`
}

type BundleIdentity struct {
	MemberCount int    `json:"member_count"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}
