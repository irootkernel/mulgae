package artifactwire

type CompositeSource struct {
	Kind                   string `json:"kind"`
	Role                   string `json:"role"`
	RunID                  string `json:"run_id"`
	ReviewID               string `json:"review_id,omitempty"`
	AttemptID              string `json:"attempt_id"`
	RoleReportSHA256       string `json:"role_report_sha256"`
	RecoveryManifestSHA256 string `json:"recovery_manifest_sha256,omitempty"`
	SourceKind             string `json:"source_kind,omitempty"`
}

type CompositeComposition struct {
	Fingerprint                string            `json:"fingerprint"`
	RootRunID                  string            `json:"root_run_id"`
	RootReviewID               string            `json:"root_review_id,omitempty"`
	Sources                    []CompositeSource `json:"sources"`
	RootRecoveryManifestSHA256 string            `json:"root_recovery_manifest_sha256,omitempty"`
	RootSourceKind             string            `json:"root_source_kind,omitempty"`
}

type CompositeManifestRole struct {
	Role        string `json:"role"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	ByteLength  int    `json:"byte_length"`
	AttemptID   string `json:"attempt_id"`
	SourceRunID string `json:"source_run_id"`
}

type CompositeRole struct {
	Role                         string   `json:"role"`
	Required                     bool     `json:"required"`
	Outcome                      string   `json:"outcome"`
	AttemptID                    string   `json:"attempt_id"`
	ProviderInstance             string   `json:"provider_instance"`
	ValidFindingIDs              []string `json:"valid_finding_ids"`
	SourceRunID                  string   `json:"source_run_id"`
	SourceReviewID               string   `json:"source_review_id,omitempty"`
	SourceRecoveryManifestSHA256 string   `json:"source_recovery_manifest_sha256,omitempty"`
	SourceKind                   string   `json:"source_kind,omitempty"`
}

type CompositeFinding struct {
	ID             string                 `json:"id"`
	Fingerprint    string                 `json:"fingerprint"`
	Role           string                 `json:"role"`
	Severity       string                 `json:"severity"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Recommendation string                 `json:"recommendation"`
	Confidence     string                 `json:"confidence"`
	Lifecycle      string                 `json:"lifecycle"`
	Source         CompositeFindingSource `json:"source"`
}

type CompositeFindingSource struct {
	RunID                  string `json:"run_id"`
	ReviewID               string `json:"review_id,omitempty"`
	AttemptID              string `json:"attempt_id"`
	FindingID              string `json:"finding_id"`
	RecoveryManifestSHA256 string `json:"recovery_manifest_sha256,omitempty"`
	SourceKind             string `json:"source_kind,omitempty"`
}
