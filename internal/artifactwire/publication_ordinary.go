package artifactwire

type BuildMetadata struct {
	Version string  `json:"version"`
	Commit  *string `json:"commit"`
}

type ImmutableLineage struct {
	ParentRunID                  *string `json:"parent_run_id"`
	SourceRunID                  *string `json:"source_run_id"`
	SourceReviewID               *string `json:"source_review_id"`
	SourceRecoveryManifestSHA256 *string `json:"source_recovery_manifest_sha256,omitempty"`
	SourceKind                   string  `json:"source_kind,omitempty"`
	SourceAttemptID              *string `json:"source_attempt_id,omitempty"`
	SourceFindingRef             *string `json:"source_finding_ref"`
	ReplayMode                   *string `json:"replay_mode"`
	LineageEdgePath              string  `json:"lineage_edge_path"`
	LineageEdgeSHA256            string  `json:"lineage_edge_sha256"`
}

type Validation struct {
	Status             string `json:"status"`
	SchemaValidation   string `json:"schema_validation"`
	SemanticValidation string `json:"semantic_validation"`
	EvidenceValidation string `json:"evidence_validation"`
}

type SeverityThreshold struct {
	RequestChangesAtOrAbove string `json:"request_changes_at_or_above"`
	PolicySource            string `json:"policy_source"`
}

type RoleOutcome struct {
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

type VisualEvidence struct {
	Path         string            `json:"path"`
	SHA256       string            `json:"sha256"`
	BBox         VisualBoundingBox `json:"bbox"`
	Verification string            `json:"verification"`
}

type VisualBoundingBox struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type ProductionProvenance struct {
	BuildProduct             string               `json:"build_product"`
	BuildVersion             string               `json:"build_version"`
	BuildCommit              string               `json:"build_commit"`
	ObjectiveSHA256          *string              `json:"objective_sha256"`
	ObjectivePresent         bool                 `json:"objective_present"`
	SnapshotManifestSHA256   string               `json:"snapshot_manifest_sha256"`
	WorkspaceTerminalReceipt string               `json:"workspace_terminal_receipt"`
	Providers                []ProductionProvider `json:"providers"`
}

type ProductionProvider struct {
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

type ManifestRoleReport struct {
	Role             string `json:"role"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	ByteLength       int    `json:"byte_length"`
	ProviderInstance string `json:"provider_instance"`
	AttemptID        string `json:"attempt_id"`
	ContentType      string `json:"content_type"`
	Transport        string `json:"transport"`
}

type ManifestAttempt struct {
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

type PathPointer struct {
	Path string `json:"path"`
}

type FinalReviewIdentity struct {
	ReviewID string `json:"review_id"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

type ManifestFailure struct {
	Class      string  `json:"class"`
	Stage      string  `json:"stage"`
	ReasonCode string  `json:"reason_code"`
	AttemptID  *string `json:"attempt_id"`
}

type LiveProductionProvenance struct {
	BuildProduct          string               `json:"build_product"`
	BuildVersion          string               `json:"build_version"`
	BuildCommit           string               `json:"build_commit"`
	ObjectiveSHA256       *string              `json:"objective_sha256"`
	ObjectivePresent      bool                 `json:"objective_present"`
	SourceIdentitySHA256  string               `json:"source_identity_sha256"`
	SourceTerminalReceipt string               `json:"source_terminal_receipt"`
	Providers             []ProductionProvider `json:"providers"`
}
