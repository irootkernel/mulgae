package artifactwire

type RestartState struct {
	SessionID                string           `json:"session_id"`
	RunID                    string           `json:"run_id"`
	PersistedJournalState    string           `json:"persisted_journal_state"`
	ExpectedStaged           ArtifactIdentity `json:"expected_staged"`
	ExpectedFinal            ArtifactIdentity `json:"expected_final"`
	ValidatedCandidateSHA256 string           `json:"validated_candidate_sha256"`
	StoreEpoch               uint64           `json:"store_epoch"`
	NormalExit               int              `json:"normal_exit"`
	ManifestPath             string           `json:"manifest_path"`
	LineageEdgePath          string           `json:"lineage_edge_path"`
	EpochPath                string           `json:"epoch_path"`
}

type PublicationJournal struct {
	SchemaVersion string `json:"schema_version"`
	RestartState
}

type PublicationStatus struct {
	SchemaVersion        string `json:"schema_version"`
	PublicationStatus    string `json:"publication_status"`
	PublicationAuthority string `json:"publication_authority"`
	RestartState
}

type PublicationEpoch struct {
	SchemaVersion string           `json:"schema_version"`
	StoreEpoch    uint64           `json:"store_epoch"`
	Manifest      ArtifactIdentity `json:"manifest"`
	LineageEdge   ArtifactIdentity `json:"lineage_edge"`
	FinalReview   ArtifactIdentity `json:"final_review"`
}

type LineageChild struct {
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id"`
	ReviewID  string `json:"review_id"`
}

type LineageEdge struct {
	SchemaVersion                string       `json:"schema_version"`
	EdgeID                       string       `json:"edge_id"`
	Child                        LineageChild `json:"child"`
	ParentRunID                  *string      `json:"parent_run_id"`
	SourceRunID                  *string      `json:"source_run_id"`
	SourceReviewID               *string      `json:"source_review_id"`
	SourceRecoveryManifestSHA256 *string      `json:"source_recovery_manifest_sha256,omitempty"`
	SourceKind                   string       `json:"source_kind,omitempty"`
	SourceAttemptID              *string      `json:"source_attempt_id,omitempty"`
	SourceFindingRef             *string      `json:"source_finding_ref"`
	ReplayMode                   *string      `json:"replay_mode"`
}

type CorruptionDiagnostic struct {
	SchemaVersion    string   `json:"schema_version"`
	SessionID        string   `json:"session_id"`
	RunID            string   `json:"run_id"`
	ObservationEpoch uint64   `json:"observation_epoch"`
	ReasonCodes      []string `json:"reason_codes"`
}
