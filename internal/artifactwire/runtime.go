// Package artifactwire owns primitive persisted representations shared by
// writers and readers. Its values carry no validation or storage authority.
package artifactwire

const (
	SupportIndexV1 = "mulgae-run-support-index.v1"
	SupportIndexV2 = "mulgae-run-support-index.v2"
	SupportIndexV4 = "mulgae-run-support-index.v4"
	SupportIndexV3 = "mulgae-run-support-index.v3"
)

type ArtifactIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type SupportIndex struct {
	SchemaVersion string             `json:"schema_version"`
	Artifacts     []ArtifactIdentity `json:"artifacts"`
}

const RuntimeTargetManifestV1 = "mulgae-runtime-target-manifest.v1"

type RuntimeTargetManifest struct {
	SchemaVersion         string                 `json:"schema_version"`
	Target                ArtifactIdentity       `json:"target"`
	CapturedArchive       *ArtifactIdentity      `json:"captured_archive,omitempty"`
	ArtistBrief           *ArtifactIdentity      `json:"artist_brief,omitempty"`
	ArtistVisualAssets    *ArtifactIdentity      `json:"artist_visual_assets,omitempty"`
	TargetKind            string                 `json:"target_kind"`
	RepositoryID          string                 `json:"repository_id"`
	BaseObjectID          string                 `json:"base_object_id"`
	HeadObjectID          string                 `json:"head_object_id"`
	HeadTreeObjectID      string                 `json:"head_tree_object_id"`
	IndexTreeObjectID     string                 `json:"index_tree_object_id"`
	GitMode               string                 `json:"git_mode"`
	Prompts               []ArtifactIdentity     `json:"prompts"`
	SelectedReplayPrompts []SelectedReplayPrompt `json:"selected_replay_prompts"`
}

type SelectedReplayPrompt struct {
	AttemptID string           `json:"attempt_id"`
	Sequence  uint64           `json:"sequence"`
	Purpose   string           `json:"purpose"`
	Artifact  ArtifactIdentity `json:"artifact"`
}

const RuntimePromptManifestV1 = "mulgae-runtime-prompt-manifest.v1"

type RuntimePromptManifest struct {
	SchemaVersion         string            `json:"schema_version"`
	Target                ArtifactIdentity  `json:"target"`
	Stdin                 ArtifactIdentity  `json:"stdin"`
	CompleteStdinSHA256   string            `json:"complete_stdin_sha256"`
	TemplateID            string            `json:"template_id"`
	TemplateVersion       string            `json:"template_version"`
	TemplateSHA256        string            `json:"template_sha256"`
	SourceInvocationID    string            `json:"source_invocation_id"`
	ExecutionInvocationID string            `json:"execution_invocation_id"`
	Scope                 string            `json:"scope"`
	Role                  string            `json:"role"`
	AdapterProfile        string            `json:"adapter_profile"`
	AdapterParameters     map[string]string `json:"adapter_parameters"`
}
