package ports

import (
	"encoding/json"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

// CapturedReviewArchive is the durable, authority-free serialization of one
// capture. It is sufficient to rematerialize the exact workspace and evidence
// used by rerun, followup, and delta without reopening the live project.
type capturedReviewArchiveWire struct {
	SchemaVersion     string                     `json:"schema_version"`
	TargetIdentity    capturedTargetIdentityWire `json:"target_identity"`
	TargetBytes       []byte                     `json:"target_bytes"`
	SnapshotPolicy    string                     `json:"snapshot_policy"`
	Snapshot          []capturedFileWire         `json:"snapshot"`
	ProjectContext    []byte                     `json:"project_context"`
	HasProjectContext bool                       `json:"has_project_context"`
	Evidence          []capturedEvidenceWire     `json:"evidence"`
}

type capturedTargetIdentityWire struct {
	Kind              string `json:"kind"`
	SHA256            string `json:"sha256"`
	RepositoryID      string `json:"repository_id"`
	BaseObjectID      string `json:"base_object_id"`
	HeadObjectID      string `json:"head_object_id"`
	HeadTreeObjectID  string `json:"head_tree_object_id"`
	IndexTreeObjectID string `json:"index_tree_object_id"`
	GitMode           string `json:"git_mode"`
}

type capturedFileWire struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Bytes     []byte `json:"bytes"`
	MediaType string `json:"media_type,omitempty"`
}

type capturedEvidenceWire struct {
	Side  string             `json:"side"`
	Files []capturedFileWire `json:"files"`
}

// MarshalCapturedReviewMaterial returns deterministic JSON. All maps are
// projected into fixed-order slices before marshaling.
func MarshalCapturedReviewMaterial(material CapturedReviewMaterial) ([]byte, error) {
	if !material.Valid() {
		return nil, fmt.Errorf("captured review archive: invalid material")
	}
	identity := material.Target().Identity()
	wire := capturedReviewArchiveWire{
		SchemaVersion: "mulgae-captured-review-archive.v1",
		TargetIdentity: capturedTargetIdentityWire{
			Kind: string(identity.Kind()), SHA256: identity.SHA256(), RepositoryID: identity.RepositoryID(),
			BaseObjectID: identity.BaseObjectID(), HeadObjectID: identity.HeadObjectID(),
			HeadTreeObjectID: identity.HeadTreeObjectID(), IndexTreeObjectID: identity.IndexTreeObjectID(),
			GitMode: string(identity.GitMode()),
		},
		TargetBytes: material.Target().Bytes(), SnapshotPolicy: material.Snapshot().PolicyIdentity(),
		Snapshot: filesToArchive(material.Snapshot().Files()), ProjectContext: material.ProjectContext(),
		HasProjectContext: material.HasProjectContext(),
	}
	for _, side := range []CapturedEvidenceSide{CapturedEvidenceBase, CapturedEvidenceHead, CapturedEvidenceIndex, CapturedEvidenceWorktree} {
		if files, ok := material.Evidence().Files(side); ok {
			wire.Evidence = append(wire.Evidence, capturedEvidenceWire{Side: string(side), Files: filesToArchive(files)})
		}
	}
	bytes, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("captured review archive: encode: %w", err)
	}
	return bytes, nil
}

// UnmarshalCapturedReviewMaterial validates every byte and identity while
// rebuilding constructor-owned domain objects.
func UnmarshalCapturedReviewMaterial(bytes []byte) (CapturedReviewMaterial, error) {
	var wire capturedReviewArchiveWire
	if err := json.Unmarshal(bytes, &wire); err != nil || wire.SchemaVersion != "mulgae-captured-review-archive.v1" {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid encoding")
	}
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetKind(wire.TargetIdentity.Kind), SHA256: wire.TargetIdentity.SHA256,
		RepositoryID: wire.TargetIdentity.RepositoryID, BaseObjectID: wire.TargetIdentity.BaseObjectID,
		HeadObjectID: wire.TargetIdentity.HeadObjectID, HeadTreeObjectID: wire.TargetIdentity.HeadTreeObjectID,
		IndexTreeObjectID: wire.TargetIdentity.IndexTreeObjectID, GitMode: domain.GitTargetMode(wire.TargetIdentity.GitMode),
	})
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: target identity: %w", err)
	}
	target, err := NewCapturedReviewTargetFromIdentity(identity, wire.TargetBytes)
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: target: %w", err)
	}
	snapshotFiles, err := archiveToFiles(wire.Snapshot)
	if err != nil {
		return CapturedReviewMaterial{}, err
	}
	snapshot, err := NewWorkspaceSnapshotRequest(snapshotFiles, wire.SnapshotPolicy)
	if err != nil {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: snapshot: %w", err)
	}
	sides := make(map[CapturedEvidenceSide][]WorkspaceSnapshotFile, len(wire.Evidence))
	for _, item := range wire.Evidence {
		side := CapturedEvidenceSide(item.Side)
		if !side.Valid() {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: invalid evidence side")
		}
		if _, duplicate := sides[side]; duplicate {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: duplicate evidence side")
		}
		files, fileErr := archiveToFiles(item.Files)
		if fileErr != nil {
			return CapturedReviewMaterial{}, fileErr
		}
		sides[side] = files
	}
	var evidence CapturedTargetEvidence
	if len(sides) > 0 {
		evidence, err = NewCapturedTargetEvidence(sides)
		if err != nil {
			return CapturedReviewMaterial{}, fmt.Errorf("captured review archive: evidence: %w", err)
		}
	}
	return NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, wire.ProjectContext, wire.HasProjectContext, evidence)
}

func filesToArchive(files []WorkspaceSnapshotFile) []capturedFileWire {
	result := make([]capturedFileWire, len(files))
	for index, file := range files {
		result[index] = capturedFileWire{Path: file.Path().String(), SHA256: file.SHA256(), Bytes: file.Bytes(), MediaType: file.MediaType()}
	}
	return result
}

func archiveToFiles(files []capturedFileWire) ([]WorkspaceSnapshotFile, error) {
	result := make([]WorkspaceSnapshotFile, len(files))
	for index, file := range files {
		path, err := NewSafeRelativePath(file.Path)
		if err != nil {
			return nil, fmt.Errorf("captured review archive: file path: %w", err)
		}
		if file.MediaType == "" || file.MediaType == "text/plain" {
			result[index], err = NewWorkspaceSnapshotFile(path, file.Bytes, file.SHA256)
		} else {
			result[index], err = NewWorkspaceVisualAsset(path, file.Bytes, file.SHA256, file.MediaType)
		}
		if err != nil {
			return nil, fmt.Errorf("captured review archive: file: %w", err)
		}
	}
	return result, nil
}
