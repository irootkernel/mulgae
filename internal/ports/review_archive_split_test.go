package ports

import (
	"bytes"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestCapturedReviewArchiveSplitsAndDeduplicatesContent(t *testing.T) {
	t.Parallel()

	shared := reviewInputWorkspaceFile(t, "src/shared.txt", "shared bytes\n")
	snapshot, err := NewWorkspaceSnapshotRequest([]WorkspaceSnapshotFile{shared}, "policy")
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewCapturedReviewPatchTarget([]byte("patch bytes\n"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{
		CapturedEvidenceHead: {shared},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, shared.Bytes(), true, evidence)
	if err != nil {
		t.Fatal(err)
	}

	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	manifest := archive.Manifest()
	if bytes.Contains(manifest, []byte(`"bytes"`)) || bytes.Contains(manifest, []byte("c2hhcmVkIGJ5dGVzCg==")) {
		t.Fatalf("capture manifest embedded file bytes: %s", manifest)
	}
	if got := len(archive.Blobs()); got != 2 {
		t.Fatalf("unique blob count = %d, want 2", got)
	}
	references, err := CapturedReviewArchiveBlobReferences(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 2 {
		t.Fatalf("reference count = %d, want 2", len(references))
	}
	restored, err := RestoreCapturedReviewArchive(manifest, archive.Blobs())
	if err != nil {
		t.Fatal(err)
	}
	want, err := MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalCapturedReviewMaterial(restored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("split archive did not restore the exact captured material")
	}
	if _, err := RestoreCapturedReviewArchive(manifest, archive.Blobs()[:1]); err == nil || !strings.Contains(err.Error(), "blob inventory mismatch") {
		t.Fatalf("missing blob restore error = %v", err)
	}
}

func TestCapturedReviewArchiveRepresentsEmptyContentWithoutEmptyBlob(t *testing.T) {
	t.Parallel()

	baseID, _ := ParseGitObjectID(strings.Repeat("a", 40))
	headID, _ := ParseGitObjectID(strings.Repeat("b", 40))
	treeID, _ := ParseGitObjectID(strings.Repeat("c", 40))
	indexID, _ := ParseGitObjectID(strings.Repeat("d", 40))
	target, err := NewCapturedReviewGitTargetWithMode(domain.GitTargetStage, "repository", baseID, headID, treeID, &indexID, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewWorkspaceSnapshotRequest(nil, "no-change-policy")
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithProjectContext(target, snapshot, []byte{}, true)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Blobs()) != 0 {
		t.Fatalf("empty capture blobs = %d, want 0", len(archive.Blobs()))
	}
	restored, err := RestoreCapturedReviewArchive(archive.Manifest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Target().NoChange() || !restored.HasProjectContext() || restored.ProjectContext() == nil {
		t.Fatal("empty target or present-empty project context was not preserved")
	}
}
