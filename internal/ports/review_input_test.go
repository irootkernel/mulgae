package ports

import (
	"bytes"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestCapturedReviewArchiveRoundTrip(t *testing.T) {
	target, snapshot, evidence := capturedReviewMaterialParts(t)
	material, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, []byte("context"), true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCapturedReviewMaterial(archive)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Target().Identity() != material.Target().Identity() || !bytes.Equal(restored.Target().Bytes(), material.Target().Bytes()) ||
		!bytes.Equal(restored.ProjectContext(), material.ProjectContext()) || restored.Snapshot().PolicyIdentity() != material.Snapshot().PolicyIdentity() {
		t.Fatal("captured review archive did not preserve material")
	}
	archive[len(archive)-2] ^= 1
	if _, err := UnmarshalCapturedReviewMaterial(archive); err == nil {
		t.Fatal("mutated captured review archive was accepted")
	}
}

func TestProviderWorkspaceUsesCurrentDirectoryForSingleTree(t *testing.T) {
	file := reviewInputWorkspaceFile(t, "src/main.go", "package main\n")
	target, err := NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewWorkspaceSnapshotRequest([]WorkspaceSnapshotFile{file}, "policy")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{CapturedEvidenceHead: {file}})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	files := workspace.Files()
	if len(files) != 2 || files[0].Path().String() != WorkspaceReviewTargetName || string(files[0].Bytes()) != "patch" ||
		files[1].Path().String() != "current/src/main.go" || string(files[1].Bytes()) != "package main\n" {
		t.Fatalf("provider workspace files = %#v", files)
	}
}

func TestProviderWorkspaceUsesBeforeAndAfterForGitComparison(t *testing.T) {
	base := reviewInputWorkspaceFile(t, "src/main.go", "before\n")
	head := reviewInputWorkspaceFile(t, "src/main.go", "after\n")
	baseID, _ := ParseGitObjectID(strings.Repeat("a", 40))
	headID, _ := ParseGitObjectID(strings.Repeat("b", 40))
	treeID, _ := ParseGitObjectID(strings.Repeat("c", 40))
	target, err := NewCapturedReviewGitTargetWithMode(domain.GitTargetDiff, "repository", baseID, headID, treeID, nil, []byte("diff\n"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewWorkspaceSnapshotRequest([]WorkspaceSnapshotFile{head}, "policy")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{
		CapturedEvidenceBase: {base}, CapturedEvidenceHead: {head},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	files := workspace.Files()
	if len(files) != 3 || files[0].Path().String() != WorkspaceReviewTargetName || string(files[0].Bytes()) != "diff\n" ||
		files[1].Path().String() != "after/src/main.go" || string(files[1].Bytes()) != "after\n" ||
		files[2].Path().String() != "before/src/main.go" || string(files[2].Bytes()) != "before\n" {
		t.Fatalf("provider comparison workspace files = %#v", files)
	}
	if material.Snapshot().Files()[0].Path().String() != "src/main.go" {
		t.Fatal("provider layout mutated the canonical captured snapshot")
	}
}

func TestProviderWorkspaceUsesCurrentDirectoryForNoChangeGitTarget(t *testing.T) {
	t.Parallel()

	file := reviewInputWorkspaceFile(t, "README.md", "current\n")
	snapshot, err := NewWorkspaceSnapshotRequest([]WorkspaceSnapshotFile{file}, "policy")
	if err != nil {
		t.Fatal(err)
	}
	baseID, _ := ParseGitObjectID(strings.Repeat("a", 40))
	headID, _ := ParseGitObjectID(strings.Repeat("b", 40))
	treeID, _ := ParseGitObjectID(strings.Repeat("c", 40))
	indexID, _ := ParseGitObjectID(strings.Repeat("d", 40))
	target, err := NewCapturedReviewGitTargetWithMode(domain.GitTargetStage, "repository", baseID, headID, treeID, &indexID, nil)
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterial(target, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}

	workspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	files := workspace.Files()
	if len(files) != 1 || files[0].Path().String() != "current/README.md" {
		t.Fatalf("provider workspace files = %#v", files)
	}
}

func reviewInputWorkspaceFile(t *testing.T, value, content string) WorkspaceSnapshotFile {
	t.Helper()
	path, err := NewSafeRelativePath(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Identifier([]byte(content))
	file, err := NewWorkspaceSnapshotFile(path, []byte(content), digest)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestCapturedReviewMaterialProjectContextPresence(t *testing.T) {
	target, snapshot, evidence := capturedReviewMaterialParts(t)

	absent, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, nil, false, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if absent.HasProjectContext() || absent.ProjectContext() != nil {
		t.Fatal("absent project context was not preserved")
	}

	presentEmpty, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, []byte{}, true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !presentEmpty.HasProjectContext() || presentEmpty.ProjectContext() == nil || len(presentEmpty.ProjectContext()) != 0 {
		t.Fatal("present empty project context was not preserved")
	}

	context := []byte("project context")
	present, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, context, true, evidence)
	if err != nil {
		t.Fatal(err)
	}
	context[0] = 'X'
	if got := string(present.ProjectContext()); got != "project context" {
		t.Fatalf("material retained caller project context storage: %q", got)
	}
	copy := present.ProjectContext()
	copy[0] = 'Y'
	if got := string(present.ProjectContext()); got != "project context" {
		t.Fatalf("ProjectContext() exposed material storage: %q", got)
	}

	legacyAbsent, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if legacyAbsent.HasProjectContext() {
		t.Fatal("legacy nil project context was treated as present")
	}
	legacyPresentEmpty, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, []byte{}, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyPresentEmpty.HasProjectContext() || legacyPresentEmpty.ProjectContext() == nil {
		t.Fatal("legacy non-nil empty project context was treated as absent")
	}
}

func TestCapturedReviewMaterialRejectsAbsentProjectContextBytes(t *testing.T) {
	target, snapshot, evidence := capturedReviewMaterialParts(t)
	if _, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, []byte("context"), false, evidence); err == nil {
		t.Fatal("absent project context with bytes was accepted")
	}
}

func capturedReviewMaterialParts(t *testing.T) (CapturedReviewTarget, WorkspaceSnapshotRequest, CapturedTargetEvidence) {
	t.Helper()
	target, err := NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewWorkspaceSnapshotRequest(nil, "captured-policy")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{
		CapturedEvidenceHead: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return target, snapshot, evidence
}
