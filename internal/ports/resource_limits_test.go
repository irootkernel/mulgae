package ports

import (
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestResourceLimitsAreCompatible(t *testing.T) {
	t.Parallel()

	if err := ValidateResourceLimits(); err != nil {
		t.Fatal(err)
	}
	if files, bytes := workspaceRequestLimits("capture-policy"); files != WorkspaceSnapshotMaxFiles || bytes != WorkspaceSnapshotMaxBytes {
		t.Fatalf("capture request limits = %d/%d", files, bytes)
	}
	if files, bytes := workspaceRequestLimits("capture-policy;layout=ordinary-directories-v1"); files != WorkspaceProviderViewMaxFiles || bytes != WorkspaceProviderViewMaxBytes {
		t.Fatalf("provider view limits = %d/%d", files, bytes)
	}
}

func TestMaximumFileCountGitComparisonIsViewableAndPublishable(t *testing.T) {
	files := make([]WorkspaceSnapshotFile, WorkspaceSnapshotMaxFiles)
	emptyDigest := sha256Identifier(nil)
	for index := range files {
		path, err := NewSafeRelativePath(fmt.Sprintf("f/%05d", index))
		if err != nil {
			t.Fatal(err)
		}
		files[index], err = NewWorkspaceSnapshotFile(path, nil, emptyDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := NewWorkspaceSnapshotRequest(files, "maximum-count")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{
		CapturedEvidenceBase: files,
		CapturedEvidenceHead: files,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseID, _ := ParseGitObjectID(strings.Repeat("a", 40))
	headID, _ := ParseGitObjectID(strings.Repeat("b", 40))
	treeID, _ := ParseGitObjectID(strings.Repeat("c", 40))
	target, err := NewCapturedReviewGitTargetWithMode(domain.GitTargetDiff, "repository", baseID, headID, treeID, nil, []byte("diff\n"))
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	view, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(view.Files()); got != WorkspaceProviderViewMaxFiles {
		t.Fatalf("provider comparison file count = %d, want %d", got, WorkspaceProviderViewMaxFiles)
	}
	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(archive.Manifest())) > CapturedReviewManifestMaxBytes {
		t.Fatalf("maximum-count manifest size = %d", len(archive.Manifest()))
	}
}
