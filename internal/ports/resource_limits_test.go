package ports

import (
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestOperationalResourceLimitsAreCompatible(t *testing.T) {
	t.Parallel()

	if err := ValidateResourceLimits(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceAdmissionAcceptsLargeValidSourceFacts(t *testing.T) {
	if err := ValidateWorkspaceAdmission("capture-policy", "current", 10001, 64<<20+1); err != nil {
		t.Fatalf("large source facts rejected: %v", err)
	}
}

func TestMoreThanLegacyMaximumFileCountGitComparisonIsViewableAndPublishable(t *testing.T) {
	const fileCount = 10001
	files := make([]WorkspaceSnapshotFile, fileCount)
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
	if got := len(view.Files()); got != 2*fileCount+1 {
		t.Fatalf("provider comparison file count = %d, want %d", got, 2*fileCount+1)
	}
	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Manifest()) == 0 {
		t.Fatal("large capture manifest is empty")
	}
}
