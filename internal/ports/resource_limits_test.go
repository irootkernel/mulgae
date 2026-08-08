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
	if files, bytes := WorkspaceAdmissionLimits("capture-policy"); files != WorkspaceSnapshotMaxFiles || bytes != WorkspaceSnapshotMaxBytes {
		t.Fatalf("capture request limits = %d/%d", files, bytes)
	}
	if files, bytes := WorkspaceAdmissionLimits("capture-policy;layout=ordinary-directories-v1"); files != WorkspaceProviderViewMaxFiles || bytes != WorkspaceProviderViewMaxBytes {
		t.Fatalf("provider view limits = %d/%d", files, bytes)
	}
}

func TestWorkspaceAdmissionReportsSnapshotAndProviderViewLimits(t *testing.T) {
	tests := []struct {
		name, policy, member, stage string
		files                       int
		bytes                       int64
		maxFiles                    int
		maxBytes                    int64
	}{
		{
			name: "captured side bytes", policy: "capture-policy", member: "base", stage: "capture_side",
			files: WorkspaceSnapshotMaxFiles, bytes: WorkspaceSnapshotMaxBytes + 1,
			maxFiles: WorkspaceSnapshotMaxFiles, maxBytes: WorkspaceSnapshotMaxBytes,
		},
		{
			name: "captured side files", policy: "capture-policy", member: "index", stage: "capture_side",
			files: WorkspaceSnapshotMaxFiles + 1, bytes: WorkspaceSnapshotMaxBytes,
			maxFiles: WorkspaceSnapshotMaxFiles, maxBytes: WorkspaceSnapshotMaxBytes,
		},
		{
			name: "provider view bytes", policy: "capture-policy;layout=ordinary-directories-v1", member: "combined", stage: "provider_view",
			files: WorkspaceProviderViewMaxFiles, bytes: WorkspaceProviderViewMaxBytes + 1,
			maxFiles: WorkspaceProviderViewMaxFiles, maxBytes: WorkspaceProviderViewMaxBytes,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateWorkspaceAdmission(test.policy, test.member, test.files, test.bytes)
			failure, ok := WorkspaceAdmissionFailureFromError(err)
			if !ok || failure.Stage() != test.stage || failure.Member() != test.member ||
				failure.FileCount() != test.files || failure.ByteCount() != test.bytes ||
				failure.MaxFiles() != test.maxFiles || failure.MaxBytes() != test.maxBytes {
				t.Fatalf("workspace admission failure = %#v, present=%t", failure, ok)
			}
		})
	}
	if err := ValidateWorkspaceAdmission("capture-policy", "current", WorkspaceSnapshotMaxFiles, WorkspaceSnapshotMaxBytes); err != nil {
		t.Fatalf("boundary admission: %v", err)
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
