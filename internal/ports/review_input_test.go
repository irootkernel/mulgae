package ports

import "testing"

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
