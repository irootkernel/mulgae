package ports

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

func TestRestoreArchiveUsesFixedLegacyV1Input(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v1-nonminified" {
			continue
		}
		raw := c.Artifacts()[c.SessionID+"/"+c.RunID+"/target/captured-review.json"]
		refs, err := CapturedReviewArchiveBlobReferences(raw)
		if err != nil || len(refs) != 0 {
			t.Fatalf("legacy references: %v", err)
		}
		restored, err := RestoreCapturedReviewArchive(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if restored.Target().Identity().Kind() != domain.TargetPatch || restored.Target().Identity().SHA256() != "cfd126680b3411bb472378d2dc0177b6faf13ed46da4d50176f57408e4ad3d2c" || !bytes.Equal(restored.Target().Bytes(), []byte("reviewed line\n")) || restored.Snapshot().PolicyIdentity() != "historical-corpus-synthetic-v1" || restored.HasProjectContext() {
			t.Fatal("fixed v1 target/context changed")
		}
		files, present := restored.Evidence().Files(CapturedEvidenceHead)
		if !present || len(files) != 1 || files[0].Path().String() != "internal/app/review.go" || !bytes.Equal(files[0].Bytes(), []byte("reviewed line\n")) {
			t.Fatal("fixed v1 evidence changed")
		}
		return
	}
	t.Fatal("fixed legacy input absent")
}

func TestCapturedArchiveLargeContentUsesOneRetainedBlob(t *testing.T) {
	contents := bytes.Repeat([]byte("x"), 1<<20)
	digest := sha256Identifier(contents)
	files := make([]WorkspaceSnapshotFile, 8)
	for index := range files {
		path, err := NewSafeRelativePath(fmt.Sprintf("fixtures/copy-%02d.bin", index))
		if err != nil {
			t.Fatal(err)
		}
		files[index], err = NewWorkspaceSnapshotFile(path, contents, digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := NewWorkspaceSnapshotRequest(files, "large-dedup-policy")
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewCapturedReviewPatchTarget([]byte("patch\n"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewCapturedTargetEvidence(map[CapturedEvidenceSide][]WorkspaceSnapshotFile{CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}

	archive, err := NewCapturedReviewArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.Manifest()) >= 1<<20 {
		t.Fatalf("reference-only manifest size = %d", len(archive.Manifest()))
	}
	if got := len(archive.Blobs()); got != 2 {
		t.Fatalf("deduplicated blob count = %d, want target plus one shared blob", got)
	}
	bundle, err := MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) >= 2<<20 || bytes.Contains(bundle, []byte("eHh4eHh4")) {
		t.Fatalf("deduplicated transport bundle size = %d", len(bundle))
	}
	if _, err := RestoreCapturedReviewArchive(archive.Manifest(), archive.Blobs()); err != nil {
		t.Fatal(err)
	}
}
