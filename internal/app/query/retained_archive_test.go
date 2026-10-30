package query

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"github.com/irootkernel/mulgae/internal/testsupport/historical"
)

// Only the two empty-file patch inputs used by queryRuntimeFixtureWithOptions
// need synthetic v1 bytes. This is not a general archive writer or authority.
func queryLegacyArchiveFixture(t *testing.T, material ports.CapturedReviewMaterial) ([]byte, error) {
	t.Helper()
	identity := material.Target().Identity()
	head, present := material.Evidence().Files(ports.CapturedEvidenceHead)
	if identity.Kind() != domain.TargetPatch || len(material.Snapshot().Files()) != 0 || material.HasProjectContext() || !present || len(head) != 0 {
		t.Fatal("legacy query fixture requires its explicit empty-file patch input")
	}
	return json.Marshal(map[string]any{
		"schema_version":  "mulgae-captured-review-archive.v1",
		"target_identity": map[string]any{"kind": "patch", "sha256": identity.SHA256(), "repository_id": "", "base_object_id": "", "head_object_id": "", "head_tree_object_id": "", "index_tree_object_id": "", "git_mode": ""},
		"target_bytes":    material.Target().Bytes(), "snapshot_policy": material.Snapshot().PolicyIdentity(), "snapshot": []any{},
		"project_context": []byte(nil), "has_project_context": false,
		"evidence": []any{map[string]any{"side": "head", "files": []any{}}},
	})
}

// The expected digests predate this test (TASK-060 corpus). They are not
// calculated by an encoder under test or by a retired publication constructor.
func TestRuntimeTargetReconstructsFrozenArchive(t *testing.T) {
	corpus, err := historical.Load()
	if err != nil {
		t.Fatal(err)
	}
	validator := mustSharedQueryTestValidator(t)
	seen := 0
	for _, c := range corpus.Cases {
		if c.ID != "ordinary-v2" && c.ID != "ordinary-v1-nonminified" && c.ID != "composite-copied-v1" && c.ID != "composite-copied-v2" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			store, run := historicalQueryStore(t, c)
			service := mustQueryService(t, store, validator, nil)
			got, err := service.ReadRuntimeTarget(context.Background(), run)
			if err != nil {
				t.Fatal(err)
			}
			raw := got.CapturedArchive()
			if querySHA(raw) != c.Expected.ArchiveSHA256 {
				t.Fatal("actual retained reconstruction differs from independent frozen digest")
			}
			if c.ID == "ordinary-v1-nonminified" {
				want := c.Artifacts()[c.SessionID+"/"+c.RunID+"/target/captured-review.json"]
				if !bytes.Equal(raw, want) || !bytes.Contains(raw, []byte("\n  ")) {
					t.Fatal("v1 exact representation changed")
				}
			}
			material, err := ports.UnmarshalCapturedReviewMaterial(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !material.Valid() {
				t.Fatal("reconstructed archive is not admitted material")
			}
			// Getter copy isolation must not alter the next actual reconstruction.
			raw[0] ^= 1
			again, err := service.ReadRuntimeTarget(context.Background(), run)
			if err != nil || querySHA(again.CapturedArchive()) != c.Expected.ArchiveSHA256 {
				t.Fatalf("reconstruction lost byte ownership: %v", err)
			}
		})
		seen++
	}
	if seen != 4 {
		t.Fatalf("archive cases=%d, want 4", seen)
	}
}
