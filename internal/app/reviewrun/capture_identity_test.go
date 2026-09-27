package reviewrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func captureContractMaterial(t *testing.T, support, policy, context string, contextPresent bool) ports.CapturedReviewMaterial {
	t.Helper()
	oid, err := ports.ParseGitObjectID(strings.Repeat("1", 40))
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewGitTarget("local-repository", oid, oid, oid, nil, []byte("unchanged patch bytes\n"))
	if err != nil {
		t.Fatal(err)
	}
	files := []ports.WorkspaceSnapshotFile{}
	for _, item := range []struct {
		path   string
		data   []byte
		binary bool
	}{{"empty.txt", nil, false}, {"image.png", []byte("\x89PNG\r\n\x1a\n"), true}, {"support.txt", []byte(support), false}} {
		path, pathErr := ports.NewSafeRelativePath(item.path)
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		var file ports.WorkspaceSnapshotFile
		if item.binary {
			file, err = ports.NewWorkspaceVisualAsset(path, item.data, identitySHA256(item.data), "image/png")
		} else {
			file, err = ports.NewWorkspaceSnapshotFile(path, item.data, identitySHA256(item.data))
		}
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, policy)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceBase: files, ports.CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, []byte(context), contextPresent, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func TestCaptureIdentitySeparatesCompleteSupportFromPatchAndRequest(t *testing.T) {
	base := captureContractMaterial(t, "original", "test-policy", "", false)
	manifest, err := NewCaptureManifest(base)
	if err != nil {
		t.Fatal(err)
	}
	id, err := manifest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string]ports.CapturedReviewMaterial{
		"support":                captureContractMaterial(t, "changed", "test-policy", "", false),
		"policy":                 captureContractMaterial(t, "original", "other-policy", "", false),
		"context":                captureContractMaterial(t, "original", "test-policy", "context", true),
		"explicit empty context": captureContractMaterial(t, "original", "test-policy", "", true),
	} {
		t.Run(name, func(t *testing.T) {
			if other.Target().Identity().SHA256() != base.Target().Identity().SHA256() {
				t.Fatal("test did not preserve patch identity")
			}
			got, err := NewCaptureManifest(other)
			if err != nil {
				t.Fatal(err)
			}
			gotID, err := got.Identity()
			if err != nil || gotID == id {
				t.Fatalf("capture collision: %v", err)
			}
		})
	}
	data, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(base)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCaptureManifest(data, restored, id); err != nil {
		t.Fatalf("restart verification: %v", err)
	}
	if err := VerifyCaptureManifest(data, captureContractMaterial(t, "changed", "test-policy", "", false), id); err == nil {
		t.Fatal("changed retained support accepted")
	}
	if bytes.Contains(data, []byte("local-repository")) {
		t.Fatal("local repository identity entered portable capture")
	}
}

func TestCaptureManifestRejectsMalformedOrIncompleteSupport(t *testing.T) {
	manifest, err := NewCaptureManifest(captureContractMaterial(t, "support", "policy", "", false))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CaptureManifest){
		"stage without index tree": func(m *CaptureManifest) {
			m.Target.GitMode = "stage"
			m.Target.IndexTreeObjectID = ""
			m.Sides = []string{"base", "head", "index", "snapshot"}
		},
		"invalid path UTF-8":         func(m *CaptureManifest) { m.Files[0].Path = "invalid\xff" },
		"missing side":               func(m *CaptureManifest) { m.Sides = []string{"head", "snapshot"} },
		"duplicate side":             func(m *CaptureManifest) { m.Sides = append(m.Sides, "snapshot") },
		"duplicate file":             func(m *CaptureManifest) { m.Files = append(m.Files, m.Files[0]) },
		"foreign side":               func(m *CaptureManifest) { m.Files[0].Side = "worktree" },
		"path traversal":             func(m *CaptureManifest) { m.Files[0].Path = "../secret" },
		"negative size":              func(m *CaptureManifest) { m.Files[0].Size = -1 },
		"empty digest mismatch":      func(m *CaptureManifest) { m.Files[0].SHA256 = identitySHA256([]byte("not empty")) },
		"invalid binary":             func(m *CaptureManifest) { m.Files[1].Disposition = "text" },
		"missing policy":             func(m *CaptureManifest) { m.PolicyIdentity = "" },
		"unknown version":            func(m *CaptureManifest) { m.SchemaVersion = "future" },
		"missing git mode":           func(m *CaptureManifest) { m.Target.GitMode = "" },
		"absent context with digest": func(m *CaptureManifest) { m.Context.SHA256 = identitySHA256(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate CaptureManifest
			if err := json.Unmarshal(encoded, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			if _, err := candidate.Identity(); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	for _, data := range [][]byte{append(append([]byte(nil), encoded...), []byte("{}")...), bytes.Replace(encoded, []byte(`"schema_version":`), []byte(`"unknown":0,"schema_version":`), 1), bytes.Replace(encoded, []byte(`"schema_version":`), []byte(`"schema_version":"ignored","schema_version":`), 1)} {
		if _, err := DecodeCaptureManifest(data); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestCaptureManifestDistinguishesLogicalSidesAndHistoricalAbsence(t *testing.T) {
	material := captureContractMaterial(t, "support", "policy", "", false)
	manifest, err := NewCaptureManifest(material)
	if err != nil {
		t.Fatal(err)
	}
	original, err := manifest.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Preserve target bytes while changing the captured comparison to an index.
	target := material.Target()
	oid, _ := target.HeadObjectID()
	tree, _ := target.HeadTreeID()
	stage, err := ports.NewCapturedReviewGitTargetWithMode(domain.GitTargetStage, "local-repository", oid, oid, tree, &tree, target.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceBase: material.Snapshot().Files(), ports.CapturedEvidenceIndex: material.Snapshot().Files()})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := ports.NewCapturedReviewMaterialWithEvidence(stage, material.Snapshot(), nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := NewCaptureManifest(staged)
	if err != nil {
		t.Fatal(err)
	}
	changedID, err := changed.Identity()
	if err != nil || changedID == original {
		t.Fatalf("logical sides were lost: %v", err)
	}
	emptyTarget, err := ports.NewCapturedReviewGitTarget("local-repository", oid, oid, tree, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ports.NewCapturedReviewMaterial(emptyTarget, material.Snapshot(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCaptureManifest(legacy); !errors.Is(err, ErrCaptureIdentityUnavailable) {
		t.Fatalf("legacy incomplete capture = %v", err)
	}
	complete, err := ports.NewCapturedReviewMaterialWithEvidence(emptyTarget, material.Snapshot(), nil, material.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCaptureManifest(complete); err != nil {
		t.Fatalf("new complete no-change capture = %v", err)
	}
}
