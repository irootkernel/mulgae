package export

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func liveExportProjection(t *testing.T, data []byte, mediaType, path string) VerifiedSourceProjection {
	t.Helper()
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, nil)
	identity, err := evidence.NewLiveSourceIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	source := validProjection()
	source.Review.SchemaVersion, source.Run.SchemaVersion = "mulgae-review-artifact.v3", "mulgae-run-manifest.v3"
	source.SchemaVersions = []string{source.Review.SchemaVersion, source.Run.SchemaVersion}
	source.SourceIdentity = SourceIdentity{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID, FindingID: source.Findings[0].ID, SourceIdentitySHA256: identity.SHA256(), SourceExcerptSHA256: source.Evidence[0].SourceExcerptSHA256}
	source.CurrentIdentity.TargetSHA256, source.CurrentIdentity.SourceIdentitySHA256 = "", identity.SHA256()
	source.CurrentIdentity.Side = "worktree"
	source.Evidence[0].SourceTargetSHA256, source.Evidence[0].TargetSHA256, source.Evidence[0].SourceIdentitySHA256 = "", "", identity.SHA256()
	source.Evidence[0].SourceSessionID, source.Evidence[0].SourceRunID, source.Evidence[0].SourceReviewID = source.SessionID, source.RunID, source.ReviewID
	source.Evidence[0].SourceFindingID, source.Evidence[0].Side = source.Findings[0].ID, "worktree"
	source.LiveSource = &evidence.LiveSourceRead{Identity: identity, Consistency: "caller_maintained"}
	if data != nil {
		safePath, _ := ports.NewSafeRelativePath(path)
		file, err := ports.NewLiveSourceFile(safePath, data, mediaType)
		if err != nil {
			t.Fatal(err)
		}
		source.LiveSource.BinaryEvidence = []evidence.LiveBinaryObservation{{Side: "worktree", Path: path, SHA256: file.SHA256(), MediaType: mediaType, ByteLength: len(data)}}
		source.BinaryEvidence = []BinaryEvidence{{Side: "worktree", Path: path, SHA256: file.SHA256(), MediaType: mediaType, Bytes: file.Bytes()}}
	}
	return source
}

func TestLiveExportRetainsSelectedRasterBytesAndExplicitSourceIdentity(t *testing.T) {
	for _, test := range []struct {
		name, media, path string
		data              []byte
	}{
		{"png", "image/png", "diagram.png", []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}},
		{"jpeg", "image/jpeg", "diagram.jpg", []byte{255, 216, 255, 224, 0}},
		{"webp", "image/webp", "diagram.webp", []byte("RIFF\x04\x00\x00\x00WEBP")},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := liveExportProjection(t, test.data, test.media, test.path)
			bundle, manifest, err := BuildRedactedBundle(source, validOptions())
			if err != nil {
				t.Fatal(err)
			}
			if manifest.SchemaVersion != liveManifestSchemaVersion || manifest.SourceIdentity.SourceTargetSHA256 != "" || manifest.CurrentIdentity.TargetSHA256 != "" || manifest.SourceIdentity.SourceIdentitySHA256 != source.LiveSource.Identity.SHA256() {
				t.Fatal("live export claimed immutable source contents")
			}
			reader, err := zip.NewReader(bytes.NewReader(bundle.Bytes), int64(len(bundle.Bytes)))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, file := range reader.File {
				if file.Name != imageMemberPath(source.BinaryEvidence[0]) {
					continue
				}
				body, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(body)
				body.Close()
				if err != nil || !bytes.Equal(data, test.data) {
					t.Fatal("export changed binary observation")
				}
				found = true
			}
			if !found {
				t.Fatal("export omitted selected image")
			}
			var exported []Evidence
			decodeBundleMember(t, bundle, "evidence.json", &exported)
			if exported[0].TargetSHA256 != "" || exported[0].SourceTargetSHA256 != "" || exported[0].SourceIdentitySHA256 != source.LiveSource.Identity.SHA256() {
				t.Fatal("export changed evidence identity meaning")
			}
			wire, _ := json.Marshal(exported)
			if bytes.Contains(wire, []byte("target_sha256")) {
				t.Fatal("live evidence emitted captured fields")
			}
		})
	}
}

func TestLiveExportRejectsMixedIdentityMissingImagesAndTamperedBytes(t *testing.T) {
	for name, mutate := range map[string]func(*VerifiedSourceProjection){
		"old source":     func(s *VerifiedSourceProjection) { s.SourceIdentity.SourceTargetSHA256 = testHash("a") },
		"old current":    func(s *VerifiedSourceProjection) { s.CurrentIdentity.TargetSHA256 = testHash("a") },
		"old evidence":   func(s *VerifiedSourceProjection) { s.Evidence[0].TargetSHA256 = testHash("a") },
		"mixed versions": func(s *VerifiedSourceProjection) { s.Run.SchemaVersion = "mulgae-run-manifest.v1" },
		"missing binary": func(s *VerifiedSourceProjection) { s.BinaryEvidence = nil },
		"changed binary": func(s *VerifiedSourceProjection) { s.BinaryEvidence[0].Bytes = append(s.BinaryEvidence[0].Bytes, 1) },
		"wrong side":     func(s *VerifiedSourceProjection) { s.BinaryEvidence[0].Side = "index" },
	} {
		t.Run(name, func(t *testing.T) {
			source := liveExportProjection(t, []byte{137, 80, 78, 71, 13, 10, 26, 10, 0}, "image/png", "diagram.png")
			mutate(&source)
			if _, _, err := BuildRedactedBundle(source, validOptions()); !errors.Is(err, ErrMalformedProjection) {
				t.Fatalf("invalid projection: %v", err)
			}
		})
	}
}

func TestLiveExportRejectsSecretsAndAbsolutePathsInsideRasterBytes(t *testing.T) {
	for name, payload := range map[string]string{
		"credential":  " api_key=synthetic-test-secret",
		"native path": " /private/fixture/source.png",
	} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte{137, 80, 78, 71, 13, 10, 26, 10, 0}, []byte(payload)...)
			source := liveExportProjection(t, data, "image/png", "diagram.png")
			if err := validateProjection(source, validOptions()); err != nil {
				t.Fatalf("fixture must reach content scanning: %v", err)
			}
			if _, _, err := BuildRedactedBundle(source, validOptions()); !errors.Is(err, ErrSecretDetected) {
				t.Fatalf("unsafe raster export: %v", err)
			}
		})
	}
}
