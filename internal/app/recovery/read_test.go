package recovery

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestReadRecoveryVerifiesSchemaBlobsAndStableManifest(t *testing.T) {
	document, source, validator, run := recoveryReadFixture(t)
	ctx := context.Background()
	manifestPath, err := ManifestPath(run)
	if err != nil {
		t.Fatal(err)
	}
	manifest := source.artifacts[manifestPath.String()]
	snapshot, err := Read(ctx, source, validator, run, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Status().Available || source.reads != len(document.Blobs())+2 {
		t.Fatal("reader skipped source validation")
	}
	t.Run("manifest changes before confirmation", func(t *testing.T) {
		source.reads = 0
		source.onRead = func() {
			if source.reads == len(document.Blobs())+2 {
				source.artifacts[manifestPath.String()] = append(append([]byte(nil), manifest...), '\n')
			}
		}
		if _, err := Read(ctx, source, validator, run, 8<<20); err == nil {
			t.Fatal("changed manifest was accepted")
		}
		source.onRead = nil
		source.artifacts[manifestPath.String()] = manifest
	})
	t.Run("missing blob is not absent source", func(t *testing.T) {
		path, err := BlobPath(run, document.Target.CapturedArchive)
		if err != nil {
			t.Fatal(err)
		}
		original := source.artifacts[path.String()]
		delete(source.artifacts, path.String())
		_, err = Read(ctx, source, validator, run, 8<<20)
		if err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatalf("missing blob lost fail-closed distinction: %v", err)
		}
		source.artifacts[path.String()] = original
	})
	t.Run("absent manifest", func(t *testing.T) {
		delete(source.artifacts, manifestPath.String())
		if _, err := Read(ctx, source, validator, run, 8<<20); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("absent source: %v", err)
		}
	})
}

type recoveryReadStore struct {
	artifacts map[string][]byte
	reads     int
	onRead    func()
}

func (*recoveryReadStore) PersistAuxiliaryArtifact(context.Context, ports.PersistAuxiliaryArtifactRequest) (ports.PersistAuxiliaryArtifactResult, error) {
	return ports.PersistAuxiliaryArtifactResult{}, errors.New("unexpected write")
}
func (store *recoveryReadStore) ReadAuxiliaryArtifact(_ context.Context, request ports.ReadAuxiliaryArtifactRequest) (ports.ImmutablePublicationArtifact, error) {
	store.reads++
	if store.onRead != nil {
		store.onRead()
	}
	raw, ok := store.artifacts[request.Path().String()]
	if !ok {
		return ports.ImmutablePublicationArtifact{}, fs.ErrNotExist
	}
	return ports.NewImmutablePublicationArtifact(request.Path(), Digest(raw), raw)
}

func recoveryReadFixture(t *testing.T) (Document, *recoveryReadStore, SchemaValidator, ports.PublicationRun) {
	t.Helper()
	ctx := context.Background()
	validator, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	document, blobs := recoveryFixture(t)
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, err := domain.ParseSessionID(document.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID(document.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, session, runID)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := ManifestPath(run)
	if err != nil {
		t.Fatal(err)
	}
	manifest := recoveryJSON(t, document)
	source := &recoveryReadStore{artifacts: map[string][]byte{manifestPath.String(): manifest}}
	for _, blob := range document.Blobs() {
		path, err := BlobPath(run, blob)
		if err != nil {
			t.Fatal(err)
		}
		source.artifacts[path.String()] = blobs[blob.SHA256]
	}
	return document, source, validator, run
}

func TestReadRetentionMetadataNeverReadsBlobs(t *testing.T) {
	document, source, validator, run := recoveryReadFixture(t)
	path, err := ManifestPath(run)
	if err != nil {
		t.Fatal(err)
	}
	// No blobs exist in this store. Retention must not materialize them.
	source.artifacts = map[string][]byte{path.String(): recoveryJSON(t, document)}
	metadata, err := ReadRetentionMetadata(context.Background(), source, validator, run, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, hasParent := metadata.Parent(); hasParent || metadata.Manifest().Path() != path || metadata.Manifest().SHA256() != Digest(source.artifacts[path.String()]) || source.reads != 2 {
		t.Fatal("retention metadata lost manifest identity or read source content")
	}
	if _, err := Read(context.Background(), source, validator, run, 8<<20); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("retention metadata authorized replay without blobs: %v", err)
	}

	document.RunType = domain.RunTypeRerun
	document.Roles = document.Roles[1:]
	document.Attempts = document.Attempts[1:]
	parent := "r_019f5a09-5eec-7001-8001-000000000012"
	review := "019f5a09-5eec-7001-8001-000000000013"
	document.Source = &Source{Kind: "published_review", RunID: parent, ReviewID: &review, AttemptID: document.Attempts[0].AttemptID, ReplayMode: "exact"}
	source.artifacts[path.String()] = recoveryJSON(t, document)
	source.reads = 0
	metadata, err = ReadRetentionMetadata(context.Background(), source, validator, run, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if reference, ok := metadata.Parent(); !ok || reference.RunID().String() != parent || reference.ReviewID().String() != review || source.reads != 2 {
		t.Fatal("retention metadata lost published parent")
	}
}

func TestReadRetentionMetadataRejectsInvalidOrChangingManifest(t *testing.T) {
	cases := map[string]func(*Document){
		"run identity":    func(d *Document) { d.RunID = "r_019f5a09-5eec-7001-8001-000000000099" },
		"role binding":    func(d *Document) { d.Attempts[0].ProviderInstance = "different" },
		"missing attempt": func(d *Document) { d.Attempts = d.Attempts[:1] },
		"source identity": func(d *Document) { d.Source = &Source{Kind: "failed_run_recovery", RunID: d.RunID} },
		"parent identity": func(d *Document) {
			d.RunType = domain.RunTypeRerun
			d.Roles, d.Attempts = d.Roles[1:], d.Attempts[1:]
			review := "019f5a09-5eec-7001-8001-000000000013"
			d.Source = &Source{Kind: "published_review", RunID: "invalid", ReviewID: &review, AttemptID: d.Attempts[0].AttemptID, ReplayMode: "exact"}
		},
		"blob lengths": func(d *Document) {
			d.Attempts[0].InitialPrompt.Stdin = d.Target.Bytes
			d.Attempts[0].InitialPrompt.Stdin.ByteLength++
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document, source, validator, run := recoveryReadFixture(t)
			mutate(&document)
			path, _ := ManifestPath(run)
			source.artifacts[path.String()] = recoveryJSON(t, document)
			if _, err := ReadRetentionMetadata(context.Background(), source, validator, run, 8<<20); err == nil || errors.Is(err, ErrUnavailable) {
				t.Fatalf("invalid metadata accepted or treated as absent: %v", err)
			}
			if source.reads != 1 {
				t.Fatalf("invalid metadata performed further reads: %d", source.reads)
			}
		})
	}
	for _, change := range []string{"absent", "noncanonical", "oversized", "changed", "disappeared"} {
		t.Run(change, func(t *testing.T) {
			_, source, validator, run := recoveryReadFixture(t)
			path, _ := ManifestPath(run)
			maximum := int64(8 << 20)
			switch change {
			case "absent":
				delete(source.artifacts, path.String())
			case "noncanonical":
				source.artifacts[path.String()] = append(source.artifacts[path.String()], '\n')
			case "oversized":
				maximum = 1
			default:
				source.onRead = func() {
					if source.reads == 2 {
						if change == "changed" {
							source.artifacts[path.String()] = append(source.artifacts[path.String()], '\n')
						} else {
							delete(source.artifacts, path.String())
						}
					}
				}
			}
			_, err := ReadRetentionMetadata(context.Background(), source, validator, run, maximum)
			if err == nil || errors.Is(err, ErrUnavailable) != (change == "absent") {
				t.Fatalf("manifest failure lost distinction: %v", err)
			}
			if source.reads > 2 {
				t.Fatal("metadata read accessed blobs")
			}
		})
	}
}

func TestReadRecoveryStopsWhenCancelledAfterBlobRead(t *testing.T) {
	document, source, validator, run := recoveryReadFixture(t)
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := Read(cancelled, source, validator, run, 8<<20); !errors.Is(err, context.Canceled) || source.reads != 0 {
		t.Fatalf("already cancelled read touched the store or lost cancellation: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source.onRead = func() {
		if source.reads == len(document.Blobs())+1 {
			cancel()
		}
	}
	if _, err := Read(ctx, source, validator, run, 8<<20); !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery validation lost cancellation: %v", err)
	}
	if source.reads != len(document.Blobs())+1 {
		t.Fatal("cancelled recovery reached manifest confirmation")
	}
}

func TestRecoveryArchiveReaderRejectsNonTextEvidence(t *testing.T) {
	for _, kind := range []string{"text", "binary", "png"} {
		t.Run(kind, func(t *testing.T) {
			path, _ := ports.NewSafeRelativePath("source." + kind)
			raw := []byte("line evidence\n")
			var file ports.WorkspaceSnapshotFile
			var err error
			switch kind {
			case "text":
				file, err = ports.NewWorkspaceSnapshotFile(path, raw, Digest(raw))
			case "binary":
				file, err = ports.NewWorkspaceBinaryFile(path, raw, Digest(raw))
			case "png":
				raw = append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, raw...)
				file, err = ports.NewWorkspaceVisualAsset(path, raw, Digest(raw), "image/png")
			}
			if err != nil {
				t.Fatal(err)
			}
			target, err := ports.NewCapturedReviewPatchTarget([]byte("target"))
			if err != nil {
				t.Fatal(err)
			}
			request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
			if err != nil {
				t.Fatal(err)
			}
			captured, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: {file}})
			if err != nil {
				t.Fatal(err)
			}
			archive, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, captured)
			if err != nil {
				t.Fatal(err)
			}
			reader := archiveReader{archive: archive, target: "target"}
			availability, got, err := reader.ReadImmutableTarget(context.Background(), "target", evidence.Side("head"), path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "text" {
				if availability != evidence.ImmutableTargetAvailable || !bytes.Equal(got, raw) {
					t.Fatal("text evidence unavailable")
				}
			} else if availability != evidence.ImmutableTargetUnavailable || got != nil {
				t.Fatal("non-text content exposed as line evidence")
			}
		})
	}
}

func TestReadRecoveryAcceptsAllSeverityValues(t *testing.T) {
	for _, severity := range []domain.Severity{domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityBlocker} {
		t.Run(string(severity), func(t *testing.T) {
			document, source, validator, run := recoveryReadFixture(t)
			document.Threshold = severity
			target, err := ports.NewCapturedReviewPatchTarget([]byte("immutable target"))
			if err != nil {
				t.Fatal(err)
			}
			path, _ := ports.NewSafeRelativePath("source.go")
			raw := []byte("line evidence")
			file, err := ports.NewWorkspaceSnapshotFile(path, raw, Digest(raw))
			if err != nil {
				t.Fatal(err)
			}
			request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
			if err != nil {
				t.Fatal(err)
			}
			captured, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: {file}})
			if err != nil {
				t.Fatal(err)
			}
			material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, captured)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := ports.MarshalCapturedReviewMaterial(material)
			if err != nil {
				t.Fatal(err)
			}
			blobs := map[string][]byte{}
			document.Target.CapturedArchive = AddBlob(blobs, archive)
			blobPath, err := BlobPath(run, document.Target.CapturedArchive)
			if err != nil {
				t.Fatal(err)
			}
			source.artifacts[blobPath.String()] = archive
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: document.Target.SHA256, Side: evidence.SideHead, Path: path.String(), LineStart: 1, LineEnd: 1, Quote: string(raw)})
			if err != nil {
				t.Fatal(err)
			}
			excerptHash, err := claim.ExcerptSHA256(raw)
			if err != nil {
				t.Fatal(err)
			}
			document.Roles[0].FindingIDs = []string{"F001"}
			document.Findings = []Finding{{ID: "F001", Fingerprint: Digest([]byte("finding")), Role: document.Roles[0].Role, ProviderInstance: document.Roles[0].ProviderInstance, Severity: severity, Title: "Finding", Description: "Verified finding", Recommendation: "Fix finding", Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen, Evidence: []Evidence{{TargetSHA256: document.Target.SHA256, Side: evidence.Side("head"), Path: path.String(), LineStart: 1, LineEnd: 1, Quote: string(raw), ExcerptSHA256: excerptHash}}}}
			manifestPath, err := ManifestPath(run)
			if err != nil {
				t.Fatal(err)
			}
			source.artifacts[manifestPath.String()] = recoveryJSON(t, document)
			snapshot, err := Read(context.Background(), source, validator, run, 8<<20)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Document().Threshold != severity || snapshot.Document().Findings[0].Severity != severity {
				t.Fatal("severity changed during recovery")
			}
		})
	}
}
