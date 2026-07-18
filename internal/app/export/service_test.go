package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

func TestBuildRedactedBundleDeterministicAndRedacted(t *testing.T) {
	source := validProjection()
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	options := validOptions()
	first, manifest, err := BuildRedactedBundle(source, options)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := BuildRedactedBundle(source, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes, second.Bytes) {
		t.Fatal("bundle bytes differ for identical inputs")
	}
	after, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("source projection was mutated")
	}
	if manifest.Bundle.SHA256 != digest(first.Bytes) || manifest.Bundle.SizeBytes != int64(len(first.Bytes)) || manifest.Bundle.MemberCount != len(first.Members) {
		t.Fatal("bundle manifest does not match finished bundle")
	}
	if len(first.Members) != 6 {
		t.Fatalf("member count = %d", len(first.Members))
	}
	reader, err := zip.NewReader(bytes.NewReader(first.Bytes), int64(len(first.Bytes)))
	if err != nil {
		t.Fatal(err)
	}
	for index, file := range reader.File {
		if file.Name != first.Members[index].Path || !canonicalPathPattern.MatchString(file.Name) {
			t.Fatalf("unsafe or unordered member %q", file.Name)
		}
	}
	contents := string(first.Bytes)
	if bytes.Contains([]byte(contents), []byte("/Users/alice/private")) {
		t.Fatal("absolute path was retained")
	}
	if !bytes.Contains([]byte(contents), []byte("[redacted-path]")) {
		t.Fatal("absolute path was not redacted")
	}
	issued, err := ports.NewSecureWriteReceipt(testRoot(t), testBundlePath(t), digest(first.Bytes), int64(len(first.Bytes)), "export_bundle", []string{source.RunID, source.ReviewID})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = BindManifestToBundleReceipt(manifest, issued)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifestBytes, []byte("raw_provider_output")) {
		t.Fatal("sidecar unexpectedly embeds bundle contents")
	}
}

func TestBuildRedactedBundleRejectsMalformedAndSecretInput(t *testing.T) {
	source := validProjection()
	source.RunManifest.ArtifactPath = "../manifest.json"
	if _, _, err := BuildRedactedBundle(source, validOptions()); !errors.Is(err, ErrMalformedProjection) {
		t.Fatalf("malformed path error = %v", err)
	}
	source = validProjection()
	source.Findings[0].Description = "token=top-secret-value"
	_, _, err := BuildRedactedBundle(source, validOptions())
	var failure *domain.Failure
	if !errors.Is(err, ErrSecretDetected) || !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy {
		t.Fatalf("secret error = %v, failure = %#v", err, failure)
	}
}

func validProjection() VerifiedSourceProjection {
	return VerifiedSourceProjection{
		SessionID: "s_018f0d1a-0000-7000-8000-000000000001", RunID: "r_018f0d1a-0000-7000-8000-000000000002", ReviewID: "018f0d1a-0000-7000-8000-000000000003",
		RunManifest: ImmutableArtifactRef{ArtifactPath: "runs/run-manifest.json", SHA256: testHash("a")}, ReviewArtifact: ImmutableArtifactRef{ArtifactPath: "reviews/review.json", SHA256: testHash("b")},
		SchemaVersions: []string{"kar-review-artifact.v2", "kar-run-manifest.v2"}, Review: Review{SchemaVersion: "kar-review-artifact.v2", ContentVerdict: "findings"}, Run: Run{SchemaVersion: "kar-run-manifest.v2", State: "completed"},
		Findings:        []Finding{{ID: "FINDING_1", Fingerprint: testHash("c"), Role: "security", Severity: "high", Title: "Path leak", Description: "seen at /Users/alice/private/file.go", Recommendation: "remove it", Confidence: "high", Lifecycle: "open"}},
		Evidence:        []Evidence{{FindingID: "FINDING_1", SourceSessionID: "s_018f0d1a-0000-7000-8000-000000000001", SourceRunID: "r_018f0d1a-0000-7000-8000-000000000002", SourceReviewID: "018f0d1a-0000-7000-8000-000000000003", SourceFindingID: "FINDING_1", SourceTargetSHA256: testHash("d"), SourceExcerptSHA256: testHash("e"), TargetSHA256: testHash("f"), Path: "internal/app/export/model.go", Side: "head", LineStart: 1, LineEnd: 2, Verification: "verified"}},
		Redaction:       RedactionManifest{Policy: "redacted_export"},
		SourceIdentity:  SourceIdentity{SessionID: "s_018f0d1a-0000-7000-8000-000000000001", RunID: "r_018f0d1a-0000-7000-8000-000000000002", ReviewID: "018f0d1a-0000-7000-8000-000000000003", FindingID: "FINDING_1", SourceTargetSHA256: testHash("d"), SourceExcerptSHA256: testHash("e")},
		CurrentIdentity: CurrentIdentity{TargetSHA256: testHash("f"), Path: "internal/app/export/model.go", Side: "head", LineStart: 1, LineEnd: 2, Verification: "verified"},
	}
}

func validOptions() BuildOptions {
	return BuildOptions{ExportID: "x_018f0d1a-0000-7000-8000-000000000004", CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)}
}
func testHash(character string) string {
	return "sha256:" + string(bytes.Repeat([]byte(character), 64))
}

type exportReader struct {
	source VerifiedSourceProjection
	err    error
}

func (reader exportReader) ReadCommittedProjection(context.Context, ExportSource) (VerifiedSourceProjection, error) {
	return reader.source, reader.err
}

type exportWriter struct {
	ensureErr error
	writeErr  error
	writes    [][]byte
}

func (writer *exportWriter) EnsurePrivateDir(ports.AnchoredRoot, ports.SafeRelativePath) error {
	return writer.ensureErr
}

func (writer *exportWriter) Write(_ context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	if writer.writeErr != nil {
		return ports.SecureWriteReceipt{}, nil, writer.writeErr
	}
	body, err := io.ReadAll(request.Source())
	if err != nil {
		return ports.SecureWriteReceipt{}, nil, err
	}
	writer.writes = append(writer.writes, append([]byte(nil), body...))
	receipt, err := ports.NewSecureWriteReceipt(request.Root(), request.Destination(), digest(body), int64(len(body)), request.Channel(), request.SourceIDs())
	return receipt, nil, err
}
func (writer *exportWriter) Install(ctx context.Context, request ExportInstallRequest) (ExportInstallResult, error) {
	if writer.ensureErr != nil {
		return ExportInstallResult{}, writer.ensureErr
	}
	if writer.writeErr != nil {
		return ExportInstallResult{}, writer.writeErr
	}
	if err := ctx.Err(); err != nil {
		return ExportInstallResult{}, err
	}
	bundleReceipt, err := ports.NewSecureWriteReceipt(request.Root, request.BundlePath, digest(request.Bundle), int64(len(request.Bundle)), "export_bundle", request.SourceIDs)
	if err != nil {
		return ExportInstallResult{}, err
	}
	writer.writes = append(writer.writes, append([]byte(nil), request.Bundle...))
	manifest, err := request.ManifestForBundleReceipt(bundleReceipt)
	if err != nil {
		return ExportInstallResult{}, err
	}
	manifestReceipt, err := ports.NewSecureWriteReceipt(request.Root, request.ManifestPath, digest(manifest), int64(len(manifest)), "export_manifest", request.SourceIDs)
	if err != nil {
		return ExportInstallResult{}, err
	}
	writer.writes = append(writer.writes, append([]byte(nil), manifest...))
	return ExportInstallResult{BundleReceipt: bundleReceipt, ManifestReceipt: manifestReceipt, ManifestBytes: append([]byte(nil), manifest...)}, nil
}

func testRoot(t *testing.T) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot("/tmp/kar-export")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func testBundlePath(t *testing.T) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath("exports/review.zip")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExportRedactedRunUsesCommittedReaderAndSecureWriter(t *testing.T) {
	source := validProjection()
	writer := &exportWriter{}
	service, err := NewService(exportReader{source: source}, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot("/tmp/kar-export")
	if err != nil {
		t.Fatal(err)
	}
	bundlePath, err := ports.NewSafeRelativePath("exports/review.zip")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := ports.NewSafeRelativePath("exports/review.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ExportRedactedRun(context.Background(), ExportRequest{
		Source: ExportSource{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID},
		Root:   root, BundlePath: bundlePath, ManifestPath: manifestPath,
		ExportID: validOptions().ExportID, CreatedAt: validOptions().CreatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.writes) != 2 || !bytes.Equal(writer.writes[0], result.Bundle.Bytes) || !bytes.Equal(writer.writes[1], result.ManifestBytes) {
		t.Fatal("secure writer did not receive the completed bundle and sidecar")
	}
	if result.Manifest.SecureWriter.ReceiptSHA256 != result.BundleReceipt.SHA256() {
		t.Fatal("manifest receipt does not bind bundle receipt")
	}
	result.Bundle.Bytes[0] ^= 0xff
	if bytes.Equal(writer.writes[0], result.Bundle.Bytes) {
		t.Fatal("result bundle aliases secure-writer input")
	}
}
func TestExportRedactedRunAcceptsCommittedNoFindingsProjection(t *testing.T) {
	source := validProjection()
	source.Findings = nil
	source.Evidence = nil
	source.SourceIdentity.FindingID = ""
	source.SourceIdentity.SourceExcerptSHA256 = ""
	source.SourceIdentity.SourceTargetSHA256 = testHash("f")
	source.CurrentIdentity = CurrentIdentity{TargetSHA256: testHash("f")}
	writer := &exportWriter{}
	service, err := NewService(exportReader{source: source}, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ExportRedactedRun(context.Background(), exportRequestFor(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.writes) != 2 || len(result.Bundle.Members) != 6 || result.Manifest.SourceIdentity.SourceTargetSHA256 != testHash("f") || result.Manifest.CurrentIdentity.TargetSHA256 != testHash("f") {
		t.Fatalf("no-findings export = %#v, writes=%d", result.Manifest, len(writer.writes))
	}
}

func TestExportRedactedRunRejectsUnboundTargetIdentity(t *testing.T) {
	source := validProjection()
	source.SourceIdentity.SourceTargetSHA256 = testHash("a")
	writer := &exportWriter{}
	service, err := NewService(exportReader{source: source}, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ExportRedactedRun(context.Background(), exportRequestFor(source))
	if !errors.Is(err, ErrMalformedProjection) || len(writer.writes) != 0 {
		t.Fatalf("unbound target identity error = %v, writes=%d", err, len(writer.writes))
	}
}
func TestExportRedactedRunRejectsSecretsBeforeInstallAsSecurityFailure(t *testing.T) {
	source := validProjection()
	source.Findings[0].Role = "token=top-secret-value"
	writer := &exportWriter{}
	service, err := NewService(exportReader{source: source}, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ExportRedactedRun(context.Background(), exportRequestFor(source))
	if !errors.Is(err, ErrSecretDetected) || len(writer.writes) != 0 {
		t.Fatalf("secret export = %v, writes = %d", err, len(writer.writes))
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || failure.Class().FallbackAllowed() {
		t.Fatalf("secret export failure = %#v", failure)
	}
}
func TestExportRedactedRunPreservesSourceCancellationWithoutInstalling(t *testing.T) {
	writer := &exportWriter{}
	service, err := NewService(exportReader{err: context.Canceled}, writer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ExportRedactedRun(context.Background(), exportRequestFor(validProjection()))
	if !errors.Is(err, ErrUnverifiedSource) || !errors.Is(err, context.Canceled) || len(writer.writes) != 0 {
		t.Fatalf("source cancellation = %v, writes = %d", err, len(writer.writes))
	}
}

func TestExportRedactedRunFailsClosedForUnsafeAndInterruptedWrites(t *testing.T) {
	source := validProjection()
	root, _ := ports.NewAnchoredRoot("/tmp/kar-export")
	bundlePath, _ := ports.NewSafeRelativePath("exports/review.zip")
	manifestPath, _ := ports.NewSafeRelativePath("exports/review.manifest.json")
	request := ExportRequest{
		Source: ExportSource{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID},
		Root:   root, BundlePath: bundlePath, ManifestPath: manifestPath,
		ExportID: validOptions().ExportID, CreatedAt: validOptions().CreatedAt,
	}
	t.Run("malicious committed projection path", func(t *testing.T) {
		unsafe := validProjection()
		unsafe.RunManifest.ArtifactPath = "../outside"
		writer := &exportWriter{}
		service, err := NewService(exportReader{source: unsafe}, writer, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ExportRedactedRun(context.Background(), request); !errors.Is(err, ErrMalformedProjection) || len(writer.writes) != 0 {
			t.Fatalf("unsafe projection result = %v, writes = %d", err, len(writer.writes))
		}
	})
	t.Run("symlink-safe writer rejection", func(t *testing.T) {
		writer := &exportWriter{ensureErr: errors.New("symlink destination")}
		service, err := NewService(exportReader{source: source}, writer, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ExportRedactedRun(context.Background(), request); !errors.Is(err, ErrSecureInstall) || len(writer.writes) != 0 {
			t.Fatalf("symlink rejection result = %v, writes = %d", err, len(writer.writes))
		}
	})
	t.Run("interrupted writer", func(t *testing.T) {
		writer := &exportWriter{writeErr: errors.New("interrupted")}
		service, err := NewService(exportReader{source: source}, writer, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ExportRedactedRun(context.Background(), request); !errors.Is(err, ErrSecureInstall) || len(writer.writes) != 0 {
			t.Fatalf("writer failure result = %v, writes = %d", err, len(writer.writes))
		}
	})
}

type recoverableExportState struct {
	bundle          []byte
	bundleReceipt   ports.SecureWriteReceipt
	bundleAdoptions int
	manifest        []byte
	manifestReceipt ports.SecureWriteReceipt
	failAfterBundle bool
}

type recoverableExportInstaller struct{ state *recoverableExportState }

func (installer recoverableExportInstaller) Install(ctx context.Context, request ExportInstallRequest) (ExportInstallResult, error) {
	if err := ctx.Err(); err != nil {
		return ExportInstallResult{}, err
	}
	state := installer.state
	if state.bundle == nil {
		receipt, err := ports.NewSecureWriteReceipt(request.Root, request.BundlePath, digest(request.Bundle), int64(len(request.Bundle)), "export_bundle", request.SourceIDs)
		if err != nil {
			return ExportInstallResult{}, err
		}
		state.bundle = append([]byte(nil), request.Bundle...)
		state.bundleReceipt = receipt
	} else if !bytes.Equal(state.bundle, request.Bundle) || state.bundleReceipt.Root() != request.Root || state.bundleReceipt.Destination() != request.BundlePath {
		return ExportInstallResult{}, errors.New("bundle no-replace conflict")
	} else {
		state.bundleAdoptions++
	}
	if state.failAfterBundle {
		state.failAfterBundle = false
		return ExportInstallResult{}, errors.New("injected failure after bundle install")
	}
	if err := ctx.Err(); err != nil {
		return ExportInstallResult{}, err
	}
	manifest, err := request.ManifestForBundleReceipt(state.bundleReceipt)
	if err != nil {
		return ExportInstallResult{}, err
	}
	if state.manifest == nil {
		receipt, err := ports.NewSecureWriteReceipt(request.Root, request.ManifestPath, digest(manifest), int64(len(manifest)), "export_manifest", request.SourceIDs)
		if err != nil {
			return ExportInstallResult{}, err
		}
		state.manifest = append([]byte(nil), manifest...)
		state.manifestReceipt = receipt
	} else if !bytes.Equal(state.manifest, manifest) || state.manifestReceipt.Root() != request.Root || state.manifestReceipt.Destination() != request.ManifestPath {
		return ExportInstallResult{}, errors.New("manifest no-replace conflict")
	}
	return ExportInstallResult{BundleReceipt: state.bundleReceipt, ManifestReceipt: state.manifestReceipt, ManifestBytes: append([]byte(nil), state.manifest...)}, nil
}

func exportRequestFor(source VerifiedSourceProjection) ExportRequest {
	root, _ := ports.NewAnchoredRoot("/tmp/kar-export")
	bundle, _ := ports.NewSafeRelativePath("exports/review.zip")
	manifest, _ := ports.NewSafeRelativePath("exports/review.manifest.json")
	return ExportRequest{Source: ExportSource{SessionID: source.SessionID, RunID: source.RunID, ReviewID: source.ReviewID}, Root: root, BundlePath: bundle, ManifestPath: manifest, ExportID: validOptions().ExportID, CreatedAt: validOptions().CreatedAt}
}

func TestExportRedactedRunRecoversAfterBundleInstallFailure(t *testing.T) {
	source := validProjection()
	state := &recoverableExportState{failAfterBundle: true}
	request := exportRequestFor(source)
	first, err := NewService(exportReader{source: source}, recoverableExportInstaller{state}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.ExportRedactedRun(context.Background(), request); !errors.Is(err, ErrSecureInstall) || state.bundle == nil || state.manifest != nil {
		t.Fatalf("first export = %v, bundle=%t manifest=%t", err, state.bundle != nil, state.manifest != nil)
	}
	restarted, err := NewService(exportReader{source: source}, recoverableExportInstaller{state}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.ExportRedactedRun(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.bundle, result.Bundle.Bytes) || !bytes.Equal(state.manifest, result.ManifestBytes) || result.Manifest.SecureWriter.ReceiptSHA256 != state.bundleReceipt.SHA256() || result.ManifestReceipt.SHA256() != digest(result.ManifestBytes) || state.bundleAdoptions != 1 {
		t.Fatal("restart did not re-adopt the installed bundle with its actual receipt")
	}
}

func TestExportRedactedRunCancellationAndNoReplaceConflict(t *testing.T) {
	source := validProjection()
	state := &recoverableExportState{}
	service, err := NewService(exportReader{source: source}, recoverableExportInstaller{state}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cancelErr := func() error {
		_, err := service.ExportRedactedRun(cancelled, exportRequestFor(source))
		return err
	}()
	if !errors.Is(cancelErr, ErrSecureInstall) || !errors.Is(cancelErr, context.Canceled) || state.bundle != nil {
		t.Fatalf("cancelled export = %v, bundle=%t", cancelErr, state.bundle != nil)
	}
	if _, err := service.ExportRedactedRun(context.Background(), exportRequestFor(source)); err != nil {
		t.Fatal(err)
	}
	conflict := validProjection()
	conflict.Findings[0].Title = "different export"
	conflicting, err := NewService(exportReader{source: conflict}, recoverableExportInstaller{state}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conflicting.ExportRedactedRun(context.Background(), exportRequestFor(conflict)); !errors.Is(err, ErrSecureInstall) {
		t.Fatalf("no-replace conflict error = %v", err)
	}
}
