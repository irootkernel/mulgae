package reviewinput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCapturedTargetReaderOmitsBinaryVisualEvidence(t *testing.T) {
	textPath, err := ports.NewSafeRelativePath("source.go")
	if err != nil {
		t.Fatal(err)
	}
	pngPath, err := ports.NewSafeRelativePath("screenshots/result.png")
	if err != nil {
		t.Fatal(err)
	}
	textBytes := []byte("package source\n")
	pngBytes := []byte("\x89PNG\r\n\x1a\nexact-binary-evidence")
	textSum := sha256.Sum256(textBytes)
	pngSum := sha256.Sum256(pngBytes)
	textFile, err := ports.NewWorkspaceSnapshotFile(textPath, textBytes, "sha256:"+hex.EncodeToString(textSum[:]))
	if err != nil {
		t.Fatal(err)
	}
	pngFile, err := ports.NewWorkspaceVisualAsset(pngPath, pngBytes, "sha256:"+hex.EncodeToString(pngSum[:]), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest([]ports.WorkspaceSnapshotFile{pngFile, textFile}, "captured-policy")
	if err != nil {
		t.Fatal(err)
	}
	capturedEvidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: {pngFile, textFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, capturedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newCapturedTargetReader(material)
	if err != nil {
		t.Fatal(err)
	}
	targetSHA := "sha256:" + target.Identity().SHA256()
	availability, got, err := reader.ReadImmutableTarget(context.Background(), targetSHA, evidence.SideHead, textPath)
	if err != nil || availability != evidence.ImmutableTargetAvailable || string(got) != string(textBytes) {
		t.Fatalf("text evidence = availability=%q bytes=%q err=%v", availability, got, err)
	}
	availability, got, err = reader.ReadImmutableTarget(context.Background(), targetSHA, evidence.SideHead, pngPath)
	if err != nil || availability != evidence.ImmutableTargetUnavailable || got != nil {
		t.Fatalf("binary evidence leaked to line reader = availability=%q bytes=%x err=%v", availability, got, err)
	}
}

type captureFake struct {
	material ports.CapturedReviewMaterial
	err      error
	calls    *[]string
}

type artistCaptureFake struct {
	captureFake
	inputs ports.ArtistReviewInputs
}

func (fake *artistCaptureFake) CaptureReviewTargetWithArtistInputs(_ context.Context, _ ports.AnchoredRoot, _ ports.ReviewTargetSelector, inputs ports.ArtistReviewInputs) (ports.CapturedReviewMaterial, error) {
	*fake.calls = append(*fake.calls, "artist-capture")
	fake.inputs = inputs
	return fake.material, fake.err
}

func (fake captureFake) CaptureReviewTarget(_ context.Context, _ ports.AnchoredRoot, _ ports.ReviewTargetSelector) (ports.CapturedReviewMaterial, error) {
	*fake.calls = append(*fake.calls, "capture")
	return fake.material, fake.err
}

type detectorFake struct {
	detection ports.ReviewInputDetection
	err       error
	calls     *[]string
	objective []byte
}

func (*detectorFake) ReviewInputDetectorIdentity() string { return "test-detector.v1" }

func (fake *detectorFake) DetectReviewInput(_ context.Context, channel ports.ReviewInputChannel, label string, value []byte) (ports.ReviewInputDetection, error) {
	*fake.calls = append(*fake.calls, "screen")
	if channel != ports.ReviewInputObjective || label != objectiveDetectorLabel {
		return ports.ReviewInputDetection{}, errors.New("unexpected detector input")
	}
	fake.objective = append([]byte(nil), value...)
	return fake.detection, fake.err
}

type leaseFactoryFake struct {
	lease   ports.WorkspaceSnapshotLease
	err     error
	calls   *[]string
	request ports.WorkspaceSnapshotRequest
}

func (fake *leaseFactoryFake) MaterializeLease(_ context.Context, request ports.WorkspaceSnapshotRequest) (ports.WorkspaceSnapshotLease, error) {
	*fake.calls = append(*fake.calls, "materialize")
	fake.request = request
	return fake.lease, fake.err
}

type leaseFake struct {
	identity ports.WorkspaceSnapshotIdentity
}

func (fake leaseFake) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return fake.identity
}
func (leaseFake) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, errors.New("not used")
}
func (leaseFake) Receipt() ports.WorkspaceSnapshotReceipt { return ports.WorkspaceSnapshotReceipt{} }
func (leaseFake) Release(ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	return ports.WorkspaceTerminalReceipt{}, nil
}
func (leaseFake) Abort(ports.WorkspaceAbortEvidence) error { return nil }

func TestImmutableInputSourceCaptureOrdersAndPreservesObjective(t *testing.T) {
	calls := []string{}
	material := testMaterial(t)
	clean, err := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	detector := &detectorFake{detection: clean, calls: &calls}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	source, root := testSource(t, captureFake{material: material, calls: &calls}, detector, materializer, []byte("@roadmap.md"), true)

	captured, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	calls = append(calls, "transfer")
	if got, want := strings.Join(calls, ","), "capture,screen,materialize,transfer"; got != want {
		t.Fatalf("call order = %q, want %q", got, want)
	}
	if got := string(detector.objective); got != "@roadmap.md" {
		t.Fatalf("screened objective = %q", got)
	}
	if got := string(captured.Input().Objective()); got != "@roadmap.md" {
		t.Fatalf("captured objective = %q", got)
	}
	expectedWorkspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	if !materializer.request.Valid() || !reflect.DeepEqual(materializer.request, expectedWorkspace) {
		t.Fatal("materializer did not receive the derived provider workspace")
	}
	if captured.PacketDetector() != detector {
		t.Fatal("captured input lost packet detector authority")
	}
}
func TestImmutableInputSourceCapturePreservesProjectContextPresence(t *testing.T) {
	cases := []struct {
		name       string
		context    []byte
		hasContext bool
	}{
		{name: "absent", context: nil, hasContext: false},
		{name: "present empty", context: []byte{}, hasContext: true},
		{name: "present nonempty", context: []byte("project context"), hasContext: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			clean, err := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			detector := &detectorFake{detection: clean, calls: &calls}
			materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
			material := testMaterialWithProjectContext(t, test.context, test.hasContext)
			source, root := testSource(t, captureFake{material: material, calls: &calls}, detector, materializer, nil, false)

			captured, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			input := captured.Input()
			if input.HasProjectContext() != test.hasContext {
				t.Fatalf("HasProjectContext() = %t, want %t", input.HasProjectContext(), test.hasContext)
			}
			context := input.ProjectContext()
			if string(context) != string(test.context) {
				t.Fatalf("ProjectContext() = %q, want %q", context, test.context)
			}
			if test.hasContext && context == nil {
				t.Fatal("present project context became absent")
			}
			if !test.hasContext && context != nil {
				t.Fatal("absent project context acquired bytes")
			}
		})
	}
}

func TestImmutableInputSourceUsesReviewScopedArtistCapture(t *testing.T) {
	calls := []string{}
	capturer := &artistCaptureFake{captureFake: captureFake{material: testMaterial(t), calls: &calls}}
	detector := &detectorFake{calls: &calls}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewReviewTargetSelector(ports.ReviewTargetPatch, "patch")
	if err != nil {
		t.Fatal(err)
	}
	artistInputs, err := ports.NewArtistReviewInputs("docs/roadmap.md", []string{"design-specs/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := reviewrun.NewInputCaptureRequestWithArtistInputs(root, target, nil, false, artistInputs)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewImmutableInputSourceFactory(capturer, detector, materializer)
	if err != nil {
		t.Fatal(err)
	}
	source, err := factory.NewImmutableInputSource(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "artist-capture,materialize" {
		t.Fatalf("artist capture order = %q", got)
	}
	if capturer.inputs.BriefPath() != "docs/roadmap.md" || len(capturer.inputs.DesignSpecGlobs()) != 1 {
		t.Fatalf("artist inputs = %#v", capturer.inputs)
	}
}

func TestImmutableInputSourceCaptureWithoutObjectiveSkipsDetector(t *testing.T) {
	calls := []string{}
	clean, _ := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
	detector := &detectorFake{detection: clean, calls: &calls}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	source, root := testSource(t, captureFake{material: testMaterial(t), calls: &calls}, detector, materializer, nil, false)

	captured, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(detector.objective) != 0 || strings.Join(calls, ",") != "capture,materialize" || len(captured.Input().Objective()) != 0 {
		t.Fatal("objective-free capture exposed or materialized an objective")
	}
}

func TestImmutableInputSourceRejectsSecondCapture(t *testing.T) {
	calls := []string{}
	clean, _ := ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
	detector := &detectorFake{detection: clean, calls: &calls}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	source, root := testSource(t, captureFake{material: testMaterial(t), calls: &calls}, detector, materializer, nil, false)
	request := reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root}
	if _, err := source.Capture(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Capture(context.Background(), request); err == nil {
		t.Fatal("second capture succeeded")
	}
	if got := strings.Join(calls, ","); got != "capture,materialize" {
		t.Fatalf("second capture invoked dependencies: %q", got)
	}
}

func TestImmutableInputSourceBlocksBeforeMaterialize(t *testing.T) {
	calls := []string{}
	blocked, _ := ports.NewReviewInputDetection(ports.ReviewInputBlocked, "secret", 1)
	detector := &detectorFake{detection: blocked, calls: &calls}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	source, root := testSource(t, captureFake{material: testMaterial(t), calls: &calls}, detector, materializer, []byte("blocked"), true)

	if _, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root}); err == nil {
		t.Fatal("blocked objective was accepted")
	} else if failure, ok := ports.ReviewCaptureFailureFromError(err); !ok || failure.Code() != ports.ReviewCapturePolicyBlocked ||
		failure.EffectiveConfiguration() != "detector_policy=test-detector.v1; detector_code=secret" {
		t.Fatalf("blocked objective failure = %#v, present=%t", failure, ok)
	}
	if got := strings.Join(calls, ","); got != "capture,screen" {
		t.Fatalf("blocked objective materialized: %q", got)
	}
}

func TestImmutableInputSourceRejectsUnpublishableManifestBeforeMaterialize(t *testing.T) {
	calls := []string{}
	materializer := &leaseFactoryFake{lease: leaseFake{identity: testIdentity(t)}, calls: &calls}
	source, root := testSource(t, captureFake{material: oversizedManifestMaterial(t), calls: &calls}, &detectorFake{calls: &calls}, materializer, nil, false)

	_, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
	failure, ok := ports.ReviewCaptureFailureFromError(err)
	if !ok || failure.Code() != ports.ReviewCaptureManifestLarge || !strings.Contains(failure.EffectiveConfiguration(), "provider_invoked=false") {
		t.Fatalf("manifest feasibility failure = %#v, present=%t, err=%v", failure, ok, err)
	}
	if got := strings.Join(calls, ","); got != "capture" {
		t.Fatalf("manifest feasibility failure invoked later dependencies: %q", got)
	}
}

func TestImmutableInputSourcePreservesTypedTargetCaptureFailure(t *testing.T) {
	calls := []string{}
	typed, err := ports.NewReviewCaptureFailure(ports.ReviewCaptureUnsupported, "image.png", "", "use binary capture", errors.New("binary"))
	if err != nil {
		t.Fatal(err)
	}
	source, root := testSource(t, captureFake{err: typed, calls: &calls}, &detectorFake{calls: &calls}, &leaseFactoryFake{calls: &calls}, nil, false)
	_, observedErr := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
	observed, ok := ports.ReviewCaptureFailureFromError(observedErr)
	if !ok || observed.Code() != ports.ReviewCaptureUnsupported || observed.Path() != "image.png" || observed.Hint() != "use binary capture" {
		t.Fatalf("target capture failure = %#v, present=%t, err=%v", observed, ok, observedErr)
	}
}

func TestImmutableInputSourceRedactsMaterializerFailure(t *testing.T) {
	calls := []string{}
	materializer := &leaseFactoryFake{err: errors.New("/private/project/secret"), calls: &calls}
	source, root := testSource(t, captureFake{material: testMaterial(t), calls: &calls}, &detectorFake{calls: &calls}, materializer, nil, false)

	_, err := source.Capture(context.Background(), reviewrun.Request{InputSource: source, ProjectRoot: root, ArtifactRoot: root})
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Join(calls, ",") != "capture,materialize" {
		t.Fatalf("materializer failure was not redacted and ordered: %v (%q)", err, strings.Join(calls, ","))
	}
}

func testSource(t *testing.T, capturer ports.ReviewTargetCapturer, detector ports.ReviewInputContentDetector, leases ports.WorkspaceSnapshotLeaseFactory, objective []byte, hasObjective bool) (reviewrun.ImmutableInputSource, ports.AnchoredRoot) {
	t.Helper()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewReviewTargetSelector(ports.ReviewTargetPatch, "patch")
	if err != nil {
		t.Fatal(err)
	}
	request, err := reviewrun.NewInputCaptureRequest(root, target, objective, hasObjective)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewImmutableInputSourceFactory(capturer, detector, leases)
	if err != nil {
		t.Fatal(err)
	}
	source, err := factory.NewImmutableInputSource(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return source, root
}

func testMaterial(t *testing.T) ports.CapturedReviewMaterial {
	t.Helper()
	return testMaterialWithProjectContext(t, []byte("project context"), true)
}

func testMaterialWithProjectContext(t *testing.T, projectContext []byte, hasProjectContext bool) ports.CapturedReviewMaterial {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(nil, "captured-policy")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{
		ports.CapturedEvidenceHead: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, projectContext, hasProjectContext, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func oversizedManifestMaterial(t *testing.T) ports.CapturedReviewMaterial {
	t.Helper()
	prefix := strings.Repeat("nested/", 100)
	files := make([]ports.WorkspaceSnapshotFile, ports.WorkspaceSnapshotMaxFiles)
	emptyDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for index := range files {
		path, err := ports.NewSafeRelativePath(prefix + fmt.Sprintf("file-%05d.txt", index))
		if err != nil {
			t.Fatal(err)
		}
		files[index], err = ports.NewWorkspaceSnapshotFile(path, nil, emptyDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := ports.NewWorkspaceSnapshotRequest(files, "oversized-manifest")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: files})
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, snapshot, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func testIdentity(t *testing.T) ports.WorkspaceSnapshotIdentity {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity(
		"/snapshot", "snapshot-0123456789abcdef0123456789abcdef",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"captured-policy", 1, 2, 3, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
