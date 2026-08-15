//go:build darwin && arm64

package gittarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewCaptureStagePreservesPNGAsBinaryEvidence(t *testing.T) {
	root := reviewCaptureRepository(t)
	if err := os.MkdirAll(filepath.Join(root, "client", "e2e", "screenshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	const imagePath = "client/e2e/screenshots/staged.png"
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(imagePath)), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", imagePath)

	material := captureReviewMaterial(t, root, ports.ReviewTargetStage, "stage")
	expectedSum := sha256.Sum256(pngBytes)
	expectedSHA := "sha256:" + hex.EncodeToString(expectedSum[:])
	assertCapturedPNG := func(name string, files []ports.WorkspaceSnapshotFile) {
		t.Helper()
		for _, file := range files {
			if file.Path().String() != imagePath {
				continue
			}
			if file.MediaType() != "image/png" || file.IsText() || file.SHA256() != expectedSHA || !bytes.Equal(file.Bytes(), pngBytes) {
				t.Fatalf("%s PNG = media=%q text=%t sha=%q bytes=%x", name, file.MediaType(), file.IsText(), file.SHA256(), file.Bytes())
			}
			return
		}
		t.Fatalf("%s omitted %q", name, imagePath)
	}
	assertCapturedPNG("snapshot", material.Snapshot().Files())
	indexFiles, ok := material.Evidence().Files(ports.CapturedEvidenceIndex)
	if !ok {
		t.Fatal("stage capture omitted index evidence")
	}
	assertCapturedPNG("index evidence", indexFiles)

	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil {
		t.Fatal(err)
	}
	assertCapturedPNG("restored snapshot", restored.Snapshot().Files())
}

func TestReviewCaptureDirtyPreservesUntrackedPNGWithoutTextDecoding(t *testing.T) {
	root := reviewCaptureRepository(t)
	pngBytes := make([]byte, 180000+4096)
	copy(pngBytes, []byte("\x89PNG\r\n\x1a\n"))
	const imagePath = "untracked.png"
	if err := os.WriteFile(filepath.Join(root, imagePath), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	material := captureReviewMaterial(t, root, ports.ReviewTargetDirty, "dirty")
	if patch := string(material.Target().Bytes()); !strings.Contains(patch, "Binary files /dev/null and b/untracked.png differ") {
		t.Fatalf("dirty target did not describe binary PNG: %q", patch)
	}
	for _, file := range material.Snapshot().Files() {
		if file.Path().String() == imagePath {
			if file.MediaType() != "image/png" || !bytes.Equal(file.Bytes(), pngBytes) {
				t.Fatalf("dirty PNG = media=%q bytes=%x", file.MediaType(), file.Bytes())
			}
			return
		}
	}
	t.Fatalf("dirty snapshot omitted %q", imagePath)
}

func TestReviewCaptureDiffPreservesSourcePastGitControlOutputLimit(t *testing.T) {
	root := reviewCaptureRepository(t)
	payload := bytes.Repeat([]byte("complete source line\n"), defaultMaxStdoutBytes/len("complete source line\n")+2)
	const sourcePath = "large-source.txt"
	if err := os.WriteFile(filepath.Join(root, sourcePath), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", sourcePath)
	reviewGit(t, root, "commit", "-m", "Add large source")

	material := captureReviewMaterial(t, root, ports.ReviewTargetDiff, "HEAD~1..HEAD")
	if len(material.Target().Bytes()) <= defaultMaxStdoutBytes {
		t.Fatalf("captured diff = %d bytes, want more than former Git stdout limit", len(material.Target().Bytes()))
	}
	for _, file := range material.Snapshot().Files() {
		if file.Path().String() == sourcePath {
			if !bytes.Equal(file.Bytes(), payload) {
				t.Fatalf("captured source = %d bytes, want %d", len(file.Bytes()), len(payload))
			}
			return
		}
	}
	t.Fatalf("snapshot omitted %q", sourcePath)
}

func TestReviewCaptureDirtyAcceptsTrackedIgnoreControlsAndExcludesTheirMaterial(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "git-ignored.txt\n")
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "excluded-*.txt\n")
	writeReviewFile(t, filepath.Join(root, "excluded-tracked.txt"), "base\n")
	reviewGit(t, root, "add", ".gitignore", ".mulgaeignore", "excluded-tracked.txt")
	reviewGit(t, root, "commit", "-m", "Track capture controls")

	writeReviewFile(t, filepath.Join(root, ".gitignore"), "git-ignored.txt\n# changed control\n")
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "excluded-*.txt\n# changed control\n")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "dirty tracked\n")
	writeReviewFile(t, filepath.Join(root, "included-untracked.txt"), "included\n")
	writeReviewFile(t, filepath.Join(root, "excluded-tracked.txt"), "dirty excluded\n")
	writeReviewFile(t, filepath.Join(root, "excluded-untracked.txt"), "excluded\n")
	writeReviewFile(t, filepath.Join(root, "git-ignored.txt"), "ignored by Git\n")

	material := captureReviewMaterial(t, root, ports.ReviewTargetDirty, "dirty")
	for _, forbidden := range []string{".gitignore", ".mulgaeignore", "excluded-tracked.txt", "excluded-untracked.txt", "git-ignored.txt"} {
		assertReviewMaterialExcludes(t, material, forbidden, "changed control")
	}
	paths := reviewFilePathSet(material.Snapshot().Files())
	if !paths["tracked.txt"] || !paths["included-untracked.txt"] {
		t.Fatalf("dirty snapshot paths = %v", paths)
	}
	workspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	for path := range reviewFilePathSet(workspace.Files()) {
		if strings.Contains(path, ".gitignore") || strings.Contains(path, ".mulgaeignore") || strings.Contains(path, "excluded-") {
			t.Fatalf("provider workspace retained control material %q", path)
		}
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(`"path":".gitignore"`), []byte(`"path":".mulgaeignore"`), []byte("changed control")} {
		if bytes.Contains(archive, forbidden) {
			t.Fatalf("captured archive retained control material %q", forbidden)
		}
	}
}

func TestFilterReviewPatchExcludesTrackedProjectConfigControl(t *testing.T) {
	patch := []byte("diff --git a/.mulgae/config.yaml b/.mulgae/config.yaml\n--- a/.mulgae/config.yaml\n+++ b/.mulgae/config.yaml\n@@ -1 +1 @@\n-version: 2\n+version: 3\n")
	filtered, err := filterReviewPatch(patch, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("project config reached provider patch: %q", filtered)
	}
}

func TestReviewCaptureGitTargetsNeverTransmitControlFileChanges(t *testing.T) {
	for _, target := range []ports.ReviewTargetSelectorKind{ports.ReviewTargetStage, ports.ReviewTargetDirty, ports.ReviewTargetDiff} {
		t.Run(string(target), func(t *testing.T) {
			root := reviewCaptureRepository(t)
			if err := os.Mkdir(filepath.Join(root, ".mulgae"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
			writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "secret.txt\n")
			writeReviewFile(t, filepath.Join(root, ".mulgae", "config.yaml"), "version: 3\nproject:\n  name: project\n")
			reviewGit(t, root, "add", ".gitignore", ".mulgaeignore")
			reviewGit(t, root, "add", "-f", ".mulgae/config.yaml")
			reviewGit(t, root, "commit", "-m", "Track controls")
			writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n# changed\n")
			writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "secret.txt\n# changed\n")
			writeReviewFile(t, filepath.Join(root, ".mulgae", "config.yaml"), "version: 3\nproject:\n  name: changed\n")
			writeReviewFile(t, filepath.Join(root, "tracked.txt"), "reviewable change\n")

			value := string(target)
			switch target {
			case ports.ReviewTargetStage:
				reviewGit(t, root, "add", ".gitignore", ".mulgaeignore", "tracked.txt")
				reviewGit(t, root, "add", "-f", ".mulgae/config.yaml")
			case ports.ReviewTargetDiff:
				reviewGit(t, root, "add", ".gitignore", ".mulgaeignore", "tracked.txt")
				reviewGit(t, root, "add", "-f", ".mulgae/config.yaml")
				reviewGit(t, root, "commit", "-m", "Change controls")
				value = "HEAD~1..HEAD"
			}
			material := captureReviewMaterial(t, root, target, value)
			patch := string(material.Target().Bytes())
			if !strings.Contains(patch, "tracked.txt") || strings.Contains(patch, ".gitignore") || strings.Contains(patch, ".mulgaeignore") || strings.Contains(patch, ".mulgae/config.yaml") || strings.Contains(patch, "# changed") {
				t.Fatalf("%s target patch = %q", target, patch)
			}
		})
	}
}

func TestReviewCapturePatchAndStdinFilterControlAndIgnoredSections(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "secret.txt\n")
	patch := strings.Join([]string{
		"diff --git a/.gitignore b/.gitignore", "--- a/.gitignore", "+++ b/.gitignore", "@@ -0,0 +1 @@", "+ignored.txt",
		"diff --git a/.mulgaeignore b/.mulgaeignore", "--- a/.mulgaeignore", "+++ b/.mulgaeignore", "@@ -0,0 +1 @@", "+secret.txt",
		"diff --git a/secret.txt b/secret.txt", "--- a/secret.txt", "+++ b/secret.txt", "@@ -0,0 +1 @@", "+secret",
		"diff --git a/kept.txt b/kept.txt", "--- a/kept.txt", "+++ b/kept.txt", "@@ -0,0 +1 @@", "+kept",
	}, "\n") + "\n"
	writeReviewFile(t, filepath.Join(root, "review.patch"), patch)

	material := captureReviewMaterial(t, root, ports.ReviewTargetPatch, "review.patch")
	if got := string(material.Target().Bytes()); !strings.Contains(got, "kept.txt") || strings.Contains(got, ".gitignore") || strings.Contains(got, ".mulgaeignore") || strings.Contains(got, "secret.txt") {
		t.Fatalf("filtered patch target = %q", got)
	}

	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte(patch)}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	stdinMaterial, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetStdin, "captured"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(stdinMaterial.Target().Bytes()); got != string(material.Target().Bytes()) {
		t.Fatalf("stdin target = %q, patch target = %q", got, material.Target().Bytes())
	}

	controlOnly := "diff --git a/.gitignore b/.gitignore\n--- a/.gitignore\n+++ b/.gitignore\n@@ -0,0 +1 @@\n+ignored.txt\n"
	writeReviewFile(t, filepath.Join(root, "control-only.patch"), controlOnly)
	err = captureReviewError(t, root, ports.ReviewTargetPatch, "control-only.patch")
	failure, ok := ports.ReviewCaptureFailureFromError(err)
	if !ok || failure.Code() != ports.ReviewCaptureNoReviewableContent {
		t.Fatalf("control-only patch failure = %#v, present=%t, err=%v", failure, ok, err)
	}

	for name, unsafePatch := range map[string]string{
		"reserved namespace": "diff --git a/.mulgae/state.json b/.mulgae/state.json\n--- a/.mulgae/state.json\n+++ b/.mulgae/state.json\n@@ -0,0 +1 @@\n+unsafe\n",
		"non-canonical path": "diff --git a/../.gitignore b/../.gitignore\n--- a/../.gitignore\n+++ b/../.gitignore\n@@ -0,0 +1 @@\n+unsafe\n",
	} {
		t.Run(name, func(t *testing.T) {
			writeReviewFile(t, filepath.Join(root, "unsafe.patch"), unsafePatch)
			if err := captureReviewError(t, root, ports.ReviewTargetPatch, "unsafe.patch"); err == nil {
				t.Fatal("unsafe patch was accepted")
			}
		})
	}
}

type rasterMutationRunner struct {
	delegate    Runner
	path        string
	replacement []byte
	writeTrees  int
}

func (runner *rasterMutationRunner) Run(ctx context.Context, command Command) (Result, error) {
	if len(command.Args) > 0 && command.Args[len(command.Args)-1] == "write-tree" {
		runner.writeTrees++
		if runner.writeTrees == 2 {
			if err := os.WriteFile(runner.path, runner.replacement, 0o644); err != nil {
				return Result{}, err
			}
		}
	}
	return runner.delegate.Run(ctx, command)
}

func TestReviewCaptureDirtyRejectsRasterMutationAfterSnapshot(t *testing.T) {
	root := reviewCaptureRepository(t)
	const imagePath = "changing.png"
	before := []byte("\x89PNG\r\n\x1a\nbefore")
	after := []byte("\x89PNG\r\n\x1a\nafter!")
	fullPath := filepath.Join(root, imagePath)
	if err := os.WriteFile(fullPath, before, 0o644); err != nil {
		t.Fatal(err)
	}
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	runner := &rasterMutationRunner{delegate: NewExecRunner(), path: fullPath, replacement: after}
	adapter, err := NewReviewTargetCapturer(runner, &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDirty, "dirty"))
	if err == nil || !strings.Contains(err.Error(), "dirty source changed while capturing") || !strings.Contains(err.Error(), imagePath) {
		t.Fatalf("raster mutation capture error = %v", err)
	}
}

func TestUntrackedRasterPatchAcceptsBeyondLegacyAggregateLimit(t *testing.T) {
	rootPath := t.TempDir()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	eligible := make(map[string]bool)
	for index := 0; index < 300; index++ {
		name := fmt.Sprintf("raster-%03d-%s.png", index, strings.Repeat("x", 160))
		if err := os.WriteFile(filepath.Join(rootPath, name), []byte("\x89PNG\r\n\x1a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		eligible[name] = true
	}
	if patch, err := untrackedPatch(root, eligible); err != nil || len(patch) <= 180000 {
		t.Fatalf("large aggregate raster patch = %d bytes, %v", len(patch), err)
	}
}

func TestUntrackedNonRasterBinaryUsesPathOnlyMarker(t *testing.T) {
	rootPath := t.TempDir()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	path := "fixtures/archive.bin"
	if err := os.MkdirAll(filepath.Join(rootPath, "fixtures"), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte{'P', 'K', 0, 0xff, 0x01}
	if err := os.WriteFile(filepath.Join(rootPath, filepath.FromSlash(path)), contents, 0o600); err != nil {
		t.Fatal(err)
	}

	patch, err := untrackedPatch(root, map[string]bool{path: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(patch, []byte("Binary files /dev/null and b/fixtures/archive.bin differ\n")) {
		t.Fatalf("binary patch did not use a path-only marker: %q", patch)
	}
	if bytes.Contains(patch, contents) {
		t.Fatal("binary bytes leaked into the textual review target")
	}
}

func TestReviewCaptureWorkspaceClassifiesSupportedRasterByExtensionAndSignature(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]struct {
		mediaType string
		bytes     []byte
	}{
		"assets/photo.jpeg":  {mediaType: "image/jpeg", bytes: []byte{0xff, 0xd8, 0xff, 0x00, 0x81}},
		"assets/result.PNG":  {mediaType: "image/png", bytes: []byte("\x89PNG\r\n\x1a\n\x00\xff")},
		"assets/screen.webp": {mediaType: "image/webp", bytes: []byte("RIFF\x04\x00\x00\x00WEBP\x00\xff")},
	}
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, fixture := range fixtures {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), fixture.bytes, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace")
	seen := make(map[string]bool, len(fixtures))
	for _, file := range material.Snapshot().Files() {
		fixture, ok := fixtures[file.Path().String()]
		if !ok {
			continue
		}
		if file.IsText() || file.MediaType() != fixture.mediaType || !bytes.Equal(file.Bytes(), fixture.bytes) {
			t.Fatalf("raster %q = media=%q text=%t bytes=%x", file.Path().String(), file.MediaType(), file.IsText(), file.Bytes())
		}
		seen[file.Path().String()] = true
	}
	if len(seen) != len(fixtures) {
		t.Fatalf("captured raster paths = %v", seen)
	}
}

func TestReviewCaptureRejectsInvalidRasterAsTypedUnsupportedContent(t *testing.T) {
	root := t.TempDir()
	writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
	writeReviewFile(t, filepath.Join(root, "broken.png"), "not a PNG")
	err := captureReviewError(t, root, ports.ReviewTargetWorkspace, "workspace")
	failure, ok := ports.ReviewCaptureFailureFromError(err)
	if !ok || failure.Code() != ports.ReviewCaptureUnsupported || failure.Path() != "broken.png" ||
		!strings.Contains(failure.Hint(), "valid image/png") || !strings.Contains(failure.Hint(), ".mulgaeignore") {
		t.Fatalf("invalid raster failure = %#v, present=%t, err=%v", failure, ok, err)
	}
}

func TestArtistManifestIncludesAddedAndBothSidesOfModifiedHintedRasterEvidence(t *testing.T) {
	root := reviewCaptureRepository(t)
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "design-specs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "ux-ui-info.md"), "Review the staged screenshot.\n")
	if err := os.WriteFile(filepath.Join(root, "design-specs", "reference.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unrelated.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "ux-ui-info.md", "design-specs/reference.png", "unrelated.png")
	reviewGit(t, root, "commit", "-m", "artist baseline")
	if err := os.WriteFile(filepath.Join(root, "design-specs", "staged-evidence.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	modifiedPNG := append(append([]byte(nil), pngBytes...), '\n')
	if err := os.WriteFile(filepath.Join(root, "design-specs", "reference.png"), modifiedPNG, 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "design-specs/staged-evidence.png", "design-specs/reference.png")

	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := ports.NewArtistReviewInputs("ux-ui-info.md", []string{"design-specs/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetStage, "stage"), inputs)
	if err != nil {
		t.Fatal(err)
	}
	contextText := string(material.ProjectContext())
	if !strings.Contains(contextText, `"task_path":"ux-ui-info.md"`) ||
		strings.Contains(contextText, `"task_path":"after/ux-ui-info.md"`) ||
		!strings.Contains(contextText, `"path":"after/design-specs/staged-evidence.png"`) ||
		!strings.Contains(contextText, `"path":"before/design-specs/reference.png"`) ||
		!strings.Contains(contextText, `"path":"after/design-specs/reference.png"`) ||
		strings.Contains(contextText, `unrelated.png`) {
		t.Fatalf("artist primary visuals = %s", contextText)
	}
}

func TestAutomaticArtistRetainsChangedVisualsWhenBriefIsMissing(t *testing.T) {
	root := reviewCaptureRepository(t)
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "design-specs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "ux-ui-info.md"), "Review the changed screen.\n")
	if err := os.WriteFile(filepath.Join(root, "design-specs", "screen.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "ux-ui-info.md", "design-specs/screen.png")
	reviewGit(t, root, "commit", "-m", "artist baseline")
	if err := os.Remove(filepath.Join(root, "ux-ui-info.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "design-specs", "screen.png"), append(append([]byte(nil), pngBytes...), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "add", "-A")

	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := ports.NewAutomaticArtistReviewInputs("ux-ui-info.md", []string{"design-specs/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetStage, "stage"), inputs)
	if err != nil {
		t.Fatal(err)
	}
	contextText := string(material.ProjectContext())
	if !strings.Contains(contextText, `"status":"missing"`) ||
		!strings.Contains(contextText, `"task_path":"ux-ui-info.md"`) ||
		!strings.Contains(contextText, `"path":"before/design-specs/screen.png"`) ||
		!strings.Contains(contextText, `"path":"after/design-specs/screen.png"`) {
		t.Fatalf("automatic artist missing-brief context = %s", contextText)
	}
}

func TestUIWorkspaceCaptureProvidesFullSnapshotForCodeOnlyArtist(t *testing.T) {
	root := reviewCaptureRepository(t)
	if err := os.MkdirAll(filepath.Join(root, "design-specs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "ux-ui-info.md"), "Match the primary action layout.\n")
	pngBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "design-specs", "home.png"), pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := ports.NewArtistReviewInputs("ux-ui-info.md", []string{"design-specs/**/*.png"})
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace"), inputs)
	if err != nil {
		t.Fatal(err)
	}
	foundVisual := false
	for _, file := range material.Snapshot().Files() {
		foundVisual = foundVisual || file.Path().String() == "design-specs/home.png" && file.MediaType() == "image/png" && !file.IsText()
	}
	if !foundVisual || !strings.Contains(string(material.ProjectContext()), `"status":"ready"`) ||
		!strings.Contains(string(material.ProjectContext()), `"path":"current/design-specs/home.png"`) {
		t.Fatalf("UI inputs were not captured: visual=%t context=%s", foundVisual, material.ProjectContext())
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil || !restored.Valid() {
		t.Fatalf("visual archive did not round-trip: %v", err)
	}

	if err := os.Remove(filepath.Join(root, "ux-ui-info.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace"), inputs); err == nil || !strings.Contains(err.Error(), "artist brief") {
		t.Fatalf("missing artist brief error = %v", err)
	}
	writeReviewFile(t, filepath.Join(root, "ux-ui-info.md"), "Match the primary action layout.\n")
	if err := os.Remove(filepath.Join(root, "design-specs", "home.png")); err != nil {
		t.Fatal(err)
	}
	if material, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace"), inputs); err != nil || !strings.Contains(string(material.ProjectContext()), `"status":"code_only"`) {
		t.Fatalf("code-only artist capture = %s, %v", material.ProjectContext(), err)
	}
}

type oneShotStdin struct {
	bytes []byte
	taken bool
}

func (store *oneShotStdin) TakeCapturedStdin(_ context.Context, token string) ([]byte, error) {
	if token != "captured" || store.taken {
		return nil, errors.New("stdin was already consumed")
	}
	store.taken = true
	return append([]byte(nil), store.bytes...), nil
}

func TestReviewCaptureRealGitRangeDirtyPatchAndStdin(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &oneShotStdin{bytes: []byte("diff --git a/x b/x\n")}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), store, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("range preserves resolved objects", func(t *testing.T) {
		selector := reviewSelector(t, ports.ReviewTargetDiff, "HEAD~1...HEAD")
		material, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector)
		if err != nil || material.Target().NoChange() || !material.Valid() {
			t.Fatalf("range capture = %#v, %v", material, err)
		}
	})

	t.Run("dirty includes eligible untracked and index identity", func(t *testing.T) {
		writeReviewFile(t, filepath.Join(root, "tracked.txt"), "changed\n")
		writeReviewFile(t, filepath.Join(root, "untracked.txt"), "new\n")
		writeReviewFile(t, filepath.Join(root, "untracked space.txt"), "space\n")
		writeReviewFile(t, filepath.Join(root, "untracked-한글.txt"), "unicode\n")
		writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored\n")
		if err := os.MkdirAll(filepath.Join(root, ".mulgae", "diagnostics"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeReviewFile(t, filepath.Join(root, ".mulgae", "diagnostics", "doctor.json"), "{}\n")
		material, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDirty, "dirty"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := material.Target().IndexTreeID(); !ok {
			t.Fatal("dirty target did not bind index tree")
		}
		patch := string(material.Target().Bytes())
		if !strings.Contains(patch, "diff --git a/untracked.txt b/untracked.txt") ||
			!strings.Contains(patch, "diff --git \"a/untracked space.txt\" \"b/untracked space.txt\"") ||
			strings.Contains(patch, "diff --git a/ignored.txt b/ignored.txt") ||
			strings.Contains(patch, ".mulgae/") {
			t.Fatalf("dirty patch did not apply captured ignore decision: %q", patch)
		}
		if parsed, privateFree := parseUnifiedDiffPrivatePathFree(material.Target().Bytes()); !parsed || !privateFree {
			t.Fatalf("dirty patch with quoted paths = parsed %t private_free %t", parsed, privateFree)
		}
	})

	t.Run("patch rejects symlinks and source replacement", func(t *testing.T) {
		if err := os.Symlink("tracked.txt", filepath.Join(root, "link.patch")); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "link.patch")); err == nil {
			t.Fatal("symlink patch was accepted")
		}
		writeReviewFile(t, filepath.Join(root, "patch.diff"), "diff --git a/a b/a\n")
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "patch.diff")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "patch.diff")); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetPatch, "patch.diff")); err == nil {
			t.Fatal("removed patch source was accepted")
		}
	})

	t.Run("stdin is one shot", func(t *testing.T) {
		selector := reviewSelector(t, ports.ReviewTargetStdin, "captured")
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, selector); err == nil {
			t.Fatal("stdin capture was reusable")
		}
	})
}

func TestReviewCaptureStageUsesIndexNotWorktree(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "staged\n")
	reviewGit(t, root, "add", "tracked.txt")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "unstaged\n")
	writeReviewFile(t, filepath.Join(root, "untracked.txt"), "untracked\n")
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "ignored.go\n")
	writeReviewFile(t, filepath.Join(root, "ignored.go"), "package ignored\n")
	reviewGit(t, root, "add", "ignored.go")
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetStage, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	patch := string(material.Target().Bytes())
	if !strings.Contains(patch, "+staged") || strings.Contains(patch, "unstaged") || strings.Contains(patch, "untracked") || strings.Contains(patch, "ignored.go") {
		t.Fatalf("stage patch = %q", patch)
	}
	if material.Target().Identity().GitMode() != domain.GitTargetStage {
		t.Fatalf("Git mode = %q", material.Target().Identity().GitMode())
	}
	files, ok := material.Evidence().Files(ports.CapturedEvidenceIndex)
	if !ok || len(files) == 0 {
		t.Fatal("stage capture has no index evidence")
	}
	for _, file := range files {
		if file.Path().String() == "tracked.txt" && string(file.Bytes()) != "staged\n" {
			t.Fatalf("index bytes = %q", file.Bytes())
		}
	}
}

func TestReviewCaptureStageAllowsCredentialLikeFixturesAndUnrelatedTrackedContent(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, "unrelated-development.env"), "DATABASE_PASSWORD=development-only\n")
	reviewGit(t, root, "add", "unrelated-development.env")
	reviewGit(t, root, "commit", "-m", "unrelated fixture")

	fixture := strings.Join([]string{
		"changePassword: vi.fn()",
		"Authorization: Bearer abcdefghijklmnop",
		"api_key = placeholder-api-key",
		"-----BEGIN RSA PRIVATE KEY-----",
		"placeholder",
		"-----END RSA PRIVATE KEY-----",
	}, "\n") + "\n"
	writeReviewFile(t, filepath.Join(root, "security-fixtures.txt"), fixture)
	reviewGit(t, root, "add", "security-fixtures.txt")
	writeReviewFile(t, filepath.Join(root, "outside-stage.env"), "API_KEY=untracked-placeholder\n")

	material := captureReviewMaterial(t, root, ports.ReviewTargetStage, "stage")
	if !strings.Contains(string(material.Target().Bytes()), "security-fixtures.txt") {
		t.Fatalf("stage target omitted security fixture: %q", material.Target().Bytes())
	}
	paths := reviewFilePathSet(material.Snapshot().Files())
	for _, path := range []string{"security-fixtures.txt", "unrelated-development.env"} {
		if !paths[path] {
			t.Fatalf("transmitted snapshot paths omitted %q: %v", path, paths)
		}
	}
	indexFiles, ok := material.Evidence().Files(ports.CapturedEvidenceIndex)
	if !ok {
		t.Fatal("stage evidence omitted index files")
	}
	assertReviewFilesContain(t, indexFiles, "security-fixtures.txt", fixture)
	assertReviewMaterialExcludes(t, material, "outside-stage.env", "untracked-placeholder")
}

func TestReviewCaptureWorkspaceWithoutGitHonorsIgnoreFiles(t *testing.T) {
	root := t.TempDir()
	writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored\n")
	writeReviewFile(t, filepath.Join(root, "image.bin"), "\x00binary")
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "*.bin\n")
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if material.Target().Kind() != domain.TargetWorkspace || material.Target().Identity().Kind() != domain.TargetWorkspace {
		t.Fatalf("workspace target = %#v", material.Target())
	}
	var paths []string
	for _, file := range material.Snapshot().Files() {
		paths = append(paths, file.Path().String())
	}
	if strings.Contains(strings.Join(paths, ","), "ignored.txt") || strings.Contains(strings.Join(paths, ","), "image.bin") || !strings.Contains(strings.Join(paths, ","), "source.go") {
		t.Fatalf("workspace paths = %v", paths)
	}
	if _, ok := material.Evidence().Files(ports.CapturedEvidenceWorktree); !ok {
		t.Fatal("workspace capture has no worktree evidence")
	}
}

func TestReviewCaptureGitComparisonAppliesCommittedIgnoreAndDerivesTwoDirectoryView(t *testing.T) {
	root := reviewCaptureRepository(t)
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored before\n")
	writeReviewFile(t, filepath.Join(root, "kept.txt"), "before\n")
	reviewGit(t, root, "add", ".gitignore", "kept.txt")
	reviewGit(t, root, "add", "-f", "ignored.txt")
	reviewGit(t, root, "commit", "-m", "comparison base")
	base := strings.TrimSpace(string(reviewGitOutput(t, root, "rev-parse", "HEAD")))

	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored after\n")
	writeReviewFile(t, filepath.Join(root, "kept.txt"), "after\n")
	reviewGit(t, root, "add", "-f", "ignored.txt")
	reviewGit(t, root, "add", "kept.txt")
	reviewGit(t, root, "commit", "-m", "comparison head")

	material := captureReviewMaterial(t, root, ports.ReviewTargetDiff, base+"..HEAD")
	for _, side := range []ports.CapturedEvidenceSide{ports.CapturedEvidenceBase, ports.CapturedEvidenceHead} {
		files, ok := material.Evidence().Files(side)
		if !ok {
			t.Fatalf("comparison evidence omitted %q", side)
		}
		paths := reviewFilePathSet(files)
		if paths[".gitignore"] || paths["ignored.txt"] || !paths["kept.txt"] {
			t.Fatalf("comparison evidence %q ignored paths = %v", side, paths)
		}
	}
	workspace, err := material.ProviderWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	paths := reviewFilePathSet(workspace.Files())
	if !paths["before/kept.txt"] || !paths["after/kept.txt"] || paths["before/.gitignore"] || paths["after/ignored.txt"] {
		t.Fatalf("provider comparison view paths = %v", paths)
	}
}

func TestParseDiffSelectorUsesGitStandardForms(t *testing.T) {
	for _, test := range []struct {
		value                  string
		left, right            string
		mergeBase, indexTarget bool
	}{
		{value: "main", left: "main", indexTarget: true},
		{value: "main..topic", left: "main", right: "topic"},
		{value: "main...topic", left: "main", right: "topic", mergeBase: true},
	} {
		left, right, mergeBase, indexTarget, err := parseDiffSelector(test.value)
		if err != nil || left != test.left || right != test.right || mergeBase != test.mergeBase || indexTarget != test.indexTarget {
			t.Fatalf("parseDiffSelector(%q) = %q %q %t %t, %v", test.value, left, right, mergeBase, indexTarget, err)
		}
	}
	if _, _, _, _, err := parseDiffSelector("git"); err != nil {
		t.Fatal(err)
	}
}

func TestReviewCaptureRejectsUnicodeAndCaseCollisions(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, filepath.Join(root, "Readme"), "one\n")
	reviewGit(t, root, "add", "Readme")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+reviewGitOutput(t, root, "hash-object", "-w", "Readme")+",README")
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDirty, "dirty")); err == nil {
		t.Fatal("case-colliding index paths were accepted")
	}

	root = reviewCaptureRepository(t)
	anchored, err = ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	reviewGit(t, root, "config", "core.precomposeunicode", "false")
	writeReviewFile(t, filepath.Join(root, "é"), "one\n")
	reviewGit(t, root, "add", "é")
	reviewGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+reviewGitOutput(t, root, "hash-object", "-w", "é")+",e\u0301")
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetDirty, "dirty")); err == nil {
		t.Fatal("NFC/NFD-colliding index paths were accepted")
	}
}

func TestReviewCaptureRejectsEligibleSpecialFile(t *testing.T) {
	root := reviewCaptureRepository(t)
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "capture.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace")); err == nil || !strings.Contains(err.Error(), "capture.fifo") || !strings.Contains(err.Error(), ".mulgaeignore") {
		t.Fatalf("eligible special file error = %v", err)
	}
	writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "capture.fifo\n")
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace")); err != nil {
		t.Fatalf("ignored special file still blocked capture: %v", err)
	}
}

func TestIntegrationReviewCaptureScopeMatrix(t *testing.T) {
	t.Run("workspace captures full Git worktree evidence", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		writeReviewFile(t, filepath.Join(root, "untracked.txt"), "worktree only\n")
		material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace")
		if material.Target().Kind() != domain.TargetWorkspace {
			t.Fatalf("workspace target kind = %q", material.Target().Kind())
		}
		assertReviewFilesContain(t, material.Snapshot().Files(), "tracked.txt", "second\n")
		assertReviewFilesContain(t, material.Snapshot().Files(), "untracked.txt", "worktree only\n")
		files, ok := material.Evidence().Files(ports.CapturedEvidenceWorktree)
		if !ok {
			t.Fatal("workspace evidence omitted worktree")
		}
		assertReviewFilesContain(t, files, "untracked.txt", "worktree only\n")
	})

	t.Run("stage and dirty separate index worktree and untracked changes", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		writeReviewFile(t, filepath.Join(root, "staged.txt"), "base staged\n")
		writeReviewFile(t, filepath.Join(root, "unstaged.txt"), "base unstaged\n")
		reviewGit(t, root, "add", "staged.txt", "unstaged.txt")
		reviewGit(t, root, "commit", "-m", "scope fixtures")
		writeReviewFile(t, filepath.Join(root, "staged.txt"), "index version\n")
		reviewGit(t, root, "add", "staged.txt")
		writeReviewFile(t, filepath.Join(root, "unstaged.txt"), "worktree version\n")
		writeReviewFile(t, filepath.Join(root, "untracked.txt"), "new version\n")

		stage := captureReviewMaterial(t, root, ports.ReviewTargetStage, "stage")
		stagePatch := string(stage.Target().Bytes())
		if !strings.Contains(stagePatch, "index version") || strings.Contains(stagePatch, "worktree version") || strings.Contains(stagePatch, "new version") {
			t.Fatalf("stage patch = %q", stagePatch)
		}
		if _, ok := stage.Evidence().Files(ports.CapturedEvidenceIndex); !ok {
			t.Fatal("stage evidence omitted index")
		}

		dirty := captureReviewMaterial(t, root, ports.ReviewTargetDirty, "dirty")
		dirtyPatch := string(dirty.Target().Bytes())
		for _, value := range []string{"index version", "worktree version", "new version"} {
			if !strings.Contains(dirtyPatch, value) {
				t.Fatalf("dirty patch omitted %q: %q", value, dirtyPatch)
			}
		}
		if _, ok := dirty.Evidence().Files(ports.CapturedEvidenceBase); !ok {
			t.Fatal("dirty evidence omitted base")
		}
		worktree, ok := dirty.Evidence().Files(ports.CapturedEvidenceWorktree)
		if !ok {
			t.Fatal("dirty evidence omitted worktree")
		}
		assertReviewFilesContain(t, worktree, "staged.txt", "index version\n")
		assertReviewFilesContain(t, worktree, "unstaged.txt", "worktree version\n")
		assertReviewFilesContain(t, worktree, "untracked.txt", "new version\n")
	})

	t.Run("diff forms retain distinct Git semantics", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		mainBranch := reviewGitOutput(t, root, "branch", "--show-current")
		base := reviewGitOutput(t, root, "rev-parse", "HEAD")
		reviewGit(t, root, "checkout", "-b", "topic")
		writeReviewFile(t, filepath.Join(root, "topic.txt"), "topic\n")
		reviewGit(t, root, "add", "topic.txt")
		reviewGit(t, root, "commit", "-m", "topic")
		topic := reviewGitOutput(t, root, "rev-parse", "HEAD")
		reviewGit(t, root, "checkout", mainBranch)
		writeReviewFile(t, filepath.Join(root, "main.txt"), "main\n")
		reviewGit(t, root, "add", "main.txt")
		reviewGit(t, root, "commit", "-m", "main")
		main := reviewGitOutput(t, root, "rev-parse", "HEAD")

		writeReviewFile(t, filepath.Join(root, "indexed.txt"), "index\n")
		reviewGit(t, root, "add", "indexed.txt")
		indexDiff := captureReviewMaterial(t, root, ports.ReviewTargetDiff, main)
		if indexDiff.Target().Identity().BaseObjectID() != main || !strings.Contains(string(indexDiff.Target().Bytes()), "indexed.txt") {
			t.Fatalf("A->index identity/patch = %#v %q", indexDiff.Target().Identity(), indexDiff.Target().Bytes())
		}

		direct := captureReviewMaterial(t, root, ports.ReviewTargetDiff, main+".."+topic)
		if direct.Target().Identity().BaseObjectID() != main || direct.Target().Identity().HeadObjectID() != topic ||
			!strings.Contains(string(direct.Target().Bytes()), "main.txt") || !strings.Contains(string(direct.Target().Bytes()), "topic.txt") {
			t.Fatalf("A..B identity/patch = %#v %q", direct.Target().Identity(), direct.Target().Bytes())
		}
		merge := captureReviewMaterial(t, root, ports.ReviewTargetDiff, main+"..."+topic)
		if merge.Target().Identity().BaseObjectID() != base || merge.Target().Identity().HeadObjectID() != topic ||
			strings.Contains(string(merge.Target().Bytes()), "main.txt") || !strings.Contains(string(merge.Target().Bytes()), "topic.txt") {
			t.Fatalf("A...B identity/patch = %#v %q", merge.Target().Identity(), merge.Target().Bytes())
		}
	})

	t.Run("non Git and unborn HEAD reject Git-only modes", func(t *testing.T) {
		for _, fixture := range []struct {
			name string
			root func(*testing.T) string
		}{
			{name: "non-git", root: func(t *testing.T) string {
				root := t.TempDir()
				writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
				return root
			}},
			{name: "unborn", root: func(t *testing.T) string {
				root := t.TempDir()
				reviewGit(t, root, "init")
				writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
				return root
			}},
		} {
			t.Run(fixture.name, func(t *testing.T) {
				root := fixture.root(t)
				if material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace"); material.Target().Kind() != domain.TargetWorkspace {
					t.Fatalf("workspace kind = %q", material.Target().Kind())
				}
				for _, selector := range []struct {
					kind  ports.ReviewTargetSelectorKind
					value string
				}{{ports.ReviewTargetStage, "stage"}, {ports.ReviewTargetDirty, "dirty"}, {ports.ReviewTargetDiff, "HEAD"}} {
					if err := captureReviewError(t, root, selector.kind, selector.value); err == nil || !strings.Contains(err.Error(), "review target") {
						t.Fatalf("%s error = %v", selector.kind, err)
					}
				}
			})
		}
	})
}

func TestIntegrationReviewCaptureIgnoreRulesAndMulgaeIgnoreAcrossModes(t *testing.T) {
	t.Run("root nested negation and anchored patterns", func(t *testing.T) {
		root := t.TempDir()
		for path, contents := range map[string]string{
			"keep.go": "package keep\n", "root-only.txt": "ignored\n", "keep.tmp": "included\n", "drop.tmp": "ignored\n",
			"nested/root-only.txt": "included\n", "nested/nested-only.txt": "ignored\n", "nested/deep/nested-only.txt": "included\n",
			"secret.txt": "ignored\n", "nested/secret.txt": "included\n",
		} {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o700); err != nil {
				t.Fatal(err)
			}
			writeReviewFile(t, filepath.Join(root, path), contents)
		}
		writeReviewFile(t, filepath.Join(root, ".gitignore"), "/root-only.txt\n*.tmp\n!keep.tmp\n")
		writeReviewFile(t, filepath.Join(root, "nested", ".gitignore"), "/nested-only.txt\n")
		writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "/secret.txt\n")
		material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace")
		paths := reviewFilePathSet(material.Snapshot().Files())
		for _, path := range []string{"keep.go", "keep.tmp", "nested/root-only.txt", "nested/deep/nested-only.txt", "nested/secret.txt"} {
			if !paths[path] {
				t.Errorf("workspace snapshot omitted %q: %v", path, paths)
			}
		}
		for _, path := range []string{"root-only.txt", "drop.tmp", "nested/nested-only.txt", "secret.txt"} {
			if paths[path] {
				t.Errorf("workspace snapshot retained ignored path %q: %v", path, paths)
			}
		}
	})

	t.Run("mulgaeignore filters target snapshot and every evidence side", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep base\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "API_KEY=ignored-base-placeholder\n")
		reviewGit(t, root, "add", "keep.txt", "ignored.txt")
		reviewGit(t, root, "commit", "-m", "ignore base")
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep committed\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "Authorization: Bearer ignored-committed-placeholder\n")
		reviewGit(t, root, "commit", "-am", "ignore changed")
		writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), "ignored.txt\n")
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep index\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "DATABASE_PASSWORD=ignored-index-placeholder\n")
		reviewGit(t, root, "add", "keep.txt", "ignored.txt")

		for _, selector := range []struct {
			name  string
			kind  ports.ReviewTargetSelectorKind
			value string
		}{
			{"workspace", ports.ReviewTargetWorkspace, "workspace"},
			{"stage", ports.ReviewTargetStage, "stage"},
			{"dirty", ports.ReviewTargetDirty, "dirty"},
			{"diff", ports.ReviewTargetDiff, "HEAD~1..HEAD"},
		} {
			t.Run(selector.name, func(t *testing.T) {
				material := captureReviewMaterial(t, root, selector.kind, selector.value)
				assertReviewMaterialExcludes(t, material, "ignored.txt", "ignored")
			})
		}
	})
}

func TestAdmittedIgnoreControlPathRejectsReservedParent(t *testing.T) {
	t.Parallel()

	for _, path := range []string{".gitignore", ".mulgaeignore", "nested/.gitignore", "nested/.mulgaeignore"} {
		if !admittedIgnoreControlPath(path) {
			t.Errorf("admittedIgnoreControlPath(%q) = false", path)
		}
	}
	for _, path := range []string{"ordinary.txt", ".git/config/.gitignore", ".mulgae/state/.mulgaeignore", ".gitignore/nested/.gitignore"} {
		if admittedIgnoreControlPath(path) {
			t.Errorf("admittedIgnoreControlPath(%q) = true", path)
		}
	}
}

func TestIntegrationReviewCapturePreservesBinaryAndRejectsSpecialPathsWithGuidance(t *testing.T) {
	for _, fixture := range []struct {
		name string
		path string
		make func(*testing.T, string)
	}{
		{name: "binary", path: "image.bin", make: func(t *testing.T, path string) { writeReviewFile(t, path, "\x00binary") }},
		{name: "symlink", path: "link.txt", make: func(t *testing.T, path string) {
			if err := os.Symlink("source.go", path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fifo", path: "events.fifo", make: func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := t.TempDir()
			writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
			fixture.make(t, filepath.Join(root, fixture.path))
			err := captureReviewError(t, root, ports.ReviewTargetWorkspace, "workspace")
			if fixture.name == "binary" {
				material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace")
				for _, file := range material.Snapshot().Files() {
					if file.Path().String() == fixture.path && file.MediaType() == "application/octet-stream" && bytes.Equal(file.Bytes(), []byte("\x00binary")) {
						return
					}
				}
				t.Fatal("binary file was not preserved byte-for-byte")
			}
			if err == nil || !strings.Contains(err.Error(), fixture.path) || !strings.Contains(err.Error(), ".mulgaeignore") {
				t.Fatalf("workspace rejection = %v", err)
			}
			writeReviewFile(t, filepath.Join(root, ".mulgaeignore"), fixture.path+"\n")
			if material := captureReviewMaterial(t, root, ports.ReviewTargetWorkspace, "workspace"); reviewFilePathSet(material.Snapshot().Files())[fixture.path] {
				t.Fatalf("ignored %s remained in snapshot", fixture.path)
			}
		})
	}
}

func captureReviewMaterial(t *testing.T, root string, kind ports.ReviewTargetSelectorKind, value string) ports.CapturedReviewMaterial {
	t.Helper()
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	material, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, kind, value))
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func captureReviewError(t *testing.T, root string, kind ports.ReviewTargetSelectorKind, value string) error {
	t.Helper()
	anchored, err := ports.NewAnchoredRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewReviewTargetCapturer(NewExecRunner(), &oneShotStdin{bytes: []byte("x")}, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, kind, value))
	return err
}

func reviewFilePathSet(files []ports.WorkspaceSnapshotFile) map[string]bool {
	paths := make(map[string]bool, len(files))
	for _, file := range files {
		paths[file.Path().String()] = true
	}
	return paths
}

func assertReviewFilesContain(t *testing.T, files []ports.WorkspaceSnapshotFile, path, contents string) {
	t.Helper()
	for _, file := range files {
		if file.Path().String() == path {
			if string(file.Bytes()) != contents {
				t.Fatalf("%s bytes = %q, want %q", path, file.Bytes(), contents)
			}
			return
		}
	}
	t.Fatalf("files omitted %q", path)
}

func assertReviewMaterialExcludes(t *testing.T, material ports.CapturedReviewMaterial, path, _ string) {
	t.Helper()
	if strings.Contains(string(material.Target().Bytes()), "diff --git a/"+path+" b/"+path) ||
		strings.Contains(string(material.Target().Bytes()), "diff --git \"a/"+path+"\" \"b/"+path+"\"") {
		t.Fatalf("target retained ignored path/content: %q", material.Target().Bytes())
	}
	for _, file := range material.Snapshot().Files() {
		if file.Path().String() == path {
			t.Fatalf("snapshot retained ignored path %q", path)
		}
	}
	for _, side := range []ports.CapturedEvidenceSide{ports.CapturedEvidenceBase, ports.CapturedEvidenceHead, ports.CapturedEvidenceIndex, ports.CapturedEvidenceWorktree} {
		files, ok := material.Evidence().Files(side)
		if !ok {
			continue
		}
		for _, file := range files {
			if file.Path().String() == path {
				t.Fatalf("%s evidence retained ignored path %q", side, path)
			}
		}
	}
}
func reviewCaptureRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	reviewGit(t, root, "init")
	reviewGit(t, root, "config", "user.email", "test@example.invalid")
	reviewGit(t, root, "config", "user.name", "Test")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "base\n")
	reviewGit(t, root, "add", "tracked.txt")
	reviewGit(t, root, "commit", "-m", "base")
	writeReviewFile(t, filepath.Join(root, "tracked.txt"), "second\n")
	reviewGit(t, root, "commit", "-am", "second")
	return root
}

func reviewGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("/usr/bin/git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
func reviewGitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("/usr/bin/git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}

func writeReviewFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func reviewSelector(t *testing.T, kind ports.ReviewTargetSelectorKind, value string) ports.ReviewTargetSelector {
	t.Helper()
	selector, err := ports.NewReviewTargetSelector(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	return selector
}
