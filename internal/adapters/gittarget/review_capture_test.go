//go:build darwin && arm64

package gittarget

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/irootkernel/kkachi-agent-review/internal/adapters/filesystem"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUIWorkspaceCaptureIncludesBoundedVisualInputs(t *testing.T) {
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
	if !foundVisual || !strings.Contains(string(material.ProjectContext()), `"status":"ready"`) {
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
	if _, err := adapter.CaptureReviewTargetWithArtistInputs(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace"), inputs); err == nil || !strings.Contains(err.Error(), "visual references") {
		t.Fatalf("missing artist visuals error = %v", err)
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
		if err := os.MkdirAll(filepath.Join(root, ".kar", "diagnostics"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeReviewFile(t, filepath.Join(root, ".kar", "diagnostics", "doctor.json"), "{}\n")
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
			strings.Contains(patch, ".kar/") {
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
	writeReviewFile(t, filepath.Join(root, ".karignore"), "ignored.go\n")
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

func TestReviewCaptureWorkspaceWithoutGitHonorsIgnoreFiles(t *testing.T) {
	root := t.TempDir()
	writeReviewFile(t, filepath.Join(root, "source.go"), "package source\n")
	writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored\n")
	writeReviewFile(t, filepath.Join(root, "image.bin"), "\x00binary")
	writeReviewFile(t, filepath.Join(root, ".gitignore"), "ignored.txt\n")
	writeReviewFile(t, filepath.Join(root, ".karignore"), "*.bin\n")
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
	if _, err := adapter.CaptureReviewTarget(context.Background(), anchored, reviewSelector(t, ports.ReviewTargetWorkspace, "workspace")); err == nil || !strings.Contains(err.Error(), "capture.fifo") || !strings.Contains(err.Error(), ".karignore") {
		t.Fatalf("eligible special file error = %v", err)
	}
	writeReviewFile(t, filepath.Join(root, ".karignore"), "capture.fifo\n")
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

func TestIntegrationReviewCaptureIgnoreRulesAndKarIgnoreAcrossModes(t *testing.T) {
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
		writeReviewFile(t, filepath.Join(root, ".karignore"), "/secret.txt\n")
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

	t.Run("karignore filters target snapshot and every evidence side", func(t *testing.T) {
		root := reviewCaptureRepository(t)
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep base\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored base\n")
		reviewGit(t, root, "add", "keep.txt", "ignored.txt")
		reviewGit(t, root, "commit", "-m", "ignore base")
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep committed\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored committed\n")
		reviewGit(t, root, "commit", "-am", "ignore changed")
		writeReviewFile(t, filepath.Join(root, ".karignore"), "ignored.txt\n")
		writeReviewFile(t, filepath.Join(root, "keep.txt"), "keep index\n")
		writeReviewFile(t, filepath.Join(root, "ignored.txt"), "ignored index\n")
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

func TestIntegrationReviewCaptureRejectsEligibleNonTextAndSpecialPathsWithGuidance(t *testing.T) {
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
			if err == nil || !strings.Contains(err.Error(), fixture.path) || !strings.Contains(err.Error(), ".karignore") {
				t.Fatalf("workspace rejection = %v", err)
			}
			writeReviewFile(t, filepath.Join(root, ".karignore"), fixture.path+"\n")
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
