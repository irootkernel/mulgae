package reviewrun

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestIntegrationLiveArtistInputsUseIndexAndRetainBeforeAfterRasters(t *testing.T) {
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git := func(arguments ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", rootPath}, arguments...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(rootPath, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := []byte{137, 80, 78, 71, 13, 10, 26, 10, 1}
	after := append(append([]byte(nil), before...), 2)
	worktree := append(append([]byte(nil), before...), 3)
	git("init", "--quiet")
	write("brief.md", []byte("Original brief\n"))
	write("design/nested/home.png", before)
	git("add", ".")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "Fixture")
	write("brief.md", []byte("Staged task requirements\n"))
	write("design/nested/home.png", after)
	git("add", ".")
	write("brief.md", []byte("Unselected worktree requirements\n"))
	write("design/nested/home.png", worktree)
	root, _ := ports.NewAnchoredRoot(rootPath)
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.NewExecRunner(), nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceStage, "")
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	inputs, _ := ports.NewArtistReviewInputs("brief.md", []string{"design/**/*.png"})
	artist, err := prepareLiveArtistContext(context.Background(), source, inputs)
	if err != nil || !artist.ready || !bytes.Equal(artist.task, []byte("Staged task requirements\n")) || len(artist.images) != 2 {
		t.Fatalf("index artist inputs: %v, ready=%v images=%d task=%s", err, artist.ready, len(artist.images), artist.task)
	}
	if artist.images[0].Side() != evidence.SideBase || !bytes.Equal(artist.images[0].Bytes(), before) || artist.images[1].Side() != evidence.SideIndex || !bytes.Equal(artist.images[1].Bytes(), after) {
		t.Fatal("selected rasters used worktree contents or lost source side")
	}
	var manifest struct {
		SchemaVersion  string `json:"schema_version"`
		SourceIdentity string `json:"source_identity_sha256"`
		Visuals        []struct {
			Path   string `json:"path"`
			Side   string `json:"side"`
			SHA256 string `json:"sha256"`
		} `json:"visual_assets"`
	}
	if err := json.Unmarshal(artist.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	identity, _ := evidence.NewLiveSourceIdentity(source.Target())
	if manifest.SchemaVersion != "mulgae-live-artist-inputs.v1" || manifest.SourceIdentity != identity.SHA256() || len(manifest.Visuals) != 2 || manifest.Visuals[0].Path != "design/nested/home.png" || manifest.Visuals[1].SHA256 != artist.images[1].FileSHA256() {
		t.Fatal("visual manifest lost verified native identity")
	}
	missing, _ := ports.NewArtistReviewInputs("missing.md", inputs.DesignSpecGlobs())
	if _, err := prepareLiveArtistContext(context.Background(), source, missing); err == nil {
		t.Fatal("explicit missing task brief admitted")
	}
	automatic, _ := ports.NewAutomaticArtistReviewInputs("missing.md", inputs.DesignSpecGlobs())
	codeOnly, err := prepareLiveArtistContext(context.Background(), source, automatic)
	if err != nil || codeOnly.ready || len(codeOnly.task) != 0 {
		t.Fatalf("automatic code-only admission changed: %v", err)
	}
}

func TestLiveArtistGlobRejectsUnsafePatterns(t *testing.T) {
	for _, pattern := range []string{"", "../*.png", "/private/*.png", "design/[a].png", "design\\*.png"} {
		if _, err := compileLiveArtistGlob(pattern); err == nil {
			t.Fatalf("unsafe image glob admitted: %s", pattern)
		}
	}
	pattern, err := compileLiveArtistGlob("design/**/*.png")
	if err != nil || !pattern.MatchString("design/home.png") || !pattern.MatchString("design/nested/home.png") || pattern.MatchString("other/home.png") {
		t.Fatalf("recursive project-relative image discovery: %v", err)
	}
}
