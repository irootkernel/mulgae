//go:build darwin && arm64

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image/png"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	adapterjsonschema "github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

const artistReviewSchema = "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json"

type artistE2EBBox struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type artistE2EVisual struct {
	Path         string        `json:"path"`
	SHA256       string        `json:"sha256"`
	BBox         artistE2EBBox `json:"bbox"`
	Verification string        `json:"verification"`
}

func TestIntegrationArtistHomepageWorkspaceReview(t *testing.T) {
	repository := repositoryRoot(t)
	project := canonicalTestTempDir(t)
	if err := os.Chmod(project, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(repository, "internal", "app", "review", "testdata", "artist-homepage")
	mustCopyArtistFixture(t, filepath.Join(fixture, "ux-ui-info.md"), filepath.Join(project, "ux-ui-info.md"))
	mustCopyArtistFixture(t, filepath.Join(fixture, "before.html"), filepath.Join(project, "index.html"))

	designDirectory := filepath.Join(project, "design-specs")
	if err := os.MkdirAll(designDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	referencePath := filepath.Join(designDirectory, "homepage-before.png")
	currentPath := filepath.Join(designDirectory, "homepage-current.png")
	captureArtistHomepage(t, filepath.Join(project, "index.html"), referencePath)
	mustCopyArtistFixture(t, filepath.Join(fixture, "after.html"), filepath.Join(project, "index.html"))
	captureArtistHomepage(t, filepath.Join(project, "index.html"), currentPath)

	referenceSHA := artistFileSHA256(t, referencePath)
	currentSHA := artistFileSHA256(t, currentPath)
	if referenceSHA == currentSHA {
		t.Fatal("Playwright produced identical before and current screenshots")
	}
	assertArtistPNG(t, referencePath)
	assertArtistPNG(t, currentPath)
	if _, err := os.Stat(filepath.Join(project, ".git")); !os.IsNotExist(err) {
		t.Fatalf("homepage fixture unexpectedly has Git metadata: %v", err)
	}
	assertArtistConfigLocality(t, project)

	afterBytes, err := os.ReadFile(filepath.Join(project, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	const evidenceLine = `        <button class="primary-action">Start free</button>`
	lineNumber := artistEvidenceLine(t, afterBytes, evidenceLine)
	bbox := artistE2EBBox{X: 1190, Y: 26, Width: 72, Height: 24}
	providerOutput := artistProviderOutput(t, lineNumber, evidenceLine+"\n", currentSHA, bbox)

	binary := buildMulgaeBinary(t, repository)
	installedUser, err := user.Current()
	if err != nil || installedUser == nil || !filepath.IsAbs(installedUser.HomeDir) {
		t.Fatalf("current native home unavailable: user=%#v err=%v", installedUser, err)
	}
	providerDirectory := canonicalTestTempDir(t)
	agyLog := filepath.Join(canonicalTestTempDir(t), "agy-artist.jsonl")
	zcodeLog := filepath.Join(canonicalTestTempDir(t), "zcode-artist.jsonl")
	agyExecutable := filepath.Join(providerDirectory, "agy")
	zcodeNode := filepath.Join(providerDirectory, "node")
	zcodeLauncher := filepath.Join(providerDirectory, "zcode.mjs")
	buildFakeAGYWithReviewOutput(t, repository, agyExecutable, agyLog, string(providerOutput))
	buildFakeZCode(t, repository, zcodeNode, zcodeLauncher, zcodeLog, "success")
	environment := isolatedMulgaeEnvWith(t, installedUser.HomeDir, providerDirectory)
	environment = append(environment, "MULGAE_FAKE_AGY_LOG="+agyLog)

	initialized := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"init", "--providers", "agy,zcode", "--project-kind", "ui", "--roles", "artist",
		"--agy-executable", agyExecutable,
		"--zcode-node-executable", zcodeNode, "--zcode-launcher", zcodeLauncher, "--output", "json")
	if initialized.exitCode != 0 || len(initialized.stderr) != 0 {
		t.Fatalf("initialize UI fixture: exit=%d stdout=%s stderr=%s", initialized.exitCode, initialized.stdout, initialized.stderr)
	}
	configBytes, err := os.ReadFile(filepath.Join(project, ".mulgae", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(configBytes, []byte("primary_provider: \"agy\"")) ||
		bytes.Contains(configBytes, []byte("fallback_provider")) {
		t.Fatalf("artist route is not AGY alone:\n%s", configBytes)
	}

	reviewResult := runMulgaeBinaryWithEnv(t, binary, project, environment,
		"review", "--workspace", "--roles", "artist",
		"--artist-brief", "ux-ui-info.md", "--artist-design-specs", "design-specs/**/*.png",
		"--output", "json")
	if reviewResult.exitCode != 1 || len(reviewResult.stderr) != 0 {
		t.Fatalf("artist workspace review: exit=%d stdout=%s stderr=%s", reviewResult.exitCode, reviewResult.stdout, reviewResult.stderr)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(reviewResult.stdout, &envelope); err != nil {
		t.Fatalf("decode review envelope: %v", err)
	}
	if envelope.Result.Kind != "review_started" || envelope.Result.SessionID == nil || envelope.Result.RunID == nil || envelope.Result.ReviewArtifactURI == nil {
		t.Fatalf("artist review did not publish: %#v", envelope)
	}
	if _, err := os.Stat(filepath.Join(project, ".git")); !os.IsNotExist(err) {
		t.Fatalf("workspace review created Git metadata: %v", err)
	}
	assertNoProjectLaneLocks(t, project)

	artifactBytes, err := os.ReadFile(filepath.Join(project, *envelope.Result.ReviewArtifactURI))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := adapterjsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	schemaID, err := ports.ParseAssetID(artistReviewSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), schemaID, artifactBytes); err != nil {
		t.Fatalf("artist final artifact is not v3-valid: %v", err)
	}
	assertArtistFinalArtifact(t, artifactBytes, currentSHA, bbox)
	assertArtistCapturedArchive(t, project, *envelope.Result.SessionID, *envelope.Result.RunID, referenceSHA, currentSHA)
	assertArtistPromptFraming(t, readFakeAGYObservations(t, agyLog), referenceSHA, currentSHA)
}

func assertArtistConfigLocality(t *testing.T, project string) {
	t.Helper()
	root, err := ports.NewAnchoredRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	source, err := adapterconfig.NewLocalConfigSource(root, true)
	if err != nil {
		t.Fatalf("pre-init config source: %v", err)
	}
	proof, err := source.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapterconfig.NewFilesystemLocalityAttestor().Attest(context.Background(), request); err != nil {
		info, _ := os.Stat(project)
		entries, _ := os.ReadDir(project)
		t.Fatalf("pre-init config locality: %v (mode=%v entries=%v)", err, info.Mode(), entries)
	}
}

func captureArtistHomepage(t *testing.T, htmlPath, screenshotPath string) {
	t.Helper()
	npx, err := exec.LookPath("npx")
	if err != nil {
		artistE2EUnavailable(t, "npx is unavailable: %v", err)
	}
	channel := os.Getenv("PLAYWRIGHT_CHANNEL")
	if channel == "" {
		channel = "chrome"
	}
	pageURL := (&url.URL{Scheme: "file", Path: htmlPath}).String()
	command := exec.Command(npx, "--offline", "playwright", "screenshot", "--channel", channel,
		"--viewport-size", "1280,720", "--color-scheme", "light", "--wait-for-selector", ".primary-action", pageURL, screenshotPath)
	if output, runErr := command.CombinedOutput(); runErr != nil {
		artistE2EUnavailable(t, "Playwright screenshot failed: %v\n%s", runErr, output)
	}
}

func artistE2EUnavailable(t *testing.T, format string, arguments ...any) {
	t.Helper()
	t.Fatalf(format, arguments...)
}

func mustCopyArtistFixture(t *testing.T, source, destination string) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteTestFile(t, destination, contents)
}

func artistFileSHA256(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func assertArtistPNG(t *testing.T, path string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := png.DecodeConfig(bytes.NewReader(contents))
	if err != nil || configuration.Width != 1280 || configuration.Height != 720 {
		t.Fatalf("Playwright PNG %q = %#v, %v", path, configuration, err)
	}
}

func artistEvidenceLine(t *testing.T, contents []byte, exact string) int {
	t.Helper()
	for index, line := range strings.Split(string(contents), "\n") {
		if line == exact {
			return index + 1
		}
	}
	t.Fatalf("evidence line %q is absent", exact)
	return 0
}

func artistProviderOutput(t *testing.T, line int, quote, screenshotSHA string, bbox artistE2EBBox) []byte {
	t.Helper()
	document := map[string]any{
		"schema_version": "mulgae-provider-review-output.v1",
		"summary":        "The primary homepage action has a material sizing and placement regression.",
		"completeness":   "complete",
		"limitations":    []string{},
		"findings": []any{map[string]any{
			"severity": "high", "title": "Primary action is undersized and detached from the hero",
			"description":    "The current primary action is only 72×24 px and is fixed in the header corner instead of remaining adjacent to the hero copy.",
			"recommendation": "Restore the primary action beside the hero copy with a minimum 160×48 px target and strong foreground contrast.",
			"confidence":     "high",
			"evidence": []any{map[string]any{
				"current": map[string]any{"path": "index.html", "side": "worktree", "line_start": line, "line_end": line, "quote": quote},
				"visual":  map[string]any{"path": "current/design-specs/homepage-current.png", "sha256": screenshotSHA, "bbox": bbox},
			}},
		}},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertArtistFinalArtifact(t *testing.T, contents []byte, screenshotSHA string, bbox artistE2EBBox) {
	t.Helper()
	var artifact struct {
		SchemaVersion string `json:"schema_version"`
		Findings      []struct {
			Role             string `json:"role"`
			ProviderInstance string `json:"provider_instance"`
			Evidence         []struct {
				Current struct {
					Side         string `json:"side"`
					Path         string `json:"path"`
					Verification string `json:"verification"`
				} `json:"current"`
				Visual *artistE2EVisual `json:"visual"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(contents, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "mulgae-review-artifact.v1" || len(artifact.Findings) != 1 ||
		artifact.Findings[0].Role != "artist" || artifact.Findings[0].ProviderInstance != "agy-artist" ||
		len(artifact.Findings[0].Evidence) != 1 {
		t.Fatalf("unexpected artist artifact: %#v", artifact)
	}
	evidence := artifact.Findings[0].Evidence[0]
	if evidence.Current.Path != "index.html" || evidence.Current.Side != "worktree" || evidence.Current.Verification != "verified" ||
		evidence.Visual == nil || evidence.Visual.Path != "current/design-specs/homepage-current.png" || evidence.Visual.SHA256 != screenshotSHA ||
		evidence.Visual.BBox != bbox || evidence.Visual.Verification != "verified" {
		t.Fatalf("artist evidence was not preserved: %#v", evidence)
	}
}

func assertArtistCapturedArchive(t *testing.T, project, sessionID, runID, referenceSHA, currentSHA string) {
	t.Helper()
	material := restoreTestCapturedReviewArchive(t, project, sessionID, runID)
	want := map[string]string{
		"design-specs/homepage-before.png":  referenceSHA,
		"design-specs/homepage-current.png": currentSHA,
	}
	for _, file := range material.Snapshot().Files() {
		if expected, ok := want[file.Path().String()]; ok && !file.IsText() && file.SHA256() == expected {
			delete(want, file.Path().String())
		}
	}
	if len(want) != 0 || !bytes.Contains(material.ProjectContext(), []byte(`"status":"ready"`)) {
		t.Fatalf("captured artist archive is incomplete: missing=%v context=%s", want, material.ProjectContext())
	}
	brief, err := os.ReadFile(filepath.Join(project, ".mulgae", sessionID, runID, "inputs", "artist-brief.md"))
	if err != nil || !bytes.Contains(brief, []byte("Homepage visual review")) {
		t.Fatalf("published artist brief = %q, %v", brief, err)
	}
	visuals, err := os.ReadFile(filepath.Join(project, ".mulgae", sessionID, runID, "inputs", "artist-visual-assets.json"))
	if err != nil || !bytes.Contains(visuals, []byte(referenceSHA)) || !bytes.Contains(visuals, []byte(currentSHA)) {
		t.Fatalf("published artist visual manifest = %q, %v", visuals, err)
	}
}

func assertArtistPromptFraming(t *testing.T, observations []fakeAGYObservation, referenceSHA, currentSHA string) {
	t.Helper()
	var reviewPrompt string
	for _, observation := range observations {
		if observation.Prompt != "@roadmap.md" && !slicesEqual(observation.Argv, []string{"--version"}) {
			reviewPrompt = observation.Prompt
		}
	}
	for _, expected := range []string{
		"The primary call to action must remain adjacent to the hero copy",
		`"status":"ready"`,
		`"path":"current/design-specs/homepage-before.png"`, referenceSHA,
		`"path":"current/design-specs/homepage-current.png"`, currentSHA,
	} {
		if !strings.Contains(reviewPrompt, expected) {
			t.Fatalf("artist prompt omitted %q: %s", expected, reviewPrompt)
		}
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
