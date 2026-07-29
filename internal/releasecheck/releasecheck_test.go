//go:build releasecheck

package releasecheck_test

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	modulePath            = "github.com/irootkernel/mulgae"
	versionSchema         = "mulgae-version.v1"
	releaseBinaryEnv      = "MULGAE_RELEASE_BINARY"
	releaseGOBINEnv       = "MULGAE_RELEASE_GOBIN"
	releaseVersionEnv     = "MULGAE_RELEASE_VERSION"
	releaseRevisionEnv    = "MULGAE_RELEASE_REVISION"
	expectedProduct       = "mulgae"
	expectedBinaryName    = "mulgae"
	expectedReadmeInstall = "go install github.com/irootkernel/mulgae@latest"
)

type versionDocument struct {
	SchemaVersion string  `json:"schema_version"`
	Product       string  `json:"product"`
	Version       string  `json:"version"`
	Module        string  `json:"module"`
	ModuleSum     *string `json:"module_sum"`
	VCSRevision   *string `json:"vcs_revision"`
}

func TestInstalledRootModuleContract(t *testing.T) {
	binary := requiredEnvironment(t, releaseBinaryEnv)
	gobin := requiredEnvironment(t, releaseGOBINEnv)
	version := requiredEnvironment(t, releaseVersionEnv)
	revision := requiredEnvironment(t, releaseRevisionEnv)

	assertInstalledBinary(t, binary, gobin)
	assertEmbeddedBuildInfo(t, binary, revision)

	wantHuman := expectedProduct + " " + version + "\n"
	for _, arguments := range [][]string{{"--version"}, {"version"}} {
		stdout, stderr := runInstalled(t, binary, arguments...)
		if stdout != wantHuman || stderr != "" {
			t.Fatalf("%v output = stdout %q stderr %q, want %q and empty stderr", arguments, stdout, stderr, wantHuman)
		}
	}

	stdout, stderr := runInstalled(t, binary, "version", "--output", "json")
	if stderr != "" {
		t.Fatalf("JSON version stderr = %q, want empty", stderr)
	}
	var document versionDocument
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode JSON version: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		t.Fatalf("JSON version trailing data: %v", err)
	}
	if document.SchemaVersion != versionSchema ||
		document.Product != expectedProduct ||
		document.Version != version ||
		document.Module != modulePath ||
		document.ModuleSum != nil ||
		document.VCSRevision == nil ||
		*document.VCSRevision != revision {
		t.Fatalf("JSON version document = %#v", document)
	}

	help, helpStderr := runInstalled(t, binary, "--help")
	if helpStderr != "" {
		t.Fatalf("--help stderr = %q, want empty", helpStderr)
	}
	for _, required := range []string{"# Mulgae", expectedReadmeInstall, "`darwin/arm64`", "mulgae help workflows"} {
		if !strings.Contains(help, required) {
			t.Errorf("--help is missing %q", required)
		}
	}
	workflows, workflowsStderr := runInstalled(t, binary, "help", "workflows")
	if workflowsStderr != "" || !strings.Contains(workflows, "# Workflows") || !strings.Contains(workflows, "--diff REVISION_RANGE") {
		t.Fatalf("workflow help = stdout %q stderr %q", workflows, workflowsStderr)
	}
}

func TestTrackedReleaseSurface(t *testing.T) {
	root := repositoryRoot(t)
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readme, []byte(expectedReadmeInstall)) {
		t.Fatalf("README does not contain %q", expectedReadmeInstall)
	}
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(license, []byte("MIT License\n")) {
		t.Fatal("LICENSE is not the MIT license")
	}

	paths := trackedAndUnignoredPaths(t, root)
	standaloneLegacy := regexp.MustCompile(`(?i)(^|[^a-z0-9_])` + "k" + `ar([^a-z0-9_]|$)`)
	legacyDirectory := "." + "k" + "ar"
	legacyEnvironment := "K" + "AR_"
	legacyModule := strings.Join([]string{"github.com", "irootkernel", "kkachi-agent-review"}, "/")
	archiveName := "assets" + "." + "zip"
	blockedExtensions := map[string]bool{
		".7z": true, ".bin": true, ".bz2": true, ".dmg": true, ".exe": true,
		".gz": true, ".pkg": true, ".tar": true, ".tgz": true, ".xz": true, ".zip": true,
	}

	for _, relative := range paths {
		lowerPath := strings.ToLower(relative)
		if blockedExtensions[strings.ToLower(filepath.Ext(relative))] {
			t.Errorf("tracked release surface contains archive or binary artifact %q", relative)
		}
		if filepath.Base(lowerPath) == archiveName ||
			strings.Contains(lowerPath, legacyDirectory) ||
			standaloneLegacy.MatchString(relative) ||
			strings.Contains(relative, legacyEnvironment) ||
			strings.Contains(relative, legacyModule) {
			t.Errorf("tracked release surface contains a legacy product identifier in path %q", relative)
		}

		contents, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatalf("read tracked path %q: %v", relative, readErr)
		}
		text := string(contents)
		if strings.Contains(strings.ToLower(text), legacyDirectory) ||
			standaloneLegacy.MatchString(text) ||
			strings.Contains(text, legacyEnvironment) ||
			strings.Contains(text, legacyModule) {
			t.Errorf("tracked release surface contains a legacy product identifier in %q", relative)
		}
	}
}

func assertInstalledBinary(t *testing.T, binary, gobin string) {
	t.Helper()
	entries, err := os.ReadDir(gobin)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != expectedBinaryName {
		t.Fatalf("GOBIN entries = %v, want only %q", entryNames(entries), expectedBinaryName)
	}
	info, err := os.Lstat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("installed binary mode = %v", info.Mode())
	}
}

func assertEmbeddedBuildInfo(t *testing.T, binary, revision string) {
	t.Helper()
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read installed build info: %v", err)
	}
	if info.Main.Path != modulePath {
		t.Fatalf("installed module path = %q, want %q", info.Main.Path, modulePath)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["-trimpath"] != "true" {
		t.Fatalf("installed build does not record -trimpath=true: %#v", settings)
	}
	if settings["vcs.revision"] != revision {
		t.Fatalf("installed VCS revision = %q, want %q", settings["vcs.revision"], revision)
	}
}

func runInstalled(t *testing.T, binary string, arguments ...string) (string, string) {
	t.Helper()
	command := exec.Command(binary, arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %v: %v; stdout=%q stderr=%q", binary, arguments, err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func trackedAndUnignoredPaths(t *testing.T, root string) []string {
	t.Helper()
	command := exec.Command("git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list release paths: %v", err)
	}
	raw := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(raw))
	for _, path := range raw {
		if len(path) != 0 {
			paths = append(paths, string(path))
		}
	}
	return paths
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	command := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	root := strings.TrimSpace(string(output))
	if root == "" || !filepath.IsAbs(root) {
		t.Fatalf("repository root = %q", root)
	}
	return root
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("additional JSON value")
	}
	return err
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
