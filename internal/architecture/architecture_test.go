package architecture

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/irootkernel/mulgae/"

func TestProductionDependencyDirection(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if hasBuildIgnoreConstraint(source) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(rel, "internal/domain/") && (strings.HasPrefix(importPath, modulePath) || importPath == "unsafe" || importPath == "C") {
				t.Errorf("%s imports forbidden domain dependency %q", rel, importPath)
			}
			if strings.HasPrefix(rel, "internal/ports/") && (strings.Contains(importPath, "/internal/app/") || strings.Contains(importPath, "/internal/adapters/") || strings.Contains(importPath, "/internal/entrypoint/")) {
				t.Errorf("%s imports outward dependency %q", rel, importPath)
			}
			if strings.HasPrefix(rel, "internal/app/") && (strings.Contains(importPath, "/internal/adapters/") || strings.Contains(importPath, "/internal/builtin")) {
				t.Errorf("%s imports outward dependency %q", rel, importPath)
			}
			if (strings.HasPrefix(rel, "internal/domain/") || strings.HasPrefix(rel, "internal/app/")) && isAdapterCapabilityImport(importPath) {
				t.Errorf("%s imports adapter capability %q", rel, importPath)
			}
			if strings.HasPrefix(rel, "internal/adapters/") && strings.Contains(importPath, "/internal/entrypoint/") {
				t.Errorf("%s imports entrypoint %q", rel, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMCPContractProjectionOwnership(t *testing.T) {
	root := repositoryRoot(t)
	composition, err := os.ReadFile(filepath.Join(root, "internal", "composition", "mcp_backend.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"crypto/sha256",
		"net/url",
		"func parseMCPResourceURI",
		"func chunkMCPResource",
		"func validateMCPPublicationPair",
	} {
		if strings.Contains(string(composition), forbidden) {
			t.Errorf("composition owns MCP contract token %q", forbidden)
		}
	}
	for path, required := range map[string][]string{
		filepath.Join(root, "internal", "entrypoint", "mcp", "resources.go"): {
			"func ParseResourceURI",
		},
		filepath.Join(root, "internal", "entrypoint", "mcp", "projection.go"): {
			"func ProjectRunStatus", "func ProjectInspection",
		},
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range required {
			if !strings.Contains(string(data), token) {
				t.Errorf("%s missing MCP contract owner %q", path, token)
			}
		}
	}
}

func hasBuildIgnoreConstraint(source []byte) bool {
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return false
		}
		if trimmed == "//go:build ignore" {
			return true
		}
	}
	return false
}

func isAdapterCapabilityImport(importPath string) bool {
	lower := strings.ToLower(importPath)
	return importPath == "os" || importPath == "os/exec" ||
		importPath == "github.com/spf13/cobra" || strings.HasSuffix(lower, "/cobra") ||
		strings.Contains(lower, "yaml") || strings.Contains(lower, "jsonschema")
}

func TestBuildIgnoreConstraintDetection(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		source string
		want   bool
	}{
		{name: "build ignore", source: "//go:build ignore\n\npackage generate\n", want: true},
		{name: "ordinary build tag", source: "//go:build darwin\n\npackage platform\n", want: false},
		{name: "late text", source: "package example\n\n//go:build ignore\n", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasBuildIgnoreConstraint([]byte(test.source)); got != test.want {
				t.Fatalf("hasBuildIgnoreConstraint() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestAdapterCapabilityImportClassification(t *testing.T) {
	t.Parallel()

	for _, importPath := range []string{"os", "os/exec", "github.com/spf13/cobra", "gopkg.in/yaml.v3", "github.com/santhosh-tekuri/jsonschema/v5"} {
		if !isAdapterCapabilityImport(importPath) {
			t.Errorf("adapter capability import %q was not rejected", importPath)
		}
	}
	for _, importPath := range []string{"context", "encoding/json", modulePath + "internal/domain"} {
		if isAdapterCapabilityImport(importPath) {
			t.Errorf("core-safe import %q was rejected", importPath)
		}
	}
}

func TestTestTierNaming(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(function.Name.Name, "Test") {
				continue
			}
			name := function.Name.Name
			if (strings.Contains(name, "Integration") && !strings.HasPrefix(name, "TestIntegration")) || (strings.Contains(name, "E2E") && !strings.HasPrefix(name, "TestE2E")) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s: %s does not use a tier prefix", rel, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRootGoSurface(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "main.go" {
		t.Fatalf("root Go files = %v, want only main.go", files)
	}
}

func TestMakefileContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, target := range []string{"test-e2e", "test-e2e-opt-in", "test-grok", "test-agy", "test-mcp-clients"} {
		start := strings.Index(text, "\n"+target+":\n")
		if start < 0 || !strings.HasPrefix(text[start+len(target)+3:], "\t@$(validate_installed_test_inputs)\n") {
			t.Fatalf("%s must validate sealed installed inputs before any workload", target)
		}
	}
	for _, target := range []string{"test:", "test-offline:", "test-prepare:", "test-unit:", "test-int:", "test-release:", "test-e2e:", "test-e2e-opt-in:", "test-herdr:", "test-grok:", "test-agy:"} {
		if !strings.Contains(text, target) {
			t.Errorf("Makefile missing %s", target)
		}
	}
	testStart := strings.Index(text, "\ntest:")
	offlineStart := strings.Index(text, "\ntest-offline:")
	prepareStart := strings.Index(text, "\ntest-prepare:")
	if testStart < 0 || offlineStart <= testStart || prepareStart <= offlineStart {
		t.Fatal("Makefile does not define test, test-offline, and test-prepare in order")
	}
	testTarget := text[testStart:offlineStart]
	fullPositions := []int{
		strings.Index(testTarget, "$(MAKE) test-offline"),
		strings.Index(testTarget, "$(MAKE) test-release"),
		strings.Index(testTarget, "$(MAKE) test-e2e"),
		strings.Index(testTarget, "$(MAKE) test-e2e-opt-in"),
	}
	for index, position := range fullPositions {
		if position < 0 || index > 0 && position <= fullPositions[index-1] {
			t.Fatalf("Makefile test order is not sequential: %v", fullPositions)
		}
	}
	for _, duplicated := range []string{"$(MAKE) test-prepare", "$(MAKE) test-unit", "$(MAKE) test-int"} {
		if strings.Contains(testTarget, duplicated) {
			t.Fatalf("Makefile test target duplicates offline stage %q", duplicated)
		}
	}
	offlineTarget := text[offlineStart:prepareStart]
	offlinePositions := []int{
		strings.Index(offlineTarget, "$(MAKE) test-prepare"),
		strings.Index(offlineTarget, "$(MAKE) test-unit"),
		strings.Index(offlineTarget, "$(MAKE) test-int"),
	}
	for index, position := range offlinePositions {
		if position < 0 || index > 0 && position <= offlinePositions[index-1] {
			t.Fatalf("Makefile test-offline order is not sequential: %v", offlinePositions)
		}
	}
	for _, forbidden := range []string{"test-release", "test-e2e", "test-e2e-opt-in", "test-herdr", "test-grok", "test-agy"} {
		if strings.Contains(offlineTarget, forbidden) {
			t.Fatalf("Makefile test-offline references non-offline stage %q", forbidden)
		}
	}
	gaoriData, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".gaori", "tester.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	gaoriText := string(gaoriData)
	if !strings.Contains(gaoriText, "\n  offline:\n    command: [\"make\", \"test-offline\"]\n") {
		t.Fatal(".gaori/tester.yaml does not map offline to make test-offline")
	}
	unitStart := strings.Index(text, "\ntest-unit:")
	unitEnd := strings.Index(text, "\ntest-int:")
	if unitStart < 0 || unitEnd <= unitStart || !strings.Contains(text[unitStart:unitEnd], "test -p 1 ") {
		t.Fatal("test-unit does not serialize race-instrumented package execution")
	}
	integrationStart := unitEnd
	integrationEnd := strings.Index(text, "\ntest-release:")
	if integrationEnd <= integrationStart || !strings.Contains(text[integrationStart:integrationEnd], "test -p 1 ") {
		t.Fatal("test-int does not serialize race-instrumented package execution")
	}
	if !regexp.MustCompile(`(?m)^RELEASE_VERSION := v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(text) {
		t.Fatal("Makefile does not declare a valid RELEASE_VERSION := v<major>.<minor>.<patch>")
	}
	releaseStart := integrationEnd
	releaseEnd := strings.Index(text, "\ntest-e2e:")
	if releaseEnd <= releaseStart {
		t.Fatal("Makefile test-release target is not before test-e2e")
	}
	releaseTarget := text[releaseStart:releaseEnd]
	for _, required := range []string{
		"GOBIN=", "$(GO) install", "-trimpath", "main.buildVersion=$(RELEASE_VERSION)",
		"main.buildRevision=", "-tags=releasecheck", "MULGAE_RELEASE_BINARY",
		"MULGAE_RELEASE_GOBIN", "MULGAE_RELEASE_VERSION", "MULGAE_RELEASE_REVISION",
		"TestIntegrationIsolatedReleaseFixtureLiveSelectors",
		"TestIntegrationIsolatedReleaseFixtureCancelsLiveReviewWithoutReplay",
	} {
		if !strings.Contains(releaseTarget, required) {
			t.Errorf("test-release missing installation-contract token %q", required)
		}
	}
	override := "github.com/irootkernel/mulgae/internal/adapters/environment.buildNativeHomeOverride="
	if strings.Count(releaseTarget, override) != 1 || !strings.Contains(releaseTarget, "release_fixture_ldflags=") {
		t.Fatal("test-release must bind the native-home override exactly once in the isolated fixture build")
	}
	installEnd := strings.Index(releaseTarget, "./internal/releasecheck")
	if installEnd < 0 || strings.Contains(releaseTarget[:installEnd], override) {
		t.Fatal("test-release production installation must not contain the test-only native-home override")
	}
	if !strings.Contains(text, "go build") && !strings.Contains(text, "$(GO) build") {
		t.Fatal("test-e2e does not build the production binary")
	}
	if strings.Contains(text, "$(MAKE) test-agy") {
		t.Fatal("the default test gate includes a standalone AGY review")
	}
	optInStart := strings.Index(text, "\ntest-e2e-opt-in:")
	grokStart := strings.Index(text, "\ntest-grok:")
	if optInStart < 0 || grokStart <= optInStart {
		t.Fatal("Makefile does not define the opt-in Codex gate before Grok")
	}
	e2eTarget := text[releaseEnd:optInStart]
	for _, required := range []string{
		"zcode_app=", `test -d "$$zcode_app"`, "zcode_executable=", `test -x "$$zcode_executable"`,
		"zcode_launcher=", `test -f "$$zcode_launcher"`,
		"MULGAE_LIVE_ZCODE_APP_BUNDLE",
		"-tags=liveprovider", "-run '^TestLiveZCodeCapability(CipherFixtures)?$$|^TestLiveCapability(FailureEvidenceIsPrivateAndScreened|MismatchGuidanceDoesNotInventRootCause)$$'", "MULGAE_E2E_BINARY", "MULGAE_E2E_PROJECT_ROOT",
		"MULGAE_E2E_ZCODE_APP_BUNDLE",
		"-tags=live_e2e", "-run '^Test(E2E|Live)'", "[test-e2e] failed; preserved private project:",
	} {
		if !strings.Contains(e2eTarget, required) {
			t.Errorf("test-e2e missing fail-closed family-capability token %q", required)
		}
	}
	for _, forbidden := range []string{"MULGAE_LIVE_CODEX_BIN", "MULGAE_E2E_CODEX_HOME", "MULGAE_E2E_CODEX_FALLBACK_HOME"} {
		if strings.Contains(e2eTarget, forbidden) {
			t.Errorf("mandatory test-e2e still requires Codex token %q", forbidden)
		}
	}
	if strings.Contains(e2eTarget, "$(MAKE) test-grok") {
		t.Fatal("mandatory test-e2e still nests the standalone Grok review target")
	}
	optInTarget := text[optInStart:grokStart]
	for _, required := range []string{
		`MULGAE_E2E_OPT_IN:-}`, "[test-e2e-opt-in] skipped: set MULGAE_E2E_OPT_IN=1",
		"MULGAE_E2E_CODEX_EXECUTABLE", "MULGAE_E2E_CODEX_PRIMARY_HOME",
		"MULGAE_E2E_PROJECT_ROOT", "-tags='live_e2e live_e2e_opt_in'", "-run '^TestE2EOptInCodexCredentialProfiles$$'",
		"[test-e2e-opt-in] failed; preserved private project:",
	} {
		if !strings.Contains(optInTarget, required) {
			t.Errorf("test-e2e-opt-in missing Codex-profile token %q", required)
		}
	}
	if strings.Contains(optInTarget, "MULGAE_E2E_CODEX_SECONDARY_HOME") {
		t.Fatal("opt-in Codex certification still requires a secondary home")
	}
	agyStart := strings.Index(text, "\ntest-agy:")
	mcpClientStart := strings.Index(text, "\ntest-mcp-clients:")
	if agyStart <= grokStart || mcpClientStart <= agyStart {
		t.Fatal("Makefile does not define AGY gate between Grok and the MCP client gate")
	}
	grokTarget := text[grokStart:agyStart]
	for _, required := range []string{
		"$(MAKE) test-herdr",
		"MULGAE_LIVE_GROK_BIN", "-tags=liveprovider", "-run '^TestLiveGrokCapability$$'",
		"MULGAE_E2E_GROK_EXECUTABLE", "main.buildVersion=$(RELEASE_VERSION)",
		"-tags='live_e2e live_grok'", "-run '^TestE2EGrokReleaseBinaryReview$$'",
	} {
		if !strings.Contains(grokTarget, required) {
			t.Errorf("test-grok missing exact-binary review token %q", required)
		}
	}
	herdrStart := strings.Index(text, "\ntest-herdr:")
	vmStart := strings.Index(text, "\ntest-vm:")
	if herdrStart < 0 || vmStart <= herdrStart {
		t.Fatal("Makefile does not define test-herdr before test-vm")
	}
	herdrTarget := text[herdrStart:vmStart]
	for _, required := range []string{
		"-tags=live_herdr", "./internal/adapters/herdr",
		"test-herdr requires an executable hc/herdr-core binary",
	} {
		if !strings.Contains(herdrTarget, required) {
			t.Errorf("test-herdr missing required token %q", required)
		}
	}
	capabilityEnd := strings.Index(grokTarget, "./internal/adapters/providercli &&")
	reviewStart := strings.Index(grokTarget, "MULGAE_E2E_BINARY=")
	if capabilityEnd < 0 || reviewStart <= capabilityEnd {
		t.Fatal("test-grok does not stop before the exact-binary review when capability certification fails")
	}
	agyTarget := text[agyStart:mcpClientStart]
	mcpClientTarget := text[mcpClientStart:]
	for targetName, targetSlice := range map[string]string{
		"test-release":     releaseTarget,
		"test-e2e":         e2eTarget,
		"test-e2e-opt-in":  optInTarget,
		"test-grok":        grokTarget,
		"test-agy":         agyTarget,
		"test-mcp-clients": mcpClientTarget,
	} {
		if !strings.Contains(targetSlice, "main.buildVersion=$(RELEASE_VERSION)") {
			t.Errorf("%s does not stamp main.buildVersion=$(RELEASE_VERSION)", targetName)
		}
	}
	capability := strings.Index(e2eTarget, "-tags=liveprovider")
	workflow := strings.Index(e2eTarget, "-tags=live_e2e")
	if workflow < 0 || capability <= workflow {
		t.Fatal("test-e2e does not run the login-recovering exact-binary production workflow before family capability certification")
	}
}

func TestMakefileInstalledBinaryProvenance(t *testing.T) {
	root := repositoryRoot(t)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	fakeGo := filepath.Join(scratch, "go")
	binary := filepath.Join(scratch, "installed mulgae")
	manifest := filepath.Join(scratch, "candidate.json")
	probe := filepath.Join(scratch, "probe.mk")
	for path, contents := range map[string]string{
		fakeGo:   "#!/bin/sh\nexit 0\n",
		binary:   "#!/bin/sh\nexit 99\n",
		manifest: "{\"source\":\"sealed fixture\"}\n",
		probe:    "installed-input-check:\n\t@$(validate_installed_test_inputs)\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const source = "0123456789012345678901234567890123456789"
	inputs := []string{
		"MULGAE_TEST_INSTALLED_BINARY=" + binary,
		"MULGAE_TEST_SOURCE_COMMIT=" + source,
		"MULGAE_TEST_PREPARED_MANIFEST=" + manifest,
	}
	run := func(t *testing.T, target string, values []string) (string, error) {
		t.Helper()
		args := []string{"--no-print-directory", "-f", filepath.Join(root, "Makefile"),
			"-f", probe, "GO=" + fakeGo, "MAKE=/usr/bin/false", target}
		cmd := exec.Command(makeBinary, args...)
		cmd.Dir = root
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			if name != "MULGAE_TEST_INSTALLED_BINARY" && name != "MULGAE_TEST_SOURCE_COMMIT" &&
				name != "MULGAE_TEST_PREPARED_MANIFEST" && name != "MAKEFLAGS" && name != "MFLAGS" {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, values...)
		output, runErr := cmd.CombinedOutput()
		return string(output), runErr
	}
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"source-without-binary", []string{inputs[1]}},
		{"manifest-without-binary", []string{inputs[2]}},
		{"binary-without-manifest", inputs[:2]},
		{"invalid-source", []string{inputs[0], "MULGAE_TEST_SOURCE_COMMIT=not-a-commit", inputs[2]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := run(t, "installed-input-check", tc.values)
			if err == nil || !strings.Contains(output, "invalid installed-test inputs") {
				t.Fatalf("unsafe installed inputs were not refused: err=%v output=%s", err, output)
			}
		})
	}
	t.Run("normal-build-inputs", func(t *testing.T) {
		output, err := run(t, "installed-input-check", nil)
		if err != nil || strings.Contains(output, "[installed-test]") {
			t.Fatalf("ordinary build acquired installed-binary inputs: err=%v output=%s", err, output)
		}
	})
	t.Run("sealed-input-provenance", func(t *testing.T) {
		output, err := run(t, "installed-input-check", inputs)
		if err != nil || !strings.Contains(output, "supplied_source_commit="+source) ||
			!strings.Contains(output, binary) || !strings.Contains(output, manifest) {
			t.Fatalf("installed input provenance missing: err=%v output=%s", err, output)
		}
		for _, path := range []string{binary, manifest} {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output, fmt.Sprintf("%x", sha256.Sum256(data))) {
				t.Fatalf("installed input hash missing for %s: %s", path, output)
			}
		}
	})
	t.Run("full-gate-refuses-overrides", func(t *testing.T) {
		output, err := run(t, "test", inputs)
		if err == nil || !strings.Contains(output, "make test refuses installed-binary overrides") {
			t.Fatalf("full gate accepted external inputs: err=%v output=%s", err, output)
		}
	})
}

func TestMakefileOfflineAndFullGateOrchestration(t *testing.T) {
	root := repositoryRoot(t)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	makefilePath := filepath.Join(root, "Makefile")
	bin := t.TempDir()
	fakeGo := filepath.Join(bin, "fake-go")
	if err := os.WriteFile(fakeGo, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	fakeMake := filepath.Join(bin, "fake-make")
	fakeMakeScript := `#!/bin/sh
target=""
for arg in "$@"; do
	case "$arg" in
		test|test-offline|test-prepare|test-unit|test-int|test-release|test-e2e|test-e2e-opt-in|test-grok|test-agy)
			target="$arg"
			;;
	esac
done
printf '%s\n' "$target" >> "$FAKE_MAKE_LOG"
if [ "$target" = "test" ] || [ "$target" = "test-offline" ]; then
	MAKEFLAGS= exec "$REAL_MAKE" --no-print-directory -f "$MAKEFILE_PATH" "MAKE=$SELF_MAKE" "GO=$FAKE_GO" "$target"
fi
if [ "$target" = "${FAKE_MAKE_FAIL_TARGET:-}" ]; then
	exit 17
fi
exit 0
`
	if err := os.WriteFile(fakeMake, []byte(fakeMakeScript), 0o700); err != nil {
		t.Fatal(err)
	}

	runGate := func(t *testing.T, target string, failTarget string) (string, string, error) {
		t.Helper()
		logPath := filepath.Join(t.TempDir(), "make.log")
		command := exec.Command(fakeMake, target)
		command.Dir = root
		command.Env = append(
			os.Environ(),
			"REAL_MAKE="+makeBinary,
			"MAKEFILE_PATH="+makefilePath,
			"SELF_MAKE="+fakeMake,
			"FAKE_GO="+fakeGo,
			"FAKE_MAKE_LOG="+logPath,
			"FAKE_MAKE_FAIL_TARGET="+failTarget,
		)
		output, runErr := command.CombinedOutput()
		logBytes, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return string(output), string(logBytes), runErr
	}

	t.Run("test-offline runs prepare unit and int once in order", func(t *testing.T) {
		output, logText, runErr := runGate(t, "test-offline", "")
		if runErr != nil {
			t.Fatalf("test-offline failed: %v\n%s", runErr, output)
		}
		wantLog := "test-offline\ntest-prepare\ntest-unit\ntest-int\n"
		if logText != wantLog {
			t.Fatalf("test-offline invocation log = %q, want %q", logText, wantLog)
		}
		if !strings.Contains(output, "[test-offline] completed\n") {
			t.Fatalf("test-offline output missing completion marker:\n%s", output)
		}
	})

	t.Run("test runs test-offline once before release and live stages", func(t *testing.T) {
		output, logText, runErr := runGate(t, "test", "")
		if runErr != nil {
			t.Fatalf("test failed: %v\n%s", runErr, output)
		}
		wantLog := "test\ntest-offline\ntest-prepare\ntest-unit\ntest-int\ntest-release\ntest-e2e\ntest-e2e-opt-in\n"
		if logText != wantLog {
			t.Fatalf("test invocation log = %q, want %q", logText, wantLog)
		}
		if !strings.Contains(output, "[test-offline] completed\n") || !strings.Contains(output, "[test] completed\n") {
			t.Fatalf("test output missing completion markers:\n%s", output)
		}
	})

	for _, tc := range []struct {
		name       string
		gate       string
		failTarget string
		wantLog    string
	}{
		{
			name:       "test-offline stops when test-prepare fails",
			gate:       "test-offline",
			failTarget: "test-prepare",
			wantLog:    "test-offline\ntest-prepare\n",
		},
		{
			name:       "test-offline stops when test-unit fails",
			gate:       "test-offline",
			failTarget: "test-unit",
			wantLog:    "test-offline\ntest-prepare\ntest-unit\n",
		},
		{
			name:       "test stops before release and live stages when test-int fails",
			gate:       "test",
			failTarget: "test-int",
			wantLog:    "test\ntest-offline\ntest-prepare\ntest-unit\ntest-int\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, logText, runErr := runGate(t, tc.gate, tc.failTarget)
			if runErr == nil {
				t.Fatalf("%s succeeded when %s failed:\n%s", tc.gate, tc.failTarget, output)
			}
			if logText != tc.wantLog {
				t.Fatalf("%s invocation log on %s failure = %q, want %q", tc.gate, tc.failTarget, logText, tc.wantLog)
			}
			if strings.Contains(output, "[test-offline] completed") || strings.Contains(output, "[test] completed") {
				t.Fatalf("%s printed completion marker after %s failure:\n%s", tc.gate, tc.failTarget, output)
			}
		})
	}
}

func TestMakefileReleaseGateUsesTrustedTemporaryDirectoryCreator(t *testing.T) {
	root := repositoryRoot(t)
	base := t.TempDir()
	preexisting := filepath.Join(base, "mulgae-release.victim")
	if err := os.Mkdir(preexisting, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(preexisting, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	shimMarker := filepath.Join(base, "path-mktemp-invoked")
	shim := "#!/bin/sh\nprintf invoked > \"$FAKE_MKTEMP_MARKER\"\nprintf '%s\\n' \"$FAKE_MKTEMP_RESULT\"\n"
	if err := os.WriteFile(filepath.Join(bin, "mktemp"), []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	fakeGo := writeReleaseGateFakeGo(t, bin)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+base, "FAKE_MKTEMP_RESULT="+preexisting, "FAKE_MKTEMP_MARKER="+shimMarker, "FAKE_GO_LOG="+filepath.Join(base, "go.log"), "FAKE_GO_FAIL_INSTALL=1")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("test-release accepted production install failure:\n%s", output)
	}
	if _, err := os.Stat(shimMarker); !os.IsNotExist(err) {
		t.Fatalf("test-release used PATH-selected mktemp: %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "preserve" {
		t.Fatalf("test-release cleanup removed pre-existing content: data=%q err=%v", data, err)
	}
	if info, err := os.Stat(preexisting); err != nil || !info.IsDir() {
		t.Fatalf("test-release removed pre-existing directory: info=%v err=%v", info, err)
	}
}

func TestMakefileReleaseGateStopsAfterProductionInstallFailure(t *testing.T) {
	root := repositoryRoot(t)
	bin := t.TempDir()
	fakeGo := writeReleaseGateFakeGo(t, bin)
	logPath := filepath.Join(t.TempDir(), "go.log")
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "FAKE_GO_LOG="+logPath, "FAKE_GO_FAIL_INSTALL=1")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("test-release accepted production install failure:\n%s", output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "install\n") || strings.Contains(string(log), "test\n") || strings.Contains(string(log), "build\n") {
		t.Fatalf("commands after failed install were executed:\n%s", log)
	}
}

func TestMakefileReleaseGatePreservesReplacedTemporaryRoot(t *testing.T) {
	root := repositoryRoot(t)
	base := t.TempDir()
	bin := t.TempDir()
	fakeGo := writeReleaseGateFakeGo(t, bin)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "TMPDIR="+base, "FAKE_GO_LOG="+filepath.Join(base, "go.log"), "FAKE_GO_REPLACE_RELEASE_ROOT=1")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("test-release accepted replaced temporary root:\n%s", output)
	}
	matches, err := filepath.Glob(filepath.Join(base, "mulgae-release.*", "replacement-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("replacement sentinel paths = %v, want one preserved replacement", matches)
	}
}

func TestMakefileReleaseGateRejectsUnprotectedTemporaryBase(t *testing.T) {
	root := repositoryRoot(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	bin := t.TempDir()
	fakeGo := writeReleaseGateFakeGo(t, bin)
	logPath := filepath.Join(t.TempDir(), "go.log")
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "TMPDIR="+base, "FAKE_GO_LOG="+logPath)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("test-release accepted an unprotected temporary base:\n%s", output)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("test-release invoked go after rejecting temporary base: %v", err)
	}
}

func TestMakefileReleaseGateSupportsTemporaryBaseWithSpaces(t *testing.T) {
	root := repositoryRoot(t)
	parent := t.TempDir()
	base := filepath.Join(parent, "release base")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	fakeGo := writeReleaseGateFakeGo(t, bin)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "TMPDIR="+base, "FAKE_GO_LOG="+filepath.Join(parent, "go.log"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("test-release rejected a protected temporary base containing spaces: %v\n%s", err, output)
	}
}

func TestMakefileReleaseGateFailsWhenCleanupCannotRemoveTemporaryRoot(t *testing.T) {
	root := repositoryRoot(t)
	base := t.TempDir()
	bin := t.TempDir()
	fakeGo := writeReleaseGateFakeGo(t, bin)
	makeBinary, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(makeBinary, "-f", filepath.Join(root, "Makefile"), "test-release", "GO="+fakeGo)
	command.Dir = root
	command.Env = append(os.Environ(), "TMPDIR="+base, "FAKE_GO_LOG="+filepath.Join(base, "go.log"), "FAKE_GO_LEAK_RELEASE_ROOT=1")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("test-release reported success after incomplete cleanup:\n%s", output)
	}
}

func writeReleaseGateFakeGo(t *testing.T, directory string) string {
	t.Helper()
	bin := filepath.Join(directory, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(bin, "go")
	pins, err := os.ReadFile(filepath.Join(repositoryRoot(t), "tools", "toolchains.env"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^GO_VERSION=(.+)$`).FindStringSubmatch(string(pins))
	if len(match) != 2 {
		t.Fatal("missing Go execution pin")
	}
	script := `#!/bin/sh
if [ "$1" = "version" ]; then
	printf 'go version go__PIN__ darwin/arm64\n'
	exit 0
fi
if [ "$1" = "env" ]; then
	case "$2" in
		GOOS) printf '%s\n' darwin ;;
		GOROOT) printf '%s\n' "${0%/bin/go}" ;;
		GOARCH) printf '%s\n' arm64 ;;
	esac
	exit 0
fi
if [ "$1" = "list" ]; then
	exit 0
fi
printf '%s\n' "$1" >> "$FAKE_GO_LOG"
if [ "$1" = "install" ] && [ "${FAKE_GO_FAIL_INSTALL:-}" = "1" ]; then
	exit 23
fi
if [ "$1" = "install" ] && [ "${FAKE_GO_REPLACE_RELEASE_ROOT:-}" = "1" ]; then
	release_root=${GOBIN%/bin}
	mv "$release_root" "$release_root.original" || exit 24
	mkdir -m 700 "$release_root" || exit 24
	printf '%s\n' preserve > "$release_root/replacement-sentinel" || exit 24
	exit 23
fi
if [ "$1" = "build" ] && [ "${FAKE_GO_LEAK_RELEASE_ROOT:-}" = "1" ]; then
	previous=
	output=
	for argument in "$@"; do
		if [ "$previous" = "-o" ]; then output=$argument; break; fi
		previous=$argument
	done
	release_root=${output%/*}
	printf '%s\n' preserve > "$release_root/unexpected-file" || exit 24
fi
exit 0
`
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(script, "__PIN__", match[1])), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestE2ELiveFamilyCapabilityAndNoSkipContract(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "internal", "adapters", "providercli", "registry_live_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"func TestLiveZCodeCapability", "func TestLiveGrokCapability", "QualifyCurrent"} {
		if !strings.Contains(text, required) {
			t.Errorf("live family capability contract missing %q", required)
		}
	}
	if strings.Contains(text, ".Skip(") || strings.Contains(text, ".Skipf(") {
		t.Fatal("required live family capability certification may not skip prerequisites")
	}
	workflowData, err := os.ReadFile(filepath.Join(root, "test", "e2e", "live_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	workflowText := string(workflowData)
	for _, required := range []string{
		"func TestE2EZCodeGrokReviewAggregation", `"logic": "zcode-logic"`, `"security": "zcode-security"`,
		"MULGAE_E2E_BINARY", "MULGAE_E2E_ZCODE_APP_BUNDLE",
	} {
		if !strings.Contains(workflowText, required) {
			t.Errorf("exact-binary live workflow contract missing %q", required)
		}
	}
	if strings.Contains(workflowText, "MULGAE_E2E_AGY_EXECUTABLE") || strings.Contains(workflowText, "MULGAE_E2E_KIMI_EXECUTABLE") || strings.Contains(workflowText, "MULGAE_E2E_KIMI_DATA_HOME") {
		t.Fatal("mandatory exact-binary workflow still requires AGY or Kimi")
	}
	if strings.Contains(workflowText, ".Skip(") || strings.Contains(workflowText, ".Skipf(") {
		t.Fatal("exact-binary actual-provider workflow may not skip prerequisites")
	}
	optInData, err := os.ReadFile(filepath.Join(root, "test", "e2e", "opt_in_live_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	optInText := string(optInData)
	for _, required := range []string{
		"live_e2e_opt_in", "func TestE2EOptInCodexCredentialProfiles",
		`"codex-primary-logic"`, `"codex-primary-security"`, `"codex-primary-documentation"`,
		"MULGAE_E2E_CODEX_PRIMARY_HOME",
	} {
		if !strings.Contains(optInText, required) {
			t.Errorf("opt-in exact-binary workflow contract missing %q", required)
		}
	}
	if strings.Contains(optInText, "MULGAE_E2E_CODEX_SECONDARY_HOME") || strings.Contains(optInText, `"codex-secondary-`) {
		t.Fatal("opt-in Codex certification still uses a secondary profile")
	}
	if strings.Contains(optInText, ".Skip(") || strings.Contains(optInText, ".Skipf(") {
		t.Fatal("enabled opt-in exact-binary workflow may not skip prerequisites")
	}
	herdrLiveData, err := os.ReadFile(filepath.Join(root, "internal", "adapters", "herdr", "live_herdr_darwin_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	herdrLiveText := string(herdrLiveData)
	if !strings.Contains(herdrLiveText, "live_herdr") {
		t.Fatal("live_herdr_darwin_test.go missing live_herdr build tag")
	}
	if strings.Contains(herdrLiveText, ".Skip(") || strings.Contains(herdrLiveText, ".Skipf(") {
		t.Fatal("live_herdr isolated-core test suite may not silently skip")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
