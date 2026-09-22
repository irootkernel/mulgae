package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
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
			"func ParseResourceURI", "func projectResource", "func resourceChunkEnd",
		},
		filepath.Join(root, "internal", "entrypoint", "mcp", "projection.go"): {
			"func ProjectRunStatus", "func ProjectFindings",
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
	for _, target := range []string{"test:", "test-prepare:", "test-unit:", "test-int:", "test-release:", "test-e2e:", "test-e2e-opt-in:", "test-grok:"} {
		if !strings.Contains(text, target) {
			t.Errorf("Makefile missing %s", target)
		}
	}
	positions := []int{
		strings.Index(text, "$(MAKE) test-prepare"),
		strings.Index(text, "$(MAKE) test-unit"),
		strings.Index(text, "$(MAKE) test-int"),
		strings.Index(text, "$(MAKE) test-release"),
		strings.Index(text, "$(MAKE) test-e2e"),
		strings.Index(text, "$(MAKE) test-e2e-opt-in"),
	}
	for index, position := range positions {
		if position < 0 || index > 0 && position <= positions[index-1] {
			t.Fatalf("Makefile test order is not sequential: %v", positions)
		}
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
	if !strings.Contains(text, "RELEASE_VERSION := v0.1.24") {
		t.Fatal("Makefile does not declare the v0.1.24 release version")
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
		"TestIntegrationIsolatedReleaseFixtureComposesExactRecoveredReview",
		"TestIntegrationIsolatedReleaseFixtureRecoversCancelledRunThroughExactReruns",
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
	if strings.Count(text, "main.buildVersion=$(RELEASE_VERSION)") != 5 {
		t.Fatal("release, mandatory E2E, opt-in E2E, Grok, and MCP client binaries do not share RELEASE_VERSION")
	}
	optInStart := strings.Index(text, "\ntest-e2e-opt-in:")
	grokStart := strings.Index(text, "\ntest-grok:")
	if optInStart < 0 || grokStart <= optInStart {
		t.Fatal("Makefile does not define the opt-in Codex gate before Grok")
	}
	e2eTarget := text[releaseEnd:optInStart]
	for _, required := range []string{
		"zcode_app=", `test -d "$$zcode_app"`, "zcode_executable=", `test -x "$$zcode_executable"`,
		"zcode_launcher=", `test -f "$$zcode_launcher"`, "grok_candidate=", `test -n "$$grok_candidate"`,
		"MULGAE_LIVE_ZCODE_APP_BUNDLE", "MULGAE_LIVE_GROK_BIN",
		"-tags=liveprovider", "-run '^TestLive(ZCode|Grok)Capability$$|^TestLiveCapability(FailureEvidenceIsPrivateAndScreened|MismatchGuidanceDoesNotInventRootCause)$$'", "MULGAE_E2E_BINARY", "MULGAE_E2E_PROJECT_ROOT",
		"MULGAE_E2E_ZCODE_APP_BUNDLE", "MULGAE_E2E_GROK_EXECUTABLE",
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
		"MULGAE_E2E_CODEX_EXECUTABLE", "MULGAE_E2E_CODEX_PRIMARY_HOME", "MULGAE_E2E_CODEX_SECONDARY_HOME",
		"MULGAE_E2E_PROJECT_ROOT", "-tags='live_e2e live_e2e_opt_in'", "-run '^TestE2EOptInCodexCredentialProfiles$$'",
		"[test-e2e-opt-in] failed; preserved private project:",
	} {
		if !strings.Contains(optInTarget, required) {
			t.Errorf("test-e2e-opt-in missing Codex-profile token %q", required)
		}
	}
	mcpClientStart := strings.Index(text, "\ntest-mcp-clients:")
	if mcpClientStart <= grokStart {
		t.Fatal("Makefile does not define the Grok gate before the MCP client gate")
	}
	grokTarget := text[grokStart:mcpClientStart]
	for _, required := range []string{
		"MULGAE_LIVE_GROK_BIN", "-tags=liveprovider", "-run '^TestLiveGrokCapability$$'",
		"MULGAE_E2E_GROK_EXECUTABLE", "main.buildVersion=$(RELEASE_VERSION)",
		"-tags='live_e2e live_grok'", "-run '^TestE2EGrokReleaseBinaryReview$$'",
	} {
		if !strings.Contains(grokTarget, required) {
			t.Errorf("test-grok missing exact-binary review token %q", required)
		}
	}
	capabilityEnd := strings.Index(grokTarget, "./internal/adapters/providercli &&")
	reviewStart := strings.Index(grokTarget, "MULGAE_E2E_BINARY=")
	if capabilityEnd < 0 || reviewStart <= capabilityEnd {
		t.Fatal("test-grok does not stop before the exact-binary review when capability certification fails")
	}
	capability := strings.Index(e2eTarget, "-tags=liveprovider")
	workflow := strings.Index(e2eTarget, "-tags=live_e2e")
	if workflow < 0 || capability <= workflow {
		t.Fatal("test-e2e does not run the login-recovering exact-binary production workflow before family capability certification")
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
	path := filepath.Join(directory, "fake-go")
	script := `#!/bin/sh
if [ "$1" = "env" ]; then
	case "$2" in
		GOOS) printf '%s\n' darwin ;;
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
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
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
		"func TestE2EZCodeGrokReviewAggregation", `"logic": "zcode-logic"`, `"security": "grok-security"`,
		"configureLiveMixedReview", "validateLiveSingleInvocationGate", "assertLiveRoleReportMarker", "assertLiveReportsOnlyAggregation",
		"validateLiveProviderQualificationHealth", "validateLiveRecoverableAssignments", "validateLivePrimaryProcessTerminals",
		"MULGAE_E2E_BINARY", "MULGAE_E2E_ZCODE_APP_BUNDLE", "MULGAE_E2E_GROK_EXECUTABLE",
	} {
		if !strings.Contains(workflowText, required) {
			t.Errorf("exact-binary live workflow contract missing %q", required)
		}
	}
	if strings.Contains(workflowText, "MULGAE_E2E_AGY_EXECUTABLE") || strings.Contains(workflowText, "MULGAE_E2E_KIMI_EXECUTABLE") || strings.Contains(workflowText, "MULGAE_E2E_KIMI_DATA_HOME") {
		t.Fatal("mandatory exact-binary workflow still requires AGY or Kimi")
	}
	if strings.Contains(workflowText, "validateLivePrimaryProcessOverlap") || strings.Contains(workflowText, "maxAttempts = 3") {
		t.Fatal("exact-binary live workflow restored an obsolete overlap or three-attempt predicate")
	}
	for _, obsolete := range []string{"runLiveChildProductionWorkflows", "assertLiveStructuredExtraction", "assertLiveSecurityDefect"} {
		if strings.Contains(workflowText, obsolete) {
			t.Errorf("exact-binary live workflow still contains obsolete deep-workflow token %q", obsolete)
		}
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
		`"codex-primary-logic"`, `"codex-primary-security"`, `"codex-secondary-documentation"`,
		"MULGAE_E2E_CODEX_PRIMARY_HOME", "MULGAE_E2E_CODEX_SECONDARY_HOME",
	} {
		if !strings.Contains(optInText, required) {
			t.Errorf("opt-in exact-binary workflow contract missing %q", required)
		}
	}
	if strings.Contains(optInText, ".Skip(") || strings.Contains(optInText, ".Skipf(") {
		t.Fatal("enabled opt-in exact-binary workflow may not skip prerequisites")
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
