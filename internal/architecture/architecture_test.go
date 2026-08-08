package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
	for _, target := range []string{"test:", "test-prepare:", "test-unit:", "test-int:", "test-release:", "test-e2e:", "test-kimi:"} {
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
	if !strings.Contains(text, "RELEASE_VERSION := v0.1.6") {
		t.Fatal("Makefile does not declare the v0.1.6 release version")
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
	} {
		if !strings.Contains(releaseTarget, required) {
			t.Errorf("test-release missing installation-contract token %q", required)
		}
	}
	if !strings.Contains(text, "go build") && !strings.Contains(text, "$(GO) build") {
		t.Fatal("test-e2e does not build the production binary")
	}
	if strings.Count(text, "main.buildVersion=$(RELEASE_VERSION)") != 2 {
		t.Fatal("release and E2E binaries do not share RELEASE_VERSION")
	}
	kimiStart := strings.Index(text, "\ntest-kimi:")
	if kimiStart < 0 {
		t.Fatal("Makefile does not define the opt-in Kimi gate")
	}
	e2eTarget := text[releaseEnd:kimiStart]
	for _, required := range []string{
		"zcode_node=", `test -n "$$zcode_node"`,
		"zcode_launcher=", `test -f "$$zcode_launcher"`, "agy_bin=", `test -n "$$agy_bin"`,
		"MULGAE_LIVE_ZCODE_NODE_BIN", "MULGAE_LIVE_ZCODE_LAUNCHER", "MULGAE_LIVE_AGY_BIN",
		"-tags=liveprovider", "-run '^TestLive(ZCode|Agy)Capability$$'", "MULGAE_E2E_BINARY", "MULGAE_E2E_PROJECT_ROOT",
		"MULGAE_E2E_ZCODE_NODE_EXECUTABLE", "MULGAE_E2E_ZCODE_LAUNCHER", "MULGAE_E2E_AGY_EXECUTABLE",
		"-tags=live_e2e", "-run '^Test(E2E|Live)'", "[test-e2e] failed; preserved private project:",
	} {
		if !strings.Contains(e2eTarget, required) {
			t.Errorf("test-e2e missing fail-closed family-capability token %q", required)
		}
	}
	for _, forbidden := range []string{"kimi_bin=", "MULGAE_LIVE_KIMI_BIN", "MULGAE_E2E_KIMI_EXECUTABLE", "MULGAE_E2E_KIMI_DATA_HOME"} {
		if strings.Contains(e2eTarget, forbidden) {
			t.Errorf("mandatory test-e2e still requires Kimi token %q", forbidden)
		}
	}
	kimiTarget := text[kimiStart:]
	for _, required := range []string{"MULGAE_LIVE_KIMI_BIN", "MULGAE_LIVE_KIMI_DATA_HOME", "-run '^TestLiveKimiCapability$$'"} {
		if !strings.Contains(kimiTarget, required) {
			t.Errorf("test-kimi missing compatibility token %q", required)
		}
	}
	capability := strings.Index(e2eTarget, "-tags=liveprovider")
	workflow := strings.Index(e2eTarget, "-tags=live_e2e")
	if workflow < 0 || capability <= workflow {
		t.Fatal("test-e2e does not run the login-recovering exact-binary production workflow before family capability certification")
	}
}

func TestE2ELiveFamilyCapabilityAndNoSkipContract(t *testing.T) {
	root := repositoryRoot(t)
	var combined strings.Builder
	for _, path := range []string{
		filepath.Join(root, "internal", "adapters", "providercli", "registry_live_test.go"),
		filepath.Join(root, "internal", "adapters", "providercli", "agy_live_test.go"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined.Write(data)
	}
	text := combined.String()
	for _, required := range []string{"func TestLiveKimiCapability", "func TestLiveZCodeCapability", "func TestLiveAgyCapability", "QualifyCurrent", "protected native credential/settings state", "auth/settings after drain"} {
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
		"func TestE2EActualProvidersProductionWorkflow", "runLiveChildProductionWorkflows", `"followup"`, `"delta"`, `"exact"`, `"recompose"`,
		"validateLiveProviderQualificationHealth", "validateLiveRecoverableAssignments", "validateLivePrimaryProcessTerminals",
		"MULGAE_E2E_BINARY", "MULGAE_E2E_ZCODE_NODE_EXECUTABLE", "MULGAE_E2E_ZCODE_LAUNCHER", "MULGAE_E2E_AGY_EXECUTABLE",
	} {
		if !strings.Contains(workflowText, required) {
			t.Errorf("exact-binary live workflow contract missing %q", required)
		}
	}
	if strings.Contains(workflowText, "MULGAE_E2E_KIMI_EXECUTABLE") || strings.Contains(workflowText, "MULGAE_E2E_KIMI_DATA_HOME") {
		t.Fatal("mandatory exact-binary workflow still requires Kimi")
	}
	if strings.Contains(workflowText, "validateLivePrimaryProcessOverlap") || strings.Contains(workflowText, "maxAttempts = 3") {
		t.Fatal("exact-binary live workflow restored an obsolete overlap or three-attempt predicate")
	}
	if !strings.Contains(workflowText, `\nclean := filepath.Clean(name)`) || strings.Contains(workflowText, `\n\tclean := filepath.Clean(name)`) {
		t.Fatal("exact-binary followup fixture does not keep candidate evidence at an exact column-one boundary")
	}
	if strings.Contains(workflowText, ".Skip(") || strings.Contains(workflowText, ".Skipf(") {
		t.Fatal("exact-binary actual-provider workflow may not skip prerequisites")
	}
	negativeData, err := os.ReadFile(filepath.Join(root, "internal", "adapters", "providercli", "agy_boundary_darwin_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	negative := string(negativeData)
	for _, required := range []string{"//go:build darwin && arm64", "func TestAgyInstalledHomeRejectsOverrideMismatch", "func TestAgyNamespaceRejectsCopiedNativeSettings", "func TestAgyAuthSettingsManifestDetectsMutation"} {
		if !strings.Contains(negative, required) {
			t.Errorf("always-executed AGY boundary coverage missing %q", required)
		}
	}
	if strings.Contains(negative, "liveprovider") || strings.Contains(negative, ".Skip(") || strings.Contains(negative, ".Skipf(") {
		t.Fatal("AGY boundary negative coverage may not require live opt-in or skip")
	}
}

func TestRequiredArtistPrerequisitesFailClosed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test", "e2e", "artist_workspace_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, ".Skip(") || strings.Contains(text, ".Skipf(") || strings.Contains(text, "MULGAE_REQUIRE_ARTIST_E2E") {
		t.Fatal("required Artist/Playwright integration may not skip unavailable prerequisites")
	}
	for _, required := range []string{"func TestIntegrationArtistHomepageWorkspaceReview", "npx", "--offline", "playwright", "t.Fatalf(format, arguments...)"} {
		if !strings.Contains(text, required) {
			t.Errorf("Artist integration fail-closed contract missing %q", required)
		}
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
