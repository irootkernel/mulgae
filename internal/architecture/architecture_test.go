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

const modulePath = "github.com/irootkernel/kkachi-agent-review/"

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

func TestMakefileContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, target := range []string{"test:", "test-prepare:", "test-unit:", "test-int:", "test-e2e:"} {
		if !strings.Contains(text, target) {
			t.Errorf("Makefile missing %s", target)
		}
	}
	positions := []int{strings.Index(text, "$(MAKE) test-prepare"), strings.Index(text, "$(MAKE) test-unit"), strings.Index(text, "$(MAKE) test-int"), strings.Index(text, "$(MAKE) test-e2e")}
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
	integrationEnd := strings.Index(text, "\ntest-e2e:")
	if integrationEnd <= integrationStart || !strings.Contains(text[integrationStart:integrationEnd], "test -p 1 ") {
		t.Fatal("test-int does not serialize race-instrumented package execution")
	}
	if !strings.Contains(text, "go build") && !strings.Contains(text, "$(GO) build") {
		t.Fatal("test-e2e does not build the production binary")
	}
	specVersion, err := os.ReadFile(filepath.Join(repositoryRoot(t), "sot", "SPEC_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	wantBuildVersion := "main.buildVersion=v" + strings.TrimSpace(string(specVersion))
	if !strings.Contains(text, wantBuildVersion) {
		t.Fatalf("test-e2e release candidate metadata does not match SOT: want %q", wantBuildVersion)
	}
	for _, required := range []string{
		"kimi_bin=", `test -n "$$kimi_bin"`, "zcode_node=", `test -n "$$zcode_node"`,
		"zcode_launcher=", `test -f "$$zcode_launcher"`, "agy_bin=", `test -n "$$agy_bin"`,
		"KAR_LIVE_KIMI_BIN", "KAR_LIVE_ZCODE_NODE_BIN", "KAR_LIVE_ZCODE_LAUNCHER", "KAR_LIVE_AGY_BIN",
		"-tags=liveprovider", "-run '^TestLive(Kimi|ZCode|Agy)Capability$$'", "KAR_E2E_BINARY", "KAR_E2E_PROJECT_ROOT",
		"KAR_E2E_KIMI_EXECUTABLE", "KAR_E2E_ZCODE_NODE_EXECUTABLE", "KAR_E2E_ZCODE_LAUNCHER", "KAR_E2E_AGY_EXECUTABLE",
		"-tags=live_e2e", "-run '^Test(E2E|Live)'", "[test-e2e] failed; preserved private project:",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("test-e2e missing fail-closed family-capability token %q", required)
		}
	}
	capability := strings.Index(text, "-tags=liveprovider")
	workflow := strings.Index(text, "-tags=live_e2e")
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
	workflowData, err := os.ReadFile(filepath.Join(root, "cmd", "kar", "live_e2e_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	workflowText := string(workflowData)
	for _, required := range []string{
		"func TestE2EActualProvidersProductionWorkflow", "runLiveChildProductionWorkflows", `"followup"`, `"delta"`, `"exact"`, `"recompose"`,
		"validateLiveProviderQualificationHealth", "validateLiveRecoverableAssignments", "validateLivePrimaryProcessTerminals",
		"KAR_E2E_BINARY", "KAR_E2E_KIMI_EXECUTABLE", "KAR_E2E_ZCODE_NODE_EXECUTABLE", "KAR_E2E_ZCODE_LAUNCHER", "KAR_E2E_AGY_EXECUTABLE",
	} {
		if !strings.Contains(workflowText, required) {
			t.Errorf("exact-binary live workflow contract missing %q", required)
		}
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
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "cmd", "kar", "artist_workspace_e2e_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, ".Skip(") || strings.Contains(text, ".Skipf(") || strings.Contains(text, "KAR_REQUIRE_ARTIST_E2E") {
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
