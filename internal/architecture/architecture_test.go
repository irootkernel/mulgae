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
	if !strings.Contains(text, "go build") && !strings.Contains(text, "$(GO) build") {
		t.Fatal("test-e2e does not build the production binary")
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
