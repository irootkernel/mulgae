package architecture

import (
	"go/ast"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func testSupportViolations(files fs.FS) ([]string, error) {
	var violations []string
	err := walkOwnershipSources(files, func(path string, file *ast.File) error {
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if importNamespace(imported, modulePath+"internal/testsupport") || importNamespace(imported, modulePath+"internal/adapters/fakeprovider") {
				violations = append(violations, path+": production-test-double: "+strconv.Quote(imported))
			}
		}
		return nil
	})
	return violations, err
}

func TestTestSupportDependencyDirection(t *testing.T) {
	violations, err := testSupportViolations(os.DirFS(repositoryRoot(t)))
	requireOwnershipViolations(t, violations, err)
}

func TestTestSupportDependencyControls(t *testing.T) {
	for _, root := range []string{"internal/testsupport", "internal/adapters/fakeprovider"} {
		for _, suffix := range []string{"", "/historical"} {
			for _, alias := range []string{"", "renamed", "_", "."} {
				for _, header := range []string{"", "//go:build ignore\n\n", "//go:build windows\n\n"} {
					t.Run(root+suffix+"/"+alias+"/"+header, func(t *testing.T) {
						const path = "tools/selected_windows.go"
						got, err := testSupportViolations(ownershipImportFixture(path, header, alias, "context"))
						requireOwnershipViolations(t, got, err)
						imported := modulePath + root + suffix
						got, err = testSupportViolations(ownershipImportFixture(path, header, alias, imported))
						requireOwnershipViolations(t, got, err, path+": production-test-double: "+strconv.Quote(imported))
					})
				}
			}
		}
	}
	for _, test := range []struct{ path, imported string }{
		{"main.go", modulePath + "internal/testsupportish"},
		{"main.go", modulePath + "internal/adapters/fakeproviderish"},
		{"main.go", "example.org/internal/testsupport"},
		{"internal/app/read_test.go", modulePath + "internal/testsupport/historical"},
		{"internal/app/review/fake_test.go", modulePath + "internal/adapters/fakeprovider"},
		{"internal/adapters/filesystem/read.go", modulePath + "internal/adapters/workspace"},
	} {
		t.Run(test.path+"/"+test.imported, func(t *testing.T) {
			got, err := testSupportViolations(ownershipImportFixture(test.path, "", "_", test.imported))
			requireOwnershipViolations(t, got, err)
		})
	}
	t.Run("malformed source", func(t *testing.T) {
		got, err := testSupportViolations(ownershipImportFixture("main.go", "", "_", "context"))
		requireOwnershipViolations(t, got, err)
		got, err = testSupportViolations(fstest.MapFS{"main.go": {Data: []byte("package")}})
		if err == nil || !strings.HasPrefix(err.Error(), "main.go: parse source: ") || len(got) != 0 {
			t.Fatalf("inspection = %q, %v; want malformed-source error only", got, err)
		}
	})
}
