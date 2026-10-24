package architecture

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func wireLeafViolations(files fs.FS, allowed map[string]bool) ([]string, error) {
	var violations []string
	err := fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := fs.ReadFile(files, path)
		if err != nil {
			return err
		}
		// Parse all production files, including inactive and ignore build tags.
		file, err := parser.ParseFile(token.NewFileSet(), path, raw, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if !allowed[name] {
				violations = append(violations, fmt.Sprintf("%s imports %q", path, name))
			}
		}
		return nil
	})
	return violations, err
}

func TestWireLeafDependencyDirection(t *testing.T) {
	allowlists := map[string]map[string]bool{
		"artifactwire": {"fmt": true, "strings": true},
		"strictjson":   {"bytes": true, "encoding/json": true, "fmt": true, "io": true, "unicode/utf8": true},
	}
	for name, allowed := range allowlists {
		path := filepath.Join(repositoryRoot(t), "internal", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
		violations, err := wireLeafViolations(os.DirFS(path), allowed)
		if err != nil {
			t.Fatal(err)
		}
		for _, violation := range violations {
			t.Errorf("%s: %s", name, violation)
		}
	}
	for name, allowed := range allowlists {
		for imported := range allowed {
			files := fstest.MapFS{"allowed.go": {Data: []byte("package leaf\nimport _ " + strconv.Quote(imported))}}
			if violations, err := wireLeafViolations(files, allowed); err != nil || len(violations) != 0 {
				t.Fatalf("%s permitted %s: %v %v", name, imported, violations, err)
			}
		}
		for _, imported := range []string{"os", "os/exec", "unsafe", "C", modulePath + "internal/domain", modulePath + "internal/ports", modulePath + "internal/app/query", modulePath + "internal/adapters/filesystem", "gopkg.in/yaml.v3", "github.com/santhosh-tekuri/jsonschema/v5"} {
			files := fstest.MapFS{
				"tagged.go":       {Data: []byte("//go:build ignore\n\npackage leaf\nimport _ " + strconv.Quote(imported))},
				"allowed_test.go": {Data: []byte("package leaf\nimport _ \"os\"")},
			}
			violations, err := wireLeafViolations(files, allowed)
			if err != nil || len(violations) != 1 || !strings.Contains(violations[0], strconv.Quote(imported)) {
				t.Fatalf("%s forbidden %s: %v %v", name, imported, violations, err)
			}
		}
	}
}
