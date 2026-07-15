package domain

import (
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDomainHasNoExternalOrAdapterDependencies(t *testing.T) {
	t.Parallel()

	domainSafeImports := map[string]struct{}{
		"crypto/sha256": {},
		"encoding/hex":  {},
		"encoding/json": {},
		"errors":        {},
		"fmt":           {},
		"path":          {},
		"regexp":        {},
		"sort":          {},
		"strings":       {},
		"time":          {},
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(entry.Name()), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if strings.Contains(comment.Text, "go:linkname") {
					t.Errorf("domain file %s uses go:linkname", entry.Name())
				}
			}
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", entry.Name(), err)
			}
			if path == "C" {
				t.Errorf("domain file %s imports cgo", entry.Name())
				continue
			}
			if path == "unsafe" {
				t.Errorf("domain file %s imports unsafe", entry.Name())
				continue
			}
			pkg, err := build.Default.Import(path, ".", build.FindOnly)
			if err != nil {
				t.Errorf("domain file %s imports unresolved or non-stdlib package %q: %v", entry.Name(), path, err)
				continue
			}
			if !pkg.Goroot {
				t.Errorf("domain file %s imports non-stdlib package %q", entry.Name(), path)
				continue
			}
			if _, allowed := domainSafeImports[path]; !allowed {
				t.Errorf("domain file %s imports stdlib capability outside the reviewed domain allowlist: %q", entry.Name(), path)
			}
		}
	}
}
