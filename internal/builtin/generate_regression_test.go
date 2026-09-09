//go:build ignore

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateMatchesGoEmbed(t *testing.T) {
	root := t.TempDir()
	packageRoot := filepath.Join(root, "internal", "builtin")
	write := func(name string, contents []byte) {
		t.Helper()
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roles, err := os.ReadFile("../../assets/roles.yaml")
	if err != nil {
		t.Fatal(err)
	}
	write("assets/roles.yaml", roles)
	write("go.mod", []byte("module fixture\n\ngo 1.26.0\n"))
	write("internal/builtin/catalog.go", []byte("package fixture\nimport \"embed\"\n//go:embed assets\nvar assets embed.FS\n"))
	write("internal/builtin/assets/visible.txt", []byte("first"))
	write("internal/builtin/assets/nested/visible.txt", []byte("nested"))
	for _, name := range []string{".hidden", "_hidden", ".omc/state/file.json", "_cache/nested/file", "nested/.hidden", "nested/_hidden", "nested/.state/file", "nested/_state/file"} {
		write("internal/builtin/assets/"+name, []byte("excluded"))
	}
	readChecksums := func() []byte {
		t.Helper()
		contents, err := os.ReadFile(filepath.Join(packageRoot, "assets", checksumSource))
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	if err := generate(packageRoot); err != nil {
		t.Fatal(err)
	}
	first := readChecksums()
	command := exec.CommandContext(t.Context(), "go", "list", "-json", ".")
	command.Dir = packageRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list embedded fixture: %v\n%s", err, output)
	}
	var metadata struct{ EmbedFiles []string }
	if err := json.Unmarshal(output, &metadata); err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{rootRoleSource: true}
	for _, name := range metadata.EmbedFiles {
		source := strings.TrimPrefix(name, "assets/")
		if source != checksumSource {
			expected[source] = true
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(first)), "\n") {
		fields := strings.SplitN(line, "  ", 2)
		if len(fields) != 2 || !expected[fields[1]] {
			t.Fatalf("checksum entry is not an embedded source or root role document: %q", line)
		}
		delete(expected, fields[1])
	}
	if len(expected) != 0 {
		t.Fatalf("embedded sources missing checksums: %v", expected)
	}
	write("internal/builtin/assets/.omc/state/file.json", []byte("changed"))
	write("internal/builtin/assets/nested/_new/file", []byte("new"))
	if err := generate(packageRoot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, readChecksums()) {
		t.Fatal("excluded files changed the checksum inventory")
	}
	write("internal/builtin/assets/visible.txt", []byte("second"))
	if err := generate(packageRoot); err != nil {
		t.Fatal(err)
	}
	second := readChecksums()
	digest := sha256.Sum256([]byte("second"))
	if bytes.Equal(first, second) || !bytes.Contains(second, []byte(hex.EncodeToString(digest[:])+"  visible.txt\n")) {
		t.Fatal("included content change was not reflected in its checksum")
	}
	if err := generate(packageRoot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, readChecksums()) {
		t.Fatal("second generation changed the checksum inventory")
	}
}

func TestReadAssetsPreservesAdmission(t *testing.T) {
	for _, name := range []string{"visible", ".hidden", "_hidden", ".omc/link"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), ".asset-root")
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "included"), []byte("source"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("missing-target", filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			files, err := readAssets(root)
			if name == "visible" {
				if err == nil || !strings.Contains(err.Error(), "symlink") {
					t.Fatalf("visible symlink was not rejected: %v", err)
				}
				return
			}
			if err != nil || len(files) != 1 || files[0].source != "included" {
				t.Fatalf("hidden entries affected admission: files=%v err=%v", files, err)
			}
		})
	}
}
