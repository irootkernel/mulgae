//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	rolecatalog "github.com/irootkernel/kkachi-agent-review/internal/roles"
)

const checksumSource = "CHECKSUMS.sha256"

type sourceFile struct {
	source string
	bytes  []byte
}

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	root := filepath.Join(filepath.Dir(generatorPath()), "assets")
	files, err := readAssets(root)
	if err != nil {
		return err
	}
	if err := validateRoles(files); err != nil {
		return err
	}
	lines := make([]string, 0, len(files)-1)
	for _, file := range files {
		if file.source == checksumSource {
			continue
		}
		sum := sha256.Sum256(file.bytes)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+file.source+"\n")
	}
	if len(lines) == 0 {
		return fmt.Errorf("generate checksums: no runtime assets")
	}
	return writeFileAtomically(filepath.Join(root, checksumSource), []byte(strings.Join(lines, "")), 0o644)
}

func readAssets(root string) ([]sourceFile, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("stat asset root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, fmt.Errorf("asset root must be a non-symlink directory")
	}

	var files []sourceFile
	err = filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("assets contain symlink %q", filename)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("assets contain non-regular file %q", filename)
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return fmt.Errorf("determine relative path for %q: %w", filename, err)
		}
		source, err := validateSourcePath(filepath.ToSlash(relative))
		if err != nil {
			return fmt.Errorf("invalid asset path %q: %w", filename, err)
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read %q: %w", filename, err)
		}
		files = append(files, sourceFile{source: source, bytes: contents})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk assets: %w", err)
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].source < files[right].source
	})
	return files, nil
}

func validateRoles(files []sourceFile) error {
	definitions := make([]rolecatalog.Definition, 0)
	for _, file := range files {
		if !strings.HasPrefix(file.source, "roles/") {
			continue
		}
		if filepath.Ext(file.source) != ".yaml" || filepath.ToSlash(filepath.Dir(file.source)) != "roles" {
			return fmt.Errorf("role catalog contains unsupported source %q", file.source)
		}
		definition, err := rolecatalog.Parse(file.bytes)
		if err != nil {
			return fmt.Errorf("parse role source %q: %w", file.source, err)
		}
		if filepath.Base(file.source) != definition.ID+".yaml" {
			return fmt.Errorf("role source %q does not match role %q", file.source, definition.ID)
		}
		definitions = append(definitions, definition)
	}
	return rolecatalog.ValidateCatalog(definitions)
}

func writeFileAtomically(filename string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".generate-*")
	if err != nil {
		return fmt.Errorf("create temporary generated file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fmt.Errorf("chmod temporary generated file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary generated file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary generated file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary generated file: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("install generated file: %w", err)
	}
	return nil
}

func generatorPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot determine generator path")
	}
	return filename
}

func validateSourcePath(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) {
		return "", fmt.Errorf("must be non-empty UTF-8")
	}
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || filepath.ToSlash(filepath.Clean(value)) != value {
		return "", fmt.Errorf("must be a canonical slash-relative path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." || component == "" {
			return "", fmt.Errorf("must not contain empty, dot, or dotdot components")
		}
	}
	return value, nil
}
