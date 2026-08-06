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

	rolecatalog "github.com/irootkernel/mulgae/internal/roles"
)

const checksumSource = "CHECKSUMS.sha256"

// rootRoleSource is the catalog source name of the repository-root role
// document. It is embedded by the root assets package rather than the embedded
// asset tree, so it is read explicitly and held to the same checksum inventory.
const rootRoleSource = "roles.yaml"

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
	packageRoot := filepath.Dir(generatorPath())
	files, err := readAssets(filepath.Join(packageRoot, "assets"))
	if err != nil {
		return err
	}
	rootRoles, err := readRootRoleDocument(filepath.Join(packageRoot, "..", "..", "assets", rootRoleSource))
	if err != nil {
		return err
	}
	files = append(files, rootRoles)
	sort.Slice(files, func(left, right int) bool {
		return files[left].source < files[right].source
	})
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
	return writeFileAtomically(filepath.Join(packageRoot, "assets", checksumSource), []byte(strings.Join(lines, "")), 0o644)
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

// readRootRoleDocument reads the repository-root role document under the same
// symlink and regular-file rules the embedded asset walk applies.
func readRootRoleDocument(filename string) (sourceFile, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return sourceFile{}, fmt.Errorf("stat root role document: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return sourceFile{}, fmt.Errorf("root role document must be a non-symlink regular file")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return sourceFile{}, fmt.Errorf("read root role document: %w", err)
	}
	return sourceFile{source: rootRoleSource, bytes: contents}, nil
}

func validateRoles(files []sourceFile) error {
	for _, file := range files {
		if file.source != rootRoleSource {
			continue
		}
		if _, err := rolecatalog.ParseCatalog(file.bytes); err != nil {
			return fmt.Errorf("parse role source %q: %w", file.source, err)
		}
		return nil
	}
	return fmt.Errorf("role catalog has no %s", rootRoleSource)
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
