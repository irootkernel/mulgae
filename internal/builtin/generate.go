//go:build ignore

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	rolecatalog "github.com/irootkernel/kkachi-agent-review/internal/roles"
)

const (
	manifestName = "manifest.json"
	zipPrefix    = "files/"
)

var zipEpoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

type catalogManifest struct {
	Version int             `json:"version"`
	Assets  []manifestAsset `json:"assets"`
}

type manifestAsset struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ZipPath   string `json:"zipPath"`
}

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
	repositoryRoot, err := resolveRepositoryRoot()
	if err != nil {
		return err
	}
	sotRoot := filepath.Join(repositoryRoot, "sot")
	if err := generateChecksums(sotRoot); err != nil {
		return err
	}
	files, err := readSOT(sotRoot)
	if err != nil {
		return err
	}
	roleFiles, err := readRoleDocuments(filepath.Join(repositoryRoot, "roles"))
	if err != nil {
		return err
	}
	files = append(files, roleFiles...)
	sort.Slice(files, func(left, right int) bool { return files[left].source < files[right].source })
	assets, err := buildManifestAssets(files)
	if err != nil {
		return err
	}
	manifestBytes, err := json.Marshal(catalogManifest{Version: 1, Assets: assets})
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	output := filepath.Join(filepath.Dir(generatorPath()), "assets.zip")
	temporary, err := os.CreateTemp(filepath.Dir(output), ".assets.zip-")
	if err != nil {
		return fmt.Errorf("create temporary archive: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := writeArchive(temporary, manifestBytes, files); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary archive: %w", err)
	}
	if err := os.Chmod(temporaryName, 0o644); err != nil {
		return fmt.Errorf("set archive permissions: %w", err)
	}
	if err := os.Rename(temporaryName, output); err != nil {
		return fmt.Errorf("install archive: %w", err)
	}
	archive, err := os.ReadFile(output)
	if err != nil {
		return fmt.Errorf("read generated archive: %w", err)
	}
	digest := sha256.Sum256(archive)
	return updateEmbeddedArchiveDigest(filepath.Join(filepath.Dir(generatorPath()), "catalog.go"), hex.EncodeToString(digest[:]))
}

func generateChecksums(sotRoot string) error {
	files, err := readSOT(sotRoot)
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(files)-1)
	for _, file := range files {
		if file.source == "CHECKSUMS.sha256" {
			continue
		}
		sum := sha256.Sum256(file.bytes)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+file.source+"\n")
	}
	if len(lines) == 0 {
		return fmt.Errorf("generate checksums: no SOT payloads")
	}
	return writeFileAtomically(filepath.Join(sotRoot, "CHECKSUMS.sha256"), []byte(strings.Join(lines, "")), 0o644)
}

func readRoleDocuments(root string) ([]sourceFile, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read role catalog: %w", err)
	}
	files := make([]sourceFile, 0, len(entries))
	definitions := make([]rolecatalog.Definition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			return nil, fmt.Errorf("role catalog contains unsupported entry %q", entry.Name())
		}
		filename := filepath.Join(root, entry.Name())
		info, err := os.Lstat(filename)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("role catalog entry %q is not a regular file", entry.Name())
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read role catalog entry %q: %w", entry.Name(), err)
		}
		definition, err := rolecatalog.Parse(contents)
		if err != nil {
			return nil, fmt.Errorf("parse role catalog entry %q: %w", entry.Name(), err)
		}
		if entry.Name() != definition.ID+".yaml" {
			return nil, fmt.Errorf("role catalog filename %q does not match role %q", entry.Name(), definition.ID)
		}
		definitions = append(definitions, definition)
		files = append(files, sourceFile{source: "roles/" + entry.Name(), bytes: contents})
	}
	if err := rolecatalog.ValidateCatalog(definitions); err != nil {
		return nil, err
	}
	return files, nil
}

func updateEmbeddedArchiveDigest(filename, digest string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read catalog source: %w", err)
	}
	prefix := []byte(`embeddedArchiveSHA256 = "`)
	start := bytes.Index(data, prefix)
	if start < 0 || bytes.Index(data[start+len(prefix):], prefix) >= 0 {
		return fmt.Errorf("catalog digest declaration is missing or ambiguous")
	}
	valueStart := start + len(prefix)
	valueEnd := bytes.IndexByte(data[valueStart:], '"')
	if valueEnd < 0 {
		return fmt.Errorf("catalog digest declaration is unterminated")
	}
	valueEnd += valueStart
	updated := make([]byte, 0, len(data)-valueEnd+valueStart+len(digest))
	updated = append(updated, data[:valueStart]...)
	updated = append(updated, digest...)
	updated = append(updated, data[valueEnd:]...)
	return writeFileAtomically(filename, updated, 0o644)
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

func resolveRepositoryRoot() (string, error) {
	generatorDirectory := filepath.Dir(generatorPath())
	repositoryRoot, err := filepath.Abs(filepath.Join(generatorDirectory, "..", ".."))
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	info, err := os.Lstat(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("stat repository root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("repository root must be a non-symlink directory")
	}
	return repositoryRoot, nil
}

func generatorPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot determine generator path")
	}
	return filename
}

func readSOT(root string) ([]sourceFile, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("stat sot root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, fmt.Errorf("sot root must be a non-symlink directory")
	}

	var files []sourceFile
	err = filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == filepath.Join(root, "plan") && entry.IsDir() {
			return filepath.SkipDir
		}
		info, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("sot contains symlink %q", filename)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("sot contains non-regular file %q", filename)
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return fmt.Errorf("determine relative path for %q: %w", filename, err)
		}
		source, err := validateSourcePath(filepath.ToSlash(relative))
		if err != nil {
			return fmt.Errorf("invalid sot path %q: %w", filename, err)
		}
		contents, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read %q: %w", filename, err)
		}
		files = append(files, sourceFile{source: source, bytes: contents})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk sot: %w", err)
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].source < files[right].source
	})
	return files, nil
}

func buildManifestAssets(files []sourceFile) ([]manifestAsset, error) {
	bySource := make(map[string]sourceFile, len(files))
	assets := make([]manifestAsset, 0, len(files)+14)
	for _, file := range files {
		if _, exists := bySource[file.source]; exists {
			return nil, fmt.Errorf("duplicate source path %q", file.source)
		}
		bySource[file.source] = file
		id, kind, err := canonicalIdentity(file.source, file.bytes)
		if err != nil {
			return nil, err
		}
		assets = append(assets, newManifestAsset(id, kind, file.source, file.bytes))
	}

	for id, source := range defaultAliases {
		file, exists := bySource[source]
		if !exists {
			return nil, fmt.Errorf("default alias %q source %q is absent", id, source)
		}
		assets = append(assets, newManifestAsset(id, "defaults", source, file.bytes))
	}
	for id, source := range helpAliases {
		file, exists := bySource[source]
		if !exists {
			return nil, fmt.Errorf("help alias %q source %q is absent", id, source)
		}
		assets = append(assets, newManifestAsset(id, "help", source, file.bytes))
	}

	sort.Slice(assets, func(left, right int) bool {
		if assets[left].Source != assets[right].Source {
			return assets[left].Source < assets[right].Source
		}
		leftCanonical := isCanonicalKind(assets[left].Kind)
		rightCanonical := isCanonicalKind(assets[right].Kind)
		if leftCanonical != rightCanonical {
			return leftCanonical
		}
		return assets[left].ID < assets[right].ID
	})
	return assets, nil
}

func newManifestAsset(id, kind, source string, contents []byte) manifestAsset {
	sum := sha256.Sum256(contents)
	return manifestAsset{
		ID:        id,
		Kind:      kind,
		Source:    source,
		MediaType: mediaTypeFor(source, kind),
		Size:      int64(len(contents)),
		SHA256:    hex.EncodeToString(sum[:]),
		ZipPath:   zipPrefix + source,
	}
}

func canonicalIdentity(source string, contents []byte) (string, string, error) {
	switch {
	case strings.HasPrefix(source, "schemas/") && strings.HasSuffix(source, ".schema.json"):
		var schema struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(contents, &schema); err != nil {
			return "", "", fmt.Errorf("decode schema %q identity: %w", source, err)
		}
		if schema.ID == "" {
			return "", "", fmt.Errorf("schema %q has no $id", source)
		}
		return schema.ID, "schema", nil
	case strings.HasPrefix(source, "examples/"):
		return "example:" + path.Base(source), "example", nil
	default:
		return "sot:" + source, "sot", nil
	}
}

func isCanonicalKind(kind string) bool {
	return kind == "sot" || kind == "schema" || kind == "example"
}

func mediaTypeFor(source, kind string) string {
	if kind == "schema" {
		return "application/schema+json"
	}
	switch path.Ext(source) {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".md":
		return "text/markdown"
	case ".txt", ".sha256":
		return "text/plain"
	default:
		return "text/plain"
	}
}

func writeArchive(output io.Writer, manifestBytes []byte, files []sourceFile) error {
	archive := zip.NewWriter(output)
	if err := writeZipEntry(archive, manifestName, manifestBytes); err != nil {
		archive.Close()
		return err
	}
	for _, file := range files {
		if err := writeZipEntry(archive, zipPrefix+file.source, file.bytes); err != nil {
			archive.Close()
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}
	return nil
}

func writeZipEntry(archive *zip.Writer, name string, contents []byte) error {
	header := &zip.FileHeader{
		Name:               name,
		Method:             zip.Store,
		UncompressedSize64: uint64(len(contents)),
		CompressedSize64:   uint64(len(contents)),
		CRC32:              crc32.ChecksumIEEE(contents),
	}
	header.SetModTime(zipEpoch)
	header.SetMode(0o644)
	writer, err := archive.CreateRaw(header)
	if err != nil {
		return fmt.Errorf("create zip entry %q: %w", name, err)
	}
	written, err := writer.Write(contents)
	if err != nil {
		return fmt.Errorf("write zip entry %q: %w", name, err)
	}
	if written != len(contents) {
		return fmt.Errorf("write zip entry %q: wrote %d of %d bytes", name, written, len(contents))
	}
	return nil
}

func validateSourcePath(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) {
		return "", fmt.Errorf("must be non-empty UTF-8")
	}
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return "", fmt.Errorf("must be a canonical slash-relative path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." || component == "" {
			return "", fmt.Errorf("must not contain empty, dot, or dotdot components")
		}
	}
	return value, nil
}

var defaultAliases = map[string]string{}

var helpAliases = map[string]string{
	"help:quickstart": "README.md",
	"help:config":     "docs/04-configuration.md",
	"help:providers":  "docs/05-provider-runtime-and-scheduling.md",
	"help:lanes":      "docs/05-provider-runtime-and-scheduling.md",
	"help:prompts":    "docs/06-prompt-contract.md",
	"help:workflows":  "docs/03-cli-workflows.md",
	"help:artifacts":  "docs/08-artifacts-lineage-and-storage.md",
	"help:validation": "docs/07-output-validation-and-repair.md",
	"help:ci":         "docs/10-reporting-ci-and-exit-codes.md",
	"help:exit-codes": "docs/10-reporting-ci-and-exit-codes.md",
	"help:security":   "docs/09-security-and-trust.md",
}
