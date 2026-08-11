package builtin

//go:generate go run generate.go

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	rootassets "github.com/irootkernel/mulgae/assets"
	"github.com/irootkernel/mulgae/internal/ports"
	rolecatalog "github.com/irootkernel/mulgae/internal/roles"
)

const catalogChecksumSource = "CHECKSUMS.sha256"

// rootRoleSource is the catalog source name of the repository-root role
// document. go:embed patterns cannot escape their own package directory, so the
// document is embedded by the root assets package and overlaid here.
const rootRoleSource = "roles.yaml"

// embeddedAssets contains the authoritative runtime catalog as ordinary files.
// No generated archive or extraction step is involved.
//
//go:embed assets
var embeddedAssets embed.FS

// Catalog implements ports.ContractCatalog over an immutable filesystem. The
// checksum inventory and every asset are validated once before reads succeed.
type Catalog struct {
	filesystem fs.FS
	// overlay carries assets that live outside the embedded filesystem. It is
	// merged before checksum validation, so overlaid bytes are held to the same
	// inventory as every embedded file.
	overlay map[string][]byte

	once  sync.Once
	state catalogState
}

type catalogState struct {
	assets map[string]catalogAsset
	list   []ports.AssetMetadata
	err    error
}

type catalogAsset struct {
	metadata ports.AssetMetadata
	bytes    []byte
}

var _ ports.ContractCatalog = (*Catalog)(nil)

// NewCatalog returns a catalog backed by the directly embedded runtime assets
// and the repository-root role document.
func NewCatalog() *Catalog {
	embedded, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		return &Catalog{state: failedCatalogState(fmt.Errorf("open embedded assets: %w", err))}
	}
	return &Catalog{
		filesystem: embedded,
		overlay:    map[string][]byte{rootRoleSource: rootassets.RolesYAML},
	}
}

// Read returns validated metadata and a newly allocated caller-owned copy of
// the requested asset bytes.
func (catalog *Catalog) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if catalog == nil {
		return ports.AssetMetadata{}, nil, fmt.Errorf("builtin catalog: nil catalog")
	}
	if err := ctx.Err(); err != nil {
		return ports.AssetMetadata{}, nil, fmt.Errorf("builtin catalog: read context: %w", err)
	}
	if !id.Valid() {
		return ports.AssetMetadata{}, nil, fmt.Errorf("builtin catalog: invalid asset ID")
	}
	state := catalog.initialize()
	if state.err != nil {
		return ports.AssetMetadata{}, nil, fmt.Errorf("builtin catalog: initialize: %w", state.err)
	}
	asset, exists := state.assets[id.String()]
	if !exists {
		return ports.AssetMetadata{}, nil, fmt.Errorf("builtin catalog: asset %q not found", id.String())
	}
	return asset.metadata, append([]byte(nil), asset.bytes...), nil
}

// List returns every asset exactly once in ascending AssetID.String() order.
func (catalog *Catalog) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	if catalog == nil {
		return nil, fmt.Errorf("builtin catalog: nil catalog")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("builtin catalog: list context: %w", err)
	}
	state := catalog.initialize()
	if state.err != nil {
		return nil, fmt.Errorf("builtin catalog: initialize: %w", state.err)
	}
	return append([]ports.AssetMetadata(nil), state.list...), nil
}

func (catalog *Catalog) initialize() catalogState {
	catalog.once.Do(func() {
		if catalog.state.err == nil {
			catalog.state = loadCatalog(catalog.filesystem, catalog.overlay)
		}
	})
	return catalog.state
}

func loadCatalog(filesystem fs.FS, overlay map[string][]byte) catalogState {
	if filesystem == nil {
		return failedCatalogState(fmt.Errorf("asset filesystem is unavailable"))
	}
	files, err := readCatalogFiles(filesystem)
	if err != nil {
		return failedCatalogState(err)
	}
	for source, contents := range overlay {
		if _, duplicate := files[source]; duplicate {
			return failedCatalogState(fmt.Errorf("overlaid asset %q collides with an embedded asset", source))
		}
		if _, err := validateEmbeddedSource(source); err != nil {
			return failedCatalogState(fmt.Errorf("invalid overlaid asset path %q: %w", source, err))
		}
		files[source] = append([]byte(nil), contents...)
	}
	checksumBytes, exists := files[catalogChecksumSource]
	if !exists {
		return failedCatalogState(fmt.Errorf("catalog has no %s", catalogChecksumSource))
	}
	checksums, err := parseChecksums(checksumBytes)
	if err != nil {
		return failedCatalogState(err)
	}
	if err := validateChecksums(files, checksums); err != nil {
		return failedCatalogState(err)
	}
	if err := validateRoleAssets(files); err != nil {
		return failedCatalogState(err)
	}
	return buildCatalog(files)
}

func failedCatalogState(err error) catalogState {
	return catalogState{err: err}
}

func readCatalogFiles(filesystem fs.FS) (map[string][]byte, error) {
	files := make(map[string][]byte)
	err := fs.WalkDir(filesystem, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		source, err := validateEmbeddedSource(name)
		if err != nil {
			return fmt.Errorf("invalid embedded source %q: %w", name, err)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat embedded source %q: %w", source, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("embedded source %q is not a regular file", source)
		}
		contents, err := fs.ReadFile(filesystem, name)
		if err != nil {
			return fmt.Errorf("read embedded source %q: %w", source, err)
		}
		files[source] = contents
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk embedded assets: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("catalog contains no assets")
	}
	return files, nil
}

func parseChecksums(contents []byte) (map[string]string, error) {
	if len(contents) == 0 || !utf8.Valid(contents) || contents[len(contents)-1] != '\n' {
		return nil, fmt.Errorf("checksum inventory is not canonical UTF-8")
	}
	checksums := make(map[string]string)
	var previous string
	for index, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		if len(line) < sha256.Size*2+3 || line[sha256.Size*2:sha256.Size*2+2] != "  " {
			return nil, fmt.Errorf("checksum inventory line %d is malformed", index+1)
		}
		digest := line[:sha256.Size*2]
		source, err := validateEmbeddedSource(line[sha256.Size*2+2:])
		if err != nil || source == catalogChecksumSource || !isLowerSHA256(digest) {
			return nil, fmt.Errorf("checksum inventory line %d is invalid", index+1)
		}
		if previous != "" && source <= previous {
			return nil, fmt.Errorf("checksum inventory is not strictly source-sorted")
		}
		if _, duplicate := checksums[source]; duplicate {
			return nil, fmt.Errorf("checksum inventory has duplicate source %q", source)
		}
		checksums[source] = digest
		previous = source
	}
	if len(checksums) == 0 {
		return nil, fmt.Errorf("checksum inventory contains no asset digests")
	}
	return checksums, nil
}

func validateChecksums(files map[string][]byte, checksums map[string]string) error {
	if len(files) != len(checksums)+1 {
		return fmt.Errorf("checksum inventory and embedded sources are not one-to-one")
	}
	for source, contents := range files {
		if source == catalogChecksumSource {
			continue
		}
		expected, exists := checksums[source]
		if !exists {
			return fmt.Errorf("embedded source %q has no checksum", source)
		}
		sum := sha256.Sum256(contents)
		if hex.EncodeToString(sum[:]) != expected {
			return fmt.Errorf("embedded source %q does not match its checksum", source)
		}
	}
	for source := range checksums {
		if _, exists := files[source]; !exists {
			return fmt.Errorf("checksum source %q is absent", source)
		}
	}
	return nil
}

// validateRoleAssets proves the role document parses and describes every fixed
// role before any asset is served.
//
// The role document is a build-owned source-of-truth asset. It supplies the
// review system prompts, init's generation-time default provider preference
// order, and the artist input defaults. It is never a runtime configuration
// authority: no command resolves a configured value from embedded bytes, and
// .mulgae/config.yaml is never re-derived after init.
func validateRoleAssets(files map[string][]byte) error {
	contents, exists := files[rootRoleSource]
	if !exists {
		return fmt.Errorf("catalog has no %s", rootRoleSource)
	}
	if _, err := rolecatalog.ParseCatalog(contents); err != nil {
		return fmt.Errorf("parse role source %q: %w", rootRoleSource, err)
	}
	return nil
}

func buildCatalog(files map[string][]byte) catalogState {
	assets := make(map[string]catalogAsset, len(files)+len(catalogHelpAliases))
	sources := make([]string, 0, len(files))
	for source := range files {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		id, kind, err := catalogCanonicalIdentity(source, files[source])
		if err != nil {
			return failedCatalogState(err)
		}
		if err := addCatalogAsset(assets, id, kind, source, files[source]); err != nil {
			return failedCatalogState(err)
		}
	}
	if err := addCatalogAliases(assets, files, catalogHelpAliases, ports.AssetKindHelp, "help"); err != nil {
		return failedCatalogState(err)
	}
	if err := addCatalogAliases(assets, files, catalogDefaultAliases, ports.AssetKindDefaults, "default"); err != nil {
		return failedCatalogState(err)
	}

	list := make([]ports.AssetMetadata, 0, len(assets))
	for _, asset := range assets {
		list = append(list, asset.metadata)
	}
	sort.Slice(list, func(left, right int) bool {
		return list[left].ID().String() < list[right].ID().String()
	})
	return catalogState{assets: assets, list: list}
}

func addCatalogAliases(assets map[string]catalogAsset, files map[string][]byte, aliases map[string]string, kind ports.AssetKind, name string) error {
	ids := make([]string, 0, len(aliases))
	for id := range aliases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		source := aliases[id]
		contents, exists := files[source]
		if !exists {
			return fmt.Errorf("%s alias %q source %q is absent", name, id, source)
		}
		if err := addCatalogAsset(assets, id, kind, source, contents); err != nil {
			return err
		}
	}
	return nil
}

func addCatalogAsset(assets map[string]catalogAsset, idValue string, kind ports.AssetKind, source string, contents []byte) error {
	id, err := ports.ParseAssetID(idValue)
	if err != nil {
		return fmt.Errorf("invalid asset ID %q: %w", idValue, err)
	}
	if _, duplicate := assets[idValue]; duplicate {
		return fmt.Errorf("duplicate asset ID %q", idValue)
	}
	sourcePath, err := ports.NewSafeRelativePath(source)
	if err != nil {
		return fmt.Errorf("asset %q source metadata: %w", idValue, err)
	}
	sum := sha256.Sum256(contents)
	metadata, err := ports.NewAssetMetadata(
		id,
		kind,
		sourcePath,
		catalogMediaType(source, kind),
		"sha256:"+hex.EncodeToString(sum[:]),
		int64(len(contents)),
	)
	if err != nil {
		return fmt.Errorf("asset %q metadata: %w", idValue, err)
	}
	assets[idValue] = catalogAsset{metadata: metadata, bytes: append([]byte(nil), contents...)}
	return nil
}

func catalogCanonicalIdentity(source string, contents []byte) (string, ports.AssetKind, error) {
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
		return schema.ID, ports.AssetKindSchema, nil
	case strings.HasPrefix(source, "examples/"):
		return "example:" + path.Base(source), ports.AssetKindExample, nil
	default:
		return "sot:" + source, ports.AssetKindSOT, nil
	}
}

func catalogMediaType(source string, kind ports.AssetKind) string {
	if kind == ports.AssetKindSchema {
		return "application/schema+json"
	}
	switch path.Ext(source) {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".md":
		return "text/markdown"
	default:
		return "text/plain"
	}
}

func validateEmbeddedSource(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) {
		return "", fmt.Errorf("must be non-empty UTF-8")
	}
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value || !fs.ValidPath(value) {
		return "", fmt.Errorf("must be a canonical slash-relative path")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("must not contain empty, dot, or dotdot components")
		}
	}
	return value, nil
}

func isLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// Configuration examples are documentation assets only. No catalog alias may
// turn embedded bytes into a runtime configuration authority.
var catalogDefaultAliases = map[string]string{}

var catalogHelpAliases = map[string]string{
	"help:quickstart": "help/quickstart.md",
	"help:config":     "help/config.md",
	"help:providers":  "help/providers.md",
	"help:role-paths": "help/providers.md",
	"help:prompts":    "help/prompts.md",
	"help:workflows":  "help/workflows.md",
	"help:artifacts":  "help/artifacts.md",
	"help:validation": "help/validation.md",
	"help:ci":         "help/automation.md",
	"help:exit-codes": "help/automation.md",
	"help:security":   "help/security.md",
}
