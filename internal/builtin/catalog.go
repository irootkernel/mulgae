package builtin

//go:generate go run generate.go

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	catalogManifestName   = "manifest.json"
	catalogZipPrefix      = "files/"
	embeddedArchiveSHA256 = "48d4d90d46f5e89837a0f6290248b71bdd5138639765e2230b3b09f22d00f0ba"
)

// embeddedArchive is generated from the authoritative repository SOT by
// generate.go. It contains no hand-maintained copies of SOT assets.
//
//go:embed assets.zip
var embeddedArchive []byte

// Catalog implements ports.ContractCatalog over the generated embedded SOT
// archive. Its manifest is validated once before any asset is made available.
type Catalog struct {
	archive        []byte
	expectedSHA256 string

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

type embeddedManifest struct {
	Version int                 `json:"version"`
	Assets  []embeddedAssetInfo `json:"assets"`
}

type embeddedAssetInfo struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ZipPath   string `json:"zipPath"`
}

var _ ports.ContractCatalog = (*Catalog)(nil)

// NewCatalog returns a catalog backed by the exact promoted SOT archive.
func NewCatalog() *Catalog {
	return &Catalog{archive: embeddedArchive, expectedSHA256: embeddedArchiveSHA256}
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
		catalog.state = loadCatalog(catalog.archive, catalog.expectedSHA256)
	})
	return catalog.state
}

func loadCatalog(archive []byte, expectedSHA256 string) catalogState {
	if !isLowerSHA256(expectedSHA256) {
		return failedCatalogState(fmt.Errorf("assets archive has no authoritative digest"))
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return failedCatalogState(fmt.Errorf("assets archive does not match the authoritative digest"))
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return failedCatalogState(fmt.Errorf("read assets archive: %w", err))
	}
	if reader.Comment != "" {
		return failedCatalogState(fmt.Errorf("assets archive has a comment"))
	}

	files := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		if err := validateZipFile(file); err != nil {
			return failedCatalogState(err)
		}
		if _, duplicate := files[file.Name]; duplicate {
			return failedCatalogState(fmt.Errorf("duplicate zip entry %q", file.Name))
		}
		files[file.Name] = file
	}
	manifestFile, exists := files[catalogManifestName]
	if !exists {
		return failedCatalogState(fmt.Errorf("assets archive has no %s", catalogManifestName))
	}
	manifestBytes, err := readZipFile(manifestFile)
	if err != nil {
		return failedCatalogState(fmt.Errorf("read manifest: %w", err))
	}
	manifest, err := parseManifest(manifestBytes)
	if err != nil {
		return failedCatalogState(err)
	}
	return validateCatalogManifest(manifest, files)
}

func failedCatalogState(err error) catalogState {
	return catalogState{err: err}
}

func validateZipFile(file *zip.File) error {
	if file.NonUTF8 || !utf8.ValidString(file.Name) {
		return fmt.Errorf("zip entry %q has a non-UTF-8 name", file.Name)
	}
	if file.Comment != "" {
		return fmt.Errorf("zip entry %q has a comment", file.Name)
	}
	if file.Method != zip.Store {
		return fmt.Errorf("zip entry %q is not stored", file.Name)
	}
	if strings.HasSuffix(file.Name, "/") {
		return fmt.Errorf("zip entry %q is a directory", file.Name)
	}
	if file.Name == catalogManifestName {
		return nil
	}
	if !strings.HasPrefix(file.Name, catalogZipPrefix) {
		return fmt.Errorf("zip entry %q is outside %s", file.Name, catalogZipPrefix)
	}
	if _, err := validateEmbeddedSource(strings.TrimPrefix(file.Name, catalogZipPrefix)); err != nil {
		return fmt.Errorf("zip entry %q has an invalid path: %w", file.Name, err)
	}
	return nil
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	contents, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return contents, nil
}

func parseManifest(contents []byte) (embeddedManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var manifest embeddedManifest
	if err := decoder.Decode(&manifest); err != nil {
		return embeddedManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return embeddedManifest{}, fmt.Errorf("decode manifest: trailing JSON value")
		}
		return embeddedManifest{}, fmt.Errorf("decode manifest suffix: %w", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return embeddedManifest{}, fmt.Errorf("marshal manifest: %w", err)
	}
	if !bytes.Equal(canonical, contents) {
		return embeddedManifest{}, fmt.Errorf("manifest is not canonical JSON")
	}
	return manifest, nil
}

func validateCatalogManifest(manifest embeddedManifest, files map[string]*zip.File) catalogState {
	if manifest.Version != 1 {
		return failedCatalogState(fmt.Errorf("unsupported manifest version %d", manifest.Version))
	}
	if len(manifest.Assets) == 0 {
		return failedCatalogState(fmt.Errorf("manifest contains no assets"))
	}

	expectedZipPaths := make(map[string]struct{}, len(manifest.Assets))
	identities := make(map[string]sourceIdentity, len(manifest.Assets))
	assets := make(map[string]catalogAsset, len(manifest.Assets))
	helpIDs := make(map[string]struct{}, len(catalogHelpAliases))
	defaultIDs := make(map[string]struct{}, len(catalogDefaultAliases))

	for _, asset := range manifest.Assets {
		id, err := ports.ParseAssetID(asset.ID)
		if err != nil {
			return failedCatalogState(fmt.Errorf("invalid asset ID %q: %w", asset.ID, err))
		}
		if _, duplicate := assets[asset.ID]; duplicate {
			return failedCatalogState(fmt.Errorf("duplicate asset ID %q", asset.ID))
		}
		kind := ports.AssetKind(asset.Kind)
		if !kind.Valid() {
			return failedCatalogState(fmt.Errorf("invalid asset kind %q", asset.Kind))
		}
		source, err := validateEmbeddedSource(asset.Source)
		if err != nil {
			return failedCatalogState(fmt.Errorf("invalid source %q: %w", asset.Source, err))
		}
		sourcePath, err := ports.NewSafeRelativePath(source)
		if err != nil {
			return failedCatalogState(fmt.Errorf("asset %q source metadata: %w", asset.ID, err))
		}
		if asset.ZipPath != catalogZipPrefix+source {
			return failedCatalogState(fmt.Errorf("asset %q has non-canonical zip path %q", asset.ID, asset.ZipPath))
		}
		if asset.MediaType != catalogMediaType(source, kind) {
			return failedCatalogState(fmt.Errorf("asset %q has invalid media type %q", asset.ID, asset.MediaType))
		}
		if asset.Size < 0 || !isLowerSHA256(asset.SHA256) {
			return failedCatalogState(fmt.Errorf("asset %q has invalid integrity metadata", asset.ID))
		}
		if existing, duplicate := identities[source]; duplicate {
			if existing.zipPath != asset.ZipPath || existing.size != asset.Size || existing.sha256 != asset.SHA256 {
				return failedCatalogState(fmt.Errorf("asset %q does not match canonical source %q", asset.ID, source))
			}
		} else {
			identities[source] = sourceIdentity{
				zipPath: asset.ZipPath,
				size:    asset.Size,
				sha256:  asset.SHA256,
			}
		}
		expectedZipPaths[asset.ZipPath] = struct{}{}

		metadata, err := ports.NewAssetMetadata(id, kind, sourcePath, asset.MediaType, "sha256:"+asset.SHA256, asset.Size)
		if err != nil {
			return failedCatalogState(fmt.Errorf("asset %q metadata: %w", asset.ID, err))
		}
		assets[asset.ID] = catalogAsset{metadata: metadata}
		if kind == ports.AssetKindHelp {
			helpIDs[asset.ID] = struct{}{}
		}
		if kind == ports.AssetKindDefaults {
			defaultIDs[asset.ID] = struct{}{}
		}
	}

	if len(files) != len(expectedZipPaths)+1 {
		return failedCatalogState(fmt.Errorf("zip entries do not exactly match manifest paths"))
	}
	for zipPath := range expectedZipPaths {
		if _, exists := files[zipPath]; !exists {
			return failedCatalogState(fmt.Errorf("manifest zip path %q is absent", zipPath))
		}
	}
	if err := validateAliasIDs(helpIDs, catalogHelpAliases, "help"); err != nil {
		return failedCatalogState(err)
	}
	if err := validateAliasIDs(defaultIDs, catalogDefaultAliases, "default"); err != nil {
		return failedCatalogState(err)
	}

	contentsByZipPath := make(map[string][]byte, len(expectedZipPaths))
	for zipPath := range expectedZipPaths {
		contents, err := readZipFile(files[zipPath])
		if err != nil {
			return failedCatalogState(fmt.Errorf("read asset zip entry %q: %w", zipPath, err))
		}
		contentsByZipPath[zipPath] = contents
	}

	for _, asset := range manifest.Assets {
		contents := contentsByZipPath[asset.ZipPath]
		if int64(len(contents)) != asset.Size {
			return failedCatalogState(fmt.Errorf("asset %q size does not match zip contents", asset.ID))
		}
		sum := sha256.Sum256(contents)
		if hex.EncodeToString(sum[:]) != asset.SHA256 {
			return failedCatalogState(fmt.Errorf("asset %q sha256 does not match zip contents", asset.ID))
		}
		kind := ports.AssetKind(asset.Kind)
		canonical, err := validateAssetIdentity(asset, kind, contents)
		if err != nil {
			return failedCatalogState(err)
		}
		identity := identities[asset.Source]
		if canonical {
			if identity.canonical {
				return failedCatalogState(fmt.Errorf("source %q has multiple canonical entries", asset.Source))
			}
			identity.canonical = true
			identities[asset.Source] = identity
		}
		stored := assets[asset.ID]
		stored.bytes = contents
		assets[asset.ID] = stored
	}
	for source, identity := range identities {
		if !identity.canonical {
			return failedCatalogState(fmt.Errorf("source %q has no canonical entry", source))
		}
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

type sourceIdentity struct {
	zipPath   string
	size      int64
	sha256    string
	canonical bool
}

func validateAssetIdentity(asset embeddedAssetInfo, kind ports.AssetKind, contents []byte) (bool, error) {
	canonicalID, canonicalKind, err := catalogCanonicalIdentity(asset.Source, contents)
	if err != nil {
		return false, err
	}
	switch kind {
	case ports.AssetKindSOT, ports.AssetKindSchema, ports.AssetKindExample:
		if kind != canonicalKind || asset.ID != canonicalID {
			return false, fmt.Errorf("asset %q does not match canonical identity for %q", asset.ID, asset.Source)
		}
		return true, nil
	case ports.AssetKindHelp:
		if source, exists := catalogHelpAliases[asset.ID]; !exists || source != asset.Source {
			return false, fmt.Errorf("asset %q is not a valid help alias", asset.ID)
		}
	case ports.AssetKindDefaults:
		if source, exists := catalogDefaultAliases[asset.ID]; !exists || source != asset.Source {
			return false, fmt.Errorf("asset %q is not a valid default alias", asset.ID)
		}
	default:
		return false, fmt.Errorf("asset %q has unsupported kind %q", asset.ID, kind)
	}
	return false, nil
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

func validateAliasIDs(actual map[string]struct{}, expected map[string]string, name string) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("manifest has %d %s aliases; want %d", len(actual), name, len(expected))
	}
	for id := range expected {
		if _, exists := actual[id]; !exists {
			return fmt.Errorf("manifest is missing %s alias %q", name, id)
		}
	}
	return nil
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
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
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
	"help:quickstart": "README.md",
	"help:config":     "docs/04-configuration.md",
	"help:providers":  "docs/05-provider-runtime-and-scheduling.md",
	"help:roles":      "docs/02-domain-and-state-model.md",
	"help:lanes":      "docs/05-provider-runtime-and-scheduling.md",
	"help:prompts":    "docs/06-prompt-contract.md",
	"help:workflows":  "docs/03-cli-workflows.md",
	"help:artifacts":  "docs/08-artifacts-lineage-and-storage.md",
	"help:validation": "docs/07-output-validation-and-repair.md",
	"help:ci":         "docs/10-reporting-ci-and-exit-codes.md",
	"help:exit-codes": "docs/10-reporting-ci-and-exit-codes.md",
	"help:security":   "docs/09-security-and-trust.md",
}
