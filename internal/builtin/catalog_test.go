package builtin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/irootkernel/mulgae/internal/ports"
)

const testSOTRoot = "assets"

// testRootRoleDocument is the repository-root role document. go:embed cannot
// escape its own package directory, so this source lives outside testSOTRoot and
// is accounted for explicitly wherever the authoritative inventory is walked.
const testRootRoleDocument = "../../assets/roles.yaml"

type embeddedManifest struct {
	Version int
	Assets  []embeddedAssetInfo
}

type embeddedAssetInfo struct {
	ID        string
	Kind      string
	Source    string
	MediaType string
	Size      int64
	SHA256    string
	ZipPath   string
}

func TestCatalogFailsClosedAfterInitializationError(t *testing.T) {
	t.Parallel()

	catalog := testCatalog(fstest.MapFS{})
	if _, err := catalog.List(context.Background()); err == nil {
		t.Fatal("List succeeded for an invalid asset filesystem")
	}
	id := mustAssetID(t, "sot:README.md")
	if _, _, err := catalog.Read(context.Background(), id); err == nil {
		t.Fatal("Read succeeded after catalog initialization failed")
	}
}

func TestProductionCatalogPinsEveryEmbeddedAssetDigest(t *testing.T) {
	files := embeddedTestFS(t)
	mutated := append([]byte(nil), files["README.md"].Data...)
	mutated[len(mutated)-1] ^= 0x01
	files["README.md"] = &fstest.MapFile{Data: mutated, Mode: 0o644}
	catalog := testCatalog(files)
	if _, err := catalog.List(context.Background()); err == nil {
		t.Fatal("production catalog accepted bytes outside the checksum inventory")
	}
}

func TestArtistVisualEvidencePathContractMatchesCommonPrompt(t *testing.T) {
	common, err := os.ReadFile(filepath.Join(testSOTRoot, "prompts", "root-review", "common.v1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := os.ReadFile(testRootRoleDocument)
	if err != nil {
		t.Fatal(err)
	}

	for name, document := range map[string][]byte{
		"common prompt": common,
		"role catalog":  roles,
	} {
		if !bytes.Contains(document, []byte("exact captured workspace path")) {
			t.Fatalf("%s does not require the exact captured workspace path for visual evidence", name)
		}
	}
	if !bytes.Contains(common, []byte("without a `current/`, `before/`, or `after/` prefix")) ||
		!bytes.Contains(common, []byte("including its `current/`, `before/`, or `after/` prefix")) {
		t.Fatal("common prompt does not distinguish project-relative code evidence from side-qualified visual evidence")
	}
	if !bytes.Contains(roles, []byte("including its current/before/after prefix")) {
		t.Fatal("artist role does not preserve the side-qualified visual evidence path")
	}
}

func TestCatalogRejectsInvalidEmbeddedFilesystems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, fstest.MapFS)
	}{
		{
			name: "missing checksummed source",
			mutate: func(_ *testing.T, files fstest.MapFS) {
				delete(files, "README.md")
			},
		},
		{
			name: "unchecksummed source",
			mutate: func(_ *testing.T, files fstest.MapFS) {
				files["unexpected.txt"] = &fstest.MapFile{Data: []byte("unexpected\n"), Mode: 0o644}
			},
		},
		{
			name: "malformed checksum inventory",
			mutate: func(_ *testing.T, files fstest.MapFS) {
				files[catalogChecksumSource] = &fstest.MapFile{Data: []byte("not a checksum\n"), Mode: 0o644}
			},
		},
		{
			name: "invalid role catalog",
			mutate: func(t *testing.T, files fstest.MapFS) {
				files[rootRoleSource] = &fstest.MapFile{Data: []byte("schema_version: invalid\n"), Mode: 0o644}
				rewriteTestChecksums(t, files)
			},
		},
		{
			name: "missing role catalog",
			mutate: func(t *testing.T, files fstest.MapFS) {
				delete(files, rootRoleSource)
				rewriteTestChecksums(t, files)
			},
		},
		{
			name: "role catalog without artist default inputs",
			mutate: func(t *testing.T, files fstest.MapFS) {
				stripped := removeArtistDefaultInputs(t, files[rootRoleSource].Data)
				files[rootRoleSource] = &fstest.MapFile{Data: stripped, Mode: 0o644}
				rewriteTestChecksums(t, files)
			},
		},
		{
			name: "invalid schema identity",
			mutate: func(t *testing.T, files fstest.MapFS) {
				files["schemas/mulgae-command-result.v1.schema.json"] = &fstest.MapFile{Data: []byte(`{"type":"object"}`), Mode: 0o644}
				rewriteTestChecksums(t, files)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			files := embeddedTestFS(t)
			test.mutate(t, files)
			if _, err := testCatalog(files).List(context.Background()); err == nil {
				t.Fatal("List succeeded for an invalid embedded filesystem")
			}
		})
	}
}

func testCatalog(filesystem fs.FS) *Catalog {
	return &Catalog{filesystem: filesystem}
}

func TestCatalogReadAndListUseDefensiveCopies(t *testing.T) {
	t.Parallel()

	catalog := NewCatalog()
	id := mustAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v1.schema.json")
	metadata, first, err := catalog.Read(context.Background(), id)
	if err != nil {
		t.Fatalf("Read(%q): %v", id.String(), err)
	}
	if metadata.ID() != id {
		t.Fatalf("Read(%q) metadata ID = %q", id.String(), metadata.ID().String())
	}
	if metadata.Kind() != ports.AssetKindSchema {
		t.Fatalf("Read(%q) kind = %q, want %q", id.String(), metadata.Kind(), ports.AssetKindSchema)
	}
	want, err := os.ReadFile(filepath.Join(testSOTRoot, "schemas", "mulgae-command-result.v1.schema.json"))
	if err != nil {
		t.Fatalf("read authoritative global default: %v", err)
	}
	if !bytes.Equal(first, want) {
		t.Fatalf("Read(%q) bytes differ from authoritative default", id.String())
	}
	if len(first) == 0 {
		t.Fatal("global default is unexpectedly empty")
	}
	first[0] ^= 0xff
	_, second, err := catalog.Read(context.Background(), id)
	if err != nil {
		t.Fatalf("second Read(%q): %v", id.String(), err)
	}
	if !bytes.Equal(second, want) {
		t.Fatal("mutating Read result changed catalog bytes")
	}

	listed, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) == 0 {
		t.Fatal("List returned no assets")
	}
	assertMetadataSorted(t, listed)
	originalFirstID := listed[0].ID().String()
	listed[0] = ports.AssetMetadata{}
	listedAgain, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("second List: %v", err)
	}
	if listedAgain[0].ID().String() != originalFirstID {
		t.Fatal("mutating List result changed catalog metadata")
	}

	unknown := mustAssetID(t, "sot:not-present")
	if _, _, err := catalog.Read(context.Background(), unknown); err == nil {
		t.Fatal("Read succeeded for an unknown asset ID")
	}
}

func TestCatalogManifestUsesCanonicalSourceOrdering(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t)
	if manifest.Version != 1 {
		t.Fatalf("manifest version = %d, want 1", manifest.Version)
	}
	if len(manifest.Assets) != 64 {
		t.Fatalf("manifest asset count = %d, want 64", len(manifest.Assets))
	}
	for index := 1; index < len(manifest.Assets); index++ {
		previous := manifest.Assets[index-1]
		current := manifest.Assets[index]
		if previous.Source > current.Source {
			t.Fatalf("manifest source order %q before %q", previous.Source, current.Source)
		}
		if previous.Source != current.Source {
			continue
		}
		previousCanonical := isCatalogCanonicalKind(previous.Kind)
		currentCanonical := isCatalogCanonicalKind(current.Kind)
		if !previousCanonical && currentCanonical {
			t.Fatalf("canonical entry for %q follows an alias", current.Source)
		}
		if previousCanonical == currentCanonical && previous.ID >= current.ID {
			t.Fatalf("manifest IDs for %q are not ordered: %q then %q", current.Source, previous.ID, current.ID)
		}
	}

	assets, err := NewCatalog().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(assets) != len(manifest.Assets) {
		t.Fatalf("List returned %d assets, manifest has %d", len(assets), len(manifest.Assets))
	}
	assertMetadataSorted(t, assets)
}

func TestCatalogSourceBytesAndIdentitiesMatchAuthoritativeSOT(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t)
	bySource := make(map[string][]embeddedAssetInfo)
	for _, asset := range manifest.Assets {
		bySource[asset.Source] = append(bySource[asset.Source], asset)
	}

	authoritativeSources := make(map[string]struct{})
	err := filepath.WalkDir(testSOTRoot, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == filepath.Join(testSOTRoot, "plan") && entry.IsDir() {
			return filepath.SkipDir
		}
		info, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("authoritative SOT unexpectedly contains symlink %q", filename)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("authoritative SOT unexpectedly contains non-regular file %q", filename)
		}
		relative, err := filepath.Rel(testSOTRoot, filename)
		if err != nil {
			return err
		}
		authoritativeSources[filepath.ToSlash(relative)] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("walk authoritative SOT: %v", err)
	}
	rootInfo, err := os.Lstat(testRootRoleDocument)
	if err != nil {
		t.Fatalf("stat root role document: %v", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.Mode().IsRegular() {
		t.Fatalf("root role document must be a non-symlink regular file")
	}
	authoritativeSources[rootRoleSource] = struct{}{}
	if len(authoritativeSources) != 53 {
		t.Fatalf("authoritative runtime source count = %d, want 53", len(authoritativeSources))
	}
	if len(bySource) != len(authoritativeSources) {
		t.Fatalf("manifest has %d unique sources, authoritative SOT has %d", len(bySource), len(authoritativeSources))
	}

	catalog := NewCatalog()
	for source := range authoritativeSources {
		entries, exists := bySource[source]
		if !exists {
			t.Errorf("manifest omits authoritative source %q", source)
			continue
		}
		authoritativePath := filepath.Join(testSOTRoot, filepath.FromSlash(source))
		if source == rootRoleSource {
			authoritativePath = filepath.FromSlash(testRootRoleDocument)
		}
		want, err := os.ReadFile(authoritativePath)
		if err != nil {
			t.Errorf("read authoritative source %q: %v", source, err)
			continue
		}
		sum := sha256.Sum256(want)
		wantSHA256 := hex.EncodeToString(sum[:])
		for _, entry := range entries {
			if entry.Size != int64(len(want)) {
				t.Errorf("asset %q size = %d, want %d", entry.ID, entry.Size, len(want))
			}
			if entry.SHA256 != wantSHA256 {
				t.Errorf("asset %q sha256 = %q, want %q", entry.ID, entry.SHA256, wantSHA256)
			}
			metadata, got, err := catalog.Read(context.Background(), mustAssetID(t, entry.ID))
			if err != nil {
				t.Errorf("Read(%q): %v", entry.ID, err)
				continue
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Read(%q) bytes differ from assets/%s", entry.ID, source)
			}
			if metadata.Source().String() != source {
				t.Errorf("Read(%q) source = %q, want %q", entry.ID, metadata.Source().String(), source)
			}
			if metadata.MediaType() != entry.MediaType {
				t.Errorf("Read(%q) media type = %q, want %q", entry.ID, metadata.MediaType(), entry.MediaType)
			}
			if metadata.ByteLength() != int64(len(want)) {
				t.Errorf("Read(%q) byte length = %d, want %d", entry.ID, metadata.ByteLength(), len(want))
			}
			if metadata.SHA256() != "sha256:"+wantSHA256 {
				t.Errorf("Read(%q) SHA256 = %q, want sha256:%s", entry.ID, metadata.SHA256(), wantSHA256)
			}
		}
	}
	for source := range bySource {
		if _, exists := authoritativeSources[source]; !exists {
			t.Errorf("manifest has non-authoritative source %q", source)
		}
	}
}

func TestCatalogHelpAliasesAreExact(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
		"help:quickstart": "help/quickstart.md",
		"help:config":     "help/config.md",
		"help:providers":  "help/providers.md",
		"help:lanes":      "help/providers.md",
		"help:prompts":    "help/prompts.md",
		"help:workflows":  "help/workflows.md",
		"help:artifacts":  "help/artifacts.md",
		"help:validation": "help/validation.md",
		"help:ci":         "help/automation.md",
		"help:exit-codes": "help/automation.md",
		"help:security":   "help/security.md",
	}
	manifest := testManifest(t)
	byID := make(map[string]embeddedAssetInfo, len(manifest.Assets))
	bySource := make(map[string][]embeddedAssetInfo)
	actualHelpIDs := make(map[string]struct{})
	for _, asset := range manifest.Assets {
		byID[asset.ID] = asset
		bySource[asset.Source] = append(bySource[asset.Source], asset)
		if asset.Kind == string(ports.AssetKindHelp) {
			actualHelpIDs[asset.ID] = struct{}{}
		}
	}
	if len(actualHelpIDs) != len(expected) {
		t.Fatalf("help alias count = %d, want %d", len(actualHelpIDs), len(expected))
	}

	catalog := NewCatalog()
	for id, source := range expected {
		alias, exists := byID[id]
		if !exists {
			t.Errorf("missing help alias %q", id)
			continue
		}
		if alias.Kind != string(ports.AssetKindHelp) || alias.Source != source {
			t.Errorf("help alias %q = kind %q source %q", id, alias.Kind, alias.Source)
		}
		var canonical *embeddedAssetInfo
		for index := range bySource[source] {
			candidate := &bySource[source][index]
			if isCatalogCanonicalKind(candidate.Kind) {
				canonical = candidate
				break
			}
		}
		if canonical == nil {
			t.Errorf("help alias %q has no canonical source entry", id)
			continue
		}
		if alias.Size != canonical.Size || alias.SHA256 != canonical.SHA256 || alias.ZipPath != canonical.ZipPath {
			t.Errorf("help alias %q does not exactly share canonical source identity", id)
		}
		_, aliasBytes, aliasErr := catalog.Read(context.Background(), mustAssetID(t, id))
		_, canonicalBytes, canonicalErr := catalog.Read(context.Background(), mustAssetID(t, canonical.ID))
		if aliasErr != nil || canonicalErr != nil {
			t.Errorf("read help alias %q or canonical %q: %v / %v", id, canonical.ID, aliasErr, canonicalErr)
		} else if !bytes.Equal(aliasBytes, canonicalBytes) {
			t.Errorf("help alias %q does not share canonical bytes", id)
		}
	}
	for id := range actualHelpIDs {
		if _, exists := expected[id]; !exists {
			t.Errorf("unexpected help alias %q", id)
		}
	}
}

func TestCatalogHelpCoversProjectLocalInitContract(t *testing.T) {
	t.Parallel()

	catalog := NewCatalog()
	var help strings.Builder
	for _, topic := range []string{"quickstart", "config", "providers", "workflows", "exit-codes", "security"} {
		_, data, err := catalog.Read(context.Background(), mustAssetID(t, "help:"+topic))
		if err != nil {
			t.Fatalf("read help %q: %v", topic, err)
		}
		help.Write(data)
		help.WriteByte('\n')
	}
	content := help.String()
	for _, required := range []string{
		"one configuration authority:\n`<canonical-project-root>/.mulgae/config.yaml`",
		"--providers auto|FAMILY[,FAMILY...]",
		"`FAMILY := kimi | zcode | agy`",
		"`execution.workspace_access` is required",
		"Mulgae roles are functional review lenses.\nThey are not people, teams, or organizational authorities.\nMulgae reports findings and recommendations only.",
		"defaults to `safe` for workspace-first",
		"`provider_permission_denied`, not as output decode failures",
		"unconditional project-root\ndurability barrier",
		"output delivery failure never rolls back a committed\nconfiguration",
		"There is no migration or compatibility path",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("embedded help is missing %q", required)
		}
	}
	for _, forbidden := range []string{"~/.config/mulgae", "$XDG_CONFIG_HOME/mulgae"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("embedded help retains legacy authority %q", forbidden)
		}
	}
}

func TestCatalogHasNoRuntimeConfigurationDefaults(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t)
	for _, asset := range manifest.Assets {
		if asset.Kind == string(ports.AssetKindDefaults) {
			t.Fatalf("runtime configuration default remains in catalog: %#v", asset)
		}
	}
}

type schemaExamplePair struct {
	schemaID      string
	schemaSource  string
	exampleSource string
}

func TestCatalogHasExactSchemaExampleInventoryWithoutOrphans(t *testing.T) {
	t.Parallel()

	expected := []schemaExamplePair{
		{"https://mulgae.local/schemas/mulgae-clean-plan.v1.schema.json", "schemas/mulgae-clean-plan.v1.schema.json", "examples/clean-plan.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-command-result.v1.schema.json", "schemas/mulgae-command-result.v1.schema.json", "examples/command-result.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-doctor-result.v1.schema.json", "schemas/mulgae-doctor-result.v1.schema.json", "examples/doctor-result.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-export-manifest.v1.schema.json", "schemas/mulgae-export-manifest.v1.schema.json", "examples/export-manifest.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-file-catalog.v1.schema.json", "schemas/mulgae-file-catalog.v1.schema.json", "examples/file-catalog.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-platform-contract-evidence.v1.schema.json", "schemas/mulgae-platform-contract-evidence.v1.schema.json", "examples/platform-contract-evidence.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v1.schema.json", "schemas/mulgae-provider-contract-evidence.v1.schema.json", "examples/provider-contract-evidence.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-provider-followup-output.v1.schema.json", "schemas/mulgae-provider-followup-output.v1.schema.json", "examples/provider-followup-output.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-provider-review-output.v1.schema.json", "schemas/mulgae-provider-review-output.v1.schema.json", "examples/provider-review-output.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-provider-review-wire.v1.schema.json", "schemas/mulgae-provider-review-wire.v1.schema.json", "examples/provider-review-wire.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-repair-patch.v1.schema.json", "schemas/mulgae-repair-patch.v1.schema.json", "examples/repair-patch.json"},
		{"https://mulgae.local/schemas/mulgae-repair-request.v1.schema.json", "schemas/mulgae-repair-request.v1.schema.json", "examples/repair-request.json"},
		{"https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", "schemas/mulgae-review-artifact.v1.schema.json", "examples/review-artifact.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-review-preflight.v1.schema.json", "schemas/mulgae-review-preflight.v1.schema.json", "examples/review-preflight.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "schemas/mulgae-run-manifest.v1.schema.json", "examples/run-manifest.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-validation-receipt.v1.schema.json", "schemas/mulgae-validation-receipt.v1.schema.json", "examples/validation-receipt.v1.valid.json"},
		{"https://mulgae.local/schemas/mulgae-validation-result.v1.schema.json", "schemas/mulgae-validation-result.v1.schema.json", "examples/validation-result.v1.valid.json"},
	}
	if len(expected) != 17 {
		t.Fatalf("test pair inventory contains %d pairs, want 17", len(expected))
	}
	authoritative := authoritativeSchemaExamplePairs(t)
	if len(authoritative) != len(expected) {
		t.Fatalf("authoritative pair count = %d, want %d", len(authoritative), len(expected))
	}
	for _, pair := range expected {
		if !containsExactPair(authoritative, pair) {
			t.Fatalf("expected pair %+v is absent from the embedded file catalog", pair)
		}
	}

	manifest := testManifest(t)
	schemas := make(map[string]embeddedAssetInfo)
	examples := make(map[string]embeddedAssetInfo)
	for _, asset := range manifest.Assets {
		switch asset.Kind {
		case string(ports.AssetKindSchema):
			schemas[asset.Source] = asset
		case string(ports.AssetKindExample):
			if strings.HasSuffix(asset.Source, ".json") {
				examples[asset.Source] = asset
			}
		}
	}
	if len(schemas) != len(expected) {
		t.Fatalf("schema count = %d, want %d", len(schemas), len(expected))
	}
	if len(examples) != len(expected) {
		t.Fatalf("paired JSON example count = %d, want %d", len(examples), len(expected))
	}
	for _, pair := range expected {
		schema, schemaExists := schemas[pair.schemaSource]
		if !schemaExists {
			t.Errorf("missing schema %q", pair.schemaSource)
		} else if schema.ID != pair.schemaID {
			t.Errorf("schema %q ID = %q, want %q", pair.schemaSource, schema.ID, pair.schemaID)
		}
		example, exampleExists := examples[pair.exampleSource]
		if !exampleExists {
			t.Errorf("missing paired example %q", pair.exampleSource)
		} else if example.ID != "example:"+filepath.Base(pair.exampleSource) {
			t.Errorf("example %q ID = %q", pair.exampleSource, example.ID)
		}
	}
	for source := range schemas {
		if !containsSchemaSource(expected, source) {
			t.Errorf("orphan schema %q", source)
		}
	}
	for source := range examples {
		if !containsExampleSource(expected, source) {
			t.Errorf("orphan paired example %q", source)
		}
	}
}

func testManifest(t *testing.T) embeddedManifest {
	t.Helper()
	catalog := NewCatalog()
	metadata, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	manifest := embeddedManifest{Version: 1, Assets: make([]embeddedAssetInfo, 0, len(metadata))}
	for _, asset := range metadata {
		_, _, err := catalog.Read(context.Background(), asset.ID())
		if err != nil {
			t.Fatalf("Read(%q): %v", asset.ID().String(), err)
		}
		manifest.Assets = append(manifest.Assets, embeddedAssetInfo{
			ID:        asset.ID().String(),
			Kind:      string(asset.Kind()),
			Source:    asset.Source().String(),
			MediaType: asset.MediaType(),
			Size:      asset.ByteLength(),
			SHA256:    strings.TrimPrefix(asset.SHA256(), "sha256:"),
			ZipPath:   asset.Source().String(),
		})
	}
	sort.Slice(manifest.Assets, func(left, right int) bool {
		if manifest.Assets[left].Source != manifest.Assets[right].Source {
			return manifest.Assets[left].Source < manifest.Assets[right].Source
		}
		leftCanonical := isCatalogCanonicalKind(manifest.Assets[left].Kind)
		rightCanonical := isCatalogCanonicalKind(manifest.Assets[right].Kind)
		if leftCanonical != rightCanonical {
			return leftCanonical
		}
		return manifest.Assets[left].ID < manifest.Assets[right].ID
	})
	return manifest
}

func embeddedTestFS(t *testing.T) fstest.MapFS {
	t.Helper()
	root, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		t.Fatalf("open embedded assets: %v", err)
	}
	files := make(fstest.MapFS)
	err = fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		contents, err := fs.ReadFile(root, name)
		if err != nil {
			return err
		}
		files[name] = &fstest.MapFile{Data: contents, Mode: 0o644}
		return nil
	})
	if err != nil {
		t.Fatalf("copy embedded assets: %v", err)
	}
	// NewCatalog overlays the repository-root role document onto the embedded
	// tree. Fixtures built directly from embeddedAssets must do the same, so a
	// test filesystem is a faithful stand-in for the production catalog.
	rootRoles, err := os.ReadFile(testRootRoleDocument)
	if err != nil {
		t.Fatalf("read root role document: %v", err)
	}
	files[rootRoleSource] = &fstest.MapFile{Data: rootRoles, Mode: 0o644}
	return files
}

// removeArtistDefaultInputs drops the artist default_inputs block so the catalog
// must reject a role document that no longer carries init's artist defaults.
func removeArtistDefaultInputs(t *testing.T, document []byte) []byte {
	t.Helper()
	lines := strings.Split(string(document), "\n")
	kept := make([]string, 0, len(lines))
	dropping := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "default_inputs:" {
			dropping = true
			continue
		}
		if dropping {
			if strings.HasPrefix(line, "      ") || strings.HasPrefix(line, "        ") {
				continue
			}
			dropping = false
		}
		kept = append(kept, line)
	}
	stripped := strings.Join(kept, "\n")
	if !strings.Contains(string(document), "default_inputs:") || strings.Contains(stripped, "default_inputs:") {
		t.Fatal("artist default inputs were not removed")
	}
	return []byte(stripped)
}

func rewriteTestChecksums(t *testing.T, files fstest.MapFS) {
	t.Helper()
	sources := make([]string, 0, len(files)-1)
	for source := range files {
		if source != catalogChecksumSource {
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	var inventory strings.Builder
	for _, source := range sources {
		sum := sha256.Sum256(files[source].Data)
		inventory.WriteString(hex.EncodeToString(sum[:]))
		inventory.WriteString("  ")
		inventory.WriteString(source)
		inventory.WriteByte('\n')
	}
	files[catalogChecksumSource] = &fstest.MapFile{Data: []byte(inventory.String()), Mode: 0o644}
}

func mustAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatalf("ParseAssetID(%q): %v", value, err)
	}
	return id
}

func assertMetadataSorted(t *testing.T, assets []ports.AssetMetadata) {
	t.Helper()
	if !sort.SliceIsSorted(assets, func(left, right int) bool {
		return assets[left].ID().String() < assets[right].ID().String()
	}) {
		t.Fatal("catalog metadata is not sorted by AssetID")
	}
}

func isCatalogCanonicalKind(kind string) bool {
	return kind == string(ports.AssetKindSOT) || kind == string(ports.AssetKindSchema) || kind == string(ports.AssetKindExample)
}

func containsSchemaSource(pairs []schemaExamplePair, source string) bool {
	for _, pair := range pairs {
		if pair.schemaSource == source {
			return true
		}
	}
	return false
}

func containsExampleSource(pairs []schemaExamplePair, source string) bool {
	for _, pair := range pairs {
		if pair.exampleSource == source {
			return true
		}
	}
	return false
}
func authoritativeSchemaExamplePairs(t *testing.T) []schemaExamplePair {
	t.Helper()

	contents, err := os.ReadFile(filepath.Join(testSOTRoot, "examples", "file-catalog.v1.valid.json"))
	if err != nil {
		t.Fatalf("read embedded file catalog: %v", err)
	}
	var fileCatalog struct {
		Files []struct {
			Path     string  `json:"path"`
			SchemaID *string `json:"schema_id"`
			Pair     *string `json:"pair"`
		} `json:"files"`
	}
	if err := json.Unmarshal(contents, &fileCatalog); err != nil {
		t.Fatalf("decode embedded file catalog: %v", err)
	}

	pairs := make([]schemaExamplePair, 0, 24)
	for _, file := range fileCatalog.Files {
		if !strings.HasPrefix(file.Path, "sot/schemas/") || file.SchemaID == nil || file.Pair == nil {
			continue
		}
		if !strings.HasPrefix(*file.Pair, "sot/examples/") {
			t.Fatalf("schema %q pair = %q, want an example path", file.Path, *file.Pair)
		}
		pairs = append(pairs, schemaExamplePair{
			schemaID:      *file.SchemaID,
			schemaSource:  strings.TrimPrefix(file.Path, "sot/"),
			exampleSource: strings.TrimPrefix(*file.Pair, "sot/"),
		})
	}
	sort.Slice(pairs, func(left, right int) bool {
		return pairs[left].schemaSource < pairs[right].schemaSource
	})
	return pairs
}

func containsExactPair(pairs []schemaExamplePair, expected schemaExamplePair) bool {
	for _, pair := range pairs {
		if pair == expected {
			return true
		}
	}
	return false
}
