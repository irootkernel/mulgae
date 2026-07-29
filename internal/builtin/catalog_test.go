package builtin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const testSOTRoot = "../../sot"
const testRolesRoot = "../../roles"

func TestCatalogFailsClosedAfterInitializationError(t *testing.T) {
	t.Parallel()

	catalog := testCatalog(malformedManifestArchive(t))
	if _, err := catalog.List(context.Background()); err == nil {
		t.Fatal("List succeeded for an invalid catalog archive")
	}
	id := mustAssetID(t, "sot:README.md")
	if _, _, err := catalog.Read(context.Background(), id); err == nil {
		t.Fatal("Read succeeded after catalog initialization failed")
	}
}

func TestProductionCatalogPinsAuthoritativeArchiveDigest(t *testing.T) {
	sum := sha256.Sum256(embeddedArchive)
	if got := hex.EncodeToString(sum[:]); got != embeddedArchiveSHA256 {
		t.Fatalf("embedded archive digest = %s, want %s", got, embeddedArchiveSHA256)
	}

	mutated := append([]byte(nil), embeddedArchive...)
	mutated[len(mutated)-1] ^= 0x01
	catalog := &Catalog{archive: mutated, expectedSHA256: embeddedArchiveSHA256}
	if _, err := catalog.List(context.Background()); err == nil {
		t.Fatal("production catalog accepted bytes outside the authoritative digest")
	}
}
func testCatalog(archive []byte) *Catalog {
	cloned := append([]byte(nil), archive...)
	sum := sha256.Sum256(cloned)
	return &Catalog{archive: cloned, expectedSHA256: hex.EncodeToString(sum[:])}
}

func TestCatalogReadAndListUseDefensiveCopies(t *testing.T) {
	t.Parallel()

	catalog := NewCatalog()
	id := mustAssetID(t, "https://kar.local/schemas/kar-command-result.v1.schema.json")
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
	want, err := os.ReadFile(filepath.Join(testSOTRoot, "schemas", "kar-command-result.v1.schema.json"))
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
	if len(manifest.Assets) != 102 {
		t.Fatalf("manifest asset count = %d, want 102", len(manifest.Assets))
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
	if len(authoritativeSources) != 84 {
		t.Fatalf("authoritative SOT source count = %d, want 84", len(authoritativeSources))
	}
	roleEntries, err := os.ReadDir(testRolesRoot)
	if err != nil {
		t.Fatalf("read authoritative roles: %v", err)
	}
	for _, entry := range roleEntries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".yaml") {
			authoritativeSources["roles/"+entry.Name()] = struct{}{}
		}
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
		root, relative := testSOTRoot, source
		if strings.HasPrefix(source, "roles/") {
			root, relative = testRolesRoot, strings.TrimPrefix(source, "roles/")
		}
		want, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
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
				t.Errorf("Read(%q) bytes differ from ../../../sot/%s", entry.ID, source)
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

func TestProductionCatalogExcludesPlanningOnlySOT(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(filepath.Join(testSOTRoot, "plan", "diagnostics"))
	if err != nil {
		t.Fatalf("read diagnostics plan: %v", err)
	}
	wantPlanningFiles := map[string]bool{
		"architecture.md":      true,
		"g010-t05-evidence.md": true,
		"roadmap.md":           true,
		"sot.md":               true,
		"spec.md":              true,
	}
	if len(entries) != len(wantPlanningFiles) {
		t.Fatalf("diagnostics plan file count = %d, want %d", len(entries), len(wantPlanningFiles))
	}
	for _, entry := range entries {
		if entry.IsDir() || !wantPlanningFiles[entry.Name()] {
			t.Fatalf("unexpected diagnostics planning entry %q", entry.Name())
		}
	}

	assets, err := NewCatalog().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, asset := range assets {
		if strings.HasPrefix(asset.Source().String(), "plan/") {
			t.Fatalf("production catalog contains planning-only source %q", asset.Source())
		}
	}
}

func TestCatalogHelpAliasesAreExact(t *testing.T) {
	t.Parallel()

	expected := map[string]string{
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
		"one configuration authority: `<canonical-project-root>/.kar/config.yaml`",
		"`--providers auto|FAMILY[,FAMILY...]`",
		"`FAMILY := kimi | zcode | agy`",
		"`execution.workspace_access` is required",
		"KAR roles are functional review lenses.\nThey are not people, teams, or organizational authorities.\nKAR reports findings and recommendations only.",
		"an explicit\n`safe` or `dangerously-skip-permissions` mode",
		"unconditional project-root durability barrier",
		"output delivery failure never rolls back a\ncommitted config",
		"There is no migration or compatibility path",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("embedded help is missing %q", required)
		}
	}
	for _, forbidden := range []string{"~/.config/kar", "$XDG_CONFIG_HOME/kar"} {
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
		{"https://kar.local/schemas/kar-clean-plan.v1.schema.json", "schemas/kar-clean-plan.v1.schema.json", "examples/clean-plan.v1.valid.json"},
		{"https://kar.local/schemas/kar-command-result.v1.schema.json", "schemas/kar-command-result.v1.schema.json", "examples/command-result.v1.valid.json"},
		{"https://kar.local/schemas/kar-doctor-result.v1.schema.json", "schemas/kar-doctor-result.v1.schema.json", "examples/doctor-result.v1.valid.json"},
		{"https://kar.local/schemas/kar-doctor-result.v2.schema.json", "schemas/kar-doctor-result.v2.schema.json", "examples/doctor-result.v2.valid.json"},
		{"https://kar.local/schemas/kar-export-manifest.v1.schema.json", "schemas/kar-export-manifest.v1.schema.json", "examples/export-manifest.v1.valid.json"},
		{"https://kar.local/schemas/kar-g0-file-catalog.v1.schema.json", "schemas/kar-g0-file-catalog.v1.schema.json", "examples/g0-file-catalog.v1.valid.json"},
		{"https://kar.local/schemas/kar-platform-contract-evidence.v1.schema.json", "schemas/kar-platform-contract-evidence.v1.schema.json", "examples/platform-contract-evidence.v1.valid.json"},
		{"https://kar.local/schemas/kar-platform-contract-evidence.v2.schema.json", "schemas/kar-platform-contract-evidence.v2.schema.json", "examples/platform-contract-evidence.v2.valid.json"},
		{"https://kar.local/schemas/kar-provider-contract-evidence.v1.schema.json", "schemas/kar-provider-contract-evidence.v1.schema.json", "examples/provider-contract-evidence.v1.valid.json"},
		{"https://kar.local/schemas/kar-provider-contract-evidence.v2.schema.json", "schemas/kar-provider-contract-evidence.v2.schema.json", "examples/provider-contract-evidence.v2.valid.json"},
		{"urn:kar:schema:provider-followup-output:v1", "schemas/kar-provider-followup-output.v1.schema.json", "examples/provider-followup-output.valid.json"},
		{"https://kar.local/schemas/kar-provider-followup-output.v2.schema.json", "schemas/kar-provider-followup-output.v2.schema.json", "examples/provider-followup-output.v2.valid.json"},
		{"urn:kar:schema:provider-review-output:v1", "schemas/kar-provider-review-output.v1.schema.json", "examples/provider-review-output.valid.json"},
		{"https://kar.local/schemas/kar-provider-review-output.v2.schema.json", "schemas/kar-provider-review-output.v2.schema.json", "examples/provider-review-output.v2.valid.json"},
		{"https://kar.local/schemas/kar-provider-review-output.v3.schema.json", "schemas/kar-provider-review-output.v3.schema.json", "examples/provider-review-output.v3.valid.json"},
		{"https://kar.local/schemas/kar-provider-review-wire.v2.schema.json", "schemas/kar-provider-review-wire.v2.schema.json", "examples/provider-review-wire.v2.valid.json"},
		{"https://kar.local/schemas/kar-provider-review-wire.v3.schema.json", "schemas/kar-provider-review-wire.v3.schema.json", "examples/provider-review-wire.v3.valid.json"},
		{"urn:kar:schema:repair-patch:v1", "schemas/kar-repair-patch.v1.schema.json", "examples/repair-patch.json"},
		{"urn:kar:schema:repair-request:v1", "schemas/kar-repair-request.v1.schema.json", "examples/repair-request.json"},
		{"urn:kar:schema:review-artifact:v1", "schemas/kar-review-artifact.v1.schema.json", "examples/review-artifact.valid.json"},
		{"https://kar.local/schemas/kar-review-artifact.v2.schema.json", "schemas/kar-review-artifact.v2.schema.json", "examples/review-artifact.v2.valid.json"},
		{"https://kar.local/schemas/kar-review-artifact.v3.schema.json", "schemas/kar-review-artifact.v3.schema.json", "examples/review-artifact.v3.valid.json"},
		{"urn:kar:schema:run-manifest:v1", "schemas/kar-run-manifest.v1.schema.json", "examples/run-manifest.valid.json"},
		{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", "schemas/kar-run-manifest.v2.schema.json", "examples/run-manifest.v2.valid.json"},
		{"https://kar.local/schemas/kar-validation-receipt.v1.schema.json", "schemas/kar-validation-receipt.v1.schema.json", "examples/validation-receipt.v1.valid.json"},
		{"urn:kar:schema:validation-result:v1", "schemas/kar-validation-result.v1.schema.json", "examples/validation-result.valid.json"},
		{"https://kar.local/schemas/kar-validation-result.v2.schema.json", "schemas/kar-validation-result.v2.schema.json", "examples/validation-result.v2.valid.json"},
	}
	if len(expected) != 27 {
		t.Fatalf("test pair inventory contains %d pairs, want 27", len(expected))
	}
	authoritative := authoritativeSchemaExamplePairs(t)
	if len(authoritative) != len(expected) {
		t.Fatalf("authoritative G0 pair count = %d, want %d", len(authoritative), len(expected))
	}
	for _, pair := range expected {
		if !containsExactPair(authoritative, pair) {
			t.Fatalf("expected pair %+v is absent from the authoritative G0 catalog", pair)
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
	reader, err := zip.NewReader(bytes.NewReader(embeddedArchive), int64(len(embeddedArchive)))
	if err != nil {
		t.Fatalf("read embedded archive: %v", err)
	}
	for _, file := range reader.File {
		if file.Name != catalogManifestName {
			continue
		}
		contents, err := readZipFile(file)
		if err != nil {
			t.Fatalf("read embedded manifest: %v", err)
		}
		manifest, err := parseManifest(contents)
		if err != nil {
			t.Fatalf("parse embedded manifest: %v", err)
		}
		return manifest
	}
	t.Fatalf("embedded archive has no %s", catalogManifestName)
	return embeddedManifest{}
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

	contents, err := os.ReadFile(filepath.Join(testSOTRoot, "examples", "g0-file-catalog.v1.valid.json"))
	if err != nil {
		t.Fatalf("read authoritative G0 file catalog: %v", err)
	}
	var fileCatalog struct {
		Files []struct {
			Path     string  `json:"path"`
			SchemaID *string `json:"schema_id"`
			Pair     *string `json:"pair"`
		} `json:"files"`
	}
	if err := json.Unmarshal(contents, &fileCatalog); err != nil {
		t.Fatalf("decode authoritative G0 file catalog: %v", err)
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
func malformedManifestArchive(t *testing.T) []byte {
	t.Helper()

	var contents bytes.Buffer
	writer := zip.NewWriter(&contents)
	entry, err := writer.CreateHeader(&zip.FileHeader{
		Name:   catalogManifestName,
		Method: zip.Store,
	})
	if err != nil {
		t.Fatalf("create malformed manifest entry: %v", err)
	}
	if _, err := entry.Write([]byte(`{"version":1,"assets":[]}`)); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close malformed archive: %v", err)
	}
	return contents.Bytes()
}
