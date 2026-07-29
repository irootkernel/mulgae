package jsonschema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestValidatorRejectsInvalidJSONInputsAndUnknownIDs(t *testing.T) {
	validator := newBuiltinValidator(t)
	schemaID := mustAssetID(t, authoritativePairs[0].schemaID)
	secret := "adapter-must-not-leak-this-input"

	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "trailing value", raw: []byte("{} {}")},
		{name: "malformed JSON", raw: []byte(`{"secret":"` + secret)},
		{name: "oversize", raw: bytes.Repeat([]byte(" "), MaxInputBytes+1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := validator.Validate(context.Background(), schemaID, test.raw)
			requireDiagnosticStage(t, err, StageDecode)
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("diagnostic leaks validation input: %q", err)
			}
		})
	}

	unknownSchemaID := mustAssetID(t, "https://mulgae.local/schemas/not-in-catalog.v1.schema.json")
	requireDiagnosticStage(t, validator.Validate(context.Background(), unknownSchemaID, []byte("{}")), StageSchema)
	requireDiagnosticStage(t, validator.Validate(context.Background(), mustAssetID(t, authoritativePairs[0].exampleID), []byte("{}")), StageSchema)
}

func TestValidatorReadinessAuthorityIsV1Only(t *testing.T) {
	for _, test := range []struct {
		id   string
		want bool
	}{
		{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v1.schema.json", true},
		{"https://mulgae.local/schemas/mulgae-platform-contract-evidence.v1.schema.json", true},
		{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json", false},
		{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v3.schema.json", false},
	} {
		if got := ReadinessAuthority(mustAssetID(t, test.id)); got != test.want {
			t.Errorf("ReadinessAuthority(%q) = %t, want %t", test.id, got, test.want)
		}
	}
}

func TestNewRejectsTamperedCatalogAndSchemaIDMismatch(t *testing.T) {
	ctx := context.Background()
	base := builtin.NewCatalog()
	targetID := mustAssetID(t, authoritativePairs[0].schemaID)
	metadata, raw, err := base.Read(ctx, targetID)
	if err != nil {
		t.Fatalf("read target schema: %v", err)
	}

	tamperedRaw := append([]byte(nil), raw...)
	tamperedRaw[0] ^= 1
	tampered := &catalogOverride{base: base, id: targetID, metadata: metadata, raw: tamperedRaw}
	requireDiagnosticStage(t, newCatalogError(ctx, tampered), StageCatalog)

	mismatchedRaw := bytes.Replace(raw, []byte(targetID.String()), []byte("urn:mulgae:tampered-schema-id"), 1)
	if bytes.Equal(mismatchedRaw, raw) {
		t.Fatal("target schema did not contain its $id")
	}
	sum := sha256.Sum256(mismatchedRaw)
	mismatchedMetadata, err := ports.NewAssetMetadata(
		metadata.ID(),
		metadata.Kind(),
		metadata.Source(),
		metadata.MediaType(),
		"sha256:"+hex.EncodeToString(sum[:]),
		int64(len(mismatchedRaw)),
	)
	if err != nil {
		t.Fatalf("construct mismatched metadata: %v", err)
	}
	mismatched := &catalogOverride{base: base, id: targetID, metadata: mismatchedMetadata, raw: mismatchedRaw}
	requireDiagnosticStage(t, newCatalogError(ctx, mismatched), StageCatalog)
	var unresolvedSchema map[string]any
	if err := json.Unmarshal(raw, &unresolvedSchema); err != nil {
		t.Fatalf("decode target schema: %v", err)
	}
	unresolvedSchema["$ref"] = "https://unresolved.invalid/schema"
	unresolvedRaw, err := json.Marshal(unresolvedSchema)
	if err != nil {
		t.Fatalf("encode unresolved schema: %v", err)
	}
	sum = sha256.Sum256(unresolvedRaw)
	unresolvedMetadata, err := ports.NewAssetMetadata(
		metadata.ID(),
		metadata.Kind(),
		metadata.Source(),
		metadata.MediaType(),
		"sha256:"+hex.EncodeToString(sum[:]),
		int64(len(unresolvedRaw)),
	)
	if err != nil {
		t.Fatalf("construct unresolved metadata: %v", err)
	}
	unresolved := &catalogOverride{base: base, id: targetID, metadata: unresolvedMetadata, raw: unresolvedRaw}
	requireDiagnosticStage(t, newCatalogError(ctx, unresolved), StageCatalog)
}
func TestSchemaCompilerDeniesExternalResolution(t *testing.T) {
	localID := "https://mulgae.local/schemas/local-reference.schema.json"
	local := newSchemaCompiler()
	if err := local.AddResource(localID, map[string]any{
		"$schema": draft2020URI,
		"$id":     localID,
		"$defs": map[string]any{
			"local": map[string]any{"type": "string"},
		},
		"$ref": "#/$defs/local",
	}); err != nil {
		t.Fatalf("add local resource: %v", err)
	}
	if _, err := local.Compile(localID); err != nil {
		t.Fatalf("compile local resource: %v", err)
	}

	for _, reference := range []string{
		"file:///definitely-not-a-schema.json",
		"http://127.0.0.1:1/schema.json",
		"https://unresolved.invalid/schema.json",
	} {
		reference := reference
		t.Run(reference, func(t *testing.T) {
			if _, err := (denyURLLoader{}).Load(reference); err == nil {
				t.Fatal("denyURLLoader accepted an external reference")
			}

			compiler := newSchemaCompiler()
			id := "https://mulgae.local/schemas/closed-loader.schema.json"
			if err := compiler.AddResource(id, map[string]any{
				"$schema": draft2020URI,
				"$id":     id,
				"$ref":    reference,
			}); err != nil {
				t.Fatalf("add external-reference resource: %v", err)
			}
			if _, err := compiler.Compile(id); err == nil {
				t.Fatal("compiler resolved an external reference")
			}
		})
	}
}

func TestNewRejectsNestedAndNonFragmentSchemaReferences(t *testing.T) {
	ctx := context.Background()
	base := builtin.NewCatalog()
	targetID := mustAssetID(t, authoritativePairs[0].schemaID)
	_, raw, err := base.Read(ctx, targetID)
	if err != nil {
		t.Fatalf("read target schema: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "file reference",
			mutate: func(document map[string]any) {
				document["$ref"] = "file:///definitely-not-a-schema.json"
			},
		},
		{
			name: "dynamic HTTP reference",
			mutate: func(document map[string]any) {
				document["$dynamicRef"] = "https://unresolved.invalid/schema.json"
			},
		},
		{
			name: "nested identifier",
			mutate: func(document map[string]any) {
				document["allOf"] = []any{map[string]any{"$id": "nested.json"}}
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("decode target schema: %v", err)
			}
			test.mutate(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode target schema: %v", err)
			}
			requireDiagnosticStage(t, newCatalogError(ctx, catalogOverrideForRaw(t, base, targetID, mutated)), StageCatalog)
		})
	}
}

func TestValidatorStrictJSONDecodeRejectsAmbiguity(t *testing.T) {
	validator := newBuiltinValidator(t)
	schemaID := mustAssetID(t, authoritativePairs[0].schemaID)

	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "nested duplicate key", raw: []byte(`{"nested":{"key":1,"key":2}}`)},
		{name: "lone high surrogate", raw: []byte(`{"value":"\uD800"}`)},
		{name: "lone low surrogate", raw: []byte(`{"value":"\uDC00"}`)},
		{name: "invalid UTF-8", raw: []byte{'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'}},
		{name: "malformed number", raw: []byte(`{"value":01}`)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			requireDiagnosticStage(t, validator.Validate(context.Background(), schemaID, test.raw), StageDecode)
		})
	}
}
func TestStrictJSONDecoderDepthUnicodeAndEquivalentKeys(t *testing.T) {
	belowLimit := append(
		[]byte(strings.Repeat("[", maxJSONDepth-1)),
		append([]byte("0"), []byte(strings.Repeat("]", maxJSONDepth-1))...)...,
	)
	if _, err := decodeJSON(belowLimit); err != nil {
		t.Fatalf("decodeJSON() rejected depth below limit: %v", err)
	}

	atLimit := append(
		[]byte(strings.Repeat("[", maxJSONDepth)),
		append([]byte("0"), []byte(strings.Repeat("]", maxJSONDepth))...)...,
	)
	if _, err := decodeJSON(atLimit); err == nil {
		t.Fatal("decodeJSON() accepted depth at the fail-closed limit")
	}

	for _, raw := range [][]byte{
		[]byte(`{"value":"\uD83D\uDE00"}`),
		[]byte(`{"value":"\\uD800"}`),
	} {
		if _, err := decodeJSON(raw); err != nil {
			t.Fatalf("decodeJSON(%q) rejected valid Unicode: %v", raw, err)
		}
	}
	if _, err := decodeJSON([]byte(`{"a":1,"\u0061":2}`)); err == nil {
		t.Fatal("decodeJSON() accepted escape-equivalent duplicate keys")
	}
}

func TestValidationDiagnosticRedactsInputControlledPath(t *testing.T) {
	const hostileKey = "secret\n\u001b[31mcredential-material"
	const id = "https://mulgae.local/schemas/path-redaction.schema.json"
	document := map[string]any{
		"$schema": draft2020URI,
		"$id":     id,
		"type":    "object",
		"properties": map[string]any{
			hostileKey: map[string]any{"type": "string"},
		},
		"required":             []any{hostileKey},
		"additionalProperties": false,
	}
	compiler := newSchemaCompiler()
	if err := compiler.AddResource(id, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{hostileKey: 1})
	if err != nil {
		t.Fatal(err)
	}
	validator := &Validator{schemas: map[string]*jschema.Schema{id: schema}}
	err = validator.Validate(context.Background(), mustAssetID(t, id), raw)
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatalf("Validate() error = %T %v, want Diagnostic", err, err)
	}
	if strings.Contains(diagnostic.Path, hostileKey) || strings.Contains(err.Error(), hostileKey) {
		t.Fatalf("validation diagnostic reflected hostile path: %#v / %q", diagnostic, err.Error())
	}
	if len(diagnostic.Path) > 256 || strings.ContainsAny(diagnostic.Path, "\r\n\u001b") {
		t.Fatalf("validation diagnostic path is unbounded or unsafe: %q", diagnostic.Path)
	}
}

func TestNewRejectsAmbiguousCatalogJSON(t *testing.T) {
	ctx := context.Background()
	base := builtin.NewCatalog()
	for _, test := range []struct {
		name string
		id   ports.AssetID
		raw  func([]byte) []byte
	}{
		{
			name: "schema duplicate key",
			id:   mustAssetID(t, authoritativePairs[0].schemaID),
			raw: func(raw []byte) []byte {
				return insertAfterJSONObjectStart(raw, []byte(`"$id":"duplicate",`))
			},
		},
		{
			name: "example duplicate key",
			id:   mustAssetID(t, authoritativePairs[0].exampleID),
			raw: func(raw []byte) []byte {
				return insertAfterJSONObjectStart(raw, []byte(`"duplicate":0,"duplicate":1,`))
			},
		},
		{
			name: "G0 lone surrogate",
			id:   mustAssetID(t, fileCatalogExampleID),
			raw: func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"schema_version"`), []byte(`"\uD800"`), 1)
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, raw, err := base.Read(ctx, test.id)
			if err != nil {
				t.Fatalf("read catalog asset: %v", err)
			}
			mutated := test.raw(raw)
			if bytes.Equal(mutated, raw) {
				t.Fatal("test mutation did not change the catalog asset")
			}
			requireDiagnosticStage(t, newCatalogError(ctx, catalogOverrideForRaw(t, base, test.id, mutated)), StageCatalog)
		})
	}
}

func TestValidatorRegexErrorsDoNotBypassApplicators(t *testing.T) {
	raw, err := json.Marshal(strings.Repeat("a", 1<<20) + "!")
	if err != nil {
		t.Fatalf("encode regex input: %v", err)
	}
	for _, test := range []struct {
		name    string
		keyword string
	}{
		{name: "not", keyword: "not"},
		{name: "if", keyword: "if"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			id := "https://mulgae.local/schemas/regexp-" + test.name + ".schema.json"
			document := map[string]any{
				"$schema": draft2020URI,
				"$id":     id,
				test.keyword: map[string]any{
					"type":    "string",
					"pattern": "^(a+)+$",
				},
			}
			if test.keyword == "if" {
				document["then"] = false
			}
			compiler := newSchemaCompiler()
			if err := compiler.AddResource(id, document); err != nil {
				t.Fatalf("add regexp schema: %v", err)
			}
			schema, err := compiler.Compile(id)
			if err != nil {
				t.Fatalf("compile regexp schema: %v", err)
			}
			validator := &Validator{schemas: map[string]*jschema.Schema{id: schema}}
			requireDiagnosticStage(t, validator.Validate(context.Background(), mustAssetID(t, id), raw), StageRuntime)
		})
	}
}

func TestValidatorCopiesCatalogBytesBeforeCompilation(t *testing.T) {
	ctx := context.Background()
	base := builtin.NewCatalog()
	pair := authoritativePairs[0]
	schemaID := mustAssetID(t, pair.schemaID)
	exampleID := mustAssetID(t, pair.exampleID)

	for _, assetID := range []ports.AssetID{schemaID, exampleID} {
		metadata, raw, err := base.Read(ctx, assetID)
		if err != nil {
			t.Fatalf("read asset %q: %v", assetID.String(), err)
		}
		catalog := &sharedReadCatalog{base: base, id: assetID, metadata: metadata, raw: raw}
		validator, err := New(ctx, catalog)
		if err != nil {
			t.Fatalf("New(shared catalog): %v", err)
		}
		for index := range catalog.raw {
			catalog.raw[index] = 0
		}
		if err := validator.ValidatePair(ctx, schemaID, exampleID); err != nil {
			t.Fatalf("validator changed after catalog alias mutation for %q: %v", assetID.String(), err)
		}
	}
}

func TestValidatorHonorsCanceledContext(t *testing.T) {
	validator := newBuiltinValidator(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireDiagnosticStage(t, validator.Validate(ctx, mustAssetID(t, authoritativePairs[0].schemaID), []byte("{}")), StageContext)
}

func newCatalogError(ctx context.Context, catalog ports.ContractCatalog) error {
	_, err := New(ctx, catalog)
	if err == nil {
		return errors.New("New unexpectedly accepted catalog")
	}
	return err
}
func catalogOverrideForRaw(t *testing.T, base ports.ContractCatalog, id ports.AssetID, raw []byte) *catalogOverride {
	t.Helper()
	metadata, _, err := base.Read(context.Background(), id)
	if err != nil {
		t.Fatalf("read overridden asset metadata: %v", err)
	}
	sum := sha256.Sum256(raw)
	updatedMetadata, err := ports.NewAssetMetadata(
		metadata.ID(),
		metadata.Kind(),
		metadata.Source(),
		metadata.MediaType(),
		"sha256:"+hex.EncodeToString(sum[:]),
		int64(len(raw)),
	)
	if err != nil {
		t.Fatalf("construct overridden asset metadata: %v", err)
	}
	return &catalogOverride{base: base, id: id, metadata: updatedMetadata, raw: raw}
}

func insertAfterJSONObjectStart(raw, value []byte) []byte {
	index := bytes.IndexByte(raw, '{')
	if index < 0 {
		return raw
	}
	mutated := make([]byte, 0, len(raw)+len(value))
	mutated = append(mutated, raw[:index+1]...)
	mutated = append(mutated, value...)
	return append(mutated, raw[index+1:]...)
}

func requireDiagnosticStage(t *testing.T, err error, want Stage) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want diagnostic at %s", want)
	}
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatalf("error %T is not *Diagnostic", err)
	}
	if diagnostic.Stage != want {
		t.Fatalf("diagnostic stage = %q, want %q (error: %v)", diagnostic.Stage, want, err)
	}
	if diagnostic.Path == "" {
		t.Fatal("diagnostic path is empty")
	}
}

type catalogOverride struct {
	base     ports.ContractCatalog
	id       ports.AssetID
	metadata ports.AssetMetadata
	raw      []byte
}

func (catalog *catalogOverride) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	assets, err := catalog.base.List(ctx)
	if err != nil {
		return nil, err
	}
	for index := range assets {
		if assets[index].ID() == catalog.id {
			assets[index] = catalog.metadata
		}
	}
	return assets, nil
}

func (catalog *catalogOverride) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if id == catalog.id {
		return catalog.metadata, append([]byte(nil), catalog.raw...), nil
	}
	return catalog.base.Read(ctx, id)
}

type sharedReadCatalog struct {
	base     ports.ContractCatalog
	id       ports.AssetID
	metadata ports.AssetMetadata
	raw      []byte
}

func (catalog *sharedReadCatalog) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	return catalog.base.List(ctx)
}

func (catalog *sharedReadCatalog) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if id == catalog.id {
		return catalog.metadata, catalog.raw, nil
	}
	return catalog.base.Read(ctx, id)
}
