package jsonschema

import (
	"bytes"
	"context"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/builtin"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type schemaExamplePair struct {
	schemaID  string
	exampleID string
}

var authoritativePairs = []schemaExamplePair{
	{"https://kar.local/schemas/kar-clean-plan.v1.schema.json", "example:clean-plan.v1.valid.json"},
	{"https://kar.local/schemas/kar-command-result.v1.schema.json", "example:command-result.v1.valid.json"},
	{"https://kar.local/schemas/kar-doctor-result.v1.schema.json", "example:doctor-result.v1.valid.json"},
	{"https://kar.local/schemas/kar-export-manifest.v1.schema.json", "example:export-manifest.v1.valid.json"},
	{"https://kar.local/schemas/kar-g0-file-catalog.v1.schema.json", "example:g0-file-catalog.v1.valid.json"},
	{"https://kar.local/schemas/kar-platform-contract-evidence.v1.schema.json", "example:platform-contract-evidence.v1.valid.json"},
	{"https://kar.local/schemas/kar-platform-contract-evidence.v2.schema.json", "example:platform-contract-evidence.v2.valid.json"},
	{"https://kar.local/schemas/kar-prompt-manifest.v1.schema.json", "example:prompt-manifest.v1.valid.json"},
	{"https://kar.local/schemas/kar-provider-contract-evidence.v1.schema.json", "example:provider-contract-evidence.v1.valid.json"},
	{"https://kar.local/schemas/kar-provider-contract-evidence.v2.schema.json", "example:provider-contract-evidence.v2.valid.json"},
	{"urn:kar:schema:provider-followup-output:v1", "example:provider-followup-output.valid.json"},
	{"https://kar.local/schemas/kar-provider-followup-output.v2.schema.json", "example:provider-followup-output.v2.valid.json"},
	{"urn:kar:schema:provider-review-output:v1", "example:provider-review-output.valid.json"},
	{"https://kar.local/schemas/kar-provider-review-output.v2.schema.json", "example:provider-review-output.v2.valid.json"},
	{"urn:kar:schema:repair-patch:v1", "example:repair-patch.json"},
	{"urn:kar:schema:repair-request:v1", "example:repair-request.json"},
	{"urn:kar:schema:review-artifact:v1", "example:review-artifact.valid.json"},
	{"https://kar.local/schemas/kar-review-artifact.v2.schema.json", "example:review-artifact.v2.valid.json"},
	{"urn:kar:schema:run-manifest:v1", "example:run-manifest.valid.json"},
	{"https://kar.local/schemas/kar-run-manifest.v2.schema.json", "example:run-manifest.v2.valid.json"},
	{"https://kar.local/schemas/kar-validation-receipt.v1.schema.json", "example:validation-receipt.v1.valid.json"},
	{"urn:kar:schema:validation-result:v1", "example:validation-result.valid.json"},
	{"https://kar.local/schemas/kar-validation-result.v2.schema.json", "example:validation-result.v2.valid.json"},
}

func TestValidatorAcceptsExactAuthoritativePairs(t *testing.T) {
	if got := len(authoritativePairs); got != authoritativePairCount {
		t.Fatalf("authoritative pair count = %d, want %d", got, authoritativePairCount)
	}
	validator := newBuiltinValidator(t)
	if got := len(validator.pairs); got != authoritativePairCount {
		t.Fatalf("validated pair count = %d, want %d", got, authoritativePairCount)
	}
	if got := len(validator.examples); got != authoritativePairCount {
		t.Fatalf("validated JSON example count = %d, want %d", got, authoritativePairCount)
	}
	ctx := context.Background()
	for _, pair := range authoritativePairs {
		pair := pair
		t.Run(pair.schemaID, func(t *testing.T) {
			if err := validator.ValidatePair(ctx, mustAssetID(t, pair.schemaID), mustAssetID(t, pair.exampleID)); err != nil {
				t.Fatalf("ValidatePair(%q, %q): %v", pair.schemaID, pair.exampleID, err)
			}
		})
	}
}

func TestValidatorRejectsEverySwappedAndOrphanPair(t *testing.T) {
	validator := newBuiltinValidator(t)
	ctx := context.Background()
	for schemaIndex, schemaPair := range authoritativePairs {
		schemaID := mustAssetID(t, schemaPair.schemaID)
		for exampleIndex, examplePair := range authoritativePairs {
			if schemaIndex == exampleIndex {
				continue
			}
			if err := validator.ValidatePair(ctx, schemaID, mustAssetID(t, examplePair.exampleID)); err == nil {
				t.Errorf("ValidatePair(%q, %q) accepted swapped example", schemaPair.schemaID, examplePair.exampleID)
			}
		}
		if err := validator.ValidatePair(ctx, schemaID, mustAssetID(t, "example:orphan.valid.json")); err == nil {
			t.Errorf("ValidatePair(%q, orphan) accepted an unknown example", schemaPair.schemaID)
		}
		if err := validator.ValidatePair(ctx, schemaID, schemaID); err == nil {
			t.Errorf("ValidatePair(%q, schema ID) accepted a non-example asset", schemaPair.schemaID)
		}
	}
}

func TestBuildPairsRejectsPairPathThatDisagreesWithSchemaID(t *testing.T) {
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	metadata, err := catalog.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	examples := make(map[string]catalogExample)
	schemaSources := make(map[string]string)
	for _, asset := range metadata {
		switch asset.Kind() {
		case ports.AssetKindSchema:
			schemaSources[asset.ID().String()] = asset.Source().String()
		case ports.AssetKindExample:
			if asset.MediaType() != "application/json" {
				continue
			}
			_, raw, readErr := catalog.Read(ctx, asset.ID())
			if readErr != nil {
				t.Fatal(readErr)
			}
			examples[asset.ID().String()] = catalogExample{metadata: asset, raw: raw}
		}
	}
	g0 := examples[g0FileCatalogExampleID]
	mutated := bytes.Replace(
		g0.raw,
		[]byte(`"pair": "sot/schemas/kar-clean-plan.v1.schema.json"`),
		[]byte(`"pair": "sot/schemas/kar-command-result.v1.schema.json"`),
		1,
	)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[g0FileCatalogExampleID] = g0

	if _, err := buildPairs(examples, schemaSources); err == nil {
		t.Fatal("buildPairs accepted a pair path that disagrees with schema_id")
	}
}
func TestBuildPairsRejectsDuplicateExampleTarget(t *testing.T) {
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	metadata, err := catalog.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	examples := make(map[string]catalogExample)
	schemaSources := make(map[string]string)
	for _, asset := range metadata {
		switch asset.Kind() {
		case ports.AssetKindSchema:
			schemaSources[asset.ID().String()] = asset.Source().String()
		case ports.AssetKindExample:
			if asset.MediaType() != "application/json" {
				continue
			}
			_, raw, readErr := catalog.Read(ctx, asset.ID())
			if readErr != nil {
				t.Fatal(readErr)
			}
			examples[asset.ID().String()] = catalogExample{metadata: asset, raw: raw}
		}
	}
	g0 := examples[g0FileCatalogExampleID]
	mutated := bytes.Replace(
		g0.raw,
		[]byte(`"path": "sot/examples/command-result.v1.valid.json"`),
		[]byte(`"path": "sot/examples/clean-plan.v1.valid.json"`),
		1,
	)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[g0FileCatalogExampleID] = g0

	if _, err := buildPairs(examples, schemaSources); err == nil {
		t.Fatal("buildPairs accepted a duplicate example target")
	}
}
func TestBuildPairsRejectsReverseAndCardinalityViolations(t *testing.T) {
	baseExamples, baseSchemas := builtinPairInputs(t)
	cleanPair := []byte(`"pair": "sot/examples/clean-plan.v1.valid.json"`)
	commandPair := []byte(`"pair": "sot/examples/command-result.v1.valid.json"`)

	tests := []struct {
		name   string
		mutate func(map[string]catalogExample, map[string]string)
	}{
		{
			name: "missing reverse pair",
			mutate: func(examples map[string]catalogExample, _ map[string]string) {
				mutateG0Raw(t, examples, cleanPair, []byte(`"pair": null`))
			},
		},
		{
			name: "duplicate reverse target",
			mutate: func(examples map[string]catalogExample, _ map[string]string) {
				mutateG0Raw(t, examples, commandPair, cleanPair)
			},
		},
		{
			name: "pair directions disagree",
			mutate: func(examples map[string]catalogExample, _ map[string]string) {
				g0 := examples[g0FileCatalogExampleID]
				temporary := []byte(`"pair": "sot/examples/__pair-swap__.json"`)
				mutated := bytes.Replace(g0.raw, cleanPair, temporary, 1)
				mutated = bytes.Replace(mutated, commandPair, cleanPair, 1)
				mutated = bytes.Replace(mutated, temporary, commandPair, 1)
				if bytes.Equal(mutated, g0.raw) {
					t.Fatal("pair-direction mutation did not change the G0 catalog")
				}
				g0.raw = mutated
				examples[g0FileCatalogExampleID] = g0
			},
		},
		{
			name: "twenty two schemas",
			mutate: func(_ map[string]catalogExample, schemas map[string]string) {
				delete(schemas, authoritativePairs[0].schemaID)
			},
		},
		{
			name: "twenty four schemas",
			mutate: func(_ map[string]catalogExample, schemas map[string]string) {
				schemas["https://kar.local/schemas/extra.schema.json"] = "schemas/extra.schema.json"
			},
		},
		{
			name: "twenty two examples",
			mutate: func(examples map[string]catalogExample, _ map[string]string) {
				delete(examples, authoritativePairs[0].exampleID)
			},
		},
		{
			name: "twenty four examples",
			mutate: func(examples map[string]catalogExample, _ map[string]string) {
				examples["example:extra.valid.json"] = examples[authoritativePairs[0].exampleID]
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			examples := cloneCatalogExamples(baseExamples)
			schemas := cloneSchemaSources(baseSchemas)
			test.mutate(examples, schemas)
			if _, err := buildPairs(examples, schemas); err == nil {
				t.Fatal("buildPairs accepted a reverse-pair or cardinality violation")
			}
		})
	}
}

func builtinPairInputs(t *testing.T) (map[string]catalogExample, map[string]string) {
	t.Helper()
	ctx := context.Background()
	catalog := builtin.NewCatalog()
	metadata, err := catalog.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	examples := make(map[string]catalogExample)
	schemas := make(map[string]string)
	for _, asset := range metadata {
		switch asset.Kind() {
		case ports.AssetKindSchema:
			schemas[asset.ID().String()] = asset.Source().String()
		case ports.AssetKindExample:
			if asset.MediaType() != "application/json" {
				continue
			}
			_, raw, readErr := catalog.Read(ctx, asset.ID())
			if readErr != nil {
				t.Fatal(readErr)
			}
			examples[asset.ID().String()] = catalogExample{metadata: asset, raw: raw}
		}
	}
	return examples, schemas
}

func mutateG0Raw(t *testing.T, examples map[string]catalogExample, old, replacement []byte) {
	t.Helper()
	g0 := examples[g0FileCatalogExampleID]
	mutated := bytes.Replace(g0.raw, old, replacement, 1)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[g0FileCatalogExampleID] = g0
}

func cloneCatalogExamples(examples map[string]catalogExample) map[string]catalogExample {
	cloned := make(map[string]catalogExample, len(examples))
	for id, example := range examples {
		example.raw = append([]byte(nil), example.raw...)
		cloned[id] = example
	}
	return cloned
}

func cloneSchemaSources(schemas map[string]string) map[string]string {
	cloned := make(map[string]string, len(schemas))
	for id, source := range schemas {
		cloned[id] = source
	}
	return cloned
}

func newBuiltinValidator(t *testing.T) *Validator {
	t.Helper()
	validator, err := New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatalf("New(builtin catalog): %v", err)
	}
	return validator
}

func mustAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatalf("ParseAssetID(%q): %v", value, err)
	}
	return id
}
