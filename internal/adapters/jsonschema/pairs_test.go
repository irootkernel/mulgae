package jsonschema

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestInitMutationEnvelopeRequiresExactOutcomeTuple(t *testing.T) {
	validator := newBuiltinValidator(t)
	schemaID := mustAssetID(t, "https://mulgae.local/schemas/mulgae-command-result.v3.schema.json")
	envelope := map[string]any{
		"schema_version": "mulgae-command-result.v3",
		"command":        "init",
		"request": map[string]any{
			"request_id": "i_019f596a-cf80-7c67-b265-f37053d51ccf", "command": "init", "project_root": ".", "project_name": "project", "context": nil,
			"selection": map[string]any{"mode": "selected", "provider_ids": []string{"agy"}}, "roles": []string{"logic", "security"}, "overrides": map[string]any{}, "overwrite": false, "output_format": "json",
		},
		"completed_at": "2026-07-21T00:00:00.000Z",
		"exit":         map[string]any{"code": 8, "kind": "security"},
		"reasons": []any{map[string]any{
			"category": "security", "code": "config_locality_drifted", "message": "The project-local Mulgae configuration failed locality admission.", "retryable": false, "artifact_uri": nil,
		}},
		"result": map[string]any{
			"kind": "initialization_failed", "config_uri": ".mulgae/config.yaml", "config_sha256": "sha256:" + string(bytes.Repeat([]byte("a"), 64)),
			"selected_provider_ids": []string{"agy"}, "candidate_provider_ids": []string{"agy"}, "configured_provider_ids": []string{"agy"}, "configured_role_ids": []string{"logic", "security"},
			"write_state": "installed_unconfirmed", "committed": false, "destination_state": "present",
			"discovery": []any{
				map[string]any{"family": "kimi", "selected": false, "candidate": false, "configured": false, "status": "not_selected", "executable_source": "not_selected", "model_source": "not_selected", "data_home_source": "not_selected"},
				map[string]any{"family": "zcode", "selected": false, "candidate": false, "configured": false, "status": "not_selected", "node_executable_source": "not_selected", "launcher_source": "not_selected"},
				map[string]any{"family": "agy", "selected": true, "candidate": true, "configured": true, "status": "candidate", "executable_source": "override", "native_home_source": "os_account", "permission_mode_source": "safe_default"},
				map[string]any{"family": "codex", "selected": false, "candidate": false, "configured": false, "status": "not_selected", "executable_source": "not_selected", "model_source": "not_selected", "reasoning_effort_source": "not_selected"},
			},
		},
	}
	validate := func(value map[string]any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return validator.Validate(context.Background(), schemaID, raw)
	}
	if err := validate(envelope); err != nil {
		t.Fatalf("valid init mutation envelope rejected: %v", err)
	}
	envelope["exit"] = map[string]any{"code": 2, "kind": "usage"}
	envelope["reasons"] = []any{map[string]any{
		"category": "configuration", "code": "init_destination_exists", "message": "The project-local Mulgae configuration already exists.", "retryable": false, "artifact_uri": nil,
	}}
	if err := validate(envelope); err == nil {
		t.Fatal("contradictory init mutation envelope was accepted")
	}
	result := envelope["result"].(map[string]any)
	result["kind"], result["write_state"], result["committed"] = "initialized", "committed", true
	envelope["exit"] = map[string]any{"code": 7, "kind": "artifact"}
	envelope["reasons"] = []any{map[string]any{
		"category": "artifact", "code": "init_result_delivery_failed", "message": "The init result could not be delivered after commit.", "retryable": true, "artifact_uri": nil,
	}}
	if err := validate(envelope); err != nil {
		t.Fatalf("valid init delivery-failure envelope rejected: %v", err)
	}
	envelope["exit"] = map[string]any{"code": 0, "kind": "success"}
	envelope["reasons"] = []any{}
	if err := validate(envelope); err != nil {
		t.Fatalf("valid committed init success envelope rejected: %v", err)
	}
}

type schemaExamplePair struct {
	schemaID  string
	exampleID string
}

var authoritativePairs = []schemaExamplePair{
	{"https://mulgae.local/schemas/mulgae-clean-plan.v1.schema.json", "example:clean-plan.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-command-result.v3.schema.json", "example:command-result.v3.valid.json"},
	{"https://mulgae.local/schemas/mulgae-doctor-result.v1.schema.json", "example:doctor-result.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-export-manifest.v1.schema.json", "example:export-manifest.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-file-catalog.v1.schema.json", "example:file-catalog.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-mcp-tool-result.v1.schema.json", "example:mcp-tool-result.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-platform-contract-evidence.v1.schema.json", "example:platform-contract-evidence.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-provider-contract-evidence.v2.schema.json", "example:provider-contract-evidence.v2.valid.json"},
	{"https://mulgae.local/schemas/mulgae-provider-followup-output.v1.schema.json", "example:provider-followup-output.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-provider-review-output.v1.schema.json", "example:provider-review-output.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-provider-review-wire.v1.schema.json", "example:provider-review-wire.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-repair-patch.v1.schema.json", "example:repair-patch.json"},
	{"https://mulgae.local/schemas/mulgae-repair-request.v1.schema.json", "example:repair-request.json"},
	{"https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json", "example:review-artifact.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-review-preflight.v3.schema.json", "example:review-preflight.v3.valid.json"},
	{"https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json", "example:run-manifest.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-validation-receipt.v1.schema.json", "example:validation-receipt.v1.valid.json"},
	{"https://mulgae.local/schemas/mulgae-validation-result.v1.schema.json", "example:validation-result.v1.valid.json"},
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
	g0 := examples[fileCatalogExampleID]
	mutated := bytes.Replace(
		g0.raw,
		[]byte(`"pair": "sot/schemas/mulgae-clean-plan.v1.schema.json"`),
		[]byte(`"pair": "sot/schemas/mulgae-command-result.v3.schema.json"`),
		1,
	)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[fileCatalogExampleID] = g0

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
	g0 := examples[fileCatalogExampleID]
	mutated := bytes.Replace(
		g0.raw,
		[]byte(`"path": "sot/examples/command-result.v3.valid.json"`),
		[]byte(`"path": "sot/examples/clean-plan.v1.valid.json"`),
		1,
	)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[fileCatalogExampleID] = g0

	if _, err := buildPairs(examples, schemaSources); err == nil {
		t.Fatal("buildPairs accepted a duplicate example target")
	}
}
func TestBuildPairsRejectsReverseAndCardinalityViolations(t *testing.T) {
	baseExamples, baseSchemas := builtinPairInputs(t)
	cleanPair := []byte(`"pair": "sot/examples/clean-plan.v1.valid.json"`)
	commandPair := []byte(`"pair": "sot/examples/command-result.v3.valid.json"`)

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
				g0 := examples[fileCatalogExampleID]
				temporary := []byte(`"pair": "sot/examples/__pair-swap__.json"`)
				mutated := bytes.Replace(g0.raw, cleanPair, temporary, 1)
				mutated = bytes.Replace(mutated, commandPair, cleanPair, 1)
				mutated = bytes.Replace(mutated, temporary, commandPair, 1)
				if bytes.Equal(mutated, g0.raw) {
					t.Fatal("pair-direction mutation did not change the G0 catalog")
				}
				g0.raw = mutated
				examples[fileCatalogExampleID] = g0
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
				schemas["https://mulgae.local/schemas/extra.schema.json"] = "schemas/extra.schema.json"
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
	g0 := examples[fileCatalogExampleID]
	mutated := bytes.Replace(g0.raw, old, replacement, 1)
	if bytes.Equal(mutated, g0.raw) {
		t.Fatal("test mutation did not change the G0 catalog")
	}
	g0.raw = mutated
	examples[fileCatalogExampleID] = g0
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
