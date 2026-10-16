//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type contractPair struct {
	schemaSource, schemaTarget   string
	exampleSource, exampleTarget string
	oldVersion, newVersion       string
}

func main() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("portfolio contract generator: caller unavailable")
	}
	assets := filepath.Join(filepath.Dir(filename), "assets")
	pairs := []contractPair{
		{"schemas/mulgae-doctor-result.v4.schema.json", "schemas/mulgae-doctor-result.v5.schema.json", "examples/doctor-result.v4.valid.json", "examples/doctor-result.v5.valid.json", "mulgae-doctor-result.v4", "mulgae-doctor-result.v5"},
		{"schemas/mulgae-provider-contract-evidence.v3.schema.json", "schemas/mulgae-provider-contract-evidence.v4.schema.json", "examples/provider-contract-evidence.v3.valid.json", "examples/provider-contract-evidence.v4.valid.json", "mulgae-provider-contract-evidence.v3", "mulgae-provider-contract-evidence.v4"},
		{"schemas/mulgae-provider-heartbeat-result.v2.schema.json", "schemas/mulgae-provider-heartbeat-result.v3.schema.json", "examples/provider-heartbeat-result.v2.valid.json", "examples/provider-heartbeat-result.v3.valid.json", "mulgae-provider-heartbeat-result.v2", "mulgae-provider-heartbeat-result.v3"},
	}
	for _, pair := range pairs {
		if err := generatePair(assets, pair); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := publishCursorSelection(assets); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	commandPair := contractPair{"schemas/mulgae-command-result.v12.schema.json", "schemas/mulgae-command-result.v13.schema.json", "examples/command-result.v12.valid.json", "examples/command-result.v13.valid.json", "mulgae-command-result.v12", "mulgae-command-result.v13"}
	if err := updateFileCatalog(assets, append(pairs, commandPair,
		contractPair{"schemas/mulgae-command-result.v13.schema.json", "schemas/mulgae-command-result.v14.schema.json", "examples/command-result.v13.valid.json", "examples/command-result.v14.valid.json", "mulgae-command-result.v13", "mulgae-command-result.v14"},
		contractPair{"schemas/mulgae-command-result.v14.schema.json", "schemas/mulgae-command-result.v15.schema.json", "examples/command-result.v14.valid.json", "examples/command-result.v15.valid.json", "mulgae-command-result.v14", "mulgae-command-result.v15"},
		contractPair{"schemas/mulgae-command-result.v15.schema.json", "schemas/mulgae-command-result.v16.schema.json", "examples/command-result.v15.valid.json", "examples/command-result.v16.valid.json", "mulgae-command-result.v15", "mulgae-command-result.v16"},
		contractPair{"schemas/mulgae-command-result.v16.schema.json", "schemas/mulgae-command-result.v17.schema.json", "examples/command-result.v16.valid.json", "examples/command-result.v17.valid.json", "mulgae-command-result.v16", "mulgae-command-result.v17"},
		contractPair{"schemas/mulgae-command-result.v17.schema.json", "schemas/mulgae-command-result.v18.schema.json", "examples/command-result.v17.valid.json", "examples/command-result.v18.valid.json", "mulgae-command-result.v17", "mulgae-command-result.v18"},
		contractPair{"schemas/mulgae-command-result.v18.schema.json", "schemas/mulgae-command-result.v19.schema.json", "examples/command-result.v18.valid.json", "examples/command-result.v19.valid.json", "mulgae-command-result.v18", "mulgae-command-result.v19"},
		contractPair{"schemas/mulgae-command-result.v19.schema.json", "schemas/mulgae-command-result.v20.schema.json", "examples/command-result.v19.valid.json", "examples/command-result.v20.valid.json", "mulgae-command-result.v19", "mulgae-command-result.v20"},
		contractPair{"schemas/mulgae-doctor-result.v5.schema.json", "schemas/mulgae-doctor-result.v6.schema.json", "examples/doctor-result.v5.valid.json", "examples/doctor-result.v6.valid.json", "mulgae-doctor-result.v5", "mulgae-doctor-result.v6"},
		contractPair{"schemas/mulgae-provider-review-output.v1.schema.json", "schemas/mulgae-provider-review-output.v2.schema.json", "examples/provider-review-output.v1.valid.json", "examples/provider-review-output.v2.valid.json", "mulgae-provider-review-output.v1", "mulgae-provider-review-output.v2"},
		contractPair{"schemas/mulgae-publication-receipt.v1.schema.json", "schemas/mulgae-publication-receipt.v2.schema.json", "examples/publication-receipt.v1.valid.json", "examples/publication-receipt.v2.valid.json", "mulgae-publication-receipt.v1", "mulgae-publication-receipt.v2"},
		contractPair{"schemas/mulgae-export-manifest.v1.schema.json", "schemas/mulgae-export-manifest.v2.schema.json", "examples/export-manifest.v1.valid.json", "examples/export-manifest.v2.valid.json", "mulgae-export-manifest.v1", "mulgae-export-manifest.v2"},
		contractPair{"schemas/mulgae-review-artifact.v1.schema.json", "schemas/mulgae-review-artifact.v3.schema.json", "examples/review-artifact.v1.valid.json", "examples/review-artifact.v3.valid.json", "mulgae-review-artifact.v1", "mulgae-review-artifact.v3"},
		contractPair{"schemas/mulgae-run-manifest.v1.schema.json", "schemas/mulgae-run-manifest.v3.schema.json", "examples/run-manifest.v1.valid.json", "examples/run-manifest.v3.valid.json", "mulgae-run-manifest.v1", "mulgae-run-manifest.v3"},
	)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func updateFileCatalog(assets string, pairs []contractPair) error {
	filename := filepath.Join(assets, "examples", "file-catalog.v1.valid.json")
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document struct {
		SchemaVersion string           `json:"schema_version"`
		Files         []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		return err
	}
	retained := document.Files[:0]
	for _, file := range document.Files {
		if file["path"] == "sot/schemas/mulgae-request-receipt.v1.schema.json" || file["path"] == "sot/examples/request-receipt.v1.valid.json" {
			continue
		}
		retained = append(retained, file)
	}
	document.Files = retained
	byPath := make(map[string]map[string]any, len(document.Files))
	for _, file := range document.Files {
		if path, ok := file["path"].(string); ok {
			byPath[path] = file
		}
	}
	for _, pair := range pairs {
		for _, item := range []struct {
			source, target, paired string
		}{{pair.schemaSource, pair.schemaTarget, pair.exampleTarget}, {pair.exampleSource, pair.exampleTarget, pair.schemaTarget}} {
			targetPath := "sot/" + item.target
			if existing, exists := byPath[targetPath]; exists {
				existing["pair"] = "sot/" + item.paired
				continue
			}
			source, exists := byPath["sot/"+item.source]
			if !exists {
				return fmt.Errorf("portfolio contract generator: file catalog source %s is absent", item.source)
			}
			encoded, _ := json.Marshal(source)
			var clone map[string]any
			if err := json.Unmarshal(encoded, &clone); err != nil {
				return err
			}
			clone = transformPortfolio(clone, pair.oldVersion, pair.newVersion, false).(map[string]any)
			clone["path"] = targetPath
			clone["pair"] = "sot/" + item.paired
			document.Files = append(document.Files, clone)
			byPath[targetPath] = clone
		}
	}
	// EPIC-007 value contracts are catalogued independently of runtime
	// command versions. Their source schemas and examples are hand-authored.
	for _, name := range []string{"capture-manifest", "publication-receipt", "finding-cursor", "composite-support"} {
		schema := "sot/schemas/mulgae-" + name + ".v1.schema.json"
		example := "sot/examples/" + name + ".v1.valid.json"
		for path, pair := range map[string]string{schema: example, example: schema} {
			if _, exists := byPath[path]; exists {
				continue
			}
			document.Files = append(document.Files, map[string]any{
				"path": path, "pair": pair, "schema_id": "https://mulgae.local/schemas/mulgae-" + name + ".v1.schema.json",
				"consumers": []string{"verified-review-contracts"}, "media_type": "application/json",
				"disposition": "ADDED", "checksum_inclusion": true, "exclusion_reason": nil,
			})
		}
	}
	sort.Slice(document.Files, func(i, j int) bool {
		return document.Files[i]["path"].(string) < document.Files[j]["path"].(string)
	})
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if err := writeGenerated(filename, append(encoded, '\n')); err != nil {
		return err
	}
	return updateFileCatalogCardinality(assets, len(document.Files))
}

func updateFileCatalogCardinality(assets string, count int) error {
	filename := filepath.Join(assets, "schemas", "mulgae-file-catalog.v1.schema.json")
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		return err
	}
	properties := document["properties"].(map[string]any)
	files := properties["files"].(map[string]any)
	files["minItems"] = count
	files["maxItems"] = count
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeGenerated(filename, append(encoded, '\n'))
}

func generatePair(root string, pair contractPair) error {
	for _, item := range []struct {
		source, target string
		schema         bool
	}{{pair.schemaSource, pair.schemaTarget, true}, {pair.exampleSource, pair.exampleTarget, false}} {
		contents, err := os.ReadFile(filepath.Join(root, item.source))
		if err != nil {
			return fmt.Errorf("portfolio contract generator: read %s: %w", item.source, err)
		}
		var document any
		if err := json.Unmarshal(contents, &document); err != nil {
			return fmt.Errorf("portfolio contract generator: decode %s: %w", item.source, err)
		}
		document = transformPortfolio(document, pair.oldVersion, pair.newVersion, item.schema)
		if item.schema && pair.newVersion == "mulgae-provider-contract-evidence.v4" {
			if err := admitCurrentProviderFamilies(document); err != nil {
				return err
			}
		}
		if pair.newVersion == "mulgae-doctor-result.v5" {
			addDoctorApplicationCompatibility(document, item.schema)
		}
		if !item.schema && pair.exampleTarget == "examples/provider-contract-evidence.v4.valid.json" {
			normalizeProviderEvidenceExample(document)
		}
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
		if err := writeGenerated(filepath.Join(root, item.target), encoded); err != nil {
			return err
		}
	}
	return nil
}

func admitCurrentProviderFamilies(document any) error {
	root := document.(map[string]any)
	definitions := root["$defs"].(map[string]any)
	providerBase := definitions["provider_base"].(map[string]any)
	properties := providerBase["properties"].(map[string]any)
	family := properties["family"].(map[string]any)
	family["enum"] = []any{"zcode", "grok", "codex", "cursor"}
	return nil
}

func restrictPermissionModes(value any) int {
	count := 0
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "permission_mode" {
					property, ok := child.(map[string]any)
					if ok {
						if _, exists := property["enum"]; exists {
							property["enum"] = []any{"not_applicable"}
							count++
						}
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return count
}

func addDoctorApplicationCompatibility(document any, schema bool) {
	if schema {
		root := document.(map[string]any)
		root["title"] = "Mulgae Project-local Doctor Result v5"
		definitions := root["$defs"].(map[string]any)
		provider := definitions["provider"].(map[string]any)
		properties := provider["properties"].(map[string]any)
		properties["application_compatible"] = map[string]any{"$ref": "#/$defs/cli_compatibility"}
		required := provider["required"].([]any)
		provider["required"] = append(required, "application_compatible")
		rootProperties := root["properties"].(map[string]any)
		config := rootProperties["config"].(map[string]any)
		var invalidConfig map[string]any
		for _, branch := range config["oneOf"].([]any) {
			candidate := branch.(map[string]any)
			candidateProperties := candidate["properties"].(map[string]any)
			status := candidateProperties["status"].(map[string]any)
			if status["const"] == "invalid" {
				invalidConfig = candidate
				break
			}
		}
		invalidProperties := invalidConfig["properties"].(map[string]any)
		reasonCodes := invalidProperties["reason_codes"].(map[string]any)
		prefixItems := reasonCodes["prefixItems"].([]any)
		reasonCode := prefixItems[0].(map[string]any)
		enum := reasonCode["enum"].([]any)
		reasonCode["enum"] = append(enum, "config_provider_retired")
		return
	}
	root := document.(map[string]any)
	providers := root["provider_inventory"].([]any)
	for _, item := range providers {
		provider := item.(map[string]any)
		compatibility := map[string]any{
			"status": "not_applicable", "observed_version": "", "eligibility": "not_evaluated", "compatibility": "not_observed",
			"minimum_version": "", "verified_latest": "", "reason_code": "",
		}
		if provider["family"] == "zcode" && provider["configured"] == true {
			provider["cli_compatible"] = map[string]any{
				"status": "verified", "observed_version": "0.16.5", "eligibility": "eligible", "compatibility": "verified",
				"minimum_version": "0.16.5", "verified_latest": "0.16.5", "reason_code": "provider_cli_version_supported",
			}
			compatibility = map[string]any{
				"status": "verified", "observed_version": "3.12.3", "eligibility": "eligible", "compatibility": "verified",
				"minimum_version": "3.12.3", "verified_latest": "3.12.3", "reason_code": "zcode_application_version_supported",
			}
			provider["reason"] = "zcode_application_version_supported"
		}
		provider["application_compatible"] = compatibility
	}
}

func transformPortfolio(value any, oldVersion, newVersion string, schema bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "kimi") || strings.Contains(lower, "agy") {
				continue
			}
			result[key] = transformPortfolio(child, oldVersion, newVersion, schema)
		}
		if schema {
			normalizePortfolioArrayBounds(result)
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		seenProviders := make(map[string]struct{})
		for _, child := range typed {
			if !schema && retiredProviderRecord(child) {
				continue
			}
			if text, ok := child.(string); ok && ((schema && (text == "kimi" || text == "agy")) || text == "agy_permission_mode") {
				continue
			}
			if schema && containsRetiredSchemaBranch(child) {
				continue
			}
			transformed := transformPortfolio(child, oldVersion, newVersion, schema)
			if !schema {
				if record, ok := transformed.(map[string]any); ok {
					if family, ok := record["family"].(string); ok {
						if _, duplicate := seenProviders[family]; duplicate {
							continue
						}
						seenProviders[family] = struct{}{}
					}
				}
			}
			result = append(result, transformed)
		}
		return result
	case string:
		result := strings.ReplaceAll(typed, oldVersion, newVersion)
		for old, next := range map[string]string{
			"mulgae-doctor-result.v4":              "mulgae-doctor-result.v5",
			"mulgae-provider-contract-evidence.v3": "mulgae-provider-contract-evidence.v4",
			"mulgae-provider-heartbeat-result.v2":  "mulgae-provider-heartbeat-result.v3",
			"mulgae-review-preflight.v4":           "mulgae-review-preflight.v5",
		} {
			result = strings.ReplaceAll(result, old, next)
		}
		result = strings.ReplaceAll(result, "(?:kimi|zcode|agy|grok|codex)", "(?:zcode|grok|codex)")
		if !schema {
			result = strings.ReplaceAll(result, "kimi", "zcode")
			result = strings.ReplaceAll(result, "agy", "grok")
		}
		return result
	default:
		return value
	}
}

func normalizePortfolioArrayBounds(value map[string]any) {
	if prefix, ok := value["prefixItems"].([]any); ok {
		if _, exists := value["minItems"]; exists {
			value["minItems"] = len(prefix)
		}
		if _, exists := value["maxItems"]; exists {
			value["maxItems"] = len(prefix)
		}
	}
	items, ok := value["items"].(map[string]any)
	if !ok {
		return
	}
	values, ok := items["enum"].([]any)
	if ok && len(values) > 0 {
		if _, exists := value["maxItems"]; exists {
			value["maxItems"] = len(values)
		}
	}
}

func retiredProviderRecord(value any) bool {
	record, ok := value.(map[string]any)
	if !ok {
		return false
	}
	family, ok := record["family"].(string)
	return ok && family == "agy"
}

func normalizeProviderEvidenceExample(value any) {
	document := value.(map[string]any)
	provider := document["provider"].(map[string]any)
	const zcodeArgvSHA256 = "724db2f4e04f01ca6240eae1f5a747ecaf9881696b18ad06cd98c53dd2f5458e"
	provider["wrapper_argv_sha256"] = zcodeArgvSHA256
	probeRunner := provider["probe_runner"].(map[string]any)
	probeRunner["argv_sha256"] = zcodeArgvSHA256
}

func containsRetiredSchemaBranch(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if reference, ok := typed["$ref"].(string); ok && (strings.Contains(reference, "kimi") || strings.Contains(reference, "agy")) {
			return true
		}
		if constant, ok := typed["const"].(string); ok && (constant == "kimi" || constant == "agy") {
			return true
		}
		for _, child := range typed {
			if containsRetiredSchemaBranch(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsRetiredSchemaBranch(child) {
				return true
			}
		}
	}
	return false
}

func writeGenerated(filename string, contents []byte) error {
	existing, err := os.ReadFile(filename)
	if err == nil && bytes.Equal(existing, contents) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".portfolio-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filename)
}

func publishCursorSelection(assets string) error {
	for _, name := range []string{
		"schemas/mulgae-provider-heartbeat-result.v3.schema.json",
		"schemas/mulgae-review-preflight.v8.schema.json",
	} {
		if err := addCursorFamilyEnum(filepath.Join(assets, name)); err != nil {
			return err
		}
	}
	if err := publishCursorCommandResult(assets); err != nil {
		return err
	}
	return publishCursorDoctorResult(assets)
}

func publishCursorDoctorResult(assets string) error {
	for _, item := range []struct{ source, target string }{
		{"schemas/mulgae-doctor-result.v5.schema.json", "schemas/mulgae-doctor-result.v6.schema.json"},
		{"examples/doctor-result.v5.valid.json", "examples/doctor-result.v6.valid.json"},
	} {
		contents, err := os.ReadFile(filepath.Join(assets, item.source))
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(contents, &document); err != nil {
			return err
		}
		rewriteDoctorVersion(document)
		widenDoctorInventory(document)
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		if err := writeGenerated(filepath.Join(assets, item.target), append(encoded, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func rewriteDoctorVersion(document any) {
	switch typed := document.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				text = strings.ReplaceAll(text, "mulgae-doctor-result.v5", "mulgae-doctor-result.v6")
				text = strings.ReplaceAll(text, "Doctor Result v5", "Doctor Result v6")
				typed[key] = text
				continue
			}
			rewriteDoctorVersion(child)
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				typed[index] = strings.ReplaceAll(text, "mulgae-doctor-result.v5", "mulgae-doctor-result.v6")
				continue
			}
			rewriteDoctorVersion(child)
		}
	}
}

func widenDoctorInventory(document any) {
	switch typed := document.(type) {
	case map[string]any:
		if definitions, ok := typed["$defs"].(map[string]any); ok {
			ensureCursorProviderDefinition(definitions)
			if inventory, ok := definitions["not_observed_inventory"].(map[string]any); ok {
				appendCursorNotObserved(inventory)
			}
		}
		extendProviderIDBranches(typed)
		if inventory, ok := typed["provider_inventory"].(map[string]any); ok {
			appendCursorProviderPrefix(inventory)
		}
		if rows, ok := typed["provider_inventory"].([]any); ok && len(rows) == 3 {
			encoded, err := json.Marshal(rows[1])
			if err == nil {
				var cursor map[string]any
				if json.Unmarshal(encoded, &cursor) == nil {
					cursor["family"] = "cursor"
					typed["provider_inventory"] = append(rows, cursor)
				}
			}
		}
		for _, child := range typed {
			widenDoctorInventory(child)
		}
	case []any:
		for _, child := range typed {
			widenDoctorInventory(child)
		}
	}
}

func ensureCursorProviderDefinition(definitions map[string]any) {
	if _, exists := definitions["provider_cursor"]; exists {
		return
	}
	grok, ok := definitions["provider_grok"]
	if !ok {
		return
	}
	encoded, err := json.Marshal(grok)
	if err != nil {
		return
	}
	var cursor map[string]any
	if json.Unmarshal(encoded, &cursor) != nil {
		return
	}
	renameProviderFamily(cursor, "cursor")
	definitions["provider_cursor"] = cursor
}

func renameProviderFamily(document map[string]any, family string) {
	allOf, _ := document["allOf"].([]any)
	for _, item := range allOf {
		branch, _ := item.(map[string]any)
		properties, _ := branch["properties"].(map[string]any)
		familyProperty, _ := properties["family"].(map[string]any)
		if familyProperty != nil && familyProperty["const"] != nil {
			familyProperty["const"] = family
		}
	}
}

func appendCursorNotObserved(inventory map[string]any) {
	prefix, ok := inventory["prefixItems"].([]any)
	if !ok || len(prefix) != 3 || inventoryFamily(prefix[0]) != "zcode" || inventoryFamily(prefix[1]) != "grok" || inventoryFamily(prefix[2]) != "codex" {
		return
	}
	encoded, err := json.Marshal(prefix[2])
	if err != nil {
		return
	}
	var cursor map[string]any
	if json.Unmarshal(encoded, &cursor) != nil {
		return
	}
	properties, _ := cursor["properties"].(map[string]any)
	family, _ := properties["family"].(map[string]any)
	if family == nil {
		return
	}
	family["const"] = "cursor"
	inventory["prefixItems"] = append(prefix, cursor)
	inventory["minItems"] = 4
	inventory["maxItems"] = 4
}

func inventoryFamily(item any) string {
	object, _ := item.(map[string]any)
	properties, _ := object["properties"].(map[string]any)
	family, _ := properties["family"].(map[string]any)
	value, _ := family["const"].(string)
	return value
}

func appendCursorProviderPrefix(inventory map[string]any) {
	prefix, ok := inventory["prefixItems"].([]any)
	if !ok || len(prefix) != 3 {
		return
	}
	refs := make([]string, 3)
	for index, item := range prefix {
		object, _ := item.(map[string]any)
		refs[index], _ = object["$ref"].(string)
	}
	if refs[0] != "#/$defs/provider_zcode" || refs[1] != "#/$defs/provider_grok" || refs[2] != "#/$defs/provider_codex" {
		return
	}
	inventory["prefixItems"] = append(prefix, map[string]any{"$ref": "#/$defs/provider_cursor"})
	inventory["minItems"] = 4
	inventory["maxItems"] = 4
}

func publishCursorCommandResult(assets string) error {
	for _, item := range []struct{ source, target string }{
		{"schemas/mulgae-command-result.v19.schema.json", "schemas/mulgae-command-result.v20.schema.json"},
		{"examples/command-result.v19.valid.json", "examples/command-result.v20.valid.json"},
	} {
		contents, err := os.ReadFile(filepath.Join(assets, item.source))
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(contents, &document); err != nil {
			return err
		}
		rewriteCursorVersionStrings(document)
		admitCursorCommandResult(document)
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		if err := writeGenerated(filepath.Join(assets, item.target), append(encoded, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func admitCursorCommandResult(document any) {
	switch typed := document.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "enum" {
				if values, ok := child.([]any); ok && stringList(values, "zcode", "grok", "codex") {
					typed[key] = []any{"zcode", "grok", "codex", "cursor"}
					continue
				}
			}
			admitCursorCommandResult(child)
		}
		if properties, ok := typed["properties"].(map[string]any); ok {
			if grok, exists := properties["grok_executable"]; exists {
				if _, present := properties["cursor_executable"]; !present {
					encoded, err := json.Marshal(grok)
					if err == nil {
						var cursor any
						if json.Unmarshal(encoded, &cursor) == nil {
							properties["cursor_executable"] = cursor
						}
					}
				}
			}
		}
		if definitions, ok := typed["$defs"].(map[string]any); ok {
			if _, exists := definitions["init_discovery_cursor"]; !exists {
				if codex, ok := definitions["init_discovery_codex"]; ok {
					encoded, _ := json.Marshal(codex)
					var cursor any
					if json.Unmarshal(encoded, &cursor) == nil {
						renameDiscoveryFamily(cursor, "cursor")
						definitions["init_discovery_cursor"] = cursor
					}
				}
			}
		}
		extendProviderIDBranches(typed)
		extendDiscoveryBranches(typed)
	case []any:
		for _, child := range typed {
			admitCursorCommandResult(child)
		}
	case string:
		return
	}
	rewriteCursorVersionStrings(document)
}

func rewriteCursorVersionStrings(document any) {
	switch typed := document.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				text = strings.ReplaceAll(text, "mulgae-command-result.v19", "mulgae-command-result.v20")
				text = strings.ReplaceAll(text, "Mulgae Command Result v19", "Mulgae Command Result v20")
				text = strings.ReplaceAll(text, "mulgae-doctor-result.v5", "mulgae-doctor-result.v6")
				typed[key] = text
				continue
			}
			rewriteCursorVersionStrings(child)
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				text = strings.ReplaceAll(text, "mulgae-command-result.v19", "mulgae-command-result.v20")
				text = strings.ReplaceAll(text, "mulgae-doctor-result.v5", "mulgae-doctor-result.v6")
				typed[index] = text
				continue
			}
			rewriteCursorVersionStrings(child)
		}
	}
}

func renameDiscoveryFamily(document any, family string) {
	object, ok := document.(map[string]any)
	if !ok {
		return
	}
	properties, _ := object["properties"].(map[string]any)
	familyProperty, _ := properties["family"].(map[string]any)
	if familyProperty != nil {
		familyProperty["const"] = family
	}
}

func extendProviderIDBranches(document any) {
	object, ok := document.(map[string]any)
	if !ok {
		return
	}
	definitions, _ := object["$defs"].(map[string]any)
	if definitions == nil {
		return
	}
	providerIDs, _ := definitions["canonical_provider_ids"].(map[string]any)
	if providerIDs == nil {
		return
	}
	families := []string{"zcode", "grok", "codex", "cursor"}
	branches := make([]any, 0, 1<<len(families))
	for mask := 0; mask < 1<<len(families); mask++ {
		selected := make([]any, 0, len(families))
		for index, family := range families {
			if mask&(1<<index) != 0 {
				selected = append(selected, map[string]any{"const": family})
			}
		}
		if len(selected) == 0 {
			branches = append(branches, map[string]any{"maxItems": 0})
			continue
		}
		branches = append(branches, map[string]any{"minItems": len(selected), "maxItems": len(selected), "prefixItems": selected, "items": false})
	}
	providerIDs["oneOf"] = branches
	providerIDs["type"] = "array"
}

func extendDiscoveryBranches(document any) {
	object, ok := document.(map[string]any)
	if !ok {
		return
	}
	definitions, _ := object["$defs"].(map[string]any)
	results, _ := definitions["results"].(map[string]any)
	initResult, _ := results["init"].(map[string]any)
	properties, _ := initResult["properties"].(map[string]any)
	discovery, _ := properties["discovery"].(map[string]any)
	if discovery == nil {
		return
	}
	discovery["oneOf"] = []any{
		map[string]any{"maxItems": 0},
		map[string]any{"minItems": 4, "maxItems": 4, "items": false, "prefixItems": []any{
			map[string]any{"$ref": "#/$defs/init_discovery_zcode"},
			map[string]any{"$ref": "#/$defs/init_discovery_grok"},
			map[string]any{"$ref": "#/$defs/init_discovery_codex"},
			map[string]any{"$ref": "#/$defs/init_discovery_cursor"},
		}},
	}
	discovery["type"] = "array"
}

func addCursorFamilyEnum(filename string) error {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var document any
	if err := json.Unmarshal(contents, &document); err != nil {
		return err
	}
	admitCursorEnum(document)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return writeGenerated(filename, append(encoded, '\n'))
}

func admitCursorEnum(document any) {
	switch typed := document.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "enum" {
				if values, ok := child.([]any); ok && stringList(values, "zcode", "grok", "codex") {
					typed[key] = []any{"zcode", "grok", "codex", "cursor"}
				}
			}
			admitCursorEnum(child)
		}
	case []any:
		for _, child := range typed {
			admitCursorEnum(child)
		}
	}
}

func stringList(values []any, expected ...string) bool {
	if len(values) != len(expected) {
		return false
	}
	for index, value := range values {
		text, ok := value.(string)
		if !ok || text != expected[index] {
			return false
		}
	}
	return true
}
