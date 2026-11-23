//go:build darwin && arm64 && vm_qualification

package e2e

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
)

// vmConfigureAndCapturePriorPolicy verifies customized old-CLI configuration
// before candidate upgrade.
func vmConfigureAndCapturePriorPolicy(t *testing.T, oldBinary, project string, environment []string) map[string]any {
	t.Helper()

	config := readE2EConfig(t, project)
	if config.Providers.ZCode == nil || config.Providers.ZCode.AppBundle == "" {
		t.Fatalf("old init configuration omitted ZCode app bundle: %#v", config.Providers)
	}
	if !config.Roles.Logic.Enabled || config.Roles.Logic.PrimaryProvider != "zcode" ||
		!config.Roles.Security.Enabled || config.Roles.Security.PrimaryProvider != "zcode" {
		t.Fatalf("old init configuration did not preserve active ZCode logic/security routes: %#v", config.Roles)
	}
	if config.Roles.Documentation.Enabled {
		t.Fatalf("old init configuration unexpectedly enabled documentation role: %#v", config.Roles.Documentation)
	}

	grokExecutable := filepath.Join(config.Providers.ZCode.AppBundle, "Contents", "MacOS", "ZCode")

	config.Providers.ZCode.Timeout = "7m"
	config.Providers.Grok = &adapterconfig.GrokProviderConfig{
		Executable: grokExecutable,
		Timeout:    "9m",
	}
	config.Roles.Documentation.PrimaryProvider = "grok"

	shared, private, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatalf("encode customized Config v5 split pair: %v", err)
	}
	for name, data := range map[string][]byte{"config.yaml": shared, "local.yaml": private} {
		if err := os.WriteFile(filepath.Join(project, ".mulgae", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	materialBefore := vmConfigMaterial(t, project)

	effectiveEnvelope := vmCLI(t, oldBinary, project, environment, 0, "config", "--mode", "effective")
	effectiveResult, ok := effectiveEnvelope["result"].(map[string]any)
	if !ok {
		t.Fatalf("old effective config omitted result object: %#v", effectiveEnvelope)
	}
	vmAssertPriorEffectivePolicy(t, effectiveResult)

	provenanceEnvelope := vmCLI(t, oldBinary, project, environment, 0, "config", "--mode", "provenance")
	provenanceResult, ok := provenanceEnvelope["result"].(map[string]any)
	if !ok {
		t.Fatalf("old provenance config omitted result object: %#v", provenanceEnvelope)
	}
	if provenanceResult["config_sha256"] != effectiveResult["config_sha256"] {
		t.Fatalf("old config_sha256 mismatch between effective (%v) and provenance (%v)", effectiveResult["config_sha256"], provenanceResult["config_sha256"])
	}

	materialAfter := vmConfigMaterial(t, project)
	if !reflect.DeepEqual(materialBefore, materialAfter) {
		t.Fatal("old config inspection mutated Config v5 files or modes")
	}

	return map[string]any{
		"config.yaml":   materialAfter["config.yaml"],
		"local.yaml":    materialAfter["local.yaml"],
		"material":      materialAfter,
		"config_sha256": effectiveResult["config_sha256"],
		"effective":     effectiveResult,
		"provenance":    provenanceResult,
	}
}

func vmAssertPriorEffectivePolicy(t *testing.T, result map[string]any) {
	t.Helper()

	if result["kind"] != "configuration_resolved" || result["mode"] != "effective" {
		t.Fatalf("unexpected old config resolution header: %#v", result)
	}
	redacted, ok := result["policy"].(map[string]any)
	if !ok {
		t.Fatalf("old effective config omitted redacted policy: %#v", result)
	}
	wantProviders := []any{"zcode", "grok"}
	if !reflect.DeepEqual(redacted["configured_provider_ids"], wantProviders) {
		t.Fatalf("old configured_provider_ids = %#v, want %#v", redacted["configured_provider_ids"], wantProviders)
	}
	policy, ok := redacted["policy"].(map[string]any)
	if !ok {
		t.Fatalf("old effective config omitted inner policy block: %#v", redacted)
	}
	wantTimeouts := []any{
		map[string]any{"family": "zcode", "timeout": "7m"},
		map[string]any{"family": "grok", "timeout": "9m"},
	}
	if !reflect.DeepEqual(policy["provider_timeouts"], wantTimeouts) {
		t.Fatalf("old provider_timeouts = %#v, want %#v", policy["provider_timeouts"], wantTimeouts)
	}
	assignments, ok := policy["role_assignments"].([]any)
	if !ok {
		t.Fatalf("old role_assignments omitted: %#v", policy)
	}
	seen := map[string]map[string]any{}
	for _, raw := range assignments {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("invalid role assignment entry: %#v", raw)
		}
		role, _ := row["role"].(string)
		seen[role] = row
	}
	for _, role := range []string{"logic", "security"} {
		row, ok := seen[role]
		if !ok || row["primary_provider"] != "zcode" {
			t.Fatalf("old %s role route = %#v, want primary_provider=zcode", role, row)
		}
	}
	doc, ok := seen["documentation"]
	if !ok || doc["primary_provider"] != "grok" {
		t.Fatalf("old documentation role route = %#v, want primary_provider=grok", doc)
	}
}
