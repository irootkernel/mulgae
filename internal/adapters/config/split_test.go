package config

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestConfigV4SplitKeepsMachinePathsOutOfProjectPolicy(t *testing.T) {
	config := validConfig()
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.NativeUser.Home, config.Providers.ZCode.AppBundle} {
		if bytes.Contains(project, []byte(forbidden)) {
			t.Fatalf("project config contains machine-local value %q", forbidden)
		}
	}
	for _, forbidden := range []string{"roles:", "validation:", "resources:", "ci:"} {
		if bytes.Contains(local, []byte(forbidden)) {
			t.Fatalf("local config contains project policy %q", forbidden)
		}
	}
	decoded, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NativeUser.Home != config.NativeUser.Home || decoded.Roles.Logic != config.Roles.Logic {
		t.Fatalf("split round trip = %#v", decoded)
	}
}

func TestConfigV4SplitKeepsGrokExecutableMachineLocalAndPolicyShared(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{Grok: &GrokProviderConfig{Executable: "/opt/grok/bin/grok", Model: "grok-4.5", ReasoningEffort: "high-precision", Timeout: "25m"}}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(project, []byte(config.Providers.Grok.Executable)) || !bytes.Contains(project, []byte(`model: "grok-4.5"`)) || !bytes.Contains(project, []byte(`reasoning_effort: "high-precision"`)) || !bytes.Contains(project, []byte(`timeout: "25m"`)) {
		t.Fatalf("Grok project policy authority is invalid:\n%s", project)
	}
	if !bytes.Contains(local, []byte(`executable: "/opt/grok/bin/grok"`)) || bytes.Contains(local, []byte("model:")) || bytes.Contains(local, []byte("reasoning_effort:")) || bytes.Contains(local, []byte("timeout:")) {
		t.Fatalf("Grok machine-path authority is invalid:\n%s", local)
	}
	decoded, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Grok == nil || decoded.Providers.Grok.Executable != config.Providers.Grok.Executable || decoded.Providers.Grok.Model != "grok-4.5" || decoded.Providers.Grok.ReasoningEffort != "high-precision" || decoded.Providers.Grok.Timeout != "25m" {
		t.Fatalf("Grok split round trip = %#v", decoded.Providers.Grok)
	}
}

func TestConfigV4SplitRejectsGrokPolicyInMachineAuthority(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{Grok: &GrokProviderConfig{Executable: "/opt/grok/bin/grok"}}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"model: grok-4.5\n", "reasoning_effort: high\n"} {
		candidate := bytes.Replace(local, []byte("  grok:\n    executable: "), []byte("  grok:\n    "+field+"    executable: "), 1)
		if _, err := DecodeSplit(project, candidate); err == nil {
			t.Fatalf("machine-local Grok policy %q was accepted", field)
		}
	}
}

func TestConfigV4SplitRejectsLegacyAndProviderSetMismatch(t *testing.T) {
	project, local, err := EncodeSplit(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(strings.Replace(string(project), "version: 5", "version: 3", 1))
	if _, err := DecodeSplit(legacy, local); err == nil {
		t.Fatal("Config v1 was accepted")
	}
	mismatchConfig := validConfig()
	mismatchConfig.Providers.ZCode = nil
	mismatchConfig.Providers.Grok = &GrokProviderConfig{Executable: "/bin/grok"}
	mismatch := encodeMachineConfig(mismatchConfig)
	if _, err := DecodeSplit(project, mismatch); err == nil {
		t.Fatal("provider mismatch was accepted")
	}
}

func TestCanonicalProjectExampleIsSharedPolicy(t *testing.T) {
	id, err := ports.ParseAssetID("example:project-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, project, err := builtin.NewCatalog().Read(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"native_user:", "app_bundle:", "executable:", "node_executable:", "launcher:", "data_home:", "fallback_repair_attempts:"} {
		if bytes.Contains(project, []byte(forbidden)) {
			t.Fatalf("project example contains machine-local field %q", forbidden)
		}
	}
	local := []byte("version: 5\nnative_user:\n  home: \"/Users/test\"\nproviders:\n  zcode:\n    app_bundle: \"/Applications/ZCode.app\"\n")
	config, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatalf("decode project example: %v", err)
	}
	canonical, _, err := EncodeSplit(config)
	if err != nil {
		t.Fatalf("encode project example: %v", err)
	}
	if !bytes.Equal(project, canonical) {
		t.Fatalf("project example is not canonical:\n%s", canonical)
	}
}
