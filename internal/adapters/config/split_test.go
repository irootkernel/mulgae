package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

func TestConfigV4SplitKeepsGrokExecutableMachineLocalAndTimeoutShared(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{Grok: &GrokProviderConfig{Executable: "/opt/grok/bin/grok", Timeout: "25m"}}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(project, []byte(config.Providers.Grok.Executable)) || !bytes.Contains(project, []byte(`timeout: "25m"`)) {
		t.Fatalf("Grok project policy authority is invalid:\n%s", project)
	}
	if !bytes.Contains(local, []byte(`executable: "/opt/grok/bin/grok"`)) || bytes.Contains(local, []byte("timeout:")) {
		t.Fatalf("Grok machine-path authority is invalid:\n%s", local)
	}
	decoded, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Grok == nil || decoded.Providers.Grok.Executable != config.Providers.Grok.Executable || decoded.Providers.Grok.Timeout != "25m" {
		t.Fatalf("Grok split round trip = %#v", decoded.Providers.Grok)
	}
}

func TestConfigV4SplitRejectsLegacyAndProviderSetMismatch(t *testing.T) {
	project, local, err := EncodeSplit(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(strings.Replace(string(project), "version: 4", "version: 3", 1))
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

func TestRepositoryProjectConfigIsCanonicalSharedPolicy(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", ".mulgae", "config.yaml")
	project, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"native_user:", "app_bundle:", "executable:", "node_executable:", "launcher:", "data_home:", "fallback_repair_attempts:"} {
		if bytes.Contains(project, []byte(forbidden)) {
			t.Fatalf("repository project config contains machine-local field %q", forbidden)
		}
	}
	local := []byte("version: 4\nnative_user:\n  home: \"/Users/test\"\nproviders:\n  zcode:\n    app_bundle: \"/Applications/ZCode.app\"\n  grok:\n    executable: \"/usr/bin/grok\"\n")
	config, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatalf("decode repository project config: %v", err)
	}
	canonical, _, err := EncodeSplit(config)
	if err != nil {
		t.Fatalf("encode repository project config: %v", err)
	}
	if !bytes.Equal(project, canonical) {
		t.Fatalf("repository project config is not canonical:\n%s", canonical)
	}
}
