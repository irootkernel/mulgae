package config

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigV2SplitKeepsMachinePathsOutOfProjectPolicy(t *testing.T) {
	config := validConfig()
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.NativeUser.Home, config.Providers.Kimi.Executable, config.Providers.Kimi.DataHome} {
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

func TestConfigV2SplitRejectsLegacyAndProviderSetMismatch(t *testing.T) {
	project, local, err := EncodeSplit(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(strings.Replace(string(project), "version: 2", "version: 1", 1))
	if _, err := DecodeSplit(legacy, local); err == nil {
		t.Fatal("Config v1 was accepted")
	}
	mismatchConfig := validConfig()
	mismatchConfig.Providers.Kimi = nil
	mismatchConfig.Providers.AGY = &AGYProviderConfig{Executable: "/bin/agy"}
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
	for _, forbidden := range []string{"native_user:", "executable:", "node_executable:", "launcher:", "data_home:", "fallback_repair_attempts:"} {
		if bytes.Contains(project, []byte(forbidden)) {
			t.Fatalf("repository project config contains machine-local field %q", forbidden)
		}
	}
	local := []byte("version: 2\nnative_user:\n  home: \"/Users/test\"\nproviders:\n  zcode:\n    node_executable: \"/usr/bin/node\"\n    launcher: \"/opt/mulgae/zcode.cjs\"\n")
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
