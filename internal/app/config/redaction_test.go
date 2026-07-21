package config_test

import (
	"encoding/json"
	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"strings"
	"testing"
)

func TestRedactionOmitsExecutableAndNativePaths(t *testing.T) {
	raw := adapterconfig.Config{Providers: adapterconfig.ProvidersConfig{Kimi: &adapterconfig.KimiProviderConfig{Executable: "/secret/bin", DataHome: "/secret/home"}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}}, Resources: adapterconfig.ResourcesConfig{RoleMaxInvocations: 2, RunMaxInvocations: 12, RunTotalOutputCap: "64MiB"}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(appconfig.Redact(resolved))
	if strings.Contains(string(data), "/secret/") {
		t.Fatalf("redaction leaked: %s", data)
	}
}
