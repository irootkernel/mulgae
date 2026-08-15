package config_test

import (
	"encoding/json"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"strings"
	"testing"
)

func TestRedactionOmitsExecutableAndNativePaths(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"kimi"})
	raw := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Providers: adapterconfig.ProvidersConfig{Kimi: &adapterconfig.KimiProviderConfig{Executable: "/secret/bin", DataHome: "/secret/home"}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}}, Resources: adapterconfig.ResourcesConfig{RoleMaxInvocations: 2, RunMaxInvocations: 12}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(appconfig.Redact(resolved))
	if strings.Contains(string(data), "/secret/") {
		t.Fatalf("redaction leaked: %s", data)
	}
	if !strings.Contains(string(data), `"primary_provider":"kimi"`) {
		t.Fatalf("redaction omitted role assignments: %s", data)
	}
	if strings.Contains(string(data), "fallback") {
		t.Fatalf("redaction still projects a fallback route: %s", data)
	}
}
