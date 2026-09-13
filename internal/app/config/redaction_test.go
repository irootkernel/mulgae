package config_test

import (
	"encoding/json"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"strings"
	"testing"
)

func TestRedactionOmitsExecutableAndNativePaths(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"zcode"})
	raw := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Providers: adapterconfig.ProvidersConfig{ZCode: &adapterconfig.ZCodeProviderConfig{NodeExecutable: "/secret/bin", Launcher: "/secret/launcher"}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}}, Resources: adapterconfig.ResourcesConfig{RoleMaxInvocations: 2, RunMaxInvocations: 12}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(appconfig.Redact(resolved))
	if strings.Contains(string(data), "/secret/") {
		t.Fatalf("redaction leaked: %s", data)
	}
	if !strings.Contains(string(data), `"primary_provider":"zcode"`) {
		t.Fatalf("redaction omitted role assignments: %s", data)
	}
	if strings.Contains(string(data), "fallback") {
		t.Fatalf("redaction still projects a fallback route: %s", data)
	}
}

// Extraction changes what a run may spend its second invocation on, so an
// operator must be able to see the admitted policy in `mulgae config`.
func TestRedactionProjectsStructuredExtractionPolicy(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"zcode"})
	for _, enabled := range []bool{true, false} {
		raw := adapterconfig.Config{
			Version: adapterconfig.ConfigVersion,
			Providers: adapterconfig.ProvidersConfig{
				ZCode: &adapterconfig.ZCodeProviderConfig{NodeExecutable: "/bin/node", Launcher: "/app/zcode.cjs"},
			},
			Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"},
			Roles:     roles,
			Review:    adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}},
			Validation: adapterconfig.ValidationConfig{
				Extraction: adapterconfig.ExtractionConfig{Enabled: enabled},
			},
			Resources: adapterconfig.ResourcesConfig{RoleMaxInvocations: 2, RunMaxInvocations: 12},
		}
		resolved, err := appconfig.ResolveConfiguration(raw)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.ExtractionEnabled() != enabled {
			t.Fatalf("ExtractionEnabled() = %t, want %t", resolved.ExtractionEnabled(), enabled)
		}
		data, _ := json.Marshal(appconfig.Redact(resolved))
		want := `"extraction_enabled":false`
		if enabled {
			want = `"extraction_enabled":true`
		}
		if !strings.Contains(string(data), want) {
			t.Fatalf("redaction omitted %s: %s", want, data)
		}
	}
}
