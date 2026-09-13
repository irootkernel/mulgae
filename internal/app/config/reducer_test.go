package config_test

import (
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
	"testing"
	"time"
)

func TestResolveConfigurationProjectsFixedPolicy(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"grok"})
	raw := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Providers: adapterconfig.ProvidersConfig{Grok: &adapterconfig.GrokProviderConfig{}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, RoleMaxInvocations: 2, RunMaxInvocations: 12}, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1}}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	logic, present := resolved.Role(domain.RoleLogic)
	if resolved.Runtime().MaxActiveLanes != 3 || len(resolved.RequiredRoles()) != 2 || !present || logic.PrimaryProvider() != "grok" {
		t.Fatalf("resolved=%#v", resolved)
	}
}

func TestResolveConfigurationProjectsEffectiveProviderTimeouts(t *testing.T) {
	raw := adapterconfig.Config{
		Providers: adapterconfig.ProvidersConfig{
			ZCode: &adapterconfig.ZCodeProviderConfig{Timeout: "30m"},
			Grok:  &adapterconfig.GrokProviderConfig{},
		},
	}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if timeout, ok := resolved.ProviderTimeout("zcode"); !ok || timeout != 30*time.Minute {
		t.Fatalf("zcode timeout = %s, %v", timeout, ok)
	}
	if timeout, ok := resolved.ProviderTimeout("grok"); !ok || timeout != appconfig.DefaultProviderTimeout {
		t.Fatalf("grok timeout = %s, %v", timeout, ok)
	}
	if _, ok := resolved.ProviderTimeout("codex"); ok {
		t.Fatal("absent provider gained a timeout")
	}
	redacted := resolved.Redacted()
	if got := redacted.Policy.ProviderTimeouts; len(got) != 2 || got[0].Family != "zcode" || got[0].Timeout != "30m" || got[1].Family != "grok" || got[1].Timeout != "60m" {
		t.Fatalf("redacted provider timeouts = %#v", got)
	}
}
