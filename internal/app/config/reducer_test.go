package config_test

import (
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
	"testing"
	"time"
)

func TestResolveConfigurationProjectsFixedPolicy(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig([]string{"agy"})
	raw := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, RoleMaxInvocations: 2, RunMaxInvocations: 12, RunTotalOutputCap: "64MiB"}, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1}}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	logic, present := resolved.Role(domain.RoleLogic)
	if resolved.Runtime().MaxActiveLanes != 3 || resolved.RunTotalOutputCapBytes() != 64<<20 || len(resolved.RequiredRoles()) != 2 || !present || logic.PrimaryProvider() != "agy" {
		t.Fatalf("resolved=%#v", resolved)
	}
}

func TestResolveConfigurationProjectsEffectiveProviderTimeouts(t *testing.T) {
	raw := adapterconfig.Config{
		Providers: adapterconfig.ProvidersConfig{
			ZCode: &adapterconfig.ZCodeProviderConfig{Timeout: "30m"},
			AGY:   &adapterconfig.AGYProviderConfig{},
		},
		Resources: adapterconfig.ResourcesConfig{RunTotalOutputCap: "64MiB"},
	}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if timeout, ok := resolved.ProviderTimeout("zcode"); !ok || timeout != 30*time.Minute {
		t.Fatalf("zcode timeout = %s, %v", timeout, ok)
	}
	if timeout, ok := resolved.ProviderTimeout("agy"); !ok || timeout != appconfig.DefaultProviderTimeout {
		t.Fatalf("agy timeout = %s, %v", timeout, ok)
	}
	if _, ok := resolved.ProviderTimeout("kimi"); ok {
		t.Fatal("absent provider gained a timeout")
	}
	redacted := resolved.Redacted()
	if got := redacted.Policy.ProviderTimeouts; len(got) != 2 || got[0].Family != "zcode" || got[0].Timeout != "30m" || got[1].Family != "agy" || got[1].Timeout != "15m" {
		t.Fatalf("redacted provider timeouts = %#v", got)
	}
}
