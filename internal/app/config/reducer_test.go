package config_test

import (
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestResolveConfigurationProjectsFixedPolicy(t *testing.T) {
	roles, _ := appconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"agy"})
	raw := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, RoleMaxInvocations: 2, RunMaxInvocations: 12}, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1}}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	logic, present := resolved.Role(domain.RoleLogic)
	if resolved.Runtime().MaxActiveLanes != 3 || len(resolved.RequiredRoles()) != 2 || !present || logic.PrimaryProvider() != "agy" {
		t.Fatalf("resolved=%#v", resolved)
	}
}

func TestResolveConfigurationProjectsEffectiveProviderTimeouts(t *testing.T) {
	raw := adapterconfig.Config{
		Providers: adapterconfig.ProvidersConfig{
			ZCode: &adapterconfig.ZCodeProviderConfig{Timeout: "30m"},
			AGY:   &adapterconfig.AGYProviderConfig{},
		},
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

func TestRedactedPolicyReportsAGYHeadlessModeAndSafeWarning(t *testing.T) {
	for _, test := range []struct {
		name         string
		mode         string
		wantWarnings int
	}{
		{name: "safe default", mode: appconfig.DefaultAGYPermissionMode},
		{name: "headless opt-in", mode: appconfig.HeadlessAGYPermissionMode, wantWarnings: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := appconfig.ResolveConfiguration(adapterconfig.Config{
				Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{PermissionMode: test.mode}},
			})
			if err != nil {
				t.Fatal(err)
			}
			policy := resolved.Redacted().Policy
			if policy.AGYPermissionMode != test.mode || len(policy.Warnings) != test.wantWarnings {
				t.Fatalf("effective AGY policy = mode %q warnings %#v", policy.AGYPermissionMode, policy.Warnings)
			}
			if test.wantWarnings != 0 && !strings.Contains(policy.Warnings[0], "dangerously-skip-permissions is opt-in") {
				t.Fatalf("headless warning = %q", policy.Warnings[0])
			}
		})
	}
}
