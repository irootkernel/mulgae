package config_test

import (
	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"testing"
)

func TestResolveConfigurationProjectsFixedPolicy(t *testing.T) {
	raw := adapterconfig.Config{Version: 1, Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, RoleMaxInvocations: 2, RunMaxInvocations: 12, RunTotalOutputCap: "64MiB"}, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1}}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	resolved, err := appconfig.ResolveConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Runtime().MaxActiveLanes != 3 || resolved.RunTotalOutputCapBytes() != 64<<20 || len(resolved.RequiredRoles()) != 2 {
		t.Fatalf("resolved=%#v", resolved)
	}
}
