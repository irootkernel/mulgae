package config_test

import (
	"context"
	adapterconfig "github.com/irootkernel/kkachi-agent-review/internal/adapters/config"
	appconfig "github.com/irootkernel/kkachi-agent-review/internal/app/config"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestServiceResolvesSoleCanonicalLocalSource(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin source")
	}
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	_ = os.Mkdir(filepath.Join(rootPath, ".kar"), 0o700)
	roles, _ := adapterconfig.CanonicalRolesConfig([]string{"agy"})
	config := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Project: adapterconfig.ProjectConfig{Name: "project"}, NativeUser: adapterconfig.NativeUserConfig{Home: "/Users/test"}, Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "safe"}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}}, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, PrimaryRepairAttempts: 1, FallbackRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 12, RunTotalOutputCap: "64MiB"}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	data, err := adapterconfig.EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".kar", "config.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	root, _ := ports.NewAnchoredRoot(rootPath)
	source, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := appconfig.NewService(adapterconfig.YAMLCodec{}).Resolve(context.Background(), appconfig.ResolveRequest{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.URI() != adapterconfig.ConfigRelativePath || resolution.SHA256() == "" || len(resolution.Provenance()) < 40 {
		t.Fatalf("resolution=%#v", resolution)
	}
	configPath := filepath.Join(rootPath, ".kar", "config.yaml")
	if err := os.Rename(configPath, configPath+".original"); err != nil {
		t.Fatal(err)
	}
	replacement := config
	replacement.Project.Name = "replacement"
	replacementData, err := adapterconfig.EncodeCanonical(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, replacementData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := appconfig.NewService(adapterconfig.YAMLCodec{}).Resolve(context.Background(), appconfig.ResolveRequest{Source: source}); err == nil {
		t.Fatal("resolution reopened and admitted a replacement config instead of rejecting source drift")
	}
}
