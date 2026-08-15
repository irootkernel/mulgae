package config_test

import (
	"context"
	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/ports"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestServiceResolvesCanonicalConfigV2Pair(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin source")
	}
	rootPath := t.TempDir()
	_ = os.Chmod(rootPath, 0o700)
	_ = os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700)
	roles, _ := adapterconfig.CanonicalRolesConfig(testRoleDefaults(), []string{"agy"})
	config := adapterconfig.Config{Version: adapterconfig.ConfigVersion, Project: adapterconfig.ProjectConfig{Name: "project"}, NativeUser: adapterconfig.NativeUserConfig{Home: "/Users/test"}, Providers: adapterconfig.ProvidersConfig{AGY: &adapterconfig.AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "safe", PermissionModeExplicit: true}}, Execution: adapterconfig.ExecutionConfig{WorkspaceAccess: "none"}, Roles: roles, Review: adapterconfig.ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}}, Validation: adapterconfig.ValidationConfig{Evidence: adapterconfig.EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: adapterconfig.RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}}, Resources: adapterconfig.ResourcesConfig{MaxActiveLanes: 3, PrimaryRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 12}, CI: adapterconfig.CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true}}
	projectData, localData, err := adapterconfig.EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), projectData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), localData, 0o600); err != nil {
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
	permissionProvenance := appconfig.ProvenanceRow{}
	for _, row := range resolution.Provenance() {
		if row.Field == "providers.agy.permission_mode" {
			permissionProvenance = row
			break
		}
	}
	if permissionProvenance.Source != "project" || permissionProvenance.Disposition != "configured" {
		t.Fatalf("safe permission provenance = %#v", permissionProvenance)
	}
	policy := resolution.Config().Redacted().Policy
	if policy.AGYPermissionMode != appconfig.SafeAGYPermissionMode || len(policy.Warnings) != 0 {
		t.Fatalf("safe effective policy = %#v", policy)
	}
	configPath := filepath.Join(rootPath, ".mulgae", "local.yaml")
	if err := os.Rename(configPath, configPath+".original"); err != nil {
		t.Fatal(err)
	}
	replacement := config
	replacement.NativeUser.Home = "/Users/replacement"
	_, replacementData, err := adapterconfig.EncodeSplit(replacement)
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

func TestBundleSHA256BindsAuthorityOrderAndBoundaries(t *testing.T) {
	baseline := appconfig.BundleSHA256([]byte("ab"), []byte("c"))
	for name, candidate := range map[string]string{
		"boundary": appconfig.BundleSHA256([]byte("a"), []byte("bc")),
		"order":    appconfig.BundleSHA256([]byte("c"), []byte("ab")),
	} {
		if candidate == baseline {
			t.Fatalf("%s did not change bundle identity", name)
		}
	}
}
