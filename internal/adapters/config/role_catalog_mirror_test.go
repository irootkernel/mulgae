package config

import (
	"bytes"
	"testing"
)

// TestRoleCatalogDefaultsSurviveThisPackagesValidator binds the safe-path rules
// duplicated in internal/roles to the ones enforced here. If the two drift, init
// would generate a configuration its own decoder rejects, and the failure would
// surface far from the cause.
func TestRoleCatalogDefaultsSurviveThisPackagesValidator(t *testing.T) {
	t.Parallel()

	config := validConfig()
	config.Project.Kind = ProjectKindUI
	config.Providers = ProvidersConfig{
		ZCode: &ZCodeProviderConfig{NodeExecutable: "/usr/local/bin/node", Launcher: "/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"},
		AGY:   &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: DefaultAGYPermissionMode},
	}
	roles, err := CanonicalRolesConfigForUI(testRoleDefaults(), config.Providers.Families())
	if err != nil {
		t.Fatalf("canonical UI roles: %v", err)
	}
	config.Roles = roles
	config.Resources.MaxActiveLanes = 7
	config.Resources.RunMaxInvocations = 28
	config.Resources.RoleMaxInvocations = 4

	canonical, err := EncodeCanonical(config)
	if err != nil {
		t.Fatalf("encode catalog-derived config: %v", err)
	}
	decoded, err := Decode(canonical)
	if err != nil {
		t.Fatalf("decode catalog-derived config: %v", err)
	}
	again, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatalf("re-encode catalog-derived config: %v", err)
	}
	if !bytes.Equal(canonical, again) {
		t.Fatalf("catalog-derived config is not canonical:\n%s\n---\n%s", canonical, again)
	}
	if decoded.Roles.Artist.Inputs == nil || decoded.Roles.Artist.Inputs.TaskPath == "" {
		t.Fatalf("artist inputs did not survive the round trip: %#v", decoded.Roles.Artist.Inputs)
	}
	if len(decoded.Roles.Artist.Inputs.DesignSpecGlobs) == 0 {
		t.Fatal("artist design spec globs did not survive the round trip")
	}
}
