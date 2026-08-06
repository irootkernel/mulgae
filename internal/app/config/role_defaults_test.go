package config_test

import (
	"testing"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/domain"
)

// syntheticDefaults builds a complete default set, then applies per-role
// overrides so each test varies exactly one thing. The orders here are
// deliberately not the shipped ones: they exist to prove the derivation follows
// whatever it is handed.
func syntheticDefaults(t *testing.T, overrides map[domain.Role]appconfig.RoleDefault) appconfig.RoleDefaults {
	t.Helper()
	entries := map[domain.Role]appconfig.RoleDefault{}
	for _, role := range domain.CoreRoleOrder() {
		entries[role] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "zcode", "agy"}}
	}
	entries[domain.RoleArtist] = appconfig.RoleDefault{
		ProviderPreferences:   []string{"agy", "zcode"},
		ArtistTaskPath:        "brief.md",
		ArtistDesignSpecGlobs: []string{"specs/**/*.png"},
	}
	for role, override := range overrides {
		entries[role] = override
	}
	defaults, err := appconfig.NewRoleDefaults(entries)
	if err != nil {
		t.Fatalf("build synthetic defaults: %v", err)
	}
	return defaults
}

func TestNewRoleDefaultsRejectsIncompleteOrInvalidEntries(t *testing.T) {
	t.Parallel()

	complete := func() map[domain.Role]appconfig.RoleDefault {
		entries := map[domain.Role]appconfig.RoleDefault{}
		for _, role := range domain.CoreRoleOrder() {
			entries[role] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "zcode", "agy"}}
		}
		entries[domain.RoleArtist] = appconfig.RoleDefault{
			ProviderPreferences:   []string{"agy", "zcode"},
			ArtistTaskPath:        "brief.md",
			ArtistDesignSpecGlobs: []string{"specs/**/*.png"},
		}
		return entries
	}
	for name, mutate := range map[string]func(map[domain.Role]appconfig.RoleDefault){
		"missing role": func(e map[domain.Role]appconfig.RoleDefault) { delete(e, domain.RoleTesting) },
		"unknown role": func(e map[domain.Role]appconfig.RoleDefault) { e[domain.Role("reviewer")] = e[domain.RoleLogic] },
		"core role missing family": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "zcode"}}
		},
		"core role duplicate family": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "kimi", "agy"}}
		},
		"core role with artist inputs": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "zcode", "agy"}, ArtistTaskPath: "brief.md"}
		},
		"artist with kimi": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"kimi", "agy"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist without task path": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"agy", "zcode"}, ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist without globs": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"agy", "zcode"}, ArtistTaskPath: "brief.md"}
		},
		"artist with too many globs": func(e map[domain.Role]appconfig.RoleDefault) {
			globs := make([]string, 0, 17)
			for index := 0; index < 17; index++ {
				globs = append(globs, "specs/"+string(rune('a'+index))+".png")
			}
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"agy", "zcode"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: globs}
		},
	} {
		t.Run(name, func(t *testing.T) {
			entries := complete()
			mutate(entries)
			if _, err := appconfig.NewRoleDefaults(entries); err == nil {
				t.Fatal("NewRoleDefaults succeeded, want rejection")
			}
		})
	}
}

func TestNewRoleDefaultsDeepCopiesEntries(t *testing.T) {
	t.Parallel()

	preferences := []string{"kimi", "zcode", "agy"}
	entries := map[domain.Role]appconfig.RoleDefault{}
	for _, role := range domain.CoreRoleOrder() {
		entries[role] = appconfig.RoleDefault{ProviderPreferences: preferences}
	}
	entries[domain.RoleArtist] = appconfig.RoleDefault{
		ProviderPreferences:   []string{"agy", "zcode"},
		ArtistTaskPath:        "brief.md",
		ArtistDesignSpecGlobs: []string{"specs/**/*.png"},
	}
	defaults, err := appconfig.NewRoleDefaults(entries)
	if err != nil {
		t.Fatalf("build defaults: %v", err)
	}
	preferences[0] = "mutated"
	delete(entries, domain.RoleLogic)
	logic, exists := defaults.Role(domain.RoleLogic)
	if !exists || logic.ProviderPreferences[0] != "kimi" {
		t.Fatalf("logic preferences = %v (present=%t), want an unmutated copy", logic.ProviderPreferences, exists)
	}
	logic.ProviderPreferences[0] = "mutated"
	again, _ := defaults.Role(domain.RoleLogic)
	if again.ProviderPreferences[0] != "kimi" {
		t.Fatalf("Role returned aliased state: %v", again.ProviderPreferences)
	}
}

// TestCanonicalRolesConfigFollowsSuppliedPreferenceOrder fails if any hardcoded
// preference order survives in Go.
func TestCanonicalRolesConfigFollowsSuppliedPreferenceOrder(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleLogic: {ProviderPreferences: []string{"agy", "zcode", "kimi"}},
	})
	roles, err := appconfig.CanonicalRolesConfig(defaults, []string{"kimi", "zcode", "agy"})
	if err != nil {
		t.Fatalf("canonical roles: %v", err)
	}
	if roles.Logic.PrimaryProvider != "agy" || roles.Logic.FallbackProvider != "zcode" {
		t.Fatalf("logic = %s/%s, want agy/zcode from the supplied defaults", roles.Logic.PrimaryProvider, roles.Logic.FallbackProvider)
	}
}

// TestCanonicalRolesConfigResolvesEachCoreRoleIndependently guards the removal of
// the shared assignment that once made four roles move together.
func TestCanonicalRolesConfigResolvesEachCoreRoleIndependently(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleSecurity: {ProviderPreferences: []string{"zcode", "agy", "kimi"}},
		domain.RoleTesting:  {ProviderPreferences: []string{"agy", "kimi", "zcode"}},
	})
	roles, err := appconfig.CanonicalRolesConfig(defaults, []string{"kimi", "zcode", "agy"})
	if err != nil {
		t.Fatalf("canonical roles: %v", err)
	}
	if roles.Security.PrimaryProvider != "zcode" || roles.Security.FallbackProvider != "agy" {
		t.Fatalf("security = %s/%s, want zcode/agy", roles.Security.PrimaryProvider, roles.Security.FallbackProvider)
	}
	if roles.Testing.PrimaryProvider != "agy" || roles.Testing.FallbackProvider != "kimi" {
		t.Fatalf("testing = %s/%s, want agy/kimi", roles.Testing.PrimaryProvider, roles.Testing.FallbackProvider)
	}
	if roles.Product.PrimaryProvider != "kimi" || roles.Product.FallbackProvider != "zcode" {
		t.Fatalf("product = %s/%s, want the untouched kimi/zcode", roles.Product.PrimaryProvider, roles.Product.FallbackProvider)
	}
}

func TestCanonicalRolesConfigOmitsFallbackForASingleFamily(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, nil)
	roles, err := appconfig.CanonicalRolesConfig(defaults, []string{"agy"})
	if err != nil {
		t.Fatalf("canonical roles: %v", err)
	}
	if roles.Logic.PrimaryProvider != "agy" || roles.Logic.FallbackProvider != "" {
		t.Fatalf("logic = %s/%s, want agy with no fallback", roles.Logic.PrimaryProvider, roles.Logic.FallbackProvider)
	}
}

// TestCanonicalRolesConfigRejectsZeroValueDefaults proves the derivation errors
// rather than panicking when it is handed nothing.
func TestCanonicalRolesConfigRejectsZeroValueDefaults(t *testing.T) {
	t.Parallel()

	roles, err := appconfig.CanonicalRolesConfig(appconfig.RoleDefaults{}, []string{"zcode", "agy"})
	if err == nil {
		t.Fatalf("canonical roles succeeded with zero-value defaults: %#v", roles)
	}
}

func TestCanonicalRolesConfigSeedsArtistInputsFromDefaults(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleArtist: {
			ProviderPreferences:   []string{"zcode", "agy"},
			ArtistTaskPath:        "docs/brief.md",
			ArtistDesignSpecGlobs: []string{"mocks/**/*.webp", "mocks/**/*.png"},
		},
	})
	roles, err := appconfig.CanonicalRolesConfigForUI(defaults, []string{"zcode", "agy"})
	if err != nil {
		t.Fatalf("canonical UI roles: %v", err)
	}
	if roles.Artist.PrimaryProvider != "zcode" || roles.Artist.FallbackProvider != "agy" {
		t.Fatalf("artist = %s/%s, want zcode/agy from the supplied defaults", roles.Artist.PrimaryProvider, roles.Artist.FallbackProvider)
	}
	if roles.Artist.Inputs == nil || roles.Artist.Inputs.TaskPath != "docs/brief.md" {
		t.Fatalf("artist inputs = %#v, want the supplied task path", roles.Artist.Inputs)
	}
	if len(roles.Artist.Inputs.DesignSpecGlobs) != 2 || roles.Artist.Inputs.DesignSpecGlobs[0] != "mocks/**/*.webp" {
		t.Fatalf("artist globs = %v, want the supplied globs", roles.Artist.Inputs.DesignSpecGlobs)
	}
}
