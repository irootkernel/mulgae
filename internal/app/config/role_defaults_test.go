package config_test

import (
	"errors"
	"strings"
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
		entries[role] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "grok"}}
	}
	entries[domain.RoleArtist] = appconfig.RoleDefault{
		ProviderPreferences:   []string{"zcode"},
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
			entries[role] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "grok"}}
		}
		entries[domain.RoleArtist] = appconfig.RoleDefault{
			ProviderPreferences:   []string{"zcode"},
			ArtistTaskPath:        "brief.md",
			ArtistDesignSpecGlobs: []string{"specs/**/*.png"},
		}
		return entries
	}
	for name, mutate := range map[string]func(map[domain.Role]appconfig.RoleDefault){
		"missing role": func(e map[domain.Role]appconfig.RoleDefault) { delete(e, domain.RoleTesting) },
		"unknown role": func(e map[domain.Role]appconfig.RoleDefault) { e[domain.Role("reviewer")] = e[domain.RoleLogic] },
		"core role missing family": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode"}}
		},
		"core role retired codex": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "codex"}}
		},
		"core role retired agy": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "agy"}}
		},
		"core role duplicate family": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "zcode"}}
		},
		"core role with artist inputs": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleLogic] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "grok"}, ArtistTaskPath: "brief.md"}
		},
		"artist with grok": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"grok"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist with retired codex": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode", "codex"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist with retired agy": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"agy"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist without task path": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode"}, ArtistDesignSpecGlobs: []string{"specs/a.png"}}
		},
		"artist without globs": func(e map[domain.Role]appconfig.RoleDefault) {
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode"}, ArtistTaskPath: "brief.md"}
		},
		"artist with too many globs": func(e map[domain.Role]appconfig.RoleDefault) {
			globs := make([]string, 0, 17)
			for index := 0; index < 17; index++ {
				globs = append(globs, "specs/"+string(rune('a'+index))+".png")
			}
			e[domain.RoleArtist] = appconfig.RoleDefault{ProviderPreferences: []string{"zcode"}, ArtistTaskPath: "brief.md", ArtistDesignSpecGlobs: globs}
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

	preferences := []string{"zcode", "grok"}
	entries := map[domain.Role]appconfig.RoleDefault{}
	for _, role := range domain.CoreRoleOrder() {
		entries[role] = appconfig.RoleDefault{ProviderPreferences: preferences}
	}
	entries[domain.RoleArtist] = appconfig.RoleDefault{
		ProviderPreferences:   []string{"zcode"},
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
	if !exists || logic.ProviderPreferences[0] != "zcode" {
		t.Fatalf("logic preferences = %v (present=%t), want an unmutated copy", logic.ProviderPreferences, exists)
	}
	logic.ProviderPreferences[0] = "mutated"
	again, _ := defaults.Role(domain.RoleLogic)
	if again.ProviderPreferences[0] != "zcode" {
		t.Fatalf("Role returned aliased state: %v", again.ProviderPreferences)
	}
}

// TestCanonicalRolesConfigFollowsSuppliedPreferenceOrder fails if any hardcoded
// preference order survives in Go.
func TestCanonicalRolesConfigFollowsSuppliedPreferenceOrder(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleLogic: {ProviderPreferences: []string{"grok", "zcode"}},
	})
	roles, err := appconfig.CanonicalRolesConfig(defaults, []string{"zcode", "grok"})
	if err != nil {
		t.Fatalf("canonical roles: %v", err)
	}
	if roles.Logic.PrimaryProvider != "grok" {
		t.Fatalf("logic = %s, want grok from the supplied defaults", roles.Logic.PrimaryProvider)
	}
}

// TestCanonicalRolesConfigResolvesEachCoreRoleIndependently guards the removal of
// the shared assignment that once made four roles move together.
func TestCanonicalRolesConfigResolvesEachCoreRoleIndependently(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleSecurity: {ProviderPreferences: []string{"zcode", "grok"}},
		domain.RoleTesting:  {ProviderPreferences: []string{"grok", "zcode"}},
	})
	roles, err := appconfig.CanonicalRolesConfig(defaults, []string{"zcode", "grok"})
	if err != nil {
		t.Fatalf("canonical roles: %v", err)
	}
	if roles.Security.PrimaryProvider != "zcode" {
		t.Fatalf("security = %s, want zcode", roles.Security.PrimaryProvider)
	}
	if roles.Testing.PrimaryProvider != "grok" {
		t.Fatalf("testing = %s, want grok", roles.Testing.PrimaryProvider)
	}
	if roles.Product.PrimaryProvider != "zcode" {
		t.Fatalf("product = %s, want the untouched zcode", roles.Product.PrimaryProvider)
	}
}

// TestCanonicalRolesConfigSelectsOneProviderPerRole proves the derivation takes
// only the first configured family from a role's preference order, however many
// families are configured. Later preferences keep the derivation total; they are
// not a second route.
func TestCanonicalRolesConfigSelectsOneProviderPerRole(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, nil)
	for _, test := range []struct {
		name       string
		configured []string
		want       string
	}{
		{"single family", []string{"grok"}, "grok"},
		{"every family", []string{"zcode", "grok"}, "zcode"},
	} {
		t.Run(test.name, func(t *testing.T) {
			roles, err := appconfig.CanonicalRolesConfig(defaults, test.configured)
			if err != nil {
				t.Fatalf("canonical roles: %v", err)
			}
			if roles.Logic.PrimaryProvider != test.want {
				t.Fatalf("logic = %s, want %s", roles.Logic.PrimaryProvider, test.want)
			}
		})
	}
}

// TestCanonicalRolesConfigRejectsZeroValueDefaults proves the derivation errors
// rather than panicking when it is handed nothing.
func TestCanonicalRolesConfigRejectsZeroValueDefaults(t *testing.T) {
	t.Parallel()

	roles, err := appconfig.CanonicalRolesConfig(appconfig.RoleDefaults{}, []string{"zcode", "grok"})
	if err == nil {
		t.Fatalf("canonical roles succeeded with zero-value defaults: %#v", roles)
	}
}

func TestCanonicalRolesConfigSeedsArtistInputsFromDefaults(t *testing.T) {
	t.Parallel()

	defaults := syntheticDefaults(t, map[domain.Role]appconfig.RoleDefault{
		domain.RoleArtist: {
			ProviderPreferences:   []string{"zcode"},
			ArtistTaskPath:        "docs/brief.md",
			ArtistDesignSpecGlobs: []string{"mocks/**/*.webp", "mocks/**/*.png"},
		},
	})
	roles, err := appconfig.CanonicalRolesConfigForUI(defaults, []string{"zcode", "grok"})
	if err != nil {
		t.Fatalf("canonical UI roles: %v", err)
	}
	if roles.Artist.PrimaryProvider != "zcode" {
		t.Fatalf("artist = %s, want zcode from the supplied defaults", roles.Artist.PrimaryProvider)
	}
	if roles.Artist.Inputs == nil || roles.Artist.Inputs.TaskPath != "docs/brief.md" {
		t.Fatalf("artist inputs = %#v, want the supplied task path", roles.Artist.Inputs)
	}
	if len(roles.Artist.Inputs.DesignSpecGlobs) != 2 || roles.Artist.Inputs.DesignSpecGlobs[0] != "mocks/**/*.webp" {
		t.Fatalf("artist globs = %v, want the supplied globs", roles.Artist.Inputs.DesignSpecGlobs)
	}
}

func TestCanonicalRolesConfigClassifiesUnsupportedArtistProvider(t *testing.T) {
	t.Parallel()

	_, err := appconfig.CanonicalRolesConfigForUI(syntheticDefaults(t, nil), []string{"grok"})
	if !errors.Is(err, appconfig.ErrRoleProviderUnsupported) {
		t.Fatalf("canonical UI roles error = %v, want ErrRoleProviderUnsupported", err)
	}
}

func TestRetiredFamilySelectionIsRejected(t *testing.T) {
	t.Parallel()
	defaults := syntheticDefaults(t, nil)
	for _, selection := range [][]string{{"kimi"}, {"cursor"}, {"codex"}, {"agy"}, {"zcode", "cursor"}, {"zcode", "codex"}, {"zcode", "agy"}, {"zcode", "grok", "codex"}, {"zcode", "grok", "agy"}} {
		if _, err := appconfig.CanonicalRolesConfig(defaults, selection); err == nil {
			t.Fatalf("retired family selection %v was accepted", selection)
		}
	}
}

func TestFamiliesReturnsZCodeAndGrokInCanonicalOrder(t *testing.T) {
	t.Parallel()
	providers := appconfig.ProvidersConfig{
		ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
		Grok:  &appconfig.GrokProviderConfig{Executable: "/usr/local/bin/grok"},
	}
	if got := providers.Families(); strings.Join(got, ",") != "zcode,grok" {
		t.Fatalf("families = %v, want zcode,grok", got)
	}
	if _, err := appconfig.CanonicalRolesConfig(syntheticDefaults(t, nil), []string{"grok", "zcode"}); err == nil {
		t.Fatal("out-of-order family set was accepted")
	}
}
