package config

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
)

// maximumDesignSpecGlobs mirrors the artist glob ceiling enforced by the
// configuration decoder.
const maximumDesignSpecGlobs = 16

// RoleDefault is one role's build-owned generation-time default.
//
// ProviderPreferences is an ordered family preference: the first configured
// family becomes the role's provider. Later entries keep the derivation total
// when a project configures a different provider set; they are not a fallback
// route, because a role runs on exactly one provider. The artist fields are
// populated only for the artist role.
type RoleDefault struct {
	ProviderPreferences   []string
	ArtistTaskPath        string
	ArtistDesignSpecGlobs []string
}

func (role RoleDefault) clone() RoleDefault {
	return RoleDefault{
		ProviderPreferences:   append([]string(nil), role.ProviderPreferences...),
		ArtistTaskPath:        role.ArtistTaskPath,
		ArtistDesignSpecGlobs: append([]string(nil), role.ArtistDesignSpecGlobs...),
	}
}

// RoleDefaults is the validated, immutable set of build-owned defaults for every
// fixed role. It is the sole source of init's default provider routing and of
// the artist input defaults; no default assignment is spelled in Go.
type RoleDefaults struct{ entries map[domain.Role]RoleDefault }

// NewRoleDefaults validates and deep-copies a complete set of role defaults.
//
// Every core role must name all provider families. That keeps the
// derivation total: the intersection with any non-empty configured family set is
// never empty, so a role can never resolve to no primary provider.
func NewRoleDefaults(entries map[domain.Role]RoleDefault) (RoleDefaults, error) {
	fixed := domain.FixedRoleOrder()
	if len(entries) != len(fixed) {
		return RoleDefaults{}, fmt.Errorf("role defaults: entry count = %d, want %d", len(entries), len(fixed))
	}
	copied := make(map[domain.Role]RoleDefault, len(fixed))
	for _, role := range fixed {
		entry, exists := entries[role]
		if !exists {
			return RoleDefaults{}, fmt.Errorf("role defaults: %q is missing", role)
		}
		if err := validateRoleDefault(role, entry); err != nil {
			return RoleDefaults{}, err
		}
		copied[role] = entry.clone()
	}
	return RoleDefaults{entries: copied}, nil
}

// Valid reports whether the defaults carry every fixed role.
func (defaults RoleDefaults) Valid() bool {
	return len(defaults.entries) == len(domain.FixedRoleOrder())
}

// Role returns a caller-owned copy of one role's defaults.
func (defaults RoleDefaults) Role(role domain.Role) (RoleDefault, bool) {
	entry, exists := defaults.entries[role]
	if !exists {
		return RoleDefault{}, false
	}
	return entry.clone(), true
}

func validateRoleDefault(role domain.Role, entry RoleDefault) error {
	allowed := []string{"kimi", "zcode", "agy", "codex"}
	required := len(allowed)
	if role == domain.RoleArtist {
		allowed = []string{"agy", "zcode", "codex"}
		required = 1
	}
	if len(entry.ProviderPreferences) < required || len(entry.ProviderPreferences) > len(allowed) {
		return fmt.Errorf("role defaults: invalid provider preferences for %q", role)
	}
	seen := make(map[string]struct{}, len(entry.ProviderPreferences))
	for _, family := range entry.ProviderPreferences {
		if !containsString(allowed, family) {
			return fmt.Errorf("role defaults: invalid provider %q for %q", family, role)
		}
		if _, duplicate := seen[family]; duplicate {
			return fmt.Errorf("role defaults: duplicate provider %q for %q", family, role)
		}
		seen[family] = struct{}{}
	}
	if role != domain.RoleArtist {
		if entry.ArtistTaskPath != "" || len(entry.ArtistDesignSpecGlobs) != 0 {
			return fmt.Errorf("role defaults: artist inputs are not valid for %q", role)
		}
		return nil
	}
	if entry.ArtistTaskPath == "" {
		return fmt.Errorf("role defaults: artist task path is required")
	}
	if len(entry.ArtistDesignSpecGlobs) == 0 || len(entry.ArtistDesignSpecGlobs) > maximumDesignSpecGlobs {
		return fmt.Errorf("role defaults: invalid artist design spec globs")
	}
	globs := make(map[string]struct{}, len(entry.ArtistDesignSpecGlobs))
	for _, pattern := range entry.ArtistDesignSpecGlobs {
		if pattern == "" {
			return fmt.Errorf("role defaults: empty artist design spec glob")
		}
		if _, duplicate := globs[pattern]; duplicate {
			return fmt.Errorf("role defaults: duplicate artist design spec glob %q", pattern)
		}
		globs[pattern] = struct{}{}
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
