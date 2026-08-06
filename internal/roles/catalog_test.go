package roles

import (
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

// roleEntry renders one document entry. An empty extra keeps the entry minimal.
func roleEntry(id string, order int, activation, preferences, extra string) string {
	entry := "  - id: " + id + "\n    order: " + itoa(order) + "\n    activation: " + activation + "\n    provider_preferences: " + preferences + "\n"
	if extra != "" {
		entry += extra
	}
	return entry + "    system_prompt: |-\n      " + strings.ToUpper(id) + " role guide\n"
}

func itoa(value int) string { return string(rune('0' + value)) }

const artistDefaultInputs = "    default_inputs:\n      task_path: ux-ui-info.md\n      design_spec_globs:\n        - design-specs/**/*.png\n"

// catalogDocument renders a complete, valid document, then applies overrides for
// individual roles so each test varies exactly one thing.
func catalogFixture(overrides map[string]string) string {
	defaults := map[string]string{
		"logic":           roleEntry("logic", 1, "always", "[kimi, zcode, agy]", ""),
		"security":        roleEntry("security", 2, "always", "[zcode, agy, kimi]", ""),
		"maintainability": roleEntry("maintainability", 3, "always", "[zcode, agy, kimi]", ""),
		"product":         roleEntry("product", 4, "always", "[zcode, agy, kimi]", ""),
		"documentation":   roleEntry("documentation", 5, "always", "[agy, zcode, kimi]", ""),
		"testing":         roleEntry("testing", 6, "always", "[zcode, agy, kimi]", ""),
		"artist":          roleEntry("artist", 7, "project_kind_ui", "[agy, zcode]", artistDefaultInputs),
	}
	document := "schema_version: " + SchemaVersion + "\nroles:\n"
	for _, role := range domain.FixedRoleOrder() {
		id := string(role)
		if override, exists := overrides[id]; exists {
			if override == "" {
				continue
			}
			document += override
			continue
		}
		document += defaults[id]
	}
	return document
}

func TestParseCatalogAcceptsTheCanonicalDocument(t *testing.T) {
	t.Parallel()

	definitions, err := ParseCatalog([]byte(catalogFixture(nil)))
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if len(definitions) != len(domain.FixedRoleOrder()) {
		t.Fatalf("definition count = %d, want %d", len(definitions), len(domain.FixedRoleOrder()))
	}
	for index, role := range domain.FixedRoleOrder() {
		if definitions[index].ID != string(role) {
			t.Fatalf("definition %d = %q, want %q", index, definitions[index].ID, role)
		}
	}
}

func TestParseCatalogEnforcesArtistExclusiveDefaultInputs(t *testing.T) {
	t.Parallel()

	for name, overrides := range map[string]map[string]string{
		"artist without default inputs": {"artist": roleEntry("artist", 7, "project_kind_ui", "[agy, zcode]", "")},
		"core role with default inputs": {"logic": roleEntry("logic", 1, "always", "[kimi, zcode, agy]", artistDefaultInputs)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err == nil {
				t.Fatal("parse catalog succeeded, want rejection")
			}
		})
	}
}

func TestParseCatalogRejectsUnsafeDefaultTaskPath(t *testing.T) {
	t.Parallel()

	for _, taskPath := range []string{"/abs.md", "../x.md", ".mulgae/x.md", ".gjc/x.md", "a//b.md", `a\b.md`, "."} {
		t.Run(taskPath, func(t *testing.T) {
			inputs := "    default_inputs:\n      task_path: '" + taskPath + "'\n      design_spec_globs:\n        - design-specs/**/*.png\n"
			overrides := map[string]string{"artist": roleEntry("artist", 7, "project_kind_ui", "[agy, zcode]", inputs)}
			if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err == nil {
				t.Fatalf("task path %q was accepted", taskPath)
			}
		})
	}
}

func TestParseCatalogRejectsInvalidDesignSpecGlobs(t *testing.T) {
	t.Parallel()

	tooMany := make([]string, 0, 17)
	for index := 0; index < 17; index++ {
		tooMany = append(tooMany, "design-specs/"+strings.Repeat("a", index+1)+".png")
	}
	for name, globs := range map[string][]string{
		"empty":               {},
		"too many":            tooMany,
		"duplicate":           {"design-specs/**/*.png", "design-specs/**/*.png"},
		"unsupported type":    {"design-specs/**/*.gif"},
		"brace expansion":     {"design-specs/**/*.{png}"},
		"negation":            {"!design-specs/**/*.png"},
		"absolute":            {"/design-specs/**/*.png"},
		"parent traversal":    {"../design-specs/**/*.png"},
		"mulgae private tree": {".mulgae/design-specs/a.png"},
	} {
		t.Run(name, func(t *testing.T) {
			inputs := "    default_inputs:\n      task_path: ux-ui-info.md\n      design_spec_globs:"
			if len(globs) == 0 {
				inputs += " []\n"
			} else {
				inputs += "\n"
				for _, glob := range globs {
					inputs += "        - '" + glob + "'\n"
				}
			}
			overrides := map[string]string{"artist": roleEntry("artist", 7, "project_kind_ui", "[agy, zcode]", inputs)}
			if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err == nil {
				t.Fatalf("globs %v were accepted", globs)
			}
		})
	}
}

// TestParseCatalogRequiresFullPermutationForCoreRoles pins the invariant that
// keeps init's derivation total: a core role that drops a family could otherwise
// resolve to no primary provider at all.
func TestParseCatalogRequiresFullPermutationForCoreRoles(t *testing.T) {
	t.Parallel()

	for name, preferences := range map[string]string{
		"missing family":   "[kimi, zcode]",
		"single family":    "[zcode]",
		"duplicate family": "[zcode, zcode, agy]",
		"unknown family":   "[zcode, agy, gpt]",
		"empty":            "[]",
	} {
		t.Run(name, func(t *testing.T) {
			overrides := map[string]string{"logic": roleEntry("logic", 1, "always", preferences, "")}
			if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err == nil {
				t.Fatalf("core preferences %q were accepted", preferences)
			}
		})
	}
	for _, preferences := range []string{"[kimi, zcode, agy]", "[agy, kimi, zcode]", "[zcode, agy, kimi]"} {
		overrides := map[string]string{"logic": roleEntry("logic", 1, "always", preferences, "")}
		if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err != nil {
			t.Fatalf("core preferences %q were rejected: %v", preferences, err)
		}
	}
}

// TestParseCatalogAcceptsEitherArtistPreferenceOrder proves the document owns
// the artist order too; no Go constant pins it.
func TestParseCatalogAcceptsEitherArtistPreferenceOrder(t *testing.T) {
	t.Parallel()

	for _, preferences := range []string{"[agy, zcode]", "[zcode, agy]", "[agy]", "[zcode]"} {
		overrides := map[string]string{"artist": roleEntry("artist", 7, "project_kind_ui", preferences, artistDefaultInputs)}
		definitions, err := ParseCatalog([]byte(catalogFixture(overrides)))
		if err != nil {
			t.Fatalf("artist preferences %q were rejected: %v", preferences, err)
		}
		got := definitions[len(definitions)-1].ProviderPreferences
		want := strings.Split(strings.Trim(preferences, "[]"), ", ")
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("artist preferences = %v, want %v", got, want)
		}
	}
	for _, preferences := range []string{"[kimi, agy]", "[agy, zcode, kimi]", "[]"} {
		overrides := map[string]string{"artist": roleEntry("artist", 7, "project_kind_ui", preferences, artistDefaultInputs)}
		if _, err := ParseCatalog([]byte(catalogFixture(overrides))); err == nil {
			t.Fatalf("artist preferences %q were accepted", preferences)
		}
	}
}

func TestParseCatalogRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()

	for name, document := range map[string]string{
		"empty":                 "",
		"wrong schema version":  strings.Replace(catalogFixture(nil), SchemaVersion, "mulgae-roles.v2", 1),
		"missing role":          catalogFixture(map[string]string{"testing": ""}),
		"duplicate role":        catalogFixture(nil) + roleEntry("logic", 1, "always", "[kimi, zcode, agy]", ""),
		"order mismatch":        catalogFixture(map[string]string{"logic": roleEntry("logic", 2, "always", "[kimi, zcode, agy]", "")}),
		"artist activation":     catalogFixture(map[string]string{"artist": roleEntry("artist", 7, "always", "[agy, zcode]", artistDefaultInputs)}),
		"core activation":       catalogFixture(map[string]string{"logic": roleEntry("logic", 1, "project_kind_ui", "[kimi, zcode, agy]", "")}),
		"unknown field":         strings.Replace(catalogFixture(nil), "  - id: logic\n", "  - id: logic\n    unexpected: true\n", 1),
		"carriage return":       strings.Replace(catalogFixture(nil), "\n", "\r\n", 1),
		"trailing document":     catalogFixture(nil) + "---\nschema_version: " + SchemaVersion + "\n",
		"sequence root":         "- id: logic\n",
		"anchor":                strings.Replace(catalogFixture(nil), "roles:\n", "roles: &all\n", 1),
		"duplicate mapping key": strings.Replace(catalogFixture(nil), "  - id: logic\n", "  - id: logic\n    id: logic\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog([]byte(document)); err == nil {
				t.Fatal("parse catalog succeeded, want rejection")
			}
		})
	}
}

func TestParseCatalogReturnsCallerOwnedValues(t *testing.T) {
	t.Parallel()

	document := []byte(catalogFixture(nil))
	first, err := ParseCatalog(document)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	first[0].ProviderPreferences[0] = "mutated"
	artist := first[len(first)-1]
	if artist.DefaultInputs == nil {
		t.Fatal("artist default inputs are absent")
	}
	artist.DefaultInputs.DesignSpecGlobs[0] = "mutated"
	second, err := ParseCatalog(document)
	if err != nil {
		t.Fatalf("re-parse catalog: %v", err)
	}
	if second[0].ProviderPreferences[0] != "kimi" {
		t.Fatalf("re-parsed logic preferences = %v, want an unmutated document", second[0].ProviderPreferences)
	}
	if second[len(second)-1].DefaultInputs.DesignSpecGlobs[0] != "design-specs/**/*.png" {
		t.Fatalf("re-parsed artist globs = %v, want an unmutated document", second[len(second)-1].DefaultInputs.DesignSpecGlobs)
	}
}
