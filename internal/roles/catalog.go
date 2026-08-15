// Package roles parses and validates the build-owned role catalog.
package roles

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = "mulgae-roles.v1"

// maximumDesignSpecGlobs mirrors the artist glob ceiling enforced by the
// configuration validator. The two limits must stay identical or init would
// generate a configuration its own decoder rejects.
const maximumDesignSpecGlobs = 16

type Activation string

const (
	ActivationAlways        Activation = "always"
	ActivationProjectKindUI Activation = "project_kind_ui"
)

func (activation Activation) Valid() bool {
	return activation == ActivationAlways || activation == ActivationProjectKindUI
}

// Definition is the authoritative build-time document for one review role.
type Definition struct {
	ID                  string         `yaml:"id"`
	Order               int            `yaml:"order"`
	Activation          Activation     `yaml:"activation"`
	ProviderPreferences []string       `yaml:"provider_preferences"`
	DefaultInputs       *DefaultInputs `yaml:"default_inputs,omitempty"`
	SystemPrompt        string         `yaml:"system_prompt"`
}

// DefaultInputs carries the build-owned init-time artist input defaults. Only
// the artist role declares it.
type DefaultInputs struct {
	TaskPath        string   `yaml:"task_path"`
	DesignSpecGlobs []string `yaml:"design_spec_globs"`
}

// Clone returns a fully caller-owned copy.
func (inputs *DefaultInputs) Clone() *DefaultInputs {
	if inputs == nil {
		return nil
	}
	return &DefaultInputs{
		TaskPath:        inputs.TaskPath,
		DesignSpecGlobs: append([]string(nil), inputs.DesignSpecGlobs...),
	}
}

type catalogDocument struct {
	SchemaVersion string       `yaml:"schema_version"`
	Roles         []Definition `yaml:"roles"`
}

// ParseCatalog decodes the build-owned multi-role document and returns every
// definition in domain.FixedRoleOrder() order. The returned slice and every
// value it holds are newly allocated and caller-owned.
func ParseCatalog(contents []byte) ([]Definition, error) {
	if len(contents) == 0 || !utf8.Valid(contents) || bytes.IndexByte(contents, 0) >= 0 || bytes.IndexByte(contents, '\r') >= 0 {
		return nil, fmt.Errorf("role catalog: document must be non-empty canonical UTF-8")
	}
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&node); err != nil {
		return nil, fmt.Errorf("role catalog: decode: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("role catalog: trailing YAML document")
	}
	if err := validateNode(&node); err != nil {
		return nil, err
	}
	// Decode the typed document from its own strict decoder. yaml.Node.Decode
	// does not inherit KnownFields, so an unknown key would otherwise be
	// silently ignored rather than rejected.
	var document catalogDocument
	strict := yaml.NewDecoder(bytes.NewReader(contents))
	strict.KnownFields(true)
	if err := strict.Decode(&document); err != nil {
		return nil, fmt.Errorf("role catalog: decode document: %w", err)
	}
	if document.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("role catalog: schema version must be %q", SchemaVersion)
	}
	if err := ValidateCatalog(document.Roles); err != nil {
		return nil, err
	}
	ordered := make([]Definition, 0, len(document.Roles))
	for _, role := range domain.FixedRoleOrder() {
		for _, definition := range document.Roles {
			if definition.ID != string(role) {
				continue
			}
			definition.ProviderPreferences = append([]string(nil), definition.ProviderPreferences...)
			definition.DefaultInputs = definition.DefaultInputs.Clone()
			ordered = append(ordered, definition)
			break
		}
	}
	return ordered, nil
}

func (definition Definition) Validate() error {
	role := domain.Role(definition.ID)
	if !role.Valid() || definition.Order < 1 || definition.Order > len(domain.FixedRoleOrder()) || !definition.Activation.Valid() {
		return fmt.Errorf("role catalog: invalid identity, order, or activation")
	}
	if (role == domain.RoleArtist) != (definition.Activation == ActivationProjectKindUI) {
		return fmt.Errorf("role catalog: invalid activation for %q", role)
	}
	if err := definition.validateProviderPreferences(role); err != nil {
		return err
	}
	if (role == domain.RoleArtist) != (definition.DefaultInputs != nil) {
		return fmt.Errorf("role catalog: default inputs are artist-only, missing or unexpected for %q", role)
	}
	if definition.DefaultInputs != nil {
		if err := definition.DefaultInputs.validate(role); err != nil {
			return err
		}
	}
	if definition.SystemPrompt == "" || strings.HasSuffix(definition.SystemPrompt, "\n") || strings.ContainsAny(definition.SystemPrompt, "\x00\r") {
		return fmt.Errorf("role catalog: invalid system prompt for %q", role)
	}
	return nil
}

// validateProviderPreferences keeps the derivation of init's default provider
// assignment total. Every core role must name all four families, so the
// intersection with any non-empty configured family set is never empty.
func (definition Definition) validateProviderPreferences(role domain.Role) error {
	allowed := []string{"kimi", "zcode", "agy", "codex"}
	required := len(allowed)
	if role == domain.RoleArtist {
		allowed = []string{"agy", "zcode", "codex"}
		required = 1
	}
	if len(definition.ProviderPreferences) < required || len(definition.ProviderPreferences) > len(allowed) {
		return fmt.Errorf("role catalog: invalid provider preferences for %q", role)
	}
	seen := make(map[string]struct{}, len(definition.ProviderPreferences))
	for _, provider := range definition.ProviderPreferences {
		if !contains(allowed, provider) {
			return fmt.Errorf("role catalog: invalid provider %q for %q", provider, role)
		}
		if _, duplicate := seen[provider]; duplicate {
			return fmt.Errorf("role catalog: duplicate provider %q for %q", provider, role)
		}
		seen[provider] = struct{}{}
	}
	return nil
}

func (inputs DefaultInputs) validate(role domain.Role) error {
	if !safeContext(inputs.TaskPath) {
		return fmt.Errorf("role catalog: invalid default task path for %q", role)
	}
	if len(inputs.DesignSpecGlobs) == 0 || len(inputs.DesignSpecGlobs) > maximumDesignSpecGlobs {
		return fmt.Errorf("role catalog: invalid default design spec globs for %q", role)
	}
	seen := make(map[string]struct{}, len(inputs.DesignSpecGlobs))
	for _, pattern := range inputs.DesignSpecGlobs {
		if !safeArtistGlob(pattern) {
			return fmt.Errorf("role catalog: invalid default design spec glob %q", pattern)
		}
		if _, duplicate := seen[pattern]; duplicate {
			return fmt.Errorf("role catalog: duplicate default design spec glob %q", pattern)
		}
		seen[pattern] = struct{}{}
	}
	return nil
}

func ValidateCatalog(definitions []Definition) error {
	if len(definitions) != len(domain.FixedRoleOrder()) {
		return fmt.Errorf("role catalog: definition count = %d, want %d", len(definitions), len(domain.FixedRoleOrder()))
	}
	ordered := append([]Definition(nil), definitions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Order < ordered[j].Order })
	for index, role := range domain.FixedRoleOrder() {
		definition := ordered[index]
		if err := definition.Validate(); err != nil {
			return err
		}
		if definition.Order != index+1 || definition.ID != string(role) {
			return fmt.Errorf("role catalog: order %d is %q, want %q", index+1, definition.ID, role)
		}
	}
	return nil
}

// safeContext mirrors the project-relative path rule enforced by the
// configuration validator.
func safeContext(value string) bool {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || strings.Contains(value, "\\") || value == "." {
		return false
	}
	return value != ".mulgae" && value != ".gjc" && !strings.HasPrefix(value, ".mulgae/") && !strings.HasPrefix(value, ".gjc/") && !strings.HasPrefix(value, "../")
}

// safeArtistGlob mirrors the design-spec pattern rule enforced by the
// configuration validator.
func safeArtistGlob(value string) bool {
	if !safeContext(value) || len(value) > 4096 || strings.ContainsAny(value, "[]{}!\\") {
		return false
	}
	extension := strings.ToLower(path.Ext(value))
	return extension == ".png" || extension == ".jpg" || extension == ".jpeg" || extension == ".webp"
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validateNode(document *yaml.Node) error {
	if document == nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("role catalog: root must be one mapping document")
	}
	stack := []*yaml.Node{document}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
			return fmt.Errorf("role catalog: aliases, anchors, and merge keys are forbidden")
		}
		if node.Kind == yaml.MappingNode {
			seen := make(map[string]struct{}, len(node.Content)/2)
			for index := 0; index < len(node.Content); index += 2 {
				key := node.Content[index]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					return fmt.Errorf("role catalog: mapping keys must be strings")
				}
				if _, duplicate := seen[key.Value]; duplicate {
					return fmt.Errorf("role catalog: duplicate key %q", key.Value)
				}
				seen[key.Value] = struct{}{}
			}
		}
		stack = append(stack, node.Content...)
	}
	return nil
}
