// Package roles parses and validates the build-owned role catalog.
package roles

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = "kar-role.v1"

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
	SchemaVersion       string     `yaml:"schema_version"`
	ID                  string     `yaml:"id"`
	Order               int        `yaml:"order"`
	Activation          Activation `yaml:"activation"`
	ProviderPreferences []string   `yaml:"provider_preferences"`
	SystemPrompt        string     `yaml:"system_prompt"`
}

func Parse(contents []byte) (Definition, error) {
	if len(contents) == 0 || !utf8.Valid(contents) || bytes.IndexByte(contents, 0) >= 0 || bytes.IndexByte(contents, '\r') >= 0 {
		return Definition{}, fmt.Errorf("role catalog: document must be non-empty canonical UTF-8")
	}
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&node); err != nil {
		return Definition{}, fmt.Errorf("role catalog: decode: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return Definition{}, fmt.Errorf("role catalog: trailing YAML document")
	}
	if err := validateNode(&node); err != nil {
		return Definition{}, err
	}
	var definition Definition
	if err := node.Decode(&definition); err != nil {
		return Definition{}, fmt.Errorf("role catalog: decode definition: %w", err)
	}
	if err := definition.Validate(); err != nil {
		return Definition{}, err
	}
	definition.ProviderPreferences = append([]string(nil), definition.ProviderPreferences...)
	return definition, nil
}

func (definition Definition) Validate() error {
	role := domain.Role(definition.ID)
	if definition.SchemaVersion != SchemaVersion || !role.Valid() || definition.Order < 1 || definition.Order > len(domain.FixedRoleOrder()) || !definition.Activation.Valid() {
		return fmt.Errorf("role catalog: invalid identity, order, or activation")
	}
	if (role == domain.RoleArtist) != (definition.Activation == ActivationProjectKindUI) {
		return fmt.Errorf("role catalog: invalid activation for %q", role)
	}
	if len(definition.ProviderPreferences) == 0 || len(definition.ProviderPreferences) > 3 {
		return fmt.Errorf("role catalog: invalid provider preferences for %q", role)
	}
	seen := make(map[string]struct{}, len(definition.ProviderPreferences))
	for _, provider := range definition.ProviderPreferences {
		if provider != "kimi" && provider != "zcode" && provider != "agy" {
			return fmt.Errorf("role catalog: invalid provider %q", provider)
		}
		if _, duplicate := seen[provider]; duplicate {
			return fmt.Errorf("role catalog: duplicate provider %q", provider)
		}
		seen[provider] = struct{}{}
	}
	if role == domain.RoleArtist && strings.Join(definition.ProviderPreferences, ",") != "agy,zcode" {
		return fmt.Errorf("role catalog: artist provider order must be agy,zcode")
	}
	if definition.SystemPrompt == "" || strings.HasSuffix(definition.SystemPrompt, "\n") || strings.ContainsAny(definition.SystemPrompt, "\x00\r") {
		return fmt.Errorf("role catalog: invalid system prompt for %q", role)
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
