package config

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
)

const (
	maxConfiguredLimit = 1_000_000
	maxOutputBytes     = 1 << 30
	// maxRawYAMLBytes is the hard pre-parse bound on yaml.v3 parser input.
	maxRawYAMLBytes = 1 << 20
	// The remaining limits are post-compose structural semantic budgets.
	maxYAMLDepth        = 64
	maxYAMLNodes        = 10_000
	maxYAMLScalarBytes  = 64 << 10
	redactedPathSegment = "[<redacted>]"
	maxSourceLabelBytes = 256
)

var byteSizePattern = regexp.MustCompile(`^([1-9][0-9]{0,8})(KiB|MiB|GiB)$`)

var yamlErrorCoordinatePattern = regexp.MustCompile(`(?m)(?:^|yaml:[[:space:]]+|\n[[:space:]]*)line[[:space:]]+([0-9]+)(?::[[:space:]]*(?:column[[:space:]]+)?([0-9]+))?`)

var fixedRoles = []string{"logic", "security", "maintainability", "product", "documentation", "testing"}
var severities = []string{"info", "low", "medium", "high", "critical", "blocker"}

// DecodeGlobal strictly decodes a global configuration proposal. It performs no
// merging and returns a zero GlobalConfig whenever any diagnostic is present.
func DecodeGlobal(source string, data []byte) (GlobalConfig, error) {
	var zero GlobalConfig
	schema := globalSchema()
	document, diagnostics := parseDocument(LayerGlobal, source, data, schema)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}

	root := document.Content[0]
	validateSchema(root, schema, LayerGlobal, sourceName(source), "$", &diagnostics)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}

	var config GlobalConfig
	if err := decodeKnown(data, &config); err != nil {
		return zero, decodeError(LayerGlobal, sourceName(source), root, err)
	}

	locations := indexLocations(root, schema)
	validateGlobal(&config, locations, sourceName(source), &diagnostics)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}
	return config, nil
}

// DecodeProject strictly decodes a trusted-base, strengthening-only project
// proposal. It performs no merging and returns a zero ProjectConfig whenever
// any diagnostic is present.
func DecodeProject(source string, data []byte) (ProjectConfig, error) {
	var zero ProjectConfig
	schema := projectSchema()
	document, diagnostics := parseDocument(LayerProject, source, data, schema)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}

	root := document.Content[0]
	validateSchema(root, schema, LayerProject, sourceName(source), "$", &diagnostics)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}

	var config ProjectConfig
	if err := decodeKnown(data, &config); err != nil {
		return zero, decodeError(LayerProject, sourceName(source), root, err)
	}

	locations := indexLocations(root, schema)
	validateProject(&config, locations, sourceName(source), &diagnostics)
	if len(diagnostics) != 0 {
		return zero, newDiagnosticError(diagnostics)
	}
	return config, nil
}

func sourceName(source string) string {
	if source == "" {
		return "<memory>"
	}

	var label strings.Builder
	label.Grow(min(len(source), maxSourceLabelBytes))
	lastTruncationPoint := 0
	for index := 0; index < len(source); {
		character, width := utf8.DecodeRuneInString(source[index:])
		var token string
		switch {
		case character == utf8.RuneError && width == 1:
			token = fmt.Sprintf(`\x%02X`, source[index])
		case unicode.IsControl(character):
			token = escapedControl(character)
		default:
			token = source[index : index+width]
		}
		if label.Len()+len(token) > maxSourceLabelBytes {
			return label.String()[:lastTruncationPoint] + "..."
		}
		label.WriteString(token)
		if label.Len() <= maxSourceLabelBytes-3 {
			lastTruncationPoint = label.Len()
		}
		index += width
	}
	return label.String()
}

func escapedControl(character rune) string {
	switch character {
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	default:
		if character <= 0xFF {
			return fmt.Sprintf(`\x%02X`, character)
		}
		return fmt.Sprintf(`\u%04X`, character)
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func parseDocument(layer Layer, source string, data []byte, schema *yamlSchema) (*yaml.Node, []Diagnostic) {
	name := sourceName(source)
	if len(data) == 0 {
		return nil, []Diagnostic{diagnosticAt(layer, name, "$", 1, 1, "empty_document", "configuration must contain exactly one mapping document")}
	}
	if len(data) > maxRawYAMLBytes {
		return nil, []Diagnostic{diagnosticAt(layer, name, "$", 1, 1, "yaml_size_limit", "configuration exceeds the 1 MiB YAML input limit")}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return nil, []Diagnostic{diagnosticAt(layer, name, "$", 1, 1, "empty_document", "configuration must contain exactly one mapping document")}
		}
		return nil, []Diagnostic{parseDiagnostic(layer, name, err)}
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, []Diagnostic{parseDiagnostic(layer, name, err)}
		}
		return nil, []Diagnostic{diagnosticAt(layer, name, "$", document.Line, document.Column, "multiple_documents", "configuration must contain exactly one YAML document")}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		line, column := nodePosition(&document)
		return nil, []Diagnostic{diagnosticAt(layer, name, "$", line, column, "invalid_root", "configuration root must be a mapping")}
	}
	if diagnostic := yamlBoundDiagnostic(document.Content[0], layer, name); diagnostic != nil {
		return nil, []Diagnostic{*diagnostic}
	}

	var diagnostics []Diagnostic
	inspectYAML(document.Content[0], schema, layer, name, "$", &diagnostics)
	return &document, diagnostics
}

func parseDiagnostic(layer Layer, source string, err error) Diagnostic {
	line, column := errorPosition(err, 1, 1)
	return diagnosticAt(layer, source, "$", line, column, "invalid_yaml", "configuration contains invalid YAML syntax")
}

// yamlBoundDiagnostic applies post-compose structural semantic budgets. The raw
// byte limit above remains the hard bound on parser input memory.
func yamlBoundDiagnostic(root *yaml.Node, layer Layer, source string) *Diagnostic {
	type pendingNode struct {
		node  *yaml.Node
		depth int
	}
	pending := []pendingNode{{node: root, depth: 1}}
	nodes := 0
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		nodes++
		if nodes > maxYAMLNodes {
			line, column := nodePosition(current.node)
			diagnostic := diagnosticAt(layer, source, "$", line, column, "yaml_node_limit", "configuration exceeds the YAML node limit")
			return &diagnostic
		}
		if current.depth > maxYAMLDepth {
			line, column := nodePosition(current.node)
			diagnostic := diagnosticAt(layer, source, "$", line, column, "yaml_depth_limit", "configuration exceeds the YAML nesting depth limit")
			return &diagnostic
		}
		if current.node.Kind == yaml.ScalarNode && len(current.node.Value) > maxYAMLScalarBytes {
			line, column := nodePosition(current.node)
			diagnostic := diagnosticAt(layer, source, "$", line, column, "yaml_scalar_limit", "configuration contains a scalar that exceeds the YAML scalar size limit")
			return &diagnostic
		}
		for index := len(current.node.Content) - 1; index >= 0; index-- {
			pending = append(pending, pendingNode{node: current.node.Content[index], depth: current.depth + 1})
		}
	}
	return nil
}

func decodeKnown(data []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(destination)
}

func decodeError(layer Layer, source string, root *yaml.Node, err error) error {
	line, column := nodePosition(root)
	line, column = errorPosition(err, line, column)
	return newDiagnosticError([]Diagnostic{diagnosticAt(layer, source, "$", line, column, "decode_error", "configuration values do not match the schema")})
}

func errorPosition(err error, fallbackLine, fallbackColumn int) (int, int) {
	if err == nil {
		return fallbackLine, fallbackColumn
	}
	matches := yamlErrorCoordinatePattern.FindStringSubmatch(err.Error())
	if len(matches) == 0 {
		return fallbackLine, fallbackColumn
	}
	line, parseErr := strconv.Atoi(matches[1])
	if parseErr != nil || line < 1 {
		return fallbackLine, fallbackColumn
	}
	if len(matches) < 3 || matches[2] == "" {
		return line, fallbackColumn
	}
	column, parseErr := strconv.Atoi(matches[2])
	if parseErr != nil || column < 1 {
		return line, fallbackColumn
	}
	return line, column
}

func inspectYAML(node *yaml.Node, schema *yamlSchema, layer Layer, source, yamlPath string, diagnostics *[]Diagnostic) {
	if node == nil {
		return
	}
	if node.Anchor != "" {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "anchor_forbidden", "YAML anchors are not allowed")
	}
	if node.Kind == yaml.AliasNode {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "alias_forbidden", "YAML aliases are not allowed")
		return
	}
	tag := node.ShortTag()
	if tag == "!!null" {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "null_forbidden", "configuration fields must not be null")
		return
	}
	if tag == "!!merge" {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "merge_forbidden", "YAML merge keys are not allowed")
		return
	}
	if !isCoreYAMLTag(tag) {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "tag_forbidden", "non-core YAML tags are not allowed")
	}

	switch node.Kind {
	case yaml.SequenceNode:
		var itemSchema *yamlSchema
		if schema != nil {
			itemSchema = schema.item
		}
		for index, child := range node.Content {
			inspectYAML(child, itemSchema, layer, source, sequencePath(yamlPath, index), diagnostics)
		}
	case yaml.MappingNode:
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.ShortTag() == "!!merge" {
				valuePath := redactedPath(yamlPath)
				appendNodeDiagnostic(diagnostics, layer, source, valuePath, key, "merge_forbidden", "YAML merge keys are not allowed")
				inspectYAML(value, nil, layer, source, valuePath, diagnostics)
				continue
			}
			inspectYAML(key, nil, layer, source, yamlPath, diagnostics)
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				appendNodeDiagnostic(diagnostics, layer, source, yamlPath, key, "non_string_key", "mapping keys must be strings")
				inspectYAML(value, nil, layer, source, redactedPath(yamlPath), diagnostics)
				continue
			}

			memberPath, memberSchema, _ := schemaMember(schema, yamlPath, key.Value)
			valuePath := memberPath
			if _, exists := seen[key.Value]; exists {
				appendNodeDiagnostic(diagnostics, layer, source, valuePath, key, "duplicate_key", "mapping key is duplicated")
			} else {
				seen[key.Value] = struct{}{}
			}
			if secretLikeKey(key.Value) {
				valuePath = redactedPath(yamlPath)
				appendNodeDiagnostic(diagnostics, layer, source, valuePath, key, "secret_like_field", "secret-like fields are not accepted in configuration")
			}
			if layer == LayerProject {
				if forbidden, reason := forbiddenProjectField(key.Value); forbidden {
					valuePath = redactedPath(yamlPath)
					appendNodeDiagnostic(diagnostics, layer, source, valuePath, key, "forbidden_field", reason)
				}
			}
			inspectYAML(value, memberSchema, layer, source, valuePath, diagnostics)
		}
	}
}

func isCoreYAMLTag(tag string) bool {
	switch tag {
	case "!!str", "!!int", "!!float", "!!bool", "!!null", "!!seq", "!!map", "!!merge":
		return true
	default:
		return false
	}
}

func secretLikeKey(key string) bool {
	switch key {
	case "redact_secrets", "secret_output_policy":
		return false
	}
	collapsed := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	return strings.Contains(collapsed, "secret") || strings.Contains(collapsed, "token") || strings.Contains(collapsed, "password") || strings.Contains(collapsed, "credential") || strings.Contains(collapsed, "apikey")
}

func forbiddenProjectField(key string) (bool, string) {
	switch strings.ToLower(key) {
	case "providers", "provider", "provider_definitions", "driver", "status", "bin", "args":
		return true, "project configuration cannot define providers or provider commands"
	case "command", "commands", "shell":
		return true, "project configuration cannot define shell or command execution"
	case "env", "environment", "env_allowlist":
		return true, "project configuration cannot configure environment"
	case "template", "prompt_template", "trusted_templates", "project_prompt_overrides", "project_prompt_source":
		return true, "project configuration cannot configure trusted templates or prompts"
	case "allow_project_provider_commands", "allow_project_shell", "cross_process_lane_lock", "strategy", "reject_unknown_fields", "reject_empty_strings", "reject_placeholder_values", "repair", "same_provider", "max_attempts", "directory_mode", "file_mode", "preserve_raw_output", "redact_secrets", "secret_output_policy", "mutation_detection", "follow_symlinks", "symlink":
		return true, "project configuration cannot set weakening-only policy"
	default:
		return false, ""
	}
}

type yamlSchema struct {
	kind       yaml.Kind
	tag        string
	fields     map[string]*yamlSchema
	additional *yamlSchema
	item       *yamlSchema
	required   []string
}

func object(fields map[string]*yamlSchema) *yamlSchema {
	return &yamlSchema{kind: yaml.MappingNode, tag: "!!map", fields: fields}
}

func requiredObject(fields map[string]*yamlSchema, required ...string) *yamlSchema {
	schema := object(fields)
	schema.required = required
	return schema
}

func dictionary(value *yamlSchema) *yamlSchema {
	return &yamlSchema{kind: yaml.MappingNode, tag: "!!map", additional: value}
}

func sequence(item *yamlSchema) *yamlSchema {
	return &yamlSchema{kind: yaml.SequenceNode, tag: "!!seq", item: item}
}

func scalar(tag string) *yamlSchema {
	return &yamlSchema{kind: yaml.ScalarNode, tag: tag}
}

func stringScalar() *yamlSchema {
	return scalar("!!str")
}

func boolScalar() *yamlSchema {
	return scalar("!!bool")
}

func intScalar() *yamlSchema {
	return scalar("!!int")
}

func schemaMember(schema *yamlSchema, parent, key string) (string, *yamlSchema, bool) {
	if schema == nil {
		return redactedPath(parent), nil, false
	}
	if schema.fields != nil {
		member, known := schema.fields[key]
		if !known {
			return redactedPath(parent), nil, false
		}
		return mappingPath(parent, key), member, true
	}
	if schema.additional != nil {
		if validProviderInstanceID(key) {
			return mappingPath(parent, key), schema.additional, true
		}
		return redactedPath(parent), schema.additional, true
	}
	return redactedPath(parent), nil, false
}

func validateSchema(node *yaml.Node, schema *yamlSchema, layer Layer, source, yamlPath string, diagnostics *[]Diagnostic) {
	if node == nil || schema == nil {
		return
	}
	tag := node.ShortTag()
	if tag == "!!null" || tag == "!!merge" || !isCoreYAMLTag(tag) || node.Kind == yaml.AliasNode {
		return
	}
	if node.Kind != schema.kind {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "invalid_node_kind", "field must be a "+schemaKindName(schema.kind))
		return
	}
	if tag != schema.tag {
		appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, "invalid_node_tag", "field must use the "+schema.tag+" YAML tag")
		return
	}

	switch schema.kind {
	case yaml.SequenceNode:
		for index, child := range node.Content {
			validateSchema(child, schema.item, layer, source, sequencePath(yamlPath, index), diagnostics)
		}
	case yaml.MappingNode:
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				continue
			}
			memberPath, memberSchema, known := schemaMember(schema, yamlPath, key.Value)
			if schema.fields != nil && !known {
				appendNodeDiagnostic(diagnostics, layer, source, memberPath, key, "unknown_field", "field is not allowed by this configuration schema")
				continue
			}
			seen[key.Value] = struct{}{}
			validateSchema(value, memberSchema, layer, source, memberPath, diagnostics)
		}
		for _, key := range schema.required {
			if _, configured := seen[key]; !configured {
				appendNodeDiagnostic(diagnostics, layer, source, mappingPath(yamlPath, key), node, "missing_required_field", "field must be configured")
			}
		}
	}
}

func schemaKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "sequence"
	default:
		return "scalar"
	}
}

func globalSchema() *yamlSchema {
	stringList := sequence(stringScalar())
	provider := requiredObject(map[string]*yamlSchema{
		"driver":           stringScalar(),
		"status":           stringScalar(),
		"optional":         boolScalar(),
		"bin":              stringScalar(),
		"args":             stringList,
		"concurrency_key":  stringScalar(),
		"timeout_sec":      intScalar(),
		"max_stdout_bytes": intScalar(),
		"max_stderr_bytes": intScalar(),
	}, "driver", "bin", "concurrency_key", "timeout_sec", "max_stdout_bytes", "max_stderr_bytes")
	role := requiredObject(map[string]*yamlSchema{
		"enabled": boolScalar(),
	}, "enabled")
	roles := requiredObject(map[string]*yamlSchema{
		"logic":           role,
		"security":        role,
		"maintainability": role,
		"product":         role,
		"documentation":   role,
		"testing":         role,
	}, "logic", "security", "maintainability", "product", "documentation", "testing")
	return requiredObject(map[string]*yamlSchema{
		"version": intScalar(),
		"runtime": requiredObject(map[string]*yamlSchema{
			"home": stringScalar(),
			"path": requiredObject(map[string]*yamlSchema{
				"inherit": boolScalar(),
				"prepend": stringList,
				"append":  stringList,
			}, "inherit", "prepend"),
			"env_allowlist":    stringList,
			"max_active_lanes": intScalar(),
		}, "home", "path", "env_allowlist", "max_active_lanes"),
		"execution": requiredObject(map[string]*yamlSchema{
			"strategy":                stringScalar(),
			"workspace_access":        stringScalar(),
			"cross_process_lane_lock": boolScalar(),
		}, "strategy", "workspace_access", "cross_process_lane_lock"),
		"providers": dictionary(provider),
		"roles":     roles,
		"review": requiredObject(map[string]*yamlSchema{
			"request_changes_on": stringList,
		}, "request_changes_on"),
		"validation": requiredObject(map[string]*yamlSchema{
			"reject_unknown_fields":     boolScalar(),
			"reject_empty_strings":      boolScalar(),
			"reject_placeholder_values": boolScalar(),
			"evidence": requiredObject(map[string]*yamlSchema{
				"require_verified_for": stringList,
			}, "require_verified_for"),
			"repair": requiredObject(map[string]*yamlSchema{
				"enabled":       boolScalar(),
				"max_attempts":  intScalar(),
				"same_provider": boolScalar(),
			}, "enabled", "max_attempts", "same_provider"),
		}, "reject_unknown_fields", "reject_empty_strings", "reject_placeholder_values", "evidence", "repair"),
		"trust": requiredObject(map[string]*yamlSchema{
			"required_roles":                  stringList,
			"project_config":                  stringScalar(),
			"project_prompt_overrides":        boolScalar(),
			"project_prompt_source":           stringScalar(),
			"allow_project_provider_commands": boolScalar(),
			"allow_project_shell":             boolScalar(),
		}, "required_roles", "project_config", "project_prompt_overrides", "project_prompt_source", "allow_project_provider_commands", "allow_project_shell"),
		"resources": requiredObject(map[string]*yamlSchema{
			"primary_repair_attempts":  intScalar(),
			"fallback_repair_attempts": intScalar(),
			"role_max_invocations":     intScalar(),
			"run_max_invocations":      intScalar(),
			"run_total_output_cap":     stringScalar(),
		}, "primary_repair_attempts", "fallback_repair_attempts", "role_max_invocations", "run_max_invocations", "run_total_output_cap"),
		"ci": requiredObject(map[string]*yamlSchema{
			"fail_on_severity":      stringList,
			"degraded_review_fails": boolScalar(),
		}, "fail_on_severity", "degraded_review_fails"),
		"artifacts": requiredObject(map[string]*yamlSchema{
			"root":                stringScalar(),
			"directory_mode":      stringScalar(),
			"file_mode":           stringScalar(),
			"preserve_raw_output": boolScalar(),
		}, "root", "directory_mode", "file_mode", "preserve_raw_output"),
		"safety": requiredObject(map[string]*yamlSchema{
			"redact_secrets":       boolScalar(),
			"secret_output_policy": stringScalar(),
			"mutation_detection":   boolScalar(),
		}, "redact_secrets", "secret_output_policy", "mutation_detection"),
	}, "version", "runtime", "execution", "providers", "roles", "review", "validation", "trust", "resources", "ci", "artifacts", "safety")
}

func projectSchema() *yamlSchema {
	stringList := sequence(stringScalar())
	role := object(map[string]*yamlSchema{
		"enabled": boolScalar(),
		"guide":   stringScalar(),
	})
	roles := object(map[string]*yamlSchema{
		"logic":           role,
		"security":        role,
		"maintainability": role,
		"product":         role,
		"documentation":   role,
		"testing":         role,
	})
	return object(map[string]*yamlSchema{
		"version":      intScalar(),
		"trusted_base": boolScalar(),
		"project": object(map[string]*yamlSchema{
			"name":    stringScalar(),
			"root":    stringScalar(),
			"context": stringScalar(),
		}),
		"execution": object(map[string]*yamlSchema{
			"workspace_access": stringScalar(),
		}),
		"review": object(map[string]*yamlSchema{
			"required_roles":     stringList,
			"request_changes_on": stringList,
		}),
		"roles": roles,
		"validation": object(map[string]*yamlSchema{
			"evidence": object(map[string]*yamlSchema{
				"require_verified_for": stringList,
			}),
		}),
		"resources": object(map[string]*yamlSchema{
			"role_max_invocations": intScalar(),
			"run_max_invocations":  intScalar(),
			"run_total_output_cap": stringScalar(),
		}),
		"ci": object(map[string]*yamlSchema{
			"fail_on_severity":      stringList,
			"degraded_review_fails": boolScalar(),
		}),
	})
}

func indexLocations(root *yaml.Node, schema *yamlSchema) map[string]*yaml.Node {
	locations := map[string]*yaml.Node{"$": root}
	indexNode(root, schema, "$", locations)
	return locations
}

func indexNode(node *yaml.Node, schema *yamlSchema, yamlPath string, locations map[string]*yaml.Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case yaml.SequenceNode:
		var itemSchema *yamlSchema
		if schema != nil {
			itemSchema = schema.item
		}
		for index, child := range node.Content {
			childPath := sequencePath(yamlPath, index)
			locations[childPath] = child
			indexNode(child, itemSchema, childPath, locations)
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				continue
			}
			memberPath, memberSchema, _ := schemaMember(schema, yamlPath, key.Value)
			if schema != nil && schema.additional != nil {
				locations[memberPath] = key
			} else {
				locations[memberPath] = value
			}
			indexNode(value, memberSchema, memberPath, locations)
		}
	}
}

func validateGlobal(config *GlobalConfig, locations map[string]*yaml.Node, source string, diagnostics *[]Diagnostic) {
	validateVersion(config.Version, "$.version", locations, LayerGlobal, source, diagnostics)
	validateNonemptyConfigured(config.Runtime.Home, "$.runtime.home", locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Runtime.MaxActiveLanes, "$.runtime.max_active_lanes", locations, LayerGlobal, source, diagnostics)
	validateStringList(config.Runtime.EnvAllowlist, "$.runtime.env_allowlist", nil, locations, LayerGlobal, source, diagnostics)

	validateEnum(config.Execution.Strategy, "$.execution.strategy", []string{"primary_only", "primary_with_fallback"}, locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Execution.WorkspaceAccess, "$.execution.workspace_access", []string{"none", "readonly_snapshot", "project"}, locations, LayerGlobal, source, diagnostics)

	for instanceID, provider := range config.Providers {
		providerPath := redactedPath("$.providers")
		if validProviderInstanceID(instanceID) {
			providerPath = mappingPath("$.providers", instanceID)
		} else {
			appendLocationDiagnostic(diagnostics, LayerGlobal, source, providerPath, locations, "invalid_provider_id", "provider instance ID must match [a-z][a-z0-9._-]{0,63}")
		}
		validateEnum(provider.Driver, providerPath+".driver", []string{"kimi", "zcode", "agy", "codex", "claude"}, locations, LayerGlobal, source, diagnostics)
		validateEnum(provider.Status, providerPath+".status", []string{"unverified"}, locations, LayerGlobal, source, diagnostics)
		validateNonemptyConfigured(provider.Bin, providerPath+".bin", locations, LayerGlobal, source, diagnostics)
		validateStringList(provider.Args, providerPath+".args", nil, locations, LayerGlobal, source, diagnostics)
		if normalized, valid := normalizeConcurrencyKey(provider.ConcurrencyKey); !valid {
			if _, configured := locations[providerPath+".concurrency_key"]; configured {
				appendLocationDiagnostic(diagnostics, LayerGlobal, source, providerPath+".concurrency_key", locations, "invalid_concurrency_key", "concurrency key must normalize to an ASCII-lower key matching [a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
			}
		} else {
			provider.ConcurrencyKey = normalized
			config.Providers[instanceID] = provider
		}
		validateConfiguredPositive(provider.TimeoutSec, providerPath+".timeout_sec", locations, LayerGlobal, source, diagnostics)
		validateConfiguredOutputLimit(provider.MaxStdoutBytes, providerPath+".max_stdout_bytes", locations, LayerGlobal, source, diagnostics)
		validateConfiguredOutputLimit(provider.MaxStderrBytes, providerPath+".max_stderr_bytes", locations, LayerGlobal, source, diagnostics)
		if provider.Driver == "codex" || provider.Driver == "claude" {
			if provider.Optional == nil || !*provider.Optional {
				appendLocationDiagnostic(diagnostics, LayerGlobal, source, providerPath+".optional", locations, "optional_provider_required", "codex and claude providers require explicit optional: true")
			}
		}
	}

	validateGlobalRoles(config.Roles, locations, source, diagnostics)
	validateSeverityList(config.Review.RequestChangesOn, "$.review.request_changes_on", locations, LayerGlobal, source, diagnostics)
	validateSeverityList(config.Validation.Evidence.RequireVerifiedFor, "$.validation.evidence.require_verified_for", locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Validation.Repair.MaxAttempts, "$.validation.repair.max_attempts", locations, LayerGlobal, source, diagnostics)
	validateRoleList(config.Trust.RequiredRoles, "$.trust.required_roles", locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Trust.ProjectConfig, "$.trust.project_config", []string{"trusted_base_only", "declarative_only"}, locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Trust.ProjectPromptSource, "$.trust.project_prompt_source", []string{"target_base"}, locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Resources.PrimaryRepairAttempts, "$.resources.primary_repair_attempts", locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Resources.FallbackRepairAttempts, "$.resources.fallback_repair_attempts", locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Resources.RoleMaxInvocations, "$.resources.role_max_invocations", locations, LayerGlobal, source, diagnostics)
	validateConfiguredPositive(config.Resources.RunMaxInvocations, "$.resources.run_max_invocations", locations, LayerGlobal, source, diagnostics)
	validateConfiguredByteSize(config.Resources.RunTotalOutputCap, "$.resources.run_total_output_cap", locations, LayerGlobal, source, diagnostics)
	validateSeverityList(config.CI.FailOnSeverity, "$.ci.fail_on_severity", locations, LayerGlobal, source, diagnostics)
	validateSafeRelativePath(config.Artifacts.Root, "$.artifacts.root", false, locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Artifacts.DirectoryMode, "$.artifacts.directory_mode", []string{"0700"}, locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Artifacts.FileMode, "$.artifacts.file_mode", []string{"0600"}, locations, LayerGlobal, source, diagnostics)
	validateEnum(config.Safety.SecretOutputPolicy, "$.safety.secret_output_policy", []string{"block"}, locations, LayerGlobal, source, diagnostics)
}

func validateProject(config *ProjectConfig, locations map[string]*yaml.Node, source string, diagnostics *[]Diagnostic) {
	validateVersion(config.Version, "$.version", locations, LayerProject, source, diagnostics)
	if !config.TrustedBase {
		appendLocationDiagnostic(diagnostics, LayerProject, source, "$.trusted_base", locations, "trusted_base_required", "trusted_base must be true")
	}
	validateNonemptyValue(config.Project.Name, "$.project.name", locations, LayerProject, source, "empty_id", "project name must not be empty", diagnostics)
	validateRequiredRelativePath(config.Project.Root, "$.project.root", true, locations, LayerProject, source, diagnostics)
	validateSafeRelativePath(config.Project.Context, "$.project.context", false, locations, LayerProject, source, diagnostics)

	if config.Execution != nil {
		validateOptionalEnum(config.Execution.WorkspaceAccess, "$.execution.workspace_access", []string{"none", "readonly_snapshot", "project"}, locations, LayerProject, source, diagnostics)
	}
	if config.Review != nil {
		if config.Review.RequiredRoles != nil {
			validateRoleList(*config.Review.RequiredRoles, "$.review.required_roles", locations, LayerProject, source, diagnostics)
		}
		if config.Review.RequestChangesOn != nil {
			validateSeverityList(*config.Review.RequestChangesOn, "$.review.request_changes_on", locations, LayerProject, source, diagnostics)
		}
	}
	if config.Roles != nil {
		validateProjectRole(config.Roles.Logic, "$.roles.logic", locations, source, diagnostics)
		validateProjectRole(config.Roles.Security, "$.roles.security", locations, source, diagnostics)
		validateProjectRole(config.Roles.Maintainability, "$.roles.maintainability", locations, source, diagnostics)
		validateProjectRole(config.Roles.Product, "$.roles.product", locations, source, diagnostics)
		validateProjectRole(config.Roles.Documentation, "$.roles.documentation", locations, source, diagnostics)
		validateProjectRole(config.Roles.Testing, "$.roles.testing", locations, source, diagnostics)
	}
	if config.Validation != nil && config.Validation.Evidence != nil && config.Validation.Evidence.RequireVerifiedFor != nil {
		validateSeverityList(*config.Validation.Evidence.RequireVerifiedFor, "$.validation.evidence.require_verified_for", locations, LayerProject, source, diagnostics)
	}
	if config.Resources != nil {
		validateOptionalPositive(config.Resources.RoleMaxInvocations, "$.resources.role_max_invocations", locations, LayerProject, source, diagnostics)
		validateOptionalPositive(config.Resources.RunMaxInvocations, "$.resources.run_max_invocations", locations, LayerProject, source, diagnostics)
		validateOptionalByteSize(config.Resources.RunTotalOutputCap, "$.resources.run_total_output_cap", locations, LayerProject, source, diagnostics)
	}
	if config.CI != nil {
		if config.CI.FailOnSeverity != nil {
			validateSeverityList(*config.CI.FailOnSeverity, "$.ci.fail_on_severity", locations, LayerProject, source, diagnostics)
		}
		if config.CI.DegradedReviewFails != nil && !*config.CI.DegradedReviewFails {
			appendLocationDiagnostic(diagnostics, LayerProject, source, "$.ci.degraded_review_fails", locations, "weakening_value", "project CI enforcement may only be set to true")
		}
	}
}

func validateGlobalRoles(roles RolesConfig, locations map[string]*yaml.Node, source string, diagnostics *[]Diagnostic) {
	for _, role := range []struct {
		name  string
		value RoleConfig
	}{
		{"logic", roles.Logic},
		{"security", roles.Security},
		{"maintainability", roles.Maintainability},
		{"product", roles.Product},
		{"documentation", roles.Documentation},
		{"testing", roles.Testing},
	} {
		rolePath := "$.roles." + role.name
		if _, exists := locations[rolePath]; !exists {
			appendLocationDiagnostic(diagnostics, LayerGlobal, source, rolePath, locations, "missing_role", "all six fixed roles must be configured")
			continue
		}
		if _, exists := locations[rolePath+".enabled"]; !exists {
			appendLocationDiagnostic(diagnostics, LayerGlobal, source, rolePath+".enabled", locations, "missing_required_field", "role enabled must be configured")
		}
	}
}

func validateProjectRole(role *ProjectRoleConfig, yamlPath string, locations map[string]*yaml.Node, source string, diagnostics *[]Diagnostic) {
	if role == nil {
		return
	}
	if role.Enabled != nil && !*role.Enabled {
		appendLocationDiagnostic(diagnostics, LayerProject, source, yamlPath+".enabled", locations, "weakening_value", "project roles may not be disabled")
	}
	if role.Guide != nil && !safeGuide(*role.Guide) {
		appendLocationDiagnostic(diagnostics, LayerProject, source, yamlPath+".guide", locations, "unsafe_path", "guide must be a nonempty, NUL-free trusted-base reference")
	}
}

func validateVersion(version int, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if version != 1 {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "unsupported_version", "version must be 1")
	}
}

func validateEnum(value, yamlPath string, allowed []string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured && !contains(allowed, value) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_enum", "value is not an allowed enum member")
	}
}

func validateOptionalEnum(value *string, yamlPath string, allowed []string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if value != nil {
		validateEnum(*value, yamlPath, allowed, locations, layer, source, diagnostics)
	}
}

func validateRoleList(values []string, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	validateStringList(values, yamlPath, fixedRoles, locations, layer, source, diagnostics)
}

func validateSeverityList(values []string, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	validateStringList(values, yamlPath, severities, locations, layer, source, diagnostics)
}

func validateStringList(values []string, yamlPath string, allowed []string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		entryPath := sequencePath(yamlPath, index)
		if strings.TrimSpace(value) == "" {
			appendLocationDiagnostic(diagnostics, layer, source, entryPath, locations, "empty_value", "list entries must not be empty")
			continue
		}
		if allowed != nil && !contains(allowed, value) {
			appendLocationDiagnostic(diagnostics, layer, source, entryPath, locations, "invalid_enum", "value is not an allowed enum member")
		}
		if _, exists := seen[value]; exists {
			appendLocationDiagnostic(diagnostics, layer, source, entryPath, locations, "duplicate_value", "list entries must not be duplicated")
		}
		seen[value] = struct{}{}
	}
}

func validateNonemptyConfigured(value, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured {
		validateNonemptyValue(value, yamlPath, locations, layer, source, "empty_value", "value must not be empty", diagnostics)
	}
}

func validateNonemptyValue(value, yamlPath string, locations map[string]*yaml.Node, layer Layer, source, code, message string, diagnostics *[]Diagnostic) {
	if strings.TrimSpace(value) == "" {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, code, message)
	}
}

func validateConfiguredPositive(value int, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured && (value <= 0 || value > maxConfiguredLimit) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_limit", fmt.Sprintf("limit must be between 1 and %d", maxConfiguredLimit))
	}
}

func validateOptionalPositive(value *int, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if value != nil && (*value <= 0 || *value > maxConfiguredLimit) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_limit", fmt.Sprintf("limit must be between 1 and %d", maxConfiguredLimit))
	}
}

func validateConfiguredOutputLimit(value int, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured && (value <= 0 || value > maxOutputBytes) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_limit", fmt.Sprintf("limit must be between 1 and %d", maxOutputBytes))
	}
}

func validateConfiguredByteSize(value, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured && !validByteSize(value) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_limit", "output cap must be a bounded positive KiB, MiB, or GiB size")
	}
}

func validateOptionalByteSize(value *string, yamlPath string, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if value != nil && !validByteSize(*value) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "invalid_limit", "output cap must be a bounded positive KiB, MiB, or GiB size")
	}
}

func validByteSize(value string) bool {
	matches := byteSizePattern.FindStringSubmatch(value)
	if len(matches) != 3 {
		return false
	}
	amount, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || amount <= 0 {
		return false
	}
	multiplier := int64(1 << 10)
	switch matches[2] {
	case "MiB":
		multiplier = 1 << 20
	case "GiB":
		multiplier = 1 << 30
	}
	return amount <= int64(maxOutputBytes)/multiplier
}

func validateSafeRelativePath(value, yamlPath string, allowDot bool, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; configured && !safeRelativePath(value, allowDot) {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "unsafe_path", "path must be canonical relative and cannot contain absolute, backslash, NUL, dot-dot, or symlink claims")
	}
}
func validateRequiredRelativePath(value, yamlPath string, allowDot bool, locations map[string]*yaml.Node, layer Layer, source string, diagnostics *[]Diagnostic) {
	if _, configured := locations[yamlPath]; !configured {
		appendLocationDiagnostic(diagnostics, layer, source, yamlPath, locations, "missing_required_field", "path must be configured")
		return
	}
	validateSafeRelativePath(value, yamlPath, allowDot, locations, layer, source, diagnostics)
}

func safeRelativePath(value string, allowDot bool) bool {
	if value == "" || !utf8.ValidString(value) || norm.NFC.String(value) != value || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	if len(value) >= 3 && isASCIIAlpha(value[0]) && value[1] == ':' && value[2] == '/' {
		return false
	}
	if path.Clean(value) != value {
		return false
	}
	if value == "." {
		return allowDot
	}
	for _, element := range strings.Split(value, "/") {
		if element == "" || element == "." || element == ".." || strings.HasPrefix(strings.ToLower(element), "symlink:") {
			return false
		}
	}
	return true
}

func safeGuide(value string) bool {
	if strings.HasPrefix(value, "builtin:") {
		return safeRelativePath(strings.TrimPrefix(value, "builtin:"), false)
	}
	return safeRelativePath(value, false)
}

func normalizeConcurrencyKey(value string) (string, bool) {
	value = norm.NFC.String(value)
	if !utf8.ValidString(value) || value == "" || len(value) > 64 {
		return "", false
	}
	bytes := []byte(value)
	for index, character := range bytes {
		if character >= 'A' && character <= 'Z' {
			bytes[index] = character + ('a' - 'A')
		}
	}
	value = string(bytes)
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return "", false
		}
	}
	if !isASCIIAlphaNumeric(value[0]) || !isASCIIAlphaNumeric(value[len(value)-1]) {
		return "", false
	}
	return value, true
}

func validProviderInstanceID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func isASCIIAlpha(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func isASCIIAlphaNumeric(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
}

func mappingPath(parent, key string) string {
	if isPathIdentifier(key) {
		return parent + "." + key
	}
	return fmt.Sprintf("%s[%q]", parent, key)
}
func redactedPath(parent string) string {
	return parent + redactedPathSegment
}

func sequencePath(parent string, index int) string {
	return fmt.Sprintf("%s[%d]", parent, index)
}

func isPathIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func appendLocationDiagnostic(diagnostics *[]Diagnostic, layer Layer, source, yamlPath string, locations map[string]*yaml.Node, code, message string) {
	node := locations[yamlPath]
	if node == nil {
		node = locations["$"]
	}
	appendNodeDiagnostic(diagnostics, layer, source, yamlPath, node, code, message)
}

func appendNodeDiagnostic(diagnostics *[]Diagnostic, layer Layer, source, yamlPath string, node *yaml.Node, code, message string) {
	line, column := nodePosition(node)
	*diagnostics = append(*diagnostics, diagnosticAt(layer, source, yamlPath, line, column, code, message))
}

func diagnosticAt(layer Layer, source, yamlPath string, line, column int, code, message string) Diagnostic {
	if line < 1 {
		line = 1
	}
	if column < 1 {
		column = 1
	}
	return Diagnostic{Layer: layer, Source: sourceName(source), Path: yamlPath, Line: line, Column: column, Code: code, Message: message}
}

func nodePosition(node *yaml.Node) (int, int) {
	if node == nil {
		return 1, 1
	}
	line, column := node.Line, node.Column
	if line < 1 {
		line = 1
	}
	if column < 1 {
		column = 1
	}
	return line, column
}
