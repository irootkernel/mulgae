package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
)

const (
	maxYAMLDepth       = 64
	maxYAMLNodes       = 8192
	maxYAMLScalarBytes = 64 << 10
)

var (
	errProviderTimeoutInvalid  = errors.New("provider timeout invalid")
	modelPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	placeholderPattern         = regexp.MustCompile(`\$\{[^{}]+\}`)
	pemPrivateKeyHeaderPattern = regexp.MustCompile(`(?i)-----BEGIN (?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY-----`)
	credentialPrefixes         = []string{"github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "sk-", "sk_", "ghp_"}
	credentialKeys             = map[string]struct{}{
		"api_key": {}, "apikey": {}, "access_key": {}, "access_token": {},
		"auth_token": {}, "authorization": {}, "bearer_token": {},
		"client_secret": {}, "credential": {}, "credentials": {},
		"password": {}, "passwd": {}, "private_key": {}, "refresh_token": {},
		"secret": {}, "secret_key": {}, "session_cookie": {}, "session_token": {}, "token": {},
	}
	fixedRoles      = []string{"logic", "security", "maintainability", "product", "documentation", "testing", "artist"}
	fixedSeverities = []string{"info", "low", "medium", "high", "critical", "blocker"}
)

// Decode admits an effective merged configuration. Defaults are expanded in
// the returned typed value while EncodeCanonical omits defaulted optional fields.
func Decode(data []byte) (Config, error) {
	var zero Config
	root, err := parseBoundedDocument(data)
	if err != nil {
		return zero, err
	}
	if reason := scanCredentials(root); reason != "" {
		return zero, reject(reason)
	}
	if !strictScalarGrammar(root) {
		return zero, reject(ReasonYAMLInvalid)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var decoded Config
	if err := decoder.Decode(&decoded); err != nil {
		return zero, reject(ReasonYAMLInvalid)
	}
	if decoded.Providers.AGY != nil {
		decoded.Providers.AGY.PermissionModeExplicit = mappingHasPath(root, "providers", "agy", "permission_mode")
	}
	if err := validate(&decoded); err != nil {
		if errors.Is(err, errProviderTimeoutInvalid) {
			return zero, reject(ReasonProviderTimeoutInvalid)
		}
		return zero, reject(ReasonYAMLInvalid)
	}
	return decoded, nil
}

func mappingHasPath(root *yaml.Node, path ...string) bool {
	current := root
	for _, key := range path {
		if current == nil || current.Kind != yaml.MappingNode {
			return false
		}
		var next *yaml.Node
		for index := 0; index < len(current.Content); index += 2 {
			if current.Content[index].Value == key {
				next = current.Content[index+1]
				break
			}
		}
		if next == nil {
			return false
		}
		current = next
	}
	return true
}

func parseBoundedDocument(data []byte) (*yaml.Node, error) {
	if len(data) == 0 || len(data) > MaximumConfigBytes || !utf8.Valid(data) {
		return nil, reject(ReasonSizeInvalid)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, reject(ReasonYAMLInvalid)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, reject(ReasonYAMLInvalid)
	}
	type pending struct {
		node  *yaml.Node
		depth int
	}
	stack := []pending{{document.Content[0], 1}}
	nodes := 0
	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > maxYAMLNodes || current.depth > maxYAMLDepth || current.node.Kind == yaml.ScalarNode && len(current.node.Value) > maxYAMLScalarBytes {
			return nil, reject(ReasonYAMLInvalid)
		}
		if current.node.Kind == yaml.AliasNode || current.node.Anchor != "" || current.node.Tag == "!!merge" || !coreTag(current.node.Tag) {
			return nil, reject(ReasonYAMLInvalid)
		}
		if current.node.Kind == yaml.MappingNode {
			seen := make(map[string]struct{}, len(current.node.Content)/2)
			for index := 0; index < len(current.node.Content); index += 2 {
				key := current.node.Content[index]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || !asciiScanKey(key.Value) {
					return nil, reject(ReasonYAMLInvalid)
				}
				if _, duplicate := seen[key.Value]; duplicate {
					return nil, reject(ReasonYAMLInvalid)
				}
				seen[key.Value] = struct{}{}
			}
		}
		if current.node.Tag == "!!null" {
			return nil, reject(ReasonYAMLInvalid)
		}
		for index := len(current.node.Content) - 1; index >= 0; index-- {
			stack = append(stack, pending{current.node.Content[index], current.depth + 1})
		}
	}
	return document.Content[0], nil
}

func asciiScanKey(value string) bool {
	if value == "" {
		return false
	}
	for index := range value {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func strictScalarGrammar(root *yaml.Node) bool {
	var walk func(*yaml.Node, bool) bool
	walk = func(node *yaml.Node, mappingKey bool) bool {
		if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
			if node.Value == "" || placeholderPattern.MatchString(node.Value) {
				return false
			}
			for _, character := range node.Value {
				if unicode.IsControl(character) {
					return false
				}
			}
			if mappingKey && !asciiKey(node.Value) {
				return false
			}
		}
		if node.Kind == yaml.MappingNode {
			for index := 0; index < len(node.Content); index += 2 {
				if !walk(node.Content[index], true) || !walk(node.Content[index+1], false) {
					return false
				}
			}
			return true
		}
		for _, child := range node.Content {
			if !walk(child, false) {
				return false
			}
		}
		return true
	}
	return walk(root, false)
}

func coreTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!bool", "!!int":
		return true
	default:
		return false
	}
}

func asciiKey(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func scanCredentials(root *yaml.Node) ReasonCode {
	var walk func(*yaml.Node) ReasonCode
	walk = func(node *yaml.Node) ReasonCode {
		if node.Kind == yaml.MappingNode {
			for index := 0; index < len(node.Content); index += 2 {
				key, value := node.Content[index], node.Content[index+1]
				if credentialKey(key.Value) {
					return ReasonCredentialKeyDetected
				}
				if value.Kind == yaml.ScalarNode && value.Tag == "!!str" && credentialValue(value.Value) {
					return ReasonCredentialValueDetected
				}
				if reason := walk(value); reason != "" {
					return reason
				}
			}
		} else if node.Kind == yaml.SequenceNode {
			for _, child := range node.Content {
				if child.Kind == yaml.ScalarNode && child.Tag == "!!str" && credentialValue(child.Value) {
					return ReasonCredentialValueDetected
				}
				if reason := walk(child); reason != "" {
					return reason
				}
			}
		}
		return ""
	}
	return walk(root)
}

func credentialKey(value string) bool {
	var b strings.Builder
	separator := false
	for index := range value {
		character := value[index]
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		if character == '-' || character == '_' || character == '.' || character == ' ' {
			if b.Len() > 0 {
				separator = true
			}
			continue
		}
		if separator {
			b.WriteByte('_')
			separator = false
		}
		b.WriteByte(character)
	}
	normalized := strings.Trim(b.String(), "_")
	if _, exact := credentialKeys[normalized]; exact {
		return true
	}
	for key := range credentialKeys {
		if strings.HasSuffix(normalized, "_"+key) {
			return true
		}
	}
	return false
}

func credentialValue(raw string) bool {
	value := strings.Trim(raw, " ")
	if pemPrivateKeyHeaderPattern.MatchString(value) {
		return true
	}
	if len(value) >= 7 && strings.EqualFold(value[:7], "Bearer ") {
		return visibleToken(value[7:], 16, 4096)
	}
	if len(value) >= 6 && strings.EqualFold(value[:6], "Basic ") {
		encoded := value[6:]
		if len(encoded) >= 8 && len(encoded) <= 4096 {
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			return err == nil && base64.StdEncoding.EncodeToString(decoded) == encoded
		}
	}
	if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() && parsed.User != nil {
		if password, present := parsed.User.Password(); present && password != "" {
			return true
		}
	}
	for _, prefix := range credentialPrefixes {
		if strings.HasPrefix(value, prefix) && admittedToken(value[len(prefix):], 16, maxYAMLScalarBytes) {
			return true
		}
	}
	if (strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA")) && len(value) == 20 {
		for _, c := range value[4:] {
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return false
			}
		}
		return true
	}
	return strings.HasPrefix(value, "AIza") && len(value) == 39 && admittedGoogleToken(value[4:])
}

func visibleToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func admittedToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func admittedGoogleToken(value string) bool {
	if len(value) != 35 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validate(config *Config) error {
	if config.Version != ConfigVersion {
		return fmt.Errorf("version")
	}
	if !norm.NFC.IsNormalString(config.Project.Name) || visibleRunes(config.Project.Name) < 1 || visibleRunes(config.Project.Name) > 128 {
		return fmt.Errorf("project name")
	}
	if config.Project.Context != "" && !safeContext(config.Project.Context) {
		return fmt.Errorf("project context")
	}
	if config.Project.Kind == "" {
		config.Project.Kind = ProjectKindNonUI
	}
	if config.Project.Kind != ProjectKindNonUI && config.Project.Kind != ProjectKindUI {
		return fmt.Errorf("project kind")
	}
	if !canonicalAbsolute(config.NativeUser.Home) {
		return fmt.Errorf("native home")
	}
	if config.Providers.Count() == 0 {
		return fmt.Errorf("providers")
	}
	if config.Providers.Kimi != nil {
		if !canonicalAbsolute(config.Providers.Kimi.Executable) {
			return fmt.Errorf("kimi executable")
		}
		if config.Providers.Kimi.Model == "" {
			config.Providers.Kimi.Model = DefaultKimiModel
		}
		if !validModel(config.Providers.Kimi.Model) {
			return fmt.Errorf("kimi model")
		}
		if config.Providers.Kimi.DataHome == "" {
			config.Providers.Kimi.DataHome = DefaultKimiDataHome(config.NativeUser.Home)
		}
		if !canonicalAbsolute(config.Providers.Kimi.DataHome) {
			return fmt.Errorf("kimi data home")
		}
		timeout, err := ParseProviderTimeout(config.Providers.Kimi.Timeout)
		if err != nil {
			return fmt.Errorf("kimi timeout: %w: %v", errProviderTimeoutInvalid, err)
		}
		config.Providers.Kimi.Timeout = ProviderTimeoutText(timeout)
	}
	if config.Providers.ZCode != nil {
		if !canonicalAbsolute(config.Providers.ZCode.NodeExecutable) || !canonicalAbsolute(config.Providers.ZCode.Launcher) {
			return fmt.Errorf("zcode paths")
		}
		timeout, err := ParseProviderTimeout(config.Providers.ZCode.Timeout)
		if err != nil {
			return fmt.Errorf("zcode timeout: %w: %v", errProviderTimeoutInvalid, err)
		}
		config.Providers.ZCode.Timeout = ProviderTimeoutText(timeout)
	}
	if config.Providers.AGY != nil {
		if !canonicalAbsolute(config.Providers.AGY.Executable) {
			return fmt.Errorf("agy executable")
		}
		if config.Providers.AGY.PermissionMode == "" {
			config.Providers.AGY.PermissionMode = DefaultAGYPermissionMode
		}
		if config.Providers.AGY.PermissionMode != "safe" && config.Providers.AGY.PermissionMode != "dangerously-skip-permissions" {
			return fmt.Errorf("agy permission")
		}
		timeout, err := ParseProviderTimeout(config.Providers.AGY.Timeout)
		if err != nil {
			return fmt.Errorf("agy timeout: %w: %v", errProviderTimeoutInvalid, err)
		}
		config.Providers.AGY.Timeout = ProviderTimeoutText(timeout)
	}
	if config.Providers.Codex != nil {
		if !canonicalAbsolute(config.Providers.Codex.Executable) {
			return fmt.Errorf("codex executable")
		}
		if config.Providers.Codex.Model != "" && !validModel(config.Providers.Codex.Model) {
			return fmt.Errorf("codex model")
		}
		if effort := config.Providers.Codex.ReasoningEffort; effort != "" && effort != "minimal" && effort != "low" && effort != "medium" && effort != "high" && effort != "xhigh" {
			return fmt.Errorf("codex reasoning effort")
		}
		timeout, err := ParseProviderTimeout(config.Providers.Codex.Timeout)
		if err != nil {
			return fmt.Errorf("codex timeout: %w: %v", errProviderTimeoutInvalid, err)
		}
		config.Providers.Codex.Timeout = ProviderTimeoutText(timeout)
		named := config.Providers.Codex.DefaultCredentialProfile != "" || len(config.Providers.Codex.CredentialHomes) != 0
		if named {
			if !validCredentialProfileID(config.Providers.Codex.DefaultCredentialProfile) || len(config.Providers.Codex.CredentialHomes) == 0 {
				return fmt.Errorf("codex credential profiles")
			}
			lastProfile := ""
			for _, entry := range config.Providers.Codex.CredentialHomes {
				if !validCredentialProfileID(entry.Profile) || !canonicalAbsolute(entry.Home) || lastProfile != "" && entry.Profile <= lastProfile {
					return fmt.Errorf("codex credential profile")
				}
				lastProfile = entry.Profile
			}
			if _, ok := config.Providers.Codex.CredentialHome(config.Providers.Codex.DefaultCredentialProfile); !ok {
				return fmt.Errorf("codex default credential profile")
			}
		}
	}
	if config.Execution.WorkspaceAccess != "none" && config.Execution.WorkspaceAccess != "readonly_snapshot" {
		return fmt.Errorf("workspace")
	}
	configuredRoles := config.Roles.Ordered()
	enabledRoleCount := 0
	referencedCredentialProfiles := make(map[string]struct{})
	if config.Providers.Codex != nil && config.Providers.Codex.DefaultCredentialProfile != "" {
		referencedCredentialProfiles[config.Providers.Codex.DefaultCredentialProfile] = struct{}{}
	}
	for index, role := range configuredRoles {
		if index == len(configuredRoles)-1 {
			if err := validateArtistRole(config, role); err != nil {
				return err
			}
			if !role.Enabled {
				continue
			}
		}
		if !config.Providers.HasFamily(role.PrimaryProvider) {
			return fmt.Errorf("role")
		}
		if role.CredentialProfile != "" {
			if role.PrimaryProvider != "codex" || config.Providers.Codex == nil || config.Providers.Codex.DefaultCredentialProfile == "" || !validCredentialProfileID(role.CredentialProfile) {
				return fmt.Errorf("role credential profile")
			}
			if _, ok := config.Providers.Codex.CredentialHome(role.CredentialProfile); !ok {
				return fmt.Errorf("role credential profile")
			}
			referencedCredentialProfiles[role.CredentialProfile] = struct{}{}
		}
		if role.Enabled {
			enabledRoleCount++
		}
	}
	if config.Providers.Codex != nil && config.Providers.Codex.DefaultCredentialProfile != "" && len(referencedCredentialProfiles) != len(config.Providers.Codex.CredentialHomes) {
		return fmt.Errorf("unused codex credential profile")
	}
	if !config.Roles.Logic.Enabled {
		return fmt.Errorf("role floor")
	}
	if !validOrderedSet(config.Review.RequiredRoles, fixedRoles, []string{"logic"}) || !validOrderedSet(config.Review.RequestChangesOn, fixedSeverities, []string{"high", "critical", "blocker"}) || !validOrderedSet(config.Validation.Evidence.RequireVerifiedFor, fixedSeverities, []string{"high", "critical", "blocker"}) || !validOrderedSet(config.CI.FailOnSeverity, fixedSeverities, []string{"high", "critical", "blocker"}) {
		return fmt.Errorf("sets")
	}
	for _, required := range config.Review.RequiredRoles {
		for index, candidate := range fixedRoles {
			if required == candidate && !configuredRoles[index].Enabled {
				return fmt.Errorf("required role disabled")
			}
		}
	}
	if config.Validation.Repair.Enabled {
		if config.Validation.Repair.MaxAttempts != 1 || config.Resources.PrimaryRepairAttempts < 0 || config.Resources.PrimaryRepairAttempts > 1 || config.Resources.PrimaryRepairAttempts > config.Validation.Repair.MaxAttempts {
			return fmt.Errorf("repair")
		}
	} else if config.Validation.Repair.MaxAttempts != 0 || config.Resources.PrimaryRepairAttempts != 0 {
		return fmt.Errorf("repair disabled")
	}
	if config.Resources.MaxActiveLanes < 1 || config.Resources.MaxActiveLanes > 64 {
		return fmt.Errorf("max active lanes")
	}
	// A role runs its provider once and may repair once on the same provider.
	roleCost := 1 + config.Resources.PrimaryRepairAttempts
	if config.Resources.RoleMaxInvocations < roleCost || config.Resources.RoleMaxInvocations > 2 || config.Resources.RunMaxInvocations < roleCost*enabledRoleCount || config.Resources.RunMaxInvocations > 14 {
		return fmt.Errorf("budgets")
	}
	return nil
}

func validateArtistRole(config *Config, role RoleConfig) error {
	if config.Project.Kind == ProjectKindNonUI {
		if role.Enabled || role.PrimaryProvider != "" || role.CredentialProfile != "" || role.Inputs != nil {
			return fmt.Errorf("artist is only valid for UI projects")
		}
		return nil
	}
	if !role.Enabled {
		if role.PrimaryProvider != "" || role.CredentialProfile != "" || role.Inputs != nil {
			return fmt.Errorf("disabled UI artist role has configuration")
		}
		return nil
	}
	if (role.PrimaryProvider != "agy" && role.PrimaryProvider != "zcode" && role.PrimaryProvider != "codex") || role.Inputs == nil {
		return fmt.Errorf("UI project artist role")
	}
	if !safeContext(role.Inputs.TaskPath) || len(role.Inputs.DesignSpecGlobs) == 0 || len(role.Inputs.DesignSpecGlobs) > 16 {
		return fmt.Errorf("artist inputs")
	}
	seen := make(map[string]struct{}, len(role.Inputs.DesignSpecGlobs))
	for _, pattern := range role.Inputs.DesignSpecGlobs {
		if !safeArtistGlob(pattern) {
			return fmt.Errorf("artist glob")
		}
		if _, duplicate := seen[pattern]; duplicate {
			return fmt.Errorf("artist glob duplicate")
		}
		seen[pattern] = struct{}{}
	}
	return nil
}

func validCredentialProfileID(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeArtistGlob(value string) bool {
	if !safeContext(value) || len(value) > 4096 || strings.ContainsAny(value, "[]{}!\\") {
		return false
	}
	extension := strings.ToLower(path.Ext(value))
	return extension == ".png" || extension == ".jpg" || extension == ".jpeg" || extension == ".webp"
}

func visibleRunes(value string) int {
	count := 0
	for _, r := range value {
		if !unicode.IsControl(r) && !unicode.IsSpace(r) {
			count++
		}
	}
	return count
}
func canonicalAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, 0)
}
func safeContext(value string) bool {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || strings.Contains(value, "\\") || value == "." {
		return false
	}
	return value != ".mulgae" && value != ".gjc" && !strings.HasPrefix(value, ".mulgae/") && !strings.HasPrefix(value, ".gjc/") && !strings.HasPrefix(value, "../")
}
func validModel(value string) bool {
	if !modelPattern.MatchString(value) || path.IsAbs(value) || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}
func validOrderedSet(values, allowed, required []string) bool {
	if len(values) == 0 {
		return false
	}
	rank := make(map[string]int, len(allowed))
	for index, value := range allowed {
		rank[value] = index
	}
	seen := make(map[string]struct{}, len(values))
	last := -1
	for _, value := range values {
		current, ok := rank[value]
		if !ok || current <= last {
			return false
		}
		if _, dup := seen[value]; dup {
			return false
		}
		seen[value] = struct{}{}
		last = current
	}
	for _, value := range required {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

// EncodeCanonical emits the one stable operator-local representation.
func EncodeCanonical(config Config) ([]byte, error) {
	if err := validate(&config); err != nil {
		return nil, err
	}
	q := strconv.Quote
	var out strings.Builder
	out.WriteString("version: " + strconv.Itoa(ConfigVersion) + "\nproject:\n  name: " + q(config.Project.Name) + "\n")
	if config.Project.Context != "" {
		out.WriteString("  context: " + q(config.Project.Context) + "\n")
	}
	if config.Project.Kind == ProjectKindUI {
		out.WriteString("  kind: \"ui\"\n")
	}
	out.WriteString("native_user:\n  home: " + q(config.NativeUser.Home) + "\nproviders:\n")
	if provider := config.Providers.Kimi; provider != nil {
		out.WriteString("  kimi:\n    executable: " + q(provider.Executable) + "\n")
		if provider.Model != DefaultKimiModel {
			out.WriteString("    model: " + q(provider.Model) + "\n")
		}
		if provider.DataHome != DefaultKimiDataHome(config.NativeUser.Home) {
			out.WriteString("    data_home: " + q(provider.DataHome) + "\n")
		}
		if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
		}
	}
	if provider := config.Providers.ZCode; provider != nil {
		out.WriteString("  zcode:\n    node_executable: " + q(provider.NodeExecutable) + "\n    launcher: " + q(provider.Launcher) + "\n")
		if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
		}
	}
	if provider := config.Providers.AGY; provider != nil {
		out.WriteString("  agy:\n    executable: " + q(provider.Executable) + "\n")
		if provider.PermissionMode != DefaultAGYPermissionMode || provider.PermissionModeExplicit {
			out.WriteString("    permission_mode: " + q(provider.PermissionMode) + "\n")
		}
		if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
		}
	}
	if provider := config.Providers.Codex; provider != nil {
		out.WriteString("  codex:\n    executable: " + q(provider.Executable) + "\n")
		if provider.DefaultCredentialProfile != "" {
			out.WriteString("    default_credential_profile: " + q(provider.DefaultCredentialProfile) + "\n")
		}
		if len(provider.CredentialHomes) != 0 {
			out.WriteString("    credential_homes:\n")
			for _, entry := range provider.CredentialHomes {
				out.WriteString("      - profile: " + q(entry.Profile) + "\n        home: " + q(entry.Home) + "\n")
			}
		}
		if provider.Model != "" {
			out.WriteString("    model: " + q(provider.Model) + "\n")
		}
		if provider.ReasoningEffort != "" {
			out.WriteString("    reasoning_effort: " + q(provider.ReasoningEffort) + "\n")
		}
		if provider.Timeout != ProviderTimeoutText(DefaultProviderTimeout) {
			out.WriteString("    timeout: " + q(provider.Timeout) + "\n")
		}
	}
	out.WriteString("execution:\n  workspace_access: " + q(config.Execution.WorkspaceAccess) + "\nroles:\n")
	for index, role := range fixedRoles {
		configured := config.Roles.Ordered()[index]
		if role == "artist" && !configured.Enabled {
			continue
		}
		if role == "artist" {
			out.WriteString("  artist:\n    enabled: true\n    primary_provider: " + q(configured.PrimaryProvider) + "\n")
			if configured.CredentialProfile != "" {
				out.WriteString("    credential_profile: " + q(configured.CredentialProfile) + "\n")
			}
			out.WriteString("    inputs:\n      task_path: " + q(configured.Inputs.TaskPath) + "\n      design_spec_globs: " + quotedList(configured.Inputs.DesignSpecGlobs) + "\n")
			continue
		}
		out.WriteString("  " + role + ": {enabled: " + strconv.FormatBool(configured.Enabled) + ", primary_provider: " + q(configured.PrimaryProvider))
		if configured.CredentialProfile != "" {
			out.WriteString(", credential_profile: " + q(configured.CredentialProfile))
		}
		out.WriteString("}\n")
	}
	out.WriteString("review:\n  required_roles: " + quotedList(config.Review.RequiredRoles) + "\n  request_changes_on: " + quotedList(config.Review.RequestChangesOn) + "\n")
	out.WriteString("validation:\n  evidence:\n    require_verified_for: " + quotedList(config.Validation.Evidence.RequireVerifiedFor) + "\n  repair:\n    enabled: " + strconv.FormatBool(config.Validation.Repair.Enabled) + "\n    max_attempts: " + strconv.Itoa(config.Validation.Repair.MaxAttempts) + "\n    same_provider: " + strconv.FormatBool(config.Validation.Repair.SameProvider) + "\n")
	out.WriteString("resources:\n  max_active_lanes: " + strconv.Itoa(config.Resources.MaxActiveLanes) + "\n  primary_repair_attempts: " + strconv.Itoa(config.Resources.PrimaryRepairAttempts) + "\n  role_max_invocations: " + strconv.Itoa(config.Resources.RoleMaxInvocations) + "\n  run_max_invocations: " + strconv.Itoa(config.Resources.RunMaxInvocations) + "\n")
	out.WriteString("ci:\n  fail_on_severity: " + quotedList(config.CI.FailOnSeverity) + "\n  degraded_review_fails: " + strconv.FormatBool(config.CI.DegradedReviewFails) + "\n")
	encoded := []byte(out.String())
	if _, err := Decode(encoded); err != nil {
		return nil, fmt.Errorf("canonical config did not round trip: %w", err)
	}
	return encoded, nil
}

func quotedList(values []string) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Quote(value)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
