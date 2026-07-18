package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const globalSOTFixture = `
version: 1
runtime:
  home: /Users/example
  path:
    inherit: true
    prepend: [/Users/example/.local/bin]
    append: [/opt/homebrew/bin]
  env_allowlist: [HOME, PATH, LANG, LC_ALL]
  max_active_lanes: 3
execution:
  strategy: primary_with_fallback
  workspace_access: readonly_snapshot
  cross_process_lane_lock: true
providers:
  kimi-main:
    driver: kimi
    status: unverified
    bin: kimi
    args: [--json]
    concurrency_key: Kimi-Main
    timeout_sec: 180
    max_stdout_bytes: 262144
    max_stderr_bytes: 262144
  zcode-main:
    driver: zcode
    status: unverified
    bin: zcode
    args: [--json]
    concurrency_key: zcode-main
    timeout_sec: 180
    max_stdout_bytes: 262144
    max_stderr_bytes: 262144
  agy-main:
    driver: agy
    status: unverified
    bin: agy
    args: [--json]
    concurrency_key: agy-main
    timeout_sec: 180
    max_stdout_bytes: 262144
    max_stderr_bytes: 262144
roles:
  logic: {enabled: true}
  security: {enabled: true}
  maintainability: {enabled: true}
  product: {enabled: true}
  documentation: {enabled: true}
  testing: {enabled: true}
review:
  request_changes_on: [high, critical, blocker]
validation:
  reject_unknown_fields: true
  reject_empty_strings: true
  reject_placeholder_values: true
  evidence:
    require_verified_for: [high, critical, blocker]
  repair:
    enabled: true
    max_attempts: 1
    same_provider: true
trust:
  required_roles: [logic, security]
  project_config: trusted_base_only
  project_prompt_overrides: false
  project_prompt_source: target_base
  allow_project_provider_commands: false
  allow_project_shell: false
resources:
  primary_repair_attempts: 1
  fallback_repair_attempts: 1
  role_max_invocations: 4
  run_max_invocations: 24
  run_total_output_cap: 64MiB
ci:
  fail_on_severity: [high, critical, blocker]
  degraded_review_fails: true
artifacts:
  root: .kar
  directory_mode: "0700"
  file_mode: "0600"
  preserve_raw_output: true
safety:
  redact_secrets: true
  secret_output_policy: block
  mutation_detection: true
`

const projectSOTFixture = `
version: 1
trusted_base: true
project:
  name: my-project
  root: .
  context: .kar/context.md
execution:
  workspace_access: none
review:
  required_roles: [logic, security, maintainability, product, documentation, testing]
  request_changes_on: [medium, high, critical, blocker]
roles:
  logic: {enabled: true, guide: builtin:roles/logic@1}
  security: {enabled: true, guide: builtin:roles/security@1}
  maintainability: {enabled: true, guide: builtin:roles/maintainability@1}
  product: {enabled: true, guide: builtin:roles/product@1}
  documentation: {enabled: true, guide: builtin:roles/documentation@1}
  testing: {enabled: true, guide: builtin:roles/testing@1}
validation:
  evidence:
    require_verified_for: [medium, high, critical, blocker]
resources:
  role_max_invocations: 3
  run_max_invocations: 18
  run_total_output_cap: 48MiB
ci:
  fail_on_severity: [medium, high, critical, blocker]
  degraded_review_fails: true
`

func TestDecodeGlobalAcceptsCompactSOTFixtureAndNormalizesConcurrencyKey(t *testing.T) {
	config, err := DecodeGlobal("global.yaml", []byte(globalSOTFixture))
	if err != nil {
		t.Fatalf("DecodeGlobal() error = %v", err)
	}
	if got, want := config.Providers["kimi-main"].ConcurrencyKey, "kimi-main"; got != want {
		t.Fatalf("normalized concurrency key = %q, want %q", got, want)
	}
}

func TestDecodeGlobalRejectsInvalidProviderInstanceID(t *testing.T) {
	input := strings.Replace(globalSOTFixture, "  kimi-main:", "  \"Bad ID\":", 1)
	config, err := DecodeGlobal("global.yaml", []byte(input))
	diagnostic := findDiagnostic(t, err, "invalid_provider_id")
	if diagnostic.Path != `$.providers[<redacted>]` {
		t.Fatalf("diagnostic path = %q, want redacted provider key path", diagnostic.Path)
	}
	if !reflect.DeepEqual(config, GlobalConfig{}) {
		t.Fatalf("rejected config = %#v, want zero value", config)
	}
}

func TestDecodeProjectAcceptsCompactSOTFixtureAndPreservesOmission(t *testing.T) {
	config, err := DecodeProject("project.yaml", []byte(projectSOTFixture))
	if err != nil {
		t.Fatalf("DecodeProject() error = %v", err)
	}
	if config.Resources == nil || config.Resources.RoleMaxInvocations == nil {
		t.Fatal("project resource omission was not preserved")
	}
	if config.CI == nil || config.CI.DegradedReviewFails == nil || !*config.CI.DegradedReviewFails {
		t.Fatal("project CI strengthening value was not preserved")
	}
}

func TestDecodeGlobalRejectsNestedDuplicateAndUnknownFields(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		code string
		path string
	}{
		{
			name: "nested duplicate",
			data: "version: 1\nproviders:\n  kimi:\n    driver: kimi\n    driver: zcode\n",
			code: "duplicate_key",
			path: "$.providers.kimi.driver",
		},
		{
			name: "nested unknown",
			data: "version: 1\nruntime:\n  unknown: true\n",
			code: "unknown_field",
			path: "$.runtime[<redacted>]",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := DecodeGlobal("global.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero GlobalConfig", config)
			}
			diagnostic := findDiagnostic(t, err, test.code)
			if diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want code %q at %q", diagnostic, test.code, test.path)
			}
		})
	}
}

func TestDecodeRejectsDuplicateAndUnknownFieldsAcrossLayerShapes(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		project bool
		data    string
		code    string
	}{
		{"global root duplicate", false, "version: 1\nversion: 1\n", "duplicate_key"},
		{"global provider unknown", false, "version: 1\nproviders:\n  kimi:\n    driver: kimi\n    unknown: true\n", "unknown_field"},
		{"project root duplicate", true, "version: 1\nversion: 1\ntrusted_base: true\n", "duplicate_key"},
		{"project nested unknown", true, "version: 1\ntrusted_base: true\nproject:\n  name: project\n  root: .\n  unknown: true\n", "unknown_field"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.project {
				config, err := DecodeProject("project.yaml", []byte(testCase.data))
				if !reflect.DeepEqual(config, ProjectConfig{}) {
					t.Fatalf("DecodeProject() config = %#v, want zero ProjectConfig", config)
				}
				findDiagnostic(t, err, testCase.code)
				return
			}
			config, err := DecodeGlobal("global.yaml", []byte(testCase.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero GlobalConfig", config)
			}
			findDiagnostic(t, err, testCase.code)
		})
	}
}

func TestDecodeGlobalRejectsAnchorsAliasesAndMultipleDocuments(t *testing.T) {
	anchoredFixture := strings.Replace(globalSOTFixture, "  home: /Users/example", "  home: &home /Users/example", 1)
	for _, test := range []struct {
		name string
		data string
		code string
		path string
	}{
		{
			name: "anchor",
			data: anchoredFixture,
			code: "anchor_forbidden",
			path: "$.runtime.home",
		},
		{
			name: "alias",
			data: strings.Replace(anchoredFixture, "  env_allowlist: [HOME, PATH, LANG, LC_ALL]", "  env_allowlist: [*home, PATH, LANG, LC_ALL]", 1),
			code: "alias_forbidden",
			path: "$.runtime.env_allowlist[0]",
		},
		{
			name: "multiple documents",
			data: globalSOTFixture + "\n---\n" + globalSOTFixture,
			code: "multiple_documents",
			path: "$",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := DecodeGlobal("global.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero GlobalConfig", config)
			}
			diagnostic := findDiagnostic(t, err, test.code)
			if diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want %q", diagnostic, test.path)
			}
		})
	}
}

func TestDiagnosticsCarryLayerSourceCanonicalPathAndLocation(t *testing.T) {
	_, err := DecodeGlobal("configs/global.yaml", []byte("version: 1\nruntime:\n  nope: true\n"))
	diagnostic := findDiagnostic(t, err, "unknown_field")
	if diagnostic.Layer != LayerGlobal || diagnostic.Source != "configs/global.yaml" || diagnostic.Path != "$.runtime[<redacted>]" {
		t.Fatalf("diagnostic identity = %#v", diagnostic)
	}
	if diagnostic.Line != 3 || diagnostic.Column != 3 {
		t.Fatalf("diagnostic location = %d:%d, want 3:3", diagnostic.Line, diagnostic.Column)
	}
}
func TestDecodeRejectsSecretLikeFields(t *testing.T) {
	_, err := DecodeGlobal("global.yaml", []byte("version: 1\nruntime:\n  api_token: value\n"))
	if diagnostic := findDiagnostic(t, err, "secret_like_field"); diagnostic.Path != "$.runtime[<redacted>]" {
		t.Fatalf("diagnostic = %#v, want redacted secret-like field path", diagnostic)
	}
}

func TestDecodeRejectsInvalidConcurrencyAndForbiddenProjectFeatures(t *testing.T) {
	_, err := DecodeGlobal("global.yaml", []byte(strings.Replace(globalSOTFixture, "    concurrency_key: Kimi-Main", "    concurrency_key: café", 1)))
	if diagnostic := findDiagnostic(t, err, "invalid_concurrency_key"); diagnostic.Path != `$.providers["kimi-main"].concurrency_key` {
		t.Fatalf("diagnostic = %#v, want concurrency-key path", diagnostic)
	}

	for _, test := range []struct {
		name string
		data string
	}{
		{
			name: "providers",
			data: "version: 1\ntrusted_base: true\nproject: {name: project, root: ., context: .kar/context.md}\nproviders: {}\n",
		},
		{
			name: "shell",
			data: "version: 1\ntrusted_base: true\nproject: {name: project, root: ., context: .kar/context.md}\nruntime: {shell: sh}\n",
		},
		{
			name: "environment",
			data: "version: 1\ntrusted_base: true\nproject: {name: project, root: ., context: .kar/context.md}\nruntime: {env: {X: y}}\n",
		},
		{
			name: "path traversal",
			data: "version: 1\ntrusted_base: true\nproject: {name: project, root: ., context: ../outside}\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeProject("project.yaml", []byte(test.data))
			if test.name == "path traversal" {
				if diagnostic := findDiagnostic(t, err, "unsafe_path"); diagnostic.Path != "$.project.context" {
					t.Fatalf("diagnostic = %#v, want project context path", diagnostic)
				}
				return
			}
			findDiagnostic(t, err, "forbidden_field")
		})
	}
}

func TestDecodeGlobalRejectsUnsupportedProviderDriversAndReturnsZeroConfigOnError(t *testing.T) {
	for _, driver := range []string{"codex", "claude", "unknown"} {
		t.Run(driver, func(t *testing.T) {
			fixture := strings.Replace(globalSOTFixture, "driver: kimi", "driver: "+driver, 1)
			config, err := DecodeGlobal("global.yaml", []byte(fixture))
			if diagnostic := findDiagnostic(t, err, "invalid_enum"); diagnostic.Path != `$.providers["kimi-main"].driver` {
				t.Fatalf("diagnostic = %#v, want unsupported driver path", diagnostic)
			}
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero GlobalConfig", config)
			}
		})
	}
}

func TestDecodeAuthoritativeSOTExamples(t *testing.T) {
	t.Parallel()

	globalPath := filepath.Join("..", "..", "..", "sot", "examples", "global-config.yaml")
	globalBytes, err := os.ReadFile(globalPath)
	if err != nil {
		t.Fatal(err)
	}
	global, err := DecodeGlobal(globalPath, globalBytes)
	if err != nil {
		t.Fatalf("DecodeGlobal(authoritative example): %v", err)
	}
	wantDrivers := map[string]string{
		"kimi-main":  "kimi",
		"zcode-main": "zcode",
		"agy-main":   "agy",
	}
	if global.Version != 1 || len(global.Providers) != len(wantDrivers) {
		t.Fatalf("authoritative global decode = version %d providers %#v", global.Version, global.Providers)
	}
	for providerID, wantDriver := range wantDrivers {
		provider, ok := global.Providers[providerID]
		if !ok || provider.Driver != wantDriver {
			t.Fatalf("authoritative provider %q = %#v, want driver %q", providerID, provider, wantDriver)
		}
	}

	projectPath := filepath.Join("..", "..", "..", "sot", "examples", "project-config.yaml")
	projectBytes, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	project, err := DecodeProject(projectPath, projectBytes)
	if err != nil {
		t.Fatalf("DecodeProject(authoritative example): %v", err)
	}
	if project.Version != 1 || !project.TrustedBase || project.Project.Name != "my-project" {
		t.Fatalf("authoritative project decode = %#v", project)
	}
}
func TestDecodeRejectsBoundedYAMLAndReturnsZeroValues(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		code    string
		message string
	}{
		{
			name:    "empty",
			data:    nil,
			code:    "empty_document",
			message: "configuration must contain exactly one mapping document",
		},
		{
			name:    "raw size",
			data:    []byte(strings.Repeat("x", maxRawYAMLBytes+1)),
			code:    "yaml_size_limit",
			message: "configuration exceeds the 1 MiB YAML input limit",
		},
		{
			name:    "depth",
			data:    boundedNestedYAML(maxYAMLDepth + 1),
			code:    "yaml_depth_limit",
			message: "configuration exceeds the YAML nesting depth limit",
		},
		{
			name:    "node count",
			data:    []byte("items:\n" + strings.Repeat("  item: value\n", maxYAMLNodes)),
			code:    "yaml_node_limit",
			message: "configuration exceeds the YAML node limit",
		},
		{
			name:    "scalar size",
			data:    []byte("value: " + strings.Repeat("x", maxYAMLScalarBytes+1) + "\n"),
			code:    "yaml_scalar_limit",
			message: "configuration contains a scalar that exceeds the YAML scalar size limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			global, err := DecodeGlobal("bounded.yaml", test.data)
			if !reflect.DeepEqual(global, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero value", global)
			}
			globalDiagnostic := onlyDiagnostic(t, err)
			if globalDiagnostic.Code != test.code || globalDiagnostic.Message != test.message || globalDiagnostic.Path != "$" || globalDiagnostic.Source != "bounded.yaml" {
				t.Fatalf("global diagnostic = %#v", globalDiagnostic)
			}

			project, err := DecodeProject("bounded.yaml", test.data)
			if !reflect.DeepEqual(project, ProjectConfig{}) {
				t.Fatalf("DecodeProject() config = %#v, want zero value", project)
			}
			projectDiagnostic := onlyDiagnostic(t, err)
			if projectDiagnostic.Code != test.code || projectDiagnostic.Message != test.message || projectDiagnostic.Path != "$" || projectDiagnostic.Source != "bounded.yaml" {
				t.Fatalf("project diagnostic = %#v", projectDiagnostic)
			}
		})
	}
}

func TestDecodeRedactsRejectedYAMLDetails(t *testing.T) {
	const secret = "sensitive-value-must-not-appear"
	tests := []struct {
		name     string
		data     string
		code     string
		path     string
		line     int
		column   int
		rejected []string
		decode   func(string, []byte) error
	}{
		{
			name:     "invalid YAML",
			data:     "version: [" + secret,
			code:     "invalid_yaml",
			path:     "$",
			line:     1,
			column:   1,
			rejected: []string{secret},
			decode: func(source string, data []byte) error {
				_, err := DecodeGlobal(source, data)
				return err
			},
		},
		{
			name:     "tag mismatch",
			data:     strings.Replace(globalSOTFixture, "version: 1", "version: "+secret, 1),
			code:     "invalid_node_tag",
			path:     "$.version",
			line:     2,
			column:   10,
			rejected: []string{secret},
			decode: func(source string, data []byte) error {
				_, err := DecodeGlobal(source, data)
				return err
			},
		},
		{
			name:     "unknown key",
			data:     "rejected_private_key: " + secret + "\n",
			code:     "unknown_field",
			path:     "$[<redacted>]",
			line:     1,
			column:   1,
			rejected: []string{"rejected_private_key", secret},
			decode: func(source string, data []byte) error {
				_, err := DecodeGlobal(source, data)
				return err
			},
		},
		{
			name:     "secret-like key",
			data:     "runtime:\n  credential_material: " + secret + "\n",
			code:     "secret_like_field",
			path:     "$.runtime[<redacted>]",
			line:     2,
			column:   3,
			rejected: []string{"credential_material", secret},
			decode: func(source string, data []byte) error {
				_, err := DecodeGlobal(source, data)
				return err
			},
		},
		{
			name:     "forbidden project key",
			data:     "version: 1\ntrusted_base: true\nproject: {name: project, root: .}\nshell: " + secret + "\n",
			code:     "forbidden_field",
			path:     "$[<redacted>]",
			line:     4,
			column:   1,
			rejected: []string{secret},
			decode: func(source string, data []byte) error {
				_, err := DecodeProject(source, data)
				return err
			},
		},
		{
			name:     "noncanonical provider key",
			data:     strings.Replace(globalSOTFixture, "  kimi-main:", "  \"Bad Provider Key\":", 1),
			code:     "invalid_provider_id",
			path:     "$.providers[<redacted>]",
			line:     16,
			column:   3,
			rejected: []string{"Bad Provider Key"},
			decode: func(source string, data []byte) error {
				_, err := DecodeGlobal(source, data)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.decode("rejected.yaml", []byte(test.data))
			diagnostic := findDiagnostic(t, err, test.code)
			if diagnostic.Path != test.path || diagnostic.Line != test.line || diagnostic.Column != test.column {
				t.Fatalf("diagnostic = %#v, want %s at %d:%d", diagnostic, test.path, test.line, test.column)
			}
			assertNoDiagnosticReflection(t, err, test.rejected...)
		})
	}
}
func TestDecodeGlobalRequiresCompleteSafetyPolicy(t *testing.T) {
	tests := []struct {
		name string
		data string
		path string
	}{
		{
			name: "top-level section",
			data: strings.Replace(globalSOTFixture, "safety:\n  redact_secrets: true\n  secret_output_policy: block\n  mutation_detection: true\n", "", 1),
			path: "$.safety",
		},
		{
			name: "safety-critical leaf",
			data: strings.Replace(globalSOTFixture, "  mutation_detection: true\n", "", 1),
			path: "$.safety.mutation_detection",
		},
		{
			name: "provider limit",
			data: strings.Replace(globalSOTFixture, "    max_stderr_bytes: 262144\n", "", 1),
			path: `$.providers["kimi-main"].max_stderr_bytes`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := DecodeGlobal("global.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero value", config)
			}
			diagnostic := findDiagnostic(t, err, "missing_required_field")
			if diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want %q", diagnostic, test.path)
			}
		})
	}
}

func TestDecodeRejectsNullAndPreservesProjectOmission(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		path string
	}{
		{
			name: "global scalar",
			data: strings.Replace(globalSOTFixture, "  strategy: primary_with_fallback", "  strategy: null", 1),
			path: "$.execution.strategy",
		},
		{
			name: "global sequence item",
			data: strings.Replace(globalSOTFixture, "  request_changes_on: [high, critical, blocker]", "  request_changes_on: [null]", 1),
			path: "$.review.request_changes_on[0]",
		},
		{
			name: "global mapping",
			data: strings.Replace(globalSOTFixture, "execution:\n  strategy: primary_with_fallback\n  workspace_access: readonly_snapshot\n  cross_process_lane_lock: true\n", "execution: null\n", 1),
			path: "$.execution",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := DecodeGlobal("global.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero value", config)
			}
			if diagnostic := findDiagnostic(t, err, "null_forbidden"); diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want %q", diagnostic, test.path)
			}
		})
	}

	const omittedProject = "version: 1\ntrusted_base: true\nproject:\n  name: my-project\n  root: .\n"
	config, err := DecodeProject("project.yaml", []byte(omittedProject))
	if err != nil {
		t.Fatalf("DecodeProject(omitted optional policy): %v", err)
	}
	if config.Execution != nil || config.Review != nil || config.Roles != nil || config.Validation != nil || config.Resources != nil || config.CI != nil {
		t.Fatalf("optional project policy was not preserved as nil: %#v", config)
	}

	for _, test := range []struct {
		name string
		data string
		path string
	}{
		{
			name: "optional section",
			data: omittedProject + "execution: null\n",
			path: "$.execution",
		},
		{
			name: "optional leaf",
			data: "version: 1\ntrusted_base: true\nproject: {name: my-project, root: .}\nexecution:\n  workspace_access: null\n",
			path: "$.execution.workspace_access",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := DecodeProject("project.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, ProjectConfig{}) {
				t.Fatalf("DecodeProject() config = %#v, want zero value", config)
			}
			if diagnostic := findDiagnostic(t, err, "null_forbidden"); diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want %q", diagnostic, test.path)
			}
		})
	}
}

func TestDecodeRejectsNonCoreTagsAndInvalidNodeKinds(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		code string
		path string
	}{
		{
			name: "non-core tag",
			data: strings.Replace(globalSOTFixture, "version: 1", "version: !!timestamp 2026-07-14", 1),
			code: "tag_forbidden",
			path: "$.version",
		},
		{
			name: "custom tag",
			data: strings.Replace(globalSOTFixture, "version: 1", "version: !opaque 1", 1),
			code: "tag_forbidden",
			path: "$.version",
		},
		{
			name: "mapping required",
			data: strings.Replace(globalSOTFixture, "runtime:\n", "runtime: []\nignored:\n", 1),
			code: "invalid_node_kind",
			path: "$.runtime",
		},
		{
			name: "sequence required",
			data: strings.Replace(globalSOTFixture, "  request_changes_on: [high, critical, blocker]", "  request_changes_on: high", 1),
			code: "invalid_node_kind",
			path: "$.review.request_changes_on",
		},
		{
			name: "scalar required",
			data: strings.Replace(globalSOTFixture, "version: 1", "version: {value: 1}", 1),
			code: "invalid_node_kind",
			path: "$.version",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeGlobal("global.yaml", []byte(test.data))
			if diagnostic := findDiagnostic(t, err, test.code); diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want %q", diagnostic, test.path)
			}
		})
	}
}
func TestDecodeRejectsCoreTagMismatchesBeforeDecode(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		path string
	}{
		{
			name: "numeric provider command",
			data: strings.Replace(globalSOTFixture, "    bin: kimi", "    bin: 42", 1),
			path: `$.providers["kimi-main"].bin`,
		},
		{
			name: "string boolean",
			data: strings.Replace(globalSOTFixture, "    inherit: true", `    inherit: "true"`, 1),
			path: "$.runtime.path.inherit",
		},
		{
			name: "string integer",
			data: strings.Replace(globalSOTFixture, "version: 1", `version: "1"`, 1),
			path: "$.version",
		},
		{
			name: "numeric string list item",
			data: strings.Replace(globalSOTFixture, "  request_changes_on: [high, critical, blocker]", "  request_changes_on: [1, critical, blocker]", 1),
			path: "$.review.request_changes_on[0]",
		},
		{
			name: "numeric byte size",
			data: strings.Replace(globalSOTFixture, "  run_total_output_cap: 64MiB", "  run_total_output_cap: 64", 1),
			path: "$.resources.run_total_output_cap",
		},
		{
			name: "mapping with sequence tag",
			data: strings.Replace(globalSOTFixture, "runtime:\n", "runtime: !!seq\n", 1),
			path: "$.runtime",
		},
		{
			name: "sequence with mapping tag",
			data: strings.Replace(globalSOTFixture, "  request_changes_on: [high, critical, blocker]", "  request_changes_on: !!map [high, critical, blocker]", 1),
			path: "$.review.request_changes_on",
		},
	} {
		t.Run("global/"+test.name, func(t *testing.T) {
			config, err := DecodeGlobal("global.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, GlobalConfig{}) {
				t.Fatalf("DecodeGlobal() config = %#v, want zero GlobalConfig", config)
			}
			if diagnostic := findDiagnostic(t, err, "invalid_node_tag"); diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want invalid_node_tag at %q", diagnostic, test.path)
			}
		})
	}

	for _, test := range []struct {
		name string
		data string
		path string
	}{
		{
			name: "string boolean",
			data: strings.Replace(projectSOTFixture, "trusted_base: true", `trusted_base: "true"`, 1),
			path: "$.trusted_base",
		},
		{
			name: "boolean project root",
			data: strings.Replace(projectSOTFixture, "  root: .", "  root: true", 1),
			path: "$.project.root",
		},
		{
			name: "string counter",
			data: strings.Replace(projectSOTFixture, "  role_max_invocations: 3", `  role_max_invocations: "3"`, 1),
			path: "$.resources.role_max_invocations",
		},
		{
			name: "numeric byte size",
			data: strings.Replace(projectSOTFixture, "  run_total_output_cap: 48MiB", "  run_total_output_cap: 48", 1),
			path: "$.resources.run_total_output_cap",
		},
		{
			name: "numeric required roles entry",
			data: strings.Replace(projectSOTFixture, "  required_roles: [logic, security, maintainability, product, documentation, testing]", "  required_roles: [1, security, maintainability, product, documentation, testing]", 1),
			path: "$.review.required_roles[0]",
		},
		{
			name: "string role boolean",
			data: strings.Replace(projectSOTFixture, "  logic: {enabled: true, guide: builtin:roles/logic@1}", `  logic: {enabled: "true", guide: builtin:roles/logic@1}`, 1),
			path: "$.roles.logic.enabled",
		},
	} {
		t.Run("project/"+test.name, func(t *testing.T) {
			config, err := DecodeProject("project.yaml", []byte(test.data))
			if !reflect.DeepEqual(config, ProjectConfig{}) {
				t.Fatalf("DecodeProject() config = %#v, want zero ProjectConfig", config)
			}
			if diagnostic := findDiagnostic(t, err, "invalid_node_tag"); diagnostic.Path != test.path {
				t.Fatalf("diagnostic = %#v, want invalid_node_tag at %q", diagnostic, test.path)
			}
		})
	}
}

func TestDecodeRejectsMergeTagsWithoutRejectingQuotedMergeLiteral(t *testing.T) {
	_, err := DecodeGlobal("global.yaml", []byte(strings.Replace(globalSOTFixture, "    inherit: true", "    <<: {inherit: true}", 1)))
	if diagnostic := findDiagnostic(t, err, "merge_forbidden"); diagnostic.Path != "$.runtime.path[<redacted>]" {
		t.Fatalf("diagnostic = %#v, want redacted merge path", diagnostic)
	}

	_, err = DecodeGlobal("global.yaml", []byte(strings.Replace(globalSOTFixture, "    inherit: true", "    \"<<\": true", 1)))
	if hasDiagnostic(err, "merge_forbidden") {
		t.Fatalf("quoted merge literal produced merge diagnostic: %v", err)
	}
	if diagnostic := findDiagnostic(t, err, "unknown_field"); diagnostic.Path != "$.runtime.path[<redacted>]" {
		t.Fatalf("diagnostic = %#v, want unknown-field path", diagnostic)
	}
}

func TestDecodePreservesSafeYAMLTagValidationCoordinates(t *testing.T) {
	const rejected = "not-a-number"
	data := strings.Replace(globalSOTFixture, "  max_active_lanes: 3", "  max_active_lanes: "+rejected, 1)
	_, err := DecodeGlobal("global.yaml", []byte(data))
	diagnostic := findDiagnostic(t, err, "invalid_node_tag")
	if diagnostic.Line != 10 || diagnostic.Column < 1 {
		t.Fatalf("diagnostic location = %d:%d, want line 10 with a positive column", diagnostic.Line, diagnostic.Column)
	}
	assertNoDiagnosticReflection(t, err, rejected)
}

func TestDiagnosticsSortAndSanitizeSourceLabels(t *testing.T) {
	err := newDiagnosticError([]Diagnostic{
		{Line: 2, Column: 2, Path: "$.b", Code: "alpha"},
		{Line: 2, Column: 2, Path: "$.a", Code: "zulu"},
		{Line: 1, Column: 1, Path: "$.z", Code: "first"},
		{Line: 2, Column: 2, Path: "$.a", Code: "alpha"},
	})
	diagnosticError, ok := AsDiagnosticError(err)
	if !ok {
		t.Fatalf("error = %T %v, want DiagnosticError", err, err)
	}
	diagnostics := diagnosticError.Diagnostics()
	for index, want := range []string{"first", "alpha", "zulu", "alpha"} {
		if diagnostics[index].Code != want {
			t.Fatalf("diagnostics = %#v, want code %q at index %d", diagnostics, want, index)
		}
	}

	_, fixedErr := DecodeGlobal("configs/global.yaml", []byte("version: null\n"))
	if diagnostic := findDiagnostic(t, fixedErr, "null_forbidden"); diagnostic.Source != "configs/global.yaml" {
		t.Fatalf("fixed source = %q", diagnostic.Source)
	}

	hostileSource := "config\nlabel\t" + strings.Repeat("x", maxSourceLabelBytes)
	_, hostileErr := DecodeGlobal(hostileSource, []byte("version: null\n"))
	diagnostic := findDiagnostic(t, hostileErr, "null_forbidden")
	if len(diagnostic.Source) > maxSourceLabelBytes || strings.ContainsAny(diagnostic.Source, "\n\r\t") {
		t.Fatalf("unsafe source label = %q", diagnostic.Source)
	}
	if !strings.HasPrefix(diagnostic.Source, `config\nlabel\t`) || !strings.HasSuffix(diagnostic.Source, "...") {
		t.Fatalf("source label was not escaped and bounded: %q", diagnostic.Source)
	}
}

func boundedNestedYAML(depth int) []byte {
	var data strings.Builder
	for level := 0; level < depth; level++ {
		data.WriteString(strings.Repeat("  ", level))
		data.WriteString("nested:\n")
	}
	data.WriteString(strings.Repeat("  ", depth))
	data.WriteString("value: true\n")
	return []byte(data.String())
}

func assertNoDiagnosticReflection(t *testing.T, err error, rejected ...string) {
	t.Helper()
	diagnosticError, ok := AsDiagnosticError(err)
	if !ok {
		t.Fatalf("error = %T %v, want DiagnosticError", err, err)
	}
	for _, value := range rejected {
		if strings.Contains(err.Error(), value) {
			t.Errorf("error reflected rejected YAML detail %q: %v", value, err)
		}
		for _, diagnostic := range diagnosticError.Diagnostics() {
			for _, field := range []string{diagnostic.Source, diagnostic.Path, diagnostic.Message} {
				if strings.Contains(field, value) {
					t.Errorf("diagnostic reflected rejected YAML detail %q: %#v", value, diagnostic)
				}
			}
		}
	}
}

func onlyDiagnostic(t *testing.T, err error) Diagnostic {
	t.Helper()
	diagnosticError, ok := AsDiagnosticError(err)
	if !ok {
		t.Fatalf("error = %T %v, want DiagnosticError", err, err)
	}
	diagnostics := diagnosticError.Diagnostics()
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want one diagnostic", diagnostics)
	}
	return diagnostics[0]
}
func hasDiagnostic(err error, code string) bool {
	diagnosticError, ok := AsDiagnosticError(err)
	if !ok {
		return false
	}
	for _, diagnostic := range diagnosticError.Diagnostics() {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func findDiagnostic(t *testing.T, err error, code string) Diagnostic {
	t.Helper()
	diagnosticError, ok := AsDiagnosticError(err)
	if !ok {
		t.Fatalf("error = %T %v, want DiagnosticError", err, err)
	}
	for _, diagnostic := range diagnosticError.Diagnostics() {
		if diagnostic.Code == code {
			return diagnostic
		}
	}
	t.Fatalf("diagnostics do not contain %q: %#v", code, diagnosticError.Diagnostics())
	return Diagnostic{}
}
