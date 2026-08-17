package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	roles, err := CanonicalRolesConfig(testRoleDefaults(), []string{"kimi"})
	if err != nil {
		panic(err)
	}
	return Config{
		Version:    ConfigVersion,
		Project:    ProjectConfig{Name: "project", Context: ".mulgae-context.md"},
		NativeUser: NativeUserConfig{Home: "/Users/test"},
		Providers:  ProvidersConfig{Kimi: &KimiProviderConfig{Executable: "/usr/local/bin/kimi", Model: DefaultKimiModel, DataHome: "/Users/test/.kimi-code"}},
		Execution:  ExecutionConfig{WorkspaceAccess: "none"},
		Roles:      roles,
		Review:     ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}},
		Validation: ValidationConfig{Evidence: EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}},
		Resources:  ResourcesConfig{MaxActiveLanes: 3, PrimaryRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 12},
		CI:         CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true},
	}
}

func TestProviderTimeoutDefaultsPreserveConfigV1CanonicalBytes(t *testing.T) {
	config := validConfig()
	canonical, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("timeout:")) {
		t.Fatalf("default timeout was emitted:\n%s", canonical)
	}
	decoded, err := Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.Kimi.Timeout != "60m" {
		t.Fatalf("omitted timeout resolved to %q", decoded.Providers.Kimi.Timeout)
	}
	rendered, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, canonical) {
		t.Fatalf("legacy canonical bytes changed:\n%s", rendered)
	}

	config.Providers.Kimi.Timeout = "60m"
	rendered, err = EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, canonical) {
		t.Fatal("explicit default did not canonicalize to the omitted form")
	}
}

func TestAGYHeadlessDefaultPreservesOmittedConfigV1CanonicalBytes(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{AGY: &AGYProviderConfig{Executable: "/usr/local/bin/agy"}}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())

	canonical, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("permission_mode:")) {
		t.Fatalf("headless default was emitted:\n%s", canonical)
	}
	decoded, err := Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Providers.AGY.PermissionMode != DefaultAGYPermissionMode {
		t.Fatalf("omitted AGY permission mode resolved to %q", decoded.Providers.AGY.PermissionMode)
	}
	rendered, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, canonical) {
		t.Fatalf("omitted Config v3 bytes changed:\n%s", rendered)
	}

	legacyExplicit := bytes.Replace(
		canonical,
		[]byte("    executable: \"/usr/local/bin/agy\"\n"),
		[]byte("    executable: \"/usr/local/bin/agy\"\n    permission_mode: \"dangerously-skip-permissions\"\n"),
		1,
	)
	decodedLegacy, err := Decode(legacyExplicit)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedLegacy.Providers.AGY.PermissionModeExplicit {
		t.Fatal("legacy explicit headless mode lost its presence marker")
	}
	renderedLegacy, err := EncodeCanonical(decodedLegacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(renderedLegacy, legacyExplicit) {
		t.Fatalf("explicit Config v3 bytes changed:\n%s", renderedLegacy)
	}

	config.Providers.AGY.PermissionMode = SafeAGYPermissionMode
	config.Providers.AGY.PermissionModeExplicit = true
	safe, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(safe, []byte(`permission_mode: "safe"`)) {
		t.Fatalf("explicit safe mode was omitted:\n%s", safe)
	}
}

func TestProviderTimeoutNonDefaultsRoundTripCanonically(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{
		Kimi:  &KimiProviderConfig{Executable: "/usr/local/bin/kimi", Model: DefaultKimiModel, DataHome: DefaultKimiDataHome(config.NativeUser.Home), Timeout: "1m"},
		ZCode: &ZCodeProviderConfig{NodeExecutable: "/usr/local/bin/node", Launcher: "/Applications/ZCode.app/zcode.cjs", Timeout: "30m"},
		AGY:   &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: DefaultAGYPermissionMode, Timeout: "45m"},
		Codex: &CodexProviderConfig{Executable: "/usr/local/bin/codex", Model: "gpt-5.3-codex", ReasoningEffort: "high", Timeout: "20m"},
	}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 12
	canonical, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`timeout: "1m"`, `timeout: "30m"`, `timeout: "45m"`, `timeout: "20m"`, `model: "gpt-5.3-codex"`, `reasoning_effort: "high"`} {
		if !bytes.Contains(canonical, []byte(field)) {
			t.Fatalf("canonical config omitted %s:\n%s", field, canonical)
		}
	}
	decoded, err := Decode(canonical)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, canonical) {
		t.Fatal("non-default provider timeouts were not canonical")
	}
	if timeout, _ := ParseProviderTimeout(decoded.Providers.ZCode.Timeout); timeout != 30*time.Minute {
		t.Fatalf("zcode timeout = %s", timeout)
	}
	if decoded.Providers.Codex.Model != "gpt-5.3-codex" || decoded.Providers.Codex.ReasoningEffort != "high" {
		t.Fatalf("Codex settings = %#v", decoded.Providers.Codex)
	}
}

func TestCodexCredentialProfilesRoundTripAcrossSplitAuthorities(t *testing.T) {
	config := validConfig()
	config.Providers = ProvidersConfig{Codex: &CodexProviderConfig{
		Executable: "/usr/local/bin/codex", DefaultCredentialProfile: "personal",
		CredentialHomes: []CodexCredentialHomeConfig{{Profile: "personal", Home: "/Users/test/.codex"}, {Profile: "work", Home: "/Users/test/.codex-work"}},
		ReasoningEffort: "high", Timeout: "20m",
	}}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	config.Roles.Security.CredentialProfile = "work"
	project, local, err := EncodeSplit(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`default_credential_profile: "personal"`, `credential_profile: "work"`} {
		if !bytes.Contains(project, []byte(fragment)) {
			t.Fatalf("project config omitted %s:\n%s", fragment, project)
		}
	}
	for _, fragment := range []string{`credential_homes:`, `profile: "personal"`, `home: "/Users/test/.codex"`, `profile: "work"`, `home: "/Users/test/.codex-work"`} {
		if !bytes.Contains(local, []byte(fragment)) {
			t.Fatalf("local config omitted %s:\n%s", fragment, local)
		}
	}
	decoded, err := DecodeSplit(project, local)
	if err != nil {
		t.Fatal(err)
	}
	workHome, _ := decoded.Providers.Codex.CredentialHome("work")
	if decoded.Providers.Codex.DefaultCredentialProfile != "personal" || decoded.Roles.Security.CredentialProfile != "work" || workHome != "/Users/test/.codex-work" {
		t.Fatalf("credential profiles did not round trip: %#v", decoded.Providers.Codex)
	}
	effective, err := EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(effective); err != nil {
		t.Fatalf("effective credential profile config did not round trip: %v\n%s", err, effective)
	}
}

func TestCodexCredentialProfilesRejectIncompleteOrCrossFamilyAssignments(t *testing.T) {
	base := validConfig()
	base.Providers = ProvidersConfig{Codex: &CodexProviderConfig{
		Executable: "/usr/local/bin/codex", DefaultCredentialProfile: "codex",
		CredentialHomes: []CodexCredentialHomeConfig{{Profile: "codex", Home: "/Users/test/.codex"}, {Profile: "unused", Home: "/Users/test/.codex-unused"}},
	}}
	base.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), base.Providers.Families())
	if _, _, err := EncodeSplit(base); err == nil {
		t.Fatal("unused credential profile was accepted")
	}
	base.Providers.Codex.CredentialHomes = []CodexCredentialHomeConfig{{Profile: "codex", Home: "/Users/test/.codex"}}
	base.Roles.Logic.CredentialProfile = "missing"
	if _, _, err := EncodeSplit(base); err == nil {
		t.Fatal("missing role credential profile was accepted")
	}
	base = validConfig()
	base.Roles.Logic.CredentialProfile = "codex"
	if _, _, err := EncodeSplit(base); err == nil {
		t.Fatal("non-Codex role credential profile was accepted")
	}
}

func TestProviderTimeoutRejectsInvalidZeroAndOutOfRangeValues(t *testing.T) {
	for _, value := range []string{"invalid", "0s", "-1m", "59s", "60m1s", "61m"} {
		t.Run(value, func(t *testing.T) {
			config := validConfig()
			config.Providers.Kimi.Timeout = value
			if _, err := EncodeCanonical(config); err == nil || !strings.Contains(err.Error(), "provider timeout must be a duration from 1m through 60m") {
				t.Fatalf("timeout %q err=%v", value, err)
			}
		})
	}
	canonical, err := EncodeCanonical(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	invalid := strings.Replace(string(canonical), "providers:\n", "providers:\n", 1)
	invalid = strings.Replace(invalid, "    executable: \"/usr/local/bin/kimi\"\n", "    executable: \"/usr/local/bin/kimi\"\n    timeout: \"0s\"\n", 1)
	_, err = Decode([]byte(invalid))
	admission, ok := AsAdmissionError(err)
	if !ok || admission.Reason() != ReasonProviderTimeoutInvalid {
		t.Fatalf("invalid timeout reason = %v", err)
	}
}

func TestProviderTimeoutCanonicalizesEquivalentDurationSpellings(t *testing.T) {
	config := validConfig()
	config.Providers.Kimi.Timeout = "1800s"
	canonical, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(`timeout: "30m"`)) || bytes.Contains(canonical, []byte("1800s")) {
		t.Fatalf("duration was not normalized:\n%s", canonical)
	}
}

func TestCanonicalRoundTripSupportsEveryProviderSubset(t *testing.T) {
	for mask := 1; mask < 8; mask++ {
		config := validConfig()
		config.Providers = ProvidersConfig{}
		if mask&1 != 0 {
			config.Providers.Kimi = &KimiProviderConfig{Executable: "/usr/local/bin/kimi", Model: DefaultKimiModel, DataHome: DefaultKimiDataHome(config.NativeUser.Home)}
		}
		if mask&2 != 0 {
			config.Providers.ZCode = &ZCodeProviderConfig{NodeExecutable: "/usr/local/bin/node", Launcher: "/Applications/ZCode.app/zcode.cjs"}
		}
		if mask&4 != 0 {
			config.Providers.AGY = &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: "safe"}
		}
		config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
		if config.Providers.Count() >= 2 {
			config.Resources.RoleMaxInvocations = 2
			config.Resources.RunMaxInvocations = 12
		}
		encoded, err := EncodeCanonical(config)
		if err != nil {
			t.Fatalf("mask %d encode: %v", mask, err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("mask %d decode: %v\n%s", mask, err, encoded)
		}
		if got := strings.Join(decoded.Providers.Families(), ","); got != strings.Join(config.Providers.Families(), ",") {
			t.Fatalf("mask %d families=%s", mask, got)
		}
	}
}

// TestConfigRejectsRemovedFallbackKeys proves a configuration written before
// cross-provider fallback was removed is refused rather than silently reread
// with the keys ignored. A role is bound to exactly one provider, so a stored
// fallback route no longer means anything and honouring it halfway would be
// worse than asking the operator to run `mulgae init` again.
func TestConfigRejectsRemovedFallbackKeys(t *testing.T) {
	t.Parallel()

	config := validConfig()
	config.Providers = ProvidersConfig{
		ZCode: &ZCodeProviderConfig{NodeExecutable: "/usr/local/bin/node", Launcher: "/Applications/ZCode.app/zcode.cjs"},
		AGY:   &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: DefaultAGYPermissionMode},
	}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	encoded, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("canonical config was rejected before mutation: %v", err)
	}

	for _, test := range []struct {
		name     string
		anchor   string
		replaced string
	}{
		{
			name:     "role fallback provider",
			anchor:   `logic: {enabled: true, primary_provider: "zcode"}`,
			replaced: `logic: {enabled: true, primary_provider: "zcode", fallback_provider: "agy"}`,
		},
		{
			name:     "fallback repair attempts",
			anchor:   "  primary_repair_attempts: 1\n",
			replaced: "  primary_repair_attempts: 1\n  fallback_repair_attempts: 1\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(string(encoded), test.anchor) {
				t.Fatalf("canonical config does not contain %q:\n%s", test.anchor, encoded)
			}
			legacy := strings.Replace(string(encoded), test.anchor, test.replaced, 1)
			if _, err := Decode([]byte(legacy)); err == nil {
				t.Fatalf("a configuration carrying %s was accepted:\n%s", test.name, legacy)
			}
		})
	}
}

func TestConfigV1RoleAssignmentsAndFutureVersionRejection(t *testing.T) {
	config := validConfig()
	config.Providers.ZCode = &ZCodeProviderConfig{NodeExecutable: "/usr/local/bin/node", Launcher: "/Applications/ZCode.app/zcode.cjs"}
	config.Providers.AGY = &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: "safe"}
	config.Roles, _ = CanonicalRolesConfig(testRoleDefaults(), config.Providers.Families())
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 12
	encoded, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	// Every core role is pinned end to end, so a change to any one of them in
	// assets/roles.yaml is visible here rather than silently shipping.
	for _, expected := range []string{
		`logic: {enabled: true, primary_provider: "kimi"}`,
		`security: {enabled: true, primary_provider: "zcode"}`,
		`maintainability: {enabled: true, primary_provider: "zcode"}`,
		`product: {enabled: true, primary_provider: "zcode"}`,
		`documentation: {enabled: true, primary_provider: "agy"}`,
		`testing: {enabled: true, primary_provider: "zcode"}`,
	} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("canonical config omitted %q:\n%s", expected, encoded)
		}
	}
	future := strings.Replace(string(encoded), "version: 3", "version: 4", 1)
	if _, err := Decode([]byte(future)); err == nil {
		t.Fatal("future config version was accepted")
	}
	invalid := config
	invalid.Roles.Logic.PrimaryProvider = "unknown"
	if _, err := EncodeCanonical(invalid); err == nil {
		t.Fatal("role provider outside the configured families was accepted")
	}
}

func TestConfigV1RoundTripsArtistBriefPath(t *testing.T) {
	config := validConfig()
	config.Project.Kind = ProjectKindUI
	config.Providers = ProvidersConfig{AGY: &AGYProviderConfig{Executable: "/usr/local/bin/agy", PermissionMode: "safe"}}
	roles, err := CanonicalRolesConfigForUI(testRoleDefaults(), config.Providers.Families())
	if err != nil {
		t.Fatal(err)
	}
	roles.Artist.Inputs.TaskPath = "docs/artist-brief.md"
	config.Roles = roles
	config.Resources.MaxActiveLanes = 7
	config.Resources.RunMaxInvocations = 14
	encoded, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Roles.Artist.Inputs == nil || decoded.Roles.Artist.Inputs.TaskPath != "docs/artist-brief.md" || !bytes.Contains(encoded, []byte(`task_path: "docs/artist-brief.md"`)) {
		t.Fatalf("artist brief path did not round-trip:\n%s", encoded)
	}
}

func TestConfigV1AllowsUIWithoutArtist(t *testing.T) {
	config := validConfig()
	config.Project.Kind = ProjectKindUI
	encoded, err := EncodeCanonical(config)
	if err != nil {
		t.Fatalf("encode UI config without artist: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode UI config without artist: %v", err)
	}
	if decoded.Roles.Artist.Enabled || decoded.Roles.Artist.PrimaryProvider != "" || decoded.Roles.Artist.Inputs != nil {
		t.Fatalf("disabled UI artist role gained configuration: %#v", decoded.Roles.Artist)
	}
}

func TestConfigSupportsProjectRoleSubsetButKeepsRequiredFloorEnabled(t *testing.T) {
	config := validConfig()
	roles, err := CanonicalRolesConfigForSelection(testRoleDefaults(), []string{"kimi"}, []string{"logic", "security", "documentation"})
	if err != nil {
		t.Fatal(err)
	}
	config.Roles = roles
	config.Resources.MaxActiveLanes = 3
	config.Resources.RunMaxInvocations = 6
	encoded, err := EncodeCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Roles.Logic.Enabled || !decoded.Roles.Security.Enabled || !decoded.Roles.Documentation.Enabled || decoded.Roles.Testing.Enabled {
		t.Fatalf("decoded subset = %#v", decoded.Roles)
	}

	config.Review.RequiredRoles = []string{"logic", "security", "testing"}
	if _, err := EncodeCanonical(config); err == nil {
		t.Fatal("disabled required role was accepted")
	}
	config.Review.RequiredRoles = []string{"logic"}
	if _, err := EncodeCanonical(config); err != nil {
		t.Fatalf("logic-only required floor was rejected: %v", err)
	}
}

func TestDecodeRejectsUnknownDuplicateNullAliasAndBounds(t *testing.T) {
	base, _ := EncodeCanonical(validConfig())
	cases := [][]byte{
		append(base, []byte("unknown: true\n")...),
		[]byte("version: 1\nversion: 1\n"),
		[]byte("version: null\n"),
		[]byte("version: &v 1\nproject: *v\n"),
		bytesOf('x', MaximumConfigBytes+1),
	}
	for index, input := range cases {
		if _, err := Decode(input); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestBoundedYAMLParserHonorsExactNodeDepthScalarAndFileLimits(t *testing.T) {
	scalarAtLimit := "value: \"" + strings.Repeat("a", maxYAMLScalarBytes) + "\"\n"
	if _, err := parseBoundedDocument([]byte(scalarAtLimit)); err != nil {
		t.Fatalf("scalar at limit rejected: %v", err)
	}
	if _, err := parseBoundedDocument([]byte("value: \"" + strings.Repeat("a", maxYAMLScalarBytes+1) + "\"\n")); err == nil {
		t.Fatal("scalar above limit accepted")
	}

	nodesAtLimit := "values: [" + strings.Repeat("a,", maxYAMLNodes-4) + "a]\n"
	if _, err := parseBoundedDocument([]byte(nodesAtLimit)); err != nil {
		t.Fatalf("node count at limit rejected: %v", err)
	}
	if _, err := parseBoundedDocument([]byte("values: [" + strings.Repeat("a,", maxYAMLNodes-3) + "a]\n")); err == nil {
		t.Fatal("node count above limit accepted")
	}

	depthAtLimit := "value: " + strings.Repeat("[", maxYAMLDepth-2) + "a" + strings.Repeat("]", maxYAMLDepth-2) + "\n"
	if _, err := parseBoundedDocument([]byte(depthAtLimit)); err != nil {
		t.Fatalf("depth at limit rejected: %v", err)
	}
	if _, err := parseBoundedDocument([]byte("value: " + strings.Repeat("[", maxYAMLDepth-1) + "a" + strings.Repeat("]", maxYAMLDepth-1) + "\n")); err == nil {
		t.Fatal("depth above limit accepted")
	}

	fileAtLimit := append([]byte("value: true\n#"), bytes.Repeat([]byte("x"), MaximumConfigBytes-len("value: true\n#"))...)
	if _, err := parseBoundedDocument(fileAtLimit); err != nil {
		t.Fatalf("file at limit rejected: %v", err)
	}
	if _, err := parseBoundedDocument(append(fileAtLimit, 'x')); err == nil {
		t.Fatal("file above limit accepted")
	}
}

func TestCredentialDetectorUsesReasonOnlyAndBoundaries(t *testing.T) {
	base, _ := EncodeCanonical(validConfig())
	for _, suffix := range []string{"api_key: value\n", "API-Key: value\n", "client.secret: value\n", "auth token: value\n", "note: sk_1234567890123456\n", "note: bEaReR 1234567890123456\n", "note: Basic QUJDRA==\n", "note: https://u:p@example.test\n", "note: AKIA1234567890ABCDEF\n", "note: ASIA1234567890ABCDEF\n", "note: AIza12345678901234567890123456789012345\n", "note: '-----BEGIN PRIVATE KEY-----'\n", "note: '-----BEGIN RSA PRIVATE KEY-----'\n", "note: '-----BEGIN EC PRIVATE KEY-----'\n", "note: '-----BEGIN OPENSSH PRIVATE KEY-----'\n", "note: '-----BEGIN ENCRYPTED PRIVATE KEY-----'\n", "note: '-----BEGIN DSA PRIVATE KEY-----'\n"} {
		_, err := Decode(append(base, []byte(suffix)...))
		admission, ok := AsAdmissionError(err)
		if !ok || (admission.Reason() != ReasonCredentialKeyDetected && admission.Reason() != ReasonCredentialValueDetected) || strings.Contains(err.Error(), "123456") {
			t.Fatalf("credential %q err=%v", suffix, err)
		}
	}
	for _, value := range []string{"-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----", "-----begin openssh private key-----"} {
		if !credentialValue(value) {
			t.Fatalf("PEM private-key header %q missed", value)
		}
	}
	for key := range credentialKeys {
		if !credentialKey(key) || !credentialKey("prefix."+key) {
			t.Fatalf("credential key %q missed", key)
		}
	}
	for _, value := range []string{
		"sk-1234567890123456", "sk_1234567890123456", "ghp_1234567890123456", "github_pat_1234567890123456",
		"xoxb-1234567890123456", "xoxp-1234567890123456", "xoxa-1234567890123456", "xoxr-1234567890123456",
	} {
		if !credentialValue(value) {
			t.Fatalf("credential prefix %q missed", value[:4])
		}
	}
	if credentialValue("sk_123456789012345") || !credentialValue("sk_1234567890123456") || credentialValue("sk_123456789012345!") {
		t.Fatal("fixed-prefix token boundary mismatch")
	}
	if credentialValue("Bearer "+strings.Repeat("a", 15)) || !credentialValue("Bearer "+strings.Repeat("a", 16)) || !credentialValue("Bearer "+strings.Repeat("a", 4096)) || credentialValue("Bearer "+strings.Repeat("a", 4097)) {
		t.Fatal("bearer boundary mismatch")
	}
	basic4096 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 3072))
	if credentialValue("Basic AAAAAAA") || !credentialValue("Basic QUJDRA==") || len(basic4096) != 4096 || !credentialValue("Basic "+basic4096) || credentialValue("Basic "+basic4096+"A") {
		t.Fatal("basic boundary mismatch")
	}
	if credentialKey("tokenization") || credentialKey("key") || credentialKey("model") || credentialKey("sha256") {
		t.Fatal("negative credential key matched")
	}
	for _, value := range []string{"kimi-code/kimi-for-coding", "/usr/local/bin/kimi", strings.Repeat("a", 64), "019f7e98-c3b2-7000-8c62-1baabe37bae9", "https://github.com/example/repo/issues/1", "Bearer", "ordinary prose mentioning token", "${TOKEN}"} {
		if credentialValue(value) {
			t.Fatalf("negative credential value %q matched", value)
		}
	}
}

func TestDecodeRejectsExplicitEmptyControlPlaceholderAndNoncanonicalUnknownKey(t *testing.T) {
	base, _ := EncodeCanonical(validConfig())
	cases := []string{
		strings.Replace(string(base), "  context: \".mulgae-context.md\"\n", "  context: \"\"\n", 1),
		strings.Replace(string(base), "name: \"project\"", "name: \"project\\tname\"", 1),
		strings.Replace(string(base), "name: \"project\"", "name: \"${PROJECT}\"", 1),
		string(base) + "Unknown-Key: true\n",
	}
	for index, input := range cases {
		_, err := Decode([]byte(input))
		admission, ok := AsAdmissionError(err)
		if !ok || admission.Reason() != ReasonYAMLInvalid {
			t.Fatalf("case %d reason=%v err=%v", index, admission, err)
		}
	}
}

func TestDecodeRejectsBudgetAndPermissionContradictions(t *testing.T) {
	config := validConfig()
	config.Providers.AGY = &AGYProviderConfig{Executable: "/bin/agy", PermissionMode: "inferred"}
	config.Resources.RoleMaxInvocations = 2
	config.Resources.RunMaxInvocations = 12
	encoded, _ := EncodeCanonical(validConfig())
	invalid := strings.Replace(string(encoded), "providers:\n", "providers:\n  agy:\n    executable: \"/bin/agy\"\n    permission_mode: \"inferred\"\n", 1)
	if _, err := Decode([]byte(invalid)); err == nil {
		t.Fatal("inferred permission accepted")
	}
	config = validConfig()
	config.Resources.RoleMaxInvocations = 1
	if _, err := EncodeCanonical(config); err == nil {
		t.Fatal("under-budget config accepted")
	}
}

func TestDecodeRejectsOmittedLegacyWorkspaceAndShellModes(t *testing.T) {
	t.Parallel()

	base, err := EncodeCanonical(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"omitted workspace access": strings.Replace(string(base), "execution:\n  workspace_access: \"none\"\n", "execution: {}\n", 1),
		"legacy project workspace": strings.Replace(string(base), "workspace_access: \"none\"", "workspace_access: \"project\"", 1),
		"shell mode":               strings.Replace(string(base), "workspace_access: \"none\"", "workspace_access: \"none\"\n  shell: true", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("unsafe or incomplete execution mode was accepted")
			}
		})
	}
}

func bytesOf(value byte, length int) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = value
	}
	return result
}
