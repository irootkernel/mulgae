package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func validConfig() Config {
	enabled := RoleConfig{Enabled: true}
	return Config{
		Version:    1,
		Project:    ProjectConfig{Name: "project", Context: ".kar-context.md"},
		NativeUser: NativeUserConfig{Home: "/Users/test"},
		Providers:  ProvidersConfig{Kimi: &KimiProviderConfig{Executable: "/usr/local/bin/kimi", Model: DefaultKimiModel, DataHome: "/Users/test/.kimi-code"}},
		Execution:  ExecutionConfig{WorkspaceAccess: "none"},
		Roles: RolesConfig{
			Logic:           enabled,
			Security:        enabled,
			Maintainability: enabled,
			Product:         enabled,
			Documentation:   enabled,
			Testing:         enabled,
		},
		Review:     ReviewConfig{RequiredRoles: []string{"logic", "security"}, RequestChangesOn: []string{"high", "critical", "blocker"}},
		Validation: ValidationConfig{Evidence: EvidenceConfig{RequireVerifiedFor: []string{"high", "critical", "blocker"}}, Repair: RepairConfig{Enabled: true, MaxAttempts: 1, SameProvider: true}},
		Resources:  ResourcesConfig{MaxActiveLanes: 3, PrimaryRepairAttempts: 1, FallbackRepairAttempts: 1, RoleMaxInvocations: 2, RunMaxInvocations: 12, RunTotalOutputCap: "64MiB"},
		CI:         CIConfig{FailOnSeverity: []string{"high", "critical", "blocker"}, DegradedReviewFails: true},
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
		if config.Providers.Count() >= 2 {
			config.Resources.RoleMaxInvocations = 4
			config.Resources.RunMaxInvocations = 24
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
	for _, value := range []string{"kimi-code/k3", "/usr/local/bin/kimi", strings.Repeat("a", 64), "019f7e98-c3b2-7000-8c62-1baabe37bae9", "https://github.com/example/repo/issues/1", "Bearer", "ordinary prose mentioning token", "${TOKEN}"} {
		if credentialValue(value) {
			t.Fatalf("negative credential value %q matched", value)
		}
	}
}

func TestDecodeRejectsExplicitEmptyControlPlaceholderAndNoncanonicalUnknownKey(t *testing.T) {
	base, _ := EncodeCanonical(validConfig())
	cases := []string{
		strings.Replace(string(base), "  context: \".kar-context.md\"\n", "  context: \"\"\n", 1),
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
	config.Resources.RoleMaxInvocations = 4
	config.Resources.RunMaxInvocations = 24
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

func bytesOf(value byte, length int) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = value
	}
	return result
}
