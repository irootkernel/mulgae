package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func testZCodeLegacyConfig(apiKey string) string {
	encoded, err := json.Marshal(map[string]any{
		"model": "zai/GLM-5.2",
		"provider": map[string]any{
			"zai": map[string]any{
				"kind": "anthropic", "name": "Z.ai",
				"options": map[string]any{"apiKey": apiKey, "baseURL": "https://api.z.ai/api/anthropic"},
				"models":  map[string]any{"GLM-5.2": map[string]any{"limit": map[string]any{"context": 1_000_000}}},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func TestCredentialSourceProjectsOnlyDeclaredFamilyFiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	cases := []struct {
		name        string
		family      CredentialSourceFamily
		source      string
		destination ports.CredentialProjectionDestination
		contents    string
		wantSeeds   int
	}{
		{"zcode_config", CredentialSourceZCode, ".zcode/cli/config.json", ports.CredentialProjectionZCodeConfig, testZCodeLegacyConfig("secret"), 2},
		{"grok_auth", CredentialSourceGrok, ".grok/auth.json", ports.CredentialProjectionGrokAuth, "declared", 1},
		{"codex_auth", CredentialSourceCodex, ".codex/auth.json", ports.CredentialProjectionCodexAuth, "declared", 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			home := credentialSourceTempDir(t)
			writeCredentialSource(t, home, test.source, test.contents)
			base, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			families := map[string]CredentialSourceFamily{"provider": test.family}
			var factory ports.ProviderNamespaceFactory
			factory, err = NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, home, families, map[string]RuntimeSafetyPolicy{"provider": mustCredentialSourcePolicy(t, test.family)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "provider", string(test.family))
			if err != nil {
				t.Fatal(err)
			}
			defer lease.DrainTerminal(context.Background())
			concrete := lease.(*namespaceLease)
			path, ok := credentialDestination(test.destination)
			if !ok {
				t.Fatal("unknown destination")
			}
			bytes, err := os.ReadFile(filepath.Join(concrete.root, path))
			if err != nil || string(bytes) != test.contents {
				t.Fatalf("declared source not projected: %v", err)
			}
			if len(concrete.seeds) != test.wantSeeds {
				t.Fatalf("projected %d files, want %d", len(concrete.seeds), test.wantSeeds)
			}
			if test.family == CredentialSourceZCode {
				providerPath, _ := credentialDestination(ports.CredentialProjectionZCodeProviderConfig)
				providerBytes, readErr := os.ReadFile(filepath.Join(concrete.root, providerPath))
				want := `{"schemaVersion":1,"config":{"providerConfigRules":{"providerRules":[{"providerId":"zai","providerName":"Z.ai","config":{"group":"standard-personal","access":{"type":"api-key","apiKey":"secret"},"api":{"type":"anthropic-messages","baseUrl":"https://api.z.ai/api/anthropic"},"personalModelIds":["GLM-5.2"],"modelOrder":["GLM-5.2"]}}]},"modelConfigRules":{"providerModelRules":[{"modelId":"GLM-5.2","config":{"properties":{"contextWindow":1000000}},"providerId":"zai"}],"manualProviderModelRules":[]},"defaultModelSelection":{"providerId":"zai","modelId":"GLM-5.2"}}}`
				if readErr != nil || string(providerBytes) != want {
					t.Fatalf("ZCode personal provider projection = %s, %v; want %s", providerBytes, readErr, want)
				}
				selection := concrete.zcodeSessionSelection()
				if selection == nil || selection.ProviderID != "zai" || selection.ModelID != "GLM-5.2" {
					t.Fatalf("ZCode session selection = %#v", selection)
				}
			}
		})
	}
}

func TestGrokCredentialProjectionRejectsNonPrivateAuth(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".grok/auth.json", "credential")
	if err := os.Chmod(filepath.Join(home, ".grok", "auth.json"), 0644); err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := mustCredentialSourcePolicy(t, CredentialSourceGrok)
	factory, err := NewCredentialProjectingNamespaceFactoryWithPolicies(
		base,
		home,
		map[string]CredentialSourceFamily{"grok": CredentialSourceGrok},
		map[string]RuntimeSafetyPolicy{"grok": policy},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.AcquireProviderNamespace(context.Background(), "grok", FamilyGrok); err == nil {
		t.Fatalf("non-private Grok auth error = %v", err)
	}
}

func TestCredentialSourceFactoryPreservesSelectedZCodeConfigurationFailure(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".zcode/cli/config.json", `{"model":"zai/model","provider":{"zai":{"options":{"apiKeyRequired":false}}}}`)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"zcode": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.AcquireProviderNamespace(context.Background(), "zcode", FamilyZcode)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
		t.Fatalf("factory error = %v, want configuration_violation", err)
	}
}

func TestCodexCredentialProjectionUsesConfiguredCodexHome(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	runtimeHome := credentialSourceTempDir(t)
	configuredHome := credentialSourceTempDir(t)
	writeCredentialSource(t, runtimeHome, ".codex/auth.json", "ambient")
	writeCredentialSource(t, configuredHome, "auth.json", "configured")
	writeCredentialSource(t, configuredHome, "config.toml", "must-not-project")
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(
		base, runtimeHome,
		map[string]CredentialSourceFamily{"codex-work-logic": CredentialSourceCodex},
		map[string]RuntimeSafetyPolicy{"codex-work-logic": mustCredentialSourcePolicy(t, CredentialSourceCodex)},
		nil, map[string]string{"codex-work-logic": configuredHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "codex-work-logic", FamilyCodex)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	concrete := lease.(*namespaceLease)
	data, err := os.ReadFile(filepath.Join(concrete.root, "home", ".codex", "auth.json"))
	if err != nil || string(data) != "configured" {
		t.Fatalf("configured Codex home was not authoritative: %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(concrete.root, "home", ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("Codex config was projected: %v", err)
	}
}
func mustCredentialSourcePolicy(t *testing.T, family CredentialSourceFamily) RuntimeSafetyPolicy {
	t.Helper()
	policy, err := RuntimeSafetyPolicyForFamily(family)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestCredentialSourceRejectsSymlinksAndAllowsAbsentFiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, home string)
		want  bool
	}{
		{"absent", func(*testing.T, string) {}, true},
		{"intermediate_symlink", func(t *testing.T, home string) { mustSymlink(t, t.TempDir(), filepath.Join(home, ".zcode")) }, false},
		{"final_symlink", func(t *testing.T, home string) {
			if err := os.MkdirAll(filepath.Join(home, ".zcode", "cli"), 0700); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(t.TempDir(), "config.json"), filepath.Join(home, ".zcode", "cli", "config.json"))
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := credentialSourceTempDir(t)
			test.setup(t, home)
			base, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
			if err != nil {
				t.Fatal(err)
			}
			lease, err := factory.AcquireProviderNamespace(context.Background(), "provider", FamilyZcode)
			if test.want {
				if err != nil {
					t.Fatal(err)
				}
				defer lease.DrainTerminal(context.Background())
				if len(lease.(*namespaceLease).seeds) != 0 {
					t.Fatal("absent source was projected")
				}
			} else if err == nil {
				lease.DrainTerminal(context.Background())
				t.Fatal("symlink source accepted")
			}
		})
	}
}

func TestCredentialSourceUsesExplicitHomeAndDetectsSourceDrift(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home, ambient := credentialSourceTempDir(t), t.TempDir()
	trusted := testZCodeLegacyConfig("trusted")
	writeCredentialSource(t, home, ".zcode/cli/config.json", trusted)
	writeCredentialSource(t, ambient, ".zcode/cli/config.json", testZCodeLegacyConfig("ambient"))
	t.Setenv("HOME", ambient)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "provider", FamilyZcode)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	concrete := lease.(*namespaceLease)
	if strings.Contains(concrete.Environment()[0].Value(), ambient) {
		t.Fatal("ambient home leaked into namespace")
	}
	path, ok := credentialDestination(ports.CredentialProjectionZCodeConfig)
	if !ok {
		t.Fatal("unknown destination")
	}
	bytes, err := os.ReadFile(filepath.Join(concrete.root, path))
	if err != nil || string(bytes) != trusted {
		t.Fatalf("explicit home source was not used: %v", err)
	}
	writeCredentialSource(t, home, ".zcode/cli/config.json", testZCodeLegacyConfig("changed"))
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("source drift accepted")
	}
}
func TestCredentialSourceRejectsPostProjectionIntermediateDirectorySwap(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".zcode/cli/config.json", testZCodeLegacyConfig("credential"))
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "provider", FamilyZcode)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	if err := os.Rename(filepath.Join(home, ".zcode"), filepath.Join(home, ".zcode-original")); err != nil {
		t.Fatal(err)
	}
	writeCredentialSource(t, home, ".zcode/cli/config.json", testZCodeLegacyConfig("credential"))
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("intermediate source-directory swap accepted")
	}
}

func TestCredentialSourceProjectionFailureDrainsLease(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".zcode/cli/config.json", testZCodeLegacyConfig("credential"))
	lease := newFailingProjectionLease(t)
	factory, err := NewCredentialProjectingNamespaceFactory(staticLeaseFactory{lease}, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.AcquireProviderNamespace(context.Background(), "provider", FamilyZcode); err == nil {
		t.Fatal("projection failure accepted")
	}
	if !lease.drained {
		t.Fatal("failed projection did not drain lease")
	}
}
func TestCredentialProjectingNamespaceFactoryWithPoliciesRejectsPolicyDrift(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	zcodePolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceZCode)
	if err != nil {
		t.Fatal(err)
	}
	codexPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCodex)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		families map[string]CredentialSourceFamily
		policies map[string]RuntimeSafetyPolicy
	}{
		{
			name:     "missing_policy",
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceZCode},
			policies: map[string]RuntimeSafetyPolicy{},
		},
		{
			name:     "family_mismatch",
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceZCode},
			policies: map[string]RuntimeSafetyPolicy{"provider": codexPolicy},
		},
		{
			name:     "empty_identity",
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceZCode},
			policies: map[string]RuntimeSafetyPolicy{"provider": {family: CredentialSourceZCode, bytes: zcodePolicy.bytes}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCredentialProjectingNamespaceFactoryWithPolicies(base, home, test.families, test.policies); err == nil {
				t.Fatal("invalid policy map accepted")
			}
		})
	}
}
func writeCredentialSource(t *testing.T, home, relative, contents string) {
	t.Helper()
	path := filepath.Join(home, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}
func credentialSourceEnvironment(environment []ports.EnvironmentVariable) map[string]string {
	values := make(map[string]string, len(environment))
	for _, variable := range environment {
		values[variable.Name()] = variable.Value()
	}
	return values
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

type staticLeaseFactory struct{ lease ports.ProviderNamespaceLease }

func (factory staticLeaseFactory) AcquireProviderNamespace(context.Context, string, string) (ports.ProviderNamespaceLease, error) {
	return factory.lease, nil
}

type failingProjectionLease struct {
	drained bool
	drain   ports.ProviderNamespaceTerminalDrain
}

func newFailingProjectionLease(t *testing.T) *failingProjectionLease {
	t.Helper()
	lease := &failingProjectionLease{}
	acquired, err := ports.AcquireProviderNamespaceLease(context.Background(), "provider", func(_ context.Context, _ string, binding ports.ProviderNamespaceTerminalBinding) (ports.ProviderNamespaceLease, error) {
		drain, err := binding.Bind("generation", func(context.Context) error {
			lease.drained = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		lease.drain = drain
		return lease, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return acquired.(*failingProjectionLease)
}

func (*failingProjectionLease) ProviderInstance() string                 { return "provider" }
func (*failingProjectionLease) Generation() string                       { return "generation" }
func (*failingProjectionLease) Environment() []ports.EnvironmentVariable { return nil }
func (*failingProjectionLease) ProjectCredential(context.Context, ports.CredentialProjectionRequest) (ports.CredentialProjectionReceipt, error) {
	return ports.CredentialProjectionReceipt{}, fmt.Errorf("projection failed")
}
func (*failingProjectionLease) ValidateForSpawn() error { return nil }
func (lease *failingProjectionLease) DrainTerminal(ctx context.Context) (ports.ProviderNamespaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

func credentialSourceTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
