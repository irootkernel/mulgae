package providercli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

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

func TestZCodeCredentialSourceIgnoresRetiredLegacyPaths(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, home string)
	}{
		{"absent", func(*testing.T, string) {}},
		{"intermediate_symlink", func(t *testing.T, home string) { mustSymlink(t, t.TempDir(), filepath.Join(home, ".zcode")) }},
		{"final_symlink", func(t *testing.T, home string) {
			if err := os.MkdirAll(filepath.Join(home, ".zcode", "cli"), 0700); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(t.TempDir(), "config.json"), filepath.Join(home, ".zcode", "cli", "config.json"))
		}},
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
			if err != nil {
				t.Fatal(err)
			}
			defer lease.DrainTerminal(context.Background())
			if len(lease.(*namespaceLease).seeds) != 0 {
				t.Fatal("retired legacy source was projected")
			}
		})
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
