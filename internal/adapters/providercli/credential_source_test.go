package providercli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
	}{
		{"kimi_config", CredentialSourceKimi, ".kimi-code/config.toml", ports.CredentialProjectionKimiConfig},
		{"kimi_credentials", CredentialSourceKimi, ".kimi-code/credentials/kimi-code.json", ports.CredentialProjectionKimiCredentials},
		{"zcode_config", CredentialSourceZCode, ".zcode/cli/config.json", ports.CredentialProjectionZCodeConfig},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			home := credentialSourceTempDir(t)
			writeCredentialSource(t, home, test.source, "declared")
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
			lease, err := factory.AcquireProviderNamespace(context.Background(), "provider")
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
			if err != nil || string(bytes) != "declared" {
				t.Fatalf("declared source not projected: %v", err)
			}
			if len(concrete.seeds) != 1 {
				t.Fatalf("projected %d files, want exactly one", len(concrete.seeds))
			}
		})
	}
}

func TestKimiCredentialProjectionUsesConfiguredDataHome(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	runtimeHome := credentialSourceTempDir(t)
	configuredDataHome := credentialSourceTempDir(t)
	writeCredentialSource(t, runtimeHome, ".kimi-code/config.toml", "ambient")
	writeCredentialSource(t, configuredDataHome, "config.toml", "configured")
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithConfiguredSourceRoots(
		base, runtimeHome,
		map[string]CredentialSourceFamily{"kimi": CredentialSourceKimi},
		map[string]RuntimeSafetyPolicy{"kimi": mustCredentialSourcePolicy(t, CredentialSourceKimi)},
		nil, map[string]string{"kimi": configuredDataHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "kimi")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	concrete := lease.(*namespaceLease)
	data, err := os.ReadFile(filepath.Join(concrete.root, "home", ".kimi-code", "config.toml"))
	if err != nil || string(data) != "configured" {
		t.Fatalf("configured Kimi data home was not authoritative: %q, %v", data, err)
	}
}
func TestAGYUsesInstalledHomeWithoutCredentialProjection(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	bootstrapHome := credentialSourceTempDir(t)
	nativeHome := credentialSourceTempDir(t)
	writeCredentialSource(t, nativeHome, ".gemini/antigravity-cli/antigravity-oauth-token", "oauth")
	writeCredentialSource(t, nativeHome, ".gemini/antigravity-cli/installation_id", "installation")
	writeCredentialSource(t, nativeHome, "sentinel", "unchanged")
	workspace := credentialSourceTempDir(t)
	policy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, workspace)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, bootstrapHome,
		map[string]CredentialSourceFamily{"agy": CredentialSourceAGY},
		map[string]RuntimeSafetyPolicy{"agy": policy},
		map[string]string{"agy": nativeHome})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "agy")
	if err != nil {
		t.Fatal(err)
	}
	concrete := lease.(*namespaceLease)
	environment := credentialSourceEnvironment(lease.Environment())
	if environment["HOME"] != nativeHome {
		t.Fatalf("AGY HOME = %q, want verified native home %q", environment["HOME"], nativeHome)
	}
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR", "TMP", "TEMP", "KAR_PROVIDER_SCRATCH"} {
		if !strings.HasPrefix(environment[name], concrete.root+string(filepath.Separator)) {
			t.Fatalf("%s escaped namespace: %q", name, environment[name])
		}
	}
	if len(concrete.seeds) != 0 {
		t.Fatalf("AGY projected %d credentials", len(concrete.seeds))
	}
	for _, relative := range []string{
		".gemini/antigravity-cli/antigravity-oauth-token",
		".gemini/antigravity-cli/installation_id",
	} {
		if _, err := os.Lstat(filepath.Join(concrete.root, "home", relative)); !os.IsNotExist(err) {
			t.Fatalf("AGY credential was copied to namespace: %s: %v", relative, err)
		}
	}
	for relative, want := range map[string]string{
		".gemini/antigravity-cli/antigravity-oauth-token": "oauth",
		".gemini/antigravity-cli/installation_id":         "installation",
		"sentinel": "unchanged",
	} {
		bytes, err := os.ReadFile(filepath.Join(nativeHome, relative))
		if err != nil || string(bytes) != want {
			t.Fatalf("installed HOME %q changed: %q, %v", relative, bytes, err)
		}
	}
	originalHome := nativeHome + "-original"
	if err := os.Rename(nativeHome, originalHome); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nativeHome, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nativeHome, "sentinel"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("AGY spawn accepted installed HOME identity drift")
	}
	if _, err := lease.DrainTerminal(context.Background()); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(nativeHome, "sentinel"))
	if err != nil || string(bytes) != "replacement" {
		t.Fatalf("drain changed replacement installed HOME: %q, %v", bytes, err)
	}
	bytes, err = os.ReadFile(filepath.Join(originalHome, "sentinel"))
	if err != nil || string(bytes) != "unchanged" {
		t.Fatalf("drain changed captured installed HOME: %q, %v", bytes, err)
	}
}
func TestNativeHomeMappingsFailClosed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	bootstrapHome := credentialSourceTempDir(t)
	nativeHome := credentialSourceTempDir(t)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	workspace := credentialSourceTempDir(t)
	agyPolicy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, workspace)
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]CredentialSourceFamily{
		"agy":  CredentialSourceAGY,
		"kimi": CredentialSourceKimi,
	}
	policies := map[string]RuntimeSafetyPolicy{
		"agy":  agyPolicy,
		"kimi": mustCredentialSourcePolicy(t, CredentialSourceKimi),
	}
	for _, mappings := range []map[string]string{
		nil,
		{"kimi": nativeHome},
		{"agy": nativeHome, "kimi": nativeHome},
		{"agy": nativeHome + "/."},
	} {
		if _, err := NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, bootstrapHome, families, policies, mappings); err == nil {
			t.Fatalf("accepted invalid native home mappings %#v", mappings)
		}
	}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, bootstrapHome, families, policies, map[string]string{"agy": nativeHome})
	if err != nil {
		t.Fatal(err)
	}
	originalHome := nativeHome + "-original"
	if err := os.Rename(nativeHome, originalHome); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(nativeHome, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := factory.AcquireProviderNamespace(context.Background(), "agy"); err == nil {
		t.Fatal("AGY acquisition accepted native home identity drift")
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
			lease, err := factory.AcquireProviderNamespace(context.Background(), "provider")
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
	writeCredentialSource(t, home, ".zcode/cli/config.json", "trusted")
	writeCredentialSource(t, ambient, ".zcode/cli/config.json", "ambient")
	t.Setenv("HOME", ambient)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "provider")
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
	if err != nil || string(bytes) != "trusted" {
		t.Fatalf("explicit home source was not used: %v", err)
	}
	writeCredentialSource(t, home, ".zcode/cli/config.json", "changed")
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("source drift accepted")
	}
}
func TestCredentialSourceRejectsPostProjectionIntermediateDirectorySwap(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".zcode/cli/config.json", "credential")
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "provider")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	if err := os.Rename(filepath.Join(home, ".zcode"), filepath.Join(home, ".zcode-original")); err != nil {
		t.Fatal(err)
	}
	writeCredentialSource(t, home, ".zcode/cli/config.json", "credential")
	if err := lease.ValidateForSpawn(); err == nil {
		t.Fatal("intermediate source-directory swap accepted")
	}
}

func TestCredentialSourceProjectionFailureDrainsLease(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	writeCredentialSource(t, home, ".zcode/cli/config.json", "credential")
	lease := newFailingProjectionLease(t)
	factory, err := NewCredentialProjectingNamespaceFactory(staticLeaseFactory{lease}, home, map[string]CredentialSourceFamily{"provider": CredentialSourceZCode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.AcquireProviderNamespace(context.Background(), "provider"); err == nil {
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
	agyPolicy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	kimiPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceKimi)
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
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceAGY},
			policies: map[string]RuntimeSafetyPolicy{},
		},
		{
			name:     "family_mismatch",
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceAGY},
			policies: map[string]RuntimeSafetyPolicy{"provider": kimiPolicy},
		},
		{
			name:     "empty_identity",
			families: map[string]CredentialSourceFamily{"provider": CredentialSourceAGY},
			policies: map[string]RuntimeSafetyPolicy{"provider": {family: CredentialSourceAGY, bytes: agyPolicy.bytes}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCredentialProjectingNamespaceFactoryWithPolicies(base, home, test.families, test.policies); err == nil {
				t.Fatal("invalid policy map accepted")
			}
		})
	}
}
func TestCredentialProjectingNamespaceFactoryWithPoliciesClonesPolicy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	nativeHome := credentialSourceTempDir(t)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	policies := map[string]RuntimeSafetyPolicy{"provider": policy}
	factory, err := NewCredentialProjectingNamespaceFactoryWithPoliciesAndNativeHomes(base, home, map[string]CredentialSourceFamily{"provider": CredentialSourceAGY}, policies, map[string]string{"provider": nativeHome})
	if err != nil {
		t.Fatal(err)
	}
	policies["provider"] = RuntimeSafetyPolicy{}
	lease, err := factory.AcquireProviderNamespace(context.Background(), "provider")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.DrainTerminal(context.Background())
	if got := lease.(*namespaceLease).RuntimeSafetyPolicyIdentity(); got != policy.Identity() {
		t.Fatalf("installed policy identity = %q, want %q", got, policy.Identity())
	}
}

func TestCredentialProjectingNamespaceFactoryLegacyConstructorsRejectAGY(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin descriptor traversal is required")
	}
	home := credentialSourceTempDir(t)
	base, err := NewNamespaceFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := RuntimeSafetyPolicyForFamilyAndWorkspaceRoot(CredentialSourceAGY, credentialSourceTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]CredentialSourceFamily{"agy": CredentialSourceAGY}
	if _, err := NewCredentialProjectingNamespaceFactory(base, home, families); err == nil {
		t.Fatal("legacy constructor accepted AGY without a native home")
	}
	if _, err := NewCredentialProjectingNamespaceFactoryWithPolicies(base, home, families, map[string]RuntimeSafetyPolicy{"agy": policy}); err == nil {
		t.Fatal("legacy policy constructor accepted AGY without a native home")
	}
	kimiPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceKimi)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCredentialProjectingNamespaceFactory(base, home, map[string]CredentialSourceFamily{"zcode": CredentialSourceZCode}); err != nil {
		t.Fatalf("legacy constructor rejected ZCode: %v", err)
	}
	if _, err := NewCredentialProjectingNamespaceFactoryWithPolicies(base, home, map[string]CredentialSourceFamily{"kimi": CredentialSourceKimi}, map[string]RuntimeSafetyPolicy{"kimi": kimiPolicy}); err != nil {
		t.Fatalf("legacy policy constructor rejected Kimi: %v", err)
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

func (factory staticLeaseFactory) AcquireProviderNamespace(context.Context, string) (ports.ProviderNamespaceLease, error) {
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
