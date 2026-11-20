//go:build darwin && arm64

package composition

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	adapterconfig "github.com/irootkernel/mulgae/internal/adapters/config"
	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/adapters/workspace"
	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func testProductionRuntimeSafetyPolicies(t *testing.T) map[reviewrun.Family]providercli.RuntimeSafetyPolicy {
	t.Helper()
	policies := make(map[reviewrun.Family]providercli.RuntimeSafetyPolicy, len(reviewrun.Families()))
	for _, item := range []struct {
		family     reviewrun.Family
		credential providercli.CredentialSourceFamily
	}{
		{reviewrun.FamilyZCode, providercli.CredentialSourceZCode},
		{reviewrun.FamilyGrok, providercli.CredentialSourceGrok},
		{reviewrun.FamilyCodex, providercli.CredentialSourceCodex},
		{reviewrun.FamilyCursor, providercli.CredentialSourceCursor},
		{reviewrun.FamilyAgy, providercli.CredentialSourceAgy},
	} {
		policy, err := providercli.RuntimeSafetyPolicyForFamily(item.credential)
		if err != nil {
			t.Fatalf("runtime safety policy for %s: %v", item.family, err)
		}
		policies[item.family] = policy
	}
	return policies
}

func TestProductionInstanceFamiliesRegistersSyntheticGrokLogicWhenConfigured(t *testing.T) {
	policies := testProductionRuntimeSafetyPolicies(t)
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
			Grok:  &appconfig.GrokProviderConfig{Executable: "/opt/homebrew/bin/grok"},
		},
		Roles: appconfig.RolesConfig{
			Logic:    appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
			Security: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
		},
	}

	families, instancePolicies, sourceRoots, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}
	wantFamilies := map[string]providercli.CredentialSourceFamily{
		"zcode-logic":    providercli.CredentialSourceZCode,
		"zcode-security": providercli.CredentialSourceZCode,
		"grok-logic":     providercli.CredentialSourceGrok,
	}
	if !reflect.DeepEqual(families, wantFamilies) {
		t.Fatalf("instanceFamilies = %v, want %v", families, wantFamilies)
	}
	if got := instancePolicies["grok-logic"]; got.Identity() != policies[reviewrun.FamilyGrok].Identity() {
		t.Fatalf("grok-logic policy identity = %q, want %q", got.Identity(), policies[reviewrun.FamilyGrok].Identity())
	}
	if len(instancePolicies) != len(families) {
		t.Fatalf("len(instancePolicies) = %d, want %d", len(instancePolicies), len(families))
	}
	if len(sourceRoots) != 0 {
		t.Fatalf("sourceRoots = %v, want empty", sourceRoots)
	}
}

func TestProductionInstanceFamiliesOmitsGrokLogicWhenUnconfigured(t *testing.T) {
	policies := testProductionRuntimeSafetyPolicies(t)
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
		},
		Roles: appconfig.RolesConfig{
			Logic: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
		},
	}

	families, instancePolicies, sourceRoots, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}
	if _, exists := families["grok-logic"]; exists {
		t.Fatalf("grok-logic registered without Providers.Grok: %v", families)
	}
	if _, exists := instancePolicies["grok-logic"]; exists {
		t.Fatalf("grok-logic policy registered without Providers.Grok")
	}
	wantFamilies := map[string]providercli.CredentialSourceFamily{
		"zcode-logic": providercli.CredentialSourceZCode,
	}
	if !reflect.DeepEqual(families, wantFamilies) {
		t.Fatalf("instanceFamilies = %v, want %v", families, wantFamilies)
	}
	if len(sourceRoots) != 0 {
		t.Fatalf("sourceRoots = %v, want empty", sourceRoots)
	}
}

func TestProductionInstanceFamiliesPreservesProviderRegistrationsAndSourceRoots(t *testing.T) {
	policies := testProductionRuntimeSafetyPolicies(t)
	workHome := "/Users/operator/.codex-work"
	personalHome := "/Users/operator/.codex-personal"
	spareHome := "/Users/operator/.codex-spare"
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
			Grok:  &appconfig.GrokProviderConfig{Executable: "/opt/homebrew/bin/grok"},
			Codex: &appconfig.CodexProviderConfig{
				Executable:               "/opt/homebrew/bin/codex",
				DefaultCredentialProfile: "work",
				CredentialHomes: []appconfig.CodexCredentialHomeConfig{
					{Profile: "work", Home: workHome},
					{Profile: "personal", Home: personalHome},
					{Profile: "spare", Home: spareHome},
					{Profile: "empty", Home: ""},
				},
			},
			Cursor: &appconfig.CursorProviderConfig{Executable: "/opt/homebrew/bin/cursor"},
			Agy:    &appconfig.AgyProviderConfig{Executable: "/opt/homebrew/bin/agy"},
		},
		Roles: appconfig.RolesConfig{
			Logic:           appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
			Security:        appconfig.RoleConfig{Enabled: true, PrimaryProvider: "codex"},
			Maintainability: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "codex", CredentialProfile: "personal"},
			Product:         appconfig.RoleConfig{Enabled: true, PrimaryProvider: "cursor"},
			Documentation:   appconfig.RoleConfig{Enabled: true, PrimaryProvider: "agy"},
			Testing:         appconfig.RoleConfig{Enabled: false, PrimaryProvider: "zcode"},
		},
	}

	families, instancePolicies, sourceRoots, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}
	wantFamilies := map[string]providercli.CredentialSourceFamily{
		"zcode-logic":                    providercli.CredentialSourceZCode,
		"codex-work-security":            providercli.CredentialSourceCodex,
		"codex-personal-maintainability": providercli.CredentialSourceCodex,
		"cursor-product":                 providercli.CredentialSourceCursor,
		"agy-documentation":              providercli.CredentialSourceAgy,
		"grok-logic":                     providercli.CredentialSourceGrok,
		"agy-logic":                      providercli.CredentialSourceAgy,
	}
	if !reflect.DeepEqual(families, wantFamilies) {
		t.Fatalf("instanceFamilies = %v, want %v", families, wantFamilies)
	}
	if len(instancePolicies) != len(wantFamilies) {
		t.Fatalf("len(instancePolicies) = %d, want %d", len(instancePolicies), len(wantFamilies))
	}
	for instance, sourceFamily := range wantFamilies {
		wantPolicy := policies[reviewrun.Family(sourceFamily)]
		if got := instancePolicies[instance]; got.Identity() != wantPolicy.Identity() {
			t.Fatalf("instancePolicies[%q] identity = %q, want %q", instance, got.Identity(), wantPolicy.Identity())
		}
	}
	wantSourceRoots := map[string]string{
		"codex-work-security":            workHome,
		"codex-personal-maintainability": personalHome,
		"profile-home-spare":             spareHome,
	}
	if !reflect.DeepEqual(sourceRoots, wantSourceRoots) {
		t.Fatalf("sourceRoots = %v, want %v", sourceRoots, wantSourceRoots)
	}

	invalid := cfg
	invalid.Roles.Testing = appconfig.RoleConfig{Enabled: true, PrimaryProvider: "unknown"}
	if _, _, _, err := productionInstanceFamilies(invalid, policies); err == nil {
		t.Fatal("invalid configured provider family was accepted")
	}
}

func TestProductionInstanceFamiliesProjectsGrokAuthOnlyOnNamespaceAcquisition(t *testing.T) {
	ctx := context.Background()
	policies := testProductionRuntimeSafetyPolicies(t)
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
			Grok:  &appconfig.GrokProviderConfig{Executable: "/opt/homebrew/bin/grok"},
		},
		Roles: appconfig.RolesConfig{
			Logic: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
		},
	}

	families, instancePolicies, sourceRoots, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}

	namespaceRoot := canonicalTestTempDir(t)
	nativeHome := canonicalTestTempDir(t)
	projectRoot := canonicalTestTempDir(t)
	grokDir := filepath.Join(nativeHome, ".grok")
	if err := os.Mkdir(grokDir, 0o700); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(grokDir, "auth.json")
	authPayload := []byte(`{"token":"synthetic-grok-heartbeat-token"}`)
	// Start with an unsafe mode so eager credential validation or projection
	// during factory construction or unrelated namespace acquisition would fail.
	// Set permissions explicitly with Chmod so a restrictive process umask
	// (such as 0077) cannot turn 0644 into 0600.
	if err := os.WriteFile(authPath, authPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(authPath, 0o644); err != nil {
		t.Fatal(err)
	}

	baseNamespaces, err := providercli.NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := providercli.NewCredentialProjectingNamespaceFactoryWithProjectRoot(
		baseNamespaces,
		nativeHome,
		projectRoot,
		families,
		instancePolicies,
		make(map[string]string),
		sourceRoots,
	)
	if err != nil {
		t.Fatalf("constructing credential namespace factory failed before grok-logic acquisition: %v", err)
	}

	// Acquiring an unrelated provider namespace must not inspect or project Grok credentials.
	zcodeLease, err := projected.AcquireProviderNamespace(ctx, "zcode-logic", string(reviewrun.FamilyZCode))
	if err != nil {
		t.Fatalf("AcquireProviderNamespace(zcode-logic) error = %v", err)
	}
	zcodeHome := environmentValue(t, zcodeLease.Environment(), "HOME")
	if _, statErr := os.Stat(filepath.Join(zcodeHome, ".grok", "auth.json")); !os.IsNotExist(statErr) {
		t.Fatalf("zcode-logic namespace unexpectedly contains .grok/auth.json (err=%v)", statErr)
	}
	if _, err := zcodeLease.DrainTerminal(ctx); err != nil {
		t.Fatalf("drain zcode-logic: %v", err)
	}

	// Acquiring grok-logic triggers projection and rejects unsafe mode 0644.
	if lease, err := projected.AcquireProviderNamespace(ctx, "grok-logic", string(reviewrun.FamilyGrok)); err == nil {
		_, _ = lease.DrainTerminal(ctx)
		t.Fatal("AcquireProviderNamespace(grok-logic) accepted unsafe 0644 auth.json")
	}

	// Once mode 0600, acquiring grok-logic projects auth.json into the disposable namespace.
	if err := os.Chmod(authPath, 0o600); err != nil {
		t.Fatal(err)
	}
	grokLease, err := projected.AcquireProviderNamespace(ctx, "grok-logic", string(reviewrun.FamilyGrok))
	if err != nil {
		t.Fatalf("AcquireProviderNamespace(grok-logic) error = %v", err)
	}
	defer func() {
		if _, drainErr := grokLease.DrainTerminal(ctx); drainErr != nil {
			t.Fatalf("drain grok-logic: %v", drainErr)
		}
	}()
	grokHome := environmentValue(t, grokLease.Environment(), "HOME")
	projectedAuthPath := filepath.Join(grokHome, ".grok", "auth.json")
	gotBytes, err := os.ReadFile(projectedAuthPath)
	if err != nil {
		t.Fatalf("read projected auth.json: %v", err)
	}
	if string(gotBytes) != string(authPayload) {
		t.Fatalf("projected auth.json = %q, want %q", gotBytes, authPayload)
	}
	info, err := os.Stat(projectedAuthPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("projected auth.json mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestProductionInstanceFamiliesMatchesGrokHeartbeatCandidateInstance(t *testing.T) {
	executable, err := filepath.EvalSymlinks("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	rootPath := canonicalTestTempDir(t)
	if err := os.Mkdir(filepath.Join(rootPath, ".mulgae"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "config.yaml"), []byte(compositionProjectConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), []byte(compositionLocalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	local, err := adapterconfig.NewLocalConfigSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Observation().Proof()
	if err != nil {
		t.Fatal(err)
	}
	localityRequest, err := ports.NewConfigLocalityRequest(root, proof, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policies := testProductionRuntimeSafetyPolicies(t)
	identities := make(map[reviewrun.Family]string, len(policies))
	timeouts := make(map[reviewrun.Family]time.Duration, len(policies))
	for family, policy := range policies {
		identities[family] = policy.Identity()
		timeouts[family] = time.Minute
	}
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
			Grok:  &appconfig.GrokProviderConfig{Executable: executable},
		},
		Roles: appconfig.RolesConfig{
			Logic: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
		},
	}
	workspaceRoot := canonicalTestTempDir(t)
	anchoredWorkspace, err := ports.NewAnchoredRoot(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := workspace.NewMaterializer(anchoredWorkspace, filesystem.NewContentDetector())
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providercli.NewProbeFixtureLeaseFactory(materializer, providercli.SecureProbeNonceGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := fixtures.Acquire(context.Background(), domain.RoleLogic)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, drainErr := seed.DrainTerminal(context.Background()); drainErr != nil {
			t.Fatalf("drain seed: %v", drainErr)
		}
	}()
	source := &configuredProductionCandidateSource{
		inspector:        environment.NewInspector(),
		config:           cfg,
		policyIdentities: identities,
		providerTimeouts: timeouts,
		source:           local,
		attestor:         stableHeartbeatLocalityAttestor{},
		staticRequest:    localityRequest,
	}
	candidate, err := source.newHeartbeatCandidate(context.Background(), seed.WorkspaceSnapshotIdentity(), reviewrun.FamilyGrok, "")
	if err != nil {
		t.Fatalf("newHeartbeatCandidate(grok) error = %v", err)
	}
	families, instancePolicies, _, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}
	instance := candidate.Definition.Instance()
	if got := families[instance]; got != providercli.CredentialSourceGrok {
		t.Fatalf("heartbeat candidate instance %q registered as %q, want %q", instance, got, providercli.CredentialSourceGrok)
	}
	if got := instancePolicies[instance]; got.Identity() != policies[reviewrun.FamilyGrok].Identity() {
		t.Fatalf("heartbeat candidate instance %q policy identity = %q, want %q", instance, got.Identity(), policies[reviewrun.FamilyGrok].Identity())
	}
}

func environmentValue(t *testing.T, vars []ports.EnvironmentVariable, name string) string {
	t.Helper()
	for _, entry := range vars {
		if entry.Name() == name {
			return entry.Value()
		}
	}
	t.Fatalf("environment variable %q missing from namespace lease", name)
	return ""
}
