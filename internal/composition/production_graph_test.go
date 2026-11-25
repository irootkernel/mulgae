//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
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
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
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

func TestProductionInstanceFamiliesRegistersSyntheticZCodeLogicWhenConfigured(t *testing.T) {
	policies := testProductionRuntimeSafetyPolicies(t)
	config := appconfig.Config{
		Providers: appconfig.ProvidersConfig{ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"}},
		Roles: appconfig.RolesConfig{
			Security: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
		},
	}
	families, instancePolicies, _, err := productionInstanceFamilies(config, policies)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]providercli.CredentialSourceFamily{
		"zcode-logic": providercli.CredentialSourceZCode, "zcode-security": providercli.CredentialSourceZCode,
	}
	if !reflect.DeepEqual(families, want) ||
		instancePolicies["zcode-logic"].Identity() != policies[reviewrun.FamilyZCode].Identity() {
		t.Fatalf("synthetic ZCode heartbeat route did not receive the configured family policy: %v", families)
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

func TestProductionInstanceFamiliesPreservesProviderRegistrations(t *testing.T) {
	policies := testProductionRuntimeSafetyPolicies(t)
	cfg := appconfig.Config{
		Providers: appconfig.ProvidersConfig{
			ZCode: &appconfig.ZCodeProviderConfig{AppBundle: "/Applications/ZCode.app"},
			Grok:  &appconfig.GrokProviderConfig{Executable: "/opt/homebrew/bin/grok"},
		},
		Roles: appconfig.RolesConfig{
			Logic:           appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
			Security:        appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
			Maintainability: appconfig.RoleConfig{Enabled: true, PrimaryProvider: "grok"},
			Product:         appconfig.RoleConfig{Enabled: true, PrimaryProvider: "grok"},
			Documentation:   appconfig.RoleConfig{Enabled: true, PrimaryProvider: "zcode"},
			Testing:         appconfig.RoleConfig{Enabled: false, PrimaryProvider: "zcode"},
		},
	}

	families, instancePolicies, sourceRoots, err := productionInstanceFamilies(cfg, policies)
	if err != nil {
		t.Fatalf("productionInstanceFamilies() error = %v", err)
	}
	wantFamilies := map[string]providercli.CredentialSourceFamily{
		"zcode-logic":          providercli.CredentialSourceZCode,
		"zcode-security":       providercli.CredentialSourceZCode,
		"grok-maintainability": providercli.CredentialSourceGrok,
		"grok-product":         providercli.CredentialSourceGrok,
		"zcode-documentation":  providercli.CredentialSourceZCode,
		"grok-logic":           providercli.CredentialSourceGrok,
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
	if len(sourceRoots) != 0 {
		t.Fatalf("sourceRoots = %v, want empty", sourceRoots)
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
	candidate, err := source.newHeartbeatCandidate(context.Background(), seed.WorkspaceSnapshotIdentity(), reviewrun.FamilyGrok)
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

type stubTerminalSession struct {
	closeCalls int
	closeErr   error
	onClose    func()
}

func (s *stubTerminalSession) RunTerminal(context.Context, ports.TerminalExecutionRequest) (ports.TerminalExecutionObservation, error) {
	return ports.TerminalExecutionObservation{}, errors.New("unused")
}

func (s *stubTerminalSession) DrainLabeledPanes(context.Context, string, string) error {
	return nil
}

func (s *stubTerminalSession) RuntimeIdentity(context.Context) (ports.TerminalRuntimeIdentity, error) {
	return ports.TerminalRuntimeIdentity{}, errors.New("unused")
}

func (s *stubTerminalSession) Close(context.Context) error {
	s.closeCalls++
	if s.onClose != nil {
		s.onClose()
	}
	return s.closeErr
}

func TestProductionRuntimeGraphCleanupRootsClosesTerminalSessionFirstAndRetainsNamespaceOnFailure(t *testing.T) {
	t.Run("failure stops before removing namespace parent", func(t *testing.T) {
		nsPath := canonicalTestTempDir(t)
		wsPath := canonicalTestTempDir(t)
		nsRoot, err := ports.NewAnchoredRoot(nsPath)
		if err != nil {
			t.Fatal(err)
		}
		wsRoot, err := ports.NewAnchoredRoot(wsPath)
		if err != nil {
			t.Fatal(err)
		}
		closeFailure := errors.New("herdr-core daemon exit unproven")
		stub := &stubTerminalSession{closeErr: closeFailure}
		graph := &productionRuntimeGraph{
			namespaceRoot:   nsRoot,
			workspaceRoot:   wsRoot,
			terminalSession: stub,
		}
		err = graph.cleanupRoots()
		if !errors.Is(err, closeFailure) {
			t.Fatalf("cleanupRoots() error = %v, want %v", err, closeFailure)
		}
		if stub.closeCalls != 1 {
			t.Fatalf("terminalSession.Close calls = %d, want 1", stub.closeCalls)
		}
		// Namespace root MUST be retained when terminal session teardown is unproven.
		if info, statErr := os.Lstat(nsPath); statErr != nil || !info.IsDir() {
			t.Fatalf("namespace parent was removed despite unproven terminal session exit: %v", statErr)
		}
		// Once terminal close succeeds, retry cleans up the roots.
		stub.closeErr = nil
		if err := graph.cleanupRoots(); err != nil {
			t.Fatalf("retry cleanupRoots() error = %v", err)
		}
		if _, statErr := os.Lstat(nsPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("namespace parent survived clean retry: %v", statErr)
		}
	})

	t.Run("happy path closes terminal session before removing namespace parent", func(t *testing.T) {
		nsPath := canonicalTestTempDir(t)
		wsPath := canonicalTestTempDir(t)
		nsRoot, _ := ports.NewAnchoredRoot(nsPath)
		wsRoot, _ := ports.NewAnchoredRoot(wsPath)
		nsExistedAtClose := false
		stub := &stubTerminalSession{
			onClose: func() {
				if info, err := os.Lstat(nsPath); err == nil && info.IsDir() {
					nsExistedAtClose = true
				}
			},
		}
		graph := &productionRuntimeGraph{
			namespaceRoot:   nsRoot,
			workspaceRoot:   wsRoot,
			terminalSession: stub,
		}
		if err := graph.cleanupRoots(); err != nil {
			t.Fatalf("cleanupRoots() error = %v", err)
		}
		if stub.closeCalls != 1 || !nsExistedAtClose {
			t.Fatalf("close ordering violated: calls=%d nsExistedAtClose=%t", stub.closeCalls, nsExistedAtClose)
		}
		if _, statErr := os.Lstat(nsPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("namespace parent survived cleanup: %v", statErr)
		}
	})
}

func TestRootCleaningReviewRunServiceRetainedErrorClosesTerminalSessionWhileKeepingRoots(t *testing.T) {
	nsPath := canonicalTestTempDir(t)
	wsPath := canonicalTestTempDir(t)
	nsRoot, _ := ports.NewAnchoredRoot(nsPath)
	wsRoot, _ := ports.NewAnchoredRoot(wsPath)
	cause := errors.New("provider drain remains unproven")
	retained := &reviewrun.LiveRunCleanup{}
	stub := &stubTerminalSession{}
	service := &rootCleaningReviewRunService{
		inner: failingReviewRunService{err: retainedLiveCleanupFailure{cause: cause, cleanup: retained}},
		graph: &productionRuntimeGraph{
			namespaceRoot:   nsRoot,
			workspaceRoot:   wsRoot,
			terminalSession: stub,
		},
	}
	_, err := service.StartReviewRun(context.Background(), mulgaeentry.ReviewRequest{}, ports.AnchoredRoot{})
	if owner, ok := reviewrun.LiveCleanupFromError(err); !ok || owner != retained || !errors.Is(err, cause) {
		t.Fatalf("retained error lost live cleanup ownership: %v", err)
	}
	if stub.closeCalls != 1 {
		t.Fatalf("retained-error branch terminalSession.Close calls = %d, want 1", stub.closeCalls)
	}
	for _, root := range []string{nsPath, wsPath} {
		if info, statErr := os.Lstat(root); statErr != nil || !info.IsDir() {
			t.Fatalf("retained root %s was deleted on retained error: %v", root, statErr)
		}
	}
}
