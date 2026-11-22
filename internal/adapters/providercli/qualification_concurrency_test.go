package providercli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// resolvedTempRoot resolves one owned temporary root once; the default macOS
// TMPDIR crosses /var through a symlink.
func resolvedTempRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestQualificationRegistryFactoryConcurrentConstructionAcrossFamilies
// overlaps the production qualification registry construction for two distinct
// families from one shared composition: the real namespace factory, the real
// credential-projecting factory, and the real QualificationRegistryFactory
// entry the application calls. ZCode and Codex (with no credential file in the
// temporary home) project no credential files, so no user credential material
// is needed.
func TestQualificationRegistryFactoryConcurrentConstructionAcrossFamilies(t *testing.T) {
	base := resolvedTempRoot(t)
	namespaceRoot := filepath.Join(base, "namespaces")
	runtimeHome := filepath.Join(base, "runtime-home")
	projectRoot := filepath.Join(base, "project")
	for _, directory := range []string{runtimeHome, projectRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	zcodePolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceZCode)
	if err != nil {
		t.Fatal(err)
	}
	codexPolicy, err := RuntimeSafetyPolicyForFamily(CredentialSourceCodex)
	if err != nil {
		t.Fatal(err)
	}
	namespaces, err := NewNamespaceFactory(namespaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := NewCredentialProjectingNamespaceFactoryWithProjectRoot(
		namespaces, runtimeHome, projectRoot,
		map[string]CredentialSourceFamily{
			"zcode_production": CredentialSourceZCode, "codex_production": CredentialSourceCodex,
		},
		map[string]RuntimeSafetyPolicy{
			"zcode_production": zcodePolicy, "codex_production": codexPolicy,
		},
		nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewQualificationRegistryFactory(&countingRunner{}, projected, testSpawnVerifier{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	zcodeTransport, err := defaultRuntimeTransport(FamilyZcode)
	if err != nil {
		t.Fatal(err)
	}
	codexTransport, err := defaultRuntimeTransport(FamilyCodex)
	if err != nil {
		t.Fatal(err)
	}
	configVariable, err := ports.NewEnvironmentVariable("ZCODE_BUILTIN_PROVIDER_CONFIG_FILE", "/private/config/zcode-builtin.json")
	if err != nil {
		t.Fatal(err)
	}
	electronVariable, err := ports.NewEnvironmentVariable("ELECTRON_RUN_AS_NODE", "1")
	if err != nil {
		t.Fatal(err)
	}
	zcodeEnvironment := []ports.EnvironmentVariable{configVariable, electronVariable}
	zcodeDefinition, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		FamilyZcode, "zcode_production", "", "/private/bin/zcode", "executable-sha256",
		"/private/bin/zcode.cjs", "executable-sha256", "/private/config/zcode-builtin.json",
		"sha256:"+strings.Repeat("a", 64),
		"zcode_production", "generation-1", zcodePolicy.Identity(),
		[]string{"/private/bin/zcode", "/private/bin/zcode.cjs"}, zcodeTransport, zcodeEnvironment, "/private/work", time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	codexDefinition, err := NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		FamilyCodex, "codex_production", "", "/private/bin/codex", "executable-sha256",
		"/private/bin/codex", "executable-sha256", "", "",
		"codex_production", "generation-1", codexPolicy.Identity(),
		[]string{"/private/bin/codex"}, codexTransport, nil, "/private/work", time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	registries := make(chan ports.ProviderQualificationRegistry, 2)
	failures := make(chan error, 2)
	var wait sync.WaitGroup
	for _, definition := range []RuntimeDefinition{zcodeDefinition, codexDefinition} {
		wait.Add(1)
		go func(definition RuntimeDefinition) {
			defer wait.Done()
			<-start
			registry, registryErr := factory.NewProviderQualificationRegistry(context.Background(), []ports.ProviderRuntimeDefinition{definition})
			if registryErr != nil {
				failures <- fmt.Errorf("%s: %w", definition.Instance(), registryErr)
				return
			}
			registries <- registry
		}(definition)
	}
	close(start)
	wait.Wait()
	close(registries)
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
	var constructed []ports.ProviderQualificationRegistry
	for registry := range registries {
		constructed = append(constructed, registry)
	}
	if len(constructed) != 2 {
		t.Fatalf("constructed registries = %d, want 2", len(constructed))
	}
	generations := make(map[string]string, 2)
	homes := make(map[string]string, 2)
	for _, registry := range constructed {
		for _, instance := range []string{"zcode_production", "codex_production"} {
			namespace, ok := registry.QualificationNamespace(instance)
			if !ok {
				continue
			}
			generations[instance] = namespace.Generation()
			for _, variable := range namespace.Environment() {
				if variable.Name() == "HOME" {
					homes[instance] = variable.Value()
				}
			}
		}
	}
	if len(generations) != 2 || generations["zcode_production"] == "" || generations["codex_production"] == "" ||
		generations["zcode_production"] == generations["codex_production"] {
		t.Fatalf("namespace generations = %v, want two distinct non-empty generations", generations)
	}
	if !filepath.IsAbs(homes["zcode_production"]) || !filepath.IsAbs(homes["codex_production"]) {
		t.Fatalf("namespace homes = %v, want absolute per-instance homes", homes)
	}
	for instance, home := range homes {
		if filepath.Base(filepath.Dir(home)) != "provider-"+instance+"-"+generations[instance] {
			t.Fatalf("%s home %q is outside its own namespace generation", instance, home)
		}
	}
	for _, registry := range constructed {
		receipt, closeErr := registry.Close(context.Background())
		if closeErr != nil || !receipt.Valid() {
			t.Fatalf("concurrent registry close = %v, receipt valid = %t", closeErr, receipt.Valid())
		}
	}
}

// barrierWorkspaceFactory is a two-caller rendezvous: the first materializer
// blocks until the second has also entered, so both factory acquisitions are
// provably in flight together before either lease is built.
type barrierWorkspaceFactory struct {
	arrivals atomic.Int32
	release  chan struct{}
	once     sync.Once
	leases   chan *fixtureTestWorkspaceLease
	next     atomic.Int32
}

func (factory *barrierWorkspaceFactory) MaterializeQualificationLease(_ context.Context, request ports.WorkspaceSnapshotRequest) (ports.QualificationWorkspaceLease, error) {
	if factory.arrivals.Add(1) == 2 {
		factory.once.Do(func() { close(factory.release) })
	} else {
		select {
		case <-factory.release:
		case <-time.After(10 * time.Second):
			factory.once.Do(func() { close(factory.release) })
			return nil, fmt.Errorf("second fixture materialization never started; acquisitions appear serialized")
		}
	}
	policyIdentity := request.PolicyIdentity()
	lease, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		index := int(factory.next.Add(1))
		identity, identityErr := ports.NewWorkspaceSnapshotIdentity(
			fmt.Sprintf("fixture-root-%d", index),
			fmt.Sprintf("snapshot-%032d", index),
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			policyIdentity, 1, 2, 3, 4,
		)
		if identityErr != nil {
			return nil, identityErr
		}
		acquired := &fixtureTestWorkspaceLease{identity: identity}
		drain, bindErr := binding.Bind(identity, acquired.drainTerminalEffects)
		if bindErr != nil {
			return nil, bindErr
		}
		acquired.terminalDrain = drain
		factory.leases <- acquired
		return acquired, nil
	})
	return lease, err
}

// TestProbeFixtureLeaseFactoryConcurrentAcquire overlaps two Acquire calls on
// the real probe fixture lease factory (real nonce generator): both workspace
// materializations must be in flight simultaneously before either completes,
// and the resulting fixtures must be nonce-distinct and valid.
func TestProbeFixtureLeaseFactoryConcurrentAcquire(t *testing.T) {
	workspaces := &barrierWorkspaceFactory{release: make(chan struct{}), leases: make(chan *fixtureTestWorkspaceLease, 2)}
	defer workspaces.once.Do(func() { close(workspaces.release) })
	factory, err := NewProbeFixtureLeaseFactory(workspaces, SecureProbeNonceGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	fixtures := make(chan ProbeFixtureLease, 2)
	failures := make(chan error, 2)
	var wait sync.WaitGroup
	for _, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		wait.Add(1)
		go func(role domain.Role) {
			defer wait.Done()
			fixture, acquireErr := factory.Acquire(context.Background(), role)
			if acquireErr != nil {
				failures <- acquireErr
				return
			}
			fixtures <- fixture
		}(role)
	}
	wait.Wait()
	close(fixtures)
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
	var acquired []ProbeFixtureLease
	for fixture := range fixtures {
		acquired = append(acquired, fixture)
	}
	if len(acquired) != 2 {
		t.Fatalf("acquired fixtures = %d, want 2", len(acquired))
	}
	if acquired[0].Nonce() == acquired[1].Nonce() || acquired[0].Link() == acquired[1].Link() {
		t.Fatal("concurrent fixture acquisition shared a nonce or link")
	}
	const (
		wantPolicy      = "current-qualification-fixture-v4"
		wantFirstLine   = "Prove readiness by returning exactly one JSON object and nothing else.\n"
		wantNeutralLine = "The root, link, and role values below are random synthetic test identifiers with no secret meaning.\n"
	)
	for _, fixture := range acquired {
		if err := fixture.Validate(); err != nil {
			t.Fatalf("concurrently acquired fixture invalid: %v", err)
		}
		if got := fixture.WorkspaceSnapshotIdentity().PolicyIdentity(); got != wantPolicy {
			t.Fatalf("concurrently acquired fixture policy = %q, want %q", got, wantPolicy)
		}
		packet := string(fixture.Packet())
		if !strings.HasPrefix(packet, wantFirstLine) ||
			!strings.Contains(packet, wantNeutralLine+"root="+fixture.Nonce()+"\nlink="+fixture.Link()+"\nrole="+string(fixture.Role())+"\n") {
			t.Fatalf("concurrently acquired fixture packet lost v4 framing or bindings: %q", packet)
		}
	}
	close(workspaces.leases)
	identities := make(map[string]struct{}, 2)
	for lease := range workspaces.leases {
		if got := lease.WorkspaceSnapshotIdentity().PolicyIdentity(); got != wantPolicy {
			t.Fatalf("materialized workspace policy = %q, want %q", got, wantPolicy)
		}
		identities[lease.WorkspaceSnapshotIdentity().SnapshotPath()] = struct{}{}
		if _, err := lease.DrainTerminal(context.Background()); err != nil {
			t.Fatalf("concurrently acquired workspace drain: %v", err)
		}
	}
	if len(identities) != 2 {
		t.Fatalf("workspace identities = %v, want two distinct snapshots", identities)
	}
}
