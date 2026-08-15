package reviewrun

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func qualificationTestReceipt(kind ReceiptKind, state ReceiptState, expiresAt time.Time, identity Identity) Receipt {
	return Receipt{Kind: kind, State: state, ExpiresAt: expiresAt, Identity: identity}
}

type qualifierClock struct{ now time.Time }

func (clock qualifierClock) Now() time.Time { return clock.now }

type qualifierRegistry struct {
	namespaces    map[string]ports.ProviderQualificationNamespace
	receipt       ports.ProviderRunTerminalReceipt
	closeErr      error
	closeErrs     []error
	closeContexts []context.Context
	closeFn       func(context.Context) error
	closed        int
}

func (registry *qualifierRegistry) QualificationNamespace(instance string) (ports.ProviderQualificationNamespace, bool) {
	namespace, ok := registry.namespaces[instance]
	return namespace, ok
}

func (registry *qualifierRegistry) Close(ctx context.Context) (ports.ProviderRunTerminalReceipt, error) {
	registry.closed++
	registry.closeContexts = append(registry.closeContexts, ctx)
	if registry.closeFn != nil {
		if err := registry.closeFn(ctx); err != nil {
			return ports.ProviderRunTerminalReceipt{}, err
		}
	}
	if len(registry.closeErrs) > 0 {
		err := registry.closeErrs[0]
		registry.closeErrs = registry.closeErrs[1:]
		if err != nil {
			return ports.ProviderRunTerminalReceipt{}, err
		}
	}
	if registry.closeErr != nil {
		return ports.ProviderRunTerminalReceipt{}, registry.closeErr
	}
	return registry.receipt, nil
}

func (registry *qualifierRegistry) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return ports.ProviderExecutionObservation{}, nil
}

type qualifierNamespace struct {
	instance, generation, policy string
}

func (namespace qualifierNamespace) ProviderInstance() string { return namespace.instance }
func (namespace qualifierNamespace) Generation() string       { return namespace.generation }
func (namespace qualifierNamespace) Environment() []ports.EnvironmentVariable {
	return nil
}
func (namespace qualifierNamespace) RuntimeSafetyPolicyIdentity() string { return namespace.policy }
func (namespace qualifierNamespace) NativeHomeLaunchAuthority() (ports.NativeHomeLaunchAuthority, bool) {
	return ports.NativeHomeLaunchAuthority{}, false
}
func (namespace qualifierNamespace) WorkingDirectory() string { return "/private/work" }
func (namespace qualifierNamespace) ValidateForSpawn() error  { return nil }

type qualifierRegistryFactory struct{ registry *qualifierRegistry }

func (factory qualifierRegistryFactory) NewProviderQualificationRegistry(_ context.Context, definitions []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	for _, definition := range definitions {
		if _, ok := factory.registry.namespaces[definition.Instance()]; !ok {
			factory.registry.namespaces[definition.Instance()] = qualifierNamespace{
				instance: definition.Instance(), generation: "generation-1", policy: definition.RuntimeSafetyPolicyIdentity(),
			}
		}
	}
	return factory.registry, nil
}

func (qualifierRegistryFactory) RegistryFromConstructionError(error) (ports.ProviderQualificationRegistry, bool) {
	return nil, false
}

type qualifierRegistrySequenceFactory struct {
	registries []*qualifierRegistry
	calls      int
}

func (factory *qualifierRegistrySequenceFactory) NewProviderQualificationRegistry(_ context.Context, _ []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	if factory.calls >= len(factory.registries) {
		return nil, errors.New("unexpected registry construction")
	}
	registry := factory.registries[factory.calls]
	factory.calls++
	return registry, nil
}

func (*qualifierRegistrySequenceFactory) RegistryFromConstructionError(error) (ports.ProviderQualificationRegistry, bool) {
	return nil, false
}

type qualifierLoginAuthenticator struct {
	calls       int
	definitions []ports.ProviderRuntimeDefinition
	err         error
}

func (authenticator *qualifierLoginAuthenticator) LoginProvider(_ context.Context, definition ports.ProviderRuntimeDefinition) error {
	authenticator.calls++
	authenticator.definitions = append(authenticator.definitions, definition)
	return authenticator.err
}

func TestQualifiedRunFactoryQualifiesIdentityOnlyProfileAndRetainsNamespace(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	profile := DiscoveredProviderProfile{family: FamilyKimi, executable: "/private/bin/kimi", launcher: "/private/bin/kimi", argv: []string{"/private/bin/kimi"}, sha256: qualifierTestSHA, launcherSHA256: qualifierTestSHA, reason: "unqualified_discovery"}
	transport, err := providercli.NewRuntimeTransport(ports.ProviderPacketChannelStdin, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := providercli.NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy("kimi", "kimi-main", "", "/private/bin/kimi", qualifierTestSHA, "/private/bin/kimi", qualifierTestSHA, "kimi-default", "profile-generation", "policy-identity", []string{"/private/bin/kimi"}, transport, nil, "/private/work", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	namespaceReceipt := acquiredProviderNamespaceTerminalReceipt(t, "kimi-main", "generation-1")
	aggregate := mustProviderRunTerminalReceipt(t, namespaceReceipt)
	registry := &qualifierRegistry{namespaces: map[string]ports.ProviderQualificationNamespace{}, receipt: aggregate}
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		if request.Namespace == nil || request.Namespace.ProviderInstance() != request.Identity.Instance ||
			request.Namespace.Generation() != request.Identity.NamespaceGeneration ||
			request.Namespace.RuntimeSafetyPolicyIdentity() != request.Definition.RuntimeSafetyPolicyIdentity() {
			t.Fatalf("qualification namespace does not match retained identity")
		}
		if request.BaseRole != domain.RoleLogic || len(request.RequestedRoles) != 1 || request.RequestedRoles[0] != domain.RoleLogic {
			t.Fatalf("qualification roles = base %q, requested %v", request.BaseRole, request.RequestedRoles)
		}
		identity := request.Identity
		identity.Version = "0.23.6"
		receipts := make([]Receipt, 0, len(ReceiptKinds()))
		for _, kind := range ReceiptKinds() {
			state := ReceiptPass
			if kind == ReceiptSecurityPolicy {
				state = ReceiptInconclusive
			}
			receipts = append(receipts, qualificationTestReceipt(kind, state, now.Add(time.Minute), identity))
		}
		return CurrentQualificationResult{
			VersionArgv: []string{"/private/bin/kimi", "--version"}, Version: "0.23.6", Receipts: receipts,
			SupportedRoles: []domain.Role{domain.RoleLogic}, RoleReceipts: []CurrentRoleReceipt{{Role: domain.RoleLogic, State: ReceiptPass, Identity: identity}},
			BaseRole: domain.RoleLogic,
		}, nil
	})
	factory, err := NewQualifiedRunFactory(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{{Profile: profile, Definition: definition, SnapshotManifest: "snapshot-manifest", SupportedRoles: []domain.Role{domain.RoleLogic}, BaseRole: domain.RoleLogic, Limits: limits}})
	if err == nil || registry.closed != 1 {
		t.Fatalf("Kimi security-inconclusive qualification admitted: %v; closes=%d", err, registry.closed)
	}
}

func TestQualifiedRunTerminalReceiptRequiresExactAdmittedSet(t *testing.T) {
	alpha := terminalEvidence("alpha-main")
	beta := terminalEvidence("beta-main")
	alphaNamespace := acquiredProviderNamespaceTerminalReceipt(t, "alpha-main", "generation")
	betaNamespace := acquiredProviderNamespaceTerminalReceipt(t, "beta-main", "generation")
	aggregate := mustProviderRunTerminalReceipt(t, betaNamespace, alphaNamespace)
	terminal, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{beta, alpha}, aggregate)
	if err != nil {
		t.Fatal(err)
	}
	providers := terminal.Providers()
	if len(providers) != 2 || providers[0].Identity().Instance != "alpha-main" ||
		providers[1].Identity().Instance != "beta-main" ||
		providers[0].NamespaceTerminalReceiptID() != alphaNamespace.ReceiptID() {
		t.Fatalf("canonical terminal providers = %#v", providers)
	}
	if _, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{alpha}, aggregate); err == nil {
		t.Fatal("extra terminal namespace accepted")
	}
	if _, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{alpha, alpha}, aggregate); err == nil {
		t.Fatal("duplicate admitted terminal instance accepted")
	}
	if _, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{alpha}, mustProviderRunTerminalReceipt(t, betaNamespace)); err == nil {
		t.Fatal("missing terminal namespace accepted")
	}
}

func terminalEvidence(instance string) qualifiedProviderEvidence {
	identity := Identity{
		Family: FamilyKimi, Instance: instance, ProfileGeneration: "profile-generation", AdapterProfile: "kimi-default",
		Version: "0.23.6", Executable: "/private/bin/kimi", ExecutableSHA256: qualifierTestSHA,
		Launcher: "/private/bin/kimi", LauncherSHA256: qualifierTestSHA, SnapshotManifest: "snapshot-manifest",
		NamespaceLease: instance + ":generation", NamespaceGeneration: "generation",
	}
	return qualifiedProviderEvidence{
		identity: identity, qualificationReceiptIDs: []string{"qualification:" + instance},
		packetTransportReceiptIDs: []string{"transport:" + instance},
	}
}

func mustProviderRunTerminalReceipt(t *testing.T, namespaces ...ports.ProviderNamespaceTerminalReceipt) ports.ProviderRunTerminalReceipt {
	t.Helper()
	receipt, err := ports.NewProviderRunTerminalReceipt(namespaces)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

type terminalNamespaceLease struct {
	instance        string
	generation      string
	drain           ports.ProviderNamespaceTerminalDrain
	terminalEffects int
}

func (lease *terminalNamespaceLease) ProviderInstance() string           { return lease.instance }
func (lease *terminalNamespaceLease) Generation() string                 { return lease.generation }
func (*terminalNamespaceLease) Environment() []ports.EnvironmentVariable { return nil }
func (*terminalNamespaceLease) ProjectCredential(context.Context, ports.CredentialProjectionRequest) (ports.CredentialProjectionReceipt, error) {
	return ports.CredentialProjectionReceipt{}, errors.New("unexpected credential projection")
}
func (*terminalNamespaceLease) ValidateForSpawn() error { return nil }
func (lease *terminalNamespaceLease) DrainTerminal(ctx context.Context) (ports.ProviderNamespaceTerminalReceipt, error) {
	return lease.drain(ctx)
}

func acquiredProviderNamespaceTerminalReceipt(t *testing.T, instance, generation string) ports.ProviderNamespaceTerminalReceipt {
	t.Helper()
	lease := &terminalNamespaceLease{instance: instance, generation: generation}
	acquired, err := ports.AcquireProviderNamespaceLease(context.Background(), instance, func(_ context.Context, acquiredInstance string, binding ports.ProviderNamespaceTerminalBinding) (ports.ProviderNamespaceLease, error) {
		if acquiredInstance != instance {
			return nil, errors.New("unexpected provider instance")
		}
		drain, err := binding.Bind(generation, func(context.Context) error {
			lease.terminalEffects++
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
	receipt, err := acquired.DrainTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lease.terminalEffects != 1 {
		t.Fatalf("terminal effects = %d, want 1", lease.terminalEffects)
	}
	return receipt
}
func TestQualifiedRunDrainDoesNotConstructReceiptOnCloseFailure(t *testing.T) {
	registry := &qualifierRegistry{closeErr: errors.New("drain failed")}
	run := &QualifiedRun{registry: registry}
	receipt, err := run.DrainTerminal(context.Background())
	if err == nil || receipt.Drained() || len(receipt.NamespaceReceipts()) != 0 {
		t.Fatalf("failed drain receipt = %#v, %v", receipt, err)
	}
	if registry.closed != 1 {
		t.Fatalf("close calls = %d", registry.closed)
	}
}
func TestQualifiedRunFactoryRejectsEveryNonPassReceiptState(t *testing.T) {
	for _, state := range []ReceiptState{ReceiptMissing, ReceiptStale, ReceiptSkipped, ReceiptInconclusive, ReceiptFailed} {
		t.Run(string(state), func(t *testing.T) {
			input := completeInput(t, FamilyAGY, "1.1.4")
			input.Receipts[len(input.Receipts)-1].State = state
			qualification := ValidateQualification(input)
			if qualification.Available() || qualification.Reason() != "non_passing_receipt" {
				t.Fatalf("state %q = available %t, reason %q", state, qualification.Available(), qualification.Reason())
			}
		})
	}
}

func TestValidateQualificationRequiresSharedReceiptExpiry(t *testing.T) {
	input := completeInput(t, FamilyAGY, "1.1.4")
	input.Receipts[1].ExpiresAt = input.Receipts[1].ExpiresAt.Add(time.Second)
	qualification := ValidateQualification(input)
	if qualification.Available() || qualification.Reason() != "expiry_mismatch" {
		t.Fatalf("qualification = available %t, reason %q", qualification.Available(), qualification.Reason())
	}
}

const qualifierTestSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestQualifiedSupportedRolesRequiresExactRequestedReceipts(t *testing.T) {
	identity := Identity{Version: "0.23.6"}
	candidate := QualifiedRunCandidate{
		SupportedRoles: []domain.Role{domain.RoleSecurity, domain.RoleLogic},
		BaseRole:       domain.RoleLogic,
	}
	for _, receipts := range [][]CurrentRoleReceipt{
		{{Role: domain.RoleLogic, State: ReceiptPass, Identity: identity}},
		{{Role: domain.RoleLogic, State: ReceiptPass, Identity: identity}, {Role: domain.RoleSecurity, State: ReceiptPass, Identity: identity}, {Role: domain.RoleTesting, State: ReceiptPass, Identity: identity}},
		{{Role: domain.RoleLogic, State: ReceiptPass, Identity: identity}, {Role: domain.RoleSecurity, State: ReceiptPass, Identity: identity}, {Role: domain.RoleSecurity, State: ReceiptPass, Identity: identity}},
	} {
		_, err := qualifiedSupportedRoles(candidate, CurrentQualificationResult{BaseRole: domain.RoleLogic, SupportedRoles: []domain.Role{domain.RoleLogic, domain.RoleSecurity}, RoleReceipts: receipts}, identity)
		if err == nil {
			t.Fatalf("non-exact role receipts accepted: %#v", receipts)
		}
	}
	roles, err := qualifiedSupportedRoles(candidate, CurrentQualificationResult{
		BaseRole:       domain.RoleLogic,
		SupportedRoles: []domain.Role{domain.RoleSecurity, domain.RoleLogic},
		RoleReceipts: []CurrentRoleReceipt{
			{Role: domain.RoleSecurity, State: ReceiptPass, Identity: identity},
			{Role: domain.RoleLogic, State: ReceiptPass, Identity: identity},
		},
	}, identity)
	if err != nil || len(roles) != 2 || roles[0] != domain.RoleLogic || roles[1] != domain.RoleSecurity {
		t.Fatalf("exact role receipts = %v, %v", roles, err)
	}
}
func TestQualifiedRunTerminalReceiptRejectsStaleNamespaceGeneration(t *testing.T) {
	stale := acquiredProviderNamespaceTerminalReceipt(t, "kimi-main", "stale-generation")
	if _, err := newQualifiedRunTerminalReceipt([]qualifiedProviderEvidence{terminalEvidence("kimi-main")}, mustProviderRunTerminalReceipt(t, stale)); err == nil {
		t.Fatal("stale namespace generation accepted")
	}
}

func TestQualifiedRunRegistryCompositeRetriesOnlyUnclosedChild(t *testing.T) {
	namespace := acquiredProviderNamespaceTerminalReceipt(t, "kimi-main", "generation-1")
	registry := &qualifierRegistry{
		receipt:   mustProviderRunTerminalReceipt(t, namespace),
		closeErrs: []error{errors.New("first close failed")},
	}
	composite := &qualifiedRunRegistryComposite{
		registries:  map[string]QualifiedRunRegistry{"kimi-main": registry},
		generations: map[string]string{"kimi-main": "generation-1"},
		instances:   []string{"kimi-main"},
	}
	ctx := context.Background()
	if _, err := composite.Close(ctx); err == nil {
		t.Fatal("first close succeeded")
	}
	if receipt, err := composite.Close(ctx); err != nil || !receipt.Valid() {
		t.Fatalf("retry close = %#v, %v", receipt, err)
	}
	if registry.closed != 2 || len(registry.closeContexts) != 2 || registry.closeContexts[0] != ctx || registry.closeContexts[1] != ctx {
		t.Fatalf("close ownership/context = closes %d contexts %#v", registry.closed, registry.closeContexts)
	}
}
func TestQualifiedRunFactoryConstructionCleanupRetriesAndRetainsOwner(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	registry.closeErrs = []error{errors.New("first close failed"), nil}
	qualifier := CurrentQualifierFunc(func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error) {
		return CurrentQualificationResult{}, errors.New("qualification failed")
	})
	factory, err := NewQualifiedRunFactory(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{authorityCandidate(t)})
	if err == nil {
		t.Fatal("construction succeeded")
	}
	if receipt, ok := ProviderRunTerminalReceiptFromError(err); !ok || !receipt.Valid() || receipt.NoNamespaces() {
		t.Fatalf("retry terminal receipt = %#v, present=%t", receipt, ok)
	}
	if _, ok := QualifiedRunRegistryFromError(err); ok || registry.closed != 2 {
		t.Fatalf("retry retained cleanup owner = %t; closes=%d", ok, registry.closed)
	}

	registry = newAuthorityRegistry(t)
	registry.closeErrs = []error{errors.New("first close failed"), errors.New("second close failed")}
	factory, err = NewQualifiedRunFactory(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{authorityCandidate(t)})
	if err == nil {
		t.Fatal("persistent construction succeeded")
	}
	if receipt, ok := ProviderRunTerminalReceiptFromError(err); ok || receipt.Valid() {
		t.Fatalf("persistent cleanup represented as terminal proof = %#v, present=%t", receipt, ok)
	}
	owner, ok := QualifiedRunRegistryFromError(err)
	if !ok || owner == nil || registry.closed != 2 {
		t.Fatalf("persistent cleanup owner = %#v, present=%t; closes=%d", owner, ok, registry.closed)
	}
	authority, ok := RunAuthorityFromError(err)
	if !ok || authority == nil {
		t.Fatalf("persistent cleanup authority = %#v, present=%t", authority, ok)
	}
	terminal, err := authority.DrainTerminal(context.Background())
	if err != nil || !terminal.Drained() || !terminal.ProviderRunTerminalReceipt().Valid() ||
		terminal.ProviderRunTerminalReceipt().NoNamespaces() || registry.closed != 3 {
		t.Fatalf("retained cleanup retry = %#v, %v; closes=%d", terminal, err, registry.closed)
	}
}

func TestQualifiedRunFactoryDoesNotSkipLoginRequiredCandidate(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		cause, err := domain.NewFailure(
			"capability",
			domain.FailureAuthentication,
			"provider login required",
			ports.ErrProviderLoginRequired,
		)
		if err != nil {
			return CurrentQualificationResult{}, err
		}
		return CurrentQualificationResult{}, NewProviderLoginRequiredError([]string{request.Definition.Instance()}, cause)
	})
	factory, err := NewQualifiedRunFactory(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidate := authorityCandidate(t)
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{candidate})
	providers, ok := ProviderLoginRequiredProvidersFromError(err)
	if !ok || !errors.Is(err, ports.ErrProviderLoginRequired) ||
		len(providers) != 1 || providers[0] != candidate.Definition.Instance() {
		t.Fatalf("login-required construction = providers %#v error %v", providers, err)
	}
	if registry.closed != 1 {
		t.Fatalf("registry closes = %d, want 1", registry.closed)
	}
	if terminal, ok := ProviderRunTerminalReceiptFromError(err); !ok || !terminal.Valid() {
		t.Fatalf("login-required terminal cleanup = %#v present=%t", terminal, ok)
	}
}

func TestQualifiedRunFactoryLogsInKimiOnceAndRestartsWithFreshNamespace(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	candidate := authorityCandidateForRoles(t, FamilyKimi, "kimi-main", []domain.Role{domain.RoleLogic})
	registry := func(generation string) *qualifierRegistry {
		namespace := &qualifierNamespace{instance: candidate.Definition.Instance(), generation: generation, policy: candidate.Definition.RuntimeSafetyPolicyIdentity()}
		return &qualifierRegistry{
			namespaces: map[string]ports.ProviderQualificationNamespace{candidate.Definition.Instance(): namespace},
			receipt:    mustProviderRunTerminalReceipt(t, acquiredProviderNamespaceTerminalReceipt(t, candidate.Definition.Instance(), generation)),
		}
	}
	first, second := registry("generation-1"), registry("generation-1")
	registries := &qualifierRegistrySequenceFactory{registries: []*qualifierRegistry{first, second}}
	authenticator := &qualifierLoginAuthenticator{}
	qualifications := 0
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		qualifications++
		if qualifications == 1 {
			cause, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
			if err != nil {
				t.Fatal(err)
			}
			observation := rejectedQualificationObservation(request.Definition.Instance(), cause, false)
			return CurrentQualificationResult{}, withQualificationObservations(NewProviderLoginRequiredError([]string{request.Definition.Instance()}, cause), []ProviderQualificationObservation{observation})
		}
		if request.Namespace == first.namespaces[candidate.Definition.Instance()] {
			t.Fatal("retry reused the drained qualification namespace")
		}
		result, err := authorityQualifier(t, now).QualifyCurrent(context.Background(), request)
		if err != nil {
			return CurrentQualificationResult{}, err
		}
		result.Observations = []ProviderQualificationObservation{qualifiedQualificationObservation(request.Definition.Instance())}
		return result, nil
	})
	factory, err := NewQualifiedRunFactoryWithLoginAuthenticator(qualifier, registries, qualifierClock{now: now}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	run, err := factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	if authenticator.calls != 1 || len(authenticator.definitions) != 1 || authenticator.definitions[0].Instance() != candidate.Definition.Instance() {
		t.Fatalf("login calls = %d definitions=%#v", authenticator.calls, authenticator.definitions)
	}
	if qualifications != 2 || registries.calls != 2 || first.closed != 1 || second.closed != 0 {
		t.Fatalf("attempts=%d registries=%d closes=(%d,%d)", qualifications, registries.calls, first.closed, second.closed)
	}
	observations := run.QualificationObservations()
	if len(observations) != 2 || observations[0].Mitigation() != qualificationMitigationLogin || observations[1].Outcome() != qualificationOutcomeQualified {
		t.Fatalf("login recovery observations = %#v", observations)
	}
	if _, err := run.Registry().Close(context.Background()); err != nil || second.closed != 1 {
		t.Fatalf("close recovered run: %v; closes=%d", err, second.closed)
	}
}

func TestQualifiedRunFactoryDoesNotAutoLoginForNonKimiProvider(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	authenticator := &qualifierLoginAuthenticator{}
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		cause, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
		if err != nil {
			t.Fatal(err)
		}
		return CurrentQualificationResult{}, NewProviderLoginRequiredError([]string{request.Definition.Instance()}, cause)
	})
	factory, err := NewQualifiedRunFactoryWithLoginAuthenticator(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{authorityCandidate(t)})
	if _, ok := ProviderLoginRequiredProvidersFromError(err); !ok || authenticator.calls != 0 || registry.closed != 1 {
		t.Fatalf("non-Kimi recovery: error=%v login calls=%d closes=%d", err, authenticator.calls, registry.closed)
	}
}

func TestQualifiedRunFactoryBoundsKimiLoginRecoveryToOneAttempt(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	candidate := authorityCandidateForRoles(t, FamilyKimi, "kimi-main", []domain.Role{domain.RoleLogic})
	registry := func() *qualifierRegistry {
		return &qualifierRegistry{
			namespaces: map[string]ports.ProviderQualificationNamespace{candidate.Definition.Instance(): &qualifierNamespace{
				instance: candidate.Definition.Instance(), generation: "generation-1", policy: candidate.Definition.RuntimeSafetyPolicyIdentity(),
			}},
			receipt: mustProviderRunTerminalReceipt(t, acquiredProviderNamespaceTerminalReceipt(t, candidate.Definition.Instance(), "generation-1")),
		}
	}
	first, second := registry(), registry()
	registries := &qualifierRegistrySequenceFactory{registries: []*qualifierRegistry{first, second}}
	authenticator := &qualifierLoginAuthenticator{}
	qualifications := 0
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		qualifications++
		cause, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
		if err != nil {
			t.Fatal(err)
		}
		observation := rejectedQualificationObservation(request.Definition.Instance(), cause, false)
		return CurrentQualificationResult{}, withQualificationObservations(NewProviderLoginRequiredError([]string{request.Definition.Instance()}, cause), []ProviderQualificationObservation{observation})
	})
	factory, err := NewQualifiedRunFactoryWithLoginAuthenticator(qualifier, registries, qualifierClock{now: now}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{candidate})
	providers, loginRequired := ProviderLoginRequiredProvidersFromError(err)
	if !loginRequired || len(providers) != 1 || providers[0] != candidate.Definition.Instance() {
		t.Fatalf("bounded recovery error = providers %#v error %v", providers, err)
	}
	if authenticator.calls != 1 || qualifications != 2 || registries.calls != 2 || first.closed != 1 || second.closed != 1 {
		t.Fatalf("login=%d qualifications=%d registries=%d closes=(%d,%d)", authenticator.calls, qualifications, registries.calls, first.closed, second.closed)
	}
	observations := qualificationObservationsFromError(err)
	if len(observations) != 2 || observations[0].Mitigation() != qualificationMitigationLogin || observations[1].Mitigation() != "" {
		t.Fatalf("bounded recovery observations = %#v", observations)
	}
}

func TestQualifiedRunFactoryDoesNotLoginBeforeQualificationNamespaceDrains(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	candidate := authorityCandidateForRoles(t, FamilyKimi, "kimi-main", []domain.Role{domain.RoleLogic})
	registry := &qualifierRegistry{
		namespaces: map[string]ports.ProviderQualificationNamespace{candidate.Definition.Instance(): &qualifierNamespace{
			instance: candidate.Definition.Instance(), generation: "generation-1", policy: candidate.Definition.RuntimeSafetyPolicyIdentity(),
		}},
		receipt:   mustProviderRunTerminalReceipt(t, acquiredProviderNamespaceTerminalReceipt(t, candidate.Definition.Instance(), "generation-1")),
		closeErrs: []error{errors.New("first drain failed"), errors.New("second drain failed")},
	}
	authenticator := &qualifierLoginAuthenticator{}
	qualifier := CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		cause, err := domain.NewFailure("capability", domain.FailureAuthentication, "provider login required", ports.ErrProviderLoginRequired)
		if err != nil {
			t.Fatal(err)
		}
		return CurrentQualificationResult{}, NewProviderLoginRequiredError([]string{request.Definition.Instance()}, cause)
	})
	factory, err := NewQualifiedRunFactoryWithLoginAuthenticator(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{candidate})
	if err == nil || authenticator.calls != 0 || registry.closed != 2 {
		t.Fatalf("incomplete drain recovery: error=%v login=%d closes=%d", err, authenticator.calls, registry.closed)
	}
	if _, ok := QualifiedRunRegistryFromError(err); !ok {
		t.Fatalf("incomplete drain did not retain cleanup authority: %v", err)
	}
}

func TestQualifiedRunFactoryReportsOperationalQualificationFailure(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	auth, err := domain.NewFailure("capability", domain.FailureAuthentication, "authentication unavailable", nil)
	if err != nil {
		t.Fatal(err)
	}
	qualifier := CurrentQualifierFunc(func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error) {
		return CurrentQualificationResult{}, auth
	})
	factory, err := NewQualifiedRunFactory(qualifier, qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidate := authorityCandidate(t)
	_, err = factory.NewQualifiedRun(context.Background(), []QualifiedRunCandidate{candidate})
	failures, ok := ProviderQualificationFailuresFromError(err)
	if !ok || len(failures) != 1 || failures[0].ProviderInstance() != candidate.Definition.Instance() ||
		failures[0].Family() != Family(candidate.Definition.Family()) || failures[0].ReasonCode() != string(domain.FailureAuthentication) {
		t.Fatalf("qualification failures = %#v present=%t error=%v", failures, ok, err)
	}
	if registry.closed != 1 {
		t.Fatalf("registry closes = %d, want 1", registry.closed)
	}
}
func TestQualifiedRunConstructionErrorRetainsPartialTerminalEvidence(t *testing.T) {
	alpha := acquiredProviderNamespaceTerminalReceipt(t, "alpha-main", "generation-1")
	beta := acquiredProviderNamespaceTerminalReceipt(t, "beta-main", "generation-1")
	owner := &qualifiedRunRegistryComposite{
		registries: map[string]QualifiedRunRegistry{
			"beta-main": &qualifierRegistry{receipt: mustProviderRunTerminalReceipt(t, beta)},
		},
		generations: map[string]string{"beta-main": "generation-1"},
		instances:   []string{"alpha-main", "beta-main"},
		closed:      map[string]ports.ProviderRunTerminalReceipt{"alpha-main": mustProviderRunTerminalReceipt(t, alpha)},
	}
	construction := newQualifiedRunConstructionError(errors.New("construction failed"), ports.ProviderRunTerminalReceipt{}, owner)
	if receipt, ok := ProviderRunTerminalReceiptFromError(construction); ok || receipt.Valid() {
		t.Fatalf("partial cleanup represented as terminal proof = %#v, present=%t", receipt, ok)
	}
	retained, ok := QualifiedRunRegistryFromError(construction)
	if !ok || retained != owner {
		t.Fatalf("partial cleanup owner = %#v, present=%t", retained, ok)
	}
	receipt, err := retained.Close(context.Background())
	if err != nil || !receipt.Valid() || len(receipt.NamespaceReceipts()) != 2 ||
		receipt.NamespaceReceipts()[0].ProviderInstance() != "alpha-main" ||
		receipt.NamespaceReceipts()[1].ProviderInstance() != "beta-main" {
		t.Fatalf("merged partial terminal evidence = %#v, %v", receipt, err)
	}
}

func TestQualifiedRunRegistryCompositePassesDeadlineToBlockingChildClose(t *testing.T) {
	namespace := acquiredProviderNamespaceTerminalReceipt(t, "kimi-main", "generation-1")
	registry := &qualifierRegistry{
		receipt: mustProviderRunTerminalReceipt(t, namespace),
		closeFn: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	composite := &qualifiedRunRegistryComposite{
		registries:  map[string]QualifiedRunRegistry{"kimi-main": registry},
		generations: map[string]string{"kimi-main": "generation-1"},
		instances:   []string{"kimi-main"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := composite.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocking close error = %v", err)
	}
	if len(registry.closeContexts) != 1 || registry.closeContexts[0] != ctx {
		t.Fatalf("blocking close context = %#v", registry.closeContexts)
	}
}
