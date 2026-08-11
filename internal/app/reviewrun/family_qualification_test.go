package reviewrun

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestGroupCandidatesByFamilyRuntimeProfileDeduplicatesRoles(t *testing.T) {
	zcodeLogic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeSecurity := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
	agyLogic := authorityCandidateForFamilyRole(t, FamilyAGY, domain.RoleLogic)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeLogic, zcodeSecurity, agyLogic})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	batches := scheduleFamilyQualificationGroups(groups)
	if len(batches) != 1 || len(batches[0]) != 2 {
		t.Fatalf("ZCode/AGY overlap batches = %#v", batches)
	}
	var zcodeRoles, agyRoles []domain.Role
	for _, group := range groups {
		switch group.family {
		case FamilyZCode:
			zcodeRoles = group.roles
		case FamilyAGY:
			agyRoles = group.roles
		}
	}
	if !reflect.DeepEqual(zcodeRoles, []domain.Role{domain.RoleLogic, domain.RoleSecurity}) {
		t.Fatalf("zcode roles = %v", zcodeRoles)
	}
	if !reflect.DeepEqual(agyRoles, []domain.Role{domain.RoleLogic}) {
		t.Fatalf("agy roles = %v", agyRoles)
	}
}

func TestFamilyRuntimeProfileKeyRejectsCapabilityRelevantMutations(t *testing.T) {
	base := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	baseKey := familyRuntimeProfileKeyFor(base.Definition)
	sibling := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
	if familyRuntimeProfileKeyFor(sibling.Definition) != baseKey {
		t.Fatal("sibling role route did not share the family profile key")
	}

	for name, mutate := range map[string]func(*testRuntimeMutation){
		"transport-index": func(d *testRuntimeMutation) { d.transportArgvIndex++ },
		"base-argv":       func(d *testRuntimeMutation) { d.baseArgv = append(append([]string(nil), d.baseArgv...), "--other") },
		"transport-ref":   func(d *testRuntimeMutation) { d.transportReference = "@other.md" },
		"working-dir":     func(d *testRuntimeMutation) { d.workingDirectory = "/private/other" },
		"max-stdout":      func(d *testRuntimeMutation) { d.maxStdoutBytes++ },
		"max-stderr":      func(d *testRuntimeMutation) { d.maxStderrBytes++ },
		"executable":      func(d *testRuntimeMutation) { d.executable = "/private/bin/other-node" },
		"launcher":        func(d *testRuntimeMutation) { d.launcher = "/private/bin/other-launcher" },
		"safety-policy":   func(d *testRuntimeMutation) { d.runtimeSafetyPolicyIdentity = "other-policy" },
		"kimi-model":      func(d *testRuntimeMutation) { d.kimiModel = "other-model" },
		"lifecycle": func(d *testRuntimeMutation) {
			lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingTerminalJSONObject, time.Second, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			d.lifecycle = lifecycle
			d.hasLifecycle = true
		},
		"environment": func(d *testRuntimeMutation) {
			d.environment = append(append([]ports.EnvironmentVariable(nil), d.environment...), mustEnvVar(t, "MULGAE_TEST", "1"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := mutateFamilyCandidateDefinition(t, base, mutate)
			if familyRuntimeProfileKeyFor(mutated.Definition) == baseKey {
				t.Fatalf("family profile key ignored %s mutation", name)
			}
		})
	}
}

func TestFamilyQualificationDerivesSiblingRoleRoutesFromOneProbe(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	var calls atomic.Int32
	var derives atomic.Int32
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			calls.Add(1)
			return syntheticFamilyQualificationResult(t, request, now), nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			derives.Add(1)
			if familyRuntimeProfileKeyFor(request.SourceDefinition) != familyRuntimeProfileKeyFor(request.Destination.Definition) {
				t.Fatal("derivation invoked across unequal family profiles")
			}
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	registryFactory := qualifierRegistryFactory{registry: newAuthorityRegistry(t)}
	factory, err := NewQualifiedRunFactory(qualifier, registryFactory, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []QualifiedRunCandidate{
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity),
	}
	run, err := factory.NewQualifiedRun(context.Background(), candidates)
	if err != nil {
		t.Fatalf("candidates=%q/%q err=%v failures=%v", candidates[0].Definition.Instance(), candidates[1].Definition.Instance(), err, func() []ProviderQualificationFailure {
			if run != nil {
				return run.QualificationFailures()
			}
			return nil
		}())
	}
	if calls.Load() != 1 {
		t.Fatalf("QualifyCurrent calls = %d, want 1 family probe", calls.Load())
	}
	if derives.Load() != 1 {
		t.Fatalf("DeriveEquivalentFamilyRoute calls = %d, want 1 sibling derivation", derives.Load())
	}
	if len(run.Routes()) != 2 {
		t.Fatalf("routes = %d, want 2 derived role routes", len(run.Routes()))
	}
	observations := run.QualificationObservations()
	if len(observations) != 2 {
		t.Fatalf("qualification observations = %d, want one per admitted sibling route", len(observations))
	}
	seen := map[string]bool{}
	for _, observation := range observations {
		if observation.Outcome() != "qualified" {
			t.Fatalf("observation outcome = %q, want qualified", observation.Outcome())
		}
		seen[observation.ProviderInstance()] = true
	}
	if !seen[candidates[0].Definition.Instance()] || !seen[candidates[1].Definition.Instance()] {
		t.Fatalf("sibling routes missing qualification observations: %#v", observations)
	}
}

func TestFamilyQualificationRetainsRetryMitigatedRejectionOnSuccess(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	transient := currentQualifierProbeFailure(t, domain.FailureInvalidOutput, domain.DiagnosticCauseProviderExecutionFailed)
	qualifier := &familyDerivingQualifier{
		qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
			result := syntheticFamilyQualificationResult(t, request, now)
			result.Observations = []ProviderQualificationObservation{
				rejectedQualificationObservation(request.Definition.Instance(), transient, true),
				qualifiedQualificationObservation(request.Definition.Instance()),
			}
			return result, nil
		},
		derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
			return syntheticDerivedFamilyRoute(t, request, now), nil
		},
	}
	registryFactory := qualifierRegistryFactory{registry: newAuthorityRegistry(t)}
	factory, err := NewQualifiedRunFactory(qualifier, registryFactory, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []QualifiedRunCandidate{
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic),
		authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity),
	}
	run, err := factory.NewQualifiedRun(context.Background(), candidates)
	if err != nil {
		t.Fatalf("bounded retry mitigated family probe failed: %v", err)
	}
	if len(run.Routes()) != 2 {
		t.Fatalf("routes = %d, want 2 derived role routes", len(run.Routes()))
	}
	observations := run.QualificationObservations()
	if len(observations) != 3 {
		t.Fatalf("qualification observations = %#v, want the attempt-1 rejection plus one per admitted route", observations)
	}
	if observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Mitigation() != qualificationMitigationRetry ||
		observations[0].Cause() != domain.DiagnosticCauseProviderExecutionFailed {
		t.Fatalf("retry-mitigated rejection was not retained first: %#v", observations)
	}
	for _, observation := range observations[1:] {
		if observation.Outcome() != qualificationOutcomeQualified {
			t.Fatalf("admitted route observation = %#v, want qualified", observation)
		}
	}
}

func TestRemapCurrentQualificationResultRejectsAuthorityBleedAcrossInstances(t *testing.T) {
	expires := time.Unix(1_700_000_000, 0).UTC().Add(time.Minute)
	sourceIdentity := Identity{
		Family: FamilyZCode, Instance: "zcode-logic", ProfileGeneration: productionProfileGeneration,
		AdapterProfile: "zcode-logic", Version: "0.15.2", Executable: "/private/bin/node",
		ExecutableSHA256: "sha256:node", Launcher: ZCodeLauncher, LauncherSHA256: "sha256:launcher",
		SnapshotManifest: "snapshot", NamespaceLease: "zcode-logic:generation", NamespaceGeneration: "generation",
	}
	authorityID := "sha256:authority"
	proof := &validatedAuthorityProof{directAuthorityID: authorityID, identity: sourceIdentity, expiresAt: expires}
	source := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	result := CurrentQualificationResult{
		VersionArgv: []string{"provider", "--version"}, Version: "0.15.2",
		SupportedRoles: []domain.Role{domain.RoleLogic}, BaseRole: domain.RoleLogic,
		familyAuthority:  fakeFamilyAuthority{id: authorityID, expires: expires},
		familyDefinition: source.Definition, familyNamespaceGeneration: "generation",
		familyProvedRoles: []domain.Role{domain.RoleLogic},
		Receipts: []Receipt{
			{Kind: ReceiptWorkspace, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptEnvironment, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptTransport, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptNativeReference, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
			{Kind: ReceiptBaseRole, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptAssignment, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity},
			{Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: expires, Identity: sourceIdentity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
		},
	}
	siblingIdentity := sourceIdentity
	siblingIdentity.Instance = "zcode-security"
	siblingIdentity.AdapterProfile = "zcode-security"
	siblingIdentity.NamespaceLease = "zcode-security:generation"
	if _, err := remapCurrentQualificationResult(result, siblingIdentity, []domain.Role{domain.RoleSecurity}, domain.RoleSecurity); err == nil {
		t.Fatal("remap manufactured sibling authority by rewriting app identity")
	}
}

func TestTransportMutatedSiblingIsNotShareableFamilyProfile(t *testing.T) {
	logic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	security := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.transportArgvIndex++
	})
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{logic, security})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("transport-mutated sibling collapsed into %d family group(s)", len(groups))
	}
}

func TestScheduleFamilyQualificationGroupsDoesNotDropNonEquivalentGroups(t *testing.T) {
	zcodeA := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeB := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.transportArgvIndex++
	})
	agyA := authorityCandidateForFamilyRole(t, FamilyAGY, domain.RoleLogic)
	agyB := authorityCandidateForFamilyRole(t, FamilyAGY, domain.RoleSecurity)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeA, zcodeB, agyA, agyB})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("groups = %d, want 4 non-equivalent family profiles", len(groups))
	}
	batches := scheduleFamilyQualificationGroups(groups)
	scheduled := 0
	for _, batch := range batches {
		scheduled += len(batch)
	}
	if scheduled != len(groups) {
		t.Fatalf("scheduled groups = %d from %#v, want %d", scheduled, batches, len(groups))
	}
}

func TestAGYInstancesDoNotShareFamilyProfileKey(t *testing.T) {
	agyLogic := authorityCandidateForFamilyRole(t, FamilyAGY, domain.RoleLogic)
	agySecurity := authorityCandidateForFamilyRole(t, FamilyAGY, domain.RoleSecurity)
	if familyRuntimeProfileKeyFor(agyLogic.Definition) == familyRuntimeProfileKeyFor(agySecurity.Definition) {
		t.Fatal("AGY instances unexpectedly shared one family profile key")
	}
}

func authorityCandidateForFamilyRole(t *testing.T, family Family, role domain.Role) QualifiedRunCandidate {
	t.Helper()
	instance := string(family) + "-" + string(role)
	// Sibling role routes must share capability-relevant runtime fields, including
	// working directory, so family-profile deduplication can be exercised.
	definition, _ := authorityProbeDefinition(t, family, instance, "1.1.4", "/private/work/"+string(family))
	limits, err := review.NewInvocationLimits(time.Second, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return QualifiedRunCandidate{
		Profile: DiscoveredProviderProfile{
			family: family, executable: definition.Executable(), launcher: definition.Launcher(),
			argv: definition.BaseArgv(), sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
			reason: "unqualified_discovery",
		},
		Definition:       definition,
		SnapshotManifest: "manifest-1",
		SupportedRoles:   []domain.Role{role},
		BaseRole:         role,
		Limits:           limits,
	}
}

type testRuntimeMutation struct {
	family                      string
	instance                    string
	version                     string
	executable                  string
	executableSHA256            string
	launcher                    string
	launcherSHA256              string
	profileGeneration           string
	runtimeSafetyPolicyIdentity string
	kimiModel                   string
	baseArgv                    []string
	transportChannel            ports.ProviderPacketChannel
	transportArgvIndex          int
	transportReference          string
	environment                 []ports.EnvironmentVariable
	workingDirectory            string
	maxStdoutBytes              int64
	maxStderrBytes              int64
	hasLifecycle                bool
	lifecycle                   ports.BoundedPostOutputLifecycle
}

func (d testRuntimeMutation) Family() string            { return d.family }
func (d testRuntimeMutation) Instance() string          { return d.instance }
func (d testRuntimeMutation) Version() string           { return d.version }
func (d testRuntimeMutation) Executable() string        { return d.executable }
func (d testRuntimeMutation) ExecutableSHA256() string  { return d.executableSHA256 }
func (d testRuntimeMutation) Launcher() string          { return d.launcher }
func (d testRuntimeMutation) LauncherSHA256() string    { return d.launcherSHA256 }
func (d testRuntimeMutation) ProfileGeneration() string { return d.profileGeneration }
func (d testRuntimeMutation) RuntimeSafetyPolicyIdentity() string {
	return d.runtimeSafetyPolicyIdentity
}
func (d testRuntimeMutation) ProfileID() string  { return d.instance }
func (d testRuntimeMutation) KimiModel() string  { return d.kimiModel }
func (d testRuntimeMutation) BaseArgv() []string { return append([]string(nil), d.baseArgv...) }
func (d testRuntimeMutation) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), d.environment...)
}
func (d testRuntimeMutation) WorkingDirectory() string { return d.workingDirectory }
func (d testRuntimeMutation) Timeout() time.Duration   { return time.Minute }
func (d testRuntimeMutation) MaxStdoutBytes() int64    { return d.maxStdoutBytes }
func (d testRuntimeMutation) MaxStderrBytes() int64    { return d.maxStderrBytes }
func (d testRuntimeMutation) PostOutputLifecycle() (ports.BoundedPostOutputLifecycle, bool) {
	return d.lifecycle, d.hasLifecycle
}
func (d testRuntimeMutation) TransportChannel() ports.ProviderPacketChannel {
	return d.transportChannel
}
func (d testRuntimeMutation) TransportArgvIndex() int    { return d.transportArgvIndex }
func (d testRuntimeMutation) TransportReference() string { return d.transportReference }

func mutateFamilyCandidateDefinition(t *testing.T, candidate QualifiedRunCandidate, mutate func(*testRuntimeMutation)) QualifiedRunCandidate {
	t.Helper()
	definition := candidate.Definition
	lifecycle, hasLifecycle := definition.PostOutputLifecycle()
	mutated := testRuntimeMutation{
		family: definition.Family(), instance: definition.Instance(), version: definition.Version(),
		executable: definition.Executable(), executableSHA256: definition.ExecutableSHA256(),
		launcher: definition.Launcher(), launcherSHA256: definition.LauncherSHA256(),
		profileGeneration: definition.ProfileGeneration(), runtimeSafetyPolicyIdentity: definition.RuntimeSafetyPolicyIdentity(),
		kimiModel: definition.KimiModel(), baseArgv: append([]string(nil), definition.BaseArgv()...),
		transportChannel: definition.TransportChannel(), transportArgvIndex: definition.TransportArgvIndex(),
		transportReference: definition.TransportReference(), environment: append([]ports.EnvironmentVariable(nil), definition.Environment()...),
		workingDirectory: definition.WorkingDirectory(), maxStdoutBytes: definition.MaxStdoutBytes(),
		maxStderrBytes: definition.MaxStderrBytes(), hasLifecycle: hasLifecycle, lifecycle: lifecycle,
	}
	mutate(&mutated)
	candidate.Definition = mutated
	return candidate
}

func mustEnvVar(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

type familyDerivingQualifier struct {
	qualify func(context.Context, CurrentQualificationRequest) (CurrentQualificationResult, error)
	derive  func(context.Context, FamilyRouteDerivationRequest) (CurrentQualificationResult, error)
}

func (qualifier *familyDerivingQualifier) QualifyCurrent(ctx context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
	return qualifier.qualify(ctx, request)
}

func (qualifier *familyDerivingQualifier) DeriveEquivalentFamilyRoute(ctx context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
	return qualifier.derive(ctx, request)
}

type fakeFamilyAuthority struct {
	id      string
	expires time.Time
}

func (authority fakeFamilyAuthority) AuthorityID() string { return authority.id }
func (authority fakeFamilyAuthority) ExpiresAt() time.Time {
	return authority.expires
}
func (authority fakeFamilyAuthority) Valid() bool { return authority.id != "" }
func (authority fakeFamilyAuthority) Matches(ports.ProviderRuntimeDefinition, string, string, []domain.Role) bool {
	return true
}
func (authority fakeFamilyAuthority) AGYControlAuthorityID() (string, bool) { return "", false }

func syntheticFamilyQualificationResult(t *testing.T, request CurrentQualificationRequest, now time.Time) CurrentQualificationResult {
	t.Helper()
	version := request.Definition.Version()
	if version == "" {
		version = "1.1.4"
	}
	identity := request.Identity
	identity.Version = version
	expires := now.Add(time.Minute)
	authorityID := "sha256:family-authority:" + request.Definition.Instance()
	proof := &validatedAuthorityProof{directAuthorityID: authorityID, identity: identity, expiresAt: expires}
	receipts := []Receipt{
		{Kind: ReceiptWorkspace, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptEnvironment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptTransport, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptNativeReference, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
		{Kind: ReceiptBaseRole, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptAssignment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
	}
	roleReceipts := make([]CurrentRoleReceipt, 0, len(request.RequestedRoles))
	for _, role := range request.RequestedRoles {
		roleReceipts = append(roleReceipts, CurrentRoleReceipt{Role: role, State: ReceiptPass, Identity: identity})
	}
	return CurrentQualificationResult{
		VersionArgv: append(append([]string(nil), request.Profile.Argv()...), "--version"), Version: version,
		Receipts: receipts, SupportedRoles: append([]domain.Role(nil), request.RequestedRoles...),
		RoleReceipts: roleReceipts, BaseRole: request.BaseRole,
		Observations:              []ProviderQualificationObservation{qualifiedQualificationObservation(request.Definition.Instance())},
		familyAuthority:           fakeFamilyAuthority{id: authorityID, expires: expires},
		familyDefinition:          request.Definition,
		familyNamespaceGeneration: request.Namespace.Generation(),
		familyProvedRoles:         []domain.Role{request.BaseRole},
	}
}

func syntheticDerivedFamilyRoute(t *testing.T, request FamilyRouteDerivationRequest, now time.Time) CurrentQualificationResult {
	t.Helper()
	if request.Source.familyAuthority == nil {
		t.Fatal("derivation missing source family authority")
	}
	identity := request.DestinationIdentity
	identity.Version = request.Source.Version
	expires := now.Add(time.Minute)
	authorityID := "sha256:derived-authority:" + request.Destination.Definition.Instance()
	if authorityID == request.Source.familyAuthority.AuthorityID() {
		t.Fatal("synthetic derivation reused source authority id")
	}
	proof := &validatedAuthorityProof{directAuthorityID: authorityID, identity: identity, expiresAt: expires}
	receipts := []Receipt{
		{Kind: ReceiptWorkspace, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptEnvironment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptTransport, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptNativeReference, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptCapability, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
		{Kind: ReceiptBaseRole, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptAssignment, State: ReceiptPass, ExpiresAt: expires, Identity: identity},
		{Kind: ReceiptSecurityPolicy, State: ReceiptPass, ExpiresAt: expires, Identity: identity, AuthorityID: authorityID, AuthorityScope: AuthorityScopeDirectExecution, authority: proof},
	}
	roles := append([]domain.Role(nil), request.Destination.SupportedRoles...)
	roleReceipts := make([]CurrentRoleReceipt, 0, len(roles))
	for _, role := range roles {
		roleReceipts = append(roleReceipts, CurrentRoleReceipt{Role: role, State: ReceiptPass, Identity: identity})
	}
	return CurrentQualificationResult{
		VersionArgv: append([]string(nil), request.Source.VersionArgv...), Version: request.Source.Version,
		Receipts: receipts, SupportedRoles: roles, RoleReceipts: roleReceipts, BaseRole: request.Destination.BaseRole,
		Observations:              append([]ProviderQualificationObservation(nil), request.Source.Observations...),
		familyAuthority:           fakeFamilyAuthority{id: authorityID, expires: expires},
		familyDefinition:          request.Destination.Definition,
		familyNamespaceGeneration: request.DestinationNamespace.Generation(),
		familyProvedRoles:         append([]domain.Role(nil), request.Source.familyProvedRoles...),
	}
}
