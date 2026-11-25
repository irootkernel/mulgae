package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestGroupCandidatesByFamilyRuntimeProfileSharesEquivalentZCodeProfiles(t *testing.T) {
	zcodeLogic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeSecurity := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
	grokLogic := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeLogic, zcodeSecurity, grokLogic})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (1 shared ZCode, 1 Grok)", len(groups))
	}
	batches := scheduleFamilyQualificationGroups(groups)
	scheduled := 0
	for _, batch := range batches {
		scheduled += len(batch)
	}
	if scheduled != len(groups) {
		t.Fatalf("scheduled groups = %d, want %d: %#v", scheduled, len(groups), batches)
	}
	var zcodeGroups int
	var zcodeRoles, grokRoles []domain.Role
	for _, group := range groups {
		switch group.family {
		case FamilyZCode:
			zcodeGroups++
			zcodeRoles = group.roles
		case FamilyGrok:
			grokRoles = group.roles
		}
	}
	if zcodeGroups != 1 {
		t.Fatalf("zcode groups = %d, want 1 shared group", zcodeGroups)
	}
	if !reflect.DeepEqual(zcodeRoles, []domain.Role{domain.RoleLogic, domain.RoleSecurity}) {
		t.Fatalf("zcode roles = %v, want [logic security]", zcodeRoles)
	}
	if !reflect.DeepEqual(grokRoles, []domain.Role{domain.RoleLogic}) {
		t.Fatalf("grok roles = %v", grokRoles)
	}

	zcodeMutated := mutateFamilyCandidateDefinition(t, zcodeSecurity, func(d *testRuntimeMutation) {
		d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
	})
	splitGroups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeLogic, zcodeMutated})
	if err != nil {
		t.Fatal(err)
	}
	if len(splitGroups) != 2 {
		t.Fatalf("capability-mutated ZCode groups = %d, want 2 distinct groups", len(splitGroups))
	}
}

func TestFamilyRuntimeProfileKeyRejectsCapabilityRelevantMutations(t *testing.T) {
	base := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	baseKey := familyRuntimeProfileKeyFor(base.Definition)
	sibling := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
	if familyRuntimeProfileKeyFor(sibling.Definition) != baseKey {
		t.Fatal("equivalent ZCode siblings did not share the family profile key")
	}

	for name, mutate := range map[string]func(*testRuntimeMutation){
		"companion-package-digest":    func(d *testRuntimeMutation) { d.companion.PackageSHA256 = strings.Repeat("d", 64) },
		"companion-bundle":            func(d *testRuntimeMutation) { d.companion.AppBundle = "/private/Other.app" },
		"transport-index":             func(d *testRuntimeMutation) { d.transportArgvIndex++ },
		"base-argv":                   func(d *testRuntimeMutation) { d.baseArgv = append(append([]string(nil), d.baseArgv...), "--other") },
		"transport-ref":               func(d *testRuntimeMutation) { d.transportReference = "@other.md" },
		"working-dir":                 func(d *testRuntimeMutation) { d.workingDirectory = "/private/other" },
		"executable":                  func(d *testRuntimeMutation) { d.executable = "/private/bin/other-node" },
		"launcher":                    func(d *testRuntimeMutation) { d.launcher = "/private/bin/other-launcher" },
		"zcode-model":                 func(d *testRuntimeMutation) { d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash" },
		"zcode-reasoning-effort":      func(d *testRuntimeMutation) { d.zcodeReasoningEffort = "high" },
		"zcode-provider-config":       func(d *testRuntimeMutation) { d.zcodeProviderConfig = "/private/other/zcode-builtin.json" },
		"zcode-provider-config-sha":   func(d *testRuntimeMutation) { d.zcodeProviderConfigSHA256 = "sha256:" + strings.Repeat("d", 64) },
		"application-version":         func(d *testRuntimeMutation) { d.applicationVersion = "3.19.0" },
		"application-metadata":        func(d *testRuntimeMutation) { d.applicationMetadata = "/private/other/Info.plist" },
		"application-metadata-sha256": func(d *testRuntimeMutation) { d.applicationMetadataSHA256 = "sha256:" + strings.Repeat("e", 64) },
		"safety-policy":               func(d *testRuntimeMutation) { d.runtimeSafetyPolicyIdentity = "other-policy" },
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

func TestFamilyQualificationSharesEquivalentZCodeProfile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	runQualification := func(t *testing.T, candidates []QualifiedRunCandidate) (*QualifiedRun, int32, int32) {
		t.Helper()
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
		factory, err := NewQualifiedRunFactory(qualifier, guardRegistryFactoryFor(t, candidates...), qualifierClock{now: now})
		if err != nil {
			t.Fatal(err)
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
		return run, calls.Load(), derives.Load()
	}

	t.Run("same-profile ZCode shares one probe and derives sibling", func(t *testing.T) {
		candidates := []QualifiedRunCandidate{
			authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic),
			authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity),
		}
		run, calls, derives := runQualification(t, candidates)
		if calls != 1 {
			t.Fatalf("QualifyCurrent calls = %d, want 1 shared ZCode probe", calls)
		}
		if derives != 1 {
			t.Fatalf("DeriveEquivalentFamilyRoute calls = %d, want 1 sibling derivation", derives)
		}
		if len(run.Routes()) != 2 {
			t.Fatalf("routes = %d, want 2 role routes", len(run.Routes()))
		}
		observations := run.QualificationObservations()
		if len(observations) != 2 {
			t.Fatalf("qualification observations = %d, want one per admitted sibling route", len(observations))
		}
		seen := map[string]bool{}
		for _, observation := range observations {
			if observation.Outcome() != qualificationOutcomeQualified {
				t.Fatalf("observation outcome = %q, want qualified", observation.Outcome())
			}
			seen[observation.ProviderInstance()] = true
		}
		if !seen["zcode-logic"] || !seen["zcode-security"] {
			t.Fatalf("sibling routes missing qualification observations: %#v", observations)
		}
	})

	t.Run("distinct-profile ZCode probes independently", func(t *testing.T) {
		logic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
		security := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
			d.zcodeModel = "account:zai-individual-coding-plan/GLM-5.3-Flash"
		})
		run, calls, derives := runQualification(t, []QualifiedRunCandidate{logic, security})
		if calls != 2 || derives != 0 || len(run.Routes()) != 2 {
			t.Fatalf("distinct ZCode calls=%d derives=%d routes=%d, want 2/0/2", calls, derives, len(run.Routes()))
		}
	})
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
		t.Fatalf("qualification observations = %#v, want [rejected(zcode-logic), qualified(zcode-logic), qualified(zcode-security)]", observations)
	}
	if observations[0].Outcome() != qualificationOutcomeRejected ||
		observations[0].Mitigation() != qualificationMitigationRetry ||
		observations[0].Cause() != domain.DiagnosticCauseProviderExecutionFailed ||
		observations[0].ProviderInstance() != "zcode-logic" {
		t.Fatalf("observations[0] = %#v, want retry-mitigated rejection for zcode-logic", observations[0])
	}
	if observations[1].Outcome() != qualificationOutcomeQualified || observations[1].ProviderInstance() != "zcode-logic" {
		t.Fatalf("observations[1] = %#v, want qualified for zcode-logic", observations[1])
	}
	if observations[2].Outcome() != qualificationOutcomeQualified || observations[2].ProviderInstance() != "zcode-security" {
		t.Fatalf("observations[2] = %#v, want qualified for zcode-security", observations[2])
	}
}

func TestRemapCurrentQualificationResultRejectsAuthorityBleedAcrossInstances(t *testing.T) {
	expires := time.Unix(1_700_000_000, 0).UTC().Add(time.Minute)
	sourceIdentity := Identity{
		Family: FamilyZCode, Instance: "zcode-logic", ProfileGeneration: productionProfileGeneration,
		AdapterProfile: "zcode-logic", Version: "0.16.3", Executable: "/private/bin/node",
		ExecutableSHA256: "sha256:runtime", Launcher: testZCodeLauncher, LauncherSHA256: "sha256:launcher",
		ApplicationVersion: "3.12.3", ApplicationMetadata: testZCodeApplicationMetadata, ApplicationMetadataSHA256: testZCodeApplicationMetadataSHA256,
		ExecutionTargetIdentity: "snapshot", NamespaceLease: "zcode-logic:generation", NamespaceGeneration: "generation",
	}
	authorityID := "sha256:authority"
	proof := &validatedAuthorityProof{directAuthorityID: authorityID, identity: sourceIdentity, expiresAt: expires}
	source := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	result := CurrentQualificationResult{
		VersionArgv: []string{"provider", "--version"}, Version: "0.16.3",
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

func TestZCodeProviderConfigMutatedSiblingIsNotShareableFamilyProfile(t *testing.T) {
	logic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	security := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.zcodeProviderConfigSHA256 = "sha256:" + strings.Repeat("b", 64)
	})
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{logic, security})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("ZCode provider-config identities shared qualification: %#v", groups)
	}
}

func TestScheduleFamilyQualificationGroupsDoesNotDropNonEquivalentGroups(t *testing.T) {
	zcodeA := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
	zcodeB := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.transportArgvIndex++
	})
	grokA := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	grokB := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity)
	groups, err := groupCandidatesByFamilyRuntimeProfile([]QualifiedRunCandidate{zcodeA, zcodeB, grokA, grokB})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3 non-equivalent family profiles", len(groups))
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

func TestGrokInstancesShareEquivalentFamilyProfileKey(t *testing.T) {
	grokLogic := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	grokSecurity := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity)
	if familyRuntimeProfileKeyFor(grokLogic.Definition) != familyRuntimeProfileKeyFor(grokSecurity.Definition) {
		t.Fatal("equivalent Grok instances did not share one family profile key")
	}
}

func TestGrokSettingsPartitionFamilyQualification(t *testing.T) {
	providerDefault := authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleLogic)
	configured := mutateFamilyCandidateDefinition(t, authorityCandidateForFamilyRole(t, FamilyGrok, domain.RoleSecurity), func(d *testRuntimeMutation) {
		d.grokSettingsIdentity = "sha256:" + strings.Repeat("c", 64)
	})
	if familyRuntimeProfileKeyFor(providerDefault.Definition) == familyRuntimeProfileKeyFor(configured.Definition) {
		t.Fatal("different Grok settings shared qualification key")
	}
}

func authorityCandidateForFamilyRole(t *testing.T, family Family, role domain.Role) QualifiedRunCandidate {
	t.Helper()
	instance := string(family) + "-" + string(role)
	// Sibling role routes must share capability-relevant runtime fields, including
	// working directory, so family-profile deduplication can be exercised.
	version := "1.0.34"
	if familyGuidance, ok := Guidance(family); ok {
		version = familyGuidance.VerifiedLatest
	}
	definition, _ := authorityProbeDefinition(t, family, instance, version, "/private/work/"+string(family))
	limits, err := review.NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return QualifiedRunCandidate{
		Profile:                 testDiscoveredProfile(definition),
		Definition:              definition,
		ExecutionTargetIdentity: "manifest-1",
		SupportedRoles:          []domain.Role{role},
		BaseRole:                role,
		Limits:                  limits,
	}
}

type testRuntimeMutation struct {
	companion                   ports.ZCodeCompanionObservation
	family                      string
	instance                    string
	version                     string
	executable                  string
	executableSHA256            string
	launcher                    string
	launcherSHA256              string
	zcodeProviderConfig         string
	zcodeProviderConfigSHA256   string
	applicationVersion          string
	applicationMetadata         string
	applicationMetadataSHA256   string
	profileGeneration           string
	profileID                   string
	runtimeSafetyPolicyIdentity string
	zcodeModel                  string
	zcodeReasoningEffort        string
	grokSettingsIdentity        string
	baseArgv                    []string
	transportChannel            ports.ProviderPacketChannel
	transportArgvIndex          int
	transportReference          string
	environment                 []ports.EnvironmentVariable
	workingDirectory            string
	hasLifecycle                bool
	lifecycle                   ports.BoundedPostOutputLifecycle
}

func (d testRuntimeMutation) Family() string                                  { return d.family }
func (d testRuntimeMutation) Instance() string                                { return d.instance }
func (d testRuntimeMutation) Version() string                                 { return d.version }
func (d testRuntimeMutation) Executable() string                              { return d.executable }
func (d testRuntimeMutation) ExecutableSHA256() string                        { return d.executableSHA256 }
func (d testRuntimeMutation) Launcher() string                                { return d.launcher }
func (d testRuntimeMutation) LauncherSHA256() string                          { return d.launcherSHA256 }
func (d testRuntimeMutation) ZCodeProviderConfig() string                     { return d.zcodeProviderConfig }
func (d testRuntimeMutation) ZCodeProviderConfigSHA256() string               { return d.zcodeProviderConfigSHA256 }
func (d testRuntimeMutation) ApplicationVersion() string                      { return d.applicationVersion }
func (d testRuntimeMutation) ApplicationMetadata() string                     { return d.applicationMetadata }
func (d testRuntimeMutation) ApplicationMetadataSHA256() string               { return d.applicationMetadataSHA256 }
func (d testRuntimeMutation) ZCodeCompanion() ports.ZCodeCompanionObservation { return d.companion }
func (d testRuntimeMutation) ProfileGeneration() string                       { return d.profileGeneration }
func (d testRuntimeMutation) RuntimeSafetyPolicyIdentity() string {
	return d.runtimeSafetyPolicyIdentity
}
func (d testRuntimeMutation) ZCodeModel() string           { return d.zcodeModel }
func (d testRuntimeMutation) ZCodeReasoningEffort() string { return d.zcodeReasoningEffort }
func (d testRuntimeMutation) GrokSettingsIdentity() string { return d.grokSettingsIdentity }
func (d testRuntimeMutation) ProfileID() string {
	if d.profileID != "" {
		return d.profileID
	}
	return d.instance
}
func (d testRuntimeMutation) BaseArgv() []string { return append([]string(nil), d.baseArgv...) }
func (d testRuntimeMutation) Environment() []ports.EnvironmentVariable {
	return append([]ports.EnvironmentVariable(nil), d.environment...)
}
func (d testRuntimeMutation) WorkingDirectory() string { return d.workingDirectory }
func (d testRuntimeMutation) Timeout() time.Duration   { return time.Minute }
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
		companion: candidate.Profile.ZCodeCompanion(),
		family:    definition.Family(), instance: definition.Instance(), version: definition.Version(),
		executable: definition.Executable(), executableSHA256: definition.ExecutableSHA256(),
		launcher: definition.Launcher(), launcherSHA256: definition.LauncherSHA256(),
		zcodeProviderConfig: definition.ZCodeProviderConfig(), zcodeProviderConfigSHA256: definition.ZCodeProviderConfigSHA256(),
		applicationVersion: definition.ApplicationVersion(), applicationMetadata: definition.ApplicationMetadata(), applicationMetadataSHA256: definition.ApplicationMetadataSHA256(),
		profileGeneration: definition.ProfileGeneration(), profileID: definition.ProfileID(), runtimeSafetyPolicyIdentity: definition.RuntimeSafetyPolicyIdentity(),
		zcodeModel:           definition.ZCodeModel(),
		zcodeReasoningEffort: definition.ZCodeReasoningEffort(),
		grokSettingsIdentity: definition.GrokSettingsIdentity(),
		baseArgv:             append([]string(nil), definition.BaseArgv()...),
		transportChannel:     definition.TransportChannel(), transportArgvIndex: definition.TransportArgvIndex(),
		transportReference: definition.TransportReference(), environment: append([]ports.EnvironmentVariable(nil), definition.Environment()...),
		workingDirectory: definition.WorkingDirectory(), hasLifecycle: hasLifecycle, lifecycle: lifecycle,
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
func (authority fakeFamilyAuthority) GrokControlAuthorityID() (string, bool) { return "", false }

func syntheticFamilyQualificationResult(t *testing.T, request CurrentQualificationRequest, now time.Time) CurrentQualificationResult {
	t.Helper()
	version := request.Definition.Version()
	if version == "" {
		version = "1.0.34"
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
	argv := append(request.Profile.Argv(), "--version")
	if companion := request.Profile.ZCodeCompanion(); companion.Valid() {
		version = companion.Version
		argv = append(argv, "--json")
		if companion.BundleOverride != "" {
			argv = append(argv, "--app-bundle", companion.BundleOverride)
		}
	}
	return CurrentQualificationResult{
		VersionArgv: argv, Version: version,
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

type sharedZCodeExecutionRegistry struct {
	*qualifierRegistry
	observe func(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error)
}

func (registry *sharedZCodeExecutionRegistry) Observe(ctx context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return registry.observe(ctx, invocation)
}

type sharedZCodeExecutionRegistryFactory struct {
	registries map[string]*sharedZCodeExecutionRegistry
}

func (factory *sharedZCodeExecutionRegistryFactory) NewProviderQualificationRegistry(_ context.Context, definitions []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	if len(definitions) != 1 {
		return nil, errors.New("expected one runtime definition per qualification registry")
	}
	registry, ok := factory.registries[definitions[0].Instance()]
	if !ok {
		return nil, errors.New("missing test registry for " + definitions[0].Instance())
	}
	return registry, nil
}

func (factory *sharedZCodeExecutionRegistryFactory) RegistryFromConstructionError(error) (ports.ProviderQualificationRegistry, bool) {
	return nil, false
}

type qualifiedRunLiveAuthorityAdapter struct {
	run   *QualifiedRun
	plan  ExecutionPlan
	build BuildIdentity
}

func (authority *qualifiedRunLiveAuthorityAdapter) Provider() ports.ObservedReviewProvider {
	return authority.run.Registry()
}

func (authority *qualifiedRunLiveAuthorityAdapter) Planner() ExecutionPlanner {
	return sharedZCodeLivePlanner{plan: authority.plan}
}

func (authority *qualifiedRunLiveAuthorityAdapter) BuildIdentity() BuildIdentity {
	return authority.build
}

func (authority *qualifiedRunLiveAuthorityAdapter) QualificationObservations() []ProviderQualificationObservation {
	return authority.run.QualificationObservations()
}

func (authority *qualifiedRunLiveAuthorityAdapter) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	return authority.run.DrainTerminal(ctx)
}

type sharedZCodeLivePlanner struct{ plan ExecutionPlan }

func (planner sharedZCodeLivePlanner) PlanSelectedRoles(context.Context, []domain.Role) (ExecutionPlan, error) {
	return planner.plan.clone(), nil
}

type sharedZCodeLiveAuthorityFactory struct {
	factory    *QualifiedRunFactory
	candidates []QualifiedRunCandidate
	plan       ExecutionPlan
	build      BuildIdentity
	mu         sync.Mutex
	runs       int
}

func (factory *sharedZCodeLiveAuthorityFactory) NewQualifiedLiveRun(ctx context.Context, _ ports.LiveReviewExecution, _ RunSelection) (RunAuthority, error) {
	factory.mu.Lock()
	factory.runs++
	factory.mu.Unlock()
	run, err := factory.factory.NewQualifiedRun(ctx, factory.candidates)
	if err != nil {
		return nil, err
	}
	return &qualifiedRunLiveAuthorityAdapter{run: run, plan: factory.plan, build: factory.build}, nil
}

type sharedZCodeTestIDs struct {
	seq atomic.Uint64
}

func (ids *sharedZCodeTestIDs) nextSuffix() string {
	return fmt.Sprintf("%012x", ids.seq.Add(1))
}

func (ids *sharedZCodeTestIDs) NewSessionID(time.Time) (domain.SessionID, error) {
	return domain.ParseSessionID("s_019f5a09-5eec-7001-8001-" + ids.nextSuffix())
}

func (ids *sharedZCodeTestIDs) NewRunID(time.Time) (domain.RunID, error) {
	return domain.ParseRunID("r_019f5a09-5eec-7001-8001-" + ids.nextSuffix())
}

func (ids *sharedZCodeTestIDs) NewAttemptID(time.Time) (domain.AttemptID, error) {
	return domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-" + ids.nextSuffix())
}

func (ids *sharedZCodeTestIDs) NewRoleTaskID(time.Time) (string, error) {
	return "rt_019f5a09-5eec-7001-8001-" + ids.nextSuffix(), nil
}

func (ids *sharedZCodeTestIDs) NewSourceInvocationID(time.Time) (string, error) {
	return "i_019f5a09-5eec-7001-8001-" + ids.nextSuffix(), nil
}

func (ids *sharedZCodeTestIDs) NewExecutionInvocationID(time.Time) (string, error) {
	return "019f5a09-5eec-7001-8001-" + ids.nextSuffix(), nil
}

type sharedZCodeCleanDetector struct{}

func (sharedZCodeCleanDetector) DetectReviewInput(context.Context, ports.ReviewInputChannel, string, []byte) (ports.ReviewInputDetection, error) {
	return ports.NewReviewInputDetection(ports.ReviewInputClean, "", 0)
}

func TestDerivedZCodeSiblingExecutionConfigurationFailureBlocksPublication(t *testing.T) {
	for _, diagnosticCode := range []string{"zcode_account_configuration", "zcode_model_selection"} {
		t.Run(diagnosticCode, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0).UTC()
			logic := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleLogic)
			security := authorityCandidateForFamilyRole(t, FamilyZCode, domain.RoleSecurity)
			candidates := []QualifiedRunCandidate{logic, security}

			var probeCalls atomic.Int32
			var deriveCalls atomic.Int32
			qualifier := &familyDerivingQualifier{
				qualify: func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
					probeCalls.Add(1)
					return syntheticFamilyQualificationResult(t, request, now), nil
				},
				derive: func(_ context.Context, request FamilyRouteDerivationRequest) (CurrentQualificationResult, error) {
					deriveCalls.Add(1)
					return syntheticDerivedFamilyRoute(t, request, now), nil
				},
			}

			var observedLogic, observedSecurity atomic.Int32
			registries := map[string]*sharedZCodeExecutionRegistry{
				"zcode-logic": {
					qualifierRegistry: guardRegistry(t, "zcode-logic", logic.Definition.RuntimeSafetyPolicyIdentity()),
					observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
						observedLogic.Add(1)
						raw := []byte(`{"schema_version":"mulgae-provider-review-output.v1","summary":"No logic findings.","completeness":"complete","limitations":[],"findings":[]}`)
						receipt, err := ports.NewStdinWriteReceipt(int64(invocation.InputIdentity().ByteLength()), int64(invocation.InputIdentity().ByteLength()), invocation.CompleteStdinSHA256(), true)
						if err != nil {
							return ports.ProviderExecutionObservation{}, err
						}
						code := 0
						process, err := ports.NewProcessObservation(raw, nil, &code, ports.ProcessTerminationExited, receipt, now, now.Add(time.Millisecond))
						if err != nil {
							return ports.ProviderExecutionObservation{}, err
						}
						result, err := ports.NewProviderResultForInput(raw, invocation.InputIdentity())
						if err != nil {
							return ports.ProviderExecutionObservation{}, err
						}
						return ports.NewSuccessfulProviderExecutionObservation(invocation, result, process)
					},
				},
				"zcode-security": {
					qualifierRegistry: guardRegistry(t, "zcode-security", security.Definition.RuntimeSafetyPolicyIdentity()),
					observe: func(_ context.Context, invocation ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
						observedSecurity.Add(1)
						if diagnosticCode == "zcode_account_configuration" {
							return ports.NewPartialFailedProviderExecutionObservation(
								ports.ProviderExecutionStatusConfigurationViolation, invocation, nil, nil,
								diagnosticCode, domain.DiagnosticCauseObservationInvalid, "",
							)
						}
						receipt, err := ports.NewStdinWriteReceipt(int64(invocation.InputIdentity().ByteLength()), int64(invocation.InputIdentity().ByteLength()), invocation.CompleteStdinSHA256(), true)
						if err != nil {
							return ports.ProviderExecutionObservation{}, err
						}
						code := 1
						process, err := ports.NewProcessObservation(nil, []byte("configuration rejected"), &code, ports.ProcessTerminationExited, receipt, now, now.Add(time.Millisecond))
						if err != nil {
							return ports.ProviderExecutionObservation{}, err
						}
						return ports.NewFailedProviderExecutionObservationWithCause(
							ports.ProviderExecutionStatusConfigurationViolation,
							invocation,
							process,
							diagnosticCode,
							domain.DiagnosticCauseObservationInvalid,
							"",
						)
					},
				},
			}

			qualifiedFactory, err := NewQualifiedRunFactory(qualifier, &sharedZCodeExecutionRegistryFactory{registries: registries}, qualifierClock{now: now})
			if err != nil {
				t.Fatal(err)
			}

			limits, err := review.NewInvocationLimits(time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			logicRoute, err := ports.NewProviderRoute("zcode-logic")
			if err != nil {
				t.Fatal(err)
			}
			securityRoute, err := ports.NewProviderRoute("zcode-security")
			if err != nil {
				t.Fatal(err)
			}
			logicAssignment, err := review.NewScheduledAssignment(domain.RoleLogic, false, logicRoute)
			if err != nil {
				t.Fatal(err)
			}
			securityAssignment, err := review.NewScheduledAssignment(domain.RoleSecurity, false, securityRoute)
			if err != nil {
				t.Fatal(err)
			}
			logicRouteBudget, err := review.NewRouteBudget(logicRoute, limits)
			if err != nil {
				t.Fatal(err)
			}
			securityRouteBudget, err := review.NewRouteBudget(securityRoute, limits)
			if err != nil {
				t.Fatal(err)
			}
			logicBudget, err := review.NewRoleBudget(domain.RoleLogic, logicRouteBudget)
			if err != nil {
				t.Fatal(err)
			}
			securityBudget, err := review.NewRoleBudget(domain.RoleSecurity, securityRouteBudget)
			if err != nil {
				t.Fatal(err)
			}
			plan := ExecutionPlan{
				Assignments: []review.Assignment{logicAssignment, securityAssignment},
				Budgets:     []review.RoleBudget{logicBudget, securityBudget},
				Threshold:   domain.SeverityLow,
				MaxWorkers:  2,
				Ceilings:    review.DefaultHarnessCeilings(),
			}

			selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
			path, _ := ports.NewSafeRelativePath("source.go")
			target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
			root, _ := ports.NewAnchoredRoot("/project")
			git, _ := ports.NewAnchoredRoot("/project/.git")
			neutral, _ := ports.NewAnchoredRoot("/neutral")
			credential, _ := ports.NewAnchoredRoot("/credentials")
			binding := ports.ProjectBindingObservation{
				Root: root, GitDirectory: git, CommonDirectory: git,
				RootIdentity:   ports.ProjectDirectoryIdentity{Device: 1, Inode: 2},
				GitIdentity:    ports.ProjectDirectoryIdentity{Device: 1, Inode: 3},
				CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3},
			}
			source := &serviceLiveSource{promptLiveReader: promptLiveReader{target: target, binding: binding}}
			build := BuildIdentity{Product: "mulgae", Version: "1.0.0", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}
			publisher := &serviceLivePublisher{t: t, source: source, stop: errors.New("unexpected publication")}
			calls := []string{}
			diagnostics := &serviceDiagnosticFactory{calls: &calls}
			common, err := LoadLiveReviewCommon(context.Background(), builtin.NewCatalog())
			if err != nil {
				t.Fatal(err)
			}
			authorityFactory := &sharedZCodeLiveAuthorityFactory{
				factory:    qualifiedFactory,
				candidates: candidates,
				plan:       plan,
				build:      build,
			}
			service, err := NewLiveService(LiveDependencies{
				Coordination:    testLiveCoordination(t),
				Sources:         serviceLiveOpener{source},
				ReviewerHome:    promptLiveHome{root: neutral},
				CredentialRoots: []ports.AnchoredRoot{credential},
				Admission:       serviceLiveAdmission{plan},
				Clock:           serviceClock{},
				IDs:             &sharedZCodeTestIDs{},
				Build:           build,
				Authority:       authorityFactory,
				Validator:       &validation.ReviewValidator{},
				Publication:     publisher,
				Templates:       mustServiceTemplates(t),
				Common:          common,
				Diagnostics:     diagnostics,
				Detector:        sharedZCodeCleanDetector{},
			})
			if err != nil {
				t.Fatal(err)
			}
			selection, err := NewRunSelection([]domain.Role{domain.RoleLogic, domain.RoleSecurity}, nil)
			if err != nil {
				t.Fatal(err)
			}

			result, err := service.Execute(context.Background(), LiveRequest{
				ProjectRoot: root, ArtifactRoot: root, Target: selector, Selection: selection,
			})
			if probeCalls.Load() != 1 || deriveCalls.Load() != 1 {
				t.Fatalf("shared ZCode qualification calls=%d derives=%d, want 1/1", probeCalls.Load(), deriveCalls.Load())
			}
			if observedLogic.Load() != 1 || observedSecurity.Load() != 1 {
				t.Fatalf("execution observations logic=%d security=%d, want 1/1", observedLogic.Load(), observedSecurity.Load())
			}
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
				t.Fatalf("derived sibling configuration failure err = %v, want typed FailureConfiguration", err)
			}
			if publisher.calls != 0 {
				t.Fatalf("publisher calls = %d, want 0", publisher.calls)
			}
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatalf("non-publishable result = %+v, want empty Result", result)
			}
		})
	}
}
