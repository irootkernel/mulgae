package providercli

import (
	"context"
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

var _ ports.ProviderRuntimeDefinition = RuntimeDefinition{}
var _ ports.ProviderRuntimeBuilder = RuntimeBuilder{}
var _ ports.ProviderDirectExecutionAuthority = CurrentProbeDirectExecutionAuthorityReceipt{}
var _ ports.ProviderCurrentProbe = (*QualificationProbeAdapter)(nil)
var _ ports.ProviderEquivalentRouteAuthorityDeriver = (*QualificationProbeAdapter)(nil)
var _ ports.ProviderQualificationFixtureFactory = (*QualificationFixtureFactoryAdapter)(nil)
var _ ports.ProviderQualificationRegistry = (*Registry)(nil)
var _ ports.ProviderQualificationRegistryFactory = (*QualificationRegistryFactory)(nil)

// RuntimeBuilder translates neutral application specs into providercli-owned
// production runtime definitions.
type RuntimeBuilder struct{}

func (RuntimeBuilder) RuntimeSafetyPolicyIdentity(family string) (string, error) {
	credentialFamily, err := credentialFamilyForRuntime(family)
	if err != nil {
		return "", err
	}
	policy, err := RuntimeSafetyPolicyForFamily(credentialFamily)
	if err != nil {
		return "", err
	}
	return policy.Identity(), nil
}

func (RuntimeBuilder) BuildProductionRuntime(spec ports.ProviderRuntimeSpec) (ports.ProviderRuntimeDefinition, error) {
	transport, err := NewRuntimeTransport(spec.TransportChannel, spec.TransportArgvIndex, spec.TransportReference)
	if err != nil {
		return nil, err
	}
	if spec.HasPostOutputLifecycle {
		return NewProductionRuntimeDefinitionWithTransportAndSafetyPolicyAndPostOutputLifecycle(
			spec.Family, spec.Instance, spec.Version, spec.Executable, spec.ExecutableSHA256, spec.Launcher, spec.LauncherSHA256,
			spec.ProfileID, spec.ProfileGeneration, spec.RuntimeSafetyPolicyIdentity,
			append([]string(nil), spec.BaseArgv...), transport, spec.PostOutputLifecycle,
			append([]ports.EnvironmentVariable(nil), spec.Environment...), spec.WorkingDirectory,
			spec.Timeout,
		)
	}
	if spec.Family == FamilyKimi {
		return NewProductionKimiRuntimeDefinitionWithTransportAndSafetyPolicy(
			spec.Family, spec.Instance, spec.Version, spec.Executable, spec.ExecutableSHA256, spec.Launcher, spec.LauncherSHA256,
			spec.ProfileID, spec.ProfileGeneration, spec.RuntimeSafetyPolicyIdentity, spec.KimiModel,
			append([]string(nil), spec.BaseArgv...), transport, append([]ports.EnvironmentVariable(nil), spec.Environment...),
			spec.WorkingDirectory, spec.Timeout,
		)
	}
	if spec.Family == FamilyCodex {
		return NewProductionCodexRuntimeDefinitionWithTransportAndSafetyPolicy(
			spec.Family, spec.Instance, spec.Version, spec.Executable, spec.ExecutableSHA256, spec.Launcher, spec.LauncherSHA256,
			spec.ProfileID, spec.ProfileGeneration, spec.RuntimeSafetyPolicyIdentity, spec.CodexModel, spec.CodexReasoningEffort,
			append([]string(nil), spec.BaseArgv...), transport, append([]ports.EnvironmentVariable(nil), spec.Environment...),
			spec.WorkingDirectory, spec.Timeout,
		)
	}
	return NewProductionRuntimeDefinitionWithTransportAndSafetyPolicy(
		spec.Family, spec.Instance, spec.Version, spec.Executable, spec.ExecutableSHA256, spec.Launcher, spec.LauncherSHA256,
		spec.ProfileID, spec.ProfileGeneration, spec.RuntimeSafetyPolicyIdentity,
		append([]string(nil), spec.BaseArgv...), transport, append([]ports.EnvironmentVariable(nil), spec.Environment...),
		spec.WorkingDirectory, spec.Timeout,
	)
}

func credentialFamilyForRuntime(family string) (CredentialSourceFamily, error) {
	switch family {
	case FamilyKimi:
		return CredentialSourceKimi, nil
	case FamilyZcode:
		return CredentialSourceZCode, nil
	case FamilyAgy:
		return CredentialSourceAGY, nil
	case FamilyCodex:
		return CredentialSourceCodex, nil
	default:
		return "", fmt.Errorf("provider runtime builder: unsupported family %q", family)
	}
}

// QualificationProbeAdapter binds the adapter-owned safe invocation strategy
// and translates current probe evidence into the neutral ports contract.
type QualificationProbeAdapter struct {
	probe      *CurrentProbe
	invocation SafeProbeInvocation
}

func NewQualificationProbeAdapter(probe *CurrentProbe, invocation SafeProbeInvocation) (*QualificationProbeAdapter, error) {
	if probe == nil || invocation == nil {
		return nil, fmt.Errorf("provider qualification probe adapter: dependencies are required")
	}
	return &QualificationProbeAdapter{probe: probe, invocation: invocation}, nil
}

func (adapter *QualificationProbeAdapter) QualifyProviderCurrent(ctx context.Context, request ports.ProviderCurrentProbeRequest) (ports.ProviderCurrentProbeResult, error) {
	definition, definitionOK := request.Definition.(RuntimeDefinition)
	namespace := request.Namespace
	fixture, fixtureOK := request.Fixture.(ProbeFixtureLease)
	if adapter == nil || adapter.probe == nil || adapter.invocation == nil || !definitionOK || namespace == nil || !fixtureOK {
		return ports.ProviderCurrentProbeResult{}, fmt.Errorf("provider qualification probe adapter: invalid request boundary")
	}
	roleFixtures := make([]ProbeFixtureLease, len(request.RoleFixtures))
	for index, candidate := range request.RoleFixtures {
		lease, ok := candidate.(ProbeFixtureLease)
		if !ok {
			return ports.ProviderCurrentProbeResult{}, fmt.Errorf("provider qualification probe adapter: invalid role fixture")
		}
		roleFixtures[index] = lease
	}
	result, err := adapter.probe.QualifyCurrent(ctx, CurrentProbeRequest{
		Definition: definition, Namespace: namespace, Fixture: fixture, RoleFixtures: roleFixtures,
		Invocation: adapter.invocation, Now: request.Now, TTL: request.TTL,
	})
	if err != nil {
		return ports.ProviderCurrentProbeResult{}, err
	}
	receipts := make([]ports.ProviderCurrentProbeReceipt, len(result.Receipts))
	for index, receipt := range result.Receipts {
		receipts[index] = ports.ProviderCurrentProbeReceipt{Kind: receipt.Kind, EvidenceID: receipt.EvidenceID, ExpiresAt: receipt.ExpiresAt}
		if receipt.DirectExecutionAuthority != nil {
			// Store the value concrete type so adapter derivation can assert
			// CurrentProbeDirectExecutionAuthorityReceipt without pointer mismatch.
			authority := *receipt.DirectExecutionAuthority
			receipts[index].DirectExecutionAuthority = authority
		}
	}
	return ports.ProviderCurrentProbeResult{
		VersionArgv: append([]string(nil), result.VersionArgv...), Version: result.Version, Receipts: receipts,
	}, nil
}

func (adapter *QualificationProbeAdapter) DeriveEquivalentRouteDirectExecutionAuthority(
	source ports.ProviderDirectExecutionAuthority,
	sourceDefinition ports.ProviderRuntimeDefinition,
	destinationDefinition ports.ProviderRuntimeDefinition,
	observedVersion string,
	sourceNamespaceGeneration string,
	destinationNamespaceGeneration string,
	sourceProvedRoles []domain.Role,
	destinationRoles []domain.Role,
) (ports.ProviderDirectExecutionAuthority, error) {
	if adapter == nil {
		return nil, fmt.Errorf("provider qualification probe adapter: unavailable")
	}
	return DeriveEquivalentRouteDirectExecutionAuthority(
		source, sourceDefinition, destinationDefinition, observedVersion,
		sourceNamespaceGeneration, destinationNamespaceGeneration, sourceProvedRoles, destinationRoles,
	)
}

// QualificationFixtureFactoryAdapter narrows adapter fixture leases to the
// application-visible fixture port.
type QualificationFixtureFactoryAdapter struct {
	factory *ProbeFixtureLeaseFactory
}

func NewQualificationFixtureFactoryAdapter(factory *ProbeFixtureLeaseFactory) (*QualificationFixtureFactoryAdapter, error) {
	if factory == nil {
		return nil, fmt.Errorf("provider qualification fixture adapter: factory is required")
	}
	return &QualificationFixtureFactoryAdapter{factory: factory}, nil
}

func (adapter *QualificationFixtureFactoryAdapter) Acquire(ctx context.Context, role domain.Role) (ports.ProviderQualificationFixtureLease, error) {
	if adapter == nil || adapter.factory == nil {
		return nil, fmt.Errorf("provider qualification fixture adapter: factory is required")
	}
	return adapter.factory.Acquire(ctx, role)
}

// QualificationRegistryFactory translates neutral runtime definitions into a
// retained providercli production registry.
type QualificationRegistryFactory struct {
	runner          ports.ProcessRunner
	namespaces      ports.ProviderNamespaceFactory
	verifier        SpawnVerifier
	verifierFactory func(context.Context) (SpawnVerifier, error)
}

func NewQualificationRegistryFactory(runner ports.ProcessRunner, namespaces ports.ProviderNamespaceFactory, verifier SpawnVerifier, verifierFactory func(context.Context) (SpawnVerifier, error)) (*QualificationRegistryFactory, error) {
	if nilRunner(runner) || nilProviderNamespaceFactory(namespaces) || (nilSpawnVerifier(verifier) && verifierFactory == nil) {
		return nil, fmt.Errorf("provider qualification registry factory: dependencies are required")
	}
	return &QualificationRegistryFactory{runner: runner, namespaces: namespaces, verifier: verifier, verifierFactory: verifierFactory}, nil
}

func (factory *QualificationRegistryFactory) NewProviderQualificationRegistry(ctx context.Context, definitions []ports.ProviderRuntimeDefinition) (ports.ProviderQualificationRegistry, error) {
	if factory == nil {
		return nil, fmt.Errorf("provider qualification registry factory: unavailable")
	}
	profiles := make([]RuntimeDefinition, len(definitions))
	for index, definition := range definitions {
		profile, ok := definition.(RuntimeDefinition)
		if !ok {
			return nil, fmt.Errorf("provider qualification registry factory: foreign runtime definition")
		}
		profiles[index] = profile
	}
	verifier := factory.verifier
	if factory.verifierFactory != nil {
		var err error
		verifier, err = factory.verifierFactory(ctx)
		if err != nil {
			return nil, fmt.Errorf("provider qualification registry factory: construct spawn verifier: %w", err)
		}
	}
	return NewProductionRegistryWithContext(ctx, factory.runner, factory.namespaces, verifier, profiles...)
}

func (*QualificationRegistryFactory) RegistryFromConstructionError(err error) (ports.ProviderQualificationRegistry, bool) {
	registry, ok := RegistryFromConstructionError(err)
	return registry, ok
}
