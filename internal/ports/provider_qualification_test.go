package ports

import (
	"context"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestProviderQualificationPortContractsRemainNarrow(t *testing.T) {
	var _ ProviderRuntimeDefinition = qualificationRuntimeDefinitionStub{}
	var _ ProviderQualificationNamespace = qualificationNamespaceStub{}
	var _ ProviderQualificationFixtureLease = qualificationFixtureStub{}
	var _ ProviderCurrentProbe = qualificationProbeStub{}
	var _ ProviderQualificationRegistry = qualificationRegistryStub{}
}

type qualificationRuntimeDefinitionStub struct{}

func (qualificationRuntimeDefinitionStub) Family() string                      { return "test" }
func (qualificationRuntimeDefinitionStub) Instance() string                    { return "test" }
func (qualificationRuntimeDefinitionStub) Version() string                     { return "1.0.0" }
func (qualificationRuntimeDefinitionStub) Executable() string                  { return "/test" }
func (qualificationRuntimeDefinitionStub) ExecutableSHA256() string            { return "digest" }
func (qualificationRuntimeDefinitionStub) Launcher() string                    { return "/test" }
func (qualificationRuntimeDefinitionStub) LauncherSHA256() string              { return "digest" }
func (qualificationRuntimeDefinitionStub) ProfileGeneration() string           { return "generation" }
func (qualificationRuntimeDefinitionStub) RuntimeSafetyPolicyIdentity() string { return "policy" }
func (qualificationRuntimeDefinitionStub) ConcurrencyKey() ConcurrencyKey      { return ConcurrencyKey{} }
func (qualificationRuntimeDefinitionStub) ProfileID() string                   { return "profile" }

type qualificationNamespaceStub struct{}

func (qualificationNamespaceStub) ProviderInstance() string { return "test" }
func (qualificationNamespaceStub) Generation() string       { return "generation" }
func (qualificationNamespaceStub) Environment() []EnvironmentVariable {
	return nil
}
func (qualificationNamespaceStub) RuntimeSafetyPolicyIdentity() string { return "policy" }
func (qualificationNamespaceStub) ValidateForSpawn() error             { return nil }
func (qualificationNamespaceStub) NativeHomeLaunchAuthority() (NativeHomeLaunchAuthority, bool) {
	return NativeHomeLaunchAuthority{}, false
}

type qualificationFixtureStub struct{}

func (qualificationFixtureStub) Role() domain.Role { return domain.RoleLogic }
func (qualificationFixtureStub) WorkspaceSnapshotIdentity() WorkspaceSnapshotIdentity {
	return WorkspaceSnapshotIdentity{}
}
func (qualificationFixtureStub) DrainTerminal(context.Context) (QualificationWorkspaceTerminalReceipt, error) {
	return QualificationWorkspaceTerminalReceipt{}, nil
}

type qualificationProbeStub struct{}

func (qualificationProbeStub) QualifyProviderCurrent(context.Context, ProviderCurrentProbeRequest) (ProviderCurrentProbeResult, error) {
	return ProviderCurrentProbeResult{}, nil
}

type qualificationRegistryStub struct{}

func (qualificationRegistryStub) Observe(context.Context, ProviderInvocation) (ProviderExecutionObservation, error) {
	return ProviderExecutionObservation{}, nil
}
func (qualificationRegistryStub) QualificationNamespace(string) (ProviderQualificationNamespace, bool) {
	return qualificationNamespaceStub{}, true
}
func (qualificationRegistryStub) Close(context.Context) (ProviderRunTerminalReceipt, error) {
	return ProviderRunTerminalReceipt{}, nil
}
