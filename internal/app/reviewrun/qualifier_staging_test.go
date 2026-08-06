package reviewrun

import (
	"context"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type stagingCompositeChildRegistry struct {
	destination ports.StagedOutputDestination
}

func (registry stagingCompositeChildRegistry) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return ports.ProviderExecutionObservation{}, nil
}

func (registry stagingCompositeChildRegistry) QualificationNamespace(string) (ports.ProviderQualificationNamespace, bool) {
	return nil, false
}

func (registry stagingCompositeChildRegistry) Close(context.Context) (ports.ProviderRunTerminalReceipt, error) {
	return ports.ProviderRunTerminalReceipt{}, nil
}

func (registry stagingCompositeChildRegistry) ProviderOutputStagingDestination(string, domain.AttemptID, ports.ProviderInvocationPurpose) (ports.StagedOutputDestination, ports.ProviderOutputTransport, bool) {
	return registry.destination, ports.ProviderOutputTransportStagedFile, true
}

type plainCompositeChildRegistry struct{}

func (registry plainCompositeChildRegistry) Observe(context.Context, ports.ProviderInvocation) (ports.ProviderExecutionObservation, error) {
	return ports.ProviderExecutionObservation{}, nil
}

func (registry plainCompositeChildRegistry) QualificationNamespace(string) (ports.ProviderQualificationNamespace, bool) {
	return nil, false
}

func (registry plainCompositeChildRegistry) Close(context.Context) (ports.ProviderRunTerminalReceipt, error) {
	return ports.ProviderRunTerminalReceipt{}, nil
}

func TestQualifiedRunRegistryCompositeDelegatesStagingLocator(t *testing.T) {
	destination, err := ports.NewStagedOutputDestination("/private/tmp/mulgae-staging-test", "role-report.md")
	if err != nil {
		t.Fatalf("staging destination: %v", err)
	}
	attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-000000000003")
	if err != nil {
		t.Fatalf("attempt ID: %v", err)
	}
	composite := &qualifiedRunRegistryComposite{registries: map[string]QualifiedRunRegistry{
		"zcode-logic": stagingCompositeChildRegistry{destination: destination},
		"agy-logic":   plainCompositeChildRegistry{},
	}}

	got, transport, ok := composite.ProviderOutputStagingDestination("zcode-logic", attemptID, ports.ProviderInvocationInitial)
	if !ok || transport != ports.ProviderOutputTransportStagedFile || got != destination {
		t.Fatalf("staging child delegation = (%v, %q, %t), want (%v, staged_file, true)", got, transport, ok, destination)
	}

	if _, transport, ok := composite.ProviderOutputStagingDestination("agy-logic", attemptID, ports.ProviderInvocationInitial); ok || transport != ports.ProviderOutputTransportStdout {
		t.Fatalf("non-locator child = (%q, %t), want fail-closed stdout", transport, ok)
	}
	if _, transport, ok := composite.ProviderOutputStagingDestination("unknown", attemptID, ports.ProviderInvocationInitial); ok || transport != ports.ProviderOutputTransportStdout {
		t.Fatalf("unknown instance = (%q, %t), want fail-closed stdout", transport, ok)
	}
	var absent *qualifiedRunRegistryComposite
	if _, transport, ok := absent.ProviderOutputStagingDestination("zcode-logic", attemptID, ports.ProviderInvocationInitial); ok || transport != ports.ProviderOutputTransportStdout {
		t.Fatalf("nil composite = (%q, %t), want fail-closed stdout", transport, ok)
	}
}
