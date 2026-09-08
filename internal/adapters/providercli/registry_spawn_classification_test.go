package providercli

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type failingSpawnVerifier struct{ err error }

func (verifier failingSpawnVerifier) VerifyProviderSpawn(context.Context, RuntimeDefinition) error {
	return verifier.err
}

// TestRegistryObserveClassifiesSpawnRevalidationRefusals pins the typed
// classification of per-spawn revalidation refusals: an inability to establish
// the launch environment right now is a retryable provider execution failure,
// while a proven environment change keeps the deterministic spawn-failed
// classification. Neither may collapse into an internal invariant.
func TestRegistryObserveClassifiesSpawnRevalidationRefusals(t *testing.T) {
	for _, test := range []struct {
		name        string
		verifierErr error
		wantCause   domain.RuntimeDiagnosticCause
	}{
		{
			name:        "transient revalidation inability",
			verifierErr: errors.New("temporary inability to attest"),
			wantCause:   domain.DiagnosticCauseProviderExecutionFailed,
		},
		{
			name:        "proven environment drift",
			verifierErr: fmt.Errorf("%w: descriptor hash mismatch", ports.ErrProviderSpawnEnvironmentDrift),
			wantCause:   domain.DiagnosticCauseProviderSpawnFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := testProductionSafetyProfile(t, FamilyKimi, "policy-expected")
			profile.requiresWorkspaceAuthority = false
			factory, err := NewNamespaceFactory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistryWithNamespaceFactory(&countingRunner{}, factory, profile)
			if err != nil || registry == nil {
				t.Fatalf("registry=%v err=%v", registry, err)
			}
			registry.spawnVerifier = failingSpawnVerifier{err: test.verifierErr}
			_, observeErr := registry.Observe(context.Background(), testInvocation(t, profile.Instance()))
			if observeErr == nil {
				t.Fatal("spawn revalidation refusal was accepted")
			}
			var failure *ports.ProviderRuntimeError
			if !errors.As(observeErr, &failure) {
				t.Fatalf("spawn revalidation refusal is untyped: %v", observeErr)
			}
			if failure.Cause() != test.wantCause {
				t.Fatalf("revalidation refusal cause = %q, want %q", failure.Cause(), test.wantCause)
			}
		})
	}
}
