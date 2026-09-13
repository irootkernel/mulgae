package providercli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type fixtureTestNonceGenerator struct{ values []string }

func (generator *fixtureTestNonceGenerator) NewProbeNonce() (string, error) {
	if len(generator.values) == 0 {
		return "", errors.New("exhausted")
	}
	value := generator.values[0]
	generator.values = generator.values[1:]
	return value, nil
}

type fixtureTestWorkspaceFactory struct {
	requests []ports.WorkspaceSnapshotRequest
	lease    ports.QualificationWorkspaceLease
}

func (factory *fixtureTestWorkspaceFactory) MaterializeQualificationLease(_ context.Context, request ports.WorkspaceSnapshotRequest) (ports.QualificationWorkspaceLease, error) {
	factory.requests = append(factory.requests, request)
	return factory.lease, nil
}

type fixtureTestWorkspaceLease struct {
	identity      ports.WorkspaceSnapshotIdentity
	identities    []ports.WorkspaceSnapshotIdentity
	identityCalls int
	drains        int
	drainErr      error
	drainBounded  bool
	terminalDrain ports.QualificationWorkspaceTerminalDrain
}

func (lease *fixtureTestWorkspaceLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	if len(lease.identities) == 0 {
		return lease.identity
	}
	index := lease.identityCalls
	lease.identityCalls++
	if index >= len(lease.identities) {
		index = len(lease.identities) - 1
	}
	return lease.identities[index]
}

func (lease *fixtureTestWorkspaceLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}

func (lease *fixtureTestWorkspaceLease) DrainTerminal(ctx context.Context) (ports.QualificationWorkspaceTerminalReceipt, error) {
	return lease.terminalDrain(ctx)
}

func (lease *fixtureTestWorkspaceLease) drainTerminalEffects(ctx context.Context) error {
	lease.drains++
	_, lease.drainBounded = ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease.drainErr != nil {
		return lease.drainErr
	}
	return nil
}

func fixtureTestLease(t *testing.T) *fixtureTestWorkspaceLease {
	t.Helper()
	identity, err := ports.NewWorkspaceSnapshotIdentity("fixture-root", "snapshot-00000000000000000000000000000000", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "current-qualification-fixture-v1", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	var acquired *fixtureTestWorkspaceLease
	lease, err := ports.AcquireQualificationWorkspaceLease(context.Background(), func(_ context.Context, binding ports.QualificationWorkspaceTerminalBinding) (ports.QualificationWorkspaceLease, error) {
		acquired = &fixtureTestWorkspaceLease{identity: identity}
		drain, err := binding.Bind(identity, acquired.drainTerminalEffects)
		if err != nil {
			return nil, err
		}
		acquired.terminalDrain = drain
		return acquired, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return lease.(*fixtureTestWorkspaceLease)
}

func TestProbeFixtureCapabilityPacketDoesNotInduceWorkspaceToolReads(t *testing.T) {
	t.Parallel()
	fixture, request, err := newProbeFixture(domain.RoleSecurity, "root-nonce", "link-nonce")
	if err != nil {
		t.Fatal(err)
	}
	packet := string(fixture.packet)
	for _, forbidden := range []string{
		"._mulgae_workspace_manifest.json",
		"selectively read",
		"read-only tools",
		"During later reviews",
		"workspace files",
		"admitted workspace",
		"--allowed-tools",
		"WebFetch",
		"WebSearch",
	} {
		if strings.Contains(packet, forbidden) {
			t.Fatalf("capability packet induces workspace/tool reads via %q: %q", forbidden, packet)
		}
	}
	if !strings.Contains(packet, "root=root-nonce") ||
		!strings.Contains(packet, "link=link-nonce") ||
		!strings.Contains(packet, "role=security") ||
		!strings.Contains(packet, "returning exactly one JSON object and nothing else") ||
		!strings.Contains(packet, "do not add Markdown, narration, or fields") {
		t.Fatalf("capability packet lost embedded fixture bindings: %q", packet)
	}
	if request.PolicyIdentity() != "current-qualification-fixture-v2" {
		t.Fatalf("capability fixture policy = %q", request.PolicyIdentity())
	}
}

func TestProbeFixtureLeaseKeepsRoleWorkspacesIndependentWithoutRoleClaims(t *testing.T) {
	lease := fixtureTestLease(t)
	factory := &fixtureTestWorkspaceFactory{lease: lease}
	fixtures, err := NewProbeFixtureLeaseFactory(factory, &fixtureTestNonceGenerator{values: []string{"a1", "a2", "b1", "b2", "c1", "c2", "d1", "d2", "e1", "e2", "f1", "f2"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range domain.CoreRoleOrder() {
		fixture, err := fixtures.Acquire(context.Background(), role)
		if err != nil {
			t.Fatal(err)
		}
		if fixture.Role() != role || strings.Contains(string(fixture.Packet()), "role:") {
			t.Fatalf("role fixture %q contained an unsupported role claim", role)
		}
	}
	if len(factory.requests) != len(domain.CoreRoleOrder()) {
		t.Fatalf("materialized fixtures = %d", len(factory.requests))
	}
}

func TestProbeFixtureLeaseDrainPropagatesAndCanRetryAfterCancellation(t *testing.T) {
	lease := fixtureTestLease(t)
	factory := &fixtureTestWorkspaceFactory{lease: lease}
	fixtures, err := NewProbeFixtureLeaseFactory(factory, &fixtureTestNonceGenerator{values: []string{"nonce", "linked"}})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := fixtures.Acquire(context.Background(), domain.RoleSecurity)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.DrainTerminal(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled drain error = %v", err)
	}
	receipt, err := fixture.DrainTerminal(context.Background())
	if err != nil || receipt.WorkspaceSnapshotIdentity() != lease.identity || lease.drains != 2 {
		t.Fatalf("terminal receipt = %#v, err = %v, drains = %d", receipt, err, lease.drains)
	}
}
func TestProbeFixtureLeaseFactoryDrainsInvalidMaterializedLeaseExactlyOnce(t *testing.T) {
	lease := fixtureTestLease(t)
	lease.identity = ports.WorkspaceSnapshotIdentity{}
	drainErr := errors.New("drain failed")
	lease.drainErr = drainErr
	fixtures, err := NewProbeFixtureLeaseFactory(&fixtureTestWorkspaceFactory{lease: lease}, &fixtureTestNonceGenerator{values: []string{"nonce", "linked"}})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := fixtures.Acquire(context.Background(), domain.RoleSecurity)
	if fixture != nil || err == nil || !errors.Is(err, drainErr) || lease.drains != 1 || !lease.drainBounded {
		t.Fatalf("fixture=%#v err=%v drains=%d bounded=%t", fixture, err, lease.drains, lease.drainBounded)
	}
}

func TestProbeFixtureLeaseFactoryDrainsPostBindValidationFailureExactlyOnce(t *testing.T) {
	lease := fixtureTestLease(t)
	second, err := ports.NewWorkspaceSnapshotIdentity("fixture-root-two", "snapshot-11111111111111111111111111111111", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "current-qualification-fixture-v1", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	lease.identities = []ports.WorkspaceSnapshotIdentity{lease.identity, second, lease.identity}
	fixtures, err := NewProbeFixtureLeaseFactory(&fixtureTestWorkspaceFactory{lease: lease}, &fixtureTestNonceGenerator{values: []string{"nonce", "linked"}})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := fixtures.Acquire(context.Background(), domain.RoleSecurity)
	if fixture != nil || err == nil || lease.drains != 1 || !lease.drainBounded {
		t.Fatalf("fixture=%#v err=%v drains=%d bounded=%t", fixture, err, lease.drains, lease.drainBounded)
	}
}

func TestProbeFixtureLeaseFactoryRejectsInvalidDependencies(t *testing.T) {
	if _, err := NewProbeFixtureLeaseFactory(nil, &fixtureTestNonceGenerator{}); err == nil {
		t.Fatal("nil workspace factory accepted")
	}
	if _, err := NewProbeFixtureLeaseFactory(&fixtureTestWorkspaceFactory{}, nil); err == nil {
		t.Fatal("nil nonce generator accepted")
	}
}

func TestSecureProbeNonceGeneratorCreatesDistinctValidValues(t *testing.T) {
	generator := SecureProbeNonceGenerator{}
	first, err := generator.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.NewProbeNonce()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 64 || len(second) != 64 || !validProbeNonce(first) || !validProbeNonce(second) {
		t.Fatalf("nonces = %q, %q", first, second)
	}
}

var _ ports.QualificationWorkspaceLease = (*fixtureTestWorkspaceLease)(nil)
