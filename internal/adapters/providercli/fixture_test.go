package providercli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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

func TestProbeFixtureLeaseAcquiresExactImmutableFixture(t *testing.T) {
	lease := fixtureTestLease(t)
	factory := &fixtureTestWorkspaceFactory{lease: lease}
	fixtures, err := NewProbeFixtureLeaseFactory(factory, &fixtureTestNonceGenerator{values: []string{"root-one", "linked-one", "root-two", "linked-two"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixtures.Acquire(context.Background(), domain.RoleLogic)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixtures.Acquire(context.Background(), domain.RoleLogic)
	if err != nil {
		t.Fatal(err)
	}
	if first.Nonce() != "root-one" || first.Link() != "linked-one" || first.Nonce() == first.Link() || first.Nonce() == second.Nonce() || first.Reference() != "roadmap.md" {
		t.Fatalf("unexpected fixture evidence: %#v", first)
	}
	if len(factory.requests) != 2 || len(factory.requests[0].Files()) != 2 {
		t.Fatalf("materialized fixture files = %#v", factory.requests)
	}
	files := factory.requests[0].Files()
	if files[0].Path().String() != "docs/linked.md" || files[1].Path().String() != "roadmap.md" {
		t.Fatalf("fixture paths = %#v", files)
	}
	for _, file := range files {
		contents := string(file.Bytes())
		switch file.Path().String() {
		case "roadmap.md":
			if !strings.Contains(contents, first.Nonce()) || strings.Contains(contents, first.Link()) {
				t.Fatalf("roadmap nonce isolation failed: %q", contents)
			}
			if strings.Contains(contents, "missing") || strings.Contains(contents, "denied") || strings.Contains(contents, "command") {
				t.Fatalf("roadmap requested denial-shaped evidence: %q", contents)
			}
		case "docs/linked.md":
			if contents != first.Link() || strings.Contains(contents, first.Nonce()) {
				t.Fatalf("linked nonce isolation failed: %q", contents)
			}
		}
	}
	definition := testProfile(t, FamilyAgy, "agy_current", "agy-current", "", "")
	argv, err := (NativeProbeInvocation{}).CapabilityArgv(definition, first)
	if err != nil || strings.Contains(strings.Join(argv, "\x00"), first.Nonce()) || strings.Contains(strings.Join(argv, "\x00"), first.Link()) {
		t.Fatalf("native invocation exposed fixture nonce: argv=%q err=%v", argv, err)
	}
	packet := first.Packet()
	packet[0] = 'X'
	if string(first.Packet()) == string(packet) || first.PacketSHA256() == "" || first.WorkspaceSnapshotIdentity() != lease.identity || first.Validate() != nil {
		t.Fatal("fixture did not preserve defensive immutable values")
	}
}

func TestProbeFixtureLeaseKeepsRoleWorkspacesIndependentWithoutRoleClaims(t *testing.T) {
	lease := fixtureTestLease(t)
	factory := &fixtureTestWorkspaceFactory{lease: lease}
	fixtures, err := NewProbeFixtureLeaseFactory(factory, &fixtureTestNonceGenerator{values: []string{"a1", "a2", "b1", "b2", "c1", "c2", "d1", "d2", "e1", "e2", "f1", "f2"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range domain.FixedRoleOrder() {
		fixture, err := fixtures.Acquire(context.Background(), role)
		if err != nil {
			t.Fatal(err)
		}
		if fixture.Role() != role || strings.Contains(string(fixture.Packet()), "role:") {
			t.Fatalf("role fixture %q contained an unsupported role claim", role)
		}
	}
	if len(factory.requests) != len(domain.FixedRoleOrder()) {
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
