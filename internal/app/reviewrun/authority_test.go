package reviewrun

import (
	"context"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/adapters/providercli"
	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type authorityCandidateSource struct{ candidates []QualifiedRunCandidate }

func (source authorityCandidateSource) NewQualifiedRunCandidates(context.Context, CapturedRunInput, RunSelection) ([]QualifiedRunCandidate, error) {
	return source.candidates, nil
}

type authorityLease struct {
	identity ports.WorkspaceSnapshotIdentity
}

func (lease authorityLease) WorkspaceSnapshotIdentity() ports.WorkspaceSnapshotIdentity {
	return lease.identity
}
func (authorityLease) RevalidateForExecution() (ports.WorkspaceExecutionGuard, error) {
	return nil, nil
}
func (authorityLease) Receipt() ports.WorkspaceSnapshotReceipt {
	return ports.WorkspaceSnapshotReceipt{}
}
func (authorityLease) Release(ports.WorkspaceCompletionEvidence) (ports.WorkspaceTerminalReceipt, error) {
	return ports.WorkspaceTerminalReceipt{}, nil
}
func (authorityLease) Abort(ports.WorkspaceAbortEvidence) error { return nil }

type authorityReader struct{}

func (authorityReader) ReadImmutableTarget(context.Context, string, evidence.Side, ports.SafeRelativePath) (evidence.ImmutableTargetAvailability, []byte, error) {
	return evidence.ImmutableTargetUnavailable, nil, nil
}

func TestRunAuthorityAdapterMapsQualifiedRunToServiceAuthority(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	qualified, err := NewQualifiedRunFactory(authorityQualifier(t, now), qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewRunAuthorityAdapter(
		qualified,
		authorityCandidateSource{candidates: []QualifiedRunCandidate{authorityCandidate(t)}},
		PlannerPolicy{},
		BuildIdentity{Product: "kar", Version: "1.2.3", Commit: "abc123"},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := adapter.NewQualifiedRun(context.Background(), authorityCaptured(t), authoritySelection(t))
	if err != nil {
		t.Fatal(err)
	}
	if authority.Provider() == nil || authority.Planner() == nil ||
		authority.BuildIdentity() != (BuildIdentity{Product: "kar", Version: "1.2.3", Commit: "abc123"}) {
		t.Fatal("authority did not retain provider, planner, and build identity")
	}
	first, err := authority.DrainTerminal(context.Background())
	if err != nil || !first.Drained() {
		t.Fatalf("terminal = %#v, %v", first, err)
	}
	if receipts := first.NamespaceReceipts(); len(receipts) != 1 || receipts[0].ProviderInstance() != "agy-main" || receipts[0].Generation() != "generation-1" {
		t.Fatalf("aggregate terminal = %#v", first)
	}
	retained := authority.(*runAuthority).terminal
	if !retained.Drained() || len(retained.Instances()) != 1 || retained.Instances()[0] != "agy-main" {
		t.Fatalf("retained terminal = %#v", retained)
	}
	second, err := authority.DrainTerminal(context.Background())
	if err != nil || !second.Drained() || registry.closed != 1 {
		t.Fatalf("repeat terminal = %#v, %v; closes=%d", second, err, registry.closed)
	}
}

func TestRunAuthorityAdapterDrainsOnPlannerConstructionFailure(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	qualified, err := NewQualifiedRunFactory(authorityQualifier(t, now), qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewRunAuthorityAdapter(qualified, authorityCandidateSource{candidates: []QualifiedRunCandidate{authorityCandidate(t)}}, PlannerPolicy{MaxLanes: -1}, BuildIdentity{Product: "kar", Version: "1.2.3", Commit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := adapter.NewQualifiedRun(ctx, authorityCaptured(t), authoritySelection(t)); err == nil || registry.closed != 1 {
		t.Fatalf("planner construction = %v; closes=%d", err, registry.closed)
	}
	if len(registry.closeContexts) != 1 || registry.closeContexts[0] == ctx {
		t.Fatalf("planner cleanup context = %#v", registry.closeContexts)
	}
	if _, bounded := registry.closeContexts[0].Deadline(); !bounded {
		t.Fatalf("planner cleanup context is unbounded")
	}
}
func TestRunAuthorityAdapterPlannerCleanupRetainsRetryOwner(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	registry := newAuthorityRegistry(t)
	registry.closeErrs = []error{context.DeadlineExceeded, context.DeadlineExceeded}
	qualified, err := NewQualifiedRunFactory(authorityQualifier(t, now), qualifierRegistryFactory{registry: registry}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewRunAuthorityAdapter(qualified, authorityCandidateSource{candidates: []QualifiedRunCandidate{authorityCandidate(t)}}, PlannerPolicy{MaxLanes: -1}, BuildIdentity{Product: "kar", Version: "1.2.3", Commit: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.NewQualifiedRun(context.Background(), authorityCaptured(t), authoritySelection(t))
	if err == nil || registry.closed != 2 {
		t.Fatalf("planner construction = %v; closes=%d", err, registry.closed)
	}
	if receipt, ok := ProviderRunTerminalReceiptFromError(err); ok || receipt.Valid() {
		t.Fatalf("persistent planner cleanup represented as terminal proof = %#v, present=%t", receipt, ok)
	}
	owner, ok := RunAuthorityFromError(err)
	if !ok || owner == nil {
		t.Fatalf("planner cleanup owner = %#v, present=%t", owner, ok)
	}
	receipt, err := owner.DrainTerminal(context.Background())
	if err != nil || !receipt.Drained() || registry.closed != 3 {
		t.Fatalf("planner cleanup retry = %#v, %v; closes=%d", receipt, err, registry.closed)
	}
}

func TestNewRunAuthorityAdapterRejectsInvalidBuildIdentity(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	qualified, err := NewQualifiedRunFactory(authorityQualifier(t, now), qualifierRegistryFactory{registry: newAuthorityRegistry(t)}, qualifierClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunAuthorityAdapter(qualified, authorityCandidateSource{}, PlannerPolicy{}, BuildIdentity{}); err == nil {
		t.Fatal("invalid build identity accepted")
	}
}

func TestImmutableReviewInputRetainsObjectivePresence(t *testing.T) {
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	absent, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if absent.HasObjective() || absent.Objective() != nil {
		t.Fatalf("absent objective = present %t, bytes %q", absent.HasObjective(), absent.Objective())
	}
	empty, err := NewImmutableReviewInput(target, []byte{}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.HasObjective() || len(empty.Objective()) != 0 {
		t.Fatalf("present empty objective = present %t, bytes %q", empty.HasObjective(), empty.Objective())
	}
	if _, err := NewImmutableReviewInput(target, []byte("objective"), false, nil); err == nil {
		t.Fatal("absent objective with bytes accepted")
	}
}
func authorityCandidate(t *testing.T) QualifiedRunCandidate {
	t.Helper()
	definition, _ := authorityProbeDefinition(t, FamilyAGY, "agy-main", "1.1.4", t.TempDir())
	limits, err := review.NewInvocationLimits(time.Second, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return QualifiedRunCandidate{
		Profile: DiscoveredProviderProfile{
			family: FamilyAGY, executable: definition.Executable(), launcher: definition.Launcher(),
			argv: definition.BaseArgv(), sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
			reason: "unqualified_discovery",
		},
		Definition:       definition,
		SnapshotManifest: "manifest-1",
		SupportedRoles:   []domain.Role{domain.RoleLogic},
		BaseRole:         domain.RoleLogic,
		Limits:           limits,
	}
}

func authorityQualifier(t *testing.T, now time.Time) CurrentQualifier {
	t.Helper()
	return CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		input := currentProbeAuthorityInputForInstance(t, request.Identity.Family, request.Identity.Instance, "1.1.4")
		return CurrentQualificationResult{
			VersionArgv: []string{request.Identity.Executable, "--version"}, Version: "1.1.4", Receipts: input.Receipts,
			SupportedRoles: []domain.Role{domain.RoleLogic}, RoleReceipts: []CurrentRoleReceipt{{Role: domain.RoleLogic, State: ReceiptPass, Identity: input.Identity}},
			BaseRole: domain.RoleLogic,
		}, nil
	})
}

func newAuthorityRegistry(t *testing.T) *qualifierRegistry {
	t.Helper()
	namespace := acquiredProviderNamespaceTerminalReceipt(t, "agy-main", "generation-1")
	aggregate := mustProviderRunTerminalReceipt(t, namespace)
	return &qualifierRegistry{
		namespaces: make(map[string]providercli.QualificationNamespace),
		receipt:    aggregate,
	}
}

func authorityCaptured(t *testing.T) CapturedRunInput {
	t.Helper()
	target, err := ports.NewCapturedReviewPatchTarget([]byte("patch"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewImmutableReviewInput(target, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ports.NewWorkspaceSnapshotIdentity("/private/snapshot", "snapshot-0123456789abcdef0123456789abcdef", "sha256:"+qualifierTestSHA, "policy", 1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := NewCapturedRunInput(input, authorityLease{identity: identity}, authorityReader{})
	if err != nil {
		t.Fatal(err)
	}
	return captured
}

func authoritySelection(t *testing.T) RunSelection {
	t.Helper()
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return selection
}
