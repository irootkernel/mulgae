package reviewrun

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type authorityCandidateSource struct{ candidates []QualifiedRunCandidate }

func authorityLiveExecution(t *testing.T) ports.LiveReviewExecution {
	t.Helper()
	selector, _ := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	path, _ := ports.NewSafeRelativePath("source.go")
	target, _ := ports.NewLiveSourceTarget(selector, ports.GitObjectID{}, ports.GitObjectID{}, false, []ports.LiveSourceChange{{Kind: "included", After: path}})
	root, _ := ports.NewAnchoredRoot("/project")
	git, _ := ports.NewAnchoredRoot("/project/.git")
	home, _ := ports.NewAnchoredRoot("/neutral")
	credentials, _ := ports.NewAnchoredRoot("/credentials")
	reader := &promptLiveReader{target: target, binding: ports.ProjectBindingObservation{Root: root, GitDirectory: git, CommonDirectory: git, RootIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 2}, GitIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}, CommonIdentity: ports.ProjectDirectoryIdentity{Device: 1, Inode: 3}}}
	execution, err := ports.NewLiveReviewExecution(context.Background(), reader, promptLiveHome{root: home}, []ports.AnchoredRoot{credentials})
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func (source authorityCandidateSource) BindLiveQualifiedRunContext(ctx context.Context, _ ports.LiveReviewExecution) (context.Context, error) {
	return ctx, nil
}
func (source authorityCandidateSource) NewLiveQualifiedRunCandidates(context.Context, ports.LiveSourceTarget, RunSelection) ([]QualifiedRunCandidate, error) {
	return source.candidates, nil
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
		plannerTestCanonicalPolicy(t, []Family{FamilyGrok}),
		BuildIdentity{Product: "mulgae", Version: "1.2.3", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"},
	)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := adapter.NewQualifiedLiveRun(context.Background(), authorityLiveExecution(t), authoritySelection(t))
	if err != nil {
		t.Fatal(err)
	}
	if authority.Provider() == nil || authority.Planner() == nil ||
		authority.BuildIdentity() != (BuildIdentity{Product: "mulgae", Version: "1.2.3", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"}) {
		t.Fatal("authority did not retain provider, planner, and build identity")
	}
	first, err := authority.DrainTerminal(context.Background())
	if err != nil || !first.Drained() {
		t.Fatalf("terminal = %#v, %v", first, err)
	}
	if receipts := first.NamespaceReceipts(); len(receipts) != 1 || receipts[0].ProviderInstance() != "grok-main" || receipts[0].Generation() != "generation-1" {
		t.Fatalf("aggregate terminal = %#v", first)
	}
	retained := authority.(*runAuthority).terminal
	if !retained.Drained() || len(retained.Instances()) != 1 || retained.Instances()[0] != "grok-main" {
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
	policy := plannerTestCanonicalPolicy(t, []Family{FamilyGrok})
	policy.MaxWorkers = -1
	adapter, err := NewRunAuthorityAdapter(qualified, authorityCandidateSource{candidates: []QualifiedRunCandidate{authorityCandidate(t)}}, policy, BuildIdentity{Product: "mulgae", Version: "1.2.3", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := adapter.NewQualifiedLiveRun(ctx, authorityLiveExecution(t), authoritySelection(t)); err == nil || registry.closed != 1 {
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
	policy := plannerTestCanonicalPolicy(t, []Family{FamilyGrok})
	policy.MaxWorkers = -1
	adapter, err := NewRunAuthorityAdapter(qualified, authorityCandidateSource{candidates: []QualifiedRunCandidate{authorityCandidate(t)}}, policy, BuildIdentity{Product: "mulgae", Version: "1.2.3", Module: "github.com/irootkernel/mulgae", VCSRevision: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.NewQualifiedLiveRun(context.Background(), authorityLiveExecution(t), authoritySelection(t))
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

func TestQualificationCandidatesAreRestrictedToSelectedAssignments(t *testing.T) {
	selected := []domain.Role{domain.RoleLogic, domain.RoleSecurity, domain.RoleDocumentation}
	selection, err := NewRunSelection(selected, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []QualifiedRunCandidate{
		authorityCandidateForRoles(t, FamilyZCode, "zcode-main", selected),
		authorityCandidateForRoles(t, FamilyGrok, "grok-main", selected),
		authorityCandidateForRoles(t, FamilyCodex, "codex-main", selected),
	}
	restricted, err := restrictCandidatesToSelectedAssignments(
		candidates,
		selection,
		plannerTestCanonicalPolicy(t, []Family{FamilyZCode, FamilyGrok, FamilyCodex}),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Each role names exactly one family, so the families partition the roles.
	want := map[Family][]domain.Role{
		FamilyZCode: {domain.RoleLogic},
		FamilyGrok:  {domain.RoleSecurity},
		FamilyCodex: {domain.RoleDocumentation},
	}
	if len(restricted) != len(want) {
		t.Fatalf("restricted candidate count = %d, want %d", len(restricted), len(want))
	}
	for _, candidate := range restricted {
		family := Family(candidate.Definition.Family())
		if !reflect.DeepEqual(candidate.SupportedRoles, want[family]) {
			t.Fatalf("%s qualification roles = %v, want %v", family, candidate.SupportedRoles, want[family])
		}
		wantBase := candidate.SupportedRoles[0]
		if candidate.BaseRole != wantBase {
			t.Fatalf("%s qualification base role = %q, want %q", family, candidate.BaseRole, wantBase)
		}
	}
}

func authorityCandidate(t *testing.T) QualifiedRunCandidate {
	t.Helper()
	definition, _ := authorityProbeDefinition(t, FamilyGrok, "grok-main", "1.0.34", t.TempDir())
	limits, err := review.NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return QualifiedRunCandidate{
		Profile: DiscoveredProviderProfile{
			family: FamilyGrok, executable: definition.Executable(), launcher: definition.Launcher(),
			argv: definition.BaseArgv(), sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
			reason: "unqualified_discovery",
		},
		Definition:              definition,
		ExecutionTargetIdentity: "manifest-1",
		SupportedRoles:          []domain.Role{domain.RoleLogic},
		BaseRole:                domain.RoleLogic,
		Limits:                  limits,
	}
}

func authorityCandidateForRoles(t *testing.T, family Family, instance string, roles []domain.Role) QualifiedRunCandidate {
	t.Helper()
	definition, _ := authorityProbeDefinition(t, family, instance, "1.0.34", t.TempDir())
	limits, err := review.NewInvocationLimits(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return QualifiedRunCandidate{
		Profile: DiscoveredProviderProfile{
			family: family, executable: definition.Executable(), launcher: definition.Launcher(),
			argv: definition.BaseArgv(), sha256: definition.ExecutableSHA256(), launcherSHA256: definition.LauncherSHA256(),
			providerConfig: definition.ZCodeProviderConfig(), providerConfigSHA256: definition.ZCodeProviderConfigSHA256(),
			applicationVersion: definition.ApplicationVersion(), applicationVersionClassification: ClassifyZCodeApplicationVersion(definition.ApplicationVersion()), applicationMetadata: definition.ApplicationMetadata(), applicationMetadataSHA256: definition.ApplicationMetadataSHA256(),
			reason: "unqualified_discovery",
		},
		Definition:              definition,
		ExecutionTargetIdentity: "manifest-1",
		SupportedRoles:          append([]domain.Role(nil), roles...),
		BaseRole:                roles[0],
		Limits:                  limits,
	}
}

func authorityQualifier(t *testing.T, now time.Time) CurrentQualifier {
	t.Helper()
	return CurrentQualifierFunc(func(_ context.Context, request CurrentQualificationRequest) (CurrentQualificationResult, error) {
		input := currentProbeAuthorityInputForInstance(t, request.Identity.Family, request.Identity.Instance, "1.0.34")
		return CurrentQualificationResult{
			VersionArgv: []string{request.Identity.Executable, "--version"}, Version: "1.0.34", Receipts: input.Receipts,
			SupportedRoles: []domain.Role{domain.RoleLogic}, RoleReceipts: []CurrentRoleReceipt{{Role: domain.RoleLogic, State: ReceiptPass, Identity: input.Identity}},
			BaseRole: domain.RoleLogic,
		}, nil
	})
}

func newAuthorityRegistry(t *testing.T) *qualifierRegistry {
	t.Helper()
	namespace := acquiredProviderNamespaceTerminalReceipt(t, "grok-main", "generation-1")
	aggregate := mustProviderRunTerminalReceipt(t, namespace)
	return &qualifierRegistry{
		namespaces: make(map[string]ports.ProviderQualificationNamespace),
		receipt:    aggregate,
	}
}

func authoritySelection(t *testing.T) RunSelection {
	t.Helper()
	selection, err := NewRunSelection([]domain.Role{domain.RoleLogic}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return selection
}
