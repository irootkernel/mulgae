package reviewrun

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// QualifiedRunCandidateSource constructs production candidates from the one
// captured input and requested role selection. Implementations may perform
// identity-only discovery, but must not acquire provider execution authority.
type QualifiedRunCandidateSource interface {
	NewQualifiedRunCandidates(context.Context, CapturedRunInput, RunSelection) ([]QualifiedRunCandidate, error)
}

// QualifiedRunContextBinder lets a production candidate source bind
// run-specific security authority after immutable target capture and before any
// provider observation. The returned context is used for candidate discovery,
// qualification, and registry construction.
type QualifiedRunContextBinder interface {
	BindQualifiedRunContext(context.Context, CapturedRunInput) (context.Context, error)
}

// RunAuthorityAdapter adapts a concrete qualified-run factory to the service
// authority boundary. It retains the concrete terminal receipt until the
// service-facing aggregate receipt is available.
type RunAuthorityAdapter struct {
	qualifiedRuns *QualifiedRunFactory
	candidates    QualifiedRunCandidateSource
	policy        PlannerPolicy
	build         BuildIdentity
}

// NewRunAuthorityAdapter constructs the service-facing adapter using only
// injected discovery/candidate construction and qualified-run authority.
func NewRunAuthorityAdapter(
	qualifiedRuns *QualifiedRunFactory,
	candidates QualifiedRunCandidateSource,
	policy PlannerPolicy,
	build BuildIdentity,
) (*RunAuthorityAdapter, error) {
	if qualifiedRuns == nil || nilInterface(candidates) || !build.Valid() {
		return nil, fmt.Errorf("review run: invalid run authority adapter dependencies")
	}
	return &RunAuthorityAdapter{
		qualifiedRuns: qualifiedRuns,
		candidates:    candidates,
		policy:        clonePlannerPolicy(policy),
		build:         build,
	}, nil
}

// NewQualifiedRun constructs a service authority from the immutable captured
// input. Candidate construction is fully injected and every malformed result
// fails closed before a provider registry is acquired.
func (adapter *RunAuthorityAdapter) NewQualifiedRun(ctx context.Context, captured CapturedRunInput, selection RunSelection) (RunAuthority, error) {
	if adapter == nil || adapter.qualifiedRuns == nil || nilInterface(adapter.candidates) || ctx == nil || !captured.Input().Target().Valid() || !selection.Valid() {
		return nil, fmt.Errorf("review run: invalid run authority request")
	}
	if binder, ok := adapter.candidates.(QualifiedRunContextBinder); ok {
		bound, err := binder.BindQualifiedRunContext(ctx, captured)
		if err != nil {
			return nil, newQualifiedRunConstructionError(
				fmt.Errorf("review run: bind qualified run context: %w", err),
				ports.NewEmptyProviderRunTerminalReceipt(),
			)
		}
		if bound == nil {
			return nil, newQualifiedRunConstructionError(
				fmt.Errorf("review run: bind qualified run context: nil context"),
				ports.NewEmptyProviderRunTerminalReceipt(),
			)
		}
		ctx = bound
	}
	candidates, err := adapter.candidates.NewQualifiedRunCandidates(ctx, captured, selection)
	if err != nil {
		return nil, newQualifiedRunConstructionError(
			fmt.Errorf("review run: construct qualified run candidates: %w", err),
			ports.NewEmptyProviderRunTerminalReceipt(),
		)
	}
	candidates = cloneQualifiedRunCandidates(candidates)
	if err := validateAuthorityCandidates(candidates); err != nil {
		return nil, newQualifiedRunConstructionError(err, ports.NewEmptyProviderRunTerminalReceipt())
	}
	candidates, err = restrictCandidatesToSelectedAssignments(candidates, selection, adapter.policy)
	if err != nil {
		return nil, newQualifiedRunConstructionError(err, ports.NewEmptyProviderRunTerminalReceipt())
	}
	run, err := adapter.qualifiedRuns.NewQualifiedRun(ctx, candidates)
	if err != nil {
		return nil, err
	}
	planner, err := newQualifiedPlanner(run.Routes(), adapter.policy, run.QualificationFailures())
	if err != nil {
		cause := fmt.Errorf("review run: construct planner: %w", err)
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			cleanupCtx, cancel := context.WithTimeout(ctx, time.Minute)
			receipt, drainErr := run.DrainTerminal(cleanupCtx)
			cancel()
			if drainErr == nil && receipt.Drained() {
				return nil, newQualifiedRunConstructionError(cause, receipt.ProviderRunTerminalReceipt())
			}
			if drainErr == nil {
				lastErr = fmt.Errorf("review run: terminal drain returned incomplete receipt")
			} else {
				lastErr = drainErr
			}
		}
		retained := &runAuthority{run: run, build: adapter.build}
		return nil, newQualifiedRunConstructionErrorWithAuthority(
			fmt.Errorf("%w; terminal drain: %v", cause, lastErr),
			retained,
		)
	}
	return &runAuthority{
		run:     run,
		planner: planner,
		build:   adapter.build,
	}, nil
}

func restrictCandidatesToSelectedAssignments(candidates []QualifiedRunCandidate, selection RunSelection, policy PlannerPolicy) ([]QualifiedRunCandidate, error) {
	if err := validatePlannerAssignments(policy.Assignments); err != nil {
		return nil, fmt.Errorf("review run: invalid assignment-scoped qualification policy: %w", err)
	}
	selected := canonicalSelectedRoles(selection.Roles())
	if len(selected) == 0 {
		return nil, fmt.Errorf("review run: assignment-scoped qualification has no selected roles")
	}
	rolesByFamily := make(map[Family][]domain.Role, len(candidates))
	for _, role := range selected {
		var assignment *RoleProviderAssignment
		for index := range policy.Assignments {
			if policy.Assignments[index].Role() == role {
				assignment = &policy.Assignments[index]
				break
			}
		}
		if assignment == nil {
			return nil, fmt.Errorf("review run: selected role %q has no configured assignment", role)
		}
		rolesByFamily[assignment.Primary()] = append(rolesByFamily[assignment.Primary()], role)
		if fallback, ok := assignment.Fallback(); ok {
			rolesByFamily[fallback] = append(rolesByFamily[fallback], role)
		}
	}

	restricted := make([]QualifiedRunCandidate, 0, len(candidates))
	coverage := make(map[Family]map[domain.Role]int, len(rolesByFamily))
	for _, candidate := range candidates {
		family := Family(candidate.Definition.Family())
		assigned := rolesByFamily[family]
		if len(assigned) == 0 {
			continue
		}
		supported := make(map[domain.Role]struct{}, len(candidate.SupportedRoles))
		for _, role := range candidate.SupportedRoles {
			supported[role] = struct{}{}
		}
		roles := make([]domain.Role, 0, len(assigned))
		for _, role := range assigned {
			if _, ok := supported[role]; ok {
				roles = append(roles, role)
			}
		}
		roles = canonicalSelectedRoles(roles)
		if len(roles) == 0 {
			continue
		}
		if coverage[family] == nil {
			coverage[family] = make(map[domain.Role]int)
		}
		for _, role := range roles {
			coverage[family][role]++
		}
		candidate.SupportedRoles = roles
		candidate.BaseRole = qualificationBaseRole(roles)
		restricted = append(restricted, candidate)
	}
	for family, roles := range rolesByFamily {
		for _, role := range canonicalSelectedRoles(roles) {
			if coverage[family][role] != 1 {
				return nil, fmt.Errorf("review run: configured %s role %q does not resolve to exactly one candidate", family, role)
			}
		}
	}
	if len(restricted) == 0 {
		return nil, fmt.Errorf("review run: no candidate is assigned to a selected role")
	}
	return restricted, nil
}

func cloneQualifiedRunCandidates(candidates []QualifiedRunCandidate) []QualifiedRunCandidate {
	cloned := append([]QualifiedRunCandidate(nil), candidates...)
	for index := range cloned {
		cloned[index].SupportedRoles = append([]domain.Role(nil), candidates[index].SupportedRoles...)
	}
	return cloned
}

func validateAuthorityCandidates(candidates []QualifiedRunCandidate) error {
	if len(candidates) == 0 || len(candidates) > 32 {
		return fmt.Errorf("review run: invalid qualified run candidates")
	}
	instances := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		definition := candidate.Definition
		if !candidate.Profile.Family().Valid() || candidate.SnapshotManifest == "" || !candidate.Limits.Valid() || !candidate.BaseRole.Valid() || len(candidate.SupportedRoles) == 0 ||
			Family(definition.Family()) != candidate.Profile.Family() || definition.Instance() == "" || definition.Executable() != candidate.Profile.Executable() || definition.ExecutableSHA256() != candidate.Profile.SHA256() || definition.Launcher() != candidate.Profile.Launcher() || definition.LauncherSHA256() != candidate.Profile.LauncherSHA256() {
			return fmt.Errorf("review run: invalid qualified run candidate")
		}
		roles := make(map[domain.Role]struct{}, len(candidate.SupportedRoles))
		hasBaseRole := false
		for _, role := range candidate.SupportedRoles {
			if !role.Valid() {
				return fmt.Errorf("review run: invalid supported role %q", role)
			}
			if _, duplicate := roles[role]; duplicate {
				return fmt.Errorf("review run: duplicate supported role %q", role)
			}
			roles[role] = struct{}{}
			hasBaseRole = hasBaseRole || role == candidate.BaseRole
		}
		if !hasBaseRole {
			return fmt.Errorf("review run: base role is not supported")
		}
		if _, duplicate := instances[definition.Instance()]; duplicate {
			return fmt.Errorf("review run: duplicate provider instance %q", definition.Instance())
		}
		instances[definition.Instance()] = struct{}{}
	}
	return nil
}

type registryCleanupAuthority struct {
	registry QualifiedRunRegistry
}

func (authority *registryCleanupAuthority) Provider() ports.ObservedReviewProvider {
	if authority == nil {
		return nil
	}
	return authority.registry
}

func (*registryCleanupAuthority) Planner() ExecutionPlanner { return nil }
func (*registryCleanupAuthority) BuildIdentity() BuildIdentity {
	return BuildIdentity{}
}

func (authority *registryCleanupAuthority) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	if authority == nil || nilInterface(authority.registry) || ctx == nil {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid registry cleanup authority")
	}
	receipt, err := authority.registry.Close(ctx)
	if err != nil {
		return QualifiedRunTerminalReceipt{}, err
	}
	if !receipt.Valid() {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: registry cleanup returned incomplete receipt")
	}
	return QualifiedRunTerminalReceipt{receipt: receipt, cleanupOnly: true}, nil
}

type runAuthority struct {
	run     *QualifiedRun
	planner ExecutionPlanner
	build   BuildIdentity

	terminalMu sync.Mutex
	terminal   QualifiedRunTerminalReceipt
}

func (authority *runAuthority) Provider() ports.ObservedReviewProvider {
	if authority == nil || authority.run == nil {
		return nil
	}
	return authority.run.Registry()
}

func (authority *runAuthority) Planner() ExecutionPlanner {
	if authority == nil {
		return nil
	}
	return authority.planner
}

func (authority *runAuthority) BuildIdentity() BuildIdentity {
	if authority == nil {
		return BuildIdentity{}
	}
	return authority.build
}

func (authority *runAuthority) QualificationObservations() []ProviderQualificationObservation {
	if authority == nil || authority.run == nil {
		return nil
	}
	return authority.run.QualificationObservations()
}

func (authority *runAuthority) DrainTerminal(ctx context.Context) (QualifiedRunTerminalReceipt, error) {
	if authority == nil || authority.run == nil || ctx == nil {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: invalid run authority terminal drain")
	}
	receipt, err := authority.run.DrainTerminal(ctx)
	if err != nil {
		return QualifiedRunTerminalReceipt{}, err
	}
	if !receipt.Drained() {
		return QualifiedRunTerminalReceipt{}, fmt.Errorf("review run: qualified run terminal drain incomplete")
	}
	authority.terminalMu.Lock()
	defer authority.terminalMu.Unlock()
	if authority.terminal.Drained() {
		return authority.terminal, nil
	}
	authority.terminal = receipt
	return receipt, nil
}
