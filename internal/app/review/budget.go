package review

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	maxBudgetInvocationsPerRole = 4
	maxBudgetInvocationsPerRun  = 24
	maxBudgetTotalOutputBytes   = int64(64 << 20)
	maxBudgetRunDeadline        = 30 * time.Minute

	budgetTransitionGrace = 2 * time.Second
	budgetRunGrace        = 5 * time.Second
)

// InvocationLimits are the immutable resource caps for every possible
// invocation through one provider route.
type InvocationLimits struct {
	timeout        time.Duration
	maxStdoutBytes int64
	maxStderrBytes int64
}

// NewInvocationLimits validates positive, independent invocation caps.
func NewInvocationLimits(timeout time.Duration, stdoutCap, stderrCap int64) (InvocationLimits, error) {
	limits := InvocationLimits{
		timeout:        timeout,
		maxStdoutBytes: stdoutCap,
		maxStderrBytes: stderrCap,
	}
	if err := validateInvocationLimits(limits); err != nil {
		return InvocationLimits{}, err
	}
	return limits, nil
}

// Timeout returns the positive invocation deadline.
func (limits InvocationLimits) Timeout() time.Duration { return limits.timeout }

// MaxStdoutBytes returns the positive stdout capture cap.
func (limits InvocationLimits) MaxStdoutBytes() int64 { return limits.maxStdoutBytes }

// MaxStderrBytes returns the positive stderr capture cap.
func (limits InvocationLimits) MaxStderrBytes() int64 { return limits.maxStderrBytes }

// Valid reports whether limits contain only positive invocation caps.
func (limits InvocationLimits) Valid() bool { return validateInvocationLimits(limits) == nil }

// RouteBudget binds immutable invocation limits to one normalized provider
// route. The limits apply to both the route's initial and repair invocations.
type RouteBudget struct {
	route  ports.ProviderRoute
	limits InvocationLimits
}

// NewRouteBudget constructs a valid route-and-limits operand.
func NewRouteBudget(route ports.ProviderRoute, limits InvocationLimits) (RouteBudget, error) {
	budget := RouteBudget{route: route, limits: limits}
	if err := validateRouteBudget(budget); err != nil {
		return RouteBudget{}, err
	}
	return budget, nil
}

// Route returns the immutable provider route.
func (budget RouteBudget) Route() ports.ProviderRoute { return budget.route }

// Limits returns the immutable invocation limits for the route.
func (budget RouteBudget) Limits() InvocationLimits { return budget.limits }

// Valid reports whether budget has a valid route and positive invocation caps.
func (budget RouteBudget) Valid() bool { return validateRouteBudget(budget) == nil }

// RoleBudget contains the primary route and optional fallback route for one
// selected review role.
type RoleBudget struct {
	role        domain.Role
	primary     RouteBudget
	fallback    RouteBudget
	hasFallback bool
}

// NewRoleBudget constructs one role's primary and optional fallback operands.
// A fallback must select a different provider instance from the primary, while
// retaining the option to share its normalized concurrency lane.
func NewRoleBudget(role domain.Role, primary RouteBudget, fallback *RouteBudget) (RoleBudget, error) {
	budget := RoleBudget{role: role, primary: primary}
	if fallback != nil {
		budget.fallback = *fallback
		budget.hasFallback = true
	}
	if err := validateRoleBudget(budget); err != nil {
		return RoleBudget{}, err
	}
	return budget, nil
}

// Role returns the selected review role.
func (budget RoleBudget) Role() domain.Role { return budget.role }

// Primary returns the immutable primary route budget.
func (budget RoleBudget) Primary() RouteBudget { return budget.primary }

// Fallback returns a caller-owned fallback route budget when one is configured.
func (budget RoleBudget) Fallback() (RouteBudget, bool) { return budget.fallback, budget.hasFallback }

// Valid reports whether budget is a complete role selection.
func (budget RoleBudget) Valid() bool { return validateRoleBudget(budget) == nil }

// HarnessCeilings are trusted preflight ceilings. They can only strengthen the
// fixed SOT resource limits; they never authorize a larger budget.
type HarnessCeilings struct {
	maxTimeout            time.Duration
	maxStdoutBytes        int64
	maxStderrBytes        int64
	maxTotalOutput        int64
	maxLaneDeadline       time.Duration
	maxRunDeadline        time.Duration
	maxInvocationsPerRole int
	maxInvocationsPerRun  int
}

// NewHarnessCeilings validates trusted execution ceilings. The fixed SOT
// maxima are closed: four invocations per role, 24 per run, 64 MiB output,
// and a 30 minute run deadline.
func NewHarnessCeilings(
	maxTimeout time.Duration,
	maxStdout, maxStderr, maxTotalOutput int64,
	maxLaneDeadline, maxRunDeadline time.Duration,
	maxInvocationsPerRole, maxInvocationsPerRun int,
) (HarnessCeilings, error) {
	ceilings := HarnessCeilings{
		maxTimeout:            maxTimeout,
		maxStdoutBytes:        maxStdout,
		maxStderrBytes:        maxStderr,
		maxTotalOutput:        maxTotalOutput,
		maxLaneDeadline:       maxLaneDeadline,
		maxRunDeadline:        maxRunDeadline,
		maxInvocationsPerRole: maxInvocationsPerRole,
		maxInvocationsPerRun:  maxInvocationsPerRun,
	}
	if err := validateHarnessCeilings(ceilings); err != nil {
		return HarnessCeilings{}, err
	}
	return ceilings, nil
}

// DefaultHarnessCeilings returns the immutable SOT default envelope. Callers
// must pass it explicitly to PreflightRunBudget when these defaults are wanted.
func DefaultHarnessCeilings() HarnessCeilings {
	return HarnessCeilings{
		maxTimeout:            180 * time.Second,
		maxStdoutBytes:        256 << 10,
		maxStderrBytes:        256 << 10,
		maxTotalOutput:        maxBudgetTotalOutputBytes,
		maxLaneDeadline:       25 * time.Minute,
		maxRunDeadline:        maxBudgetRunDeadline,
		maxInvocationsPerRole: maxBudgetInvocationsPerRole,
		maxInvocationsPerRun:  maxBudgetInvocationsPerRun,
	}
}

// MaxTimeout returns the trusted per-invocation timeout ceiling.
func (ceilings HarnessCeilings) MaxTimeout() time.Duration { return ceilings.maxTimeout }

// MaxStdoutBytes returns the trusted per-invocation stdout ceiling.
func (ceilings HarnessCeilings) MaxStdoutBytes() int64 { return ceilings.maxStdoutBytes }

// MaxStderrBytes returns the trusted per-invocation stderr ceiling.
func (ceilings HarnessCeilings) MaxStderrBytes() int64 { return ceilings.maxStderrBytes }

// MaxTotalOutput returns the trusted aggregate stdout-plus-stderr ceiling.
func (ceilings HarnessCeilings) MaxTotalOutput() int64 { return ceilings.maxTotalOutput }

// MaxLaneDeadline returns the trusted per-lane deadline ceiling.
func (ceilings HarnessCeilings) MaxLaneDeadline() time.Duration { return ceilings.maxLaneDeadline }

// MaxRunDeadline returns the trusted full-run deadline ceiling.
func (ceilings HarnessCeilings) MaxRunDeadline() time.Duration { return ceilings.maxRunDeadline }

// MaxInvocationsPerRole returns the trusted role invocation ceiling.
func (ceilings HarnessCeilings) MaxInvocationsPerRole() int {
	return ceilings.maxInvocationsPerRole
}

// MaxInvocationsPerRun returns the trusted run invocation ceiling.
func (ceilings HarnessCeilings) MaxInvocationsPerRun() int { return ceilings.maxInvocationsPerRun }

// Valid reports whether ceilings are positive and no weaker than the fixed SOT
// resource bounds.
func (ceilings HarnessCeilings) Valid() bool { return validateHarnessCeilings(ceilings) == nil }

// BudgetReasonCode is the closed, safe preflight outcome code recorded in a
// run budget receipt.
type BudgetReasonCode string

const (
	BudgetReasonEligible              BudgetReasonCode = "eligible"
	BudgetReasonInvalidCeilings       BudgetReasonCode = "invalid_ceilings"
	BudgetReasonInvalidRole           BudgetReasonCode = "invalid_role"
	BudgetReasonDuplicateRole         BudgetReasonCode = "duplicate_role"
	BudgetReasonMissingRequiredRole   BudgetReasonCode = "missing_required_role"
	BudgetReasonMissingRole           BudgetReasonCode = "missing_role"
	BudgetReasonInvalidPrimaryRoute   BudgetReasonCode = "invalid_primary_route"
	BudgetReasonInvalidFallbackRoute  BudgetReasonCode = "invalid_fallback_route"
	BudgetReasonDuplicateRoleRoute    BudgetReasonCode = "duplicate_role_route"
	BudgetReasonInvocationCapExceeded BudgetReasonCode = "invocation_cap_exceeded"
	BudgetReasonRoleInvocationLimit   BudgetReasonCode = "role_invocation_limit"
	BudgetReasonRunInvocationLimit    BudgetReasonCode = "run_invocation_limit"
	BudgetReasonTotalOutputLimit      BudgetReasonCode = "total_output_limit"
	BudgetReasonLaneDeadlineLimit     BudgetReasonCode = "lane_deadline_limit"
	BudgetReasonRunDeadlineLimit      BudgetReasonCode = "run_deadline_limit"
)

// Valid reports whether code is a closed preflight reason code.
func (code BudgetReasonCode) Valid() bool {
	switch code {
	case BudgetReasonEligible,
		BudgetReasonInvalidCeilings,
		BudgetReasonInvalidRole,
		BudgetReasonDuplicateRole,
		BudgetReasonMissingRequiredRole,
		BudgetReasonMissingRole,
		BudgetReasonInvalidPrimaryRoute,
		BudgetReasonInvalidFallbackRoute,
		BudgetReasonDuplicateRoleRoute,
		BudgetReasonInvocationCapExceeded,
		BudgetReasonRoleInvocationLimit,
		BudgetReasonRunInvocationLimit,
		BudgetReasonTotalOutputLimit,
		BudgetReasonLaneDeadlineLimit,
		BudgetReasonRunDeadlineLimit:
		return true
	default:
		return false
	}
}

// LaneDeadline records the fully accumulated worst-case deadline for one
// normalized concurrency lane.
type LaneDeadline struct {
	concurrencyKey     ports.ConcurrencyKey
	invocationCount    int
	transitionCount    int
	invocationTimeouts time.Duration
	deadline           time.Duration
}

// ConcurrencyKey returns the immutable normalized lane key.
func (lane LaneDeadline) ConcurrencyKey() ports.ConcurrencyKey { return lane.concurrencyKey }

// InvocationCount returns the number of possible invocations assigned to lane.
func (lane LaneDeadline) InvocationCount() int { return lane.invocationCount }

// TransitionCount returns the number of possible repair or fallback transitions
// charged to lane.
func (lane LaneDeadline) TransitionCount() int { return lane.transitionCount }

// InvocationTimeouts returns the sum of all possible invocation timeouts.
func (lane LaneDeadline) InvocationTimeouts() time.Duration { return lane.invocationTimeouts }

// Deadline returns invocation timeouts plus two seconds per transition.
func (lane LaneDeadline) Deadline() time.Duration { return lane.deadline }

// RunBudgetReceipt is the immutable result of a pure assignment preflight.
// All slice getters return caller-owned copies in canonical order.
type RunBudgetReceipt struct {
	ceilings         HarnessCeilings
	roles            []RoleBudget
	lanes            []LaneDeadline
	totalInvocations int
	totalOutputCap   int64
	runDeadline      time.Duration
	eligible         bool
	reasonCode       BudgetReasonCode
}

// Ceilings returns the trusted ceilings used for this preflight.
func (receipt RunBudgetReceipt) Ceilings() HarnessCeilings { return receipt.ceilings }

// RoleBudgets returns copied role operands in fixed role order.
func (receipt RunBudgetReceipt) RoleBudgets() []RoleBudget {
	return append([]RoleBudget(nil), receipt.roles...)
}

// LaneDeadlines returns copied per-lane results in normalized key order.
func (receipt RunBudgetReceipt) LaneDeadlines() []LaneDeadline {
	return append([]LaneDeadline(nil), receipt.lanes...)
}

// TotalInvocations returns the count of every possible initial and repair
// invocation across primary and fallback routes.
func (receipt RunBudgetReceipt) TotalInvocations() int { return receipt.totalInvocations }

// TotalOutputCap returns the worst-case stdout-plus-stderr capture total.
func (receipt RunBudgetReceipt) TotalOutputCap() int64 { return receipt.totalOutputCap }

// RunDeadline returns max(lane deadlines) plus the fixed five-second run grace.
func (receipt RunBudgetReceipt) RunDeadline() time.Duration { return receipt.runDeadline }

// Eligible reports whether every closed resource constraint passed.
func (receipt RunBudgetReceipt) Eligible() bool { return receipt.eligible }

// ReasonCode returns the safe, closed preflight result code.
func (receipt RunBudgetReceipt) ReasonCode() BudgetReasonCode { return receipt.reasonCode }

// PreflightRunBudget evaluates every possible primary, repair, and configured
// fallback invocation without starting providers, scheduling work, or changing
// runtime state. Rejected inputs still return a receipt containing copied
// canonical operands and every safely computable result.
func PreflightRunBudget(roles []RoleBudget, ceilings HarnessCeilings) (RunBudgetReceipt, error) {
	receipt := RunBudgetReceipt{
		ceilings:   ceilings,
		roles:      canonicalRoleBudgets(roles),
		reasonCode: BudgetReasonEligible,
	}

	if !ceilings.Valid() {
		return rejectBudget(receipt, BudgetReasonInvalidCeilings)
	}
	if reason := validateRoleSelection(receipt.roles); reason != BudgetReasonEligible {
		return rejectBudget(receipt, reason)
	}

	lanes, totalInvocations, totalOutputCap, overflow := accumulateRunBudget(receipt.roles)
	receipt.lanes = lanes
	receipt.totalInvocations = totalInvocations
	receipt.totalOutputCap = totalOutputCap

	maxLaneDeadline := time.Duration(0)
	for _, lane := range receipt.lanes {
		if lane.deadline > maxLaneDeadline {
			maxLaneDeadline = lane.deadline
		}
	}
	var runDeadlineOverflow bool
	receipt.runDeadline, runDeadlineOverflow = addDuration(maxLaneDeadline, budgetRunGrace)
	if overflow {
		return rejectBudget(receipt, BudgetReasonInvocationCapExceeded)
	}

	if reason := validateRouteCaps(receipt.roles, ceilings); reason != BudgetReasonEligible {
		return rejectBudget(receipt, reason)
	}
	if totalInvocations > ceilings.maxInvocationsPerRun {
		return rejectBudget(receipt, BudgetReasonRunInvocationLimit)
	}
	if totalOutputCap > ceilings.maxTotalOutput {
		return rejectBudget(receipt, BudgetReasonTotalOutputLimit)
	}
	for _, lane := range receipt.lanes {
		if lane.deadline > ceilings.maxLaneDeadline {
			return rejectBudget(receipt, BudgetReasonLaneDeadlineLimit)
		}
	}
	if runDeadlineOverflow || receipt.runDeadline > ceilings.maxRunDeadline {
		return rejectBudget(receipt, BudgetReasonRunDeadlineLimit)
	}

	receipt.eligible = true
	return receipt, nil
}

func validateInvocationLimits(limits InvocationLimits) error {
	if limits.timeout <= 0 {
		return fmt.Errorf("review run budget: timeout must be positive")
	}
	if limits.maxStdoutBytes <= 0 {
		return fmt.Errorf("review run budget: stdout cap must be positive")
	}
	if limits.maxStderrBytes <= 0 {
		return fmt.Errorf("review run budget: stderr cap must be positive")
	}
	return nil
}

func validateRouteBudget(budget RouteBudget) error {
	if !budget.route.Valid() {
		return fmt.Errorf("review run budget: provider route is invalid")
	}
	if err := validateInvocationLimits(budget.limits); err != nil {
		return err
	}
	return nil
}

func validateRoleBudget(budget RoleBudget) error {
	if !budget.role.Valid() {
		return fmt.Errorf("review run budget: invalid role %q", budget.role)
	}
	if err := validateRouteBudget(budget.primary); err != nil {
		return fmt.Errorf("review run budget: primary: %w", err)
	}
	if !budget.hasFallback {
		return nil
	}
	if err := validateRouteBudget(budget.fallback); err != nil {
		return fmt.Errorf("review run budget: fallback: %w", err)
	}
	if budget.primary.route.ProviderInstance() == budget.fallback.route.ProviderInstance() {
		return fmt.Errorf("review run budget: fallback provider must differ from primary")
	}
	return nil
}

func validateHarnessCeilings(ceilings HarnessCeilings) error {
	switch {
	case ceilings.maxTimeout <= 0:
		return fmt.Errorf("review run budget: maximum timeout must be positive")
	case ceilings.maxStdoutBytes <= 0:
		return fmt.Errorf("review run budget: maximum stdout cap must be positive")
	case ceilings.maxStderrBytes <= 0:
		return fmt.Errorf("review run budget: maximum stderr cap must be positive")
	case ceilings.maxTotalOutput <= 0:
		return fmt.Errorf("review run budget: maximum total output must be positive")
	case ceilings.maxLaneDeadline <= 0:
		return fmt.Errorf("review run budget: maximum lane deadline must be positive")
	case ceilings.maxRunDeadline <= 0:
		return fmt.Errorf("review run budget: maximum run deadline must be positive")
	case ceilings.maxInvocationsPerRole <= 0:
		return fmt.Errorf("review run budget: maximum role invocations must be positive")
	case ceilings.maxInvocationsPerRun <= 0:
		return fmt.Errorf("review run budget: maximum run invocations must be positive")
	case ceilings.maxInvocationsPerRole > maxBudgetInvocationsPerRole:
		return fmt.Errorf("review run budget: maximum role invocations exceed %d", maxBudgetInvocationsPerRole)
	case ceilings.maxInvocationsPerRun > maxBudgetInvocationsPerRun:
		return fmt.Errorf("review run budget: maximum run invocations exceed %d", maxBudgetInvocationsPerRun)
	case ceilings.maxTotalOutput > maxBudgetTotalOutputBytes:
		return fmt.Errorf("review run budget: maximum total output exceeds %d", maxBudgetTotalOutputBytes)
	case ceilings.maxRunDeadline > maxBudgetRunDeadline:
		return fmt.Errorf("review run budget: maximum run deadline exceeds %s", maxBudgetRunDeadline)
	case ceilings.maxLaneDeadline > maxBudgetRunDeadline:
		return fmt.Errorf("review run budget: maximum lane deadline exceeds %s", maxBudgetRunDeadline)
	}
	return nil
}

func canonicalRoleBudgets(roles []RoleBudget) []RoleBudget {
	canonical := append([]RoleBudget(nil), roles...)
	sort.Slice(canonical, func(left, right int) bool {
		return compareRoleBudgets(canonical[left], canonical[right]) < 0
	})
	return canonical
}

func compareRoleBudgets(left, right RoleBudget) int {
	if leftRank, rightRank := roleRank(left.role), roleRank(right.role); leftRank != rightRank {
		return leftRank - rightRank
	}
	if compared := compareRouteBudgets(left.primary, right.primary); compared != 0 {
		return compared
	}
	if left.hasFallback != right.hasFallback {
		if !left.hasFallback {
			return -1
		}
		return 1
	}
	return compareRouteBudgets(left.fallback, right.fallback)
}

func compareRouteBudgets(left, right RouteBudget) int {
	if compared := compareStrings(left.route.ProviderInstance(), right.route.ProviderInstance()); compared != 0 {
		return compared
	}
	if compared := compareStrings(left.route.ConcurrencyKey().String(), right.route.ConcurrencyKey().String()); compared != 0 {
		return compared
	}
	if left.limits.timeout != right.limits.timeout {
		if left.limits.timeout < right.limits.timeout {
			return -1
		}
		return 1
	}
	if left.limits.maxStdoutBytes != right.limits.maxStdoutBytes {
		if left.limits.maxStdoutBytes < right.limits.maxStdoutBytes {
			return -1
		}
		return 1
	}
	if left.limits.maxStderrBytes < right.limits.maxStderrBytes {
		return -1
	}
	if left.limits.maxStderrBytes > right.limits.maxStderrBytes {
		return 1
	}
	return 0
}

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func roleRank(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if role == candidate {
			return index
		}
	}
	return len(domain.FixedRoleOrder())
}

func validateRoleSelection(roles []RoleBudget) BudgetReasonCode {
	counts := make(map[domain.Role]int, len(roles))
	for _, budget := range roles {
		if !budget.role.Valid() {
			return BudgetReasonInvalidRole
		}
		counts[budget.role]++
	}
	for _, role := range domain.FixedRoleOrder() {
		if counts[role] > 1 {
			return BudgetReasonDuplicateRole
		}
	}
	for _, role := range domain.FixedRoleOrder() {
		if role.RequiredFloor() && counts[role] == 0 {
			return BudgetReasonMissingRequiredRole
		}
	}
	for _, role := range domain.FixedRoleOrder() {
		if counts[role] == 0 {
			return BudgetReasonMissingRole
		}
	}
	for _, budget := range roles {
		if !budget.primary.route.Valid() || !budget.primary.limits.Valid() {
			return BudgetReasonInvalidPrimaryRoute
		}
		if !budget.hasFallback {
			continue
		}
		if !budget.fallback.route.Valid() || !budget.fallback.limits.Valid() {
			return BudgetReasonInvalidFallbackRoute
		}
		if budget.primary.route.ProviderInstance() == budget.fallback.route.ProviderInstance() {
			return BudgetReasonDuplicateRoleRoute
		}
	}
	return BudgetReasonEligible
}

func accumulateRunBudget(roles []RoleBudget) ([]LaneDeadline, int, int64, bool) {
	lanes := make(map[string]LaneDeadline, len(roles)*2)
	totalInvocations := 0
	totalOutputCap := int64(0)
	overflow := false
	for _, budget := range roles {
		overflow = addRouteBudget(lanes, budget.primary, 2, 1, &totalInvocations, &totalOutputCap) || overflow
		if budget.hasFallback {
			overflow = addRouteBudget(lanes, budget.primary, 0, 1, &totalInvocations, &totalOutputCap) || overflow
			overflow = addRouteBudget(lanes, budget.fallback, 2, 1, &totalInvocations, &totalOutputCap) || overflow
		}
	}

	canonical := make([]LaneDeadline, 0, len(lanes))
	for _, lane := range lanes {
		var overflowed bool
		lane.deadline, overflowed = addDuration(lane.invocationTimeouts, time.Duration(lane.transitionCount)*budgetTransitionGrace)
		overflow = overflow || overflowed
		canonical = append(canonical, lane)
	}
	sort.Slice(canonical, func(left, right int) bool {
		return canonical[left].concurrencyKey.String() < canonical[right].concurrencyKey.String()
	})
	return canonical, totalInvocations, totalOutputCap, overflow
}

func addRouteBudget(
	lanes map[string]LaneDeadline,
	budget RouteBudget,
	invocations, transitions int,
	totalInvocations *int,
	totalOutputCap *int64,
) bool {
	key := budget.route.ConcurrencyKey()
	lane := lanes[key.String()]
	if !lane.concurrencyKey.Valid() {
		lane.concurrencyKey = key
	}
	overflow := false
	for range invocations {
		var overflowed bool
		lane.invocationTimeouts, overflowed = addDuration(lane.invocationTimeouts, budget.limits.timeout)
		overflow = overflow || overflowed
		lane.invocationCount++
		(*totalInvocations)++

		outputCap, outputOverflow := addInt64(budget.limits.maxStdoutBytes, budget.limits.maxStderrBytes)
		overflow = overflow || outputOverflow
		*totalOutputCap, outputOverflow = addInt64(*totalOutputCap, outputCap)
		overflow = overflow || outputOverflow
	}
	lane.transitionCount += transitions
	lanes[key.String()] = lane
	return overflow
}

func addDuration(left, right time.Duration) (time.Duration, bool) {
	if right > 0 && left > time.Duration(math.MaxInt64)-right {
		return time.Duration(math.MaxInt64), true
	}
	return left + right, false
}

func addInt64(left, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right {
		return math.MaxInt64, true
	}
	return left + right, false
}

func validateRouteCaps(roles []RoleBudget, ceilings HarnessCeilings) BudgetReasonCode {
	for _, budget := range roles {
		if routeCapsExceed(budget.primary, ceilings) {
			return BudgetReasonInvocationCapExceeded
		}
		if budget.hasFallback && routeCapsExceed(budget.fallback, ceilings) {
			return BudgetReasonInvocationCapExceeded
		}
		invocations := 2
		if budget.hasFallback {
			invocations += 2
		}
		if invocations > ceilings.maxInvocationsPerRole {
			return BudgetReasonRoleInvocationLimit
		}
	}
	return BudgetReasonEligible
}

func routeCapsExceed(budget RouteBudget, ceilings HarnessCeilings) bool {
	return budget.limits.timeout > ceilings.maxTimeout ||
		budget.limits.maxStdoutBytes > ceilings.maxStdoutBytes ||
		budget.limits.maxStderrBytes > ceilings.maxStderrBytes
}

func rejectBudget(receipt RunBudgetReceipt, reason BudgetReasonCode) (RunBudgetReceipt, error) {
	receipt.eligible = false
	receipt.reasonCode = reason
	return receipt, fmt.Errorf("review run budget: %w: %s", domain.ErrInvariant, reason)
}
