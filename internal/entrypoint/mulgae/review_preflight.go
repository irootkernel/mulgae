package mulgae

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/query"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const reviewPreflightSchemaVersion = "mulgae-review-preflight.v8"

// ReviewPreflightService admits original-source selection without invoking
// providers or creating execution or publication state. Selected artist inputs
// are read for validation; ordinary preflight only lists native source reads.
type ReviewPreflightService interface {
	PreflightReview(context.Context, ReviewRequest, ports.AnchoredRoot) (ReviewPreflightResult, error)
}

// ReviewPreflightResult describes the current selection and configured routes.
// Its source identity binds selection metadata, not mutable file contents.
type ReviewPreflightResult struct {
	SchemaVersion        string                         `json:"schema_version"`
	Capabilities         query.VerifiedReadCapabilities `json:"capabilities"`
	ProjectBinding       string                         `json:"project_binding"`
	ConfigurationSHA256  string                         `json:"configuration_sha256"`
	SourceIdentitySHA256 string                         `json:"source_identity_sha256"`
	Target               json.RawMessage                `json:"target"`
	CandidateCount       int                            `json:"candidate_count"`
	Status               string                         `json:"status"`
	Qualification        string                         `json:"qualification"`
	Warnings             []string                       `json:"warnings"`
	ReadPlan             []ReviewPreflightRead          `json:"read_plan"`
	Transmissions        []ReviewPreflightTransmission  `json:"transmissions"`
	Budget               ReviewPreflightBudget          `json:"budget"`
}

type ReviewPreflightRead struct {
	Side domain.LiveSourceSide `json:"side"`
	Path string                `json:"path"`
}

type ReviewPreflightTransmission struct {
	Role              string `json:"role"`
	RouteKind         string `json:"route_kind"`
	ProviderInstance  string `json:"provider_instance"`
	ProviderFamily    string `json:"provider_family"`
	ConfiguredTimeout string `json:"configured_timeout"`
	PermissionMode    string `json:"permission_mode"`
	TargetChannel     string `json:"target_channel"`
}

type ReviewPreflightBudget struct {
	Eligible             bool                      `json:"eligible"`
	ReasonCode           string                    `json:"reason_code"`
	MaxActiveLanes       int                       `json:"max_active_lanes"`
	TotalInvocations     int                       `json:"total_invocations"`
	CriticalPathDeadline string                    `json:"critical_path_deadline"`
	RunDeadline          string                    `json:"run_deadline"`
	Ceilings             ReviewPreflightCeilings   `json:"ceilings"`
	RolePaths            []ReviewPreflightRolePath `json:"role_paths"`
}

type ReviewPreflightCeilings struct {
	ProviderTimeout       string `json:"provider_timeout"`
	RolePathDeadline      string `json:"role_path_deadline"`
	RunDeadline           string `json:"run_deadline"`
	MaxInvocationsPerRole int    `json:"max_invocations_per_role"`
	MaxInvocationsPerRun  int    `json:"max_invocations_per_run"`
}

type ReviewPreflightRolePath struct {
	Role               string `json:"role"`
	ProviderInstance   string `json:"provider_instance"`
	InvocationCount    int    `json:"invocation_count"`
	TransitionCount    int    `json:"transition_count"`
	InvocationTimeouts string `json:"invocation_timeouts"`
	Deadline           string `json:"deadline"`
}

type reviewPreflightValidationFailure struct{ code, invariant string }

func (failure *reviewPreflightValidationFailure) Error() string {
	return "review preflight projection violated an internal invariant"
}

func NewLiveReviewPreflightResult(target ports.LiveSourceTarget, binding domain.ProjectBinding, configurationSHA256 string, reads []ports.LiveSourceRead, plan reviewrun.ExecutionPlan, budget review.RunBudgetReceipt) (ReviewPreflightResult, error) {
	source, err := evidence.NewLiveSourceIdentity(target)
	if err != nil || binding.String() == "" && target.Selector().Scope() != domain.LiveSourceWorkspace || !budget.Eligible() || len(plan.Assignments) != len(plan.Budgets) {
		return ReviewPreflightResult{}, fmt.Errorf("live preflight: invalid admitted plan")
	}
	result := ReviewPreflightResult{SchemaVersion: reviewPreflightSchemaVersion,
		Capabilities:   query.VerifiedReadCapabilities{ProjectBinding: "v1", LiveSource: "v1"},
		ProjectBinding: binding.String(), ConfigurationSHA256: configurationSHA256,
		SourceIdentitySHA256: source.SHA256(), Target: source.Bytes(), CandidateCount: len(target.Changes()),
		Status: "eligible", Qualification: "not_run", Warnings: []string{},
		ReadPlan: make([]ReviewPreflightRead, 0, len(reads)), Transmissions: []ReviewPreflightTransmission{},
	}
	if binding.String() == "" {
		result.Capabilities.ProjectBinding = ""
	}
	for _, read := range reads {
		result.ReadPlan = append(result.ReadPlan, ReviewPreflightRead{Side: read.Side(), Path: read.Path().String()})
	}
	ceilings := budget.Ceilings()
	result.Budget = ReviewPreflightBudget{Eligible: true, ReasonCode: string(budget.ReasonCode()), MaxActiveLanes: budget.MaxActiveLanes(), TotalInvocations: budget.TotalInvocations(), CriticalPathDeadline: budget.CriticalPathDeadline().String(), RunDeadline: budget.RunDeadline().String(),
		Ceilings: ReviewPreflightCeilings{ProviderTimeout: appconfig.ProviderTimeoutText(ceilings.MaxTimeout()), RolePathDeadline: ceilings.MaxRolePathDeadline().String(), RunDeadline: ceilings.MaxRunDeadline().String(), MaxInvocationsPerRole: ceilings.MaxInvocationsPerRole(), MaxInvocationsPerRun: ceilings.MaxInvocationsPerRun()}, RolePaths: []ReviewPreflightRolePath{},
	}
	if target.NoChange() {
		result.Status = "no_change"
		result.Budget.ReasonCode, result.Budget.MaxActiveLanes, result.Budget.TotalInvocations = "no_change", 0, 0
		result.Budget.CriticalPathDeadline, result.Budget.RunDeadline = "0s", "0s"
	} else {
		for index, assignment := range plan.Assignments {
			route := plan.Budgets[index].Primary()
			instance := route.Route().ProviderInstance()
			result.Transmissions = append(result.Transmissions, ReviewPreflightTransmission{Role: string(assignment.Role()), RouteKind: "primary", ProviderInstance: instance, ProviderFamily: strings.SplitN(instance, "-", 2)[0], ConfiguredTimeout: appconfig.ProviderTimeoutText(route.Limits().Timeout()), PermissionMode: "read_only", TargetChannel: "native_source"})
		}
		for _, path := range budget.RolePathDeadlines() {
			result.Budget.RolePaths = append(result.Budget.RolePaths, ReviewPreflightRolePath{Role: string(path.Role()), ProviderInstance: path.ProviderInstance(), InvocationCount: path.InvocationCount(), TransitionCount: path.TransitionCount(), InvocationTimeouts: path.InvocationTimeouts().String(), Deadline: path.Deadline().String()})
		}
	}
	return result, result.Validate()
}

// Validate checks selection, native read sides, and the independently rebuilt
// route budget before exposing a successful projection.
func (result ReviewPreflightResult) Validate() (err error) {
	defer func() {
		if err != nil {
			err = &reviewPreflightValidationFailure{code: "preflight_result_validation_failed", invariant: "result_projection"}
		}
	}()
	if result.SchemaVersion != reviewPreflightSchemaVersion || result.Qualification != "not_run" || (result.Status != "eligible" && result.Status != "no_change") || result.CandidateCount < 0 || !result.Budget.Eligible || len(result.Warnings) != 0 {
		return fmt.Errorf("live preflight: invalid result")
	}
	if err := result.Capabilities.Validate(); err != nil {
		return err
	}
	if result.Capabilities.LiveSource != "v1" || (result.Capabilities.ProjectBinding == "v1") != (result.ProjectBinding != "") || result.Capabilities.ExecutionGuard != "" || result.Capabilities.CaptureIdentity != "" {
		return fmt.Errorf("live preflight: invalid capabilities")
	}
	if result.ProjectBinding != "" {
		if _, err := domain.ParseProjectBinding(result.ProjectBinding); err != nil {
			return err
		}
	}
	if !preflightSHA256(result.ConfigurationSHA256) {
		return fmt.Errorf("live preflight: invalid configuration identity")
	}
	var canonical bytes.Buffer
	if err := json.Compact(&canonical, result.Target); err != nil {
		return err
	}
	source, err := evidence.DecodeLiveSourceIdentity(canonical.Bytes())
	if err != nil || source.SHA256() != result.SourceIdentitySHA256 {
		return fmt.Errorf("live preflight: invalid source identity")
	}
	if result.ProjectBinding == "" && source.Target().Selector().Scope() != domain.LiveSourceWorkspace {
		return fmt.Errorf("live preflight: Git source has no project binding")
	}
	previousSide, previousPath := domain.LiveSourceSide(""), ""
	seenSides := map[domain.LiveSourceSide]bool{}
	for _, read := range result.ReadPlan {
		if _, err := ports.NewSafeRelativePath(read.Path); err != nil {
			return err
		}
		validSide := false
		switch source.Target().Selector().Scope() {
		case domain.LiveSourceWorkspace:
			validSide = read.Side == domain.LiveSourceWorktree
		case domain.LiveSourceStage:
			validSide = read.Side == domain.LiveSourceIndex || !source.Target().EmptyBase() && read.Side == domain.LiveSourceBefore
		case domain.LiveSourceHead:
			validSide = read.Side == domain.LiveSourceAfter
		default:
			validSide = read.Side == domain.LiveSourceAfter || !source.Target().EmptyBase() && read.Side == domain.LiveSourceBefore
		}
		if !validSide {
			return fmt.Errorf("live preflight: invalid read side")
		}
		if previousSide != read.Side {
			if seenSides[read.Side] || read.Side == domain.LiveSourceBefore && previousSide != "" {
				return fmt.Errorf("live preflight: invalid read order")
			}
			seenSides[read.Side] = true
			previousPath = ""
		}
		if read.Path <= previousPath {
			return fmt.Errorf("live preflight: duplicate or unordered source path")
		}
		previousSide, previousPath = read.Side, read.Path
	}
	if err := validatePreflightBudget(result.Budget, result.Status); err != nil {
		return err
	}
	if result.Status == "no_change" {
		if result.CandidateCount != 0 || len(result.Transmissions) != 0 || result.Budget.CriticalPathDeadline != "0s" || result.Budget.RunDeadline != "0s" {
			return fmt.Errorf("live preflight: invalid no-change projection")
		}
		return nil
	}
	if result.CandidateCount == 0 || len(result.Transmissions) == 0 {
		return fmt.Errorf("live preflight: missing candidate or route")
	}
	lastRole := -1
	for _, transmission := range result.Transmissions {
		role, family := domain.Role(transmission.Role), reviewrun.Family(transmission.ProviderFamily)
		ordinal := preflightRoleOrdinal(role)
		if ordinal < 0 || ordinal <= lastRole || transmission.RouteKind != "primary" || !reviewrun.RoleProviderInstanceMatches(family, role, transmission.ProviderInstance) || transmission.TargetChannel != "native_source" || transmission.PermissionMode != "read_only" || !activePreflightFamily(family) {
			return fmt.Errorf("live preflight: invalid native route")
		}
		if _, err := appconfig.ParseProviderTimeout(transmission.ConfiguredTimeout); err != nil {
			return err
		}
		lastRole = ordinal
	}
	return validatePreflightBudgetProjection(result.Transmissions, result.Budget)
}

func validatePreflightBudgetProjection(transmissions []ReviewPreflightTransmission, projected ReviewPreflightBudget) error {
	roleBudgets := make([]review.RoleBudget, 0, len(transmissions))
	for _, transmission := range transmissions {
		primary, err := preflightRouteBudget(transmission)
		if err != nil || transmission.RouteKind != "primary" {
			return fmt.Errorf("review preflight: invalid primary budget")
		}
		roleBudget, err := review.NewRoleBudget(domain.Role(transmission.Role), primary)
		if err != nil {
			return fmt.Errorf("review preflight: invalid role budget")
		}
		roleBudgets = append(roleBudgets, roleBudget)
	}
	providerTimeout, err := appconfig.ParseProviderTimeout(projected.Ceilings.ProviderTimeout)
	if err != nil {
		return fmt.Errorf("review preflight: invalid provider ceiling")
	}
	rolePathDeadline, err := time.ParseDuration(projected.Ceilings.RolePathDeadline)
	if err != nil {
		return fmt.Errorf("review preflight: invalid role path ceiling")
	}
	runDeadline, err := time.ParseDuration(projected.Ceilings.RunDeadline)
	if err != nil {
		return fmt.Errorf("review preflight: invalid run ceiling")
	}
	ceilings, err := review.NewHarnessCeilings(
		providerTimeout, rolePathDeadline, runDeadline,
		projected.Ceilings.MaxInvocationsPerRole, projected.Ceilings.MaxInvocationsPerRun,
	)
	if err != nil {
		return fmt.Errorf("review preflight: invalid reconstructed ceilings: %w", err)
	}
	receipt, err := review.PreflightRunBudgetWithCapacity(roleBudgets, ceilings, projected.MaxActiveLanes)
	if err != nil || !receipt.Eligible() {
		return fmt.Errorf("review preflight: invalid reconstructed budget")
	}
	if projected.ReasonCode != string(receipt.ReasonCode()) || projected.TotalInvocations != receipt.TotalInvocations() ||
		projected.CriticalPathDeadline != receipt.CriticalPathDeadline().String() ||
		projected.RunDeadline != receipt.RunDeadline().String() {
		return fmt.Errorf("review preflight: budget projection mismatch")
	}
	paths := receipt.RolePathDeadlines()
	if len(paths) != len(projected.RolePaths) {
		return fmt.Errorf("review preflight: role path projection mismatch")
	}
	for index, path := range paths {
		row := projected.RolePaths[index]
		if row.Role != string(path.Role()) || row.ProviderInstance != path.ProviderInstance() || row.InvocationCount != path.InvocationCount() ||
			row.TransitionCount != path.TransitionCount() || row.InvocationTimeouts != path.InvocationTimeouts().String() || row.Deadline != path.Deadline().String() {
			return fmt.Errorf("review preflight: role path projection mismatch: got %#v want %s/%s/%d/%d/%s/%s", row, path.Role(), path.ProviderInstance(), path.InvocationCount(), path.TransitionCount(), path.InvocationTimeouts(), path.Deadline())
		}
	}
	return nil
}

func preflightRouteBudget(transmission ReviewPreflightTransmission) (review.RouteBudget, error) {
	route, err := ports.NewProviderRoute(transmission.ProviderInstance)
	if err != nil {
		return review.RouteBudget{}, err
	}
	timeout, err := appconfig.ParseProviderTimeout(transmission.ConfiguredTimeout)
	if err != nil {
		return review.RouteBudget{}, err
	}
	limits, err := review.NewInvocationLimits(timeout)
	if err != nil {
		return review.RouteBudget{}, err
	}
	return review.NewRouteBudget(route, limits)
}

func validatePreflightBudget(budget ReviewPreflightBudget, status string) error {
	for _, value := range []string{budget.CriticalPathDeadline, budget.RunDeadline, budget.Ceilings.RolePathDeadline, budget.Ceilings.RunDeadline} {
		if duration, err := time.ParseDuration(value); err != nil || duration < 0 {
			return fmt.Errorf("review preflight: invalid budget duration")
		}
	}
	if _, err := appconfig.ParseProviderTimeout(budget.Ceilings.ProviderTimeout); err != nil {
		return fmt.Errorf("review preflight: invalid provider ceiling")
	}
	if budget.Ceilings.MaxInvocationsPerRole < 1 || budget.Ceilings.MaxInvocationsPerRun < 1 {
		return fmt.Errorf("review preflight: invalid ceilings")
	}
	if status == "no_change" {
		if budget.ReasonCode != "no_change" || budget.MaxActiveLanes != 0 || budget.TotalInvocations != 0 || len(budget.RolePaths) != 0 {
			return fmt.Errorf("review preflight: invalid no-change budget")
		}
		return nil
	}
	if budget.ReasonCode != string(review.BudgetReasonEligible) || budget.MaxActiveLanes < 1 || budget.TotalInvocations < 1 {
		return fmt.Errorf("review preflight: invalid eligible budget")
	}
	if len(budget.RolePaths) > len(domain.FixedRoleOrder()) {
		return fmt.Errorf("review preflight: too many role paths")
	}
	previousRole := -1
	seenRoles := make(map[string]struct{}, len(budget.RolePaths))
	for _, path := range budget.RolePaths {
		ordinal := preflightRoleOrdinal(domain.Role(path.Role))
		if ordinal <= previousRole || path.ProviderInstance == "" || path.InvocationCount < 1 || path.InvocationCount > 2 || path.TransitionCount < 0 || path.TransitionCount > 1 {
			return fmt.Errorf("review preflight: invalid role path")
		}
		if _, duplicate := seenRoles[path.Role]; duplicate {
			return fmt.Errorf("review preflight: duplicate role path")
		}
		seenRoles[path.Role] = struct{}{}
		for _, value := range []string{path.InvocationTimeouts, path.Deadline} {
			if duration, err := time.ParseDuration(value); err != nil || duration <= 0 {
				return fmt.Errorf("review preflight: invalid role path duration")
			}
		}
		previousRole = ordinal
	}
	return nil
}

func preflightSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func preflightRoleOrdinal(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if role == candidate {
			return index
		}
	}
	return -1
}

func activePreflightFamily(family reviewrun.Family) bool {
	for _, candidate := range reviewrun.Families() {
		if family == candidate {
			return true
		}
	}
	return false
}

func renderReviewPreflightHuman(result ReviewPreflightResult) []byte {
	var output strings.Builder
	binding := result.ProjectBinding
	if binding == "" {
		binding = "unavailable (non-Git workspace)"
	}
	fmt.Fprintf(&output, "review preflight: %s\nqualification: %s\nproject binding: %s\nsource identity: %s\nselection: %s\ncandidates: %d\n", result.Status, result.Qualification, binding, result.SourceIdentitySHA256, result.Target, result.CandidateCount)
	for _, read := range result.ReadPlan {
		fmt.Fprintf(&output, "read: %s %s\n", read.Side, read.Path)
	}
	for _, route := range result.Transmissions {
		fmt.Fprintf(&output, "route: %s %s timeout=%s permission=%s target_channel=%s\n", route.Role, route.ProviderInstance, route.ConfiguredTimeout, route.PermissionMode, route.TargetChannel)
	}
	fmt.Fprintf(&output, "budget: %s invocations=%d run_deadline=%s max_active_lanes=%d", result.Budget.ReasonCode, result.Budget.TotalInvocations, result.Budget.RunDeadline, result.Budget.MaxActiveLanes)
	return []byte(output.String())
}

func reviewPreflightFailureJSON() []byte {
	bytes, _ := json.Marshal(struct {
		Kind          string `json:"kind"`
		SchemaVersion string `json:"schema_version"`
		Eligible      bool   `json:"eligible"`
	}{"review_preflight_failed", reviewPreflightSchemaVersion, false})
	return bytes
}

func reviewPreflightSuccessJSON(result ReviewPreflightResult) ([]byte, error) {
	return json.Marshal(struct {
		Kind      string                `json:"kind"`
		Preflight ReviewPreflightResult `json:"preflight"`
	}{"review_preflight", result})
}
