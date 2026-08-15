package mulgae

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appconfig "github.com/irootkernel/mulgae/internal/app/config"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const reviewPreflightSchemaVersion = "mulgae-review-preflight.v3"

// ReviewPreflightService projects the exact capture and configured execution
// envelope without provider discovery, qualification, invocation, or durable
// publication.
type ReviewPreflightService interface {
	PreflightReview(context.Context, ReviewRequest, ports.AnchoredRoot) (ReviewPreflightResult, error)
}

// ReviewPreflightResult is the schema-facing, deterministic execution-free
// review projection. Every slice is owned by the result.
type ReviewPreflightResult struct {
	SchemaVersion     string                         `json:"schema_version"`
	Status            string                         `json:"status"`
	Qualification     string                         `json:"qualification"`
	Target            ReviewPreflightTarget          `json:"target"`
	AGYPermissionMode string                         `json:"agy_permission_mode"`
	Warnings          []string                       `json:"warnings"`
	FileSets          []ReviewPreflightFileSet       `json:"file_sets"`
	GeneratedFiles    []ReviewPreflightGeneratedFile `json:"generated_files"`
	Transmissions     []ReviewPreflightTransmission  `json:"transmissions"`
	Budget            ReviewPreflightBudget          `json:"budget"`
}

type ReviewPreflightTarget struct {
	RequestedKind string `json:"requested_kind"`
	CapturedKind  string `json:"captured_kind"`
	GitMode       string `json:"git_mode"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
}

type ReviewPreflightFileSet struct {
	ID             string                `json:"id"`
	PolicyIdentity string                `json:"policy_identity"`
	Files          []ReviewPreflightFile `json:"files"`
}

type ReviewPreflightFile struct {
	Path        string `json:"path"`
	MediaType   string `json:"media_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Disposition string `json:"disposition"`
}

type ReviewPreflightGeneratedFile struct {
	Path        string `json:"path"`
	MediaType   string `json:"media_type"`
	Disposition string `json:"disposition"`
}

type ReviewPreflightTransmission struct {
	Role              string `json:"role"`
	RouteKind         string `json:"route_kind"`
	ProviderInstance  string `json:"provider_instance"`
	ProviderFamily    string `json:"provider_family"`
	ConfiguredTimeout string `json:"configured_timeout"`
	PermissionMode    string `json:"permission_mode"`
	TargetChannel     string `json:"target_channel"`
	FileSetID         string `json:"file_set_id"`
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

type reviewPreflightValidationFailure struct {
	code          string
	invariant     string
	fileCount     int
	byteCount     int64
	maxFiles      int
	maxBytes      int64
	hasLimitFacts bool
}

func (failure *reviewPreflightValidationFailure) Error() string {
	return "review preflight projection violated an internal invariant"
}

func newReviewPreflightValidationFailure(invariant string) error {
	return &reviewPreflightValidationFailure{
		code:      "preflight_result_validation_failed",
		invariant: invariant,
	}
}

func newReviewPreflightLimitValidationFailure(policyIdentity string, fileCount int, byteCount int64, maxFiles int, maxBytes int64) error {
	code := "preflight_result_validation_failed"
	invariant := "snapshot_resource_limit"
	if strings.HasSuffix(policyIdentity, ";layout=ordinary-directories-v1") {
		code = "provider_view_limit_validation_failed"
		invariant = "provider_view_resource_limit"
	}
	return &reviewPreflightValidationFailure{
		code: code, invariant: invariant, fileCount: fileCount, byteCount: byteCount,
		maxFiles: maxFiles, maxBytes: maxBytes, hasLimitFacts: true,
	}
}

// NewReviewPreflightResult converts the already-captured snapshot and the
// authoritative pure budget receipt into the stable external projection.
func NewReviewPreflightResult(
	material ports.CapturedReviewMaterial,
	workspaceReceipt ports.WorkspaceSnapshotReceipt,
	requestedKind string,
	plan reviewrun.ExecutionPlan,
	budgetReceipt review.RunBudgetReceipt,
	agyPermissionMode string,
) (ReviewPreflightResult, error) {
	if !material.Valid() || !workspaceReceipt.Valid() || !budgetReceipt.Eligible() || requestedKind == "" || len(plan.Assignments) == 0 || len(plan.Budgets) != len(plan.Assignments) {
		return ReviewPreflightResult{}, fmt.Errorf("review preflight: invalid captured plan")
	}
	providerWorkspace, err := material.ProviderWorkspace()
	if err != nil {
		return ReviewPreflightResult{}, fmt.Errorf("review preflight: provider workspace: %w", err)
	}
	if err := validatePreflightSnapshotBinding(providerWorkspace, workspaceReceipt); err != nil {
		return ReviewPreflightResult{}, err
	}
	if agyPermissionMode != appconfig.SafeAGYPermissionMode && agyPermissionMode != appconfig.HeadlessAGYPermissionMode {
		return ReviewPreflightResult{}, fmt.Errorf("review preflight: invalid AGY permission mode")
	}
	files := workspaceReceipt.Files()
	fileRows := make([]ReviewPreflightFile, 0, len(files))
	for _, file := range files {
		disposition := "text"
		if !file.IsText() {
			disposition = "binary_preserved"
		}
		fileRows = append(fileRows, ReviewPreflightFile{
			Path: file.Path().String(), MediaType: file.MediaType(), Size: int64(len(file.Bytes())),
			SHA256: file.SHA256(), Disposition: disposition,
		})
	}
	fileSetID, err := reviewPreflightFileSetID(workspaceReceipt.PolicyIdentity(), fileRows)
	if err != nil {
		return ReviewPreflightResult{}, err
	}
	transmissions := make([]ReviewPreflightTransmission, 0, len(plan.Assignments))
	if !material.Target().NoChange() {
		for index, assignment := range plan.Assignments {
			transmissions = append(transmissions, preflightTransmission(
				assignment.Role(), "primary", plan.Budgets[index].Primary(), agyPermissionMode, fileSetID,
			))
		}
	}
	ceilings := budgetReceipt.Ceilings()
	paths := budgetReceipt.RolePathDeadlines()
	pathRows := make([]ReviewPreflightRolePath, len(paths))
	for index, path := range paths {
		pathRows[index] = ReviewPreflightRolePath{
			Role: string(path.Role()), ProviderInstance: path.ProviderInstance(), InvocationCount: path.InvocationCount(),
			TransitionCount: path.TransitionCount(), InvocationTimeouts: path.InvocationTimeouts().String(),
			Deadline: path.Deadline().String(),
		}
	}
	warnings := []string{}
	if agyPermissionMode == appconfig.HeadlessAGYPermissionMode {
		warnings = append(warnings, "AGY dangerously-skip-permissions is opt-in and may approve write or shell tool requests outside Mulgae's read-oriented boundary.")
	}
	targetBytes := material.Target().Bytes()
	status := "eligible"
	reasonCode := string(budgetReceipt.ReasonCode())
	maxActiveLanes, totalInvocations := budgetReceipt.MaxActiveLanes(), budgetReceipt.TotalInvocations()
	criticalPath, runDeadline := budgetReceipt.CriticalPathDeadline().String(), budgetReceipt.RunDeadline().String()
	if material.Target().NoChange() {
		status, reasonCode = "no_change", "no_change"
		maxActiveLanes, totalInvocations = 0, 0
		criticalPath, runDeadline, pathRows = "0s", "0s", []ReviewPreflightRolePath{}
	}
	result := ReviewPreflightResult{
		SchemaVersion: reviewPreflightSchemaVersion,
		Status:        status,
		Qualification: "not_run",
		Target: ReviewPreflightTarget{
			RequestedKind: requestedKind, CapturedKind: string(material.Target().Kind()), GitMode: string(material.Target().Identity().GitMode()),
			SHA256: "sha256:" + material.Target().Identity().SHA256(), Size: int64(len(targetBytes)),
		},
		AGYPermissionMode: agyPermissionMode,
		Warnings:          warnings,
		FileSets: []ReviewPreflightFileSet{{
			ID: fileSetID, PolicyIdentity: workspaceReceipt.PolicyIdentity(), Files: fileRows,
		}},
		GeneratedFiles: []ReviewPreflightGeneratedFile{{
			Path: ports.WorkspaceSnapshotManifestName, MediaType: "application/json", Disposition: "generated_at_execution",
		}},
		Transmissions: transmissions,
		Budget: ReviewPreflightBudget{
			Eligible: true, ReasonCode: reasonCode, MaxActiveLanes: maxActiveLanes,
			TotalInvocations:     totalInvocations,
			CriticalPathDeadline: criticalPath, RunDeadline: runDeadline,
			Ceilings: ReviewPreflightCeilings{
				ProviderTimeout: appconfig.ProviderTimeoutText(ceilings.MaxTimeout()), RolePathDeadline: ceilings.MaxRolePathDeadline().String(),
				RunDeadline: ceilings.MaxRunDeadline().String(), MaxInvocationsPerRole: ceilings.MaxInvocationsPerRole(),
				MaxInvocationsPerRun: ceilings.MaxInvocationsPerRun(),
			},
			RolePaths: pathRows,
		},
	}
	return result, nil
}

func validatePreflightSnapshotBinding(snapshot ports.WorkspaceSnapshotRequest, receipt ports.WorkspaceSnapshotReceipt) error {
	if snapshot.PolicyIdentity() != receipt.PolicyIdentity() {
		return fmt.Errorf("review preflight: workspace receipt policy mismatch")
	}
	expected, observed := snapshot.Files(), receipt.Files()
	if len(expected) != len(observed) {
		return fmt.Errorf("review preflight: workspace receipt file count mismatch")
	}
	for index := range expected {
		if expected[index].Path() != observed[index].Path() || expected[index].MediaType() != observed[index].MediaType() ||
			expected[index].SHA256() != observed[index].SHA256() || !bytes.Equal(expected[index].Bytes(), observed[index].Bytes()) {
			return fmt.Errorf("review preflight: workspace receipt file mismatch")
		}
	}
	return nil
}

// Validate rejects malformed service projections before either renderer can
// expose them as successful preflight evidence.
func (result ReviewPreflightResult) Validate() (err error) {
	defer func() {
		if err == nil {
			return
		}
		if _, ok := err.(*reviewPreflightValidationFailure); !ok {
			err = newReviewPreflightValidationFailure("result_projection")
		}
	}()
	if result.SchemaVersion != reviewPreflightSchemaVersion || result.Qualification != "not_run" ||
		(result.Status != "eligible" && result.Status != "no_change") || !validPreflightTarget(result.Target) ||
		(result.AGYPermissionMode != appconfig.SafeAGYPermissionMode && result.AGYPermissionMode != appconfig.HeadlessAGYPermissionMode) ||
		len(result.FileSets) != 1 || len(result.GeneratedFiles) != 1 || !result.Budget.Eligible {
		return fmt.Errorf("review preflight: invalid result")
	}
	wantWarnings := 0
	if result.AGYPermissionMode == appconfig.HeadlessAGYPermissionMode {
		wantWarnings = 1
	}
	if len(result.Warnings) != wantWarnings || wantWarnings == 1 && result.Warnings[0] != "AGY dangerously-skip-permissions is opt-in and may approve write or shell tool requests outside Mulgae's read-oriented boundary." {
		return fmt.Errorf("review preflight: invalid warnings")
	}
	fileSet := result.FileSets[0]
	if !preflightSHA256(fileSet.ID) || fileSet.PolicyIdentity == "" {
		return fmt.Errorf("review preflight: invalid file set")
	}
	previous := ""
	for _, file := range fileSet.Files {
		path, pathErr := ports.NewSafeRelativePath(file.Path)
		if pathErr != nil || !path.Valid() || file.Path == ports.WorkspaceSnapshotManifestName || file.Path <= previous ||
			file.Size < 0 || !preflightSHA256(file.SHA256) ||
			(file.MediaType == "text/plain" && file.Disposition != "text") ||
			(file.MediaType != "text/plain" && file.MediaType != "application/octet-stream" && file.MediaType != "image/png" && file.MediaType != "image/jpeg" && file.MediaType != "image/webp") ||
			(file.MediaType != "text/plain" && file.Disposition != "binary_preserved") {
			return fmt.Errorf("review preflight: invalid file")
		}
		previous = file.Path
	}
	recomputed, err := reviewPreflightFileSetID(fileSet.PolicyIdentity, fileSet.Files)
	if err != nil || recomputed != fileSet.ID {
		return fmt.Errorf("review preflight: file set identity mismatch")
	}
	generated := result.GeneratedFiles[0]
	if generated.Path != ports.WorkspaceSnapshotManifestName || generated.MediaType != "application/json" || generated.Disposition != "generated_at_execution" {
		return fmt.Errorf("review preflight: invalid generated file")
	}
	if err := validatePreflightBudget(result.Budget, result.Status); err != nil {
		return err
	}
	if result.Status == "no_change" {
		if len(result.Transmissions) != 0 {
			return fmt.Errorf("review preflight: no-change result has transmissions")
		}
		return nil
	}
	if len(result.Transmissions) == 0 {
		return fmt.Errorf("review preflight: eligible result has no transmissions")
	}
	// One role, one provider, one transmission: role ordinals strictly increase.
	lastRole := -1
	for _, transmission := range result.Transmissions {
		role := domain.Role(transmission.Role)
		ordinal := preflightRoleOrdinal(role)
		if ordinal < 0 || ordinal <= lastRole || transmission.RouteKind != "primary" ||
			transmission.ProviderInstance != transmission.ProviderFamily+"-"+transmission.Role ||
			transmission.TargetChannel != "prompt" || transmission.FileSetID != fileSet.ID {
			return fmt.Errorf("review preflight: invalid transmission order")
		}
		if _, err := appconfig.ParseProviderTimeout(transmission.ConfiguredTimeout); err != nil {
			return fmt.Errorf("review preflight: invalid transmission timeout")
		}
		wantPermission := "not_applicable"
		if transmission.ProviderFamily == string(reviewrun.FamilyAGY) {
			wantPermission = result.AGYPermissionMode
		}
		if !reviewrun.Family(transmission.ProviderFamily).Valid() || transmission.PermissionMode != wantPermission {
			return fmt.Errorf("review preflight: invalid transmission provider")
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

func validPreflightTarget(target ReviewPreflightTarget) bool {
	switch target.RequestedKind {
	case "workspace", "stage", "dirty", "diff", "patch", "stdin":
	default:
		return false
	}
	if target.Size < 0 || !preflightSHA256(target.SHA256) {
		return false
	}
	switch domain.TargetKind(target.CapturedKind) {
	case domain.TargetGit, domain.TargetWorkspace, domain.TargetPatch, domain.TargetStdin:
	default:
		return false
	}
	mode := domain.GitTargetMode(target.GitMode)
	return target.CapturedKind == string(domain.TargetGit) && mode.Valid() || target.CapturedKind != string(domain.TargetGit) && target.GitMode == ""
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

func preflightTransmission(role domain.Role, routeKind string, budget review.RouteBudget, agyPermissionMode, fileSetID string) ReviewPreflightTransmission {
	instance := budget.Route().ProviderInstance()
	family := strings.SplitN(instance, "-", 2)[0]
	permissionMode := "not_applicable"
	if family == string(reviewrun.FamilyAGY) {
		permissionMode = agyPermissionMode
	}
	return ReviewPreflightTransmission{
		Role: string(role), RouteKind: routeKind, ProviderInstance: instance, ProviderFamily: family,
		ConfiguredTimeout: appconfig.ProviderTimeoutText(budget.Limits().Timeout()), PermissionMode: permissionMode,
		TargetChannel: "prompt", FileSetID: fileSetID,
	}
}

func reviewPreflightFileSetID(policy string, files []ReviewPreflightFile) (string, error) {
	bytes, err := json.Marshal(struct {
		Policy string                `json:"policy"`
		Files  []ReviewPreflightFile `json:"files"`
	}{policy, files})
	if err != nil {
		return "", fmt.Errorf("review preflight: file set identity: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func renderReviewPreflightHuman(result ReviewPreflightResult) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "review preflight: %s\nqualification: %s\nagy permission mode: %s\n", result.Status, result.Qualification, result.AGYPermissionMode)
	for _, warning := range result.Warnings {
		fmt.Fprintf(&output, "warning: %s\n", warning)
	}
	fmt.Fprintf(&output, "status: %s\ntarget: requested=%s captured=%s git_mode=%s %d bytes %s\n",
		result.Status, result.Target.RequestedKind, result.Target.CapturedKind, result.Target.GitMode, result.Target.Size, result.Target.SHA256)
	for _, transmission := range result.Transmissions {
		fmt.Fprintf(&output, "route: %s %s %s timeout=%s permission=%s target_channel=%s file_set=%s\n",
			transmission.Role, transmission.RouteKind, transmission.ProviderInstance,
			transmission.ConfiguredTimeout, transmission.PermissionMode, transmission.TargetChannel, transmission.FileSetID)
	}
	for _, fileSet := range result.FileSets {
		fmt.Fprintf(&output, "file set: %s policy=%s\n", fileSet.ID, fileSet.PolicyIdentity)
		for _, file := range fileSet.Files {
			fmt.Fprintf(&output, "file: %s media=%s size=%d sha256=%s disposition=%s\n",
				file.Path, file.MediaType, file.Size, file.SHA256, file.Disposition)
		}
	}
	for _, file := range result.GeneratedFiles {
		fmt.Fprintf(&output, "generated file: %s media=%s disposition=%s\n", file.Path, file.MediaType, file.Disposition)
	}
	fmt.Fprintf(&output, "budget: %s invocations=%d critical_path=%s run_deadline=%s max_active_lanes=%d\n",
		result.Budget.ReasonCode, result.Budget.TotalInvocations,
		result.Budget.CriticalPathDeadline, result.Budget.RunDeadline, result.Budget.MaxActiveLanes)
	fmt.Fprintf(&output, "ceilings: provider_timeout=%s role_path_deadline=%s run_deadline=%s role_invocations=%d run_invocations=%d\n",
		result.Budget.Ceilings.ProviderTimeout, result.Budget.Ceilings.RolePathDeadline, result.Budget.Ceilings.RunDeadline,
		result.Budget.Ceilings.MaxInvocationsPerRole, result.Budget.Ceilings.MaxInvocationsPerRun)
	for _, path := range result.Budget.RolePaths {
		fmt.Fprintf(&output, "role path: %s provider=%s invocations=%d transitions=%d provider_time=%s deadline=%s\n",
			path.Role, path.ProviderInstance, path.InvocationCount, path.TransitionCount, path.InvocationTimeouts, path.Deadline)
	}
	return []byte(strings.TrimSuffix(output.String(), "\n"))
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
