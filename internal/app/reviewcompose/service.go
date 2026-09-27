package reviewcompose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/compositesupport"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type Service struct{ sources SourceReader }

func NewService(sources SourceReader) (*Service, error) {
	if nilDependency(sources) {
		return nil, fmt.Errorf("review composition service: source reader is required")
	}
	return &Service{sources: sources}, nil
}

// Compose admits exact source identities and deterministically recomputes the
// complete effective review. It performs no writes and invokes no provider.
func (service *Service) Compose(ctx context.Context, request Request) (Result, error) {
	if service == nil || nilDependency(service.sources) {
		return Result{}, fail(domain.CompositeValidationFailed, "composition service is unavailable", nil)
	}
	if ctx == nil {
		return Result{}, fail(domain.CompositeValidationFailed, "context is required", nil)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := domain.ParseRunID(request.RootRunID.String()); err != nil || len(request.RecoveryRuns) == 0 || len(request.RecoveryRuns) > len(domain.FixedRoleOrder()) {
		return Result{}, fail(domain.CompositeRecoveryIncomplete, "one root and a bounded non-empty recovery selection are required", err)
	}
	seenRuns := map[domain.RunID]struct{}{request.RootRunID: {}}
	for _, runID := range request.RecoveryRuns {
		if _, err := domain.ParseRunID(runID.String()); err != nil {
			return Result{}, fail(domain.CompositeRecoveryUnavailable, "recovery run identity is invalid", err)
		}
		if _, duplicate := seenRuns[runID]; duplicate {
			return Result{}, fail(domain.CompositeSelectionAmbiguous, "a run was selected more than once", nil)
		}
		seenRuns[runID] = struct{}{}
	}

	root, err := service.sources.ReadCompositionSource(ctx, request.RootRunID)
	if err != nil {
		return Result{}, fail(domain.CompositeValidationFailed, "committed root is unavailable", err)
	}
	if err := validateRoot(root, request.RootRunID); err != nil {
		return Result{}, err
	}

	roles := make(map[domain.Role]Role, len(root.Roles))
	missing := make(map[domain.Role]Role)
	for _, role := range root.Roles {
		roles[role.Name] = role
		if role.Outcome == "failed" && role.HasAttempt {
			missing[role.Name] = role
		}
	}
	if len(missing) == 0 {
		return Result{}, fail(domain.CompositeRoleAlreadySatisfied, "root has no missing selected role", nil)
	}

	recoveries := make(map[domain.Role]Source, len(request.RecoveryRuns))
	for _, runID := range request.RecoveryRuns {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		recovery, readErr := service.sources.ReadCompositionSource(ctx, runID)
		if readErr != nil {
			return Result{}, fail(domain.CompositeRecoveryUnavailable, "selected recovery is not a committed review", readErr)
		}
		if recovery.RunID != runID {
			return Result{}, fail(domain.CompositeRecoveryUnavailable, "source reader substituted a different recovery identity", nil)
		}
		role, admitErr := service.admitRecovery(ctx, root, recovery)
		if admitErr != nil {
			return Result{}, admitErr
		}
		if _, duplicate := recoveries[role.Name]; duplicate {
			return Result{}, fail(domain.CompositeSelectionAmbiguous, "more than one recovery selected the same role", nil)
		}
		recoveries[role.Name] = recovery
	}
	if len(recoveries) != len(missing) {
		return Result{}, fail(domain.CompositeRecoveryIncomplete, "selection does not recover every missing selected role", nil)
	}

	return buildResult(root, roles, recoveries)
}

func validateRoot(root Source, expected domain.RunID) error {
	if root.RunID != expected || root.RunType != domain.RunTypeReview || root.Coverage != domain.CoverageIncomplete {
		return fail(domain.CompositeValidationFailed, "root must be the exact committed incomplete ordinary review", nil)
	}
	if !validDigest(root.TargetSHA256) {
		return fail(domain.CompositeTargetDigestInvalid, "root target digest is invalid", nil)
	}
	if !root.Threshold.Valid() || len(root.Roles) == 0 || len(root.Roles) > len(domain.FixedRoleOrder()) {
		return fail(domain.CompositeValidationFailed, "root policy or role set is invalid", nil)
	}
	if _, err := domain.ParseSessionID(root.SessionID.String()); err != nil {
		return fail(domain.CompositeValidationFailed, "root session identity is invalid", err)
	}
	if _, err := sourceReference(root.RunID, root.ReviewID, root.RecoveryManifestSHA256); err != nil {
		return fail(domain.CompositeValidationFailed, "root source identity is invalid", err)
	}
	seen := make(map[domain.Role]struct{}, len(root.Roles))
	for _, role := range root.Roles {
		if !role.Name.Valid() {
			return fail(domain.CompositeValidationFailed, "root contains an invalid role", nil)
		}
		if _, duplicate := seen[role.Name]; duplicate {
			return fail(domain.CompositeValidationFailed, "root contains a duplicate role", nil)
		}
		seen[role.Name] = struct{}{}
		if accepted(role) {
			if _, err := acceptedReport(root, role); err != nil {
				return err
			}
		} else {
			switch role.Outcome {
			case "failed":
				if !role.HasAttempt || strings.TrimSpace(role.ProviderInstance) == "" {
					return fail(domain.CompositeValidationFailed, "failed root role has no attempt binding", nil)
				}
			case "skipped", "not_applicable":
				if role.HasAttempt || strings.TrimSpace(role.ProviderInstance) != "" || len(role.FindingIDs) != 0 {
					return fail(domain.CompositeValidationFailed, "non-attempt root role has attempt-owned content", nil)
				}
			default:
				return fail(domain.CompositeValidationFailed, "missing root role has an invalid outcome", nil)
			}
		}
	}
	if err := validateSourceAttempts(root); err != nil {
		return err
	}
	return validateFindings(root)
}

func (service *Service) admitRecovery(ctx context.Context, root, recovery Source) (Role, error) {
	if recovery.RunType != domain.RunTypeRerun ||
		(recovery.Coverage != domain.CoverageComplete && recovery.Coverage != domain.CoverageDegraded) || len(recovery.Roles) != 1 {
		return Role{}, fail(domain.CompositeRecoveryIncomplete, "recovery must be one complete committed rerun role", nil)
	}
	if !validDigest(recovery.TargetSHA256) {
		return Role{}, fail(domain.CompositeTargetDigestInvalid, "recovery target digest is invalid", nil)
	}
	if recovery.TargetSHA256 != root.TargetSHA256 {
		return Role{}, fail(domain.CompositeTargetMismatch, "recovery target does not match root target", nil)
	}
	if _, err := domain.ParseReviewID(recovery.ReviewID.String()); err != nil || recovery.SessionID != root.SessionID {
		return Role{}, fail(domain.CompositeLineageMismatch, "recovery session or review identity is invalid", err)
	}
	role := recovery.Roles[0]
	rootRole, exists := findRole(root.Roles, role.Name)
	if !exists {
		return Role{}, fail(domain.CompositeRoleNotRequired, "recovery role was not selected by the root", nil)
	}
	if accepted(rootRole) {
		return Role{}, fail(domain.CompositeRoleAlreadySatisfied, "recovery would replace an accepted root role", nil)
	}
	if !accepted(role) {
		return Role{}, fail(domain.CompositeRecoveryIncomplete, "recovery role has no accepted terminal result", nil)
	}
	if err := validateSourceAttempts(recovery); err != nil {
		return Role{}, err
	}
	if _, err := acceptedReport(recovery, role); err != nil {
		return Role{}, err
	}
	if err := validateFindings(recovery); err != nil {
		return Role{}, err
	}
	if err := service.verifyLineage(ctx, root, recovery, role.Name); err != nil {
		return Role{}, err
	}
	return role, nil
}

func (service *Service) verifyLineage(ctx context.Context, root, recovery Source, role domain.Role) error {
	current := recovery
	seen := map[domain.RunID]struct{}{current.RunID: {}}
	for {
		if len(seen) > 128 {
			return fail(domain.CompositeLineageMismatch, "recovery lineage exceeds 128 runs", nil)
		}
		if current.RunType != domain.RunTypeRerun || !current.HasSource || !current.HasSourceAttempt {
			return fail(domain.CompositeLineageMismatch, "recovery lineage is not a rerun chain", nil)
		}
		if current.SessionID != root.SessionID || current.TargetSHA256 != root.TargetSHA256 || len(current.Roles) != 1 || current.Roles[0].Name != role {
			return fail(domain.CompositeLineageMismatch, "recovery lineage changed session, target, or role", nil)
		}
		if current.SourceRunID == root.RunID {
			if current.SourceReviewID != root.ReviewID || current.SourceRecoveryManifestSHA256 != root.RecoveryManifestSHA256 {
				return fail(domain.CompositeLineageMismatch, "recovery lineage root review does not match", nil)
			}
			rootRole, exists := findRole(root.Roles, role)
			if !exists || accepted(rootRole) || !failedAttempt(root, role, current.SourceAttemptID) {
				return fail(domain.CompositeLineageMismatch, "recovery does not end at the failed root role attempt", nil)
			}
			return nil
		}
		if _, cycle := seen[current.SourceRunID]; cycle {
			return fail(domain.CompositeLineageMismatch, "recovery lineage contains a cycle", nil)
		}
		seen[current.SourceRunID] = struct{}{}
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := service.sources.ReadCompositionSource(ctx, current.SourceRunID)
		if err != nil {
			return fail(domain.CompositeLineageMismatch, "recovery lineage source is unavailable", err)
		}
		if next.ReviewID != current.SourceReviewID || next.RecoveryManifestSHA256 != current.SourceRecoveryManifestSHA256 {
			return fail(domain.CompositeLineageMismatch, "recovery lineage source review does not match", nil)
		}
		if next.RunID != current.SourceRunID {
			return fail(domain.CompositeLineageMismatch, "source reader substituted a different lineage run", nil)
		}
		if !sourceAttempt(next, role, current.SourceAttemptID, false) {
			return fail(domain.CompositeLineageMismatch, "recovery lineage source attempt does not match", nil)
		}
		current = next
	}
}

func failedAttempt(source Source, role domain.Role, attemptID domain.AttemptID) bool {
	return sourceAttempt(source, role, attemptID, true)
}

func sourceAttempt(source Source, role domain.Role, attemptID domain.AttemptID, requireFailure bool) bool {
	for _, attempt := range source.Attempts {
		if attempt.AttemptID != attemptID || attempt.Role != role {
			continue
		}
		if !requireFailure {
			return true
		}
		switch attempt.State {
		case domain.AttemptFailed, domain.AttemptTimedOut, domain.AttemptCancelled, domain.AttemptBlocked:
			return true
		}
	}
	return false
}

func validateSourceAttempts(source Source) error {
	seen := make(map[domain.AttemptID]struct{}, len(source.Attempts))
	for _, attempt := range source.Attempts {
		if _, err := domain.ParseAttemptID(attempt.AttemptID.String()); err != nil || !attempt.Role.Valid() || !attempt.State.Valid() || strings.TrimSpace(attempt.ProviderInstance) == "" {
			return fail(domain.CompositeValidationFailed, "source attempt inventory is invalid", err)
		}
		if _, duplicate := seen[attempt.AttemptID]; duplicate {
			return fail(domain.CompositeValidationFailed, "source attempt inventory is ambiguous", nil)
		}
		seen[attempt.AttemptID] = struct{}{}
	}
	for _, role := range source.Roles {
		if !role.HasAttempt {
			continue
		}
		matched := false
		for _, attempt := range source.Attempts {
			if attempt.AttemptID != role.AttemptID || attempt.Role != role.Name || attempt.ProviderInstance != role.ProviderInstance {
				continue
			}
			matched = accepted(role) && attempt.State == domain.AttemptSucceeded || !accepted(role) && sourceAttempt(source, role.Name, role.AttemptID, true)
		}
		if !matched {
			return fail(domain.CompositeValidationFailed, "role outcome does not match source attempt inventory", nil)
		}
	}
	return nil
}

func buildResult(root Source, rootRoles map[domain.Role]Role, recoveries map[domain.Role]Source) (Result, error) {
	recoveryCoordinates := make([]domain.CompositionSource, 0, len(recoveries))
	for role, source := range recoveries {
		selected := source.Roles[0]
		coordinate, err := domain.NewCompositionSource(role, source.RunID, source.ReviewID, selected.AttemptID)
		if err != nil {
			return Result{}, fail(domain.CompositeValidationFailed, "recovery coordinate is invalid", err)
		}
		recoveryCoordinates = append(recoveryCoordinates, coordinate)
	}
	fingerprint, err := compositionFingerprint(root, recoveryCoordinates)
	if err != nil {
		return Result{}, fail(domain.CompositeValidationFailed, "composition fingerprint is invalid", err)
	}
	result := Result{
		Fingerprint: fingerprint, RootRunID: root.RunID, RootReviewID: root.ReviewID, RootRecoveryManifestSHA256: root.RecoveryManifestSHA256,
		SessionID: root.SessionID, TargetSHA256: root.TargetSHA256, Threshold: root.Threshold,
		TargetIdentity: root.TargetIdentity, TargetBytes: append([]byte(nil), root.TargetBytes...),
		CapturedArchive: append([]byte(nil), root.CapturedArchive...),
		CoverageStatus:  domain.CoverageComplete,
	}
	type pendingFinding struct {
		finding SourceFinding
		source  Source
		attempt domain.AttemptID
	}
	var pending []pendingFinding
	structured, reportsOnly, degraded := 0, 0, false
	for _, roleName := range domain.FixedRoleOrder() {
		rootRole, exists := rootRoles[roleName]
		if !exists {
			continue
		}
		if !accepted(rootRole) {
			if _, recovered := recoveries[roleName]; !recovered {
				continue
			}
		}
		source, kind, selectedRole := root, "root", rootRole
		if recovery, recovered := recoveries[roleName]; recovered {
			source, kind, selectedRole = recovery, "recovery", recovery.Roles[0]
		}
		report, reportErr := acceptedReport(source, selectedRole)
		if reportErr != nil {
			return Result{}, reportErr
		}
		var support *compositesupport.Material
		if source.Support != nil {
			value := compositesupport.Clone(*source.Support)
			value.Source.Role = roleName
			value.Source.AttemptID = selectedRole.AttemptID.String()
			findings := value.Findings
			value.Findings = nil
			for _, f := range findings {
				if f.Finding.Role == roleName {
					value.Findings = append(value.Findings, f)
				}
			}
			support = &value
		}
		result.Sources = append(result.Sources, SelectedSource{
			Support: support,
			Kind:    kind, Role: roleName, RunID: source.RunID, ReviewID: source.ReviewID, RecoveryManifestSHA256: source.RecoveryManifestSHA256,
			AttemptID: selectedRole.AttemptID, RoleReport: cloneRoleReport(report),
		})
		result.Roles = append(result.Roles, CompositeRole{
			Role: roleName, Required: rootRole.Required, Outcome: selectedRole.Outcome,
			AttemptID: selectedRole.AttemptID, ProviderInstance: selectedRole.ProviderInstance,
			ReportsOnly: selectedRole.ReportsOnly, SourceRunID: source.RunID, SourceReviewID: source.ReviewID, SourceRecoveryManifestSHA256: source.RecoveryManifestSHA256,
		})
		if selectedRole.ReportsOnly {
			reportsOnly++
		} else {
			structured++
		}
		degraded = degraded || selectedRole.Outcome == "degraded"
		for _, finding := range source.Findings {
			if finding.Role == roleName {
				pending = append(pending, pendingFinding{finding: finding, source: source, attempt: selectedRole.AttemptID})
			}
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		a, b := pending[i], pending[j]
		if a.finding.Severity.Rank() != b.finding.Severity.Rank() {
			return a.finding.Severity.Rank() > b.finding.Severity.Rank()
		}
		if a.finding.Role != b.finding.Role {
			return roleIndex(a.finding.Role) < roleIndex(b.finding.Role)
		}
		if a.source.RunID != b.source.RunID {
			return a.source.RunID.String() < b.source.RunID.String()
		}
		if a.attempt != b.attempt {
			return a.attempt.String() < b.attempt.String()
		}
		if a.finding.ID != b.finding.ID {
			return a.finding.ID < b.finding.ID
		}
		return a.finding.Fingerprint < b.finding.Fingerprint
	})
	if len(pending) > 999 {
		return Result{}, fail(domain.CompositeValidationFailed, "composite finding count exceeds the versioned identity limit", nil)
	}
	roleFindingIDs := make(map[domain.Role][]string)
	for index, item := range pending {
		id := fmt.Sprintf("F%03d", index+1)
		fingerprint := item.finding.Fingerprint
		if !strings.HasPrefix(fingerprint, "sha256:") {
			fingerprint = "sha256:" + fingerprint
		}
		result.Findings = append(result.Findings, Finding{
			ID: id, Fingerprint: fingerprint, Role: item.finding.Role, ProviderInstance: item.finding.ProviderInstance,
			Severity: item.finding.Severity, Title: item.finding.Title, Description: item.finding.Description,
			Recommendation: item.finding.Recommendation, Confidence: item.finding.Confidence, Lifecycle: item.finding.Lifecycle,
			SourceRunID: item.source.RunID, SourceReviewID: item.source.ReviewID, SourceRecoveryManifestSHA256: item.source.RecoveryManifestSHA256,
			SourceAttemptID: item.attempt, SourceFindingID: item.finding.ID,
		})
		roleFindingIDs[item.finding.Role] = append(roleFindingIDs[item.finding.Role], id)
	}
	for i := range result.Sources {
		support := result.Sources[i].Support
		if support == nil {
			continue
		}
		for j := range support.Findings {
			for _, f := range result.Findings {
				if f.Role == support.Source.Role && f.SourceFindingID == support.Findings[j].Finding.SourceFindingID {
					support.Findings[j].Finding.ID = f.ID
				}
			}
		}
	}
	for index := range result.Roles {
		result.Roles[index].FindingIDs = roleFindingIDs[result.Roles[index].Role]
	}
	switch {
	case structured > 0 && reportsOnly > 0:
		result.ExtractionStatus = domain.StructuredExtractionMixed
	case reportsOnly > 0:
		result.ExtractionStatus = domain.StructuredExtractionReportsOnly
	default:
		result.ExtractionStatus = domain.StructuredExtractionStructured
	}
	result.ContentVerdict = domain.ContentNoFindings
	if len(result.Findings) > 0 {
		result.ContentVerdict = domain.ContentFindingsPresent
		for _, finding := range result.Findings {
			if finding.Severity.Rank() >= root.Threshold.Rank() {
				result.ContentVerdict = domain.ContentRequestChanges
			}
		}
	} else if reportsOnly > 0 {
		result.ContentVerdict = domain.ContentReportsOnly
	}
	result.CIDecision = domain.CIPass
	if result.ContentVerdict == domain.ContentRequestChanges || degraded {
		result.CIDecision = domain.CIFail
	}
	if result.ContentVerdict == domain.ContentRequestChanges {
		result.CIReasonCodes = append(result.CIReasonCodes, "request_changes_threshold")
	}
	if degraded {
		result.CIReasonCodes = append(result.CIReasonCodes, "degraded_role")
	}
	if len(result.CIReasonCodes) == 0 {
		result.CIReasonCodes = []string{"policy_evaluated"}
	}
	return result, nil
}

func cloneRoleReport(report RoleReport) RoleReport {
	report.Bytes = append([]byte(nil), report.Bytes...)
	return report
}

func validateFindings(source Source) error {
	byRole := make(map[domain.Role]map[string]struct{}, len(source.Roles))
	for _, role := range source.Roles {
		ids := make(map[string]struct{}, len(role.FindingIDs))
		for _, id := range role.FindingIDs {
			if !validFindingID(id) {
				return fail(domain.CompositeValidationFailed, "source contains an invalid finding identity", nil)
			}
			if _, duplicate := ids[id]; duplicate {
				return fail(domain.CompositeValidationFailed, "source contains a duplicate finding identity", nil)
			}
			ids[id] = struct{}{}
		}
		byRole[role.Name] = ids
	}
	seen := make(map[string]struct{}, len(source.Findings))
	for _, finding := range source.Findings {
		if !validFindingID(finding.ID) || !validFingerprint(finding.Fingerprint) || !finding.Role.Valid() || !finding.Severity.Valid() || !finding.Confidence.Valid() || !finding.Lifecycle.Valid() || strings.TrimSpace(finding.ProviderInstance) == "" || strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.Description) == "" || strings.TrimSpace(finding.Recommendation) == "" {
			return fail(domain.CompositeValidationFailed, "source finding content is invalid", nil)
		}
		key := string(finding.Role) + "\x00" + finding.ID
		if _, duplicate := seen[key]; duplicate {
			return fail(domain.CompositeValidationFailed, "source contains duplicate role-local finding identity", nil)
		}
		seen[key] = struct{}{}
		ids, exists := byRole[finding.Role]
		if !exists {
			return fail(domain.CompositeValidationFailed, "source finding role is absent", nil)
		}
		if _, selected := ids[finding.ID]; !selected {
			return fail(domain.CompositeValidationFailed, "source finding is not selected by its role", nil)
		}
		delete(ids, finding.ID)
	}
	for _, ids := range byRole {
		if len(ids) != 0 {
			return fail(domain.CompositeValidationFailed, "source role references a missing finding", nil)
		}
	}
	return nil
}

func acceptedReport(source Source, role Role) (RoleReport, error) {
	if !accepted(role) {
		return RoleReport{}, fail(domain.CompositeValidationFailed, "role is not accepted", nil)
	}
	var selected *RoleReport
	for index := range source.RoleReports {
		report := &source.RoleReports[index]
		if report.Role != role.Name {
			continue
		}
		if selected != nil {
			return RoleReport{}, fail(domain.CompositeValidationFailed, "role has more than one committed report", nil)
		}
		selected = report
	}
	if selected == nil || selected.AttemptID != role.AttemptID || selected.ProviderInstance != role.ProviderInstance || !validDigest(selected.SHA256) || selected.ByteLength <= 0 || selected.ContentType != "text/markdown" || len(selected.Bytes) != 0 && (len(selected.Bytes) != selected.ByteLength || !validRoleReportBytes(selected.Bytes, selected.SHA256)) {
		return RoleReport{}, fail(domain.CompositeValidationFailed, "accepted role report integrity is invalid", nil)
	}
	if _, err := domain.ParseAttemptID(role.AttemptID.String()); err != nil {
		return RoleReport{}, fail(domain.CompositeValidationFailed, "accepted role attempt identity is invalid", err)
	}
	if _, err := ports.NewSafeRelativePath(selected.Path); err != nil {
		return RoleReport{}, fail(domain.CompositeValidationFailed, "accepted role report path is invalid", err)
	}
	return *selected, nil
}

func validRoleReportBytes(value []byte, digest string) bool {
	if len(value) == 0 || !utf8.Valid(value) || len(strings.TrimSpace(string(value))) == 0 {
		return false
	}
	sum := sha256.Sum256(value)
	return digest == "sha256:"+hex.EncodeToString(sum[:])
}

func accepted(role Role) bool {
	return (role.Outcome == "completed" || role.Outcome == "degraded") && role.HasAttempt && strings.TrimSpace(role.ProviderInstance) != ""
}

func findRole(roles []Role, name domain.Role) (Role, bool) {
	for _, role := range roles {
		if role.Name == name {
			return role, true
		}
	}
	return Role{}, false
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validFingerprint(value string) bool {
	if strings.HasPrefix(value, "sha256:") {
		return validDigest(value)
	}
	return validDigest("sha256:" + value)
}

func validFindingID(value string) bool {
	if len(value) != 4 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func roleIndex(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if candidate == role {
			return index
		}
	}
	return len(domain.FixedRoleOrder())
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
