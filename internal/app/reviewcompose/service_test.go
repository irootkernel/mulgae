package reviewcompose

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type sourceReader map[domain.RunID]Source

func (reader sourceReader) ReadCompositionSource(_ context.Context, runID domain.RunID) (Source, error) {
	source, ok := reader[runID]
	if !ok {
		return Source{}, errors.New("not found")
	}
	return source, nil
}

func TestComposeRecoversMultipleRolesDeterministicallyAndKeepsCollidingSourceIDs(t *testing.T) {
	root, security, docs := compositionFixtures(t)
	reader := sourceReader{root.RunID: root, security.RunID: security, docs.RunID: docs}
	service, err := NewService(reader)
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{docs.RunID, security.RunID}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID, docs.RunID}})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same exact selection was order-dependent:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if first.CoverageStatus != domain.CoverageComplete || first.ContentVerdict != domain.ContentRequestChanges || first.CIDecision != domain.CIFail {
		t.Fatalf("unexpected outcome: coverage=%s content=%s ci=%s", first.CoverageStatus, first.ContentVerdict, first.CIDecision)
	}
	if len(first.Findings) != 2 || first.Findings[0].ID == first.Findings[1].ID || first.Findings[0].SourceFindingID != "F001" || first.Findings[1].SourceFindingID != "F001" {
		t.Fatalf("colliding source finding IDs were not retained distinctly: %#v", first.Findings)
	}
	if len(first.Sources) != 3 || first.Sources[0].Kind != "root" || first.Sources[1].Kind != "recovery" || first.Sources[2].Kind != "recovery" {
		t.Fatalf("unexpected selected sources: %#v", first.Sources)
	}
}

func TestIdentifiedPublicationFailurePreservesDeterministicReconciliationIdentity(t *testing.T) {
	sessionID := sessionID(t)
	runID := runID(t, "01")
	err := failWithIdentity(domain.CompositePublicationIncomplete, "reconcile", errors.New("private"), sessionID, runID)
	var failure *Failure
	if !errors.As(err, &failure) || failure.ReasonCode() != domain.CompositePublicationIncomplete {
		t.Fatalf("identified failure = %v", err)
	}
	gotSession, gotRun, ok := failure.CompositeIdentity()
	if !ok || gotSession != sessionID || gotRun != runID {
		t.Fatalf("reconciliation identity = %s/%s, %t", gotSession, gotRun, ok)
	}
}

func TestCompositeReasonCodeContract(t *testing.T) {
	want := []string{
		"composite_target_mismatch",
		"composite_target_digest_invalid",
		"composite_lineage_mismatch",
		"composite_role_not_required",
		"composite_role_already_satisfied",
		"composite_recovery_incomplete",
		"composite_recovery_unavailable",
		"composite_selection_ambiguous",
		"composite_validation_failed",
		"composite_publication_incomplete",
	}
	if got := domain.CompositeReasonCodes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("composite reason codes = %#v, want %#v", got, want)
	}
	for _, code := range want {
		if !domain.ValidCompositeReasonCode(code) {
			t.Fatalf("documented composite reason code %q is invalid", code)
		}
	}
	if domain.ValidCompositeReasonCode("") || domain.ValidCompositeReasonCode("composite_unknown") {
		t.Fatal("undocumented composite reason code was accepted")
	}
}

func TestComposeAcceptsTransitiveSameRoleRerunLineage(t *testing.T) {
	root, security, _ := compositionFixtures(t)
	intermediate := security
	intermediate.RunID = runID(t, "04")
	intermediate.ReviewID = reviewID(t, "14")
	intermediate.SourceRunID = root.RunID
	intermediate.SourceReviewID = root.ReviewID
	intermediate.SourceAttemptID = root.Roles[1].AttemptID
	security.SourceRunID = intermediate.RunID
	security.SourceReviewID = intermediate.ReviewID
	security.SourceAttemptID = intermediate.Roles[0].AttemptID
	reader := sourceReader{root.RunID: root, intermediate.RunID: intermediate, security.RunID: security}
	service, _ := NewService(reader)

	result, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}})
	if err == nil {
		// Documentation is also missing in the shared fixture, so exact coverage must fail.
		t.Fatalf("incomplete transitive selection unexpectedly succeeded: %#v", result)
	}
	wantReason(t, err, domain.CompositeRecoveryIncomplete)

	root.Roles = root.Roles[:2]
	reader[root.RunID] = root
	if _, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}}); err != nil {
		t.Fatalf("valid transitive lineage rejected: %v", err)
	}
}

func TestComposeAcceptsExactNonSelectedFailedRootAttempt(t *testing.T) {
	root, security, _ := compositionFixtures(t)
	root.Roles = root.Roles[:2]
	root.Attempts = root.Attempts[:2]
	primaryFailure := attemptID(t, "26")
	root.Attempts = append(root.Attempts, Attempt{AttemptID: primaryFailure, Role: domain.RoleSecurity, ProviderInstance: "provider-security-primary", State: domain.AttemptFailed})
	security.SourceAttemptID = primaryFailure
	reader := sourceReader{root.RunID: root, security.RunID: security}
	service, _ := NewService(reader)
	if _, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}}); err != nil {
		t.Fatalf("exact failed primary attempt was rejected: %v", err)
	}
}

func TestComposeRejectsAdmissionMatrix(t *testing.T) {
	baseRoot, baseSecurity, baseDocs := compositionFixtures(t)
	tests := []struct {
		name   string
		mutate func(*Source, *Source, *Source, *Request, sourceReader)
		want   string
	}{
		{"target mismatch", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) {
			security.TargetSHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, domain.CompositeTargetMismatch},
		{"target digest invalid", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) { security.TargetSHA256 = "bad" }, domain.CompositeTargetDigestInvalid},
		{"lineage review mismatch", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) {
			security.SourceReviewID = reviewID(t, "99")
		}, domain.CompositeLineageMismatch},
		{"lineage attempt mismatch", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) {
			security.SourceAttemptID = attemptID(t, "99")
		}, domain.CompositeLineageMismatch},
		{"non-required role", func(root, security, _ *Source, _ *Request, _ sourceReader) {
			root.Roles[1].Required = false
			security.Roles[0].Name = domain.RoleProduct
			security.RoleReports[0].Role = domain.RoleProduct
			security.Findings[0].Role = domain.RoleProduct
		}, domain.CompositeRoleNotRequired},
		{"already satisfied", func(root, security, _ *Source, _ *Request, _ sourceReader) {
			root.Roles[1] = acceptedRole(t, domain.RoleSecurity, "27", []string{"F001"})
			root.RoleReports = append(root.RoleReports, reportFor(root.Roles[1]))
			root.Findings = append(root.Findings, finding(domain.RoleSecurity, "F001", domain.SeverityLow))
			root.Attempts[1] = attemptFor(root.Roles[1], domain.AttemptSucceeded)
		}, domain.CompositeRoleAlreadySatisfied},
		{"duplicate role selection", func(_ *Source, _, docs *Source, _ *Request, _ sourceReader) {
			docs.Roles[0].Name = domain.RoleSecurity
			docs.RoleReports[0].Role = domain.RoleSecurity
			docs.SourceAttemptID = attemptID(t, "22")
			docs.Attempts[0].Role = domain.RoleSecurity
			docs.Findings = nil
			docs.Roles[0].FindingIDs = nil
		}, domain.CompositeSelectionAmbiguous},
		{"missing recovery", func(_ *Source, _ *Source, _ *Source, request *Request, _ sourceReader) {
			request.RecoveryRuns = request.RecoveryRuns[:1]
		}, domain.CompositeRecoveryIncomplete},
		{"unpublished recovery", func(_ *Source, security, _ *Source, _ *Request, reader sourceReader) { delete(reader, security.RunID) }, domain.CompositeRecoveryUnavailable},
		{"invalid role report digest", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) {
			security.RoleReports[0].SHA256 = "bad"
		}, domain.CompositeValidationFailed},
		{"recovery incomplete", func(_ *Source, security, _ *Source, _ *Request, _ sourceReader) {
			security.Coverage = domain.CoverageIncomplete
		}, domain.CompositeRecoveryIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, security, docs := baseRoot, baseSecurity, baseDocs
			root.Roles, root.RoleReports, root.Findings = append([]Role(nil), baseRoot.Roles...), append([]RoleReport(nil), baseRoot.RoleReports...), append([]SourceFinding(nil), baseRoot.Findings...)
			security.Roles, security.RoleReports, security.Findings = append([]Role(nil), baseSecurity.Roles...), append([]RoleReport(nil), baseSecurity.RoleReports...), append([]SourceFinding(nil), baseSecurity.Findings...)
			docs.Roles, docs.RoleReports, docs.Findings = append([]Role(nil), baseDocs.Roles...), append([]RoleReport(nil), baseDocs.RoleReports...), append([]SourceFinding(nil), baseDocs.Findings...)
			root.Attempts, security.Attempts, docs.Attempts = append([]Attempt(nil), baseRoot.Attempts...), append([]Attempt(nil), baseSecurity.Attempts...), append([]Attempt(nil), baseDocs.Attempts...)
			request := Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID, docs.RunID}}
			reader := sourceReader{root.RunID: root, security.RunID: security, docs.RunID: docs}
			test.mutate(&root, &security, &docs, &request, reader)
			reader[root.RunID], reader[security.RunID], reader[docs.RunID] = root, security, docs
			if test.name == "unpublished recovery" {
				delete(reader, security.RunID)
			}
			service, _ := NewService(reader)
			_, err := service.Compose(context.Background(), request)
			wantReason(t, err, test.want)
		})
	}
}

func TestComposeOmitsFailedOptionalRolesAndAcceptsDegradedRecovery(t *testing.T) {
	root, security, _ := compositionFixtures(t)
	root.Roles[2].Required = false
	security.Roles[0].Outcome = "degraded"
	security.Coverage = domain.CoverageDegraded
	reader := sourceReader{root.RunID: root, security.RunID: security}
	service, _ := NewService(reader)

	result, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Roles) != 2 || result.Roles[0].Role != domain.RoleLogic || result.Roles[1].Role != domain.RoleSecurity {
		t.Fatalf("optional failed role was retained: %#v", result.Roles)
	}
	if result.CoverageStatus != domain.CoverageComplete || result.CIDecision != domain.CIFail || !reflect.DeepEqual(result.CIReasonCodes, []string{"request_changes_threshold", "degraded_role"}) {
		t.Fatalf("degraded recovery policy = coverage:%s ci:%s reasons:%v", result.CoverageStatus, result.CIDecision, result.CIReasonCodes)
	}
}

func TestComposeRejectsFindingIdentityOverflow(t *testing.T) {
	root, security, _ := compositionFixtures(t)
	root.Roles = root.Roles[:2]
	root.Roles[0].FindingIDs = make([]string, 999)
	root.Findings = make([]SourceFinding, 999)
	for index := range root.Findings {
		id := fmt.Sprintf("F%03d", index+1)
		root.Roles[0].FindingIDs[index] = id
		root.Findings[index] = finding(domain.RoleLogic, id, domain.SeverityLow)
	}
	reader := sourceReader{root.RunID: root, security.RunID: security}
	service, _ := NewService(reader)
	_, err := service.Compose(context.Background(), Request{RootRunID: root.RunID, RecoveryRuns: []domain.RunID{security.RunID}})
	wantReason(t, err, domain.CompositeValidationFailed)
}

func compositionFixtures(t *testing.T) (Source, Source, Source) {
	t.Helper()
	root := Source{
		SessionID: sessionID(t), RunID: runID(t, "01"), ReviewID: reviewID(t, "11"),
		RunType: domain.RunTypeReview, TargetSHA256: testDigest, Coverage: domain.CoverageIncomplete, Threshold: domain.SeverityHigh,
		Roles: []Role{
			acceptedRole(t, domain.RoleLogic, "21", []string{"F001"}),
			failedRole(t, domain.RoleSecurity, "22"),
			failedRole(t, domain.RoleDocumentation, "23"),
		},
	}
	root.RoleReports = []RoleReport{reportFor(root.Roles[0])}
	root.Findings = []SourceFinding{finding(domain.RoleLogic, "F001", domain.SeverityLow)}
	root.Attempts = []Attempt{
		attemptFor(root.Roles[0], domain.AttemptSucceeded),
		attemptFor(root.Roles[1], domain.AttemptFailed),
		attemptFor(root.Roles[2], domain.AttemptFailed),
	}
	security := recoverySource(t, root, domain.RoleSecurity, "02", "12", "24", domain.SeverityHigh)
	docs := recoverySource(t, root, domain.RoleDocumentation, "03", "13", "25", "")
	return root, security, docs
}

func recoverySource(t *testing.T, root Source, role domain.Role, runSuffix, reviewSuffix, attemptSuffix string, severity domain.Severity) Source {
	t.Helper()
	selected := acceptedRole(t, role, attemptSuffix, nil)
	source := Source{
		SessionID: root.SessionID, RunID: runID(t, runSuffix), ReviewID: reviewID(t, reviewSuffix), RunType: domain.RunTypeRerun,
		TargetSHA256: testDigest, Coverage: domain.CoverageComplete, Threshold: domain.SeverityHigh,
		Roles: []Role{selected}, SourceRunID: root.RunID, SourceReviewID: root.ReviewID, HasSource: true,
		SourceAttemptID: failedAttemptFor(root, role), HasSourceAttempt: true,
	}
	if severity.Valid() {
		source.Roles[0].FindingIDs = []string{"F001"}
		source.Findings = []SourceFinding{finding(role, "F001", severity)}
	}
	source.RoleReports = []RoleReport{reportFor(source.Roles[0])}
	source.Attempts = []Attempt{attemptFor(source.Roles[0], domain.AttemptSucceeded)}
	return source
}

func attemptFor(role Role, state domain.AttemptState) Attempt {
	return Attempt{AttemptID: role.AttemptID, Role: role.Name, ProviderInstance: role.ProviderInstance, State: state}
}

func failedAttemptFor(root Source, role domain.Role) domain.AttemptID {
	selected, _ := findRole(root.Roles, role)
	return selected.AttemptID
}

func acceptedRole(t *testing.T, role domain.Role, suffix string, findings []string) Role {
	t.Helper()
	return Role{Name: role, Required: true, Outcome: "completed", AttemptID: attemptID(t, suffix), HasAttempt: true, ProviderInstance: "provider-" + string(role), FindingIDs: append([]string(nil), findings...)}
}

func failedRole(t *testing.T, role domain.Role, suffix string) Role {
	t.Helper()
	return Role{Name: role, Required: true, Outcome: "failed", AttemptID: attemptID(t, suffix), HasAttempt: true, ProviderInstance: "provider-" + string(role)}
}

func reportFor(role Role) RoleReport {
	return RoleReport{Role: role.Name, AttemptID: role.AttemptID, ProviderInstance: role.ProviderInstance, Path: "role-reports/" + string(role.Name) + ".md", SHA256: testDigest, ByteLength: 12, ContentType: "text/markdown"}
}

func finding(role domain.Role, id string, severity domain.Severity) SourceFinding {
	return SourceFinding{ID: id, Fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Role: role, ProviderInstance: "provider-" + string(role), Severity: severity, Title: "title", Description: "description", Recommendation: "recommendation", Confidence: domain.ConfidenceHigh, Lifecycle: domain.FindingOpen}
}

func wantReason(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s failure", want)
	}
	var failure *Failure
	if !errors.As(err, &failure) || failure.ReasonCode() != want {
		t.Fatalf("failure = %v, want reason %s", err, want)
	}
}

func sessionID(t *testing.T) domain.SessionID {
	t.Helper()
	value, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func runID(t *testing.T, suffix string) domain.RunID {
	t.Helper()
	value, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func reviewID(t *testing.T, suffix string) domain.ReviewID {
	t.Helper()
	value, err := domain.ParseReviewID("019f596a-d174-7321-b920-c2d312c82c" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func attemptID(t *testing.T, suffix string) domain.AttemptID {
	t.Helper()
	value, err := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f0122" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
