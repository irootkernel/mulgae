package review

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestAttemptKindClosed(t *testing.T) {
	t.Parallel()

	if !AttemptKindPrimary.Valid() || !AttemptKindFallback.Valid() {
		t.Fatal("defined attempt kinds must be valid")
	}
	if AttemptKind("").Valid() || AttemptKind("other").Valid() {
		t.Fatal("undefined attempt kind is valid")
	}
}

func TestNewInvocationJobRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	route := coordinatorTypesRoute(t, "provider")
	attemptID := coordinatorTypesAttemptID(t, 1)
	limits := coordinatorTypesLimits(t)
	target := coordinatorTypesTarget(t, 1)
	tests := []struct {
		name      string
		role      domain.Role
		route     ports.ProviderRoute
		attemptID domain.AttemptID
		purpose   domain.InvocationPurpose
		ordinal   uint64
		limits    InvocationLimits
	}{
		{
			name:      "role",
			role:      domain.Role("unknown"),
			route:     route,
			attemptID: attemptID,
			purpose:   domain.InvocationInitial,
			ordinal:   1,
			limits:    limits,
		},
		{
			name:      "route",
			role:      domain.RoleLogic,
			route:     ports.ProviderRoute{},
			attemptID: attemptID,
			purpose:   domain.InvocationInitial,
			ordinal:   1,
			limits:    limits,
		},
		{
			name:      "attempt identity",
			role:      domain.RoleLogic,
			route:     route,
			attemptID: domain.AttemptID{},
			purpose:   domain.InvocationInitial,
			ordinal:   1,
			limits:    limits,
		},
		{
			name:      "purpose",
			role:      domain.RoleLogic,
			route:     route,
			attemptID: attemptID,
			purpose:   domain.InvocationPurpose("unknown"),
			ordinal:   1,
			limits:    limits,
		},
		{
			name:      "ordinal",
			role:      domain.RoleLogic,
			route:     route,
			attemptID: attemptID,
			purpose:   domain.InvocationInitial,
			ordinal:   0,
			limits:    limits,
		},
		{
			name:      "repair without an issued attempt identity",
			role:      domain.RoleLogic,
			route:     route,
			attemptID: domain.AttemptID{},
			purpose:   domain.InvocationRepair,
			ordinal:   2,
			limits:    limits,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewInvocationJob(test.role, test.route, target, test.limits, test.attemptID, test.purpose, test.ordinal); err == nil {
				t.Fatal("NewInvocationJob() error = nil")
			}
		})
	}
	if _, err := NewInvocationJob(
		domain.RoleLogic,
		route,
		domain.TargetIdentity{},
		limits,
		attemptID,
		domain.InvocationInitial,
		1,
	); err == nil {
		t.Fatal("NewInvocationJob() accepted a zero target")
	}
}
func TestNewInvocationJobRejectsMissingLimits(t *testing.T) {
	t.Parallel()

	if _, err := NewInvocationJob(
		domain.RoleLogic,
		coordinatorTypesRoute(t, "provider"),
		coordinatorTypesTarget(t, 1),
		InvocationLimits{},
		coordinatorTypesAttemptID(t, 9),
		domain.InvocationInitial,
		1,
	); err == nil {
		t.Fatal("NewInvocationJob() accepted missing invocation limits")
	}
}

func TestInvocationJobAccessorsRetainCanonicalValues(t *testing.T) {
	t.Parallel()

	route := coordinatorTypesRoute(t, "provider")
	attemptID := coordinatorTypesAttemptID(t, 2)
	target := coordinatorTypesTarget(t, 1)
	job, err := NewInvocationJob(domain.RoleLogic, route, target, coordinatorTypesLimits(t), attemptID, domain.InvocationRepair, 3)
	if err != nil {
		t.Fatalf("NewInvocationJob() error = %v", err)
	}
	if job.SessionID().String() != "" || job.RunID().String() != "" {
		t.Fatalf("legacy job coordinates = %q/%q, want zero values", job.SessionID().String(), job.RunID().String())
	}
	if job.Role() != domain.RoleLogic ||
		job.AttemptID() != attemptID || job.Purpose() != domain.InvocationRepair || job.Ordinal() != 3 {
		t.Fatalf("job accessors = %#v", job)
	}
	returnedRoute := job.Route()
	if !returnedRoute.Valid() || returnedRoute.ProviderInstance() != "provider" {
		t.Fatalf("job route = %#v", returnedRoute)
	}
	if got := job.Target(); got != target {
		t.Fatalf("job target = %#v, want %#v", got, target)
	}
	if limits := job.Limits(); limits.Timeout() != time.Second || limits.MaxStdoutBytes() != 11 || limits.MaxStderrBytes() != 12 {
		t.Fatalf("job limits = %#v", limits)
	}
}
func TestCoordinatorInvocationJobRetainsCoordinates(t *testing.T) {
	t.Parallel()

	sessionID, err := domain.ParseSessionID("s_00000000-0000-7000-8000-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_00000000-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	job, err := newCoordinatorInvocationJob(
		sessionID,
		runID,
		domain.RoleLogic,
		coordinatorTypesRoute(t, "provider"),
		coordinatorTypesTarget(t, 1),
		coordinatorTypesLimits(t),
		coordinatorTypesAttemptID(t, 2),
		domain.InvocationInitial,
		1,
	)
	if err != nil {
		t.Fatalf("newCoordinatorInvocationJob() error = %v", err)
	}
	if job.SessionID() != sessionID || job.RunID() != runID {
		t.Fatalf("job coordinates = %q/%q, want %q/%q", job.SessionID().String(), job.RunID().String(), sessionID.String(), runID.String())
	}
}
func TestCoordinatorInvocationJobRejectsIncompleteCoordinates(t *testing.T) {
	t.Parallel()

	runID, err := domain.ParseRunID("r_00000000-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCoordinatorInvocationJob(
		domain.SessionID{},
		runID,
		domain.RoleLogic,
		coordinatorTypesRoute(t, "provider"),
		coordinatorTypesTarget(t, 1),
		coordinatorTypesLimits(t),
		coordinatorTypesAttemptID(t, 2),
		domain.InvocationInitial,
		1,
	); err == nil {
		t.Fatal("newCoordinatorInvocationJob() accepted incomplete coordinates")
	}
}

func TestNewValidatedRoleOutputRejectsInvalidContent(t *testing.T) {
	t.Parallel()

	ordered := coordinatorTypesOrderedFindings(t, []domain.Finding{
		coordinatorTypesFinding(t, "first", domain.RoleLogic, "provider"),
	})
	target := coordinatorTypesTarget(t, 1)
	tests := []struct {
		name             string
		role             domain.Role
		providerInstance string
		findings         []domain.Finding
		completeness     string
	}{
		{
			name:             "role",
			role:             domain.Role("unknown"),
			providerInstance: "provider",
			findings:         ordered,
			completeness:     "complete",
		},
		{
			name:             "provider instance",
			role:             domain.RoleLogic,
			providerInstance: "Provider",
			findings:         ordered,
			completeness:     "complete",
		},
		{
			name:             "completeness",
			role:             domain.RoleLogic,
			providerInstance: "provider",
			findings:         ordered,
			completeness:     "partial",
		},
		{
			name:             "finding role",
			role:             domain.RoleLogic,
			providerInstance: "provider",
			findings: coordinatorTypesOrderedFindings(t, []domain.Finding{
				coordinatorTypesFinding(t, "first", domain.RoleSecurity, "provider"),
			}),
			completeness: "complete",
		},
		{
			name:             "finding provider instance",
			role:             domain.RoleLogic,
			providerInstance: "provider",
			findings: coordinatorTypesOrderedFindings(t, []domain.Finding{
				coordinatorTypesFinding(t, "first", domain.RoleLogic, "other"),
			}),
			completeness: "complete",
		},
		{
			name:             "invalid finding",
			role:             domain.RoleLogic,
			providerInstance: "provider",
			findings:         []domain.Finding{{}},
			completeness:     "complete",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewEvidenceValidatedRoleOutput(
				test.role,
				test.providerInstance,
				target,
				test.findings,
				test.completeness,
				nil,
				bridgeFullyVerifiedEvidence(t, len(test.findings)),
			); err == nil {
				t.Fatal("NewEvidenceValidatedRoleOutput() error = nil")
			}
		})
	}
	if _, err := NewEvidenceValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		domain.TargetIdentity{},
		ordered,
		"complete",
		nil,
		bridgeFullyVerifiedEvidence(t, len(ordered)),
	); err == nil {
		t.Fatal("NewEvidenceValidatedRoleOutput() accepted a zero target")
	}
}
func TestNewValidatedRoleOutputSharesCompletenessValidation(t *testing.T) {
	t.Parallel()
	target := coordinatorTypesTarget(t, 1)

	tooMany := make([]string, 21)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("limitation %d", index)
	}
	tooLong := strings.Repeat("界", 2001)
	invalid := []struct {
		name         string
		completeness string
		limitations  []string
	}{
		{name: "invalid completeness", completeness: "partial"},
		{name: "placeholder casing and whitespace", completeness: "incomplete", limitations: []string{" \tTbD\n"}},
		{name: "duplicate limitation", completeness: "complete", limitations: []string{"Generated fixtures were excluded.", "Generated fixtures were excluded."}},
		{name: "too many limitations", completeness: "complete", limitations: tooMany},
		{name: "limitation exceeds rune limit", completeness: "complete", limitations: []string{tooLong}},
		{name: "complete material files unloaded", completeness: "complete", limitations: []string{"Material files could not be loaded."}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewValidatedRoleOutput(domain.RoleLogic, "provider", target, nil, test.completeness, test.limitations); err == nil {
				t.Fatal("NewValidatedRoleOutput() error = nil")
			}
		})
	}

	valid := []struct {
		name         string
		completeness string
		limitations  []string
	}{
		{name: "complete informational limitation", completeness: "complete", limitations: []string{"Generated fixtures were outside the requested review scope."}},
		{name: "incomplete meaningful limitation", completeness: "incomplete", limitations: []string{"Generated fixtures were outside the requested review scope."}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewValidatedRoleOutput(domain.RoleLogic, "provider", target, nil, test.completeness, test.limitations); err != nil {
				t.Fatalf("NewValidatedRoleOutput() error = %v", err)
			}
		})
	}
	zeroFindingOutput, err := NewValidatedRoleOutput(domain.RoleLogic, "provider", target, nil, "complete", nil)
	if err != nil {
		t.Fatalf("NewValidatedRoleOutput() error = %v", err)
	}
	if got := zeroFindingOutput.Target(); got != target {
		t.Fatalf("zero-finding output target = %#v, want %#v", got, target)
	}
	if _, err := NewValidatedRoleOutput(domain.RoleLogic, "provider", domain.TargetIdentity{}, nil, "complete", nil); err == nil {
		t.Fatal("NewValidatedRoleOutput() accepted a zero target")
	}
}

func TestNewValidatedRoleOutputRejectsUnorderedAndDuplicateFindings(t *testing.T) {
	t.Parallel()
	target := coordinatorTypesTarget(t, 1)

	ordered := coordinatorTypesOrderedFindings(t, []domain.Finding{
		coordinatorTypesFinding(t, "lower", domain.RoleLogic, "provider"),
		coordinatorTypesFinding(t, "higher", domain.RoleLogic, "provider"),
	})
	unordered := []domain.Finding{ordered[1], ordered[0]}
	if _, err := NewEvidenceValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		target,
		unordered,
		"complete",
		nil,
		bridgeFullyVerifiedEvidence(t, len(unordered)),
	); err == nil {
		t.Fatal("NewEvidenceValidatedRoleOutput() error = nil for unordered findings")
	}

	duplicate := coordinatorTypesOrderedFindings(t, []domain.Finding{
		coordinatorTypesFinding(t, "duplicate", domain.RoleLogic, "provider"),
		coordinatorTypesFinding(t, "duplicate", domain.RoleLogic, "provider"),
	})
	if _, err := NewEvidenceValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		target,
		duplicate,
		"complete",
		nil,
		bridgeFullyVerifiedEvidence(t, len(duplicate)),
	); err == nil {
		t.Fatal("NewEvidenceValidatedRoleOutput() error = nil for duplicate findings")
	}
}

func TestValidatedRoleOutputDefensiveCopies(t *testing.T) {
	t.Parallel()
	target := coordinatorTypesTarget(t, 1)

	review, evidenceGroups, err := coordinatorVerifiedEvidenceFixture(
		domain.RoleLogic,
		"provider",
		coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "first",
			path:         "src/coordinator-types-first.go",
			quote:        "first\n",
			targetBytes:  "first\n",
			availability: evidence.ImmutableTargetAvailable,
		},
	)
	if err != nil {
		t.Fatalf("coordinatorVerifiedEvidenceFixture() error = %v", err)
	}
	findings := review.Findings()
	limitations := []string{"scope was limited"}
	output, err := NewEvidenceValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		target,
		findings,
		"incomplete",
		limitations,
		evidenceGroups,
	)
	if err != nil {
		t.Fatalf("NewEvidenceValidatedRoleOutput() error = %v", err)
	}
	if output.Role() != domain.RoleLogic || output.ProviderInstance() != "provider" || output.Completeness() != "incomplete" {
		t.Fatalf("output accessors = %#v", output)
	}
	if got := output.Target(); got != target {
		t.Fatalf("output target = %#v, want %#v", got, target)
	}

	findings[0] = domain.Finding{}
	limitations[0] = "changed"
	evidenceGroups[0] = VerifiedFindingEvidence{}
	returnedFindings := output.Findings()
	returnedEvidence := output.Evidence()
	returnedLimitations := output.Limitations()
	returnedFindings[0] = domain.Finding{}
	returnedEvidence[0] = VerifiedFindingEvidence{}
	returnedLimitations[0] = "changed again"

	if got := output.Findings(); len(got) != 1 || got[0].ID() != "F001" {
		t.Fatalf("findings copy leaked mutation: %#v", got)
	}
	if got := output.Evidence(); len(got) != 1 || got[0].FindingID() != "F001" ||
		len(got[0].Receipts()) != 1 || got[0].Receipts()[0].Status() != evidence.ReceiptVerified {
		t.Fatalf("evidence copy leaked mutation: %#v", got)
	}
	if got := output.Limitations(); len(got) != 1 || got[0] != "scope was limited" {
		t.Fatalf("limitations copy leaked mutation: %#v", got)
	}
}
func TestNewEvidenceValidatedRoleOutputProjectsStructuralEvidence(t *testing.T) {
	t.Parallel()
	target := coordinatorTypesTarget(t, 1)

	review, groups, err := coordinatorVerifiedEvidenceFixture(
		domain.RoleLogic,
		"provider",
		coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "stale",
			path:         "src/output-stale.go",
			quote:        "stale\n",
			availability: evidence.ImmutableTargetStale,
		},
	)
	if err != nil {
		t.Fatalf("coordinatorVerifiedEvidenceFixture() error = %v", err)
	}
	output, err := NewEvidenceValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		target,
		review.Findings(),
		"complete",
		nil,
		groups,
	)
	if err != nil {
		t.Fatalf("NewEvidenceValidatedRoleOutput() error = %v", err)
	}
	if got := output.Findings()[0].EvidenceState(); got != domain.EvidenceOutsideScope {
		t.Fatalf("output evidence state = %q, want %q", got, domain.EvidenceOutsideScope)
	}
	if got := output.Evidence()[0].Receipts()[0].Status(); got != evidence.ReceiptStale {
		t.Fatalf("output receipt status = %q, want %q", got, evidence.ReceiptStale)
	}
}
func TestNewValidatedRoleOutputCannotForgeFindingSuccess(t *testing.T) {
	t.Parallel()

	findings := coordinatorTypesOrderedFindings(t, []domain.Finding{
		coordinatorTypesFinding(t, "forged", domain.RoleLogic, "provider"),
	})
	output, err := NewValidatedRoleOutput(domain.RoleLogic, "provider", coordinatorTypesTarget(t, 1), findings, "complete", nil)
	if err == nil {
		t.Fatalf("NewValidatedRoleOutput() = %#v, nil error; want verifier receipt rejection", output)
	}
}

func TestNewAttemptOutcomeRejectsAmbiguityAndMismatches(t *testing.T) {
	t.Parallel()

	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	output := coordinatorTypesOutput(t, domain.RoleLogic, "provider", nil)
	condition := AttemptConditionTimeout
	invalidCondition := AttemptCondition("unknown")
	validReview := AttemptConditionValidReview

	if _, err := NewAttemptOutcome(job, nil, nil); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil without output or condition")
	}
	if _, err := NewAttemptOutcome(job, &output, &condition); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil with both output and condition")
	}
	if _, err := NewAttemptOutcome(job, nil, &invalidCondition); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil with an unknown condition")
	}
	if _, err := NewAttemptOutcome(job, nil, &validReview); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil for a success condition without output")
	}

	wrongRole := coordinatorTypesOutput(t, domain.RoleSecurity, "provider", nil)
	if _, err := NewAttemptOutcome(job, &wrongRole, nil); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil for output role mismatch")
	}
	wrongProvider := coordinatorTypesOutput(t, domain.RoleLogic, "other", nil)
	if _, err := NewAttemptOutcome(job, &wrongProvider, nil); err == nil {
		t.Fatal("NewAttemptOutcome() error = nil for output provider mismatch")
	}
	targetBOutput, err := NewValidatedRoleOutput(
		domain.RoleLogic,
		"provider",
		coordinatorTypesTarget(t, 2),
		nil,
		"complete",
		nil,
	)
	if err != nil {
		t.Fatalf("NewValidatedRoleOutput() error = %v", err)
	}
	if _, err := NewAttemptOutcome(job, &targetBOutput, nil); err == nil {
		t.Fatal("NewAttemptOutcome() accepted a zero-finding output for a different target")
	}
	mismatchedTargetOutcome := AttemptOutcome{
		job:       job,
		output:    targetBOutput,
		hasOutput: true,
	}
	if mismatchedTargetOutcome.validFor(job) {
		t.Fatal("AttemptOutcome.validFor() accepted a zero-finding output for a different target")
	}
}

func TestProviderTimeoutAttemptOutcomeBindsConfiguredAndElapsedTiming(t *testing.T) {
	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	elapsed := 875 * time.Millisecond
	outcome, err := NewProviderTimeoutAttemptOutcome(job, elapsed)
	if err != nil {
		t.Fatal(err)
	}
	condition, ok := outcome.Condition()
	facts, hasFacts := outcome.ProviderTimeoutFacts()
	if !ok || condition != AttemptConditionProviderTimeout || !hasFacts ||
		facts.ConfiguredTimeout() != job.Limits().Timeout() || facts.Elapsed() != elapsed || !outcome.validFor(job) {
		t.Fatalf("timeout outcome = condition %q/%t facts %#v/%t", condition, ok, facts, hasFacts)
	}
	if _, err := NewProviderTimeoutAttemptOutcome(job, -time.Nanosecond); err == nil {
		t.Fatal("negative elapsed timeout outcome succeeded")
	}
}

func TestAttemptOutcomeAccessorsAreDefensiveAndBoundToJob(t *testing.T) {
	t.Parallel()

	job := coordinatorTypesJob(t, domain.RoleLogic, "provider", 1)
	output := coordinatorTypesOutput(t, domain.RoleLogic, "provider", []string{"scope was limited"})
	outcome, err := NewAttemptOutcome(job, &output, nil)
	if err != nil {
		t.Fatalf("NewAttemptOutcome() error = %v", err)
	}
	if !outcome.Succeeded() || !outcome.validFor(job) {
		t.Fatal("successful outcome is not valid for its job")
	}
	returnedJob := outcome.Job()
	if returnedJob.Role() != job.Role() || returnedJob.AttemptID() != job.AttemptID() || returnedJob.Ordinal() != job.Ordinal() ||
		returnedJob.Route().ProviderInstance() != "provider" || returnedJob.Target() != job.Target() {
		t.Fatalf("outcome job = %#v", returnedJob)
	}
	returnedOutput, ok := outcome.Output()
	if !ok {
		t.Fatal("Output() did not return successful output")
	}
	if returnedOutput.Target() != job.Target() {
		t.Fatalf("outcome output target = %#v, want %#v", returnedOutput.Target(), job.Target())
	}
	returnedFindings := returnedOutput.Findings()
	returnedFindings[0] = domain.Finding{}
	returnedEvidence := returnedOutput.Evidence()
	returnedEvidence[0] = VerifiedFindingEvidence{}
	returnedLimitations := returnedOutput.Limitations()
	returnedLimitations[0] = "changed"
	storedOutput, ok := outcome.Output()
	if !ok || len(storedOutput.Findings()) != 1 || storedOutput.Findings()[0].ID() != "F001" ||
		len(storedOutput.Evidence()) != 1 || storedOutput.Evidence()[0].FindingID() != "F001" ||
		len(storedOutput.Limitations()) != 1 || storedOutput.Limitations()[0] != "scope was limited" {
		t.Fatalf("outcome output copy leaked mutation: %#v", storedOutput)
	}
	if _, ok := outcome.Condition(); ok {
		t.Fatal("successful outcome returned a condition")
	}

	otherJob := coordinatorTypesJob(t, domain.RoleLogic, "provider", 2)
	if outcome.validFor(otherJob) {
		t.Fatal("outcome was valid for a different job identity")
	}

	condition := AttemptConditionProviderUnavailable
	failure, err := NewAttemptOutcome(job, nil, &condition)
	if err != nil {
		t.Fatalf("NewAttemptOutcome() failure error = %v", err)
	}
	if failure.Succeeded() || !failure.validFor(job) {
		t.Fatal("failure outcome has an invalid success state")
	}
	if _, ok := failure.Output(); ok {
		t.Fatal("failure outcome returned output")
	}
	if got, ok := failure.Condition(); !ok || got != condition {
		t.Fatalf("failure condition = %q/%t, want %q/true", got, ok, condition)
	}
}

func TestNilInvocationRuntimeRecognizesTypedNil(t *testing.T) {
	t.Parallel()

	var runtime InvocationRuntime = (*coordinatorTypesNilRuntime)(nil)
	if !nilInvocationRuntime(runtime) {
		t.Fatal("nilInvocationRuntime() = false for typed-nil runtime")
	}
	if nilInvocationRuntime(&coordinatorTypesNilRuntime{}) {
		t.Fatal("nilInvocationRuntime() = true for non-nil runtime")
	}
}

func coordinatorTypesRoute(t *testing.T, providerInstance string) ports.ProviderRoute {
	t.Helper()
	route, err := ports.NewProviderRoute(providerInstance)
	if err != nil {
		t.Fatalf("NewProviderRoute() error = %v", err)
	}
	return route
}

func coordinatorTypesAttemptID(t *testing.T, suffix int) domain.AttemptID {
	t.Helper()

	value := fmt.Sprintf("a_00000000-0000-7000-8000-%012d", suffix)
	attemptID, err := domain.ParseAttemptID(value)
	if err != nil {
		t.Fatalf("ParseAttemptID() error = %v", err)
	}
	return attemptID
}
func coordinatorTypesTarget(t *testing.T, suffix int) domain.TargetIdentity {
	t.Helper()

	target, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind:   domain.TargetStdin,
		SHA256: fmt.Sprintf("%064x", suffix),
	})
	if err != nil {
		t.Fatalf("NewTargetIdentity() error = %v", err)
	}
	return target
}

func coordinatorTypesFinding(t *testing.T, title string, role domain.Role, providerInstance string) domain.Finding {
	t.Helper()

	finding, err := domain.NewFinding(domain.FindingInput{
		Severity:                 domain.SeverityHigh,
		Path:                     "file.go",
		LineStart:                1,
		Role:                     role,
		ProviderInstance:         providerInstance,
		Title:                    title,
		Description:              "description " + title,
		Recommendation:           "recommendation " + title,
		Confidence:               domain.ConfidenceHigh,
		Lifecycle:                domain.FindingOpen,
		EvidenceState:            domain.EvidenceUnverified,
		NormalizedRuleCategory:   title,
		NormalizedEvidenceRegion: "region " + title,
	})
	if err != nil {
		t.Fatalf("NewFinding() error = %v", err)
	}
	return finding
}

func coordinatorTypesOrderedFindings(t *testing.T, findings []domain.Finding) []domain.Finding {
	t.Helper()

	ordered, err := domain.OrderAndAssignFindings(findings)
	if err != nil {
		t.Fatalf("OrderAndAssignFindings() error = %v", err)
	}
	return ordered
}

func coordinatorTypesJob(t *testing.T, role domain.Role, providerInstance string, ordinal uint64) InvocationJob {
	t.Helper()

	job, err := NewInvocationJob(
		role,
		coordinatorTypesRoute(t, providerInstance),
		coordinatorTypesTarget(t, 1),
		coordinatorTypesLimits(t),
		coordinatorTypesAttemptID(t, int(ordinal)),
		domain.InvocationInitial,
		ordinal,
	)
	if err != nil {
		t.Fatalf("NewInvocationJob() error = %v", err)
	}
	return job
}
func coordinatorTypesLimits(t *testing.T) InvocationLimits {
	t.Helper()

	limits, err := NewInvocationLimits(time.Second, 11, 12)
	if err != nil {
		t.Fatalf("NewInvocationLimits() error = %v", err)
	}
	return limits
}

func coordinatorTypesOutput(t *testing.T, role domain.Role, providerInstance string, limitations []string) ValidatedRoleOutput {
	t.Helper()

	review, groups, err := coordinatorVerifiedEvidenceFixture(
		role,
		providerInstance,
		coordinatorEvidenceFixtureInput{
			severity:     domain.SeverityHigh,
			title:        "finding",
			path:         "src/coordinator-types-" + string(role) + ".go",
			quote:        "finding\n",
			targetBytes:  "finding\n",
			availability: evidence.ImmutableTargetAvailable,
		},
	)
	if err != nil {
		t.Fatalf("coordinatorVerifiedEvidenceFixture() error = %v", err)
	}
	output, err := NewEvidenceValidatedRoleOutput(
		role,
		providerInstance,
		coordinatorTypesTarget(t, 1),
		review.Findings(),
		"complete",
		limitations,
		groups,
	)
	if err != nil {
		t.Fatalf("NewEvidenceValidatedRoleOutput() error = %v", err)
	}
	return output
}

type coordinatorTypesNilRuntime struct{}

func (*coordinatorTypesNilRuntime) Invoke(context.Context, InvocationJob) AttemptOutcome {
	return AttemptOutcome{}
}
