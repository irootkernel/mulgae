package review

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// AttemptKind identifies whether an attempt uses the role's primary or fallback
// provider route.
type AttemptKind string

const (
	AttemptKindPrimary  AttemptKind = "primary"
	AttemptKindFallback AttemptKind = "fallback"
)

// Valid reports whether kind is a coordinator-defined attempt kind.
func (kind AttemptKind) Valid() bool {
	return kind == AttemptKindPrimary || kind == AttemptKindFallback
}

// InvocationJob is the immutable, value-only work item sent from the
// coordinator to a provider runtime. It carries no mutable run or attempt
// aggregate.
type InvocationJob struct {
	sessionID   domain.SessionID
	runID       domain.RunID
	role        domain.Role
	attemptKind AttemptKind
	route       ports.ProviderRoute
	target      domain.TargetIdentity
	limits      InvocationLimits
	attemptID   domain.AttemptID
	purpose     domain.InvocationPurpose
	ordinal     uint64
}

// NewInvocationJob validates and canonicalizes a legacy direct provider
// invocation job. Coordinator-issued jobs must use newCoordinatorInvocationJob
// and always carry run coordinates.
func NewInvocationJob(
	role domain.Role,
	attemptKind AttemptKind,
	route ports.ProviderRoute,
	target domain.TargetIdentity,
	limits InvocationLimits,
	attemptID domain.AttemptID,
	purpose domain.InvocationPurpose,
	ordinal uint64,
) (InvocationJob, error) {
	return newInvocationJob(domain.SessionID{}, domain.RunID{}, role, attemptKind, route, target, limits, attemptID, purpose, ordinal)
}

func newCoordinatorInvocationJob(
	sessionID domain.SessionID,
	runID domain.RunID,
	role domain.Role,
	attemptKind AttemptKind,
	route ports.ProviderRoute,
	target domain.TargetIdentity,
	limits InvocationLimits,
	attemptID domain.AttemptID,
	purpose domain.InvocationPurpose,
	ordinal uint64,
) (InvocationJob, error) {
	return newInvocationJob(sessionID, runID, role, attemptKind, route, target, limits, attemptID, purpose, ordinal)
}

func newInvocationJob(
	sessionID domain.SessionID,
	runID domain.RunID,
	role domain.Role,
	attemptKind AttemptKind,
	route ports.ProviderRoute,
	target domain.TargetIdentity,
	limits InvocationLimits,
	attemptID domain.AttemptID,
	purpose domain.InvocationPurpose,
	ordinal uint64,
) (InvocationJob, error) {
	canonicalRoute, err := canonicalCoordinatorRoute(route)
	if err != nil {
		return InvocationJob{}, err
	}
	canonicalTarget, err := canonicalCoordinatorTarget(target)
	if err != nil {
		return InvocationJob{}, err
	}
	job := InvocationJob{
		sessionID:   sessionID,
		runID:       runID,
		role:        role,
		attemptKind: attemptKind,
		route:       canonicalRoute,
		target:      canonicalTarget,
		limits:      limits,
		attemptID:   attemptID,
		purpose:     purpose,
		ordinal:     ordinal,
	}
	if err := job.validate(); err != nil {
		return InvocationJob{}, err
	}
	return job, nil
}

// SessionID returns the coordinator-authorized review session identity, or zero
// for a legacy direct job.
func (job InvocationJob) SessionID() domain.SessionID { return job.sessionID }

// RunID returns the coordinator-authorized review run identity, or zero for a
// legacy direct job.
func (job InvocationJob) RunID() domain.RunID { return job.runID }

// Role returns the canonical coordinator-selected role.
func (job InvocationJob) Role() domain.Role { return job.role }

// AttemptKind returns whether this job uses the primary or fallback route.
func (job InvocationJob) AttemptKind() AttemptKind { return job.attemptKind }

// Route returns a reconstructed canonical provider route.
func (job InvocationJob) Route() ports.ProviderRoute {
	route, err := canonicalCoordinatorRoute(job.route)
	if err != nil {
		return ports.ProviderRoute{}
	}
	return route
}

// Target returns a reconstructed canonical immutable target identity.
func (job InvocationJob) Target() domain.TargetIdentity {
	target, err := canonicalCoordinatorTarget(job.target)
	if err != nil {
		return domain.TargetIdentity{}
	}
	return target
}

// Limits returns the exact validated runtime authority for this invocation.
func (job InvocationJob) Limits() InvocationLimits { return job.limits }

// AttemptID returns the coordinator-issued attempt identity.
func (job InvocationJob) AttemptID() domain.AttemptID { return job.attemptID }

// Purpose returns the initial or repair invocation purpose.
func (job InvocationJob) Purpose() domain.InvocationPurpose { return job.purpose }

// Ordinal returns the stable positive coordinator dispatch ordinal.
func (job InvocationJob) Ordinal() uint64 { return job.ordinal }

func (job InvocationJob) validate() error {
	if (job.sessionID.String() == "") != (job.runID.String() == "") {
		return fmt.Errorf("review coordinator invocation job: session and run IDs must both be present or absent")
	}
	if job.sessionID.String() != "" {
		if _, err := domain.ParseSessionID(job.sessionID.String()); err != nil {
			return fmt.Errorf("review coordinator invocation job: invalid session ID: %w", err)
		}
		if _, err := domain.ParseRunID(job.runID.String()); err != nil {
			return fmt.Errorf("review coordinator invocation job: invalid run ID: %w", err)
		}
	}
	if !job.role.Valid() {
		return fmt.Errorf("review coordinator invocation job: invalid role %q", job.role)
	}
	if !job.attemptKind.Valid() {
		return fmt.Errorf("review coordinator invocation job: invalid attempt kind %q", job.attemptKind)
	}
	if _, err := canonicalCoordinatorRoute(job.route); err != nil {
		return fmt.Errorf("review coordinator invocation job: invalid provider route: %w", err)
	}
	if _, err := canonicalCoordinatorTarget(job.target); err != nil {
		return fmt.Errorf("review coordinator invocation job: invalid target: %w", err)
	}
	if !job.limits.Valid() {
		return fmt.Errorf("review coordinator invocation job: invalid invocation limits")
	}
	if _, err := domain.ParseAttemptID(job.attemptID.String()); err != nil {
		return fmt.Errorf("review coordinator invocation job: invalid attempt ID: %w", err)
	}
	if !job.purpose.Valid() {
		return fmt.Errorf("review coordinator invocation job: invalid invocation purpose %q", job.purpose)
	}
	if job.ordinal == 0 {
		return fmt.Errorf("review coordinator invocation job: ordinal must be positive")
	}
	return nil
}

func (job InvocationJob) clone() InvocationJob {
	clone := job
	clone.route = job.Route()
	clone.target = job.Target()
	return clone
}

func canonicalCoordinatorRoute(route ports.ProviderRoute) (ports.ProviderRoute, error) {
	if !route.Valid() {
		return ports.ProviderRoute{}, fmt.Errorf("provider route is invalid")
	}
	canonical, err := ports.NewProviderRoute(route.ProviderInstance(), route.ConcurrencyKey())
	if err != nil {
		return ports.ProviderRoute{}, err
	}
	return canonical, nil
}

// ValidatedRoleOutput is immutable validated provider content for one role,
// provider instance, and immutable target. It has no transition, policy,
// outcome-axis, or publication authority.
type ValidatedRoleOutput struct {
	role             domain.Role
	providerInstance string
	target           domain.TargetIdentity
	findings         []domain.Finding
	evidence         []VerifiedFindingEvidence
	completeness     string
	limitations      []string
	reportMarkdown   []byte
	reportsOnly      bool
	parseState       domain.ParseState
	validationState  domain.ValidationState
	outputTransport  ports.ProviderOutputTransport
}

// NewValidatedRoleOutput records a zero-finding validated role output. Finding
// output requires verifier-owned receipts and must use
// NewEvidenceValidatedRoleOutput.
func NewValidatedRoleOutput(
	role domain.Role,
	providerInstance string,
	target domain.TargetIdentity,
	findings []domain.Finding,
	completeness string,
	limitations []string,
) (ValidatedRoleOutput, error) {
	canonicalTarget, err := canonicalCoordinatorTarget(target)
	if err != nil {
		return ValidatedRoleOutput{}, err
	}

	if len(findings) != 0 {
		return ValidatedRoleOutput{}, fmt.Errorf(
			"review coordinator role output: findings require verifier-owned evidence receipts",
		)
	}
	output := ValidatedRoleOutput{
		role:             role,
		providerInstance: providerInstance,
		target:           canonicalTarget,
		completeness:     completeness,
		limitations:      append([]string(nil), limitations...),
		parseState:       domain.ParseValid,
		validationState:  domain.ValidationValid,
		outputTransport:  ports.ProviderOutputTransportStdout,
	}
	if err := output.bindReportMarkdown([]byte("# "+string(role)+" review\n\nStructured provider review accepted.\n"), false); err != nil {
		return ValidatedRoleOutput{}, err
	}
	if err := output.validate(); err != nil {
		return ValidatedRoleOutput{}, err
	}
	return output, nil
}

// NewEvidenceValidatedRoleOutput records finding output only after receipt
// groups prove one nonempty verifier-owned group for every assigned finding.
// It projects receipt states with a structural policy; the coordinator applies
// its authoritative policy separately.
func NewEvidenceValidatedRoleOutput(
	role domain.Role,
	providerInstance string,
	target domain.TargetIdentity,
	findings []domain.Finding,
	completeness string,
	limitations []string,
	evidenceGroups []VerifiedFindingEvidence,
) (ValidatedRoleOutput, error) {
	canonicalTarget, err := canonicalCoordinatorTarget(target)
	if err != nil {
		return ValidatedRoleOutput{}, err
	}

	reduced, err := ReduceVerifiedFindingEvidence(findings, evidenceGroups, structuralEvidencePolicy())
	if err != nil {
		return ValidatedRoleOutput{}, fmt.Errorf("review coordinator role output: invalid evidence: %w", err)
	}
	output := ValidatedRoleOutput{
		role:             role,
		providerInstance: providerInstance,
		target:           canonicalTarget,
		findings:         append([]domain.Finding(nil), reduced...),
		evidence:         cloneVerifiedFindingEvidence(evidenceGroups),
		completeness:     completeness,
		limitations:      append([]string(nil), limitations...),
		parseState:       domain.ParseValid,
		validationState:  domain.ValidationValid,
		outputTransport:  ports.ProviderOutputTransportStdout,
	}
	if err := output.bindReportMarkdown([]byte("# "+string(role)+" review\n\nStructured provider review accepted.\n"), false); err != nil {
		return ValidatedRoleOutput{}, err
	}
	if err := output.validate(); err != nil {
		return ValidatedRoleOutput{}, err
	}
	return output, nil
}

// Role returns the selected review role.
func (output ValidatedRoleOutput) Role() domain.Role { return output.role }

// ProviderInstance returns the exact selected provider instance.
func (output ValidatedRoleOutput) ProviderInstance() string { return output.providerInstance }

// Target returns a reconstructed canonical immutable target identity.
func (output ValidatedRoleOutput) Target() domain.TargetIdentity {
	target, err := canonicalCoordinatorTarget(output.target)
	if err != nil {
		return domain.TargetIdentity{}
	}
	return target
}

// Findings returns caller-owned copies in deterministic assigned-ID order.
func (output ValidatedRoleOutput) Findings() []domain.Finding {
	return append([]domain.Finding(nil), output.findings...)
}

// Evidence returns defensive receipt-group copies in deterministic finding-ID
// order.
func (output ValidatedRoleOutput) Evidence() []VerifiedFindingEvidence {
	return cloneVerifiedFindingEvidence(output.evidence)
}

// Completeness returns the validated provider-declared review completeness.
func (output ValidatedRoleOutput) Completeness() string { return output.completeness }

// Limitations returns a caller-owned copy of the validated limitations.
func (output ValidatedRoleOutput) Limitations() []string {
	return append([]string(nil), output.limitations...)
}

// OutputTransport returns the transport that carried the accepted provider
// content. An output that records no explicit transport was carried by process
// stdout, which keeps every legacy accept path unchanged.
func (output ValidatedRoleOutput) OutputTransport() ports.ProviderOutputTransport {
	if output.outputTransport == "" {
		return ports.ProviderOutputTransportStdout
	}
	return output.outputTransport
}

func (output *ValidatedRoleOutput) bindOutputTransport(transport ports.ProviderOutputTransport) error {
	if transport == "" {
		transport = ports.ProviderOutputTransportStdout
	}
	if !transport.Valid() {
		return fmt.Errorf("invalid provider output transport %q", transport)
	}
	output.outputTransport = transport
	return nil
}

func (output ValidatedRoleOutput) validate() error {
	if !output.role.Valid() {
		return fmt.Errorf("review coordinator role output: invalid role %q", output.role)
	}
	if !validCoordinatorProviderInstance(output.providerInstance) {
		return fmt.Errorf("review coordinator role output: invalid provider instance %q", output.providerInstance)
	}
	if _, err := canonicalCoordinatorTarget(output.target); err != nil {
		return fmt.Errorf("review coordinator role output: invalid target: %w", err)
	}
	if err := validation.ValidateReviewCompleteness(output.completeness, output.limitations); err != nil {
		return fmt.Errorf("review coordinator role output: %w", err)
	}

	ordered, err := domain.OrderAndAssignFindings(output.findings)
	if err != nil {
		return fmt.Errorf("review coordinator role output: invalid findings: %w", err)
	}
	for index := range ordered {
		finding := output.findings[index]
		if finding.Role() != output.role {
			return fmt.Errorf("review coordinator role output: finding %d role %q does not match output role %q", index, finding.Role(), output.role)
		}
		if finding.ProviderInstance() != output.providerInstance {
			return fmt.Errorf("review coordinator role output: finding %d provider instance %q does not match output provider instance %q", index, finding.ProviderInstance(), output.providerInstance)
		}
		if !sameCoordinatorFinding(finding, ordered[index]) {
			return fmt.Errorf("review coordinator role output: findings are not the exact deterministic order-and-assign result")
		}
	}
	if duplicateCoordinatorFinding(output.findings) {
		return fmt.Errorf("review coordinator role output: duplicate normalized finding")
	}
	if _, err := normalizeRoleReportMarkdown(output.reportMarkdown); err != nil {
		return fmt.Errorf("review coordinator role output: %w", err)
	}
	if !output.parseState.Valid() || !output.validationState.Valid() {
		return fmt.Errorf("review coordinator role output: extraction states are invalid")
	}
	if !output.OutputTransport().Valid() {
		return fmt.Errorf("review coordinator role output: invalid provider output transport %q", output.outputTransport)
	}
	if output.reportsOnly {
		if len(output.findings) != 0 || len(output.evidence) != 0 {
			return fmt.Errorf("review coordinator role output: reports-only output cannot retain structured findings")
		}
		return nil
	}
	if len(output.findings) == 0 {
		if len(output.evidence) != 0 {
			return fmt.Errorf("review coordinator role output: zero-finding output cannot retain evidence receipts")
		}
		return nil
	}

	reduced, err := ReduceVerifiedFindingEvidence(output.findings, output.evidence, structuralEvidencePolicy())
	if err != nil {
		return fmt.Errorf("review coordinator role output: invalid evidence: %w", err)
	}
	for index := range reduced {
		if !sameCoordinatorFinding(output.findings[index], reduced[index]) {
			return fmt.Errorf("review coordinator role output: findings do not match verifier receipt evidence states")
		}
	}
	return nil
}

func (output ValidatedRoleOutput) clone() ValidatedRoleOutput {
	return ValidatedRoleOutput{
		role:             output.role,
		providerInstance: output.providerInstance,
		target:           output.Target(),
		findings:         append([]domain.Finding(nil), output.findings...),
		evidence:         cloneVerifiedFindingEvidence(output.evidence),
		completeness:     output.completeness,
		limitations:      append([]string(nil), output.limitations...),
		reportMarkdown:   append([]byte(nil), output.reportMarkdown...),
		reportsOnly:      output.reportsOnly,
		parseState:       output.parseState,
		validationState:  output.validationState,
		outputTransport:  output.outputTransport,
	}
}

func validCoordinatorProviderInstance(providerInstance string) bool {
	key, err := ports.ParseConcurrencyKey("provider")
	if err != nil {
		return false
	}
	_, err = ports.NewProviderRoute(providerInstance, key)
	return err == nil
}

type coordinatorFindingIdentity struct {
	fingerprint              string
	severity                 domain.Severity
	path                     string
	lineStart                int
	role                     domain.Role
	providerInstance         string
	title                    string
	description              string
	recommendation           string
	confidence               domain.Confidence
	lifecycle                domain.FindingLifecycle
	evidenceState            domain.EvidenceState
	normalizedRuleCategory   string
	normalizedEvidenceRegion string
}

func coordinatorFindingIdentityFor(finding domain.Finding) coordinatorFindingIdentity {
	return coordinatorFindingIdentity{
		fingerprint:              finding.Fingerprint(),
		severity:                 finding.Severity(),
		path:                     finding.Path(),
		lineStart:                finding.LineStart(),
		role:                     finding.Role(),
		providerInstance:         finding.ProviderInstance(),
		title:                    finding.Title(),
		description:              finding.Description(),
		recommendation:           finding.Recommendation(),
		confidence:               finding.Confidence(),
		lifecycle:                finding.Lifecycle(),
		evidenceState:            finding.EvidenceState(),
		normalizedRuleCategory:   finding.NormalizedRuleCategory(),
		normalizedEvidenceRegion: finding.NormalizedEvidenceRegion(),
	}
}

func sameCoordinatorFinding(left, right domain.Finding) bool {
	return left.ID() == right.ID() &&
		coordinatorFindingIdentityFor(left) == coordinatorFindingIdentityFor(right)
}

func duplicateCoordinatorFinding(findings []domain.Finding) bool {
	seen := make(map[coordinatorFindingIdentity]struct{}, len(findings))
	for _, finding := range findings {
		identity := coordinatorFindingIdentityFor(finding)
		if _, duplicate := seen[identity]; duplicate {
			return true
		}
		seen[identity] = struct{}{}
	}
	return false
}

// AttemptOutcome is one immutable provider-runtime response for one invocation
// job. It contains either validated role content or one closed failure
// condition, never both.
type AttemptOutcome struct {
	job             InvocationJob
	output          ValidatedRoleOutput
	condition       AttemptCondition
	timeoutFacts    ProviderTimeoutFacts
	hasOutput       bool
	hasCondition    bool
	hasTimeoutFacts bool
}

// ProviderTimeoutFacts contains only safe timing facts from a provider process
// boundary. Configured is bound to the coordinator job, and elapsed is derived
// from validated process timestamps or a local monotonic measurement; no
// provider streams are retained.
type ProviderTimeoutFacts struct {
	configured time.Duration
	elapsed    time.Duration
}

func NewProviderTimeoutFacts(configured, elapsed time.Duration) (ProviderTimeoutFacts, error) {
	facts := ProviderTimeoutFacts{configured: configured, elapsed: elapsed}
	if !facts.Valid() {
		return ProviderTimeoutFacts{}, fmt.Errorf("provider timeout facts: invalid timing")
	}
	return facts, nil
}

func (facts ProviderTimeoutFacts) ConfiguredTimeout() time.Duration { return facts.configured }
func (facts ProviderTimeoutFacts) Elapsed() time.Duration           { return facts.elapsed }
func (facts ProviderTimeoutFacts) Valid() bool {
	return facts.configured > 0 && facts.elapsed >= 0
}

// NewAttemptOutcome constructs a success with output or a failure with a closed
// condition. Successful outputs must retain the exact job role, provider, and target.
func NewAttemptOutcome(
	job InvocationJob,
	output *ValidatedRoleOutput,
	condition *AttemptCondition,
) (AttemptOutcome, error) {
	if err := job.validate(); err != nil {
		return AttemptOutcome{}, fmt.Errorf("review coordinator attempt outcome: invalid job: %w", err)
	}
	if (output == nil) == (condition == nil) {
		return AttemptOutcome{}, fmt.Errorf("review coordinator attempt outcome: exactly one output or condition is required")
	}

	outcome := AttemptOutcome{job: job.clone()}
	if output != nil {
		if err := output.validate(); err != nil {
			return AttemptOutcome{}, fmt.Errorf("review coordinator attempt outcome: invalid output: %w", err)
		}
		if output.role != job.role || output.providerInstance != job.route.ProviderInstance() || output.target != job.target {
			return AttemptOutcome{}, fmt.Errorf("review coordinator attempt outcome: output role, provider instance, or target does not match job")
		}
		outcome.output = output.clone()
		outcome.hasOutput = true
		return outcome, nil
	}

	if !condition.Valid() || *condition == AttemptConditionValidReview {
		return AttemptOutcome{}, fmt.Errorf("review coordinator attempt outcome: invalid failure condition %q", *condition)
	}
	outcome.condition = *condition
	outcome.hasCondition = true
	return outcome, nil
}

// NewProviderTimeoutAttemptOutcome binds one observed provider timeout to the
// exact configured job limit and a safe elapsed duration.
func NewProviderTimeoutAttemptOutcome(job InvocationJob, elapsed time.Duration) (AttemptOutcome, error) {
	condition := AttemptConditionProviderTimeout
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err != nil {
		return AttemptOutcome{}, err
	}
	facts, err := NewProviderTimeoutFacts(job.Limits().Timeout(), elapsed)
	if err != nil {
		return AttemptOutcome{}, err
	}
	outcome.timeoutFacts = facts
	outcome.hasTimeoutFacts = true
	return outcome, nil
}

// Job returns a defensive value copy of the invocation job this outcome answers.
func (outcome AttemptOutcome) Job() InvocationJob { return outcome.job.clone() }

// Succeeded reports whether this outcome contains validated role output.
func (outcome AttemptOutcome) Succeeded() bool { return outcome.hasOutput }

// Output returns a defensive copy of the validated role output on success.
func (outcome AttemptOutcome) Output() (ValidatedRoleOutput, bool) {
	if !outcome.hasOutput {
		return ValidatedRoleOutput{}, false
	}
	return outcome.output.clone(), true
}

// Condition returns the closed failure condition when this outcome failed.
func (outcome AttemptOutcome) Condition() (AttemptCondition, bool) {
	return outcome.condition, outcome.hasCondition
}

func (outcome AttemptOutcome) ProviderTimeoutFacts() (ProviderTimeoutFacts, bool) {
	return outcome.timeoutFacts, outcome.hasTimeoutFacts
}

func (outcome AttemptOutcome) validFor(job InvocationJob) bool {
	if err := job.validate(); err != nil || outcome.job != job {
		return false
	}
	if outcome.hasOutput == outcome.hasCondition {
		return false
	}
	if outcome.hasTimeoutFacts && (!outcome.timeoutFacts.Valid() ||
		outcome.condition != AttemptConditionProviderTimeout ||
		outcome.timeoutFacts.configured != job.limits.timeout) {
		return false
	}
	if !outcome.hasCondition && outcome.hasTimeoutFacts {
		return false
	}
	if outcome.hasOutput {
		if err := outcome.output.validate(); err != nil {
			return false
		}
		return outcome.output.role == job.role &&
			outcome.output.providerInstance == job.route.ProviderInstance() &&
			outcome.output.target == job.target
	}
	return outcome.condition.Valid() && outcome.condition != AttemptConditionValidReview
}

// InvocationRuntime executes immutable jobs. Calls for jobs in distinct
// provider concurrency lanes may occur concurrently. The runtime MUST enforce
// job.Limits() timeout, stdout, and stderr capture caps. Both the job and
// outcome are value-only boundaries and must not carry mutable coordinator
// state.
type InvocationRuntime interface {
	Invoke(context.Context, InvocationJob) AttemptOutcome
}

func nilInvocationRuntime(runtime InvocationRuntime) bool {
	if runtime == nil {
		return true
	}
	value := reflect.ValueOf(runtime)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
