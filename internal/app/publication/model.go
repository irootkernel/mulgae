// Package publication builds deterministic, schema-validated publication records.
package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/review"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	finalReviewSchemaAsset = "https://kar.local/schemas/kar-review-artifact.v2.schema.json"
	runManifestSchemaAsset = "https://kar.local/schemas/kar-run-manifest.v2.schema.json"

	targetManifestPath   = "target/target-manifest.json"
	aggregationPath      = "aggregation.json"
	finalValidationPath  = "validation/final-validation.json"
	publicationJournalV1 = "kar-publication-journal.v1"
	publicationStatusV1  = "kar-publication-status.v1"
	lineageEdgeV1        = "kar-lineage-edge.v1"
	publicationEpochV1   = "kar-publication-epoch.v1"
)

// SchemaValidator validates bytes against one embedded schema asset. It is
// consumer-owned because publication owns byte construction, not schema lookup.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// PreparedCandidate is a fully semantically validated terminal review result.
// It deliberately has no ReviewID. A ReviewID is supplied only after this
// pre-publication validation has completed.
type PreparedCandidate struct {
	sessionID domain.SessionID
	runID     domain.RunID
	runState  domain.RunState
	target    preparedTarget
	threshold domain.Severity
	kar       preparedKAR
	axes      preparedAxes
	roles     []preparedRole
	findings  []preparedFinding
	failures  []preparedFailure
	limits    []string
	reasons   []string
	exitCode  int
}

type preparedTarget struct {
	sha256  string
	baseOID string
	headOID string
}

type preparedKAR struct {
	version string
	commit  string
}

type preparedAxes struct {
	content  domain.ContentVerdict
	coverage domain.CoverageStatus
	ci       domain.CIDecision
}

type preparedRole struct {
	role            domain.Role
	required        bool
	state           domain.RoleTaskState
	valid           bool
	degraded        bool
	repaired        bool
	failureClass    domain.FailureClass
	failureReason   string
	attempts        []preparedAttempt
	validFindingIDs []string
	outcome         string
	limitations     []string
}

type preparedAttempt struct {
	id          domain.AttemptID
	kind        review.AttemptKind
	provider    string
	state       domain.AttemptState
	invocations []preparedInvocation
}

type preparedInvocation struct {
	sequence uint64
	purpose  domain.InvocationPurpose
	state    domain.InvocationState
}

type preparedFinding struct {
	id             string
	fingerprint    string
	role           domain.Role
	provider       string
	severity       domain.Severity
	title          string
	description    string
	recommendation string
	confidence     domain.Confidence
	lifecycle      domain.FindingLifecycle
	evidence       []preparedEvidence
}

type preparedEvidence struct {
	targetSHA256  string
	side          evidence.Side
	path          string
	lineStart     int
	lineEnd       int
	quote         string
	excerptSHA256 string
	excerpt       []byte
}

type preparedFailure struct {
	class     domain.FailureClass
	stage     string
	reason    string
	attemptID *domain.AttemptID
}

// PublicationDocument is an exact mutable publication record. Bytes returns a
// caller-owned copy; its path and digest identify the complete replacement.
type PublicationDocument struct {
	path   ports.SafeRelativePath
	sha256 string
	bytes  []byte
}

// Path returns the canonical mutable record path.
func (document PublicationDocument) Path() ports.SafeRelativePath { return document.path }

// SHA256 returns the canonical exact-byte digest.
func (document PublicationDocument) SHA256() string { return document.sha256 }

// Bytes returns a caller-owned copy of the exact record bytes.
func (document PublicationDocument) Bytes() []byte { return cloneBytes(document.bytes) }

// Valid reports whether this document has a coherent immutable identity.
func (document PublicationDocument) Valid() bool {
	return document.path.Valid() && validSHA256(document.sha256) &&
		document.sha256 == sha256Identifier(document.bytes)
}

// PublicationBundle is the defensive publication payload for one P2 composite.
// Its authority is represented solely by serialized records; this Go value has
// no authority flag or authorization accessor.
type PublicationBundle struct {
	final       ports.FinalReviewArtifact
	manifest    ports.ImmutablePublicationArtifact
	lineageEdge ports.ImmutablePublicationArtifact
	epoch       ports.PublicationEpoch
	staged      ports.ImmutablePublicationArtifact
	journal     PublicationDocument
	status      PublicationDocument
	excerpts    []ports.ImmutablePublicationArtifact
}

// Final returns the final review artifact with defensive byte accessors.
func (bundle PublicationBundle) Final() ports.FinalReviewArtifact { return bundle.final }

// Manifest returns the immutable committed manifest.
func (bundle PublicationBundle) Manifest() ports.ImmutablePublicationArtifact { return bundle.manifest }

// LineageEdge returns the immutable root-review lineage edge.
func (bundle PublicationBundle) LineageEdge() ports.ImmutablePublicationArtifact {
	return bundle.lineageEdge
}

// Epoch returns the positive immutable epoch record.
func (bundle PublicationBundle) Epoch() ports.PublicationEpoch { return bundle.epoch }

// StagedFinal returns final bytes at their required staged temporary identity.
func (bundle PublicationBundle) StagedFinal() ports.ImmutablePublicationArtifact {
	return bundle.staged
}

// Journal returns the exact mutable journal replacement.
func (bundle PublicationBundle) Journal() PublicationDocument { return bundle.journal }

// Status returns the exact mutable status replacement.
func (bundle PublicationBundle) Status() PublicationDocument { return bundle.status }

// Excerpts returns caller-owned immutable excerpt artifact values.
func (bundle PublicationBundle) Excerpts() []ports.ImmutablePublicationArtifact {
	return append([]ports.ImmutablePublicationArtifact(nil), bundle.excerpts...)
}

// Valid reports whether every bundle member remains self-consistent. It does
// not assert reader authority; only the serialized P2 records can do that.
func (bundle PublicationBundle) Valid() bool {
	if !bundle.final.Valid() || !bundle.manifest.Valid() || !bundle.lineageEdge.Valid() ||
		!bundle.epoch.Valid() || !bundle.staged.Valid() || !bundle.journal.Valid() || !bundle.status.Valid() {
		return false
	}
	for _, excerpt := range bundle.excerpts {
		if !excerpt.Valid() {
			return false
		}
	}
	return validatePublicationBundleSemantics(bundle) == nil
}

// PrepareCandidate validates every semantic fact available before a ReviewID is
// issued. It accepts only root review publication and therefore always records
// run_type=review and root lineage in its eventual serialized artifacts.
func PrepareCandidate(
	result review.CoordinatorResult,
	target domain.TargetIdentity,
	severityThreshold domain.Severity,
	karVersion string,
	karCommit string,
) (PreparedCandidate, error) {
	if err := validateIdentity(result.SessionID(), result.RunID()); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: result identity: %w", err)
	}
	if err := validateTarget(target); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: target: %w", err)
	}
	if severityThreshold == "" {
		severityThreshold = domain.SeverityHigh
	}
	if !severityThreshold.Valid() {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: invalid severity threshold %q", severityThreshold)
	}
	if err := validateBuildMetadata(karVersion, karCommit); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: build metadata: %w", err)
	}

	roles, failures, err := prepareRoles(result.RoleSummaries())
	if err != nil {
		return PreparedCandidate{}, err
	}
	findings, err := prepareFindings(result.Findings(), result.Evidence(), target, roles)
	if err != nil {
		return PreparedCandidate{}, err
	}
	bindFindingIDs(roles, findings)
	for index := range roles {
		if err := validatePreparedRole(roles[index]); err != nil {
			return PreparedCandidate{}, fmt.Errorf("publication candidate: role %q: %w", roles[index].role, err)
		}
	}

	axes, reasons, exitCode, limits, err := validateOutcomeAxes(result, roles, findings, severityThreshold)
	if err != nil {
		return PreparedCandidate{}, err
	}
	if err := validateTerminalRun(result.RunState(), roles, axes.coverage); err != nil {
		return PreparedCandidate{}, err
	}

	candidate := PreparedCandidate{
		sessionID: result.SessionID(),
		runID:     result.RunID(),
		runState:  result.RunState(),
		target: preparedTarget{
			sha256:  "sha256:" + target.SHA256(),
			baseOID: target.BaseObjectID(),
			headOID: target.HeadObjectID(),
		},
		threshold: severityThreshold,
		kar: preparedKAR{
			version: karVersion,
			commit:  karCommit,
		},
		axes:     axes,
		roles:    clonePreparedRoles(roles),
		findings: clonePreparedFindings(findings),
		failures: clonePreparedFailures(failures),
		limits:   append([]string(nil), limits...),
		reasons:  append([]string(nil), reasons...),
		exitCode: exitCode,
	}
	if err := candidate.validate(); err != nil {
		return PreparedCandidate{}, err
	}
	return candidate, nil
}

// Valid reports whether this value is a complete semantic pre-publication
// candidate. A zero value is never valid.
func (candidate PreparedCandidate) Valid() bool { return candidate.validate() == nil }

// SessionID returns the immutable review-session identity bound by validation.
func (candidate PreparedCandidate) SessionID() domain.SessionID { return candidate.sessionID }

// RunID returns the immutable review-run identity bound by validation.
func (candidate PreparedCandidate) RunID() domain.RunID { return candidate.runID }

// ValidatedCandidateSHA256 returns a deterministic, domain-separated identity
// over every semantic input validated before ReviewID issuance. It returns an
// empty string for an invalid candidate.
func (candidate PreparedCandidate) ValidatedCandidateSHA256() string {
	if !candidate.Valid() {
		return ""
	}
	digest := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(value))
	}
	write("KAR-PUBLICATION-CANDIDATE/1")
	write(candidate.sessionID.String())
	write(candidate.runID.String())
	write(string(candidate.runState))
	write(candidate.target.sha256)
	write(candidate.target.baseOID)
	write(candidate.target.headOID)
	write(string(candidate.threshold))
	write(candidate.kar.version)
	write(candidate.kar.commit)
	write(string(candidate.axes.content))
	write(string(candidate.axes.coverage))
	write(string(candidate.axes.ci))
	for _, role := range candidate.roles {
		write(string(role.role))
		write(fmt.Sprintf("%t", role.required))
		write(string(role.state))
		write(fmt.Sprintf("%t", role.valid))
		write(fmt.Sprintf("%t", role.degraded))
		write(fmt.Sprintf("%t", role.repaired))
		write(role.outcome)
		write(string(role.failureClass))
		write(role.failureReason)
		for _, attempt := range role.attempts {
			write(attempt.id.String())
			write(string(attempt.kind))
			write(attempt.provider)
			write(string(attempt.state))
			for _, invocation := range attempt.invocations {
				write(fmt.Sprintf("%d", invocation.sequence))
				write(string(invocation.purpose))
				write(string(invocation.state))
			}
		}
		for _, findingID := range role.validFindingIDs {
			write(findingID)
		}
		for _, limitation := range role.limitations {
			write(limitation)
		}
	}
	for _, finding := range candidate.findings {
		write(finding.id)
		write(finding.fingerprint)
		write(string(finding.role))
		write(finding.provider)
		write(string(finding.severity))
		write(finding.title)
		write(finding.description)
		write(finding.recommendation)
		write(string(finding.confidence))
		write(string(finding.lifecycle))
		for _, item := range finding.evidence {
			write(item.targetSHA256)
			write(string(item.side))
			write(item.path)
			write(fmt.Sprintf("%d", item.lineStart))
			write(fmt.Sprintf("%d", item.lineEnd))
			write(item.quote)
			write(item.excerptSHA256)
			write(string(item.excerpt))
		}
	}
	for _, failure := range candidate.failures {
		write(string(failure.class))
		write(failure.stage)
		write(failure.reason)
		if failure.attemptID == nil {
			write("")
		} else {
			write(failure.attemptID.String())
		}
	}
	for _, limitation := range candidate.limits {
		write(limitation)
	}
	for _, reason := range candidate.reasons {
		write(reason)
	}
	write(fmt.Sprintf("%d", candidate.exitCode))
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func (candidate PreparedCandidate) validate() error {
	if err := validateIdentity(candidate.sessionID, candidate.runID); err != nil {
		return err
	}
	if candidate.runState != domain.RunCompleted && candidate.runState != domain.RunDegraded && candidate.runState != domain.RunFailed {
		return fmt.Errorf("run state %q is not publishable", candidate.runState)
	}
	if !candidate.threshold.Valid() || !validSHA256(candidate.target.sha256) ||
		!validOptionalOID(candidate.target.baseOID) || !validOptionalOID(candidate.target.headOID) {
		return fmt.Errorf("target or threshold is invalid")
	}
	if err := validateBuildMetadata(candidate.kar.version, candidate.kar.commit); err != nil {
		return err
	}
	if !candidate.axes.content.Valid() || !candidate.axes.coverage.Valid() || !candidate.axes.ci.Valid() {
		return fmt.Errorf("outcome axes are invalid")
	}
	if len(candidate.roles) == 0 || len(candidate.reasons) == 0 || !validNormalExit(candidate.exitCode) {
		return fmt.Errorf("candidate has incomplete role, reason, or exit data")
	}
	seenRoles := make(map[domain.Role]struct{}, len(candidate.roles))
	for index := range candidate.roles {
		role := candidate.roles[index]
		if _, duplicate := seenRoles[role.role]; duplicate {
			return fmt.Errorf("duplicate role %q", role.role)
		}
		seenRoles[role.role] = struct{}{}
		if err := validatePreparedRole(role); err != nil {
			return fmt.Errorf("role %q: %w", role.role, err)
		}
		if index > 0 && roleOrdinal(candidate.roles[index-1].role) >= roleOrdinal(role.role) {
			return fmt.Errorf("roles are not in deterministic order")
		}
	}
	if _, ok := seenRoles[domain.RoleLogic]; !ok {
		return fmt.Errorf("required logic role is absent")
	}
	if _, ok := seenRoles[domain.RoleSecurity]; !ok {
		return fmt.Errorf("required security role is absent")
	}
	if err := validatePreparedFindings(candidate.findings, candidate.roles, candidate.target.sha256); err != nil {
		return err
	}
	if err := validatePreparedFailures(candidate.failures, candidate.roles); err != nil {
		return err
	}
	if err := validateStringSlice(candidate.limits, 100, 2000, true); err != nil {
		return fmt.Errorf("limitations: %w", err)
	}
	if err := validateReasonCodes(candidate.reasons); err != nil {
		return err
	}
	if err := validateTerminalRun(candidate.runState, candidate.roles, candidate.axes.coverage); err != nil {
		return err
	}
	return nil
}

func prepareRoles(summaries []review.CoordinatorRoleSummary) ([]preparedRole, []preparedFailure, error) {
	if len(summaries) == 0 {
		return nil, nil, fmt.Errorf("publication candidate: result has no role summaries")
	}
	roles := make([]preparedRole, 0, len(summaries))
	failures := make([]preparedFailure, 0)
	seen := make(map[domain.Role]struct{}, len(summaries))
	seenAttempts := make(map[string]struct{})
	for index, summary := range summaries {
		role := summary.Role()
		if !role.Valid() {
			return nil, nil, fmt.Errorf("publication candidate: role summary %d has invalid role", index)
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, nil, fmt.Errorf("publication candidate: duplicate role %q", role)
		}
		seen[role] = struct{}{}
		if index > 0 && roleOrdinal(summaries[index-1].Role()) >= roleOrdinal(role) {
			return nil, nil, fmt.Errorf("publication candidate: role summaries are not in fixed order")
		}
		if !terminalRoleState(summary.State()) {
			return nil, nil, fmt.Errorf("publication candidate: role %q is not terminal", role)
		}
		attempts := summary.Attempts()
		if len(attempts) == 0 {
			return nil, nil, fmt.Errorf("publication candidate: role %q has no terminal attempt", role)
		}
		preparedAttempts := make([]preparedAttempt, len(attempts))
		for attemptIndex, attempt := range attempts {
			if _, err := domain.ParseAttemptID(attempt.ID().String()); err != nil {
				return nil, nil, fmt.Errorf("publication candidate: role %q attempt %d: invalid ID", role, attemptIndex)
			}
			if _, duplicate := seenAttempts[attempt.ID().String()]; duplicate {
				return nil, nil, fmt.Errorf("publication candidate: duplicate attempt ID %q", attempt.ID())
			}
			seenAttempts[attempt.ID().String()] = struct{}{}
			if !attempt.Kind().Valid() || !attempt.Route().Valid() || !terminalAttemptState(attempt.State()) {
				return nil, nil, fmt.Errorf("publication candidate: role %q has invalid terminal attempt", role)
			}
			invocations := attempt.Invocations()
			if len(invocations) == 0 {
				return nil, nil, fmt.Errorf("publication candidate: role %q attempt %q has no invocations", role, attempt.ID())
			}
			preparedInvocations := make([]preparedInvocation, len(invocations))
			for invocationIndex, invocation := range invocations {
				if invocation.Sequence() != uint64(invocationIndex+1) || !invocation.Purpose().Valid() || !terminalInvocationState(invocation.State()) {
					return nil, nil, fmt.Errorf("publication candidate: role %q attempt %q has inconsistent invocation %d", role, attempt.ID(), invocationIndex)
				}
				preparedInvocations[invocationIndex] = preparedInvocation{
					sequence: invocation.Sequence(), purpose: invocation.Purpose(), state: invocation.State(),
				}
			}
			preparedAttempts[attemptIndex] = preparedAttempt{
				id: attempt.ID(), kind: attempt.Kind(), provider: attempt.Route().ProviderInstance(), state: attempt.State(), invocations: preparedInvocations,
			}
		}

		finalAttempt := preparedAttempts[len(preparedAttempts)-1]
		roleResult := preparedRole{
			role:          role,
			required:      summary.Required() || role == domain.RoleLogic || role == domain.RoleSecurity,
			state:         summary.State(),
			valid:         summary.Valid(),
			degraded:      summary.Degraded(),
			repaired:      summary.Repaired(),
			failureClass:  summary.FailureClass(),
			failureReason: summary.ReasonCode(),
			attempts:      preparedAttempts,
		}
		if summary.Valid() {
			if summary.State() != domain.RoleTaskSucceeded || finalAttempt.state != domain.AttemptSucceeded ||
				summary.FailureClass() != "" || summary.ReasonCode() != "" {
				return nil, nil, fmt.Errorf("publication candidate: successful role %q is inconsistent", role)
			}
			if summary.Degraded() {
				roleResult.outcome = "degraded"
				roleResult.limitations = []string{"Role coverage is degraded."}
			} else {
				roleResult.outcome = "completed"
				roleResult.limitations = []string{}
			}
		} else {
			if summary.State() != domain.RoleTaskFailed || !summary.FailureClass().Valid() ||
				!validReasonCode(summary.ReasonCode()) || finalAttempt.state == domain.AttemptSucceeded {
				return nil, nil, fmt.Errorf("publication candidate: failed role %q is inconsistent", role)
			}
			if forbiddenPublicationFailure(summary.FailureClass()) {
				return nil, nil, fmt.Errorf("publication candidate: role %q has non-publishable failure %q", role, summary.FailureClass())
			}
			roleResult.outcome = "failed"
			roleResult.limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
			attemptID := finalAttempt.id
			failures = append(failures, preparedFailure{
				class: summary.FailureClass(), stage: "review", reason: summary.ReasonCode(), attemptID: &attemptID,
			})
		}
		roles = append(roles, roleResult)
	}
	return roles, failures, nil
}

func prepareFindings(
	findings []domain.Finding,
	groups []review.VerifiedFindingEvidence,
	target domain.TargetIdentity,
	roles []preparedRole,
) ([]preparedFinding, error) {
	if len(findings) != len(groups) {
		return nil, fmt.Errorf("publication candidate: finding and evidence counts differ")
	}
	byRole := make(map[domain.Role]preparedRole, len(roles))
	for _, role := range roles {
		byRole[role.role] = role
	}
	prepared := make([]preparedFinding, len(findings))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID() != expectedID || finding.Validate() != nil || groups[index].FindingID() != expectedID {
			return nil, fmt.Errorf("publication candidate: finding %d does not have exact ordered evidence binding", index)
		}
		role, exists := byRole[finding.Role()]
		if !exists || !role.valid || role.attempts[len(role.attempts)-1].provider != finding.ProviderInstance() {
			return nil, fmt.Errorf("publication candidate: finding %q has inconsistent role or provider binding", expectedID)
		}
		if err := validateFindingStrings(finding); err != nil {
			return nil, fmt.Errorf("publication candidate: finding %q: %w", expectedID, err)
		}
		receipts := groups[index].Receipts()
		if len(receipts) == 0 {
			return nil, fmt.Errorf("publication candidate: finding %q has no current evidence receipts", expectedID)
		}
		preparedReceipts := make([]preparedEvidence, len(receipts))
		for receiptIndex, receipt := range receipts {
			if receipt.Status() != evidence.ReceiptVerified || receipt.ReasonCode() != evidence.ReasonVerified {
				return nil, fmt.Errorf("publication candidate: finding %q receipt %d is not verified", expectedID, receiptIndex)
			}
			claim := receipt.Claim()
			if claim.TargetSHA256() != "sha256:"+target.SHA256() || !claim.Side().Valid() || !claim.Path().Valid() ||
				claim.LineStart() < 1 || claim.LineEnd() < claim.LineStart() || !safeText(claim.Quote(), 8000, false) {
				return nil, fmt.Errorf("publication candidate: finding %q receipt %d has invalid current claim", expectedID, receiptIndex)
			}
			excerpt := receipt.Excerpt()
			if len(excerpt) == 0 || !utf8.Valid(excerpt) || !bytes.Equal(claim.QuoteBytes(), excerpt) {
				return nil, fmt.Errorf("publication candidate: finding %q receipt %d has inconsistent verified excerpt", expectedID, receiptIndex)
			}
			excerptSHA256, err := claim.ExcerptSHA256(excerpt)
			if err != nil || receipt.ExcerptSHA256() != excerptSHA256 {
				return nil, fmt.Errorf("publication candidate: finding %q receipt %d has inconsistent excerpt identity", expectedID, receiptIndex)
			}
			preparedReceipts[receiptIndex] = preparedEvidence{
				targetSHA256: claim.TargetSHA256(), side: claim.Side(), path: claim.Path().String(), lineStart: claim.LineStart(),
				lineEnd: claim.LineEnd(), quote: claim.Quote(), excerptSHA256: receipt.ExcerptSHA256(), excerpt: cloneBytes(excerpt),
			}
		}
		prepared[index] = preparedFinding{
			id: expectedID, fingerprint: "sha256:" + finding.Fingerprint(), role: finding.Role(), provider: finding.ProviderInstance(),
			severity: finding.Severity(), title: finding.Title(), description: finding.Description(), recommendation: finding.Recommendation(),
			confidence: finding.Confidence(), lifecycle: finding.Lifecycle(), evidence: preparedReceipts,
		}
	}
	return prepared, nil
}

func bindFindingIDs(roles []preparedRole, findings []preparedFinding) {
	for roleIndex := range roles {
		ids := make([]string, 0)
		for _, finding := range findings {
			if finding.role == roles[roleIndex].role {
				ids = append(ids, finding.id)
			}
		}
		roles[roleIndex].validFindingIDs = ids
	}
}

func validateOutcomeAxes(
	result review.CoordinatorResult,
	roles []preparedRole,
	findings []preparedFinding,
	threshold domain.Severity,
) (preparedAxes, []string, int, []string, error) {
	outcomes := result.Outcomes()
	if !outcomes.ContentVerdict().Valid() || !outcomes.CoverageStatus().Valid() || !outcomes.CIDecision().Valid() ||
		outcomes.PublicationStatus() != domain.PublicationNotPublished {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: result outcome axes are not pre-publication")
	}
	roleResults := make([]domain.RoleResultSummary, len(roles))
	for index, role := range roles {
		roleResults[index] = domain.RoleResultSummary{
			Role: role.role, Selected: true, Required: role.required, Valid: role.valid, Degraded: role.degraded,
		}
	}
	domainFindings := result.Findings()
	expected, err := domain.ComputeOutcomeAxes(domainFindings, roleResults, threshold, domain.PublicationNotPublished, nil)
	if err != nil {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: recompute axes: %w", err)
	}
	if outcomes.ContentVerdict() != expected.ContentVerdict() || outcomes.CoverageStatus() != expected.CoverageStatus() ||
		outcomes.CIDecision() != expected.CIDecision() {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: result outcome axes do not match trusted policy")
	}
	reasons := make([]string, 0, 2)
	if outcomes.ContentVerdict() == domain.ContentRequestChanges {
		reasons = append(reasons, "request_changes_threshold")
	}
	switch outcomes.CoverageStatus() {
	case domain.CoverageIncomplete:
		reasons = append(reasons, "required_role_incomplete")
	case domain.CoverageDegraded:
		reasons = append(reasons, "degraded_coverage")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "policy_evaluated")
	}
	exitCode := 0
	if outcomes.CoverageStatus() == domain.CoverageIncomplete {
		exitCode = int(domain.ExitIncompleteCoverage)
	} else if outcomes.CIDecision() == domain.CIFail {
		exitCode = int(domain.ExitCommittedCIRejected)
	}
	limits := make([]string, 0, 1)
	if outcomes.CoverageStatus() == domain.CoverageIncomplete {
		limits = append(limits, "Required review coverage is incomplete.")
	} else if outcomes.CoverageStatus() == domain.CoverageDegraded {
		limits = append(limits, "Review coverage is degraded.")
	}
	return preparedAxes{content: outcomes.ContentVerdict(), coverage: outcomes.CoverageStatus(), ci: outcomes.CIDecision()}, reasons, exitCode, limits, nil
}

func validateTerminalRun(state domain.RunState, roles []preparedRole, coverage domain.CoverageStatus) error {
	if state != domain.RunCompleted && state != domain.RunDegraded && state != domain.RunFailed {
		return fmt.Errorf("publication candidate: run state %q is not terminal and publishable", state)
	}
	failedRequired := false
	failedAny := false
	for _, role := range roles {
		if role.outcome != "failed" {
			continue
		}
		failedAny = true
		failedRequired = failedRequired || role.required
		if forbiddenPublicationFailure(role.failureClass) {
			return fmt.Errorf("publication candidate: non-publishable failure %q", role.failureClass)
		}
	}
	switch state {
	case domain.RunCompleted:
		if failedAny {
			return fmt.Errorf("publication candidate: completed run has failed role")
		}
	case domain.RunDegraded:
		if failedRequired || !failedAny {
			return fmt.Errorf("publication candidate: degraded run has inconsistent failed roles")
		}
	case domain.RunFailed:
		if !failedRequired || coverage != domain.CoverageIncomplete {
			return fmt.Errorf("publication candidate: failed run does not represent required incomplete coverage")
		}
		for _, role := range roles {
			if role.outcome == "failed" && !role.failureClass.FallbackAllowed() {
				return fmt.Errorf("publication candidate: failed run contains non-fallback-eligible failure %q", role.failureClass)
			}
		}
	}
	return nil
}

func validatePreparedRole(role preparedRole) error {
	if !role.role.Valid() || !terminalRoleState(role.state) || len(role.attempts) == 0 {
		return fmt.Errorf("identity, state, or attempts are invalid")
	}
	if (role.role == domain.RoleLogic || role.role == domain.RoleSecurity) && !role.required {
		return fmt.Errorf("required role state is inconsistent")
	}
	seenAttempts := make(map[string]struct{}, len(role.attempts))
	for index, attempt := range role.attempts {
		if _, err := domain.ParseAttemptID(attempt.id.String()); err != nil {
			return fmt.Errorf("attempt %d ID is invalid", index)
		}
		if _, duplicate := seenAttempts[attempt.id.String()]; duplicate {
			return fmt.Errorf("duplicate attempt ID %q", attempt.id)
		}
		seenAttempts[attempt.id.String()] = struct{}{}
		switch index {
		case 0:
			if attempt.kind != review.AttemptKindPrimary {
				return fmt.Errorf("attempt sequence must begin with primary")
			}
		case 1:
			if attempt.kind != review.AttemptKindFallback || role.attempts[0].state == domain.AttemptSucceeded {
				return fmt.Errorf("fallback attempt is not a canonical continuation")
			}
		default:
			return fmt.Errorf("role has more than primary and fallback attempts")
		}
		if !attempt.kind.Valid() || !validProviderInstance(attempt.provider) || !terminalAttemptState(attempt.state) || len(attempt.invocations) == 0 {
			return fmt.Errorf("attempt %q is invalid", attempt.id)
		}
		for invocationIndex, invocation := range attempt.invocations {
			if invocation.sequence != uint64(invocationIndex+1) || !invocation.purpose.Valid() || !terminalInvocationState(invocation.state) {
				return fmt.Errorf("attempt %q invocation %d is invalid", attempt.id, invocationIndex)
			}
		}
	}
	finalAttempt := role.attempts[len(role.attempts)-1]
	switch role.outcome {
	case "completed", "degraded":
		if !role.valid || role.state != domain.RoleTaskSucceeded || finalAttempt.state != domain.AttemptSucceeded ||
			role.failureClass != "" || role.failureReason != "" {
			return fmt.Errorf("successful role values are inconsistent")
		}
		if role.outcome == "completed" && role.degraded {
			return fmt.Errorf("completed role is marked degraded")
		}
		if role.outcome == "degraded" && !role.degraded {
			return fmt.Errorf("degraded role is not marked degraded")
		}
	case "failed":
		if role.valid || role.degraded || role.state != domain.RoleTaskFailed || !role.failureClass.Valid() ||
			!validReasonCode(role.failureReason) || finalAttempt.state == domain.AttemptSucceeded ||
			forbiddenPublicationFailure(role.failureClass) {
			return fmt.Errorf("failed role values are inconsistent")
		}
	default:
		return fmt.Errorf("unknown outcome %q", role.outcome)
	}
	if err := validateStringSlice(role.limitations, 20, 2000, true); err != nil {
		return err
	}
	for index, id := range role.validFindingIDs {
		if !validFindingID(id) || (index > 0 && role.validFindingIDs[index-1] >= id) {
			return fmt.Errorf("valid finding IDs are not ordered")
		}
	}
	return nil
}

func validatePreparedFindings(findings []preparedFinding, roles []preparedRole, targetSHA256 string) error {
	roleByName := make(map[domain.Role]preparedRole, len(roles))
	for _, role := range roles {
		roleByName[role.role] = role
	}
	expectedFindingIDs := make(map[domain.Role][]string, len(roles))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.id != expectedID || !validSHA256(finding.fingerprint) || !finding.role.Valid() ||
			!validProviderInstance(finding.provider) || !finding.severity.Valid() || !finding.confidence.Valid() || !finding.lifecycle.Valid() {
			return fmt.Errorf("finding %d identity is invalid", index)
		}
		role, exists := roleByName[finding.role]
		if !exists || !role.valid || role.attempts[len(role.attempts)-1].provider != finding.provider {
			return fmt.Errorf("finding %q has inconsistent role binding", finding.id)
		}
		if !safeText(finding.title, 300, true) || !safeText(finding.description, 12000, false) || !safeText(finding.recommendation, 12000, false) || len(finding.evidence) == 0 || len(finding.evidence) > 20 {
			return fmt.Errorf("finding %q text or evidence is invalid", finding.id)
		}
		for evidenceIndex, item := range finding.evidence {
			if item.targetSHA256 != targetSHA256 || !item.side.Valid() || !safePath(item.path) || item.lineStart < 1 ||
				item.lineEnd < item.lineStart || !safeText(item.quote, 8000, false) || !validSHA256(item.excerptSHA256) ||
				len(item.excerpt) == 0 || !utf8.Valid(item.excerpt) {
				return fmt.Errorf("finding %q evidence %d is invalid", finding.id, evidenceIndex)
			}
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
				TargetSHA256: item.targetSHA256,
				Side:         item.side,
				Path:         item.path,
				LineStart:    item.lineStart,
				LineEnd:      item.lineEnd,
				Quote:        item.quote,
			})
			if err != nil || !bytes.Equal(claim.QuoteBytes(), item.excerpt) {
				return fmt.Errorf("finding %q evidence %d does not match its verified excerpt", finding.id, evidenceIndex)
			}
			excerptSHA256, err := claim.ExcerptSHA256(item.excerpt)
			if err != nil || excerptSHA256 != item.excerptSHA256 {
				return fmt.Errorf("finding %q evidence %d excerpt identity is invalid", finding.id, evidenceIndex)
			}
		}
		expectedFindingIDs[finding.role] = append(expectedFindingIDs[finding.role], finding.id)
	}
	for _, role := range roles {
		expected := expectedFindingIDs[role.role]
		if len(role.validFindingIDs) != len(expected) {
			return fmt.Errorf("role %q finding binding count is inconsistent", role.role)
		}
		for index := range expected {
			if role.validFindingIDs[index] != expected[index] {
				return fmt.Errorf("role %q finding binding is inconsistent", role.role)
			}
		}
	}
	return nil
}

func validatePreparedFailures(failures []preparedFailure, roles []preparedRole) error {
	failedRoles := 0
	for _, role := range roles {
		if role.outcome == "failed" {
			failedRoles++
		}
	}
	if len(failures) != failedRoles {
		return fmt.Errorf("failure projection count does not match failed roles")
	}
	for index, failure := range failures {
		if !failure.class.Valid() || forbiddenPublicationFailure(failure.class) || !safeText(failure.stage, 128, true) ||
			!validReasonCode(failure.reason) || failure.attemptID == nil {
			return fmt.Errorf("failure %d is invalid", index)
		}
		if _, err := domain.ParseAttemptID(failure.attemptID.String()); err != nil {
			return fmt.Errorf("failure %d has invalid attempt ID", index)
		}
	}
	return nil
}

func validateIdentity(sessionID domain.SessionID, runID domain.RunID) error {
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return err
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return err
	}
	return nil
}

func validateTarget(target domain.TargetIdentity) error {
	canonical, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: target.Kind(), SHA256: target.SHA256(), RepositoryID: target.RepositoryID(), BaseObjectID: target.BaseObjectID(),
		HeadObjectID: target.HeadObjectID(), HeadTreeObjectID: target.HeadTreeObjectID(), IndexTreeObjectID: target.IndexTreeObjectID(),
	})
	if err != nil || canonical != target {
		return fmt.Errorf("target identity is invalid")
	}
	return nil
}

func validateBuildMetadata(version, commit string) error {
	if !safeText(version, 128, true) {
		return fmt.Errorf("KAR version is invalid")
	}
	if commit != "" && !safeText(commit, 128, true) {
		return fmt.Errorf("KAR commit is invalid")
	}
	return nil
}

func validateFindingStrings(finding domain.Finding) error {
	if !safePath(finding.Path()) || !safeText(finding.ProviderInstance(), 128, true) || !safeText(finding.Title(), 300, true) ||
		!safeText(finding.Description(), 12000, false) || !safeText(finding.Recommendation(), 12000, false) {
		return fmt.Errorf("unsafe finding strings")
	}
	return nil
}

func validProviderInstance(value string) bool {
	if !safeText(value, 128, true) || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeText(value string, maximum int, singleLine bool) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == 0 || unicode.IsControl(character) && character != '\n' && character != '\t' {
			return false
		}
		if singleLine && (character == '\n' || character == '\t') {
			return false
		}
	}
	return true
}

func safePath(value string) bool {
	path, err := ports.NewSafeRelativePath(value)
	return err == nil && path.String() == value
}

func validOptionalOID(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validReasonCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateReasonCodes(values []string) error {
	if len(values) == 0 || len(values) > 32 {
		return fmt.Errorf("reason codes are empty or exceed the limit")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validReasonCode(value) {
			return fmt.Errorf("invalid reason code %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate reason code %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateStringSlice(values []string, maximumItems, maximumBytes int, allowEmpty bool) error {
	if len(values) > maximumItems || (!allowEmpty && len(values) == 0) {
		return fmt.Errorf("invalid item count")
	}
	for _, value := range values {
		if !safeText(value, maximumBytes, false) {
			return fmt.Errorf("unsafe text")
		}
	}
	return nil
}

func validFindingID(value string) bool {
	if len(value) < 4 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validNormalExit(code int) bool {
	return code == int(domain.ExitCommittedPass) || code == int(domain.ExitCommittedCIRejected) || code == int(domain.ExitIncompleteCoverage)
}
func validatePublicationBundleSemantics(bundle PublicationBundle) error {
	normalExit, err := validatePublicationCompositeSemantics(
		bundle.final,
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	)
	if err != nil {
		return err
	}
	var finalWire finalReviewWire
	if err := unmarshalCanonicalPublicationRecord(bundle.final.Bytes(), &finalWire, "final review"); err != nil {
		return err
	}
	sessionID, err := domain.ParseSessionID(finalWire.SessionID)
	if err != nil {
		return err
	}
	runID, err := domain.ParseRunID(finalWire.RunID)
	if err != nil {
		return err
	}
	paths, err := publicationPaths(sessionID, runID, bundle.final.Identity().ReviewID(), bundle.epoch.Value())
	if err != nil {
		return err
	}
	if bundle.staged.Path() != paths.staged ||
		bundle.staged.SHA256() != bundle.final.Identity().SHA256() ||
		!bytes.Equal(bundle.staged.Bytes(), bundle.final.Bytes()) {
		return fmt.Errorf("staged final does not match the exact final review")
	}
	if err := validateBundleExcerptBindings(bundle.excerpts, finalWire, paths); err != nil {
		return err
	}

	var journal publicationJournalWire
	if err := unmarshalCanonicalPublicationRecord(bundle.journal.Bytes(), &journal, "publication journal"); err != nil {
		return err
	}
	if journal.SchemaVersion != publicationJournalV1 {
		return fmt.Errorf("publication journal schema version is invalid")
	}
	if err := validateRestartStateSemantics(
		journal.restartStateWire,
		domain.JournalManifestCommitted,
		normalExit,
		bundle.final.Identity(),
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	); err != nil {
		return fmt.Errorf("publication journal: %w", err)
	}

	var status publicationStatusWire
	if err := unmarshalCanonicalPublicationRecord(bundle.status.Bytes(), &status, "publication status"); err != nil {
		return err
	}
	if status.SchemaVersion != publicationStatusV1 ||
		status.PublicationStatus != string(domain.PublicationCommitted) ||
		status.PublicationAuthority != string(domain.PublicationAuthorityP2) {
		return fmt.Errorf("publication status does not grant the exact P2 projection")
	}
	if err := validateRestartStateSemantics(
		status.restartStateWire,
		domain.JournalManifestCommitted,
		normalExit,
		bundle.final.Identity(),
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	); err != nil {
		return fmt.Errorf("publication status: %w", err)
	}
	return nil
}

func validateBundleExcerptBindings(
	excerpts []ports.ImmutablePublicationArtifact,
	final finalReviewWire,
	paths publicationPathsSet,
) error {
	expectedCount := 0
	for _, finding := range final.Findings {
		expectedCount += len(finding.Evidence)
	}
	if len(excerpts) != expectedCount {
		return fmt.Errorf("excerpt count does not match final evidence")
	}
	index := 0
	for _, finding := range final.Findings {
		for evidenceIndex, item := range finding.Evidence {
			expectedPath, err := ports.NewSafeRelativePath(
				fmt.Sprintf("%s/%s_%d.md", paths.excerptsDir, finding.ID, evidenceIndex+1),
			)
			if err != nil {
				return err
			}
			artifact := excerpts[index]
			if artifact.Path() != expectedPath ||
				!bytes.Equal(artifact.Bytes(), []byte(item.Current.Quote)) {
				return fmt.Errorf("excerpt %q/%d does not match final evidence", finding.ID, evidenceIndex+1)
			}
			index++
		}
	}
	return nil
}
func validateCommittedSnapshotSemantics(
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) (domain.OperationalExitCode, error) {
	if !run.Valid() || !snapshot.Valid() {
		return 0, fmt.Errorf("invalid run or committed snapshot")
	}
	final := snapshot.Final()
	if final.Identity().Path().String() != run.SessionID().String()+"/"+run.RunID().String()+"/review_"+final.Identity().ReviewID().String()+".json" {
		return 0, fmt.Errorf("committed final path is not canonical for the observed run")
	}
	return validatePublicationCompositeSemantics(
		final,
		snapshot.Manifest(),
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	)
}

func validatePublicationCompositeSemantics(
	final ports.FinalReviewArtifact,
	manifestArtifact ports.ImmutablePublicationArtifact,
	lineageArtifact ports.ImmutablePublicationArtifact,
	epoch ports.PublicationEpoch,
) (domain.OperationalExitCode, error) {
	if !final.Valid() || !manifestArtifact.Valid() || !lineageArtifact.Valid() || !epoch.Valid() {
		return 0, fmt.Errorf("invalid immutable publication member")
	}

	var finalWire finalReviewWire
	if err := unmarshalCanonicalPublicationRecord(final.Bytes(), &finalWire, "final review"); err != nil {
		return 0, err
	}
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(manifestArtifact.Bytes(), &manifest, "run manifest"); err != nil {
		return 0, err
	}
	var lineage lineageEdgeWire
	if err := unmarshalCanonicalPublicationRecord(lineageArtifact.Bytes(), &lineage, "lineage edge"); err != nil {
		return 0, err
	}
	var epochWire publicationEpochWire
	if err := unmarshalCanonicalPublicationRecord(epoch.Record().Bytes(), &epochWire, "publication epoch"); err != nil {
		return 0, err
	}

	sessionID, err := domain.ParseSessionID(finalWire.SessionID)
	if err != nil {
		return 0, fmt.Errorf("final review session ID: %w", err)
	}
	runID, err := domain.ParseRunID(finalWire.RunID)
	if err != nil {
		return 0, fmt.Errorf("final review run ID: %w", err)
	}
	reviewID, err := domain.ParseReviewID(finalWire.ReviewID)
	if err != nil {
		return 0, fmt.Errorf("final review ID: %w", err)
	}
	paths, err := publicationPaths(sessionID, runID, reviewID, epoch.Value())
	if err != nil {
		return 0, err
	}
	if finalWire.SchemaVersion != "kar-review-artifact.v2" ||
		finalWire.RunType != string(domain.RunTypeReview) ||
		final.Identity().ReviewID() != reviewID ||
		final.Identity().Path() != paths.final ||
		finalWire.PublicationStatus != string(domain.PublicationCommitted) ||
		(finalWire.Validation.Status != "valid" && finalWire.Validation.Status != "repaired_valid") ||
		finalWire.Validation.SchemaValidation != "passed" ||
		finalWire.Validation.SemanticValidation != "passed" ||
		finalWire.Validation.EvidenceValidation != "passed" ||
		finalWire.Target.ManifestPath != targetManifestPath ||
		!validSHA256(finalWire.Target.ContentSHA256) ||
		!domain.ContentVerdict(finalWire.ContentVerdict).Valid() ||
		!domain.CoverageStatus(finalWire.CoverageStatus).Valid() ||
		!domain.CIDecision(finalWire.CIDecision).Valid() ||
		finalWire.Provenance.AggregationPath != aggregationPath ||
		finalWire.Provenance.FinalValidationPath != finalValidationPath ||
		finalWire.Provenance.ManifestPath != "manifest.json" {
		return 0, fmt.Errorf("final review has invalid publication semantics")
	}
	karCommit := ""
	if finalWire.KAR.Commit != nil {
		karCommit = *finalWire.KAR.Commit
	}
	if err := validateBuildMetadata(finalWire.KAR.Version, karCommit); err != nil ||
		(finalWire.KAR.Commit != nil && karCommit == "") ||
		(finalWire.Target.BaseOID != nil &&
			(*finalWire.Target.BaseOID == "" || !validOptionalOID(*finalWire.Target.BaseOID))) ||
		(finalWire.Target.HeadOID != nil &&
			(*finalWire.Target.HeadOID == "" || !validOptionalOID(*finalWire.Target.HeadOID))) {
		return 0, fmt.Errorf("final review build metadata or target identity is invalid")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, finalWire.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("final review creation time: %w", err)
	}
	canonicalCreatedAt, err := canonicalTime(createdAt)
	if err != nil || canonicalCreatedAt != finalWire.CreatedAt {
		return 0, fmt.Errorf("final review creation time is not canonical")
	}
	if err := validateReasonCodes(finalWire.CIReasonCodes); err != nil {
		return 0, fmt.Errorf("final review CI reasons: %w", err)
	}
	if err := validateRootLineage(finalWire.ImmutableLineage, lineageArtifact); err != nil {
		return 0, fmt.Errorf("final review lineage: %w", err)
	}
	content, coverage, ci, err := validateFinalOutcomeSemantics(finalWire)
	if err != nil {
		return 0, err
	}
	if err := validateFinalReportSemantics(finalWire, content, coverage, ci); err != nil {
		return 0, err
	}

	if manifest.SchemaVersion != "kar-run-manifest.v2" ||
		manifest.SessionID != finalWire.SessionID ||
		manifest.RunID != finalWire.RunID ||
		manifest.RunType != finalWire.RunType ||
		(manifest.State != string(domain.RunCompleted) &&
			manifest.State != string(domain.RunDegraded) &&
			manifest.State != string(domain.RunFailed)) ||
		!manifest.Sealed ||
		manifest.CreatedAt != finalWire.CreatedAt ||
		manifest.StartedAt == nil || *manifest.StartedAt != finalWire.CreatedAt ||
		manifest.CompletedAt == nil || *manifest.CompletedAt != finalWire.CreatedAt ||
		manifest.KARVersion != finalWire.KAR.Version ||
		!reflect.DeepEqual(manifest.ImmutableLineage, finalWire.ImmutableLineage) ||
		manifest.Target.ManifestPath != finalWire.Target.ManifestPath ||
		manifest.Target.ContentSHA256 != finalWire.Target.ContentSHA256 ||
		manifest.ContentVerdict != string(content) ||
		manifest.CoverageStatus != string(coverage) ||
		manifest.PublicationStatus != string(domain.PublicationCommitted) ||
		manifest.CIDecision != string(ci) ||
		!reflect.DeepEqual(manifest.CIReasonCodes, finalWire.CIReasonCodes) ||
		manifest.PersistedJournalState != string(domain.JournalManifestCommitted) ||
		manifest.DurableObservationClass != string(domain.DurableObservationP2Committed) ||
		manifest.DerivedPublicationStatus != string(domain.PublicationCommitted) ||
		manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) ||
		manifest.RecoveryAction != string(domain.RecoveryActionReconstructCompletedStatus) ||
		manifest.FinalReview.ReviewID != reviewID.String() ||
		manifest.FinalReview.Path != final.Identity().Path().String() ||
		manifest.FinalReview.SHA256 != final.Identity().SHA256() ||
		manifest.RecoveryJournal.ExpectedStaged.Path != paths.staged.String() ||
		manifest.RecoveryJournal.ExpectedStaged.SHA256 != final.Identity().SHA256() ||
		manifest.RecoveryJournal.ExpectedFinal.Path != final.Identity().Path().String() ||
		manifest.RecoveryJournal.ExpectedFinal.SHA256 != final.Identity().SHA256() ||
		!validSHA256(manifest.RecoveryJournal.ValidatedCandidateSHA256) ||
		manifest.CompositeIdentity.Manifest.Path != manifestArtifact.Path().String() ||
		manifest.CompositeIdentity.LineageEdge.Path != lineageArtifact.Path().String() ||
		manifest.CompositeIdentity.LineageEdge.SHA256 != lineageArtifact.SHA256() ||
		manifest.CompositeIdentity.Epoch.Path != epoch.Record().Path().String() {
		return 0, fmt.Errorf("manifest does not match the final review and immutable composite")
	}
	repaired, err := validateManifestRoleBindings(manifest, finalWire)
	if err != nil {
		return 0, err
	}
	expectedValidationStatus := "valid"
	if repaired {
		expectedValidationStatus = "repaired_valid"
	}
	if finalWire.Validation.Status != expectedValidationStatus {
		return 0, fmt.Errorf("final review validation status does not match repaired attempt facts")
	}

	normalExit := normalExitForPublicationAxes(coverage, ci)
	if manifest.ExitCode != int(normalExit) {
		return 0, fmt.Errorf("manifest normal exit does not match final outcome axes")
	}
	if lineage.SchemaVersion != lineageEdgeV1 ||
		lineage.EdgeID != "e_"+reviewID.String() ||
		lineage.Child.SessionID != sessionID.String() ||
		lineage.Child.RunID != runID.String() ||
		lineage.Child.ReviewID != reviewID.String() ||
		lineage.ParentRunID != nil ||
		lineage.SourceRunID != nil ||
		lineage.SourceReviewID != nil ||
		lineage.SourceFindingRef != nil ||
		lineage.ReplayMode != nil {
		return 0, fmt.Errorf("lineage edge is not the exact root-review edge")
	}
	if epochWire.SchemaVersion != publicationEpochV1 ||
		epochWire.StoreEpoch != epoch.Value() ||
		epoch.Record().Path() != paths.epoch ||
		epochWire.Manifest.Path != manifestArtifact.Path().String() ||
		epochWire.Manifest.SHA256 != manifestArtifact.SHA256() ||
		epochWire.LineageEdge.Path != lineageArtifact.Path().String() ||
		epochWire.LineageEdge.SHA256 != lineageArtifact.SHA256() ||
		epochWire.FinalReview.Path != final.Identity().Path().String() ||
		epochWire.FinalReview.SHA256 != final.Identity().SHA256() {
		return 0, fmt.Errorf("epoch does not bind the exact immutable composite")
	}
	return normalExit, nil
}

func unmarshalCanonicalPublicationRecord(data []byte, value any, name string) error {
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	canonical, err := marshalCanonical(value)
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", name, err)
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("%s is not canonical", name)
	}
	return nil
}

func validateRootLineage(lineage immutableLineageWire, edge ports.ImmutablePublicationArtifact) error {
	if lineage.ParentRunID != nil ||
		lineage.SourceRunID != nil ||
		lineage.SourceReviewID != nil ||
		lineage.SourceFindingRef != nil ||
		lineage.ReplayMode != nil ||
		lineage.LineageEdgePath != edge.Path().String() ||
		lineage.LineageEdgeSHA256 != edge.SHA256() {
		return fmt.Errorf("root lineage does not match the immutable edge")
	}
	return nil
}

func validateFinalOutcomeSemantics(final finalReviewWire) (domain.ContentVerdict, domain.CoverageStatus, domain.CIDecision, error) {
	threshold := domain.Severity(final.SeverityThreshold.RequestChangesAtOrAbove)
	if !threshold.Valid() || final.SeverityThreshold.PolicySource != "trusted_base" {
		return "", "", "", fmt.Errorf("final review severity threshold is invalid")
	}
	roles := make([]domain.RoleResultSummary, len(final.RoleOutcomes))
	seenRoles := make(map[domain.Role]struct{}, len(final.RoleOutcomes))
	for index, role := range final.RoleOutcomes {
		parsedRole := domain.Role(role.Role)
		if !parsedRole.Valid() ||
			(index > 0 && roleOrdinal(domain.Role(final.RoleOutcomes[index-1].Role)) >= roleOrdinal(parsedRole)) {
			return "", "", "", fmt.Errorf("final review role outcomes are invalid or unordered")
		}
		if _, duplicate := seenRoles[parsedRole]; duplicate {
			return "", "", "", fmt.Errorf("final review role outcomes are duplicated")
		}
		seenRoles[parsedRole] = struct{}{}
		if !validReasonPointer(role.FailureReason) ||
			validateStringSlice(role.ValidFindingIDs, 1000, 64, true) != nil ||
			validateStringSlice(role.Limitations, 20, 2000, true) != nil {
			return "", "", "", fmt.Errorf("final review role outcome %q is malformed", role.Role)
		}
		if role.Outcome == "skipped" {
			if role.AttemptID != nil || role.ProviderInstance != nil || role.SelectedVia != nil ||
				len(role.ValidFindingIDs) != 0 {
				return "", "", "", fmt.Errorf("skipped role outcome %q has attempt-owned content", role.Role)
			}
			roles[index] = domain.RoleResultSummary{
				Role: parsedRole, Selected: true, Required: role.Required, Valid: false,
			}
			continue
		}
		if role.Outcome != "completed" && role.Outcome != "degraded" && role.Outcome != "failed" {
			return "", "", "", fmt.Errorf("final review role outcome %q is invalid", role.Outcome)
		}
		if role.AttemptID == nil || role.ProviderInstance == nil || role.SelectedVia == nil ||
			!validProviderInstance(*role.ProviderInstance) || !review.AttemptKind(*role.SelectedVia).Valid() {
			return "", "", "", fmt.Errorf("final review role outcome %q has no valid attempt binding", role.Role)
		}
		if _, err := domain.ParseAttemptID(*role.AttemptID); err != nil {
			return "", "", "", fmt.Errorf("final review role outcome %q attempt ID: %w", role.Role, err)
		}
		if role.Outcome == "failed" && role.FailureReason == nil {
			return "", "", "", fmt.Errorf("failed role outcome omits its failure reason")
		}
		if role.Outcome != "failed" && role.FailureReason != nil {
			return "", "", "", fmt.Errorf("successful role outcome carries a failure reason")
		}
		roles[index] = domain.RoleResultSummary{
			Role:     parsedRole,
			Selected: true,
			Required: role.Required,
			Valid:    role.Outcome != "failed",
			Degraded: role.Outcome == "degraded",
		}
	}
	axes, err := domain.ComputeOutcomeAxes(nil, roles, threshold, domain.PublicationCommitted, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("final review coverage: %w", err)
	}
	content := domain.ContentNoFindings
	for _, finding := range final.Findings {
		severity := domain.Severity(finding.Severity)
		if !severity.Valid() {
			return "", "", "", fmt.Errorf("final review finding severity is invalid")
		}
		if content == domain.ContentNoFindings {
			content = domain.ContentFindingsPresent
		}
		if severity.Rank() >= threshold.Rank() {
			content = domain.ContentRequestChanges
		}
	}
	ci := domain.CIPass
	if content == domain.ContentRequestChanges || axes.CoverageStatus() != domain.CoverageComplete {
		ci = domain.CIFail
	}
	if domain.ContentVerdict(final.ContentVerdict) != content ||
		domain.CoverageStatus(final.CoverageStatus) != axes.CoverageStatus() ||
		domain.CIDecision(final.CIDecision) != ci {
		return "", "", "", fmt.Errorf("final review outcome axes are inconsistent")
	}
	return content, axes.CoverageStatus(), ci, nil
}

func validateFinalReportSemantics(
	final finalReviewWire,
	content domain.ContentVerdict,
	coverage domain.CoverageStatus,
	ci domain.CIDecision,
) error {
	expectedReasons := ciReasonCodesForPublicationAxes(content, coverage)
	if !reflect.DeepEqual(final.CIReasonCodes, expectedReasons) {
		return fmt.Errorf("final review CI reasons do not match publication axes")
	}
	if ci != domain.CIPass && len(expectedReasons) == 0 {
		return fmt.Errorf("final review failing CI omits reasons")
	}
	expectedLimitations := publicationLimitationsForCoverage(coverage)
	if !reflect.DeepEqual(final.Limitations, expectedLimitations) {
		return fmt.Errorf("final review limitations do not match coverage")
	}
	return validateFinalFindingBindings(final)
}

func ciReasonCodesForPublicationAxes(
	content domain.ContentVerdict,
	coverage domain.CoverageStatus,
) []string {
	reasons := make([]string, 0, 2)
	if content == domain.ContentRequestChanges {
		reasons = append(reasons, "request_changes_threshold")
	}
	switch coverage {
	case domain.CoverageIncomplete:
		reasons = append(reasons, "required_role_incomplete")
	case domain.CoverageDegraded:
		reasons = append(reasons, "degraded_coverage")
	}
	if len(reasons) == 0 {
		return []string{"policy_evaluated"}
	}
	return reasons
}

func publicationLimitationsForCoverage(coverage domain.CoverageStatus) []string {
	switch coverage {
	case domain.CoverageIncomplete:
		return []string{"Required review coverage is incomplete."}
	case domain.CoverageDegraded:
		return []string{"Review coverage is degraded."}
	default:
		return []string{}
	}
}

func roleLimitationsForOutcome(outcome string) ([]string, error) {
	switch outcome {
	case "completed":
		return []string{}, nil
	case "degraded":
		return []string{"Role coverage is degraded."}, nil
	case "failed":
		return []string{"Role coverage is incomplete due to a terminal provider failure."}, nil
	default:
		return nil, fmt.Errorf("unknown role outcome %q", outcome)
	}
}

func validateFinalFindingBindings(final finalReviewWire) error {
	roleByName := make(map[string]roleOutcomeWire, len(final.RoleOutcomes))
	expectedFindingIDs := make(map[string][]string, len(final.RoleOutcomes))
	for _, role := range final.RoleOutcomes {
		roleByName[role.Role] = role
		expectedFindingIDs[role.Role] = []string{}
	}
	for index, finding := range final.Findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID != expectedID ||
			!validSHA256(finding.Fingerprint) ||
			!domain.Severity(finding.Severity).Valid() ||
			!domain.Confidence(finding.Confidence).Valid() ||
			!domain.FindingLifecycle(finding.Lifecycle).Valid() ||
			!safeText(finding.Title, 300, true) ||
			!safeText(finding.Description, 12000, false) ||
			!safeText(finding.Recommendation, 12000, false) ||
			len(finding.Evidence) == 0 || len(finding.Evidence) > 20 {
			return fmt.Errorf("final finding %q is invalid", finding.ID)
		}
		role, ok := roleByName[finding.Role]
		if !ok || (role.Outcome != "completed" && role.Outcome != "degraded") ||
			role.ProviderInstance == nil || *role.ProviderInstance != finding.ProviderInstance ||
			!validProviderInstance(finding.ProviderInstance) {
			return fmt.Errorf("final finding %q does not bind to a valid role outcome", finding.ID)
		}
		for evidenceIndex, item := range finding.Evidence {
			if item.Source.SessionID != final.SessionID ||
				item.Source.RunID != final.RunID ||
				item.Source.ReviewID != final.ReviewID ||
				item.Source.FindingID != finding.ID ||
				item.Source.SourceTargetSHA256 != final.Target.ContentSHA256 ||
				!validSHA256(item.Source.SourceExcerptSHA256) ||
				item.Current.TargetSHA256 != final.Target.ContentSHA256 ||
				!evidence.Side(item.Current.Side).Valid() ||
				!safePath(item.Current.Path) ||
				item.Current.LineStart < 1 ||
				item.Current.LineEnd < item.Current.LineStart ||
				!safeText(item.Current.Quote, 8000, false) ||
				item.Current.Verification != "verified" {
				return fmt.Errorf("final finding %q evidence %d is invalid", finding.ID, evidenceIndex)
			}
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
				TargetSHA256: item.Current.TargetSHA256,
				Side:         evidence.Side(item.Current.Side),
				Path:         item.Current.Path,
				LineStart:    item.Current.LineStart,
				LineEnd:      item.Current.LineEnd,
				Quote:        item.Current.Quote,
			})
			if err != nil {
				return fmt.Errorf("final finding %q evidence %d claim: %w", finding.ID, evidenceIndex, err)
			}
			excerptSHA256, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
			if err != nil || excerptSHA256 != item.Source.SourceExcerptSHA256 {
				return fmt.Errorf("final finding %q evidence %d excerpt identity is invalid", finding.ID, evidenceIndex)
			}
		}
		expectedFindingIDs[finding.Role] = append(expectedFindingIDs[finding.Role], finding.ID)
	}
	for _, role := range final.RoleOutcomes {
		if !reflect.DeepEqual(role.ValidFindingIDs, expectedFindingIDs[role.Role]) {
			return fmt.Errorf("final role outcome %q finding IDs do not match findings", role.Role)
		}
	}
	return nil
}

func validateManifestRoleBindings(manifest runManifestWire, final finalReviewWire) (bool, error) {
	if len(manifest.SelectedRoles) != len(final.RoleOutcomes) {
		return false, fmt.Errorf("manifest selected roles do not match final role outcomes")
	}
	selected := make(map[string]int, len(manifest.SelectedRoles))
	for index, role := range manifest.SelectedRoles {
		if !domain.Role(role).Valid() {
			return false, fmt.Errorf("manifest selected role %q is invalid", role)
		}
		if _, duplicate := selected[role]; duplicate {
			return false, fmt.Errorf("manifest selected role %q is duplicated", role)
		}
		if index > 0 && roleOrdinal(domain.Role(manifest.SelectedRoles[index-1])) >= roleOrdinal(domain.Role(role)) {
			return false, fmt.Errorf("manifest selected roles are not ordered")
		}
		selected[role] = index
	}
	lastAttemptByRole := make(map[string]manifestAttemptWire, len(manifest.SelectedRoles))
	attemptCountByRole := make(map[string]int, len(manifest.SelectedRoles))
	seenAttempts := make(map[string]struct{}, len(manifest.Attempts))
	lastRoleIndex := -1
	repaired := false
	for _, attempt := range manifest.Attempts {
		if _, err := domain.ParseAttemptID(attempt.AttemptID); err != nil ||
			!domain.Role(attempt.Role).Valid() ||
			!validProviderInstance(attempt.ProviderInstance) ||
			!review.AttemptKind(attempt.SelectedAs).Valid() ||
			!domain.AttemptState(attempt.State).Valid() ||
			!terminalAttemptState(domain.AttemptState(attempt.State)) ||
			attempt.Path != "attempts/"+attempt.AttemptID+"/status.json" ||
			attempt.InvocationCount < 1 {
			return false, fmt.Errorf("manifest attempt %q is invalid", attempt.AttemptID)
		}
		if _, duplicate := seenAttempts[attempt.AttemptID]; duplicate {
			return false, fmt.Errorf("manifest attempt %q is duplicated", attempt.AttemptID)
		}
		roleIndex, exists := selected[attempt.Role]
		if !exists || roleIndex < lastRoleIndex {
			return false, fmt.Errorf("manifest attempt %q has unordered or unselected role", attempt.AttemptID)
		}
		lastRoleIndex = roleIndex
		switch attemptCountByRole[attempt.Role] {
		case 0:
			if attempt.SelectedAs != string(review.AttemptKindPrimary) {
				return false, fmt.Errorf("manifest role %q does not begin with a primary attempt", attempt.Role)
			}
		case 1:
			previous := lastAttemptByRole[attempt.Role]
			if attempt.SelectedAs != string(review.AttemptKindFallback) ||
				previous.State == string(domain.AttemptSucceeded) {
				return false, fmt.Errorf("manifest role %q has a non-canonical fallback", attempt.Role)
			}
		default:
			return false, fmt.Errorf("manifest role %q has more than primary and fallback attempts", attempt.Role)
		}
		attemptCountByRole[attempt.Role]++
		if attempt.State == string(domain.AttemptSucceeded) {
			if attempt.ParseState != "valid" ||
				(attempt.ValidationState != "valid" && attempt.ValidationState != "repaired_valid") {
				return false, fmt.Errorf("successful manifest attempt %q has invalid validation facts", attempt.AttemptID)
			}
			repaired = repaired || attempt.ValidationState == "repaired_valid"
		} else if attempt.ParseState != "not_started" || attempt.ValidationState != "not_started" {
			return false, fmt.Errorf("failed manifest attempt %q has invalid validation facts", attempt.AttemptID)
		}
		seenAttempts[attempt.AttemptID] = struct{}{}
		lastAttemptByRole[attempt.Role] = attempt
	}

	required := make([]string, 0, len(final.RoleOutcomes))
	failedRequired := false
	failedAny := false
	expectedFailures := make(map[string]string)
	for index, outcome := range final.RoleOutcomes {
		if manifest.SelectedRoles[index] != outcome.Role {
			return false, fmt.Errorf("manifest selected role %d does not match final role outcome", index)
		}
		role := domain.Role(outcome.Role)
		if !role.Valid() || (role == domain.RoleLogic || role == domain.RoleSecurity) && !outcome.Required {
			return false, fmt.Errorf("final role outcome %q has invalid required policy", outcome.Role)
		}
		expectedLimitations, err := roleLimitationsForOutcome(outcome.Outcome)
		if err != nil || !reflect.DeepEqual(outcome.Limitations, expectedLimitations) {
			return false, fmt.Errorf("final role outcome %q limitations are inconsistent", outcome.Role)
		}
		if outcome.Required {
			required = append(required, outcome.Role)
		}
		attempt, ok := lastAttemptByRole[outcome.Role]
		if !ok || outcome.AttemptID == nil || outcome.ProviderInstance == nil || outcome.SelectedVia == nil ||
			attempt.AttemptID != *outcome.AttemptID ||
			attempt.ProviderInstance != *outcome.ProviderInstance ||
			attempt.SelectedAs != *outcome.SelectedVia {
			return false, fmt.Errorf("manifest final attempt does not match role outcome %q", outcome.Role)
		}
		switch outcome.Outcome {
		case "completed", "degraded":
			if attempt.State != string(domain.AttemptSucceeded) || outcome.FailureReason != nil {
				return false, fmt.Errorf("successful role outcome %q has inconsistent manifest attempt", outcome.Role)
			}
		case "failed":
			if attempt.State == string(domain.AttemptSucceeded) || outcome.FailureReason == nil ||
				!validReasonCode(*outcome.FailureReason) {
				return false, fmt.Errorf("failed role outcome %q has inconsistent manifest attempt", outcome.Role)
			}
			expectedFailures[attempt.AttemptID] = *outcome.FailureReason
			failedAny = true
			failedRequired = failedRequired || outcome.Required
		default:
			return false, fmt.Errorf("unknown role outcome %q", outcome.Outcome)
		}
	}
	if !reflect.DeepEqual(manifest.RequiredRoles, required) {
		return false, fmt.Errorf("manifest required roles do not match final role outcomes")
	}
	if err := validateManifestFailures(manifest, expectedFailures); err != nil {
		return false, err
	}
	if len(manifest.Warnings) != 0 {
		return false, fmt.Errorf("G006 manifest must not contain warnings")
	}
	switch manifest.State {
	case string(domain.RunCompleted):
		if failedAny {
			return false, fmt.Errorf("completed manifest has a failed role outcome")
		}
	case string(domain.RunDegraded):
		if failedRequired || !failedAny {
			return false, fmt.Errorf("degraded manifest has inconsistent failed role outcomes")
		}
	case string(domain.RunFailed):
		if !failedRequired || manifest.CoverageStatus != string(domain.CoverageIncomplete) {
			return false, fmt.Errorf("failed manifest has inconsistent failed role outcomes")
		}
	}
	return repaired, nil
}

func validateManifestFailures(manifest runManifestWire, expected map[string]string) error {
	if len(manifest.Failures) != len(expected) {
		return fmt.Errorf("manifest failures do not match failed role outcomes")
	}
	seen := make(map[string]struct{}, len(manifest.Failures))
	for _, failure := range manifest.Failures {
		if !domain.FailureClass(failure.Class).Valid() ||
			forbiddenPublicationFailure(domain.FailureClass(failure.Class)) ||
			failure.Stage != "review" ||
			failure.AttemptID == nil ||
			!validReasonCode(failure.ReasonCode) {
			return fmt.Errorf("manifest failure is invalid")
		}
		if _, err := domain.ParseAttemptID(*failure.AttemptID); err != nil {
			return fmt.Errorf("manifest failure attempt ID: %w", err)
		}
		expectedReason, ok := expected[*failure.AttemptID]
		if !ok || expectedReason != failure.ReasonCode {
			return fmt.Errorf("manifest failure does not match failed role outcome")
		}
		if _, duplicate := seen[*failure.AttemptID]; duplicate {
			return fmt.Errorf("manifest failure attempt ID is duplicated")
		}
		if manifest.State == string(domain.RunFailed) &&
			!domain.FailureClass(failure.Class).FallbackAllowed() {
			return fmt.Errorf("failed manifest contains non-fallback-eligible failure")
		}
		seen[*failure.AttemptID] = struct{}{}
	}
	return nil
}

func validateRestartStateSemantics(
	restart restartStateWire,
	expectedState domain.PersistedJournalState,
	normalExit domain.OperationalExitCode,
	final ports.FinalReviewIdentity,
	manifest ports.ImmutablePublicationArtifact,
	lineage ports.ImmutablePublicationArtifact,
	epoch ports.PublicationEpoch,
) error {
	sessionID, err := domain.ParseSessionID(restart.SessionID)
	if err != nil {
		return fmt.Errorf("session ID: %w", err)
	}
	runID, err := domain.ParseRunID(restart.RunID)
	if err != nil {
		return fmt.Errorf("run ID: %w", err)
	}
	paths, err := publicationPaths(sessionID, runID, final.ReviewID(), epoch.Value())
	if err != nil {
		return err
	}
	var manifestWire runManifestWire
	if err := unmarshalCanonicalPublicationRecord(manifest.Bytes(), &manifestWire, "run manifest"); err != nil {
		return err
	}
	if paths.final != final.Path() ||
		restart.PersistedJournalState != string(expectedState) ||
		restart.ExpectedStaged.Path != paths.staged.String() ||
		restart.ExpectedStaged.SHA256 != final.SHA256() ||
		restart.ExpectedFinal.Path != final.Path().String() ||
		restart.ExpectedFinal.SHA256 != final.SHA256() ||
		!validSHA256(restart.ValidatedCandidateSHA256) ||
		restart.ValidatedCandidateSHA256 != manifestWire.RecoveryJournal.ValidatedCandidateSHA256 ||
		restart.StoreEpoch != epoch.Value() ||
		restart.NormalExit != int(normalExit) ||
		restart.ManifestPath != manifest.Path().String() ||
		restart.LineageEdgePath != lineage.Path().String() ||
		restart.EpochPath != epoch.Record().Path().String() {
		return fmt.Errorf("restart state does not match the immutable composite")
	}
	return nil
}

func normalExitForPublicationAxes(coverage domain.CoverageStatus, ci domain.CIDecision) domain.OperationalExitCode {
	if coverage == domain.CoverageIncomplete {
		return domain.ExitIncompleteCoverage
	}
	if ci == domain.CIFail {
		return domain.ExitCommittedCIRejected
	}
	return domain.ExitCommittedPass
}

func validReasonPointer(value *string) bool {
	return value == nil || validReasonCode(*value)
}

func roleOrdinal(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if candidate == role {
			return index
		}
	}
	return -1
}
func terminalRoleState(state domain.RoleTaskState) bool {
	return state == domain.RoleTaskSucceeded || state == domain.RoleTaskFailed
}

func terminalAttemptState(state domain.AttemptState) bool {
	return state == domain.AttemptSucceeded || state == domain.AttemptFailed || state == domain.AttemptTimedOut ||
		state == domain.AttemptCancelled || state == domain.AttemptBlocked
}

func terminalInvocationState(state domain.InvocationState) bool {
	return state == domain.InvocationSucceeded || state == domain.InvocationFailed || state == domain.InvocationTimedOut ||
		state == domain.InvocationCancelled || state == domain.InvocationBlocked
}

func forbiddenPublicationFailure(class domain.FailureClass) bool {
	switch class {
	case domain.FailureSecurityPolicy, domain.FailureConfiguration, domain.FailureArtifact, domain.FailureInternal, domain.FailureCancelled:
		return true
	default:
		return false
	}
}

func clonePreparedRoles(source []preparedRole) []preparedRole {
	cloned := make([]preparedRole, len(source))
	for index, role := range source {
		cloned[index] = role
		cloned[index].attempts = clonePreparedAttempts(role.attempts)
		cloned[index].validFindingIDs = append([]string(nil), role.validFindingIDs...)
		cloned[index].limitations = append([]string(nil), role.limitations...)
	}
	return cloned
}

func clonePreparedAttempts(source []preparedAttempt) []preparedAttempt {
	cloned := make([]preparedAttempt, len(source))
	for index, attempt := range source {
		cloned[index] = attempt
		cloned[index].invocations = append([]preparedInvocation(nil), attempt.invocations...)
	}
	return cloned
}

func clonePreparedFindings(source []preparedFinding) []preparedFinding {
	cloned := make([]preparedFinding, len(source))
	for index, finding := range source {
		cloned[index] = finding
		cloned[index].evidence = make([]preparedEvidence, len(finding.evidence))
		for evidenceIndex, item := range finding.evidence {
			cloned[index].evidence[evidenceIndex] = item
			cloned[index].evidence[evidenceIndex].excerpt = cloneBytes(item.excerpt)
		}
	}
	return cloned
}

func clonePreparedFailures(source []preparedFailure) []preparedFailure {
	cloned := make([]preparedFailure, len(source))
	for index, failure := range source {
		cloned[index] = failure
		if failure.attemptID != nil {
			attemptID := *failure.attemptID
			cloned[index].attemptID = &attemptID
		}
	}
	return cloned
}

func cloneBytes(source []byte) []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source...)
}

func sha256Identifier(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nilSchemaValidator(validator SchemaValidator) bool {
	if validator == nil {
		return true
	}
	value := reflect.ValueOf(validator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func canonicalTime(value time.Time) (string, error) {
	if value.IsZero() {
		return "", fmt.Errorf("publication build: created time is required")
	}
	return value.UTC().Format(time.RFC3339Nano), nil
}
