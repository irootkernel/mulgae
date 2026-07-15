package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// VerifiedFindingEvidence binds an exact final finding proof to the immutable
// receipts produced by the coordinator-owned current-evidence verifier.
type VerifiedFindingEvidence struct {
	findingID       string
	finding         domain.Finding
	validationProof validation.FindingEvidenceClaims
	claims          []validation.CurrentEvidenceClaim
	receipts        []evidence.CurrentReceipt
}

// FindingID returns the final system-assigned finding ID.
func (verified VerifiedFindingEvidence) FindingID() string { return verified.findingID }

func (verified VerifiedFindingEvidence) findingProof() domain.Finding { return verified.finding }

func (verified VerifiedFindingEvidence) matchesFinding(finding domain.Finding) bool {
	validationState, err := finding.WithEvidenceState(verified.finding.EvidenceState())
	if err != nil {
		return false
	}
	return verified.findingID == finding.ID() &&
		sameFindingIdentity(verified.finding, validationState) &&
		verified.validationProof.MatchesFinding(verified.finding)
}

// Receipts returns caller-owned receipt values in the supplied claim order.
func (verified VerifiedFindingEvidence) Receipts() []evidence.CurrentReceipt {
	return append([]evidence.CurrentReceipt(nil), verified.receipts...)
}

// EvidencePolicy is an immutable minimum receipt-verification policy.
type EvidencePolicy struct {
	required   []domain.Severity
	structural bool
}

var minimumEvidenceSeverities = [...]domain.Severity{
	domain.SeverityHigh,
	domain.SeverityCritical,
	domain.SeverityBlocker,
}

// NewEvidencePolicy canonicalizes required severities. Every policy must retain
// the high, critical, and blocker verification minimum.
func NewEvidencePolicy(required []domain.Severity) (EvidencePolicy, error) {
	seen := make(map[domain.Severity]struct{}, len(required))
	for _, severity := range required {
		if !severity.Valid() {
			return EvidencePolicy{}, fmt.Errorf("review evidence policy: invalid required severity %q", severity)
		}
		seen[severity] = struct{}{}
	}
	for _, severity := range minimumEvidenceSeverities {
		if _, ok := seen[severity]; !ok {
			return EvidencePolicy{}, fmt.Errorf(
				"review evidence policy: required severities must include high, critical, and blocker",
			)
		}
	}

	canonical := make([]domain.Severity, 0, len(seen))
	for severity := range seen {
		canonical = append(canonical, severity)
	}
	sort.Slice(canonical, func(left, right int) bool {
		return canonical[left].Rank() < canonical[right].Rank()
	})
	return EvidencePolicy{required: canonical}, nil
}

// DefaultEvidencePolicy requires verified receipts for exactly high, critical,
// and blocker findings.
func DefaultEvidencePolicy() EvidencePolicy {
	policy, err := NewEvidencePolicy(minimumEvidenceSeverities[:])
	if err != nil {
		panic(fmt.Sprintf("review evidence policy default: %v", err))
	}
	return policy
}

// Requires reports whether severity must have all receipts verified.
func (policy EvidencePolicy) Requires(severity domain.Severity) bool {
	for _, required := range policy.required {
		if severity == required {
			return true
		}
	}
	return false
}

// RequiredSeverities returns the canonical required severity set.
func (policy EvidencePolicy) RequiredSeverities() []domain.Severity {
	return append([]domain.Severity(nil), policy.required...)
}

func (policy EvidencePolicy) valid() bool {
	if policy.structural {
		return len(policy.required) == 0
	}
	if len(policy.required) < len(minimumEvidenceSeverities) {
		return false
	}
	for index, severity := range policy.required {
		if !severity.Valid() || (index > 0 && policy.required[index-1].Rank() >= severity.Rank()) {
			return false
		}
	}
	for _, severity := range minimumEvidenceSeverities {
		if !policy.Requires(severity) {
			return false
		}
	}
	return true
}

func structuralEvidencePolicy() EvidencePolicy {
	return EvidencePolicy{structural: true}
}

// EvidencePolicyError rejects output whose policy-required finding lacks fully
// verified evidence. It identifies the finding without exposing receipt data.
type EvidencePolicyError struct {
	findingID string
	severity  domain.Severity
	state     domain.EvidenceState
}

// Error implements error.
func (err *EvidencePolicyError) Error() string {
	if err == nil {
		return "review evidence policy rejected"
	}
	return fmt.Sprintf(
		"review evidence policy: invalid evidence for required finding %q with severity %q: %q",
		err.findingID,
		err.severity,
		err.state,
	)
}

// FindingID returns the policy-rejected finding ID.
func (err *EvidencePolicyError) FindingID() string {
	if err == nil {
		return ""
	}
	return err.findingID
}

// Severity returns the policy-rejected finding severity.
func (err *EvidencePolicyError) Severity() domain.Severity {
	if err == nil {
		return ""
	}
	return err.severity
}

// EvidenceState returns the reduced state that violated the policy.
func (err *EvidencePolicyError) EvidenceState() domain.EvidenceState {
	if err == nil {
		return ""
	}
	return err.state
}

// AsEvidencePolicyError returns the typed policy error, including when wrapped.
func AsEvidencePolicyError(err error) (*EvidencePolicyError, bool) {
	var policyError *EvidencePolicyError
	if !errors.As(err, &policyError) {
		return nil, false
	}
	return policyError, true
}

// ReduceVerifiedFindingEvidence proves each finding's exact unverified
// validation prestate has one nonempty verifier-owned receipt group with the
// same validation claim set, then projects receipt outcomes into immutable
// finding evidence states.
func ReduceVerifiedFindingEvidence(
	findings []domain.Finding,
	groups []VerifiedFindingEvidence,
	policy EvidencePolicy,
) ([]domain.Finding, error) {
	if !policy.valid() {
		return nil, fmt.Errorf("review evidence reduction: invalid evidence policy")
	}
	if len(findings) != len(groups) {
		return nil, fmt.Errorf(
			"review evidence reduction: finding count %d does not match receipt group count %d",
			len(findings),
			len(groups),
		)
	}

	reduced := make([]domain.Finding, len(findings))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID() != expectedID {
			return nil, fmt.Errorf(
				"review evidence reduction: finding %d ID %q is not canonical %q",
				index,
				finding.ID(),
				expectedID,
			)
		}
		if !groups[index].matchesFinding(finding) {
			return nil, fmt.Errorf(
				"review evidence reduction: receipt group %d does not prove the exact finding %q",
				index,
				expectedID,
			)
		}
		claims := groups[index].claims
		proofClaims := groups[index].validationProof.Claims()
		receipts := groups[index].Receipts()
		if len(proofClaims) == 0 || len(claims) == 0 || len(receipts) == 0 {
			return nil, fmt.Errorf("review evidence reduction: finding %q has no verifier receipt claims", expectedID)
		}
		if len(receipts) != len(claims) || len(claims) != len(proofClaims) {
			return nil, fmt.Errorf(
				"review evidence reduction: finding %q receipt, claim, and proof counts differ",
				expectedID,
			)
		}
		for claimIndex, receipt := range receipts {
			if !currentEvidenceClaimsEqual(claims[claimIndex], proofClaims[claimIndex]) {
				return nil, fmt.Errorf(
					"review evidence reduction: finding %q claim %d does not match its validation proof",
					expectedID,
					claimIndex,
				)
			}
			if !receiptMatchesValidationClaim(receipt, claims[claimIndex]) {
				return nil, fmt.Errorf(
					"review evidence reduction: finding %q receipt %d does not match its validation claim",
					expectedID,
					claimIndex,
				)
			}
		}

		state := reducedEvidenceState(receipts)
		updated, err := finding.WithEvidenceState(state)
		if err != nil {
			return nil, fmt.Errorf("review evidence reduction: finding %q: %w", expectedID, err)
		}
		if policy.Requires(updated.Severity()) && state != domain.EvidenceVerified {
			return nil, &EvidencePolicyError{
				findingID: updated.ID(),
				severity:  updated.Severity(),
				state:     state,
			}
		}
		reduced[index] = updated
	}
	return reduced, nil
}

func reducedEvidenceState(receipts []evidence.CurrentReceipt) domain.EvidenceState {
	verified := 0
	for _, receipt := range receipts {
		if receipt.Status() == evidence.ReceiptVerified {
			verified++
		}
	}
	if verified == len(receipts) {
		return domain.EvidenceVerified
	}
	if verified != 0 {
		return domain.EvidencePartiallyVerified
	}
	return closedUnverifiedEvidenceState(receipts)
}

func closedUnverifiedEvidenceState(receipts []evidence.CurrentReceipt) domain.EvidenceState {
	state, exact := receiptClosedEvidenceState(receipts[0])
	if !exact {
		return domain.EvidenceUnverified
	}
	for _, receipt := range receipts[1:] {
		other, exact := receiptClosedEvidenceState(receipt)
		if !exact || other != state {
			return domain.EvidenceUnverified
		}
	}
	return state
}

func receiptClosedEvidenceState(receipt evidence.CurrentReceipt) (domain.EvidenceState, bool) {
	switch receipt.ReasonCode() {
	case evidence.ReasonInvalidPath:
		return domain.EvidenceInvalidPath, receipt.Status() == evidence.ReceiptInvalid
	case evidence.ReasonInvalidLineRange, evidence.ReasonLineRangeOutOfBounds:
		return domain.EvidenceInvalidLine, receipt.Status() == evidence.ReceiptInvalid
	case evidence.ReasonQuoteMismatch:
		return domain.EvidenceQuoteMismatch, receipt.Status() == evidence.ReceiptInvalid
	case evidence.ReasonStaleTarget:
		return domain.EvidenceOutsideScope, receipt.Status() == evidence.ReceiptStale
	default:
		return domain.EvidenceUnverified, false
	}
}

func cloneVerifiedFindingEvidence(groups []VerifiedFindingEvidence) []VerifiedFindingEvidence {
	copied := make([]VerifiedFindingEvidence, len(groups))
	for index, group := range groups {
		copied[index] = VerifiedFindingEvidence{
			findingID:       group.FindingID(),
			finding:         group.findingProof(),
			validationProof: group.validationProof,
			claims:          append([]validation.CurrentEvidenceClaim(nil), group.claims...),
			receipts:        group.Receipts(),
		}
	}
	return copied
}

// VerifyValidatedEvidence converts validated current-evidence claims into
// verifier-owned claims and verifies them in their deterministic input order.
// Any invalid bridge input, cancellation, or verifier failure rejects the whole
// result so no partial evidence can escape.
func VerifyValidatedEvidence(
	ctx context.Context,
	verifier *evidence.Verifier,
	groups []validation.FindingEvidenceClaims,
) ([]VerifiedFindingEvidence, error) {
	if verifier == nil {
		return nil, fmt.Errorf("review evidence verification: nil verifier")
	}
	if err := verifiedEvidenceContextError(ctx); err != nil {
		return nil, err
	}

	prepared := make([]preparedFindingEvidence, len(groups))
	for groupIndex, group := range groups {
		if err := verifiedEvidenceContextError(ctx); err != nil {
			return nil, err
		}
		findingID := group.FindingID()
		if expected := fmt.Sprintf("F%03d", groupIndex+1); findingID != expected {
			return nil, fmt.Errorf(
				"review evidence verification: finding group %d ID %q is not canonical %q",
				groupIndex,
				findingID,
				expected,
			)
		}

		finding := group.Finding()
		if !group.MatchesFinding(finding) {
			return nil, fmt.Errorf(
				"review evidence verification: finding group %d proof, ID, or claims are inconsistent",
				groupIndex,
			)
		}
		if finding.ID() != findingID {
			return nil, fmt.Errorf(
				"review evidence verification: finding group %d proof ID %q does not match %q",
				groupIndex,
				finding.ID(),
				findingID,
			)
		}
		claims := group.Claims()
		if len(claims) == 0 {
			return nil, fmt.Errorf("review evidence verification: finding %q has no evidence claims", findingID)
		}

		preparedClaims := make([]evidence.CurrentClaim, len(claims))
		for claimIndex, claim := range claims {
			if err := verifiedEvidenceContextError(ctx); err != nil {
				return nil, err
			}
			converted, err := newVerifiedCurrentClaim(claim)
			if err != nil {
				return nil, fmt.Errorf(
					"review evidence verification: finding %q claim %d: %w",
					findingID,
					claimIndex,
					err,
				)
			}
			if claimIndex > 0 && validation.CompareCurrentEvidenceClaims(claims[claimIndex-1], claim) > 0 {
				return nil, fmt.Errorf(
					"review evidence verification: finding %q claims are not in canonical order",
					findingID,
				)
			}
			preparedClaims[claimIndex] = converted
		}
		prepared[groupIndex] = preparedFindingEvidence{
			findingID:        findingID,
			finding:          finding,
			validationProof:  group,
			validationClaims: append([]validation.CurrentEvidenceClaim(nil), claims...),
			claims:           preparedClaims,
		}
	}

	verified := make([]VerifiedFindingEvidence, len(prepared))
	for groupIndex, group := range prepared {
		receipts := make([]evidence.CurrentReceipt, len(group.claims))
		for claimIndex, claim := range group.claims {
			if err := verifiedEvidenceContextError(ctx); err != nil {
				return nil, err
			}
			receipt, err := verifier.VerifyCurrent(ctx, claim)
			if err != nil {
				return nil, fmt.Errorf(
					"review evidence verification: finding %q claim %d: %w",
					group.findingID,
					claimIndex,
					err,
				)
			}
			if err := verifiedEvidenceContextError(ctx); err != nil {
				return nil, err
			}
			if !receiptMatchesValidationClaim(receipt, group.validationClaims[claimIndex]) {
				return nil, fmt.Errorf(
					"review evidence verification: finding %q receipt %d does not match its validation claim",
					group.findingID,
					claimIndex,
				)
			}
			receipts[claimIndex] = receipt
		}
		verified[groupIndex] = VerifiedFindingEvidence{
			findingID:       group.findingID,
			finding:         group.finding,
			validationProof: group.validationProof,
			claims:          append([]validation.CurrentEvidenceClaim(nil), group.validationClaims...),
			receipts:        receipts,
		}
	}
	return verified, nil
}

type preparedFindingEvidence struct {
	findingID        string
	finding          domain.Finding
	validationProof  validation.FindingEvidenceClaims
	validationClaims []validation.CurrentEvidenceClaim
	claims           []evidence.CurrentClaim
}

func receiptMatchesValidationClaim(receipt evidence.CurrentReceipt, claim validation.CurrentEvidenceClaim) bool {
	receiptClaim := receipt.Claim()
	return receiptClaim.TargetSHA256() == claim.TargetSHA256() &&
		receiptClaim.Path() == claim.Path() &&
		receiptClaim.Side() == evidence.Side(claim.Side()) &&
		receiptClaim.LineStart() == claim.LineStart() &&
		receiptClaim.LineEnd() == claim.LineEnd() &&
		bytes.Equal(receiptClaim.QuoteBytes(), claim.QuoteBytes())
}
func currentEvidenceClaimsEqual(left, right validation.CurrentEvidenceClaim) bool {
	return left.TargetSHA256() == right.TargetSHA256() &&
		left.Path() == right.Path() &&
		left.Side() == right.Side() &&
		left.LineStart() == right.LineStart() &&
		left.LineEnd() == right.LineEnd() &&
		bytes.Equal(left.QuoteBytes(), right.QuoteBytes())
}
func verifiedEvidenceContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("review evidence verification: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("review evidence verification: context: %w", err)
	}
	return nil
}

func newVerifiedCurrentClaim(claim validation.CurrentEvidenceClaim) (evidence.CurrentClaim, error) {
	side, err := verifiedEvidenceSide(claim.Side())
	if err != nil {
		return evidence.CurrentClaim{}, err
	}
	converted, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: claim.TargetSHA256(),
		Side:         side,
		Path:         claim.Path().String(),
		LineStart:    claim.LineStart(),
		LineEnd:      claim.LineEnd(),
		Quote:        string(claim.QuoteBytes()),
	})
	if err != nil {
		return evidence.CurrentClaim{}, err
	}
	return converted, nil
}

func verifiedEvidenceSide(side validation.CurrentEvidenceSide) (evidence.Side, error) {
	switch side {
	case validation.CurrentEvidenceSideBase:
		return evidence.SideBase, nil
	case validation.CurrentEvidenceSideHead:
		return evidence.SideHead, nil
	case validation.CurrentEvidenceSideWorktree:
		return evidence.SideWorktree, nil
	default:
		return "", fmt.Errorf("invalid current evidence side %q", side)
	}
}
