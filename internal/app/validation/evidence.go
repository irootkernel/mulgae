package validation

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// CurrentEvidenceSide identifies one closed side of the trusted current target.
type CurrentEvidenceSide string

const (
	CurrentEvidenceSideBase     CurrentEvidenceSide = "base"
	CurrentEvidenceSideHead     CurrentEvidenceSide = "head"
	CurrentEvidenceSideWorktree CurrentEvidenceSide = "worktree"
	CurrentEvidenceSideIndex    CurrentEvidenceSide = "index"
)

// Valid reports whether side is a supported current-target side.
func (side CurrentEvidenceSide) Valid() bool {
	switch side {
	case CurrentEvidenceSideBase, CurrentEvidenceSideHead, CurrentEvidenceSideWorktree, CurrentEvidenceSideIndex:
		return true
	default:
		return false
	}
}

// CurrentEvidenceClaim is an immutable, unverified current-evidence claim.
// Target identity is supplied only by trusted validation scope. Verification is
// intentionally owned by the coordinator's evidence verifier.
type CurrentEvidenceClaim struct {
	targetSHA256 string
	path         ports.SafeRelativePath
	lineStart    int
	lineEnd      int
	side         CurrentEvidenceSide
	quote        []byte
}

// TargetSHA256 returns the canonical sha256:<lowercase-hex> trusted target ID.
func (claim CurrentEvidenceClaim) TargetSHA256() string { return claim.targetSHA256 }

// Path returns the canonical relative path claimed within the trusted target.
func (claim CurrentEvidenceClaim) Path() ports.SafeRelativePath { return claim.path }

// LineStart returns the one-based inclusive first line of the claim.
func (claim CurrentEvidenceClaim) LineStart() int { return claim.lineStart }

// LineEnd returns the one-based inclusive final line of the claim.
func (claim CurrentEvidenceClaim) LineEnd() int { return claim.lineEnd }

// Side returns the claimed closed side of the trusted target.
func (claim CurrentEvidenceClaim) Side() CurrentEvidenceSide { return claim.side }

// QuoteBytes returns a defensive copy of the provider's exact quote bytes.
func (claim CurrentEvidenceClaim) QuoteBytes() []byte {
	return append([]byte(nil), claim.quote...)
}

// CompareCurrentEvidenceClaims orders claims by their canonical evidence region:
// path, numeric line range, side, normalized quote, then exact quote bytes.
// Target identity is a final trusted tie-breaker for callers comparing claims
// from different validation scopes.
func CompareCurrentEvidenceClaims(left, right CurrentEvidenceClaim) int {
	if comparison := strings.Compare(left.path.String(), right.path.String()); comparison != 0 {
		return comparison
	}
	if left.lineStart != right.lineStart {
		if left.lineStart < right.lineStart {
			return -1
		}
		return 1
	}
	if left.lineEnd != right.lineEnd {
		if left.lineEnd < right.lineEnd {
			return -1
		}
		return 1
	}
	if comparison := strings.Compare(string(left.side), string(right.side)); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(normalizeContent(string(left.quote)), normalizeContent(string(right.quote))); comparison != 0 {
		return comparison
	}
	if comparison := bytes.Compare(left.quote, right.quote); comparison != 0 {
		return comparison
	}
	return strings.Compare(left.targetSHA256, right.targetSHA256)
}

func (claim CurrentEvidenceClaim) clone() CurrentEvidenceClaim {
	claim.quote = append([]byte(nil), claim.quote...)
	return claim
}

// FindingEvidenceClaims binds an exact final system-assigned finding proof to
// its immutable, unverified current-evidence claims.
type FindingEvidenceClaims struct {
	findingID    string
	targetSHA256 string
	finding      domain.Finding
	claims       []CurrentEvidenceClaim
}

// FindingID returns the final system-assigned finding ID.
func (claims FindingEvidenceClaims) FindingID() string { return claims.findingID }

// Finding returns the immutable final validation finding proof.
func (claims FindingEvidenceClaims) Finding() domain.Finding { return claims.finding }

// MatchesFinding reports whether finding is the exact complete final validation
// finding bound to these claims. It also rejects an internally inconsistent
// proof, ID, or claim set.
func (claims FindingEvidenceClaims) MatchesFinding(finding domain.Finding) bool {
	return claims.finding == finding && claims.valid()
}

// Claims returns defensive copies in normalized evidence-region order.
func (claims FindingEvidenceClaims) Claims() []CurrentEvidenceClaim {
	return cloneCurrentEvidenceClaims(claims.claims)
}

func (claims FindingEvidenceClaims) clone() FindingEvidenceClaims {
	claims.claims = cloneCurrentEvidenceClaims(claims.claims)
	return claims
}
func newFindingEvidenceClaims(
	finding domain.Finding,
	claims []CurrentEvidenceClaim,
	trustedTargetSHA256 string,
) (FindingEvidenceClaims, error) {
	result := FindingEvidenceClaims{
		findingID:    finding.ID(),
		targetSHA256: trustedTargetSHA256,
		finding:      finding,
		claims:       cloneCurrentEvidenceClaims(claims),
	}
	if !result.valid() {
		return FindingEvidenceClaims{}, fmt.Errorf("finding evidence proof, ID, and claims disagree")
	}
	return result, nil
}

func (claims FindingEvidenceClaims) valid() bool {
	if claims.findingID == "" ||
		claims.findingID != claims.finding.ID() ||
		claims.targetSHA256 == "" ||
		claims.finding.Lifecycle() != domain.FindingOpen ||
		claims.finding.EvidenceState() != domain.EvidenceUnverified ||
		claims.finding.Validate() != nil ||
		len(claims.claims) == 0 {
		return false
	}

	targetSHA256 := claims.targetSHA256
	regionParts := make([]string, len(claims.claims))
	for index, claim := range claims.claims {
		if !validCurrentEvidenceClaim(claim) ||
			claim.targetSHA256 != targetSHA256 ||
			(index > 0 && CompareCurrentEvidenceClaims(claims.claims[index-1], claim) > 0) {
			return false
		}
		regionParts[index] = evidenceKey(claim)
	}

	reconstructed, err := domain.NewFinding(domain.FindingInput{
		Severity:                 claims.finding.Severity(),
		Path:                     claims.claims[0].Path().String(),
		LineStart:                claims.claims[0].LineStart(),
		Role:                     claims.finding.Role(),
		ProviderInstance:         claims.finding.ProviderInstance(),
		Title:                    claims.finding.Title(),
		Description:              claims.finding.Description(),
		Recommendation:           claims.finding.Recommendation(),
		Confidence:               claims.finding.Confidence(),
		Lifecycle:                claims.finding.Lifecycle(),
		EvidenceState:            claims.finding.EvidenceState(),
		NormalizedRuleCategory:   claims.finding.NormalizedRuleCategory(),
		NormalizedEvidenceRegion: strings.Join(regionParts, " | "),
	})
	return err == nil && sameFindingContent(reconstructed, claims.finding)
}

func validCurrentEvidenceClaim(claim CurrentEvidenceClaim) bool {
	targetSHA256, err := canonicalTargetSHA256(claim.targetSHA256)
	return err == nil &&
		targetSHA256 == claim.targetSHA256 &&
		claim.path.Valid() &&
		claim.lineStart > 0 &&
		claim.lineEnd >= claim.lineStart &&
		claim.side.Valid() &&
		len(claim.quote) > 0 &&
		utf8.Valid(claim.quote)
}

func sameFindingContent(left, right domain.Finding) bool {
	return left.Fingerprint() == right.Fingerprint() &&
		left.Severity() == right.Severity() &&
		left.Path() == right.Path() &&
		left.LineStart() == right.LineStart() &&
		left.Role() == right.Role() &&
		left.ProviderInstance() == right.ProviderInstance() &&
		left.Title() == right.Title() &&
		left.Description() == right.Description() &&
		left.Recommendation() == right.Recommendation() &&
		left.Confidence() == right.Confidence() &&
		left.Lifecycle() == right.Lifecycle() &&
		left.EvidenceState() == right.EvidenceState() &&
		left.NormalizedRuleCategory() == right.NormalizedRuleCategory() &&
		left.NormalizedEvidenceRegion() == right.NormalizedEvidenceRegion()
}

func cloneCurrentEvidenceClaims(claims []CurrentEvidenceClaim) []CurrentEvidenceClaim {
	if claims == nil {
		return nil
	}
	cloned := make([]CurrentEvidenceClaim, len(claims))
	for index := range claims {
		cloned[index] = claims[index].clone()
	}
	return cloned
}

func cloneFindingEvidenceClaims(claims []FindingEvidenceClaims) []FindingEvidenceClaims {
	if claims == nil {
		return nil
	}
	cloned := make([]FindingEvidenceClaims, len(claims))
	for index := range claims {
		cloned[index] = claims[index].clone()
	}
	return cloned
}
