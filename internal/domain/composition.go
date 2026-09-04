package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	CompositeTargetMismatch        = "composite_target_mismatch"
	CompositeTargetDigestInvalid   = "composite_target_digest_invalid"
	CompositeLineageMismatch       = "composite_lineage_mismatch"
	CompositeRoleNotRequired       = "composite_role_not_required"
	CompositeRoleAlreadySatisfied  = "composite_role_already_satisfied"
	CompositeRecoveryIncomplete    = "composite_recovery_incomplete"
	CompositeRecoveryUnavailable   = "composite_recovery_unavailable"
	CompositeSelectionAmbiguous    = "composite_selection_ambiguous"
	CompositeValidationFailed      = "composite_validation_failed"
	CompositePublicationIncomplete = "composite_publication_incomplete"
)

// CompositionState describes the retry-safe state of one exact composition.
type CompositionState string

const (
	CompositionCreated               CompositionState = "created"
	CompositionRecovered             CompositionState = "recovered"
	CompositionAlreadyCommitted      CompositionState = "already_committed"
	CompositionPublicationIncomplete CompositionState = "publication_incomplete"
	CompositionFailed                CompositionState = "failed"
)

func (state CompositionState) Valid() bool {
	return oneOf(string(state), string(CompositionCreated), string(CompositionRecovered), string(CompositionAlreadyCommitted), string(CompositionPublicationIncomplete), string(CompositionFailed))
}

// CompositionSource is the trusted coordinate of one accepted role result.
type CompositionSource struct {
	role      Role
	runID     RunID
	reviewID  ReviewID
	attemptID AttemptID
}

func NewCompositionSource(role Role, runID RunID, reviewID ReviewID, attemptID AttemptID) (CompositionSource, error) {
	if !role.Valid() || runID.String() == "" || reviewID.String() == "" || attemptID.String() == "" {
		return CompositionSource{}, fmt.Errorf("composition source: %w: role and exact source identities are required", ErrInvariant)
	}
	return CompositionSource{role: role, runID: runID, reviewID: reviewID, attemptID: attemptID}, nil
}

func (source CompositionSource) Role() Role           { return source.role }
func (source CompositionSource) RunID() RunID         { return source.runID }
func (source CompositionSource) ReviewID() ReviewID   { return source.reviewID }
func (source CompositionSource) AttemptID() AttemptID { return source.attemptID }

// CompositionFingerprint binds one root to one exact, role-complete recovery mapping.
type CompositionFingerprint struct{ value string }

func NewCompositionFingerprint(root RunID, sources []CompositionSource) (CompositionFingerprint, error) {
	if root.String() == "" || len(sources) == 0 || len(sources) > len(FixedRoleOrder()) {
		return CompositionFingerprint{}, fmt.Errorf("composition fingerprint: %w: root and bounded sources are required", ErrInvariant)
	}
	ordered := append([]CompositionSource(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return rolePosition(ordered[i].role) < rolePosition(ordered[j].role) })
	seen := make(map[Role]struct{}, len(ordered))
	var input strings.Builder
	input.WriteString("mulgae-review-composition-v1\x00")
	writeCompositionField(&input, root.String())
	for _, source := range ordered {
		if !source.role.Valid() || source.runID.String() == "" || source.reviewID.String() == "" || source.attemptID.String() == "" {
			return CompositionFingerprint{}, fmt.Errorf("composition fingerprint: %w: invalid source", ErrInvariant)
		}
		if _, duplicate := seen[source.role]; duplicate {
			return CompositionFingerprint{}, fmt.Errorf("composition fingerprint: %w: duplicate role %q", ErrInvariant, source.role)
		}
		seen[source.role] = struct{}{}
		writeCompositionField(&input, string(source.role))
		writeCompositionField(&input, source.runID.String())
		writeCompositionField(&input, source.attemptID.String())
	}
	digest := sha256.Sum256([]byte(input.String()))
	return CompositionFingerprint{value: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func (fingerprint CompositionFingerprint) String() string { return fingerprint.value }

func writeCompositionField(builder *strings.Builder, value string) {
	fmt.Fprintf(builder, "%d:", len(value))
	builder.WriteString(value)
	builder.WriteByte('|')
}

func rolePosition(role Role) int {
	for index, candidate := range FixedRoleOrder() {
		if candidate == role {
			return index
		}
	}
	return len(FixedRoleOrder())
}

func CompositeReasonCodes() []string {
	return []string{CompositeTargetMismatch, CompositeTargetDigestInvalid, CompositeLineageMismatch, CompositeRoleNotRequired, CompositeRoleAlreadySatisfied, CompositeRecoveryIncomplete, CompositeRecoveryUnavailable, CompositeSelectionAmbiguous, CompositeValidationFailed, CompositePublicationIncomplete}
}
