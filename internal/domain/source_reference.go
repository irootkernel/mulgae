package domain

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// SourceReference identifies either a published review or an immutable failed-run
// recovery manifest. A recovery reference never carries publication authority.
type SourceReference struct {
	runID          RunID
	reviewID       ReviewID
	recoverySHA256 string
}

func NewPublishedSourceReference(run RunID, review ReviewID) (SourceReference, error) {
	reference := SourceReference{runID: run, reviewID: review}
	if !reference.Valid() {
		return SourceReference{}, fmt.Errorf("source reference: invalid published identity")
	}
	return reference, nil
}

func NewRecoverySourceReference(run RunID, manifestSHA256 string) (SourceReference, error) {
	reference := SourceReference{runID: run, recoverySHA256: manifestSHA256}
	if !reference.Valid() {
		return SourceReference{}, fmt.Errorf("source reference: invalid recovery identity")
	}
	return reference, nil
}

func (reference SourceReference) Valid() bool {
	if _, err := ParseRunID(reference.runID.String()); err != nil {
		return false
	}
	if reference.recoverySHA256 == "" {
		_, err := ParseReviewID(reference.reviewID.String())
		return err == nil
	}
	if reference.reviewID.String() != "" || !strings.HasPrefix(reference.recoverySHA256, "sha256:") {
		return false
	}
	digest := strings.TrimPrefix(reference.recoverySHA256, "sha256:")
	bytes, err := hex.DecodeString(digest)
	return err == nil && len(bytes) == 32 && strings.ToLower(digest) == digest
}
func (reference SourceReference) RunID() RunID                   { return reference.runID }
func (reference SourceReference) ReviewID() ReviewID             { return reference.reviewID }
func (reference SourceReference) RecoveryManifestSHA256() string { return reference.recoverySHA256 }
func (reference SourceReference) Kind() string {
	if !reference.Valid() {
		return ""
	}
	if reference.recoverySHA256 != "" {
		return "failed_run_recovery"
	}
	return "published_review"
}
