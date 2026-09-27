package publication

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// WithCapturedMaterial binds the admitted immutable input independently of
// provider attempts, including a provider-free no-change publication.
func (candidate PreparedCandidate) WithCapturedMaterial(archive []byte) (PreparedCandidate, error) {
	material, err := ports.UnmarshalCapturedReviewMaterial(archive)
	if err != nil || ("sha256:"+material.Target().Identity().SHA256() != candidate.target.sha256 || material.Target().Identity().BaseObjectID() != candidate.target.baseOID || material.Target().Identity().HeadObjectID() != candidate.target.headOID) {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: capture target mismatch")
	}
	if _, err := capture.NewCaptureManifest(material); err != nil {
		return PreparedCandidate{}, err
	}
	candidate.capturedArchive = cloneBytes(archive)
	return candidate, nil
}

func (candidate PreparedCandidate) buildCaptureSupport(existing []ports.ImmutablePublicationArtifact) ([]ports.ImmutablePublicationArtifact, error) {
	if len(candidate.capturedArchive) == 0 && candidate.lineage.runType != domain.RunTypeReview {
		if archive := candidate.childRuntimeCapture(); len(archive) > 0 {
			bound, err := candidate.WithCapturedMaterial(archive)
			if errors.Is(err, capture.ErrCaptureIdentityUnavailable) {
				return existing, nil
			}
			if err != nil {
				return nil, err
			}
			candidate = bound
		}
	}
	if len(candidate.capturedArchive) == 0 {
		return existing, nil
	}
	material, err := ports.UnmarshalCapturedReviewMaterial(candidate.capturedArchive)
	if err != nil {
		return nil, err
	}
	manifest, err := capture.NewCaptureManifest(material)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	archive, err := ports.NewCapturedReviewArchive(material)
	if err != nil {
		return nil, err
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/target/"
	byPath := make(map[string]ports.ImmutablePublicationArtifact, len(existing))
	for _, artifact := range existing {
		byPath[artifact.Path().String()] = artifact
	}
	appendArtifact := func(name string, data []byte) error {
		path, err := ports.NewSafeRelativePath(prefix + name)
		if err != nil {
			return err
		}
		if old, ok := byPath[path.String()]; ok {
			if !bytes.Equal(old.Bytes(), data) {
				return fmt.Errorf("publication candidate: retained capture differs from runtime capture")
			}
			return nil
		}
		artifact, err := immutableArtifact(path, data)
		if err != nil {
			return err
		}
		existing = append(existing, artifact)
		byPath[path.String()] = artifact
		return nil
	}
	if err := appendArtifact("capture-manifest.json", manifestBytes); err != nil {
		return nil, err
	}
	if err := appendArtifact("captured-review.json", archive.Manifest()); err != nil {
		return nil, err
	}
	for _, blob := range archive.Blobs() {
		if err := appendArtifact(blob.Path().String(), blob.Bytes()); err != nil {
			return nil, err
		}
	}
	if _, err := capture.VerifySupport(candidate.sessionID, candidate.runID, candidate.target.sha256, &candidate.target.baseOID, &candidate.target.headOID, byPath); err != nil {
		return nil, err
	}
	return existing, nil
}

// Runtime serialization already rejects divergent archives across invocations.
func (candidate PreparedCandidate) childRuntimeCapture() []byte {
	for _, role := range candidate.roles {
		for _, attempt := range role.attempts {
			for _, invocation := range attempt.invocations {
				if invocation.runtime != nil && len(invocation.runtime.capturedArchive) > 0 {
					return invocation.runtime.capturedArchive
				}
			}
		}
	}
	return nil
}
