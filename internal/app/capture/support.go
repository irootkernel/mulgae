package capture

import (
	"fmt"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// VerifySupport reconstructs the complete capture exclusively from hash-bound
// publication artifacts. Callers retain ownership of the stable P2 observation.
func VerifySupport(session domain.SessionID, run domain.RunID, targetSHA256 string, baseOID, headOID *string, artifacts map[string]ports.ImmutablePublicationArtifact) (domain.CaptureIdentity, error) {
	prefix := session.String() + "/" + run.String() + "/target/"
	manifestArtifact, ok := artifacts[prefix+"capture-manifest.json"]
	if !ok {
		return domain.CaptureIdentity{}, fmt.Errorf("capture support: manifest absent")
	}
	manifest, err := DecodeCaptureManifest(manifestArtifact.Bytes())
	if err != nil || manifest.Target.SHA256 != targetSHA256 || !matchesObjectID(manifest.Target.BaseObjectID, baseOID) || !matchesObjectID(manifest.Target.HeadObjectID, headOID) {
		return domain.CaptureIdentity{}, fmt.Errorf("capture support: target binding invalid")
	}
	archive, ok := artifacts[prefix+"captured-review.json"]
	if !ok {
		return domain.CaptureIdentity{}, fmt.Errorf("capture support: archive absent")
	}
	references, err := ports.CapturedReviewArchiveBlobReferences(archive.Bytes())
	if err != nil {
		return domain.CaptureIdentity{}, fmt.Errorf("capture support: archive invalid: %w", err)
	}
	blobs := make([]ports.CapturedReviewArchiveBlob, 0, len(references))
	for _, reference := range references {
		artifact, ok := artifacts[prefix+reference.Path().String()]
		if !ok || artifact.SHA256() != reference.SHA256() {
			return domain.CaptureIdentity{}, fmt.Errorf("capture support: blob binding invalid")
		}
		blob, err := ports.NewCapturedReviewArchiveBlob(reference.Path(), artifact.Bytes())
		if err != nil {
			return domain.CaptureIdentity{}, err
		}
		blobs = append(blobs, blob)
	}
	material, err := ports.RestoreCapturedReviewArchive(archive.Bytes(), blobs)
	if err != nil {
		return domain.CaptureIdentity{}, fmt.Errorf("capture support: restore failed: %w", err)
	}
	identity, err := manifest.Identity()
	if err != nil {
		return domain.CaptureIdentity{}, err
	}
	if err := VerifyCaptureManifest(manifestArtifact.Bytes(), material, identity); err != nil {
		return domain.CaptureIdentity{}, err
	}
	return identity, nil
}

func matchesObjectID(captured string, published *string) bool {
	if published == nil {
		return captured == ""
	}
	return captured == *published
}
