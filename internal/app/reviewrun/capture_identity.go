package reviewrun

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/irootkernel/mulgae/internal/app/capture"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// These names preserve the planning contract while publication and query share
// the same capture encoding without depending on review orchestration.
const CaptureManifestVersion = capture.CaptureManifestVersion

var ErrCaptureIdentityUnavailable = capture.ErrCaptureIdentityUnavailable

type CaptureManifest = capture.CaptureManifest
type CaptureTarget = capture.CaptureTarget
type CaptureFile = capture.CaptureFile
type CaptureContext = capture.CaptureContext

func NewCaptureManifest(material ports.CapturedReviewMaterial) (CaptureManifest, error) {
	return capture.NewCaptureManifest(material)
}

func DecodeCaptureManifest(data []byte) (CaptureManifest, error) {
	return capture.DecodeCaptureManifest(data)
}

func VerifyCaptureManifest(data []byte, material ports.CapturedReviewMaterial, expected domain.CaptureIdentity) error {
	return capture.VerifyCaptureManifest(data, material, expected)
}

func identitySHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func identityDigestValid(value string) bool {
	_, err := domain.ParseCaptureIdentity(value)
	return err == nil
}
