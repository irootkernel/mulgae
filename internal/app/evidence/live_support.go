package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// LiveNoChangeLimitation is the shared wire statement for provider-free live results.
const LiveNoChangeLimitation = "The selected source contains no review candidates."

// LiveSourceRead describes verified source selection and retained observations.
// The metadata alone confers no publication authority.
type LiveSourceRead struct {
	Identity       LiveSourceIdentity
	NoChange       bool
	Consistency    string
	BinaryEvidence []LiveBinaryObservation
}

type LiveSourceMetadata struct {
	Identity             json.RawMessage         `json:"identity"`
	SourceIdentitySHA256 string                  `json:"source_identity_sha256"`
	Changes              []LiveSourceChange      `json:"changes"`
	NoChange             bool                    `json:"no_change"`
	Consistency          string                  `json:"consistency"`
	ReplayAvailability   string                  `json:"replay_availability"`
	BinaryEvidence       []LiveBinaryObservation `json:"binary_evidence"`
}

type LiveSourceChange struct {
	Kind   string `json:"kind"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type LiveBinaryObservation struct {
	Side         string `json:"side"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	MediaType    string `json:"media_type"`
	ByteLength   int    `json:"byte_length"`
	ArtifactPath string `json:"artifact_path"`
}

func SourceConsistency(identity LiveSourceIdentity) string {
	if scope := identity.Target().Selector().Scope(); scope == domain.LiveSourceWorkspace || scope == domain.LiveSourceStage {
		return "caller_maintained"
	}
	return "resolved_git_objects"
}

func SourceImageArtifactPath(sessionID domain.SessionID, runID domain.RunID, digest, mediaType string) (ports.SafeRelativePath, error) {
	extension := ""
	switch mediaType {
	case "image/png":
		extension = "png"
	case "image/jpeg":
		extension = "jpg"
	case "image/webp":
		extension = "webp"
	default:
		return ports.SafeRelativePath{}, fmt.Errorf("unsupported source image media type")
	}
	if !validSourceSupportSHA256(digest) {
		return ports.SafeRelativePath{}, fmt.Errorf("invalid source image digest")
	}
	return ports.NewSafeRelativePath(sessionID.String() + "/" + runID.String() + "/evidence/images/sha256-" + strings.TrimPrefix(digest, "sha256:") + "." + extension)
}

func ValidateLiveSourceMetadata(live *LiveSourceMetadata) (LiveSourceRead, error) {
	if live == nil {
		return LiveSourceRead{}, fmt.Errorf("live source support: invalid source target format")
	}
	identity, err := DecodeLiveSourceIdentity(live.Identity)
	if err != nil || identity.SHA256() != live.SourceIdentitySHA256 || live.Consistency != SourceConsistency(identity) || live.ReplayAvailability != "unsupported" || live.Changes == nil || live.BinaryEvidence == nil {
		return LiveSourceRead{}, fmt.Errorf("live source support: invalid source identity or consistency claims")
	}
	changes := make([]ports.LiveSourceChange, 0, len(live.Changes))
	seenBefore, seenAfter := make(map[string]bool), make(map[string]bool)
	for _, value := range live.Changes {
		var before, after ports.SafeRelativePath
		if value.Before != "" {
			before, err = ports.NewSafeRelativePath(value.Before)
			if err != nil {
				return LiveSourceRead{}, err
			}
		}
		if value.After != "" {
			after, err = ports.NewSafeRelativePath(value.After)
			if err != nil {
				return LiveSourceRead{}, err
			}
		}
		if before.Valid() && seenBefore[before.String()] || after.Valid() && seenAfter[after.String()] {
			return LiveSourceRead{}, fmt.Errorf("live source support: duplicate candidate path")
		}
		seenBefore[before.String()], seenAfter[after.String()] = true, true
		changes = append(changes, ports.LiveSourceChange{Kind: value.Kind, Before: before, After: after})
	}
	selected, err := ports.NewLiveSourceTarget(identity.Target().Selector(), identity.Target().Base(), identity.Target().Head(), identity.Target().EmptyBase(), changes)
	if err != nil || live.NoChange != selected.NoChange() || live.NoChange && len(live.BinaryEvidence) != 0 {
		return LiveSourceRead{}, fmt.Errorf("live source support: inconsistent source selection")
	}
	return LiveSourceRead{Identity: identity, NoChange: live.NoChange, Consistency: live.Consistency, BinaryEvidence: append([]LiveBinaryObservation(nil), live.BinaryEvidence...)}, nil
}

func VerifyLiveSourceArtifacts(live *LiveSourceMetadata, sessionID domain.SessionID, runID domain.RunID, artifacts map[string]ports.ImmutablePublicationArtifact) error {
	read, err := ValidateLiveSourceMetadata(live)
	identity := read.Identity
	if err != nil {
		return err
	}
	prefix := sessionID.String() + "/" + runID.String() + "/"
	metadata, ok := artifacts[prefix+"source/source.json"]
	if !ok || metadata.SHA256() != identity.SHA256() || !bytes.Equal(metadata.Bytes(), identity.Bytes()) {
		return fmt.Errorf("live source support: missing or damaged source metadata")
	}
	expectedImages := make(map[string]string)
	for index, image := range live.BinaryEvidence {
		path, err := SourceImageArtifactPath(sessionID, runID, image.SHA256, image.MediaType)
		if err != nil || image.ArtifactPath != path.String() || image.ByteLength < 1 || !identity.SupportsSide(Side(image.Side)) {
			return fmt.Errorf("live source support: invalid binary identity")
		}
		if index > 0 {
			previous := live.BinaryEvidence[index-1]
			if previous.Side+"\x00"+previous.Path >= image.Side+"\x00"+image.Path {
				return fmt.Errorf("live source support: ambiguous or unordered binary observations")
			}
		}
		sourcePath, err := ports.NewSafeRelativePath(image.Path)
		if err != nil {
			return err
		}
		artifact, ok := artifacts[path.String()]
		if !ok || artifact.SHA256() != image.SHA256 || len(artifact.Bytes()) != image.ByteLength {
			return fmt.Errorf("live source support: missing or damaged binary evidence")
		}
		if _, err := ports.NewLiveSourceFile(sourcePath, artifact.Bytes(), image.MediaType); err != nil {
			return err
		}
		expectedImages[path.String()] = image.SHA256
	}
	for path, artifact := range artifacts {
		if !artifact.Valid() || path != artifact.Path().String() {
			return fmt.Errorf("live source support: inconsistent artifact identity")
		}
		kind, err := ports.ClassifyRunSupportArtifactPath(sessionID, runID, artifact.Path())
		if err != nil {
			return err
		}
		switch kind {
		case ports.RunSupportArtifactTargetBytes, ports.RunSupportArtifactTargetManifest, ports.RunSupportArtifactCaptureManifest, ports.RunSupportArtifactCapturedArchive, ports.RunSupportArtifactCapturedBlob, ports.RunSupportArtifactCompositeMetadata, ports.RunSupportArtifactSourceFinding, ports.RunSupportArtifactPromptStdin, ports.RunSupportArtifactPromptManifest, ports.RunSupportArtifactArtistBrief, ports.RunSupportArtifactArtistVisuals, ports.RunSupportArtifactRecoveryManifest, ports.RunSupportArtifactRecoveryBlob:
			return fmt.Errorf("live source support: captured or replay support is forbidden")
		case ports.RunSupportArtifactSourceImage:
			if expectedImages[path] != artifact.SHA256() {
				return fmt.Errorf("live source support: unbound image support")
			}
		case ports.RunSupportArtifactLiveSource:
			if path != prefix+"source/source.json" {
				return fmt.Errorf("live source support: unbound source metadata")
			}
		}
	}
	return nil
}

func validSourceSupportSHA256(value string) bool {
	_, _, err := canonicalTargetSHA256(value)
	return err == nil && strings.HasPrefix(value, "sha256:")
}
