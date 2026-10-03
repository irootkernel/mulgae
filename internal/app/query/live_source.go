package query

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ErrSourceReplayUnavailable is explicit absence of retained source/replay
// authority. Stored observations remain readable through their P2 receipt.
const ErrSourceReplayUnavailable ReadContractError = "source_replay_unavailable"

// ReadSourceImageArtifact returns the complete retained raster for an offline
// export bound to an exact final identity. It does not read the original path.
func (service *Service) ReadSourceImageArtifact(ctx context.Context, run ports.PublicationRun, finalSHA256, sourceSHA256, side, path string) (ports.ImmutablePublicationArtifact, error) {
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if review.liveSource == nil || review.FinalSHA256() != finalSHA256 || review.SourceIdentitySHA256() != sourceSHA256 {
		return ports.ImmutablePublicationArtifact{}, ErrPublicationReceiptMismatch
	}
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	for _, image := range review.liveSource.BinaryEvidence {
		if image.Side == side && image.Path == path {
			artifactPath, _ := ports.NewSafeRelativePath(image.ArtifactPath)
			return service.readIndexedRuntimeArtifact(ctx, run, review, index, artifactPath)
		}
	}
	return ports.ImmutablePublicationArtifact{}, typedFailure("query.read_source_image", domain.FailureArtifact, "source image is unavailable", nil)
}

func validateLiveQueryTarget(final finalDTO) (evidence.LiveSourceRead, error) {
	value, err := evidence.ValidateLiveSourceMetadata(final.Target.LiveSource)
	if err != nil {
		return evidence.LiveSourceRead{}, err
	}
	identity := value.Identity
	if final.SchemaVersion != "mulgae-review-artifact.v3" || final.RunType != string(domain.RunTypeReview) || final.Target.ContentSHA256 != "" || final.Target.ManifestPath != "source/source.json" ||
		!optionalObjectIDMatches(final.Target.BaseOID, identity.Target().Base().String()) || !optionalObjectIDMatches(final.Target.HeadOID, identity.Target().Head().String()) || final.Provenance.Production != nil || final.Provenance.LiveProduction == nil || final.FollowupOutcome != nil {
		return evidence.LiveSourceRead{}, fmt.Errorf("live source final contains mixed authority")
	}
	production := final.Provenance.LiveProduction
	if production.BuildProduct != "mulgae" || !validBoundedText(production.BuildVersion, 128) || !validBoundedText(production.BuildCommit, 128) || production.BuildVersion != final.Mulgae.Version || final.Mulgae.Commit == nil || production.BuildCommit != *final.Mulgae.Commit ||
		production.SourceIdentitySHA256 != identity.SHA256() || !validReceiptID(production.SourceTerminalReceipt) || value.NoChange != (len(production.Providers) == 0) || production.ObjectivePresent != (production.ObjectiveSHA256 != nil) || production.ObjectivePresent && !validSHA256(*production.ObjectiveSHA256) {
		return evidence.LiveSourceRead{}, fmt.Errorf("live source provenance is inconsistent")
	}
	for i, provider := range production.Providers {
		if !validProductionProvider(provider) || i > 0 && provider.Family+"\x00"+provider.Instance <= production.Providers[i-1].Family+"\x00"+production.Providers[i-1].Instance {
			return evidence.LiveSourceRead{}, fmt.Errorf("live source provider provenance is invalid")
		}
	}
	for _, role := range final.RoleOutcomes {
		if value.NoChange && (len(role.Limitations) != 1 || role.Limitations[0] != evidence.LiveNoChangeLimitation) {
			return evidence.LiveSourceRead{}, fmt.Errorf("live no-change role limitations are inconsistent")
		}
	}
	return value, nil
}

func optionalObjectIDMatches(value *string, expected string) bool {
	if expected == "" {
		return value == nil
	}
	return value != nil && *value == expected
}

func verifyLiveReadSupport(run ports.PublicationRun, review CommittedReview, artifacts map[string]ports.ImmutablePublicationArtifact) error {
	final, err := decodeFinalDTO(review.FinalBytes())
	if err != nil {
		return err
	}
	if err := evidence.VerifyLiveSourceArtifacts(final.Target.LiveSource, run.SessionID(), run.RunID(), artifacts); err != nil {
		return err
	}
	expected := make(map[string]struct{})
	images := make(map[string]string)
	for _, image := range review.liveSource.BinaryEvidence {
		images[image.Side+"\x00"+image.Path] = image.SHA256
	}
	for _, finding := range final.Findings {
		metadataPath := fmt.Sprintf("%s/%s/excerpts/%s.json", run.SessionID().String(), run.RunID().String(), finding.ID)
		metadata, ok := artifacts[metadataPath]
		var stored finalFindingDTO
		if !ok || decodeStrictDTO(metadata.Bytes(), &stored) != nil || !reflect.DeepEqual(stored, finding) {
			return fmt.Errorf("live source normalized finding is absent or rebound")
		}
		expected[metadataPath] = struct{}{}
		for index, item := range finding.Evidence {
			path, err := excerptArtifactPath(run, finding.ID, index+1)
			if err != nil {
				return err
			}
			artifact, ok := artifacts[path.String()]
			if !ok || !bytes.Equal(artifact.Bytes(), []byte(item.Current.Quote)) {
				return fmt.Errorf("live source excerpt is absent or rebound")
			}
			if item.Visual != nil && images[item.Current.Side+"\x00"+item.Visual.Path] != item.Visual.SHA256 {
				return fmt.Errorf("live source visual lacks retained binary")
			}
			expected[path.String()] = struct{}{}
		}
	}
	for name, artifact := range artifacts {
		kind, err := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), artifact.Path())
		if err != nil {
			return err
		}
		if kind == ports.RunSupportArtifactExcerpt {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("live source support contains an unbound excerpt")
			}
		}
	}
	return nil
}
