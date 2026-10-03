package publication

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type liveSourceTargetWire = evidence.LiveSourceMetadata
type liveSourceChangeWire = evidence.LiveSourceChange
type liveBinaryEvidenceWire = evidence.LiveBinaryObservation

type liveProductionProvenanceWire struct {
	BuildProduct          string                   `json:"build_product"`
	BuildVersion          string                   `json:"build_version"`
	BuildCommit           string                   `json:"build_commit"`
	ObjectiveSHA256       *string                  `json:"objective_sha256"`
	ObjectivePresent      bool                     `json:"objective_present"`
	SourceIdentitySHA256  string                   `json:"source_identity_sha256"`
	SourceTerminalReceipt string                   `json:"source_terminal_receipt"`
	Providers             []productionProviderWire `json:"providers"`
}

func (target finalTargetWire) identitySHA256() string {
	if target.LiveSource != nil {
		return target.LiveSource.SourceIdentitySHA256
	}
	return target.ContentSHA256
}

func sourceImageArtifactPath(session domain.SessionID, run domain.RunID, digest, mediaType string) (ports.SafeRelativePath, error) {
	return evidence.SourceImageArtifactPath(session, run, digest, mediaType)
}

func (candidate PreparedCandidate) liveTargetWire() *liveSourceTargetWire {
	source := candidate.target.live
	if source == nil {
		return nil
	}
	changes := make([]liveSourceChangeWire, 0, len(source.target.Changes()))
	for _, change := range source.target.Changes() {
		changes = append(changes, liveSourceChangeWire{Kind: change.Kind, Before: change.Before.String(), After: change.After.String()})
	}
	binary := make([]liveBinaryEvidenceWire, 0, len(source.binary))
	for _, receipt := range source.binary {
		path, _ := sourceImageArtifactPath(candidate.sessionID, candidate.runID, receipt.FileSHA256(), receipt.MediaType())
		binary = append(binary, liveBinaryEvidenceWire{Side: string(receipt.Side()), Path: receipt.Path().String(), SHA256: receipt.FileSHA256(), MediaType: receipt.MediaType(), ByteLength: len(receipt.Bytes()), ArtifactPath: path.String()})
	}
	return &liveSourceTargetWire{Identity: source.identity.Bytes(), SourceIdentitySHA256: source.identity.SHA256(), Changes: changes, NoChange: candidate.noChange,
		Consistency: evidence.SourceConsistency(source.identity), ReplayAvailability: "unsupported", BinaryEvidence: binary}
}

func productionProvidersWire(values []ProductionProviderProvenance) []productionProviderWire {
	providers := make([]productionProviderWire, len(values))
	for index, provider := range values {
		providers[index] = productionProviderWire{Family: provider.Family, Instance: provider.Instance, Version: provider.Version, Executable: provider.Executable, ExecutableSHA256: provider.ExecutableSHA256,
			Launcher: provider.Launcher, LauncherSHA256: provider.LauncherSHA256, ProfileGeneration: provider.ProfileGeneration, AdapterProfile: provider.AdapterProfile,
			QualificationReceiptIDs: append([]string(nil), provider.QualificationReceiptIDs...), PacketTransportReceiptIDs: append([]string(nil), provider.PacketTransportReceiptIDs...), NamespaceTerminalReceipt: provider.NamespaceTerminalReceipt}
	}
	return providers
}

func (candidate PreparedCandidate) liveProvenanceWire() *liveProductionProvenanceWire {
	if candidate.target.live == nil {
		return nil
	}
	value := candidate.target.live.provenance
	return &liveProductionProvenanceWire{BuildProduct: value.BuildProduct, BuildVersion: value.BuildVersion, BuildCommit: value.BuildCommit, ObjectiveSHA256: optionalString(value.ObjectiveSHA256), ObjectivePresent: value.HasObjective,
		SourceIdentitySHA256: value.SourceIdentitySHA256, SourceTerminalReceipt: value.SourceTerminalReceipt, Providers: productionProvidersWire(value.Providers)}
}

func (candidate PreparedCandidate) finalTargetWire() finalTargetWire {
	target := finalTargetWire{ContentSHA256: candidate.target.sha256, ManifestPath: targetManifestPath, BaseOID: optionalString(candidate.target.baseOID), HeadOID: optionalString(candidate.target.headOID)}
	if candidate.target.live != nil {
		target.ContentSHA256 = ""
		target.ManifestPath = liveSourceManifestPath
		target.LiveSource = candidate.liveTargetWire()
	}
	return target
}

func (candidate PreparedCandidate) manifestTargetWire() manifestTargetWire {
	if candidate.target.live != nil {
		return manifestTargetWire{ManifestPath: liveSourceManifestPath, SourceIdentitySHA256: candidate.target.sha256}
	}
	return manifestTargetWire{ManifestPath: targetManifestPath, ContentSHA256: candidate.target.sha256}
}

func (candidate PreparedCandidate) artifactVersion(legacy string) string {
	if candidate.target.live != nil {
		return strings.TrimSuffix(legacy, ".v1") + ".v3"
	}
	return lineageVersion(legacy, candidate.publicationLineage().sourceRecoveryManifestSHA256)
}

func (candidate PreparedCandidate) artifactSchema(legacy string) string {
	if candidate.target.live != nil {
		return strings.Replace(legacy, ".v1.schema.json", ".v3.schema.json", 1)
	}
	return lineageSchema(legacy, candidate.publicationLineage().sourceRecoveryManifestSHA256)
}

func (candidate PreparedCandidate) buildLiveSupport(existing []ports.ImmutablePublicationArtifact) ([]ports.ImmutablePublicationArtifact, error) {
	source := candidate.target.live
	if source == nil || len(candidate.capturedArchive) != 0 {
		return nil, fmt.Errorf("live publication: invalid source support")
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/"
	path, err := ports.NewSafeRelativePath(prefix + liveSourceManifestPath)
	if err != nil {
		return nil, err
	}
	metadata, err := immutableArtifact(path, source.identity.Bytes())
	if err != nil || metadata.SHA256() != source.identity.SHA256() {
		return nil, fmt.Errorf("live publication: inconsistent source metadata")
	}
	result := append(append([]ports.ImmutablePublicationArtifact(nil), existing...), metadata)
	seen := make(map[string]string)
	for _, receipt := range source.binary {
		path, err := sourceImageArtifactPath(candidate.sessionID, candidate.runID, receipt.FileSHA256(), receipt.MediaType())
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[path.String()]; ok {
			if previous != receipt.FileSHA256() {
				return nil, fmt.Errorf("live publication: ambiguous binary support")
			}
			continue
		}
		artifact, err := immutableArtifact(path, receipt.Bytes())
		if err != nil || artifact.SHA256() != receipt.FileSHA256() {
			return nil, fmt.Errorf("live publication: inconsistent binary support")
		}
		seen[path.String()] = artifact.SHA256()
		result = append(result, artifact)
	}
	return result, nil
}

func validateLiveTargetWire(target finalTargetWire) (evidence.LiveSourceIdentity, error) {
	if target.ContentSHA256 != "" || target.ManifestPath != liveSourceManifestPath {
		return evidence.LiveSourceIdentity{}, fmt.Errorf("live publication: invalid target format")
	}
	read, err := evidence.ValidateLiveSourceMetadata(target.LiveSource)
	if err != nil {
		return evidence.LiveSourceIdentity{}, err
	}
	if !publicationOptionalStringsEqual(target.BaseOID, optionalString(read.Identity.Target().Base().String())) || !publicationOptionalStringsEqual(target.HeadOID, optionalString(read.Identity.Target().Head().String())) {
		return evidence.LiveSourceIdentity{}, fmt.Errorf("live publication: resolved operand mismatch")
	}
	return read.Identity, nil
}

func validateLiveSupport(final finalReviewWire, artifacts map[string]ports.ImmutablePublicationArtifact) error {
	session, err := domain.ParseSessionID(final.SessionID)
	if err != nil {
		return err
	}
	run, err := domain.ParseRunID(final.RunID)
	if err != nil {
		return err
	}
	if err := evidence.VerifyLiveSourceArtifacts(final.Target.LiveSource, session, run, artifacts); err != nil {
		return err
	}
	expected := make(map[string]struct{})
	images := make(map[string]string)
	for _, image := range final.Target.LiveSource.BinaryEvidence {
		images[image.Side+"\x00"+image.Path] = image.SHA256
	}
	for _, finding := range final.Findings {
		metadataPath := fmt.Sprintf("%s/%s/excerpts/%s.json", session.String(), run.String(), finding.ID)
		metadataBytes, err := marshalCanonical(finding)
		metadata, ok := artifacts[metadataPath]
		if err != nil || !ok || !bytes.Equal(metadata.Bytes(), metadataBytes) {
			return fmt.Errorf("live publication: missing or rebound normalized finding")
		}
		expected[metadataPath] = struct{}{}
		for i, item := range finding.Evidence {
			name := fmt.Sprintf("%s/%s/excerpts/%s_%d.md", session.String(), run.String(), finding.ID, i+1)
			artifact, ok := artifacts[name]
			if !ok || !bytes.Equal(artifact.Bytes(), []byte(item.Current.Quote)) {
				return fmt.Errorf("live publication: missing or rebound excerpt")
			}
			expected[name] = struct{}{}
			if item.Visual != nil && images[item.Current.Side+"\x00"+item.Visual.Path] != item.Visual.SHA256 {
				return fmt.Errorf("live publication: visual reference lacks selected binary")
			}
		}
	}
	for name, artifact := range artifacts {
		kind, err := ports.ClassifyRunSupportArtifactPath(session, run, artifact.Path())
		if err != nil {
			return err
		}
		if kind == ports.RunSupportArtifactExcerpt {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("live publication: unbound excerpt")
			}
		}
	}
	return nil
}

func publicationOptionalStringsEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func finalArtifactVersion(final finalReviewWire) string {
	if final.Target.LiveSource != nil {
		return "mulgae-review-artifact.v3"
	}
	return lineageVersion("mulgae-review-artifact.v1", final.ImmutableLineage.SourceRecoveryManifestSHA256)
}

func manifestArtifactVersion(final finalReviewWire) string {
	if final.Target.LiveSource != nil {
		return "mulgae-run-manifest.v3"
	}
	return lineageVersion("mulgae-run-manifest.v1", final.ImmutableLineage.SourceRecoveryManifestSHA256)
}

func validatePublicationTargetFormats(final finalReviewWire, manifest runManifestWire) error {
	if final.Target.LiveSource == nil {
		if final.Target.ManifestPath != targetManifestPath || !validSHA256(final.Target.ContentSHA256) || manifest.Target.SourceIdentitySHA256 != "" || final.Provenance.LiveProduction != nil {
			return fmt.Errorf("captured publication contains live source authority")
		}
		return nil
	}
	if final.RunType != string(domain.RunTypeReview) || final.FollowupOutcome != nil || manifest.FollowupOutcome != nil || manifest.Target.ContentSHA256 != "" || manifest.Target.SourceIdentitySHA256 != final.Target.LiveSource.SourceIdentitySHA256 || final.Provenance.Production != nil || final.Provenance.LiveProduction == nil {
		return fmt.Errorf("live publication: mixed or absent source authority")
	}
	if _, err := validateLiveTargetWire(final.Target); err != nil {
		return err
	}
	for _, role := range final.RoleOutcomes {
		if final.Target.LiveSource.NoChange != (role.Outcome == "not_applicable") {
			return fmt.Errorf("live publication: selection does not match attempted role outcomes")
		}
	}
	if final.Target.LiveSource.NoChange && (len(final.Findings) != 0 || len(manifest.Attempts) != 0 || len(manifest.Failures) != 0 || len(manifest.RoleReports) != 0) {
		return fmt.Errorf("live publication: no-change result contains provider work")
	}
	return nil
}

func currentEvidenceIdentity(item currentEvidenceWire) string {
	if item.SourceIdentitySHA256 != "" {
		return item.SourceIdentitySHA256
	}
	return item.TargetSHA256
}

func sourceEvidenceIdentity(item sourceEvidenceWire) string {
	if item.SourceIdentitySHA256 != "" {
		return item.SourceIdentitySHA256
	}
	return item.SourceTargetSHA256
}

func publishedCurrentClaim(target finalTargetWire, item currentEvidenceWire) (evidence.CurrentClaim, error) {
	if target.LiveSource != nil {
		identity, err := evidence.DecodeLiveSourceIdentity(target.LiveSource.Identity)
		if err != nil || item.TargetSHA256 != "" || item.SourceIdentitySHA256 != identity.SHA256() || !identity.SupportsSide(evidence.Side(item.Side)) {
			return evidence.CurrentClaim{}, fmt.Errorf("live publication: rebound evidence claim")
		}
		return evidence.NewLiveClaim(identity, evidence.Side(item.Side), item.Path, item.LineStart, item.LineEnd, item.Quote)
	}
	if item.SourceIdentitySHA256 != "" || item.TargetSHA256 != target.ContentSHA256 {
		return evidence.CurrentClaim{}, fmt.Errorf("captured publication contains live evidence")
	}
	return evidence.NewCurrentClaim(evidence.CurrentClaimInput{TargetSHA256: item.TargetSHA256, Side: evidence.Side(item.Side), Path: item.Path, LineStart: item.LineStart, LineEnd: item.LineEnd, Quote: item.Quote})
}

func validateLiveFinalProvenance(final finalReviewWire) error {
	value := final.Provenance.LiveProduction
	if value == nil || final.Provenance.Production != nil || final.Target.LiveSource == nil || value.ObjectivePresent != (value.ObjectiveSHA256 != nil) {
		return fmt.Errorf("live publication: absent or mixed production provenance")
	}
	identity, err := validateLiveTargetWire(final.Target)
	if err != nil {
		return err
	}
	provenance := LiveProductionProvenance{BuildProduct: value.BuildProduct, BuildVersion: value.BuildVersion, BuildCommit: value.BuildCommit, HasObjective: value.ObjectivePresent, SourceIdentitySHA256: value.SourceIdentitySHA256, SourceTerminalReceipt: value.SourceTerminalReceipt, Providers: make([]ProductionProviderProvenance, len(value.Providers))}
	if value.ObjectiveSHA256 != nil {
		provenance.ObjectiveSHA256 = *value.ObjectiveSHA256
	}
	for index, provider := range value.Providers {
		provenance.Providers[index] = ProductionProviderProvenance(provider)
	}
	if err := validateLiveProvenance(provenance, identity, final.Target.LiveSource.NoChange); err != nil {
		return err
	}
	commit := ""
	if final.Mulgae.Commit != nil {
		commit = *final.Mulgae.Commit
	}
	if final.Mulgae.Version != provenance.BuildVersion || commit != provenance.BuildCommit {
		return fmt.Errorf("live publication: production build mismatch")
	}
	return nil
}
