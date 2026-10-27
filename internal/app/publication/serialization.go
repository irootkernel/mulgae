package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Construction counting is part of the disabled-by-default publication
// verification seam. Each counter is incremented only at artifact-creation
// points of one review-independent support family, never over a returned
// slice, so the counts record newly constructed immutable artifacts.
var publicationEvidenceExcerptConstructions atomic.Int64
var publicationAttemptArtifactConstructions atomic.Int64
var publicationRoleReportConstructions atomic.Int64
var publicationLiveSupportConstructions atomic.Int64

func notePublicationConstruction(counter *atomic.Int64) {
	if publicationVerificationCounting.Load() {
		counter.Add(1)
	}
}

// Build assigns the post-validation ReviewID and constructs every deterministic
// publication member. It validates final-review and manifest bytes against the
// embedded schema assets before returning any bundle.
func (candidate PreparedCandidate) Build(
	ctx context.Context,
	validator SchemaValidator,
	reviewID domain.ReviewID,
	createdAt time.Time,
	epoch uint64,
) (PublicationBundle, error) {
	if ctx == nil {
		return PublicationBundle{}, fmt.Errorf("publication build: context is required")
	}
	if err := ctx.Err(); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: context: %w", err)
	}
	if nilSchemaValidator(validator) {
		return PublicationBundle{}, fmt.Errorf("publication build: schema validator is required")
	}
	if err := candidate.validate(); err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationCandidate, domain.DiagnosticCausePublicationCandidateInvalid, fmt.Errorf("publication build: candidate is not prevalidated: %w", err))
	}
	if _, err := domain.ParseReviewID(reviewID.String()); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: review ID: %w", err)
	}
	createdAtText, err := canonicalTime(createdAt)
	if err != nil {
		return PublicationBundle{}, err
	}
	if epoch == 0 {
		return PublicationBundle{}, fmt.Errorf("publication build: epoch must be positive")
	}
	if candidate.target.live == nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationCandidate, domain.DiagnosticCausePublicationCandidateInvalid, fmt.Errorf("publication build: live source is required"))
	}

	paths, err := publicationPaths(candidate.sessionID, candidate.runID, reviewID, epoch)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationStaging, domain.DiagnosticCausePublicationPathFailed, err)
	}
	lineageEdge, err := candidate.buildLineageEdge(paths, reviewID)
	if err != nil {
		return PublicationBundle{}, err
	}

	excerpts, err := candidate.buildExcerpts(paths, reviewID)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	attemptArtifacts, err := candidate.buildAttemptArtifacts()
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	roleReports, err := candidate.buildRoleReports()
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	excerpts = append(excerpts, attemptArtifacts...)
	excerpts = append(excerpts, roleReports...)
	excerpts, err = candidate.buildLiveSupport(excerpts)
	if err != nil {
		return PublicationBundle{}, err
	}
	excerpts, err = candidate.buildRequirementsSupport(excerpts)
	if err != nil {
		return PublicationBundle{}, err
	}
	return candidate.assembleBoundMembers(ctx, validator, reviewID, createdAtText, epoch, paths, lineageEdge, excerpts, candidate.manifestRoleReports)
}

// buildLineageEdge constructs the review-ID-bound lineage edge member.
func (candidate PreparedCandidate) buildLineageEdge(paths publicationPathsSet, reviewID domain.ReviewID) (ports.ImmutablePublicationArtifact, error) {
	lineage := candidate.publicationLineage()
	edgeBytes, err := marshalCanonical(lineageEdgeWire{
		SchemaVersion: lineageVersion(lineageEdgeV1, lineage.sourceRecoveryManifestSHA256),
		EdgeID:        "e_" + reviewID.String(),
		Child: lineageChildWire{
			SessionID: candidate.sessionID.String(),
			RunID:     candidate.runID.String(),
			ReviewID:  reviewID.String(),
		},
		ParentRunID:                  lineageRunID(lineage.parentRunID),
		SourceRunID:                  lineageRunID(lineage.sourceRunID),
		SourceReviewID:               lineageReviewID(lineage.sourceReviewID),
		SourceRecoveryManifestSHA256: cloneOptionalString(lineage.sourceRecoveryManifestSHA256),
		SourceKind:                   recoverySourceKind(lineage.sourceRecoveryManifestSHA256),
		SourceAttemptID:              lineageAttemptID(lineage.sourceAttemptID),
		SourceFindingRef:             cloneOptionalString(lineage.sourceFindingRef),
		ReplayMode:                   lineageReplayMode(lineage.replayMode),
	})
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, buildFailure(domain.DiagnosticPhasePublicationManifest, domain.DiagnosticCausePublicationSerializationFailed, fmt.Errorf("publication build: serialize lineage edge: %w", err))
	}
	lineageEdge, err := immutableArtifact(paths.lineageEdge, edgeBytes)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("publication build: lineage edge: %w", err)
	}
	return lineageEdge, nil
}

// assembleBoundMembers constructs every member that binds the review ID once
// the support artifacts exist: support index, final, staged copy, manifest,
// epoch record, journal and status, then validates the assembled bundle. The
// manifest role-report wires are requested at the manifest step so both
// callers keep the historical construction sequence.
func (candidate PreparedCandidate) assembleBoundMembers(
	ctx context.Context,
	validator SchemaValidator,
	reviewID domain.ReviewID,
	createdAtText string,
	epoch uint64,
	paths publicationPathsSet,
	lineageEdge ports.ImmutablePublicationArtifact,
	excerpts []ports.ImmutablePublicationArtifact,
	roleReports func() []manifestRoleReportWire,
) (PublicationBundle, error) {
	supportIndex, err := buildRunSupportIndex(paths.supportIndex, excerpts)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	excerpts = append(excerpts, supportIndex)
	finalBytes, err := candidate.buildFinalBytes(reviewID, createdAtText, lineageEdge)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	finalSchema, err := ports.ParseAssetID(candidate.artifactSchema(finalReviewSchemaAsset))
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: final schema asset: %w", err)
	}
	if err := validator.Validate(ctx, finalSchema, cloneBytes(finalBytes)); err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSchemaFailed, fmt.Errorf("publication build: final review schema validation: %w", err))
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(reviewID, paths.final, sha256Identifier(finalBytes))
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: final identity: %w", err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: final artifact: %w", err)
	}
	staged, err := immutableArtifact(paths.staged, finalBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: staged final: %w", err)
	}

	manifestBytes, err := candidate.buildManifestBytesWithRoleReports(reviewID, createdAtText, epoch, paths, final, lineageEdge, supportIndex, roleReports())
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationManifest, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	manifestSchema, err := ports.ParseAssetID(candidate.artifactSchema(runManifestSchemaAsset))
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: manifest schema asset: %w", err)
	}
	if err := validator.Validate(ctx, manifestSchema, cloneBytes(manifestBytes)); err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationManifest, domain.DiagnosticCausePublicationSchemaFailed, fmt.Errorf("publication build: run manifest schema validation: %w", err))
	}
	manifest, err := immutableArtifact(paths.manifest, manifestBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: manifest: %w", err)
	}

	epochBytes, err := marshalCanonical(publicationEpochWire{
		SchemaVersion: publicationEpochV1,
		StoreEpoch:    epoch,
		Manifest:      artifactIdentityWire{Path: manifest.Path().String(), SHA256: manifest.SHA256()},
		LineageEdge:   artifactIdentityWire{Path: lineageEdge.Path().String(), SHA256: lineageEdge.SHA256()},
		FinalReview:   artifactIdentityWire{Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256()},
	})
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: serialize epoch: %w", err)
	}
	epochRecord, err := immutableArtifact(paths.epoch, epochBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: epoch record: %w", err)
	}
	publicationEpoch, err := ports.NewPublicationEpoch(epoch, epochRecord)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: epoch: %w", err)
	}

	restart := restartStateWire{
		SessionID:                candidate.sessionID.String(),
		RunID:                    candidate.runID.String(),
		PersistedJournalState:    string(domain.JournalManifestCommitted),
		ExpectedStaged:           artifactIdentityWire{Path: staged.Path().String(), SHA256: staged.SHA256()},
		ExpectedFinal:            artifactIdentityWire{Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256()},
		ValidatedCandidateSHA256: candidate.ValidatedCandidateSHA256(),
		StoreEpoch:               epoch,
		NormalExit:               candidate.exitCode,
		ManifestPath:             manifest.Path().String(),
		LineageEdgePath:          lineageEdge.Path().String(),
		EpochPath:                publicationEpoch.Record().Path().String(),
	}
	journalBytes, err := marshalCanonical(publicationJournalWire{
		SchemaVersion: publicationJournalV1,
		RestartState:  restart,
	})
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: serialize journal: %w", err)
	}
	journal, err := mutableDocument(paths.journal, journalBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: journal: %w", err)
	}
	statusBytes, err := marshalCanonical(publicationStatusWire{
		SchemaVersion:        publicationStatusV1,
		PublicationStatus:    string(domain.PublicationCommitted),
		PublicationAuthority: string(domain.PublicationAuthorityP2),
		RestartState:         restart,
	})
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: serialize status: %w", err)
	}
	status, err := mutableDocument(paths.status, statusBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: status: %w", err)
	}

	bundle := PublicationBundle{
		final: final, manifest: manifest, lineageEdge: lineageEdge, epoch: publicationEpoch, staged: staged,
		journal: journal, status: status, excerpts: append([]ports.ImmutablePublicationArtifact(nil), excerpts...),
	}
	if err := validatePublicationBundleSemantics(bundle); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: constructed bundle is inconsistent: %w", err)
	}
	if !bundle.Valid() {
		return PublicationBundle{}, fmt.Errorf("publication build: constructed bundle contains an invalid member")
	}
	return bundle, nil
}

// reviewIndependentSupport holds the support shares whose paths and bytes do
// not depend on the issued review ID. leading precedes and trailing follows
// the per-binding normalized findings in the bundle's support order, and
// roleReports retains each published report's identity for manifest reuse.
type reviewIndependentSupport struct {
	leading     []ports.ImmutablePublicationArtifact
	trailing    []ports.ImmutablePublicationArtifact
	roleReports map[domain.Role]roleReportIdentity
}

// livePublicationBuilder binds one live candidate inside one publication
// invocation. The first binding follows Build's exact member order and retains
// the review-independent support shares; later bindings reuse those shares at
// the same positions and rebuild only the members that bind the review ID. A
// builder never outlives its publication invocation and is never shared.
type livePublicationBuilder struct {
	candidate PreparedCandidate
	support   reviewIndependentSupport
	prepared  bool
}

// newLivePublicationBuilder applies the live wrapper's candidate-first
// rejection before any binding.
func newLivePublicationBuilder(candidate PreparedLiveCandidate) (*livePublicationBuilder, error) {
	if !candidate.Valid() {
		return nil, fmt.Errorf("live publication: invalid candidate")
	}
	return &livePublicationBuilder{candidate: candidate.candidate}, nil
}

// bind runs the complete Build prologue for reviewID and constructs the bundle
// in Build's member order, constructing the review-independent support shares
// on the first binding and reusing them afterwards.
func (builder *livePublicationBuilder) bind(
	ctx context.Context,
	validator SchemaValidator,
	reviewID domain.ReviewID,
	createdAt time.Time,
	epoch uint64,
) (PublicationBundle, error) {
	candidate := builder.candidate
	// The prologue mirrors Build's prologue check for check and in the same
	// order; TestLiveFirstBindingProloguePrecedenceMatchesBuild pins the parity.
	if ctx == nil {
		return PublicationBundle{}, fmt.Errorf("publication build: context is required")
	}
	if err := ctx.Err(); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: context: %w", err)
	}
	if nilSchemaValidator(validator) {
		return PublicationBundle{}, fmt.Errorf("publication build: schema validator is required")
	}
	if err := candidate.validate(); err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationCandidate, domain.DiagnosticCausePublicationCandidateInvalid, fmt.Errorf("publication build: candidate is not prevalidated: %w", err))
	}
	if _, err := domain.ParseReviewID(reviewID.String()); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: review ID: %w", err)
	}
	createdAtText, err := canonicalTime(createdAt)
	if err != nil {
		return PublicationBundle{}, err
	}
	if epoch == 0 {
		return PublicationBundle{}, fmt.Errorf("publication build: epoch must be positive")
	}
	if candidate.target.live == nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationCandidate, domain.DiagnosticCausePublicationCandidateInvalid, fmt.Errorf("publication build: live source is required"))
	}

	paths, err := publicationPaths(candidate.sessionID, candidate.runID, reviewID, epoch)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationStaging, domain.DiagnosticCausePublicationPathFailed, err)
	}
	lineageEdge, err := candidate.buildLineageEdge(paths, reviewID)
	if err != nil {
		return PublicationBundle{}, err
	}
	leading := builder.support.leading
	if !builder.prepared {
		leading, err = candidate.buildEvidenceExcerpts(paths.excerptsDir)
		if err != nil {
			return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
		}
	}
	normalized, err := candidate.buildNormalizedFindingExcerpts(paths.excerptsDir, reviewID)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	if !builder.prepared {
		attemptArtifacts, err := candidate.buildAttemptArtifacts()
		if err != nil {
			return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
		}
		roleReports, err := candidate.buildRoleReports()
		if err != nil {
			return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
		}
		// Live support receives exactly the list Build assembles before it.
		input := make([]ports.ImmutablePublicationArtifact, 0, len(leading)+len(normalized)+len(attemptArtifacts)+len(roleReports))
		input = append(input, leading...)
		input = append(input, normalized...)
		input = append(input, attemptArtifacts...)
		input = append(input, roleReports...)
		result, err := candidate.buildLiveSupport(input)
		if err != nil {
			return PublicationBundle{}, err
		}
		result, err = candidate.buildRequirementsSupport(result)
		if err != nil {
			return PublicationBundle{}, err
		}
		liveSupport := result[len(input):]
		trailing := make([]ports.ImmutablePublicationArtifact, 0, len(attemptArtifacts)+len(roleReports)+len(liveSupport))
		trailing = append(trailing, attemptArtifacts...)
		trailing = append(trailing, roleReports...)
		trailing = append(trailing, liveSupport...)
		builder.support = reviewIndependentSupport{leading: leading, trailing: trailing, roleReports: candidate.roleReportIdentities(roleReports)}
		builder.prepared = true
	}
	excerpts := make([]ports.ImmutablePublicationArtifact, 0, len(leading)+len(normalized)+len(builder.support.trailing))
	excerpts = append(excerpts, leading...)
	excerpts = append(excerpts, normalized...)
	excerpts = append(excerpts, builder.support.trailing...)
	identities := builder.support.roleReports
	return candidate.assembleBoundMembers(ctx, validator, reviewID, createdAtText, epoch, paths, lineageEdge, excerpts, func() []manifestRoleReportWire {
		return candidate.manifestRoleReportsFromIdentities(identities)
	})
}

type publicationPathsSet struct {
	final        ports.SafeRelativePath
	manifest     ports.SafeRelativePath
	journal      ports.SafeRelativePath
	status       ports.SafeRelativePath
	staged       ports.SafeRelativePath
	lineageEdge  ports.SafeRelativePath
	epoch        ports.SafeRelativePath
	supportIndex ports.SafeRelativePath
	excerptsDir  string
}

func publicationPaths(sessionID domain.SessionID, runID domain.RunID, reviewID domain.ReviewID, epoch uint64) (publicationPathsSet, error) {
	prefix := sessionID.String() + "/" + runID.String()
	return publicationPathsSet{
		final:        mustPublicationPath(artifactwire.FinalPath(sessionID.String(), runID.String(), reviewID.String())),
		manifest:     mustPublicationPath(artifactwire.RunPath(sessionID.String(), runID.String(), artifactwire.ManifestPath)),
		journal:      mustPublicationPath(artifactwire.RunPath(sessionID.String(), runID.String(), artifactwire.JournalPath)),
		status:       mustPublicationPath(artifactwire.RunPath(sessionID.String(), runID.String(), artifactwire.StatusPath)),
		staged:       mustPublicationPath(artifactwire.StagedFinalPath(sessionID.String(), runID.String(), reviewID.String())),
		lineageEdge:  mustPublicationPath(artifactwire.LineageEdgePath(reviewID.String())),
		epoch:        mustPublicationPath(artifactwire.EpochPath(epoch)),
		supportIndex: mustPublicationPath(artifactwire.RunPath(sessionID.String(), runID.String(), artifactwire.SupportIndexPath)),
		excerptsDir:  prefix + "/excerpts",
	}, nil
}

func mustPublicationPath(value string) ports.SafeRelativePath {
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		panic(fmt.Sprintf("publication path invariant %q: %v", value, err))
	}
	return path
}

func (candidate PreparedCandidate) buildExcerpts(paths publicationPathsSet, reviewID domain.ReviewID) ([]ports.ImmutablePublicationArtifact, error) {
	excerpts, err := candidate.buildEvidenceExcerpts(paths.excerptsDir)
	if err != nil {
		return nil, err
	}
	normalized, err := candidate.buildNormalizedFindingExcerpts(paths.excerptsDir, reviewID)
	if err != nil {
		return nil, err
	}
	return append(excerpts, normalized...), nil
}

// buildEvidenceExcerpts constructs the review-ID-independent evidence excerpt
// artifacts in finding and evidence order.
func (candidate PreparedCandidate) buildEvidenceExcerpts(excerptsDir string) ([]ports.ImmutablePublicationArtifact, error) {
	excerpts := make([]ports.ImmutablePublicationArtifact, 0)
	for _, finding := range candidate.findings {
		for index, item := range finding.evidence {
			path, err := ports.NewSafeRelativePath(excerptsDir + "/" + artifactwire.EvidenceExcerptName(finding.id, index+1))
			if err != nil {
				return nil, fmt.Errorf("publication build: excerpt path: %w", err)
			}
			if !validSHA256(item.currentExcerptSHA256) || len(item.excerpt) == 0 {
				return nil, fmt.Errorf("publication build: excerpt %s/%d is invalid", finding.id, index+1)
			}
			artifact, err := immutableArtifact(path, item.excerpt)
			if err != nil {
				return nil, fmt.Errorf("publication build: excerpt %s/%d: %w", finding.id, index+1, err)
			}
			notePublicationConstruction(&publicationEvidenceExcerptConstructions)
			excerpts = append(excerpts, artifact)
		}
	}
	return excerpts, nil
}

// buildNormalizedFindingExcerpts constructs the normalized finding artifacts,
// whose evidence source identity binds the supplied review ID.
func (candidate PreparedCandidate) buildNormalizedFindingExcerpts(excerptsDir string, reviewID domain.ReviewID) ([]ports.ImmutablePublicationArtifact, error) {
	excerpts := make([]ports.ImmutablePublicationArtifact, 0)
	for _, finding := range candidate.finalFindings(reviewID) {
		path, err := ports.NewSafeRelativePath(excerptsDir + "/" + artifactwire.FindingName(finding.ID))
		if err != nil {
			return nil, fmt.Errorf("publication build: normalized finding path: %w", err)
		}
		bytes, err := marshalCanonical(finding)
		if err != nil {
			return nil, fmt.Errorf("publication build: normalized finding %s: %w", finding.ID, err)
		}
		artifact, err := immutableArtifact(path, bytes)
		if err != nil {
			return nil, fmt.Errorf("publication build: normalized finding artifact %s: %w", finding.ID, err)
		}
		excerpts = append(excerpts, artifact)
	}
	return excerpts, nil
}

type runSupportIndexWire = artifactwire.SupportIndex

func buildRunSupportIndex(path ports.SafeRelativePath, artifacts []ports.ImmutablePublicationArtifact) (ports.ImmutablePublicationArtifact, error) {
	identities := make([]artifactIdentityWire, 0, len(artifacts))
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if !artifact.Valid() {
			return ports.ImmutablePublicationArtifact{}, fmt.Errorf("publication build: invalid support artifact")
		}
		key := artifact.Path().String()
		if _, duplicate := seen[key]; duplicate {
			return ports.ImmutablePublicationArtifact{}, fmt.Errorf("publication build: duplicate support artifact path %q", key)
		}
		seen[key] = struct{}{}
		identities = append(identities, artifactIdentityWire{Path: key, SHA256: artifact.SHA256()})
	}
	version := artifactwire.SupportIndexV1
	for _, artifact := range artifacts {
		if kind, ok := publicationSupportArtifactKind(artifact.Path()); ok && (kind == ports.RunSupportArtifactCaptureManifest || kind == ports.RunSupportArtifactCompositeMetadata) {
			version = artifactwire.SupportIndexV2
		}
		if kind, ok := publicationSupportArtifactKind(artifact.Path()); ok && kind == ports.RunSupportArtifactLiveSource {
			version = artifactwire.SupportIndexV3
		}
	}
	for _, artifact := range artifacts {
		if kind, ok := publicationSupportArtifactKind(artifact.Path()); ok && kind == ports.RunSupportArtifactRequirements {
			version = artifactwire.SupportIndexV4
		}
	}
	bytes, err := marshalCanonical(runSupportIndexWire{SchemaVersion: version, Artifacts: identities})
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("publication build: serialize support index: %w", err)
	}
	artifact, err := immutableArtifact(path, bytes)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, fmt.Errorf("publication build: support index: %w", err)
	}
	return artifact, nil
}

type attemptArtifactWire struct {
	Kind             string                `json:"kind"`
	SecurityRejected bool                  `json:"security_rejected"`
	Artifact         *artifactIdentityWire `json:"artifact,omitempty"`
}

type attemptInvocationStatusWire struct {
	Sequence  uint64                `json:"sequence"`
	Purpose   string                `json:"purpose"`
	State     string                `json:"state"`
	Artifacts []attemptArtifactWire `json:"artifacts"`
}

type attemptStatusWire struct {
	SchemaVersion string                        `json:"schema_version"`
	AttemptID     string                        `json:"attempt_id"`
	Invocations   []attemptInvocationStatusWire `json:"invocations"`
}

func (candidate PreparedCandidate) buildAttemptArtifacts() ([]ports.ImmutablePublicationArtifact, error) {
	artifacts := make([]ports.ImmutablePublicationArtifact, 0)
	for _, role := range candidate.roles {
		for _, attempt := range role.attempts {
			status := attemptStatusWire{SchemaVersion: "mulgae-attempt-status.v1", AttemptID: attempt.id.String()}
			hasCapture := false
			repairOrdinal := 0
			retryOrdinal := 0
			extractOrdinal := 0
			for _, invocation := range attempt.invocations {
				if invocation.purpose == domain.InvocationRepair {
					repairOrdinal++
				}
				if invocation.purpose == domain.InvocationRetry {
					retryOrdinal++
				}
				if invocation.purpose == domain.InvocationExtract {
					extractOrdinal++
				}
				if len(invocation.artifacts) == 0 {
					continue
				}
				hasCapture = true
				item := attemptInvocationStatusWire{
					Sequence: invocation.sequence, Purpose: string(invocation.purpose), State: string(invocation.state),
					Artifacts: make([]attemptArtifactWire, 0, len(invocation.artifacts)),
				}
				for _, capture := range invocation.artifacts {
					wire := attemptArtifactWire{Kind: string(capture.kind), SecurityRejected: capture.securityRejected}
					if !capture.securityRejected {
						var path ports.SafeRelativePath
						var err error
						switch capture.kind {
						case ports.AttemptArtifactInitialCandidate:
							path, err = ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), "candidate.initial.json")))
						case ports.AttemptArtifactRetryCandidate:
							path, err = ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), artifactwire.CandidateName("retry", retryOrdinal))))
						case ports.AttemptArtifactRepairedCandidate:
							path, err = ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), artifactwire.CandidateName("repaired", repairOrdinal))))
						case ports.AttemptArtifactExtractedCandidate:
							path, err = ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), artifactwire.CandidateName("extracted", extractOrdinal))))
						case ports.AttemptArtifactStdout, ports.AttemptArtifactStderr:
							path, err = ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), artifactwire.InvocationPath(invocation.sequence, string(invocation.purpose), string(capture.kind)))))
						default:
							return nil, fmt.Errorf("publication build: unsupported attempt artifact kind %q", capture.kind)
						}
						if err != nil {
							return nil, fmt.Errorf("publication build: attempt artifact path: %w", err)
						}
						artifact, err := immutableArtifact(path, capture.bytes)
						if err != nil {
							return nil, fmt.Errorf("publication build: attempt artifact: %w", err)
						}
						notePublicationConstruction(&publicationAttemptArtifactConstructions)
						wire.Artifact = &artifactIdentityWire{Path: artifact.Path().String(), SHA256: artifact.SHA256()}
						artifacts = append(artifacts, artifact)
					}
					item.Artifacts = append(item.Artifacts, wire)
				}
				status.Invocations = append(status.Invocations, item)
			}
			if !hasCapture {
				continue
			}
			statusBytes, err := marshalCanonical(status)
			if err != nil {
				return nil, fmt.Errorf("publication build: attempt status: %w", err)
			}
			statusPath, err := ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.AttemptPath(attempt.id.String(), "status.json")))
			if err != nil {
				return nil, fmt.Errorf("publication build: attempt status path: %w", err)
			}
			statusArtifact, err := immutableArtifact(statusPath, statusBytes)
			if err != nil {
				return nil, fmt.Errorf("publication build: attempt status artifact: %w", err)
			}
			notePublicationConstruction(&publicationAttemptArtifactConstructions)
			artifacts = append(artifacts, statusArtifact)
		}
	}
	return artifacts, nil
}

func (candidate PreparedCandidate) buildFinalBytes(
	reviewID domain.ReviewID,
	createdAt string,
	lineageEdge ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	commit := optionalString(candidate.mulgae.commit)
	status := "valid"
	for _, role := range candidate.roles {
		if role.repaired {
			status = "repaired_valid"
			break
		}
	}
	return marshalCanonical(finalReviewWire{
		RequirementsSupport: candidate.requirementsBinding(),
		SchemaVersion:       candidate.artifactVersion(artifactwire.ReviewArtifactV1),
		SessionID:           candidate.sessionID.String(),
		RunID:               candidate.runID.String(),
		ReviewID:            reviewID.String(),
		RunType:             string(candidate.publicationLineage().runType),
		CreatedAt:           createdAt,
		Mulgae: mulgaeWire{
			Version: candidate.mulgae.version,
			Commit:  commit,
		},
		ImmutableLineage: candidate.immutableLineageWire(lineageEdge),
		FollowupOutcome:  nil,
		Target:           candidate.finalTargetWire(),
		Validation: validationWire{
			Status: status, SchemaValidation: "passed", SemanticValidation: "passed", EvidenceValidation: "passed",
		},
		ContentVerdict:             string(candidate.axes.content),
		CoverageStatus:             string(candidate.axes.coverage),
		StructuredExtractionStatus: string(candidate.axes.structuredExtraction),
		PublicationStatus:          string(domain.PublicationCommitted),
		CIDecision:                 string(candidate.axes.ci),
		CIReasonCodes:              append([]string{}, candidate.reasons...),
		SeverityThreshold: severityThresholdWire{
			RequestChangesAtOrAbove: string(candidate.threshold), PolicySource: "project_local",
		},
		RoleOutcomes: candidate.finalRoleOutcomes(),
		Findings:     candidate.finalFindings(reviewID),
		Limitations:  append([]string{}, candidate.limits...),
		Provenance: provenanceWire{
			AggregationPath: aggregationPath, FinalValidationPath: finalValidationPath, ManifestPath: "manifest.json",
			Production: nil, LiveProduction: candidate.liveProvenanceWire(),
		},
	})
}

func (candidate PreparedCandidate) buildManifestBytesWithRoleReports(
	reviewID domain.ReviewID,
	createdAt string,
	epoch uint64,
	paths publicationPathsSet,
	final ports.FinalReviewArtifact,
	lineageEdge ports.ImmutablePublicationArtifact,
	supportIndex ports.ImmutablePublicationArtifact,
	roleReports []manifestRoleReportWire,
) ([]byte, error) {
	return marshalCanonical(runManifestWire{
		RequirementsSupport:        candidate.requirementsBinding(),
		SchemaVersion:              candidate.artifactVersion(artifactwire.RunManifestV1),
		SessionID:                  candidate.sessionID.String(),
		RunID:                      candidate.runID.String(),
		RunType:                    string(candidate.publicationLineage().runType),
		State:                      string(candidate.runState),
		Sealed:                     true,
		CreatedAt:                  createdAt,
		StartedAt:                  optionalString(createdAt),
		CompletedAt:                optionalString(createdAt),
		MulgaeVersion:              candidate.mulgae.version,
		ImmutableLineage:           candidate.immutableLineageWire(lineageEdge),
		FollowupOutcome:            nil,
		Target:                     candidate.manifestTargetWire(),
		SelectedRoles:              candidate.selectedRoles(),
		RequiredRoles:              candidate.requiredRoles(),
		Attempts:                   candidate.manifestAttempts(),
		ContentVerdict:             string(candidate.axes.content),
		CoverageStatus:             string(candidate.axes.coverage),
		StructuredExtractionStatus: string(candidate.axes.structuredExtraction),
		PublicationStatus:          string(domain.PublicationCommitted),
		CIDecision:                 string(candidate.axes.ci),
		CIReasonCodes:              append([]string{}, candidate.reasons...),
		PersistedJournalState:      string(domain.JournalManifestCommitted),
		DurableObservationClass:    string(domain.DurableObservationP2Committed),
		DerivedPublicationStatus:   string(domain.PublicationCommitted),
		PublicationAuthority:       string(domain.PublicationAuthorityP2),
		RecoveryJournal: recoveryJournalWire{
			ExpectedStaged:           artifactIdentityWire{Path: paths.staged.String(), SHA256: final.Identity().SHA256()},
			ExpectedFinal:            artifactIdentityWire{Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256()},
			ValidatedCandidateSHA256: candidate.ValidatedCandidateSHA256(),
		},
		CompositeIdentity: compositeIdentityWire{
			Manifest:     pathPointerWire{Path: paths.manifest.String()},
			LineageEdge:  artifactIdentityWire{Path: lineageEdge.Path().String(), SHA256: lineageEdge.SHA256()},
			Epoch:        pathPointerWire{Path: paths.epoch.String()},
			SupportIndex: artifactIdentityWire{Path: supportIndex.Path().String(), SHA256: supportIndex.SHA256()},
		},
		RecoveryAction: "reconstruct_completed_status",
		FinalReview: finalReviewIdentityWire{
			ReviewID: reviewID.String(), Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256(),
		},
		RoleReports: roleReports,
		Failures:    candidate.manifestFailures(),
		Warnings:    []string{},
		ExitCode:    candidate.exitCode,
	})
}

func (candidate PreparedCandidate) buildRoleReports() ([]ports.ImmutablePublicationArtifact, error) {
	reports := make([]ports.ImmutablePublicationArtifact, 0)
	for _, role := range candidate.roles {
		if !role.valid || len(role.reportMarkdown) == 0 {
			continue
		}
		path, err := ports.NewSafeRelativePath(artifactwire.RunPath(candidate.sessionID.String(), candidate.runID.String(), artifactwire.RoleReportPath(string(role.role))))
		if err != nil {
			return nil, fmt.Errorf("publication build: role report path: %w", err)
		}
		artifact, err := immutableArtifact(path, role.reportMarkdown)
		if err != nil {
			return nil, fmt.Errorf("publication build: role report %s: %w", role.role, err)
		}
		notePublicationConstruction(&publicationRoleReportConstructions)
		reports = append(reports, artifact)
	}
	return reports, nil
}

func (candidate PreparedCandidate) manifestRoleReports() []manifestRoleReportWire {
	reports := make([]manifestRoleReportWire, 0)
	for _, role := range candidate.roles {
		if !role.valid || len(role.reportMarkdown) == 0 {
			continue
		}
		if len(role.attempts) == 0 {
			continue
		}
		finalAttempt := role.attempts[len(role.attempts)-1]
		reports = append(reports, manifestRoleReportWire{
			Role:             string(role.role),
			Path:             artifactwire.RoleReportPath(string(role.role)),
			SHA256:           sha256Identifier(role.reportMarkdown),
			ByteLength:       len(role.reportMarkdown),
			ProviderInstance: finalAttempt.provider,
			AttemptID:        finalAttempt.id.String(),
			ContentType:      "text/markdown",
			Transport:        string(role.outputTransport),
		})
	}
	return reports
}

// roleReportIdentity is the exact-byte identity of one constructed role
// report artifact, retained so later bindings reuse it instead of digesting
// the report markdown again.
type roleReportIdentity struct {
	sha256     string
	byteLength int
}

// roleReportIdentities maps each published role to the identity of the
// artifact buildRoleReports constructed for it, walking the roles with the
// same emission guard so the mapping stays positional.
func (candidate PreparedCandidate) roleReportIdentities(reports []ports.ImmutablePublicationArtifact) map[domain.Role]roleReportIdentity {
	identities := make(map[domain.Role]roleReportIdentity, len(reports))
	next := 0
	for _, role := range candidate.roles {
		if !role.valid || len(role.reportMarkdown) == 0 || next >= len(reports) {
			continue
		}
		identities[role.role] = roleReportIdentity{sha256: reports[next].SHA256(), byteLength: reports[next].ByteLength()}
		next++
	}
	return identities
}

// manifestRoleReportsFromIdentities applies the manifestRoleReports skip
// rules while taking each report's digest and length from the retained
// identities instead of re-hashing the markdown.
func (candidate PreparedCandidate) manifestRoleReportsFromIdentities(identities map[domain.Role]roleReportIdentity) []manifestRoleReportWire {
	reports := make([]manifestRoleReportWire, 0)
	for _, role := range candidate.roles {
		if !role.valid || len(role.reportMarkdown) == 0 {
			continue
		}
		if len(role.attempts) == 0 {
			continue
		}
		identity, ok := identities[role.role]
		if !ok {
			identity = roleReportIdentity{sha256: sha256Identifier(role.reportMarkdown), byteLength: len(role.reportMarkdown)}
		}
		finalAttempt := role.attempts[len(role.attempts)-1]
		reports = append(reports, manifestRoleReportWire{
			Role:             string(role.role),
			Path:             artifactwire.RoleReportPath(string(role.role)),
			SHA256:           identity.sha256,
			ByteLength:       identity.byteLength,
			ProviderInstance: finalAttempt.provider,
			AttemptID:        finalAttempt.id.String(),
			ContentType:      "text/markdown",
			Transport:        string(role.outputTransport),
		})
	}
	return reports
}

func (candidate PreparedCandidate) finalRoleOutcomes() []roleOutcomeWire {
	outcomes := make([]roleOutcomeWire, len(candidate.roles))
	for index, role := range candidate.roles {
		failureReason := optionalString(role.failureReason)
		outcome := roleOutcomeWire{
			Role: string(role.role), Required: role.required, Outcome: role.outcome,
			ValidFindingIDs: append([]string{}, role.validFindingIDs...), FailureReason: failureReason,
			Limitations: append([]string{}, role.limitations...),
		}
		if len(role.attempts) != 0 {
			finalAttempt := role.attempts[len(role.attempts)-1]
			outcome.AttemptID = optionalString(finalAttempt.id.String())
			outcome.ProviderInstance = optionalString(finalAttempt.provider)
			outcome.SelectedVia = optionalString(string(finalAttempt.kind))
		}
		outcomes[index] = outcome
	}
	return outcomes
}

func (candidate PreparedCandidate) finalFindings(reviewID domain.ReviewID) []finalFindingWire {
	findings := make([]finalFindingWire, len(candidate.findings))
	for index, finding := range candidate.findings {
		evidenceItems := make([]findingEvidenceWire, len(finding.evidence))
		for evidenceIndex, item := range finding.evidence {
			sourceSessionID, sourceRunID, sourceReviewID, sourceFindingID := candidate.sessionID.String(), candidate.runID.String(), reviewID.String(), finding.id
			sourceTargetSHA256, sourceExcerptSHA256 := candidate.target.sha256, item.currentExcerptSHA256
			if item.sourceSessionID != "" {
				sourceSessionID, sourceRunID, sourceReviewID, sourceFindingID = item.sourceSessionID, item.sourceRunID, item.sourceReviewID, item.sourceFindingID
				sourceTargetSHA256, sourceExcerptSHA256 = item.sourceTargetSHA256, item.sourceExcerptSHA256
			}
			evidenceItems[evidenceIndex] = findingEvidenceWire{
				Source: sourceEvidenceWire{
					SessionID: sourceSessionID, RunID: sourceRunID, ReviewID: sourceReviewID, FindingID: sourceFindingID,
					SourceTargetSHA256: sourceTargetSHA256, SourceExcerptSHA256: sourceExcerptSHA256,
				},
				Current: currentEvidenceWire{
					TargetSHA256: item.targetSHA256, Side: string(item.side), Path: item.path, LineStart: item.lineStart, LineEnd: item.lineEnd,
					Quote: item.quote, CurrentExcerptSHA256: item.currentExcerptSHA256, Verification: "verified",
				},
			}
			if candidate.target.live != nil {
				evidenceItems[evidenceIndex].Source.SourceIdentitySHA256 = sourceTargetSHA256
				evidenceItems[evidenceIndex].Source.SourceTargetSHA256 = ""
				evidenceItems[evidenceIndex].Current.SourceIdentitySHA256 = item.targetSHA256
				evidenceItems[evidenceIndex].Current.TargetSHA256 = ""
			}
			if item.visual != nil {
				evidenceItems[evidenceIndex].Visual = &visualEvidenceWire{
					Path: item.visual.path, SHA256: item.visual.sha256,
					BBox: visualBoundingBoxWire{
						X: item.visual.x, Y: item.visual.y, Width: item.visual.width, Height: item.visual.height,
					},
					Verification: "verified",
				}
			}
		}
		findings[index] = finalFindingWire{
			ID: finding.id, Fingerprint: finding.fingerprint, Role: string(finding.role), ProviderInstance: finding.provider,
			Severity: string(finding.severity), Title: finding.title, Description: finding.description, Evidence: evidenceItems,
			Recommendation: finding.recommendation, Confidence: string(finding.confidence), Lifecycle: string(finding.lifecycle),
		}
	}
	return findings
}

func (candidate PreparedCandidate) selectedRoles() []string {
	roles := make([]string, len(candidate.roles))
	for index, role := range candidate.roles {
		roles[index] = string(role.role)
	}
	return roles
}

func (candidate PreparedCandidate) requiredRoles() []string {
	roles := make([]string, 0, len(candidate.roles))
	for _, role := range candidate.roles {
		if role.required {
			roles = append(roles, string(role.role))
		}
	}
	return roles
}

func (candidate PreparedCandidate) manifestAttempts() []manifestAttemptWire {
	attempts := make([]manifestAttemptWire, 0)
	for _, role := range candidate.roles {
		for _, attempt := range role.attempts {
			parseState := domain.ParseNotStarted
			validationState := domain.ValidationNotStarted
			if attempt.state == domain.AttemptSucceeded {
				parseState = attempt.parseState
				validationState = attempt.validationState
			}
			attempts = append(attempts, manifestAttemptWire{
				AttemptID: attempt.id.String(), Role: string(role.role), ProviderInstance: attempt.provider,
				SelectedAs: string(attempt.kind), State: string(attempt.state), ParseState: string(parseState),
				ValidationState: string(validationState), Path: "attempts/" + attempt.id.String() + "/status.json",
				InvocationCount: len(attempt.invocations),
			})
		}
	}
	return attempts
}

func (candidate PreparedCandidate) manifestFailures() []manifestFailureWire {
	failures := make([]manifestFailureWire, len(candidate.failures))
	for index, failure := range candidate.failures {
		attemptID := (*string)(nil)
		if failure.attemptID != nil {
			attemptID = optionalString(failure.attemptID.String())
		}
		failures[index] = manifestFailureWire{
			Class: string(failure.class), Stage: failure.stage, ReasonCode: failure.reason, AttemptID: attemptID,
		}
	}
	return failures
}

func immutableArtifact(path ports.SafeRelativePath, bytes []byte) (ports.ImmutablePublicationArtifact, error) {
	return ports.NewImmutablePublicationArtifact(path, sha256Identifier(bytes), bytes)
}

func mutableDocument(path ports.SafeRelativePath, bytes []byte) (PublicationDocument, error) {
	document := PublicationDocument{path: path, sha256: sha256Identifier(bytes), bytes: cloneBytes(bytes)}
	if !document.Valid() {
		return PublicationDocument{}, fmt.Errorf("mutable publication document is invalid")
	}
	return document, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	copyValue := value
	return &copyValue
}
func lineageRunID(value *domain.RunID) *string {
	if value == nil {
		return nil
	}
	return optionalString(value.String())
}

func lineageReviewID(value *domain.ReviewID) *string {
	if value == nil {
		return nil
	}
	return optionalString(value.String())
}

func lineageAttemptID(value *domain.AttemptID) *string {
	if value == nil {
		return nil
	}
	return optionalString(value.String())
}

func lineageReplayMode(value *ReplayMode) *string {
	if value == nil {
		return nil
	}
	return optionalString(string(*value))
}

func cloneOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func (candidate PreparedCandidate) immutableLineageWire(edge ports.ImmutablePublicationArtifact) immutableLineageWire {
	return immutableLineageWire{
		ParentRunID:                  lineageRunID(candidate.publicationLineage().parentRunID),
		SourceRunID:                  lineageRunID(candidate.publicationLineage().sourceRunID),
		SourceReviewID:               lineageReviewID(candidate.publicationLineage().sourceReviewID),
		SourceRecoveryManifestSHA256: cloneOptionalString(candidate.publicationLineage().sourceRecoveryManifestSHA256),
		SourceKind:                   recoverySourceKind(candidate.publicationLineage().sourceRecoveryManifestSHA256),
		SourceAttemptID:              lineageAttemptID(candidate.publicationLineage().sourceAttemptID),
		SourceFindingRef:             cloneOptionalString(candidate.publicationLineage().sourceFindingRef),
		ReplayMode:                   lineageReplayMode(candidate.publicationLineage().replayMode),
		LineageEdgePath:              edge.Path().String(),
		LineageEdgeSHA256:            edge.SHA256(),
	}
}

func marshalCanonical(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return cloneBytes(buffer.Bytes()), nil
}

type mulgaeWire = artifactwire.BuildMetadata

type immutableLineageWire = artifactwire.ImmutableLineage

type finalTargetWire struct {
	ContentSHA256 string                `json:"content_sha256,omitempty"`
	ManifestPath  string                `json:"manifest_path"`
	BaseOID       *string               `json:"base_oid"`
	HeadOID       *string               `json:"head_oid"`
	LiveSource    *liveSourceTargetWire `json:"live_source,omitempty"`
}

type manifestTargetWire struct {
	ManifestPath         string `json:"manifest_path"`
	ContentSHA256        string `json:"content_sha256,omitempty"`
	SourceIdentitySHA256 string `json:"source_identity_sha256,omitempty"`
}

type validationWire = artifactwire.Validation

type severityThresholdWire = artifactwire.SeverityThreshold

type roleOutcomeWire = artifactwire.RoleOutcome

type finalFindingWire struct {
	ID               string                `json:"id"`
	Fingerprint      string                `json:"fingerprint"`
	Role             string                `json:"role"`
	ProviderInstance string                `json:"provider_instance"`
	Severity         string                `json:"severity"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Evidence         []findingEvidenceWire `json:"evidence"`
	Recommendation   string                `json:"recommendation"`
	Confidence       string                `json:"confidence"`
	Lifecycle        string                `json:"lifecycle"`
}

type findingEvidenceWire struct {
	Source  sourceEvidenceWire  `json:"source"`
	Current currentEvidenceWire `json:"current"`
	Visual  *visualEvidenceWire `json:"visual,omitempty"`
}

type visualEvidenceWire = artifactwire.VisualEvidence

type visualBoundingBoxWire = artifactwire.VisualBoundingBox

type sourceEvidenceWire struct {
	SessionID            string `json:"session_id"`
	RunID                string `json:"run_id"`
	ReviewID             string `json:"review_id"`
	FindingID            string `json:"finding_id"`
	SourceTargetSHA256   string `json:"source_target_sha256,omitempty"`
	SourceIdentitySHA256 string `json:"source_identity_sha256,omitempty"`
	SourceExcerptSHA256  string `json:"source_excerpt_sha256"`
}

type currentEvidenceWire struct {
	TargetSHA256         string `json:"target_sha256,omitempty"`
	SourceIdentitySHA256 string `json:"source_identity_sha256,omitempty"`
	Side                 string `json:"side"`
	Path                 string `json:"path"`
	LineStart            int    `json:"line_start"`
	LineEnd              int    `json:"line_end"`
	Quote                string `json:"quote"`
	CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
	Verification         string `json:"verification"`
}

type provenanceWire struct {
	AggregationPath     string                        `json:"aggregation_path"`
	FinalValidationPath string                        `json:"final_validation_path"`
	ManifestPath        string                        `json:"manifest_path"`
	Production          *productionProvenanceWire     `json:"production,omitempty"`
	LiveProduction      *liveProductionProvenanceWire `json:"live_production,omitempty"`
}

type productionProvenanceWire = artifactwire.ProductionProvenance

type productionProviderWire = artifactwire.ProductionProvider

type followupOutcomeWire struct {
	Resolution string                `json:"resolution"`
	Rationale  string                `json:"rationale"`
	Evidence   []findingEvidenceWire `json:"evidence"`
}

type finalReviewWire struct {
	RequirementsSupport        *artifactIdentityWire `json:"requirements_support,omitempty"`
	SchemaVersion              string                `json:"schema_version"`
	SessionID                  string                `json:"session_id"`
	RunID                      string                `json:"run_id"`
	ReviewID                   string                `json:"review_id"`
	RunType                    string                `json:"run_type"`
	CreatedAt                  string                `json:"created_at"`
	Mulgae                     mulgaeWire            `json:"mulgae"`
	ImmutableLineage           immutableLineageWire  `json:"immutable_lineage"`
	FollowupOutcome            *followupOutcomeWire  `json:"followup_outcome,omitempty"`
	Target                     finalTargetWire       `json:"target"`
	Validation                 validationWire        `json:"validation"`
	ContentVerdict             string                `json:"content_verdict"`
	CoverageStatus             string                `json:"coverage_status"`
	StructuredExtractionStatus string                `json:"structured_extraction_status"`
	PublicationStatus          string                `json:"publication_status"`
	CIDecision                 string                `json:"ci_decision"`
	CIReasonCodes              []string              `json:"ci_reason_codes"`
	SeverityThreshold          severityThresholdWire `json:"severity_threshold"`
	RoleOutcomes               []roleOutcomeWire     `json:"role_outcomes"`
	Findings                   []finalFindingWire    `json:"findings"`
	Limitations                []string              `json:"limitations"`
	Provenance                 provenanceWire        `json:"provenance"`
}

type manifestRoleReportWire = artifactwire.ManifestRoleReport

type manifestAttemptWire = artifactwire.ManifestAttempt

type artifactIdentityWire = artifactwire.ArtifactIdentity

type recoveryJournalWire struct {
	ExpectedStaged           artifactIdentityWire `json:"expected_staged"`
	ExpectedFinal            artifactIdentityWire `json:"expected_final"`
	ValidatedCandidateSHA256 string               `json:"validated_candidate_sha256"`
}

type pathPointerWire = artifactwire.PathPointer

type compositeIdentityWire struct {
	Manifest     pathPointerWire      `json:"manifest"`
	LineageEdge  artifactIdentityWire `json:"lineage_edge"`
	Epoch        pathPointerWire      `json:"epoch"`
	SupportIndex artifactIdentityWire `json:"support_index"`
}

type finalReviewIdentityWire = artifactwire.FinalReviewIdentity

type manifestFailureWire = artifactwire.ManifestFailure

type runManifestWire struct {
	RequirementsSupport        *artifactIdentityWire    `json:"requirements_support,omitempty"`
	SchemaVersion              string                   `json:"schema_version"`
	SessionID                  string                   `json:"session_id"`
	RunID                      string                   `json:"run_id"`
	RunType                    string                   `json:"run_type"`
	State                      string                   `json:"state"`
	Sealed                     bool                     `json:"sealed"`
	CreatedAt                  string                   `json:"created_at"`
	StartedAt                  *string                  `json:"started_at"`
	CompletedAt                *string                  `json:"completed_at"`
	MulgaeVersion              string                   `json:"mulgae_version"`
	ImmutableLineage           immutableLineageWire     `json:"immutable_lineage"`
	FollowupOutcome            *followupOutcomeWire     `json:"followup_outcome,omitempty"`
	Target                     manifestTargetWire       `json:"target"`
	SelectedRoles              []string                 `json:"selected_roles"`
	RequiredRoles              []string                 `json:"required_roles"`
	Attempts                   []manifestAttemptWire    `json:"attempts"`
	ContentVerdict             string                   `json:"content_verdict"`
	CoverageStatus             string                   `json:"coverage_status"`
	StructuredExtractionStatus string                   `json:"structured_extraction_status"`
	PublicationStatus          string                   `json:"publication_status"`
	CIDecision                 string                   `json:"ci_decision"`
	CIReasonCodes              []string                 `json:"ci_reason_codes"`
	PersistedJournalState      string                   `json:"persisted_journal_state"`
	DurableObservationClass    string                   `json:"durable_observation_class"`
	DerivedPublicationStatus   string                   `json:"derived_publication_status"`
	PublicationAuthority       string                   `json:"publication_authority"`
	RecoveryJournal            recoveryJournalWire      `json:"recovery_journal"`
	CompositeIdentity          compositeIdentityWire    `json:"composite_identity"`
	RecoveryAction             string                   `json:"recovery_action"`
	FinalReview                finalReviewIdentityWire  `json:"final_review"`
	RoleReports                []manifestRoleReportWire `json:"role_reports"`
	Failures                   []manifestFailureWire    `json:"failures"`
	Warnings                   []string                 `json:"warnings"`
	ExitCode                   int                      `json:"exit_code"`
}

type lineageChildWire = artifactwire.LineageChild

type lineageEdgeWire = artifactwire.LineageEdge

type publicationEpochWire = artifactwire.PublicationEpoch

// restartStateWire is intentionally embedded verbatim in both mutable records.
// It provides deterministic restart material without granting publication
// authority outside the persisted record bytes.
type restartStateWire = artifactwire.RestartState

type publicationJournalWire = artifactwire.PublicationJournal

type publicationStatusWire = artifactwire.PublicationStatus
