package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

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

	paths, err := publicationPaths(candidate.sessionID, candidate.runID, reviewID, epoch)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationStaging, domain.DiagnosticCausePublicationPathFailed, err)
	}
	lineage := candidate.publicationLineage()
	edgeBytes, err := marshalCanonical(lineageEdgeWire{
		SchemaVersion: lineageEdgeV1,
		EdgeID:        "e_" + reviewID.String(),
		Child: lineageChildWire{
			SessionID: candidate.sessionID.String(),
			RunID:     candidate.runID.String(),
			ReviewID:  reviewID.String(),
		},
		ParentRunID:      lineageRunID(lineage.parentRunID),
		SourceRunID:      lineageRunID(lineage.sourceRunID),
		SourceReviewID:   lineageReviewID(lineage.sourceReviewID),
		SourceFindingRef: cloneOptionalString(lineage.sourceFindingRef),
		ReplayMode:       lineageReplayMode(lineage.replayMode),
	})
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationManifest, domain.DiagnosticCausePublicationSerializationFailed, fmt.Errorf("publication build: serialize lineage edge: %w", err))
	}
	lineageEdge, err := immutableArtifact(paths.lineageEdge, edgeBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: lineage edge: %w", err)
	}

	excerpts, err := candidate.buildExcerpts(paths, reviewID)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	attemptArtifacts, err := candidate.buildAttemptArtifacts()
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	runtimeArtifacts, err := candidate.buildRuntimeArtifacts()
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	roleReports, err := candidate.buildRoleReports()
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	excerpts = append(excerpts, attemptArtifacts...)
	excerpts = append(excerpts, runtimeArtifacts...)
	excerpts = append(excerpts, roleReports...)
	supportIndex, err := buildRunSupportIndex(paths.supportIndex, excerpts)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationPersistence, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	excerpts = append(excerpts, supportIndex)
	finalBytes, err := candidate.buildFinalBytes(reviewID, createdAtText, lineageEdge)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	finalSchema, err := ports.ParseAssetID(finalReviewSchemaAsset)
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

	manifestBytes, err := candidate.buildManifestBytes(reviewID, createdAtText, epoch, paths, final, lineageEdge, supportIndex)
	if err != nil {
		return PublicationBundle{}, buildFailure(domain.DiagnosticPhasePublicationManifest, domain.DiagnosticCausePublicationSerializationFailed, err)
	}
	manifestSchema, err := ports.ParseAssetID(runManifestSchemaAsset)
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
		SchemaVersion:    publicationJournalV1,
		restartStateWire: restart,
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
		restartStateWire:     restart,
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
		final:        mustPublicationPath(prefix + "/review_" + reviewID.String() + ".json"),
		manifest:     mustPublicationPath(prefix + "/manifest.json"),
		journal:      mustPublicationPath(prefix + "/publication/journal.json"),
		status:       mustPublicationPath(prefix + "/status.json"),
		staged:       mustPublicationPath(prefix + "/publication/staged/review_" + reviewID.String() + ".json.tmp"),
		lineageEdge:  mustPublicationPath("store/lineage-edges/e_" + reviewID.String() + ".json"),
		epoch:        mustPublicationPath(fmt.Sprintf("store/epochs/epoch_%020d.json", epoch)),
		supportIndex: mustPublicationPath(prefix + "/support/index.json"),
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
	excerpts := make([]ports.ImmutablePublicationArtifact, 0)
	for _, finding := range candidate.findings {
		for index, item := range finding.evidence {
			path, err := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s_%d.md", paths.excerptsDir, finding.id, index+1))
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
			excerpts = append(excerpts, artifact)
		}
	}
	for _, finding := range candidate.finalFindings(reviewID) {
		path, err := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s.json", paths.excerptsDir, finding.ID))
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

type runSupportIndexWire struct {
	SchemaVersion string                 `json:"schema_version"`
	Artifacts     []artifactIdentityWire `json:"artifacts"`
}

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
	bytes, err := marshalCanonical(runSupportIndexWire{SchemaVersion: "mulgae-run-support-index.v1", Artifacts: identities})
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
			for _, invocation := range attempt.invocations {
				if invocation.purpose == domain.InvocationRepair {
					repairOrdinal++
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
							path, err = ports.NewSafeRelativePath(fmt.Sprintf(
								"%s/%s/attempts/%s/candidate.initial.json",
								candidate.sessionID, candidate.runID, attempt.id,
							))
						case ports.AttemptArtifactRepairedCandidate:
							path, err = ports.NewSafeRelativePath(fmt.Sprintf(
								"%s/%s/attempts/%s/candidate.repaired.%03d.json",
								candidate.sessionID, candidate.runID, attempt.id, repairOrdinal,
							))
						case ports.AttemptArtifactStdout, ports.AttemptArtifactStderr:
							path, err = ports.NewSafeRelativePath(fmt.Sprintf(
								"%s/%s/attempts/%s/invocations/%03d-%s/%s.raw",
								candidate.sessionID, candidate.runID, attempt.id, invocation.sequence, invocation.purpose, capture.kind,
							))
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
			statusPath, err := ports.NewSafeRelativePath(fmt.Sprintf(
				"%s/%s/attempts/%s/status.json", candidate.sessionID, candidate.runID, attempt.id,
			))
			if err != nil {
				return nil, fmt.Errorf("publication build: attempt status path: %w", err)
			}
			statusArtifact, err := immutableArtifact(statusPath, statusBytes)
			if err != nil {
				return nil, fmt.Errorf("publication build: attempt status artifact: %w", err)
			}
			artifacts = append(artifacts, statusArtifact)
		}
	}
	return artifacts, nil
}

type runtimeTargetManifestWire struct {
	SchemaVersion         string                     `json:"schema_version"`
	Target                artifactIdentityWire       `json:"target"`
	CapturedArchive       *artifactIdentityWire      `json:"captured_archive,omitempty"`
	ArtistBrief           *artifactIdentityWire      `json:"artist_brief,omitempty"`
	ArtistVisualAssets    *artifactIdentityWire      `json:"artist_visual_assets,omitempty"`
	TargetKind            string                     `json:"target_kind"`
	RepositoryID          string                     `json:"repository_id"`
	BaseObjectID          string                     `json:"base_object_id"`
	HeadObjectID          string                     `json:"head_object_id"`
	HeadTreeObjectID      string                     `json:"head_tree_object_id"`
	IndexTreeObjectID     string                     `json:"index_tree_object_id"`
	GitMode               string                     `json:"git_mode"`
	Prompts               []artifactIdentityWire     `json:"prompts"`
	SelectedReplayPrompts []selectedReplayPromptWire `json:"selected_replay_prompts"`
}

type capturedArtistInputWire struct {
	SchemaVersion string                     `json:"schema_version"`
	Status        string                     `json:"status"`
	TaskPath      string                     `json:"task_path"`
	Task          string                     `json:"task"`
	VisualAssets  []capturedArtistVisualWire `json:"visual_assets"`
}

type capturedArtistVisualWire struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type publishedArtistVisualsWire struct {
	SchemaVersion string                     `json:"schema_version"`
	BriefPath     string                     `json:"brief_path"`
	VisualAssets  []capturedArtistVisualWire `json:"visual_assets"`
}
type selectedReplayPromptWire struct {
	AttemptID string               `json:"attempt_id"`
	Sequence  uint64               `json:"sequence"`
	Purpose   string               `json:"purpose"`
	Artifact  artifactIdentityWire `json:"artifact"`
}

type runtimePromptManifestWire struct {
	SchemaVersion         string               `json:"schema_version"`
	Target                artifactIdentityWire `json:"target"`
	Stdin                 artifactIdentityWire `json:"stdin"`
	CompleteStdinSHA256   string               `json:"complete_stdin_sha256"`
	TemplateID            string               `json:"template_id"`
	TemplateVersion       string               `json:"template_version"`
	TemplateSHA256        string               `json:"template_sha256"`
	SourceInvocationID    string               `json:"source_invocation_id"`
	ExecutionInvocationID string               `json:"execution_invocation_id"`
	Scope                 string               `json:"scope"`
	Role                  string               `json:"role"`
	AdapterProfile        string               `json:"adapter_profile"`
	AdapterParameters     map[string]string    `json:"adapter_parameters"`
}

func (candidate PreparedCandidate) buildRuntimeArtifacts() ([]ports.ImmutablePublicationArtifact, error) {
	var target []byte
	var capturedArchive []byte
	prompts := make([]artifactIdentityWire, 0)
	selectedPrompts := make([]selectedReplayPromptWire, 0)
	var identity *preparedRuntimeArtifact
	artifacts := make([]ports.ImmutablePublicationArtifact, 0)
	for roleIndex := range candidate.roles {
		role := &candidate.roles[roleIndex]
		for attemptIndex := range role.attempts {
			attempt := &role.attempts[attemptIndex]
			for invocationIndex := range attempt.invocations {
				invocation := &attempt.invocations[invocationIndex]
				if invocation.runtime == nil {
					continue
				}
				runtime := invocation.runtime
				if target == nil {
					target = cloneBytes(runtime.target)
					capturedArchive = cloneBytes(runtime.capturedArchive)
					identity = runtime
				} else if !bytes.Equal(target, runtime.target) || !bytes.Equal(capturedArchive, runtime.capturedArchive) {
					return nil, fmt.Errorf("publication build: runtime target bytes diverge")
				}
				stdinPath, err := ports.NewSafeRelativePath(fmt.Sprintf(
					"%s/%s/prompts/%s/%03d-%s.stdin", candidate.sessionID, candidate.runID,
					attempt.id, invocation.sequence, invocation.purpose,
				))
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime stdin path: %w", err)
				}
				stdin, err := immutableArtifact(stdinPath, runtime.stdin)
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime stdin: %w", err)
				}
				targetPath, err := ports.NewSafeRelativePath(fmt.Sprintf(
					"%s/%s/target/target.bytes", candidate.sessionID, candidate.runID,
				))
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime target path: %w", err)
				}
				targetArtifact, err := immutableArtifact(targetPath, runtime.target)
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime target: %w", err)
				}
				if len(artifacts) == 0 {
					artifacts = append(artifacts, targetArtifact)
				}
				promptPath, err := ports.NewSafeRelativePath(fmt.Sprintf(
					"%s/%s/prompts/%s/%03d-%s.manifest.json", candidate.sessionID, candidate.runID,
					attempt.id, invocation.sequence, invocation.purpose,
				))
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime prompt path: %w", err)
				}
				promptBytes, err := marshalCanonical(runtimePromptManifestWire{
					SchemaVersion:       "mulgae-runtime-prompt-manifest.v1",
					Target:              artifactIdentityWire{Path: targetArtifact.Path().String(), SHA256: targetArtifact.SHA256()},
					Stdin:               artifactIdentityWire{Path: stdin.Path().String(), SHA256: stdin.SHA256()},
					CompleteStdinSHA256: runtime.stdinSHA256,
					TemplateID:          runtime.templateID, TemplateVersion: runtime.templateVersion,
					TemplateSHA256: runtime.templateSHA256, SourceInvocationID: runtime.sourceInvocationID,
					ExecutionInvocationID: runtime.executionInvocationID, Scope: runtime.scope,
					Role: string(runtime.role), AdapterProfile: runtime.adapterProfile,
					AdapterParameters: runtime.adapterParameters,
				})
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime prompt manifest: %w", err)
				}
				promptArtifact, err := immutableArtifact(promptPath, promptBytes)
				if err != nil {
					return nil, fmt.Errorf("publication build: runtime prompt artifact: %w", err)
				}
				artifacts = append(artifacts, stdin, promptArtifact)
				promptIdentity := artifactIdentityWire{Path: promptArtifact.Path().String(), SHA256: promptArtifact.SHA256()}
				prompts = append(prompts, promptIdentity)
				if invocation.sequence == 1 && invocation.purpose == domain.InvocationInitial {
					selectedPrompts = append(selectedPrompts, selectedReplayPromptWire{
						AttemptID: attempt.id.String(), Sequence: invocation.sequence,
						Purpose: string(invocation.purpose), Artifact: promptIdentity,
					})
				}
			}
		}
	}
	if len(target) == 0 {
		return artifacts, nil
	}
	var capturedArchiveIdentity *artifactIdentityWire
	var artistBriefIdentity *artifactIdentityWire
	var artistVisualsIdentity *artifactIdentityWire
	if len(capturedArchive) > 0 {
		material, archiveErr := ports.UnmarshalCapturedReviewMaterial(capturedArchive)
		if archiveErr != nil {
			return nil, fmt.Errorf("publication build: captured archive decode: %w", archiveErr)
		}
		splitArchive, archiveErr := ports.NewCapturedReviewArchive(material)
		if archiveErr != nil {
			return nil, fmt.Errorf("publication build: captured archive split: %w", archiveErr)
		}
		archivePath, pathErr := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s/target/captured-review.json", candidate.sessionID, candidate.runID))
		if pathErr != nil {
			return nil, fmt.Errorf("publication build: captured archive path: %w", pathErr)
		}
		archiveArtifact, artifactErr := immutableArtifact(archivePath, splitArchive.Manifest())
		if artifactErr != nil {
			return nil, fmt.Errorf("publication build: captured archive: %w", artifactErr)
		}
		artifacts = append(artifacts, archiveArtifact)
		for _, blob := range splitArchive.Blobs() {
			blobPath, blobPathErr := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s/target/%s", candidate.sessionID, candidate.runID, blob.Path().String()))
			if blobPathErr != nil {
				return nil, fmt.Errorf("publication build: captured blob path: %w", blobPathErr)
			}
			blobArtifact, blobArtifactErr := immutableArtifact(blobPath, blob.Bytes())
			if blobArtifactErr != nil {
				return nil, fmt.Errorf("publication build: captured blob: %w", blobArtifactErr)
			}
			if blobArtifact.SHA256() != blob.SHA256() {
				return nil, fmt.Errorf("publication build: captured blob identity mismatch")
			}
			artifacts = append(artifacts, blobArtifact)
		}
		value := artifactIdentityWire{Path: archiveArtifact.Path().String(), SHA256: archiveArtifact.SHA256()}
		capturedArchiveIdentity = &value
		artistArtifacts, briefIdentity, visualsIdentity, artistErr := candidate.buildArtistInputArtifacts(material)
		if artistErr != nil {
			return nil, artistErr
		}
		artifacts = append(artifacts, artistArtifacts...)
		artistBriefIdentity, artistVisualsIdentity = briefIdentity, visualsIdentity
	}
	targetManifestArtifactPath, err := ports.NewSafeRelativePath(fmt.Sprintf(
		"%s/%s/%s", candidate.sessionID, candidate.runID, targetManifestPath,
	))
	if err != nil {
		return nil, fmt.Errorf("publication build: runtime target manifest path: %w", err)
	}
	targetManifestBytes, err := marshalCanonical(runtimeTargetManifestWire{
		SchemaVersion: "mulgae-runtime-target-manifest.v1",
		Target: artifactIdentityWire{
			Path:   fmt.Sprintf("%s/%s/target/target.bytes", candidate.sessionID, candidate.runID),
			SHA256: sha256Identifier(target),
		},
		CapturedArchive: capturedArchiveIdentity, ArtistBrief: artistBriefIdentity, ArtistVisualAssets: artistVisualsIdentity,
		TargetKind: string(identity.targetKind), RepositoryID: identity.targetRepository,
		BaseObjectID: identity.targetBaseOID, HeadObjectID: identity.targetHeadOID,
		HeadTreeObjectID: identity.targetHeadTreeOID, IndexTreeObjectID: identity.targetIndexTreeOID,
		GitMode: string(identity.targetGitMode),
		Prompts: prompts, SelectedReplayPrompts: selectedPrompts,
	})
	if err != nil {
		return nil, fmt.Errorf("publication build: runtime target manifest: %w", err)
	}
	targetManifest, err := immutableArtifact(targetManifestArtifactPath, targetManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("publication build: runtime target manifest artifact: %w", err)
	}
	return append(artifacts, targetManifest), nil
}

func (candidate PreparedCandidate) buildArtistInputArtifacts(material ports.CapturedReviewMaterial) ([]ports.ImmutablePublicationArtifact, *artifactIdentityWire, *artifactIdentityWire, error) {
	if !material.Valid() || !material.HasProjectContext() {
		return nil, nil, nil, nil
	}
	raw := material.ProjectContext()
	if index := bytes.LastIndexByte(raw, '\n'); index >= 0 {
		raw = raw[index+1:]
	}
	var inputs capturedArtistInputWire
	if json.Unmarshal(raw, &inputs) != nil || inputs.SchemaVersion != "mulgae-artist-inputs.v1" {
		return nil, nil, nil, nil
	}
	if inputs.Status != "ready" || inputs.TaskPath == "" || inputs.Task == "" || len(inputs.VisualAssets) == 0 {
		return nil, nil, nil, fmt.Errorf("publication build: captured artist inputs are incomplete")
	}
	files := make(map[string]ports.WorkspaceSnapshotFile, len(material.Snapshot().Files()))
	for _, file := range material.Snapshot().Files() {
		files[file.Path().String()] = file
	}
	for _, visual := range inputs.VisualAssets {
		file, ok := files[visual.Path]
		if !ok || file.IsText() || file.SHA256() != visual.SHA256 || file.MediaType() != visual.MediaType {
			return nil, nil, nil, fmt.Errorf("publication build: captured artist visual identity mismatch")
		}
	}
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/inputs/"
	briefPath, err := ports.NewSafeRelativePath(prefix + "artist-brief.md")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publication build: artist brief path: %w", err)
	}
	briefArtifact, err := immutableArtifact(briefPath, []byte(inputs.Task))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publication build: artist brief: %w", err)
	}
	visualBytes, err := marshalCanonical(publishedArtistVisualsWire{SchemaVersion: "mulgae-artist-visual-assets.v1", BriefPath: inputs.TaskPath, VisualAssets: inputs.VisualAssets})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publication build: artist visual manifest: %w", err)
	}
	visualPath, err := ports.NewSafeRelativePath(prefix + "artist-visual-assets.json")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publication build: artist visual manifest path: %w", err)
	}
	visualArtifact, err := immutableArtifact(visualPath, visualBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("publication build: artist visual manifest artifact: %w", err)
	}
	briefIdentity := &artifactIdentityWire{Path: briefArtifact.Path().String(), SHA256: briefArtifact.SHA256()}
	visualIdentity := &artifactIdentityWire{Path: visualArtifact.Path().String(), SHA256: visualArtifact.SHA256()}
	return []ports.ImmutablePublicationArtifact{briefArtifact, visualArtifact}, briefIdentity, visualIdentity, nil
}

func (candidate PreparedCandidate) buildFinalBytes(
	reviewID domain.ReviewID,
	createdAt string,
	lineageEdge ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	commit := optionalString(candidate.mulgae.commit)
	baseOID := optionalString(candidate.target.baseOID)
	headOID := optionalString(candidate.target.headOID)
	status := "valid"
	for _, role := range candidate.roles {
		if role.repaired {
			status = "repaired_valid"
			break
		}
	}
	return marshalCanonical(finalReviewWire{
		SchemaVersion: "mulgae-review-artifact.v1",
		SessionID:     candidate.sessionID.String(),
		RunID:         candidate.runID.String(),
		ReviewID:      reviewID.String(),
		RunType:       string(candidate.publicationLineage().runType),
		CreatedAt:     createdAt,
		Mulgae: mulgaeWire{
			Version: candidate.mulgae.version,
			Commit:  commit,
		},
		ImmutableLineage: candidate.immutableLineageWire(lineageEdge),
		FollowupOutcome:  candidate.followupOutcomeWire(),
		Target: finalTargetWire{
			ContentSHA256: candidate.target.sha256, ManifestPath: targetManifestPath, BaseOID: baseOID, HeadOID: headOID,
		},
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
			Production: candidate.productionProvenanceWire(),
		},
	})
}

func (candidate PreparedCandidate) buildManifestBytes(
	reviewID domain.ReviewID,
	createdAt string,
	epoch uint64,
	paths publicationPathsSet,
	final ports.FinalReviewArtifact,
	lineageEdge ports.ImmutablePublicationArtifact,
	supportIndex ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	return marshalCanonical(runManifestWire{
		SchemaVersion:              "mulgae-run-manifest.v1",
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
		FollowupOutcome:            candidate.followupOutcomeWire(),
		Target:                     manifestTargetWire{ManifestPath: targetManifestPath, ContentSHA256: candidate.target.sha256},
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
		RoleReports: candidate.manifestRoleReports(),
		Failures:    candidate.manifestFailures(),
		Warnings:    []string{},
		ExitCode:    candidate.exitCode,
	})
}

func (candidate PreparedCandidate) buildRoleReports() ([]ports.ImmutablePublicationArtifact, error) {
	prefix := candidate.sessionID.String() + "/" + candidate.runID.String() + "/role-reports"
	reports := make([]ports.ImmutablePublicationArtifact, 0)
	for _, role := range candidate.roles {
		if !role.valid || len(role.reportMarkdown) == 0 {
			continue
		}
		path, err := ports.NewSafeRelativePath(prefix + "/" + string(role.role) + ".md")
		if err != nil {
			return nil, fmt.Errorf("publication build: role report path: %w", err)
		}
		artifact, err := immutableArtifact(path, role.reportMarkdown)
		if err != nil {
			return nil, fmt.Errorf("publication build: role report %s: %w", role.role, err)
		}
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
			Path:             "role-reports/" + string(role.role) + ".md",
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

func (candidate PreparedCandidate) productionProvenanceWire() *productionProvenanceWire {
	if candidate.production == nil {
		return nil
	}
	value := candidate.production
	providers := make([]productionProviderWire, len(value.Providers))
	for index, provider := range value.Providers {
		providers[index] = productionProviderWire{
			Family: provider.Family, Instance: provider.Instance, Version: provider.Version,
			Executable: provider.Executable, ExecutableSHA256: provider.ExecutableSHA256,
			Launcher: provider.Launcher, LauncherSHA256: provider.LauncherSHA256,
			ProfileGeneration: provider.ProfileGeneration, AdapterProfile: provider.AdapterProfile,
			QualificationReceiptIDs:   append([]string(nil), provider.QualificationReceiptIDs...),
			PacketTransportReceiptIDs: append([]string(nil), provider.PacketTransportReceiptIDs...),
			NamespaceTerminalReceipt:  provider.NamespaceTerminalReceipt,
		}
	}
	var objective *string
	if value.HasObjective {
		objectiveValue := value.ObjectiveSHA256
		objective = &objectiveValue
	}
	return &productionProvenanceWire{
		BuildProduct: value.BuildProduct, BuildVersion: value.BuildVersion, BuildCommit: value.BuildCommit,
		ObjectiveSHA256: objective, ObjectivePresent: value.HasObjective,
		SnapshotManifestSHA256:   value.SnapshotManifestSHA256,
		WorkspaceTerminalReceipt: value.WorkspaceTerminalReceipt, Providers: providers,
	}
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
		ParentRunID:       lineageRunID(candidate.publicationLineage().parentRunID),
		SourceRunID:       lineageRunID(candidate.publicationLineage().sourceRunID),
		SourceReviewID:    lineageReviewID(candidate.publicationLineage().sourceReviewID),
		SourceFindingRef:  cloneOptionalString(candidate.publicationLineage().sourceFindingRef),
		ReplayMode:        lineageReplayMode(candidate.publicationLineage().replayMode),
		LineageEdgePath:   edge.Path().String(),
		LineageEdgeSHA256: edge.SHA256(),
	}
}

func (candidate PreparedCandidate) followupOutcomeWire() *followupOutcomeWire {
	if candidate.followup == nil {
		return nil
	}
	evidenceItems := make([]findingEvidenceWire, len(candidate.followup.evidence))
	for index, item := range candidate.followup.evidence {
		evidenceItems[index] = findingEvidenceWire{
			Source: sourceEvidenceWire{
				SessionID: item.sourceSessionID, RunID: item.sourceRunID, ReviewID: item.sourceReviewID,
				FindingID: item.sourceFindingID, SourceTargetSHA256: item.sourceTargetSHA256,
				SourceExcerptSHA256: item.sourceExcerptSHA256,
			},
			Current: currentEvidenceWire{
				TargetSHA256: item.targetSHA256, Side: string(item.side), Path: item.path,
				LineStart: item.lineStart, LineEnd: item.lineEnd, Quote: item.quote, CurrentExcerptSHA256: item.currentExcerptSHA256, Verification: "verified",
			},
		}
	}
	return &followupOutcomeWire{
		Resolution: string(candidate.followup.resolution), Rationale: candidate.followup.rationale, Evidence: evidenceItems,
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

type mulgaeWire struct {
	Version string  `json:"version"`
	Commit  *string `json:"commit"`
}

type immutableLineageWire struct {
	ParentRunID       *string `json:"parent_run_id"`
	SourceRunID       *string `json:"source_run_id"`
	SourceReviewID    *string `json:"source_review_id"`
	SourceFindingRef  *string `json:"source_finding_ref"`
	ReplayMode        *string `json:"replay_mode"`
	LineageEdgePath   string  `json:"lineage_edge_path"`
	LineageEdgeSHA256 string  `json:"lineage_edge_sha256"`
}

type finalTargetWire struct {
	ContentSHA256 string  `json:"content_sha256"`
	ManifestPath  string  `json:"manifest_path"`
	BaseOID       *string `json:"base_oid"`
	HeadOID       *string `json:"head_oid"`
}

type manifestTargetWire struct {
	ManifestPath  string `json:"manifest_path"`
	ContentSHA256 string `json:"content_sha256"`
}

type validationWire struct {
	Status             string `json:"status"`
	SchemaValidation   string `json:"schema_validation"`
	SemanticValidation string `json:"semantic_validation"`
	EvidenceValidation string `json:"evidence_validation"`
}

type severityThresholdWire struct {
	RequestChangesAtOrAbove string `json:"request_changes_at_or_above"`
	PolicySource            string `json:"policy_source"`
}

type roleOutcomeWire struct {
	Role             string   `json:"role"`
	Required         bool     `json:"required"`
	Outcome          string   `json:"outcome"`
	AttemptID        *string  `json:"attempt_id"`
	ProviderInstance *string  `json:"provider_instance"`
	SelectedVia      *string  `json:"selected_via"`
	ValidFindingIDs  []string `json:"valid_finding_ids"`
	FailureReason    *string  `json:"failure_reason"`
	Limitations      []string `json:"limitations"`
}

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

type visualEvidenceWire struct {
	Path         string                `json:"path"`
	SHA256       string                `json:"sha256"`
	BBox         visualBoundingBoxWire `json:"bbox"`
	Verification string                `json:"verification"`
}

type visualBoundingBoxWire struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type sourceEvidenceWire struct {
	SessionID           string `json:"session_id"`
	RunID               string `json:"run_id"`
	ReviewID            string `json:"review_id"`
	FindingID           string `json:"finding_id"`
	SourceTargetSHA256  string `json:"source_target_sha256"`
	SourceExcerptSHA256 string `json:"source_excerpt_sha256"`
}

type currentEvidenceWire struct {
	TargetSHA256         string `json:"target_sha256"`
	Side                 string `json:"side"`
	Path                 string `json:"path"`
	LineStart            int    `json:"line_start"`
	LineEnd              int    `json:"line_end"`
	Quote                string `json:"quote"`
	CurrentExcerptSHA256 string `json:"current_excerpt_sha256"`
	Verification         string `json:"verification"`
}

type provenanceWire struct {
	AggregationPath     string                    `json:"aggregation_path"`
	FinalValidationPath string                    `json:"final_validation_path"`
	ManifestPath        string                    `json:"manifest_path"`
	Production          *productionProvenanceWire `json:"production,omitempty"`
}

type productionProvenanceWire struct {
	BuildProduct             string                   `json:"build_product"`
	BuildVersion             string                   `json:"build_version"`
	BuildCommit              string                   `json:"build_commit"`
	ObjectiveSHA256          *string                  `json:"objective_sha256"`
	ObjectivePresent         bool                     `json:"objective_present"`
	SnapshotManifestSHA256   string                   `json:"snapshot_manifest_sha256"`
	WorkspaceTerminalReceipt string                   `json:"workspace_terminal_receipt"`
	Providers                []productionProviderWire `json:"providers"`
}

type productionProviderWire struct {
	Family                    string   `json:"family"`
	Instance                  string   `json:"instance"`
	Version                   string   `json:"version"`
	Executable                string   `json:"executable"`
	ExecutableSHA256          string   `json:"executable_sha256"`
	Launcher                  string   `json:"launcher"`
	LauncherSHA256            string   `json:"launcher_sha256"`
	ProfileGeneration         string   `json:"profile_generation"`
	AdapterProfile            string   `json:"adapter_profile"`
	QualificationReceiptIDs   []string `json:"qualification_receipt_ids"`
	PacketTransportReceiptIDs []string `json:"packet_transport_receipt_ids"`
	NamespaceTerminalReceipt  string   `json:"namespace_terminal_receipt"`
}

type followupOutcomeWire struct {
	Resolution string                `json:"resolution"`
	Rationale  string                `json:"rationale"`
	Evidence   []findingEvidenceWire `json:"evidence"`
}

type finalReviewWire struct {
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

type manifestRoleReportWire struct {
	Role             string `json:"role"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	ByteLength       int    `json:"byte_length"`
	ProviderInstance string `json:"provider_instance"`
	AttemptID        string `json:"attempt_id"`
	ContentType      string `json:"content_type"`
	Transport        string `json:"transport"`
}

type manifestAttemptWire struct {
	AttemptID        string `json:"attempt_id"`
	Role             string `json:"role"`
	ProviderInstance string `json:"provider_instance"`
	SelectedAs       string `json:"selected_as"`
	State            string `json:"state"`
	ParseState       string `json:"parse_state"`
	ValidationState  string `json:"validation_state"`
	Path             string `json:"path"`
	InvocationCount  int    `json:"invocation_count"`
}

type artifactIdentityWire struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type recoveryJournalWire struct {
	ExpectedStaged           artifactIdentityWire `json:"expected_staged"`
	ExpectedFinal            artifactIdentityWire `json:"expected_final"`
	ValidatedCandidateSHA256 string               `json:"validated_candidate_sha256"`
}

type pathPointerWire struct {
	Path string `json:"path"`
}

type compositeIdentityWire struct {
	Manifest     pathPointerWire      `json:"manifest"`
	LineageEdge  artifactIdentityWire `json:"lineage_edge"`
	Epoch        pathPointerWire      `json:"epoch"`
	SupportIndex artifactIdentityWire `json:"support_index"`
}

type finalReviewIdentityWire struct {
	ReviewID string `json:"review_id"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

type manifestFailureWire struct {
	Class      string  `json:"class"`
	Stage      string  `json:"stage"`
	ReasonCode string  `json:"reason_code"`
	AttemptID  *string `json:"attempt_id"`
}

type runManifestWire struct {
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

type lineageChildWire struct {
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id"`
	ReviewID  string `json:"review_id"`
}

type lineageEdgeWire struct {
	SchemaVersion    string           `json:"schema_version"`
	EdgeID           string           `json:"edge_id"`
	Child            lineageChildWire `json:"child"`
	ParentRunID      *string          `json:"parent_run_id"`
	SourceRunID      *string          `json:"source_run_id"`
	SourceReviewID   *string          `json:"source_review_id"`
	SourceFindingRef *string          `json:"source_finding_ref"`
	ReplayMode       *string          `json:"replay_mode"`
}

type publicationEpochWire struct {
	SchemaVersion string               `json:"schema_version"`
	StoreEpoch    uint64               `json:"store_epoch"`
	Manifest      artifactIdentityWire `json:"manifest"`
	LineageEdge   artifactIdentityWire `json:"lineage_edge"`
	FinalReview   artifactIdentityWire `json:"final_review"`
}

// restartStateWire is intentionally embedded verbatim in both mutable records.
// It provides deterministic restart material without granting publication
// authority outside the persisted record bytes.
type restartStateWire struct {
	SessionID                string               `json:"session_id"`
	RunID                    string               `json:"run_id"`
	PersistedJournalState    string               `json:"persisted_journal_state"`
	ExpectedStaged           artifactIdentityWire `json:"expected_staged"`
	ExpectedFinal            artifactIdentityWire `json:"expected_final"`
	ValidatedCandidateSHA256 string               `json:"validated_candidate_sha256"`
	StoreEpoch               uint64               `json:"store_epoch"`
	NormalExit               int                  `json:"normal_exit"`
	ManifestPath             string               `json:"manifest_path"`
	LineageEdgePath          string               `json:"lineage_edge_path"`
	EpochPath                string               `json:"epoch_path"`
}

type publicationJournalWire struct {
	SchemaVersion string `json:"schema_version"`
	restartStateWire
}

type publicationStatusWire struct {
	SchemaVersion        string `json:"schema_version"`
	PublicationStatus    string `json:"publication_status"`
	PublicationAuthority string `json:"publication_authority"`
	restartStateWire
}
