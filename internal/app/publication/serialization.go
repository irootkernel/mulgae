package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
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
		return PublicationBundle{}, fmt.Errorf("publication build: candidate is not prevalidated: %w", err)
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
		return PublicationBundle{}, err
	}
	edgeBytes, err := marshalCanonical(lineageEdgeWire{
		SchemaVersion: lineageEdgeV1,
		EdgeID:        "e_" + reviewID.String(),
		Child: lineageChildWire{
			SessionID: candidate.sessionID.String(),
			RunID:     candidate.runID.String(),
			ReviewID:  reviewID.String(),
		},
		ParentRunID:      nil,
		SourceRunID:      nil,
		SourceReviewID:   nil,
		SourceFindingRef: nil,
		ReplayMode:       nil,
	})
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: serialize lineage edge: %w", err)
	}
	lineageEdge, err := immutableArtifact(paths.lineageEdge, edgeBytes)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: lineage edge: %w", err)
	}

	excerpts, err := candidate.buildExcerpts(paths, reviewID)
	if err != nil {
		return PublicationBundle{}, err
	}
	finalBytes, err := candidate.buildFinalBytes(reviewID, createdAtText, lineageEdge)
	if err != nil {
		return PublicationBundle{}, err
	}
	finalSchema, err := ports.ParseAssetID(finalReviewSchemaAsset)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: final schema asset: %w", err)
	}
	if err := validator.Validate(ctx, finalSchema, cloneBytes(finalBytes)); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: final review schema validation: %w", err)
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

	manifestBytes, err := candidate.buildManifestBytes(reviewID, createdAtText, epoch, paths, final, lineageEdge)
	if err != nil {
		return PublicationBundle{}, err
	}
	manifestSchema, err := ports.ParseAssetID(runManifestSchemaAsset)
	if err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: manifest schema asset: %w", err)
	}
	if err := validator.Validate(ctx, manifestSchema, cloneBytes(manifestBytes)); err != nil {
		return PublicationBundle{}, fmt.Errorf("publication build: run manifest schema validation: %w", err)
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
	if !bundle.Valid() {
		return PublicationBundle{}, fmt.Errorf("publication build: constructed bundle is inconsistent")
	}
	return bundle, nil
}

type publicationPathsSet struct {
	final       ports.SafeRelativePath
	manifest    ports.SafeRelativePath
	journal     ports.SafeRelativePath
	status      ports.SafeRelativePath
	staged      ports.SafeRelativePath
	lineageEdge ports.SafeRelativePath
	epoch       ports.SafeRelativePath
	excerptsDir string
}

func publicationPaths(sessionID domain.SessionID, runID domain.RunID, reviewID domain.ReviewID, epoch uint64) (publicationPathsSet, error) {
	prefix := sessionID.String() + "/" + runID.String()
	return publicationPathsSet{
		final:       mustPublicationPath(prefix + "/review_" + reviewID.String() + ".json"),
		manifest:    mustPublicationPath(prefix + "/manifest.json"),
		journal:     mustPublicationPath(prefix + "/publication/journal.json"),
		status:      mustPublicationPath(prefix + "/status.json"),
		staged:      mustPublicationPath(prefix + "/publication/staged/review_" + reviewID.String() + ".json.tmp"),
		lineageEdge: mustPublicationPath("store/lineage-edges/e_" + reviewID.String() + ".json"),
		epoch:       mustPublicationPath(fmt.Sprintf("store/epochs/epoch_%020d.json", epoch)),
		excerptsDir: prefix + "/excerpts",
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
			if !validSHA256(item.excerptSHA256) || len(item.excerpt) == 0 {
				return nil, fmt.Errorf("publication build: excerpt %s/%d is invalid", finding.id, index+1)
			}
			artifact, err := immutableArtifact(path, item.excerpt)
			if err != nil {
				return nil, fmt.Errorf("publication build: excerpt %s/%d: %w", finding.id, index+1, err)
			}
			excerpts = append(excerpts, artifact)
		}
	}
	return excerpts, nil
}

func (candidate PreparedCandidate) buildFinalBytes(
	reviewID domain.ReviewID,
	createdAt string,
	lineageEdge ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	commit := optionalString(candidate.kar.commit)
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
		SchemaVersion: "kar-review-artifact.v2",
		SessionID:     candidate.sessionID.String(),
		RunID:         candidate.runID.String(),
		ReviewID:      reviewID.String(),
		RunType:       string(domain.RunTypeReview),
		CreatedAt:     createdAt,
		KAR: karWire{
			Version: candidate.kar.version,
			Commit:  commit,
		},
		ImmutableLineage: immutableLineageWire{
			ParentRunID: nil, SourceRunID: nil, SourceReviewID: nil, SourceFindingRef: nil, ReplayMode: nil,
			LineageEdgePath: lineageEdge.Path().String(), LineageEdgeSHA256: lineageEdge.SHA256(),
		},
		Target: finalTargetWire{
			ContentSHA256: candidate.target.sha256, ManifestPath: targetManifestPath, BaseOID: baseOID, HeadOID: headOID,
		},
		Validation: validationWire{
			Status: status, SchemaValidation: "passed", SemanticValidation: "passed", EvidenceValidation: "passed",
		},
		ContentVerdict:    string(candidate.axes.content),
		CoverageStatus:    string(candidate.axes.coverage),
		PublicationStatus: string(domain.PublicationCommitted),
		CIDecision:        string(candidate.axes.ci),
		CIReasonCodes:     append([]string{}, candidate.reasons...),
		SeverityThreshold: severityThresholdWire{
			RequestChangesAtOrAbove: string(candidate.threshold), PolicySource: "trusted_base",
		},
		RoleOutcomes: candidate.finalRoleOutcomes(),
		Findings:     candidate.finalFindings(reviewID),
		Limitations:  append([]string{}, candidate.limits...),
		Provenance: provenanceWire{
			AggregationPath: aggregationPath, FinalValidationPath: finalValidationPath, ManifestPath: "manifest.json",
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
) ([]byte, error) {
	return marshalCanonical(runManifestWire{
		SchemaVersion: "kar-run-manifest.v2",
		SessionID:     candidate.sessionID.String(),
		RunID:         candidate.runID.String(),
		RunType:       string(domain.RunTypeReview),
		State:         string(candidate.runState),
		Sealed:        true,
		CreatedAt:     createdAt,
		StartedAt:     optionalString(createdAt),
		CompletedAt:   optionalString(createdAt),
		KARVersion:    candidate.kar.version,
		ImmutableLineage: immutableLineageWire{
			ParentRunID: nil, SourceRunID: nil, SourceReviewID: nil, SourceFindingRef: nil, ReplayMode: nil,
			LineageEdgePath: lineageEdge.Path().String(), LineageEdgeSHA256: lineageEdge.SHA256(),
		},
		Target:                   manifestTargetWire{ManifestPath: targetManifestPath, ContentSHA256: candidate.target.sha256},
		SelectedRoles:            candidate.selectedRoles(),
		RequiredRoles:            candidate.requiredRoles(),
		Attempts:                 candidate.manifestAttempts(),
		ContentVerdict:           string(candidate.axes.content),
		CoverageStatus:           string(candidate.axes.coverage),
		PublicationStatus:        string(domain.PublicationCommitted),
		CIDecision:               string(candidate.axes.ci),
		CIReasonCodes:            append([]string{}, candidate.reasons...),
		PersistedJournalState:    string(domain.JournalManifestCommitted),
		DurableObservationClass:  string(domain.DurableObservationP2Committed),
		DerivedPublicationStatus: string(domain.PublicationCommitted),
		PublicationAuthority:     string(domain.PublicationAuthorityP2),
		RecoveryJournal: recoveryJournalWire{
			ExpectedStaged:           artifactIdentityWire{Path: paths.staged.String(), SHA256: final.Identity().SHA256()},
			ExpectedFinal:            artifactIdentityWire{Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256()},
			ValidatedCandidateSHA256: candidate.ValidatedCandidateSHA256(),
		},
		CompositeIdentity: compositeIdentityWire{
			Manifest:    pathPointerWire{Path: paths.manifest.String()},
			LineageEdge: artifactIdentityWire{Path: lineageEdge.Path().String(), SHA256: lineageEdge.SHA256()},
			Epoch:       pathPointerWire{Path: paths.epoch.String()},
		},
		RecoveryAction: "reconstruct_completed_status",
		FinalReview: finalReviewIdentityWire{
			ReviewID: reviewID.String(), Path: final.Identity().Path().String(), SHA256: final.Identity().SHA256(),
		},
		Failures: candidate.manifestFailures(),
		Warnings: []string{},
		ExitCode: candidate.exitCode,
	})
}

func (candidate PreparedCandidate) finalRoleOutcomes() []roleOutcomeWire {
	outcomes := make([]roleOutcomeWire, len(candidate.roles))
	for index, role := range candidate.roles {
		finalAttempt := role.attempts[len(role.attempts)-1]
		failureReason := optionalString(role.failureReason)
		outcomes[index] = roleOutcomeWire{
			Role: string(role.role), Required: role.required, Outcome: role.outcome, AttemptID: optionalString(finalAttempt.id.String()),
			ProviderInstance: optionalString(finalAttempt.provider), SelectedVia: optionalString(string(finalAttempt.kind)),
			ValidFindingIDs: append([]string{}, role.validFindingIDs...), FailureReason: failureReason,
			Limitations: append([]string{}, role.limitations...),
		}
	}
	return outcomes
}

func (candidate PreparedCandidate) finalFindings(reviewID domain.ReviewID) []finalFindingWire {
	findings := make([]finalFindingWire, len(candidate.findings))
	for index, finding := range candidate.findings {
		evidenceItems := make([]findingEvidenceWire, len(finding.evidence))
		for evidenceIndex, item := range finding.evidence {
			evidenceItems[evidenceIndex] = findingEvidenceWire{
				Source: sourceEvidenceWire{
					SessionID: candidate.sessionID.String(), RunID: candidate.runID.String(), ReviewID: reviewID.String(), FindingID: finding.id,
					SourceTargetSHA256: candidate.target.sha256, SourceExcerptSHA256: item.excerptSHA256,
				},
				Current: currentEvidenceWire{
					TargetSHA256: item.targetSHA256, Side: string(item.side), Path: item.path, LineStart: item.lineStart, LineEnd: item.lineEnd,
					Quote: item.quote, Verification: "verified",
				},
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
			parseState := "not_started"
			validationState := "not_started"
			if attempt.state == domain.AttemptSucceeded {
				parseState = "valid"
				validationState = "valid"
				if role.repaired {
					validationState = "repaired_valid"
				}
			}
			attempts = append(attempts, manifestAttemptWire{
				AttemptID: attempt.id.String(), Role: string(role.role), ProviderInstance: attempt.provider,
				SelectedAs: string(attempt.kind), State: string(attempt.state), ParseState: parseState,
				ValidationState: validationState, Path: "attempts/" + attempt.id.String() + "/status.json",
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

func marshalCanonical(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return cloneBytes(buffer.Bytes()), nil
}

type karWire struct {
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
	TargetSHA256 string `json:"target_sha256"`
	Side         string `json:"side"`
	Path         string `json:"path"`
	LineStart    int    `json:"line_start"`
	LineEnd      int    `json:"line_end"`
	Quote        string `json:"quote"`
	Verification string `json:"verification"`
}

type provenanceWire struct {
	AggregationPath     string `json:"aggregation_path"`
	FinalValidationPath string `json:"final_validation_path"`
	ManifestPath        string `json:"manifest_path"`
}

type finalReviewWire struct {
	SchemaVersion     string                `json:"schema_version"`
	SessionID         string                `json:"session_id"`
	RunID             string                `json:"run_id"`
	ReviewID          string                `json:"review_id"`
	RunType           string                `json:"run_type"`
	CreatedAt         string                `json:"created_at"`
	KAR               karWire               `json:"kar"`
	ImmutableLineage  immutableLineageWire  `json:"immutable_lineage"`
	Target            finalTargetWire       `json:"target"`
	Validation        validationWire        `json:"validation"`
	ContentVerdict    string                `json:"content_verdict"`
	CoverageStatus    string                `json:"coverage_status"`
	PublicationStatus string                `json:"publication_status"`
	CIDecision        string                `json:"ci_decision"`
	CIReasonCodes     []string              `json:"ci_reason_codes"`
	SeverityThreshold severityThresholdWire `json:"severity_threshold"`
	RoleOutcomes      []roleOutcomeWire     `json:"role_outcomes"`
	Findings          []finalFindingWire    `json:"findings"`
	Limitations       []string              `json:"limitations"`
	Provenance        provenanceWire        `json:"provenance"`
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
	Manifest    pathPointerWire      `json:"manifest"`
	LineageEdge artifactIdentityWire `json:"lineage_edge"`
	Epoch       pathPointerWire      `json:"epoch"`
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
	SchemaVersion            string                  `json:"schema_version"`
	SessionID                string                  `json:"session_id"`
	RunID                    string                  `json:"run_id"`
	RunType                  string                  `json:"run_type"`
	State                    string                  `json:"state"`
	Sealed                   bool                    `json:"sealed"`
	CreatedAt                string                  `json:"created_at"`
	StartedAt                *string                 `json:"started_at"`
	CompletedAt              *string                 `json:"completed_at"`
	KARVersion               string                  `json:"kar_version"`
	ImmutableLineage         immutableLineageWire    `json:"immutable_lineage"`
	Target                   manifestTargetWire      `json:"target"`
	SelectedRoles            []string                `json:"selected_roles"`
	RequiredRoles            []string                `json:"required_roles"`
	Attempts                 []manifestAttemptWire   `json:"attempts"`
	ContentVerdict           string                  `json:"content_verdict"`
	CoverageStatus           string                  `json:"coverage_status"`
	PublicationStatus        string                  `json:"publication_status"`
	CIDecision               string                  `json:"ci_decision"`
	CIReasonCodes            []string                `json:"ci_reason_codes"`
	PersistedJournalState    string                  `json:"persisted_journal_state"`
	DurableObservationClass  string                  `json:"durable_observation_class"`
	DerivedPublicationStatus string                  `json:"derived_publication_status"`
	PublicationAuthority     string                  `json:"publication_authority"`
	RecoveryJournal          recoveryJournalWire     `json:"recovery_journal"`
	CompositeIdentity        compositeIdentityWire   `json:"composite_identity"`
	RecoveryAction           string                  `json:"recovery_action"`
	FinalReview              finalReviewIdentityWire `json:"final_review"`
	Failures                 []manifestFailureWire   `json:"failures"`
	Warnings                 []string                `json:"warnings"`
	ExitCode                 int                     `json:"exit_code"`
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
