package query

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	coreapp "github.com/irootkernel/kkachi-agent-review/internal/app"
	"github.com/irootkernel/kkachi-agent-review/internal/app/evidence"
	"github.com/irootkernel/kkachi-agent-review/internal/app/prompt"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	resolveRunStage        = "query.resolve_run"
	readCommittedStage     = "query.read_committed"
	readStatusStage        = "query.read_run_status"
	listFindingsStage      = "query.list_findings"
	renderExcerptStage     = "query.render_excerpt"
	readRuntimeTargetStage = "query.read_runtime_target"

	finalReviewSchemaURI = "https://kar.local/schemas/kar-review-artifact.v3.schema.json"
	runManifestSchemaURI = "https://kar.local/schemas/kar-run-manifest.v2.schema.json"
)

var (
	finalReviewSchemaAsset = requiredSchemaAsset(finalReviewSchemaURI)
	runManifestSchemaAsset = requiredSchemaAsset(runManifestSchemaURI)
)

// Service reads only physically safe P2 snapshots, then independently verifies
// their schema and semantic identities before exposing consumer-facing views.
type Service struct {
	store        ports.PublicationStore
	validator    SchemaValidator
	maxReadBytes int64
}

type observedRun struct {
	decision   domain.PublicationDecision
	storeEpoch uint64
	snapshot   ports.CommittedPublicationSnapshot
}

type runtimeSupportIndexDTO struct {
	SchemaVersion string                `json:"schema_version"`
	Artifacts     []artifactIdentityDTO `json:"artifacts"`
}

// NewService constructs the shared committed-read service. The immutable target
// reader remains an accepted dependency for source compatibility, but v2
// publications require their own durable excerpts and never fall back to it.
func NewService(
	store ports.PublicationStore,
	validator SchemaValidator,
	_ evidence.ImmutableTargetReader,
	maxReadBytes int64,
) (*Service, error) {
	if missingDependency(store) {
		return nil, fmt.Errorf("query service: publication store is required")
	}
	if missingDependency(validator) {
		return nil, fmt.Errorf("query service: schema validator is required")
	}
	if maxReadBytes <= 0 {
		return nil, fmt.Errorf("query service: max read bytes must be positive")
	}
	return &Service{
		store: store, validator: validator, maxReadBytes: maxReadBytes,
	}, nil
}

// ResolveRun resolves a caller-selected canonical run ID beneath an approved
// artifact root through the store boundary. It never scans artifact directories.
func (service *Service) ResolveRun(
	ctx context.Context,
	root ports.AnchoredRoot,
	runID domain.RunID,
) (ports.PublicationRun, error) {
	if missingDependency(service) || missingDependency(service.store) {
		return ports.PublicationRun{}, typedFailure(
			resolveRunStage,
			domain.FailureArtifact,
			"publication store is unavailable",
			nil,
		)
	}
	if err := contextFailure(ctx, resolveRunStage); err != nil {
		return ports.PublicationRun{}, err
	}
	request, err := ports.NewResolvePublicationRunRequest(root, runID, service.maxReadBytes)
	if err != nil {
		return ports.PublicationRun{}, typedFailure(
			resolveRunStage,
			domain.FailureConfiguration,
			"publication run resolution request is invalid",
			err,
		)
	}
	run, err := service.store.ResolveRun(ctx, request)
	if err != nil {
		return ports.PublicationRun{}, dependencyFailure(
			ctx,
			resolveRunStage,
			domain.FailureArtifact,
			"publication run resolution failed",
			err,
		)
	}
	if !run.Valid() || run.Root() != root || run.RunID() != runID {
		return ports.PublicationRun{}, typedFailure(
			resolveRunStage,
			domain.FailureArtifact,
			"publication run resolution returned an invalid scope",
			nil,
		)
	}
	return run, nil
}

// ReadCommitted returns a defensive view only when the observed P2 epoch binds
// the snapshot and remains unchanged under P2 re-observation.
func (service *Service) ReadCommitted(ctx context.Context, run ports.PublicationRun) (CommittedReview, error) {
	if err := service.preflight(ctx, readCommittedStage); err != nil {
		return CommittedReview{}, err
	}
	observation, err := service.observe(ctx, run, readCommittedStage)
	if err != nil {
		return CommittedReview{}, err
	}
	if observation.decision.Status() != domain.PublicationCommitted ||
		observation.decision.Authority() != domain.PublicationAuthorityP2 {
		return CommittedReview{}, typedFailure(
			readCommittedStage,
			domain.FailureArtifact,
			"committed review is unavailable without P2 authority",
			nil,
		)
	}
	return service.readCommittedSnapshot(ctx, run, observation, readCommittedStage)
}

// ReadRuntimeTarget reconstructs target authority only from artifacts bound by a
// freshly verified P2 final. It never reads a working tree or mutable target.
func (service *Service) ReadRuntimeTarget(ctx context.Context, run ports.PublicationRun) (RuntimeTarget, error) {
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return RuntimeTarget{}, err
	}
	final, err := decodeFinalDTO(review.FinalBytes())
	if err != nil {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed final decode failed", err)
	}
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return RuntimeTarget{}, err
	}
	targetManifestPath, err := runSupportPath(run, final.Target.ManifestPath)
	if err != nil {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed target manifest path is invalid", err)
	}
	targetManifest, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, targetManifestPath)
	if err != nil {
		return RuntimeTarget{}, err
	}
	var manifest runtimeTargetManifestDTO
	if err := decodeStrictDTO(targetManifest.Bytes(), &manifest); err != nil {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target manifest decode failed", err)
	}
	if manifest.SchemaVersion != "kar-runtime-target-manifest.v1" || !validSHA256(manifest.Target.SHA256) {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target manifest is invalid", nil)
	}
	targetPath, err := ports.NewSafeRelativePath(manifest.Target.Path)
	if err != nil {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target path is invalid", err)
	}
	if index[targetPath.String()] != manifest.Target.SHA256 {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target manifest digest is not support-indexed", nil)
	}
	targetArtifact, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, targetPath)
	if err != nil {
		return RuntimeTarget{}, err
	}
	if strings.TrimPrefix(manifest.Target.SHA256, "sha256:") != strings.TrimPrefix(final.Target.ContentSHA256, "sha256:") ||
		!sameOptionalTargetOID(manifest.BaseObjectID, final.Target.BaseOID) ||
		!sameOptionalTargetOID(manifest.HeadObjectID, final.Target.HeadOID) {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target identity does not match committed final", nil)
	}
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: domain.TargetKind(manifest.TargetKind), SHA256: strings.TrimPrefix(manifest.Target.SHA256, "sha256:"),
		RepositoryID: manifest.RepositoryID, BaseObjectID: manifest.BaseObjectID, HeadObjectID: manifest.HeadObjectID,
		HeadTreeObjectID: manifest.HeadTreeObjectID, IndexTreeObjectID: manifest.IndexTreeObjectID,
		GitMode: domain.GitTargetMode(manifest.GitMode),
	})
	if err != nil {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target identity is invalid", err)
	}
	if identity.SHA256() != strings.TrimPrefix(manifest.Target.SHA256, "sha256:") {
		return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target identity digest mismatch", nil)
	}
	var capturedArchive []byte
	if manifest.CapturedArchive != nil {
		if !validSHA256(manifest.CapturedArchive.SHA256) {
			return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "captured archive identity is invalid", nil)
		}
		archivePath, pathErr := ports.NewSafeRelativePath(manifest.CapturedArchive.Path)
		if pathErr != nil || index[archivePath.String()] != manifest.CapturedArchive.SHA256 {
			return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "captured archive is not support-indexed", pathErr)
		}
		archiveArtifact, readErr := service.readIndexedRuntimeArtifact(ctx, run, review, index, archivePath)
		if readErr != nil {
			return RuntimeTarget{}, readErr
		}
		material, decodeErr := ports.UnmarshalCapturedReviewMaterial(archiveArtifact.Bytes())
		if decodeErr != nil || material.Target().Identity() != identity || !bytes.Equal(material.Target().Bytes(), targetArtifact.Bytes()) {
			return RuntimeTarget{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "captured archive target binding is invalid", decodeErr)
		}
		capturedArchive = archiveArtifact.Bytes()
	}
	return RuntimeTarget{identity: identity, bytes: targetArtifact.Bytes(), capturedArchive: capturedArchive}, nil
}

func sameOptionalTargetOID(value string, expected *string) bool {
	if value == "" {
		return expected == nil
	}
	return expected != nil && value == *expected
}

func (service *Service) readRuntimeSupportIndex(ctx context.Context, run ports.PublicationRun, review CommittedReview) (map[string]string, error) {
	manifest, err := decodeManifestDTO(review.ManifestBytes())
	if err != nil {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed manifest decode failed", err)
	}
	ref := manifest.CompositeIdentity.SupportIndex
	if ref == nil || !validSHA256(ref.SHA256) {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "manifest-bound support index is absent", nil)
	}
	path, err := ports.NewSafeRelativePath(ref.Path)
	if err != nil {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index path is invalid", err)
	}
	kind, err := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path)
	if err != nil || kind != ports.RunSupportArtifactSupportIndex {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index path is not canonical", err)
	}
	artifact, err := service.readBoundRuntimeArtifact(ctx, run, review, path, ref.SHA256)
	if err != nil {
		return nil, err
	}
	var index runtimeSupportIndexDTO
	if err := decodeStrictDTO(artifact.Bytes(), &index); err != nil {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index decode failed", err)
	}
	if index.SchemaVersion != "kar-run-support-index.v1" || len(index.Artifacts) == 0 {
		return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index is invalid", nil)
	}
	identities := make(map[string]string, len(index.Artifacts))
	for _, item := range index.Artifacts {
		path, pathErr := ports.NewSafeRelativePath(item.Path)
		if pathErr != nil || !validSHA256(item.SHA256) {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact identity is invalid", pathErr)
		}
		if _, classifyErr := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path); classifyErr != nil {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact path is invalid", classifyErr)
		}
		if _, duplicate := identities[item.Path]; duplicate {
			return nil, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "support index artifact is ambiguous", nil)
		}
		identities[item.Path] = item.SHA256
	}
	return identities, nil
}

func (service *Service) readIndexedRuntimeArtifact(ctx context.Context, run ports.PublicationRun, review CommittedReview, index map[string]string, path ports.SafeRelativePath) (ports.ImmutablePublicationArtifact, error) {
	digest, ok := index[path.String()]
	if !ok || !validSHA256(digest) {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact is absent from support index", nil)
	}
	return service.readBoundRuntimeArtifact(ctx, run, review, path, digest)
}

func (service *Service) readBoundRuntimeArtifact(ctx context.Context, run ports.PublicationRun, review CommittedReview, path ports.SafeRelativePath, digest string) (ports.ImmutablePublicationArtifact, error) {
	if !validSHA256(digest) {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact digest is absent", nil)
	}
	request, err := ports.NewReadAuxiliaryArtifactRequest(run, path, digest, service.maxReadBytes)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact request is invalid", err)
	}
	artifact, err := service.store.ReadAuxiliaryArtifact(ctx, request)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, dependencyFailure(ctx, readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact read failed", err)
	}
	if !artifact.Valid() || artifact.Path() != path || artifact.SHA256() != digest {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime artifact identity drifted", nil)
	}
	observed, err := service.ReadCommitted(context.WithoutCancel(ctx), run)
	if err != nil {
		return ports.ImmutablePublicationArtifact{}, err
	}
	if observed.Epoch() != review.Epoch() || !bytes.Equal(observed.FinalBytes(), review.FinalBytes()) || !bytes.Equal(observed.ManifestBytes(), review.ManifestBytes()) {
		return ports.ImmutablePublicationArtifact{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed source changed during runtime read", nil)
	}
	return artifact, nil
}

func runSupportPath(run ports.PublicationRun, value string) (ports.SafeRelativePath, error) {
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	if !strings.HasPrefix(value, prefix) {
		value = prefix + strings.TrimPrefix(value, "/")
	}
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		return ports.SafeRelativePath{}, err
	}
	if _, err := ports.ClassifyRunSupportArtifactPath(run.SessionID(), run.RunID(), path); err != nil {
		return ports.SafeRelativePath{}, err
	}
	return path, nil
}

// ReadCommittedAttempt reconstructs one exact-replay source attempt from P2.
// The only replay authority is the unique persisted initial prompt for that
// attempt; repair and fallback prompts are deliberately not candidates.
func (service *Service) ReadCommittedAttempt(ctx context.Context, run ports.PublicationRun, attemptID domain.AttemptID) (CommittedAttempt, error) {
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return CommittedAttempt{}, err
	}
	manifest, err := decodeManifestDTO(review.ManifestBytes())
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed manifest decode failed", err)
	}
	index, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return CommittedAttempt{}, err
	}
	var selected *manifestAttemptDTO
	for index := range manifest.Attempts {
		candidate := &manifest.Attempts[index]
		if candidate.AttemptID == attemptID.String() {
			if selected != nil {
				return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed attempt is ambiguous", nil)
			}
			selected = candidate
		}
	}
	if selected == nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed attempt is absent", nil)
	}
	role := domain.Role(selected.Role)
	if !role.Valid() {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed attempt role is invalid", nil)
	}
	target, err := service.ReadRuntimeTarget(ctx, run)
	if err != nil {
		return CommittedAttempt{}, err
	}
	final, err := decodeFinalDTO(review.FinalBytes())
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed final decode failed", err)
	}
	targetManifestPath, err := runSupportPath(run, final.Target.ManifestPath)
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target manifest path is invalid", err)
	}
	targetManifest, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, targetManifestPath)
	if err != nil {
		return CommittedAttempt{}, err
	}
	var inventory runtimeTargetManifestDTO
	if err := decodeStrictDTO(targetManifest.Bytes(), &inventory); err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime target manifest decode failed", err)
	}
	var promptSelection *selectedReplayPromptDTO
	for index := range inventory.SelectedReplayPrompts {
		candidate := &inventory.SelectedReplayPrompts[index]
		if candidate.AttemptID != attemptID.String() {
			continue
		}
		if promptSelection != nil {
			return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt is ambiguous", nil)
		}
		promptSelection = candidate
	}
	if promptSelection == nil || promptSelection.Sequence != 1 ||
		domain.InvocationPurpose(promptSelection.Purpose) != domain.InvocationInitial ||
		!validSHA256(promptSelection.Artifact.SHA256) {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt is absent or invalid", nil)
	}
	promptRef := promptSelection.Artifact
	promptInventoryMatches := 0
	for _, candidate := range inventory.Prompts {
		if candidate.Path == promptRef.Path && candidate.SHA256 == promptRef.SHA256 {
			promptInventoryMatches++
		}
	}
	if promptInventoryMatches != 1 {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt is not uniquely inventoried", nil)
	}
	expectedSuffix := fmt.Sprintf("/%03d-%s.manifest.json", promptSelection.Sequence, promptSelection.Purpose)
	expectedPrefix := run.SessionID().String() + "/" + run.RunID().String() + "/prompts/" + attemptID.String()
	if !strings.HasPrefix(promptRef.Path, expectedPrefix) || !strings.HasSuffix(promptRef.Path, expectedSuffix) {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt path does not match its binding", nil)
	}
	promptPath, err := ports.NewSafeRelativePath(promptRef.Path)
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt path is invalid", err)
	}
	if index[promptPath.String()] != promptRef.SHA256 {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected replay prompt digest is not support-indexed", nil)
	}
	promptArtifact, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, promptPath)
	if err != nil {
		return CommittedAttempt{}, err
	}
	var wire runtimePromptManifestDTO
	if err := decodeStrictDTO(promptArtifact.Bytes(), &wire); err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime prompt manifest decode failed", err)
	}
	promptRole := domain.Role(wire.Role)
	if !promptRole.Valid() || wire.SchemaVersion != "kar-runtime-prompt-manifest.v1" || promptRole != role ||
		wire.Target.Path == "" || strings.TrimPrefix(wire.Target.SHA256, "sha256:") != target.Identity().SHA256() ||
		!validSHA256(wire.Stdin.SHA256) || wire.CompleteStdinSHA256 == "" {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime prompt manifest binding is invalid", nil)
	}
	stdinPath, err := ports.NewSafeRelativePath(wire.Stdin.Path)
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime stdin path is invalid", err)
	}
	if index[stdinPath.String()] != wire.Stdin.SHA256 {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime stdin digest is not support-indexed", nil)
	}
	stdin, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, stdinPath)
	if err != nil {
		return CommittedAttempt{}, err
	}
	if prompt.CompleteStdinSHA256(stdin.Bytes()) != wire.CompleteStdinSHA256 {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "runtime complete stdin identity is invalid", nil)
	}
	return CommittedAttempt{
		sessionID: review.SessionID(), runID: review.RunID(), reviewID: review.ReviewID(), attemptID: attemptID,
		role: role, provider: selected.ProviderInstance, target: target,
		prompt: RuntimePrompt{stdin: stdin.Bytes(), stdinSHA256: wire.Stdin.SHA256,
			completeStdinSHA256: wire.CompleteStdinSHA256, manifestPath: promptPath,
			manifestSHA256: promptRef.SHA256, templateID: wire.TemplateID, templateVersion: wire.TemplateVersion,
			templateSHA256: wire.TemplateSHA256, sourceInvocationID: wire.SourceInvocationID,
			executionInvocationID: wire.ExecutionInvocationID, scope: wire.Scope, role: promptRole,
			adapterProfile: wire.AdapterProfile, adapterParameters: wire.AdapterParameters},
	}, nil
}

// ResolveCommittedAttempt selects exactly one manifest attempt by role and
// provider. It deliberately treats zero and multiple matches as artifact
// failures instead of relying on attempt order.
func (service *Service) ResolveCommittedAttempt(ctx context.Context, run ports.PublicationRun, role domain.Role, provider string) (CommittedAttempt, error) {
	if !role.Valid() || strings.TrimSpace(provider) == "" {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "attempt selector is invalid", nil)
	}
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return CommittedAttempt{}, err
	}
	manifest, err := decodeManifestDTO(review.ManifestBytes())
	if err != nil {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "committed manifest decode failed", err)
	}
	var selected domain.AttemptID
	matches := 0
	for _, candidate := range manifest.Attempts {
		if candidate.Role != string(role) || candidate.ProviderInstance != provider {
			continue
		}
		attemptID, parseErr := domain.ParseAttemptID(candidate.AttemptID)
		if parseErr != nil {
			return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "selected attempt ID is invalid", parseErr)
		}
		selected, matches = attemptID, matches+1
	}
	if matches != 1 {
		return CommittedAttempt{}, typedFailure(readRuntimeTargetStage, domain.FailureArtifact, "attempt selector does not resolve exactly one committed attempt", nil)
	}
	return service.ReadCommittedAttempt(ctx, run, selected)
}

// ReadRunStatus returns classifier-derived status for every valid observation.
// P0 and P1 never cause a final snapshot read or expose a final path. A corrupt
// durable or semantic result returns a safe corrupt status with an artifact
// failure so callers can still render the non-sensitive status projection.
func (service *Service) ReadRunStatus(ctx context.Context, run ports.PublicationRun) (RunStatus, error) {
	observation, err := service.observe(ctx, run, readStatusStage)
	if err != nil {
		return RunStatus{}, err
	}
	decision := observation.decision
	status := statusFromDecision(run, decision)
	if decision.Status() == domain.PublicationCorrupt {
		return status, typedFailure(
			readStatusStage,
			domain.FailureArtifact,
			"publication observation is corrupt",
			nil,
		)
	}
	if decision.Status() != domain.PublicationCommitted || decision.Authority() != domain.PublicationAuthorityP2 {
		return status, nil
	}

	review, err := service.readCommittedSnapshot(ctx, run, observation, readStatusStage)
	if err != nil {
		return corruptStatus(run), err
	}
	status.runState = review.RunState()
	status.hasRunState = true
	status.content = review.ContentVerdict()
	status.coverage = review.CoverageStatus()
	status.ci = review.CIDecision()
	status.hasAxes = true
	status.finalPath = review.FinalPath()
	status.hasFinalPath = true
	return status, nil
}

// ListFindings returns final-order findings at or above minimum severity. An
// empty minimum returns every committed finding, including informational ones.
func (service *Service) ListFindings(
	ctx context.Context,
	run ports.PublicationRun,
	minimum domain.Severity,
) ([]Finding, error) {
	if err := service.preflight(ctx, listFindingsStage); err != nil {
		return nil, err
	}
	if minimum != "" && !minimum.Valid() {
		return nil, typedFailure(
			listFindingsStage,
			domain.FailureConfiguration,
			"finding severity filter is invalid",
			nil,
		)
	}
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return nil, err
	}
	findings := review.Findings()
	if minimum == "" {
		return findings, nil
	}
	filtered := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity().Rank() >= minimum.Rank() {
			filtered = append(filtered, finding)
		}
	}
	return filtered, nil
}

// ReadCommittedFindingSource rereads the final and manifest, then exposes only
// normalized finding and excerpt artifacts whose exact identities are bound by
// the manifest support index for one stable P2 finding.
func (service *Service) ReadCommittedFindingSource(ctx context.Context, run ports.PublicationRun, findingID string) (CommittedFindingSource, error) {
	if err := service.preflight(ctx, renderExcerptStage); err != nil {
		return CommittedFindingSource{}, err
	}
	if !validFindingID(findingID) {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureConfiguration, "finding ID is invalid", nil)
	}
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return CommittedFindingSource{}, err
	}
	var finding Finding
	for _, candidate := range review.Findings() {
		if candidate.ID() == findingID {
			finding = candidate
			break
		}
	}
	if finding.ID() == "" {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding is not bound to the requested run", nil)
	}
	normalizedPath, err := ports.NewSafeRelativePath(fmt.Sprintf("%s/%s/excerpts/%s.json", run.SessionID().String(), run.RunID().String(), findingID))
	if err != nil {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "normalized finding artifact path is invalid", err)
	}
	supportIndex, err := service.readRuntimeSupportIndex(ctx, run, review)
	if err != nil {
		return CommittedFindingSource{}, err
	}
	normalized, err := service.readIndexedRuntimeArtifact(ctx, run, review, supportIndex, normalizedPath)
	if err != nil {
		return CommittedFindingSource{}, err
	}
	if len(normalized.Bytes()) == 0 {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "normalized finding artifact is invalid", nil)
	}
	claims := finding.Evidence()
	if len(claims) == 0 {
		return CommittedFindingSource{}, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding has no committed current evidence", nil)
	}
	var excerpt []byte
	for evidenceIndex, current := range claims {
		persisted, readErr := service.readCommittedFindingExcerpt(ctx, run, review, findingID, evidenceIndex+1, current, supportIndex)
		if readErr != nil {
			return CommittedFindingSource{}, readErr
		}
		if evidenceIndex == 0 {
			excerpt = persisted
		}
	}
	return CommittedFindingSource{review: review, finding: finding, normalized: normalized.Bytes(), excerpt: excerpt}, nil
}

func (service *Service) readCommittedFindingExcerpt(
	ctx context.Context,
	run ports.PublicationRun,
	review CommittedReview,
	findingID string,
	evidenceIndex int,
	current Evidence,
	index map[string]string,
) ([]byte, error) {
	if current.TargetSHA256() != review.TargetSHA256() || current.Verification() != evidence.ReceiptVerified {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "finding current evidence is not bound to the committed target", nil)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: current.TargetSHA256(),
		Side:         current.Side(),
		Path:         current.Path().String(),
		LineStart:    current.LineStart(),
		LineEnd:      current.LineEnd(),
		Quote:        current.quote,
	})
	if err != nil {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "committed current evidence is invalid", err)
	}
	path, err := excerptArtifactPath(run, findingID, evidenceIndex)
	if err != nil {
		return nil, typedFailure(renderExcerptStage, domain.FailureArtifact, "committed excerpt artifact path is invalid", err)
	}
	artifact, err := service.readIndexedRuntimeArtifact(ctx, run, review, index, path)
	if err != nil {
		return nil, err
	}
	return service.verifyPersistedExcerpt(ctx, claim, current.CurrentExcerptSHA256(), path, artifact)
}

// RenderExcerpt returns the first canonical committed evidence excerpt. Callers
// rendering multiple items must use RenderExcerptAt with its one-based index.
func (service *Service) RenderExcerpt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
) ([]byte, error) {
	return service.RenderExcerptAt(ctx, run, findingID, targetSHA256, 1)
}

// RenderExcerptAt returns one canonical committed evidence excerpt by its
// one-based canonical index.
func (service *Service) RenderExcerptAt(
	ctx context.Context,
	run ports.PublicationRun,
	findingID string,
	targetSHA256 string,
	evidenceIndex int,
) ([]byte, error) {
	if err := service.preflight(ctx, renderExcerptStage); err != nil {
		return nil, err
	}
	if !validFindingID(findingID) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"finding ID is invalid",
			nil,
		)
	}
	if evidenceIndex < 1 || evidenceIndex > 20 {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"evidence index is invalid",
			nil,
		)
	}
	canonicalTarget, ok := canonicalSHA256(targetSHA256)
	if !ok {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"target SHA-256 is invalid",
			nil,
		)
	}
	review, err := service.ReadCommitted(ctx, run)
	if err != nil {
		return nil, err
	}
	var finding Finding
	found := false
	for _, candidate := range review.Findings() {
		if candidate.ID() == findingID {
			finding = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"finding is not bound to the requested run",
			nil,
		)
	}
	if canonicalTarget != review.TargetSHA256() {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"target SHA-256 does not match the committed finding",
			nil,
		)
	}
	claims := finding.Evidence()
	if evidenceIndex > len(claims) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureConfiguration,
			"evidence index is not bound to the committed finding",
			nil,
		)
	}
	current := claims[evidenceIndex-1]
	if current.TargetSHA256() != canonicalTarget || current.Verification() != evidence.ReceiptVerified {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"finding current evidence is not bound to the committed target",
			nil,
		)
	}
	claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
		TargetSHA256: current.TargetSHA256(),
		Side:         current.Side(),
		Path:         current.Path().String(),
		LineStart:    current.LineStart(),
		LineEnd:      current.LineEnd(),
		Quote:        current.quote,
	})
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed current evidence is invalid",
			err,
		)
	}
	if err := contextFailure(ctx, renderExcerptStage); err != nil {
		return nil, err
	}
	artifactPath, err := excerptArtifactPath(run, findingID, evidenceIndex)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact path is invalid",
			err,
		)
	}
	request, err := ports.NewReadAuxiliaryArtifactRequest(run, artifactPath, "", service.maxReadBytes)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact request is invalid",
			err,
		)
	}
	artifact, err := service.store.ReadAuxiliaryArtifact(ctx, request)
	if err != nil {
		return nil, dependencyFailure(
			ctx,
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact read failed",
			err,
		)
	}
	return service.verifyPersistedExcerpt(ctx, claim, current.CurrentExcerptSHA256(), artifactPath, artifact)
}

func (service *Service) verifyPersistedExcerpt(
	ctx context.Context,
	claim evidence.CurrentClaim,
	currentExcerptSHA256 string,
	expectedPath ports.SafeRelativePath,
	artifact ports.ImmutablePublicationArtifact,
) ([]byte, error) {
	if !artifact.Valid() {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact is invalid",
			nil,
		)
	}
	if artifact.Path() != expectedPath {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact path does not match the finding",
			nil,
		)
	}
	artifactBytes := artifact.Bytes()
	targetBytes, err := syntheticExcerptLayout(claim.LineStart(), artifactBytes, service.maxReadBytes)
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact cannot satisfy the committed range",
			err,
		)
	}
	verifier, err := evidence.NewVerifier(persistedExcerptReader{
		targetSHA256: claim.TargetSHA256(),
		side:         claim.Side(),
		path:         claim.Path(),
		bytes:        targetBytes,
	})
	if err != nil {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt verifier is unavailable",
			err,
		)
	}
	receipt, err := verifier.VerifyCurrent(ctx, claim)
	if err != nil {
		return nil, dependencyFailure(
			ctx,
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact verification failed",
			err,
		)
	}
	if receipt.Status() != evidence.ReceiptVerified {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact does not match the finding",
			nil,
		)
	}
	verifiedExcerpt := receipt.Excerpt()
	if !bytes.Equal(verifiedExcerpt, artifactBytes) {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact bytes do not match the finding",
			nil,
		)
	}
	if receipt.ExcerptSHA256() != currentExcerptSHA256 {
		return nil, typedFailure(
			renderExcerptStage,
			domain.FailureArtifact,
			"committed excerpt artifact does not match the current excerpt identity",
			nil,
		)
	}
	return verifiedExcerpt, nil
}

func excerptArtifactPath(
	run ports.PublicationRun,
	findingID string,
	evidenceIndex int,
) (ports.SafeRelativePath, error) {
	return ports.NewSafeRelativePath(
		fmt.Sprintf(
			"%s/%s/excerpts/%s_%d.md",
			run.SessionID().String(),
			run.RunID().String(),
			findingID,
			evidenceIndex,
		),
	)
}

func syntheticExcerptLayout(lineStart int, excerpt []byte, maxReadBytes int64) ([]byte, error) {
	if lineStart <= 0 {
		return nil, fmt.Errorf("line start is invalid")
	}
	prefixLength := lineStart - 1
	excerptLength := int64(len(excerpt))
	if excerptLength > maxReadBytes || int64(prefixLength) > maxReadBytes-excerptLength {
		return nil, fmt.Errorf("synthetic excerpt layout exceeds read cap")
	}
	maxInt := int(^uint(0) >> 1)
	if prefixLength > maxInt-len(excerpt) {
		return nil, fmt.Errorf("synthetic excerpt layout overflows")
	}
	target := make([]byte, prefixLength+len(excerpt))
	for index := 0; index < prefixLength; index++ {
		target[index] = '\n'
	}
	copy(target[prefixLength:], excerpt)
	return target, nil
}

type persistedExcerptReader struct {
	targetSHA256 string
	side         evidence.Side
	path         ports.SafeRelativePath
	bytes        []byte
}

func (reader persistedExcerptReader) ReadImmutableTarget(
	_ context.Context,
	targetSHA256 string,
	side evidence.Side,
	path ports.SafeRelativePath,
) (evidence.ImmutableTargetAvailability, []byte, error) {
	if targetSHA256 != reader.targetSHA256 || side != reader.side || path != reader.path {
		return evidence.ImmutableTargetUnavailable, nil, nil
	}
	return evidence.ImmutableTargetAvailable, cloneBytes(reader.bytes), nil
}

func (service *Service) observe(
	ctx context.Context,
	run ports.PublicationRun,
	stage string,
) (observedRun, error) {
	if missingDependency(service) || missingDependency(service.store) {
		return observedRun{}, typedFailure(stage, domain.FailureArtifact, "publication store is unavailable", nil)
	}
	if err := contextFailure(ctx, stage); err != nil {
		return observedRun{}, err
	}
	if !run.Valid() {
		return observedRun{}, typedFailure(stage, domain.FailureConfiguration, "publication run is invalid", nil)
	}
	request, err := ports.NewObserveRunRequest(run, service.maxReadBytes)
	if err != nil {
		return observedRun{}, typedFailure(stage, domain.FailureConfiguration, "publication observation request is invalid", err)
	}
	observation, err := service.store.ObserveRun(ctx, request)
	if err != nil {
		return observedRun{}, dependencyFailure(
			ctx,
			stage,
			domain.FailureArtifact,
			"publication observation failed",
			err,
		)
	}
	if !observation.Valid() {
		return observedRun{}, typedFailure(stage, domain.FailureArtifact, "publication observation is invalid", nil)
	}
	decision, err := domain.ClassifyPublication(observation.ClassifierInput())
	if err != nil || !decision.Valid() {
		return observedRun{}, typedFailure(stage, domain.FailureArtifact, "publication classification failed", err)
	}
	result := observedRun{decision: decision, storeEpoch: observation.StoreEpoch()}
	if decision.Authority() == domain.PublicationAuthorityP2 {
		material, present := observation.RecoveryMaterial()
		if !present {
			return observedRun{}, typedFailure(stage, domain.FailureArtifact, "P2 observation omitted immutable identities", nil)
		}
		snapshot, present := material.CommittedSnapshot()
		if !present || !snapshot.Valid() || snapshot.Epoch().Value() != observation.StoreEpoch() {
			return observedRun{}, typedFailure(stage, domain.FailureArtifact, "P2 observation immutable identities are invalid", nil)
		}
		result.snapshot = snapshot
	}
	return result, nil
}

func (service *Service) readCommittedSnapshot(
	ctx context.Context,
	run ports.PublicationRun,
	observation observedRun,
	stage string,
) (CommittedReview, error) {
	if missingDependency(service) || missingDependency(service.store) || missingDependency(service.validator) {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "committed read dependency is unavailable", nil)
	}
	if err := contextFailure(ctx, stage); err != nil {
		return CommittedReview{}, err
	}
	if observation.decision.Status() != domain.PublicationCommitted ||
		observation.decision.Authority() != domain.PublicationAuthorityP2 {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "committed snapshot was requested without P2 authority", nil)
	}
	request, err := ports.NewReadCommittedSnapshotRequest(run, service.maxReadBytes)
	if err != nil {
		return CommittedReview{}, typedFailure(stage, domain.FailureConfiguration, "committed snapshot request is invalid", err)
	}
	snapshot, err := service.store.ReadCommittedSnapshot(ctx, request)
	if err != nil {
		return CommittedReview{}, dependencyFailure(
			ctx,
			stage,
			domain.FailureArtifact,
			"committed snapshot read failed",
			err,
		)
	}
	if !snapshot.Valid() {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "committed snapshot is invalid", nil)
	}
	final := snapshot.Final()
	manifest := snapshot.Manifest()
	if !final.Valid() || !manifest.Valid() || !snapshot.LineageEdge().Valid() || !snapshot.Epoch().Valid() {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "committed snapshot members are invalid", nil)
	}
	if !sameCommittedSnapshot(observation.snapshot, snapshot) {
		return CommittedReview{}, typedFailure(
			stage,
			domain.FailureArtifact,
			"committed snapshot identities do not match the observed P2 authority",
			nil,
		)
	}
	if observation.storeEpoch != snapshot.Epoch().Value() {
		return CommittedReview{}, typedFailure(
			stage,
			domain.FailureArtifact,
			"committed snapshot epoch does not match the observed P2 authority",
			nil,
		)
	}
	finalBytes := final.Bytes()
	manifestBytes := manifest.Bytes()
	if err := service.validator.Validate(ctx, finalReviewSchemaAsset, cloneBytes(finalBytes)); err != nil {
		return CommittedReview{}, dependencyFailure(
			ctx,
			stage,
			domain.FailureArtifact,
			"final review schema validation failed",
			err,
		)
	}
	if err := service.validator.Validate(ctx, runManifestSchemaAsset, cloneBytes(manifestBytes)); err != nil {
		return CommittedReview{}, dependencyFailure(
			ctx,
			stage,
			domain.FailureArtifact,
			"run manifest schema validation failed",
			err,
		)
	}
	finalRecord, err := decodeFinalDTO(finalBytes)
	if err != nil {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "final review strict JSON decoding failed", err)
	}
	manifestRecord, err := decodeManifestDTO(manifestBytes)
	if err != nil {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "run manifest strict JSON decoding failed", err)
	}
	review, err := buildCommittedReview(run, observation.decision, snapshot, finalRecord, manifestRecord)
	if err != nil {
		return CommittedReview{}, typedFailure(stage, domain.FailureArtifact, "committed publication semantic validation failed", err)
	}
	confirmation, err := service.observe(ctx, run, stage)
	if err != nil {
		return CommittedReview{}, err
	}
	if confirmation.decision.Status() != domain.PublicationCommitted ||
		confirmation.decision.Authority() != domain.PublicationAuthorityP2 ||
		!samePublicationDecision(confirmation.decision, observation.decision) ||
		confirmation.storeEpoch != observation.storeEpoch ||
		!sameCommittedSnapshot(confirmation.snapshot, observation.snapshot) {
		return CommittedReview{}, typedFailure(
			stage,
			domain.FailureArtifact,
			"committed snapshot is not stable under P2 re-observation",
			nil,
		)
	}
	return review, nil
}

func buildCommittedReview(
	run ports.PublicationRun,
	decision domain.PublicationDecision,
	snapshot ports.CommittedPublicationSnapshot,
	final finalDTO,
	manifest manifestDTO,
) (CommittedReview, error) {
	if decision.Status() != domain.PublicationCommitted || decision.Authority() != domain.PublicationAuthorityP2 {
		return CommittedReview{}, fmt.Errorf("snapshot was read without P2 authority")
	}
	finalArtifact := snapshot.Final()
	finalIdentity := finalArtifact.Identity()
	manifestArtifact := snapshot.Manifest()
	lineageArtifact := snapshot.LineageEdge()
	epoch := snapshot.Epoch()
	expectedFinalPath := run.SessionID().String() + "/" + run.RunID().String() + "/review_" + finalIdentity.ReviewID().String() + ".json"
	if finalIdentity.Path().String() != expectedFinalPath {
		return CommittedReview{}, fmt.Errorf("final path is not canonical")
	}
	expectedManifestPath := run.SessionID().String() + "/" + run.RunID().String() + "/manifest.json"
	if manifestArtifact.Path().String() != expectedManifestPath {
		return CommittedReview{}, fmt.Errorf("manifest path is not canonical")
	}

	if final.SchemaVersion != "kar-review-artifact.v3" || manifest.SchemaVersion != "kar-run-manifest.v2" {
		return CommittedReview{}, fmt.Errorf("schema version does not match committed contract")
	}
	sessionID, err := domain.ParseSessionID(final.SessionID)
	if err != nil || sessionID != run.SessionID() {
		return CommittedReview{}, fmt.Errorf("final session identity does not match run")
	}
	runID, err := domain.ParseRunID(final.RunID)
	if err != nil || runID != run.RunID() {
		return CommittedReview{}, fmt.Errorf("final run identity does not match run")
	}
	reviewID, err := domain.ParseReviewID(final.ReviewID)
	if err != nil || reviewID != finalIdentity.ReviewID() {
		return CommittedReview{}, fmt.Errorf("final review identity does not match artifact")
	}
	if !domain.RunType(final.RunType).Valid() || final.RunType != manifest.RunType {
		return CommittedReview{}, fmt.Errorf("run type binding is invalid")
	}
	if err := validateProductionProvenance(final); err != nil {
		return CommittedReview{}, err
	}
	if final.Validation.Status != "valid" && final.Validation.Status != "repaired_valid" ||
		final.Validation.SchemaValidation != "passed" ||
		final.Validation.SemanticValidation != "passed" ||
		(final.Validation.EvidenceValidation != "passed" && final.Validation.EvidenceValidation != "passed_with_warnings") {
		return CommittedReview{}, fmt.Errorf("final validation summary is invalid")
	}
	if !validSHA256(final.Target.ContentSHA256) || !validSHA256(manifest.Target.ContentSHA256) ||
		final.Target.ContentSHA256 != manifest.Target.ContentSHA256 || final.Target.ManifestPath != manifest.Target.ManifestPath {
		return CommittedReview{}, fmt.Errorf("target binding is invalid")
	}
	if _, err := ports.NewSafeRelativePath(final.Target.ManifestPath); err != nil {
		return CommittedReview{}, fmt.Errorf("target manifest path is invalid")
	}
	if !matchesArtifactPath(final.ImmutableLineage.LineageEdgePath, lineageArtifact.Path(), run) ||
		final.ImmutableLineage.LineageEdgeSHA != lineageArtifact.SHA256() {
		return CommittedReview{}, fmt.Errorf("final lineage edge binding is invalid")
	}
	if !sameLineage(final.ImmutableLineage, manifest.ImmutableLineage) ||
		!matchesArtifactPath(manifest.ImmutableLineage.LineageEdgePath, lineageArtifact.Path(), run) ||
		manifest.ImmutableLineage.LineageEdgeSHA != lineageArtifact.SHA256() {
		return CommittedReview{}, fmt.Errorf("manifest lineage edge binding is invalid")
	}
	if err := validateFollowupOutcome(final, manifest); err != nil {
		return CommittedReview{}, err
	}
	if !domain.RunState(manifest.State).Valid() ||
		(domain.RunState(manifest.State) != domain.RunCompleted && domain.RunState(manifest.State) != domain.RunDegraded && domain.RunState(manifest.State) != domain.RunFailed) ||
		!manifest.Sealed {
		return CommittedReview{}, fmt.Errorf("committed run state is invalid")
	}
	if manifest.SessionID != final.SessionID || manifest.RunID != final.RunID {
		return CommittedReview{}, fmt.Errorf("manifest identity does not match final")
	}
	if manifest.FinalReview == nil || manifest.FinalReview.ReviewID != reviewID.String() ||
		!matchesArtifactPath(manifest.FinalReview.Path, finalIdentity.Path(), run) ||
		manifest.FinalReview.SHA256 != finalIdentity.SHA256() {
		return CommittedReview{}, fmt.Errorf("manifest final identity does not match final artifact")
	}
	if manifest.RecoveryJournal.ExpectedFinal == nil ||
		!matchesArtifactPath(manifest.RecoveryJournal.ExpectedFinal.Path, finalIdentity.Path(), run) ||
		manifest.RecoveryJournal.ExpectedFinal.SHA256 != finalIdentity.SHA256() ||
		manifest.RecoveryJournal.ValidatedCandidateSHA256 == nil ||
		!validSHA256(*manifest.RecoveryJournal.ValidatedCandidateSHA256) {
		return CommittedReview{}, fmt.Errorf("manifest recovery final identity is invalid")
	}
	issued, err := ports.NewIssuedReviewID(reviewID, *manifest.RecoveryJournal.ValidatedCandidateSHA256)
	if err != nil {
		return CommittedReview{}, fmt.Errorf("manifest issuance candidate binding is invalid")
	}
	binding, err := ports.NewIssuedFinalBinding(issued, finalIdentity)
	if err != nil ||
		binding.ValidatedCandidateSHA256() != *manifest.RecoveryJournal.ValidatedCandidateSHA256 ||
		binding.Final() != finalIdentity {
		return CommittedReview{}, fmt.Errorf("manifest issuance-to-final binding is invalid")
	}
	if manifest.CompositeIdentity.Manifest == nil || manifest.CompositeIdentity.LineageEdge == nil || manifest.CompositeIdentity.Epoch == nil ||
		!matchesArtifactPath(manifest.CompositeIdentity.Manifest.Path, manifestArtifact.Path(), run) ||
		!matchesArtifactPath(manifest.CompositeIdentity.LineageEdge.Path, lineageArtifact.Path(), run) ||
		manifest.CompositeIdentity.LineageEdge.SHA256 != lineageArtifact.SHA256() ||
		!matchesArtifactPath(manifest.CompositeIdentity.Epoch.Path, epoch.Record().Path(), run) {
		return CommittedReview{}, fmt.Errorf("manifest composite identity is invalid")
	}
	if manifest.DurableObservationClass != string(domain.DurableObservationP2Committed) ||
		manifest.DerivedPublicationStatus != string(domain.PublicationCommitted) ||
		manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) ||
		manifest.RecoveryAction != string(domain.RecoveryActionReconstructCompletedStatus) {
		return CommittedReview{}, fmt.Errorf("manifest publication authority is invalid")
	}
	content := domain.ContentVerdict(final.ContentVerdict)
	coverage := domain.CoverageStatus(final.CoverageStatus)
	publication := domain.PublicationStatus(final.PublicationStatus)
	ci := domain.CIDecision(final.CIDecision)
	if !content.Valid() || !coverage.Valid() || publication != domain.PublicationCommitted || !ci.Valid() ||
		manifest.ContentVerdict != final.ContentVerdict || manifest.CoverageStatus != final.CoverageStatus ||
		manifest.PublicationStatus != final.PublicationStatus || manifest.CIDecision != final.CIDecision {
		return CommittedReview{}, fmt.Errorf("independent outcome axes are invalid")
	}
	roles, expectedRoleFindingIDs, err := buildRolesForRun(final.RoleOutcomes, domain.RunType(final.RunType), final.ImmutableLineage.ReplayMode)
	if err != nil {
		return CommittedReview{}, err
	}
	findings, err := buildFindings(
		final.Findings,
		sessionID,
		runID,
		reviewID,
		final.Target.ContentSHA256,
		domain.RunType(final.RunType),
		final.ImmutableLineage,
		expectedRoleFindingIDs,
		roles,
	)
	if err != nil {
		return CommittedReview{}, err
	}
	followupOutcome, err := buildFollowupOutcome(final.FollowupOutcome, sessionID)
	if err != nil {
		return CommittedReview{}, err
	}
	if !sameRoles(manifest.SelectedRoles, roles, false) || !sameRoles(manifest.RequiredRoles, roles, true) {
		return CommittedReview{}, fmt.Errorf("manifest role binding is invalid")
	}
	if err := validateManifestRoleAttemptBindings(manifest.Attempts, roles); err != nil {
		return CommittedReview{}, err
	}
	if err := validateManifestFailures(manifest.Failures, manifest.Attempts, roles); err != nil {
		return CommittedReview{}, err
	}
	if !consistentCommittedRunState(domain.RunState(manifest.State), roles, coverage) {
		return CommittedReview{}, fmt.Errorf("committed run state does not match role outcomes")
	}
	if err := validateOutcomeProjection(final, manifest, roles, findings, content, coverage, ci, decision); err != nil {
		return CommittedReview{}, err
	}
	lineage, err := buildCommittedLineage(domain.RunType(final.RunType), runID, final.ImmutableLineage)
	if err != nil {
		return CommittedReview{}, err
	}
	return CommittedReview{
		sessionID: sessionID, runID: runID, reviewID: reviewID, runState: domain.RunState(manifest.State),
		finalPath: finalIdentity.Path(), finalSHA256: finalIdentity.SHA256(),
		manifestPath: manifestArtifact.Path(), manifestSHA256: manifestArtifact.SHA256(),
		lineageEdgePath: lineageArtifact.Path(), lineageEdgeSHA: lineageArtifact.SHA256(),
		epoch: epoch.Value(), epochPath: epoch.Record().Path(), targetSHA256: final.Target.ContentSHA256,
		content: content, coverage: coverage, publication: publication, ci: ci,
		followupOutcome: followupOutcome,
		lineage:         lineage,
		roles:           cloneRoles(roles), findings: cloneFindings(findings),
		finalBytes: finalArtifact.Bytes(), manifestBytes: manifestArtifact.Bytes(),
	}, nil
}

func validateProductionProvenance(final finalDTO) error {
	production := final.Provenance.Production
	if production == nil {
		return nil
	}
	if final.RunType != string(domain.RunTypeReview) ||
		final.Target.ContentSHA256 == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return fmt.Errorf("production provenance is only valid for changed root reviews")
	}
	if production.BuildProduct != "kar" || !validBoundedText(production.BuildVersion, 128) ||
		!validBoundedText(production.BuildCommit, 128) || production.BuildVersion != final.KAR.Version ||
		final.KAR.Commit == nil || production.BuildCommit != *final.KAR.Commit {
		return fmt.Errorf("production provenance build metadata does not match final KAR metadata")
	}
	if (production.ObjectivePresent && (production.ObjectiveSHA256 == nil || !validSHA256(*production.ObjectiveSHA256))) ||
		(!production.ObjectivePresent && production.ObjectiveSHA256 != nil) ||
		!validSHA256(production.SnapshotManifestSHA256) ||
		!validReceiptID(production.WorkspaceTerminalReceipt) || len(production.Providers) == 0 {
		return fmt.Errorf("production provenance root identity is invalid")
	}
	for index, provider := range production.Providers {
		if !validProductionProvider(provider) {
			return fmt.Errorf("production provider %d is invalid", index)
		}
		key := provider.Family + "\x00" + provider.Instance
		if index > 0 && key <= production.Providers[index-1].Family+"\x00"+production.Providers[index-1].Instance {
			return fmt.Errorf("production providers are not in canonical order")
		}
	}
	return nil
}

func validProductionProvider(provider productionProviderDTO) bool {
	if !validBoundedText(provider.Family, 64) || !validProviderInstance(provider.Instance) ||
		!validBoundedText(provider.Version, 128) || !validBoundedText(provider.Executable, 1024) ||
		!validSHA256(provider.ExecutableSHA256) || !validBoundedText(provider.ProfileGeneration, 256) ||
		!validBoundedText(provider.AdapterProfile, 256) || !validReceiptID(provider.NamespaceTerminalReceipt) ||
		!validOrderedReceiptIDs(provider.QualificationReceiptIDs) ||
		!validOrderedReceiptIDs(provider.PacketTransportReceiptIDs) {
		return false
	}
	return (provider.Launcher == "" && provider.LauncherSHA256 == "") ||
		(validBoundedText(provider.Launcher, 1024) && validSHA256(provider.LauncherSHA256))
}

func validBoundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) != ""
}

func validProviderInstance(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validOrderedReceiptIDs(receipts []string) bool {
	if len(receipts) == 0 {
		return false
	}
	for index, receipt := range receipts {
		if !validReceiptID(receipt) || index > 0 && receipts[index-1] >= receipt {
			return false
		}
	}
	return true
}

func validReceiptID(value string) bool {
	if len(value) <= 65 {
		return false
	}
	prefix, digest := value[:len(value)-64], value[len(value)-64:]
	for _, character := range prefix {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == ':' || character == '-') {
			return false
		}
	}
	if !strings.HasSuffix(prefix, ":") {
		return false
	}
	for _, character := range digest {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
func buildCommittedLineage(runType domain.RunType, runID domain.RunID, value lineageDTO) (CommittedLineage, error) {
	if runType == domain.RunTypeReview {
		if value.ParentRunID != nil || value.SourceRunID != nil || value.SourceReviewID != nil ||
			value.SourceFindingRef != nil || value.ReplayMode != nil {
			return CommittedLineage{}, fmt.Errorf("root review lineage is not empty")
		}
		return CommittedLineage{}, nil
	}
	if value.ParentRunID == nil || value.SourceRunID == nil || value.SourceReviewID == nil {
		return CommittedLineage{}, fmt.Errorf("%s lineage is missing required source identities", runType)
	}
	parentRunID, err := domain.ParseRunID(*value.ParentRunID)
	if err != nil || parentRunID == runID {
		return CommittedLineage{}, fmt.Errorf("parent run lineage identity is invalid")
	}
	sourceRunID, err := domain.ParseRunID(*value.SourceRunID)
	if err != nil || sourceRunID == runID {
		return CommittedLineage{}, fmt.Errorf("source run lineage identity is invalid")
	}
	sourceReviewID, err := domain.ParseReviewID(*value.SourceReviewID)
	if err != nil {
		return CommittedLineage{}, fmt.Errorf("source review lineage identity is invalid")
	}
	result := CommittedLineage{
		parentRunID: &parentRunID, sourceRunID: &sourceRunID, sourceReviewID: &sourceReviewID,
	}
	if value.SourceFindingRef != nil {
		if !validFindingID(*value.SourceFindingRef) {
			return CommittedLineage{}, fmt.Errorf("source finding lineage reference is invalid")
		}
		sourceFindingRef := *value.SourceFindingRef
		result.sourceFindingRef = &sourceFindingRef
	}
	if value.ReplayMode != nil {
		replayMode := ReplayMode(*value.ReplayMode)
		if replayMode != ReplayModeExact && replayMode != ReplayModeRecompose {
			return CommittedLineage{}, fmt.Errorf("replay mode lineage value is invalid")
		}
		result.replayMode = &replayMode
	}
	switch runType {
	case domain.RunTypeFollowup:
		if result.sourceFindingRef == nil || result.replayMode != nil {
			return CommittedLineage{}, fmt.Errorf("followup lineage optional fields are invalid")
		}
	case domain.RunTypeDelta:
		if result.sourceFindingRef != nil || result.replayMode != nil {
			return CommittedLineage{}, fmt.Errorf("delta lineage optional fields are invalid")
		}
	case domain.RunTypeRerun:
		if result.sourceFindingRef != nil || result.replayMode == nil {
			return CommittedLineage{}, fmt.Errorf("rerun lineage optional fields are invalid")
		}
	default:
		return CommittedLineage{}, fmt.Errorf("lineage run type is invalid")
	}
	return result, nil
}
func validateFollowupOutcome(final finalDTO, manifest manifestDTO) error {
	if final.RunType != string(domain.RunTypeFollowup) {
		if final.FollowupOutcome != nil || manifest.FollowupOutcome != nil {
			return fmt.Errorf("non-followup publication has followup outcome")
		}
		return nil
	}
	if final.FollowupOutcome == nil || manifest.FollowupOutcome == nil ||
		!reflect.DeepEqual(final.FollowupOutcome, manifest.FollowupOutcome) {
		return fmt.Errorf("followup outcome is missing or differs between final and manifest")
	}
	outcome := final.FollowupOutcome
	if !domain.FollowupResolution(outcome.Resolution).Valid() || strings.TrimSpace(outcome.Rationale) == "" ||
		len(outcome.Rationale) > 12000 || len(outcome.Evidence) == 0 || len(outcome.Evidence) > 20 {
		return fmt.Errorf("followup outcome is invalid")
	}
	lineage := final.ImmutableLineage
	if lineage.SourceRunID == nil || lineage.SourceReviewID == nil || lineage.SourceFindingRef == nil {
		return fmt.Errorf("followup source lineage is absent")
	}
	for index, item := range outcome.Evidence {
		if item.Source.SessionID != final.SessionID || item.Source.RunID != *lineage.SourceRunID ||
			item.Source.ReviewID != *lineage.SourceReviewID || item.Source.FindingID != *lineage.SourceFindingRef ||
			!validSHA256(item.Source.SourceTargetSHA256) || !validSHA256(item.Source.SourceExcerptSHA256) ||
			!validSHA256(item.Current.CurrentExcerptSHA256) ||
			item.Current.TargetSHA256 != final.Target.ContentSHA256 || item.Current.Verification != "verified" ||
			item.Current.LineStart < 1 || item.Current.LineEnd < item.Current.LineStart ||
			strings.TrimSpace(item.Current.Path) == "" || strings.TrimSpace(item.Current.Quote) == "" {
			return fmt.Errorf("followup outcome evidence %d is invalid", index)
		}
	}
	if outcome.Resolution == string(domain.FollowupStillOpen) && len(final.Findings) == 0 &&
		(final.ContentVerdict != string(domain.ContentRequestChanges) || final.CoverageStatus != string(domain.CoverageComplete) ||
			final.CIDecision != string(domain.CIFail)) {
		return fmt.Errorf("still-open followup without new findings has unsafe outcome axes")
	}
	return nil
}
func buildFollowupOutcome(value *followupOutcomeDTO, sessionID domain.SessionID) (*FollowupOutcome, error) {
	if value == nil {
		return nil, nil
	}
	evidenceViews := make([]FollowupEvidence, len(value.Evidence))
	for index, item := range value.Evidence {
		sourceSessionID, err := domain.ParseSessionID(item.Source.SessionID)
		if err != nil || sourceSessionID != sessionID {
			return nil, fmt.Errorf("followup outcome evidence %d source session is invalid", index)
		}
		sourceRunID, err := domain.ParseRunID(item.Source.RunID)
		if err != nil {
			return nil, fmt.Errorf("followup outcome evidence %d source run is invalid", index)
		}
		sourceReviewID, err := domain.ParseReviewID(item.Source.ReviewID)
		if err != nil {
			return nil, fmt.Errorf("followup outcome evidence %d source review is invalid", index)
		}
		path, err := ports.NewSafeRelativePath(item.Current.Path)
		if err != nil {
			return nil, fmt.Errorf("followup outcome evidence %d path is invalid", index)
		}
		claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
			TargetSHA256: item.Current.TargetSHA256,
			Side:         evidence.Side(item.Current.Side),
			Path:         item.Current.Path,
			LineStart:    item.Current.LineStart,
			LineEnd:      item.Current.LineEnd,
			Quote:        item.Current.Quote,
		})
		if err != nil {
			return nil, fmt.Errorf("followup outcome evidence %d current claim is invalid", index)
		}
		currentExcerptSHA256, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
		if err != nil || currentExcerptSHA256 != item.Current.CurrentExcerptSHA256 {
			return nil, fmt.Errorf("followup outcome evidence %d current excerpt identity is invalid", index)
		}
		evidenceViews[index] = FollowupEvidence{
			sourceSessionID: sourceSessionID, sourceRunID: sourceRunID, sourceReviewID: sourceReviewID,
			sourceFindingID: item.Source.FindingID, sourceTargetSHA256: item.Source.SourceTargetSHA256,
			sourceExcerptSHA256: item.Source.SourceExcerptSHA256, currentExcerptSHA256: item.Current.CurrentExcerptSHA256,
			targetSHA256: claim.TargetSHA256(), side: claim.Side(), path: path, lineStart: claim.LineStart(),
			lineEnd: claim.LineEnd(), quote: claim.Quote(), verification: evidence.ReceiptVerified,
		}
	}
	return &FollowupOutcome{
		resolution: domain.FollowupResolution(value.Resolution),
		rationale:  value.Rationale,
		evidence:   evidenceViews,
	}, nil
}
func buildRoles(values []finalRoleDTO) ([]Role, map[domain.Role][]string, error) {
	return buildRolesForRun(values, domain.RunTypeReview, nil)
}

func buildRolesForRun(values []finalRoleDTO, _ domain.RunType, _ *string) ([]Role, map[domain.Role][]string, error) {
	if len(values) == 0 {
		return nil, nil, fmt.Errorf("final has no role outcomes")
	}
	roles := make([]Role, len(values))
	findingIDs := make(map[domain.Role][]string, len(values))
	seen := make(map[domain.Role]struct{}, len(values))
	previous := -1
	for index, value := range values {
		role := domain.Role(value.Role)
		ordinal := roleOrdinal(role)
		if !role.Valid() || ordinal <= previous {
			return nil, nil, fmt.Errorf("final role order is invalid")
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, nil, fmt.Errorf("final role is duplicated")
		}
		seen[role] = struct{}{}
		previous = ordinal
		if (role == domain.RoleLogic || role == domain.RoleSecurity) && !value.Required {
			return nil, nil, fmt.Errorf("required role floor is missing")
		}
		switch value.Outcome {
		case "completed", "degraded", "failed", "skipped":
		default:
			return nil, nil, fmt.Errorf("final role outcome is invalid")
		}
		ids := append([]string(nil), value.ValidFindingIDs...)
		seenIDs := make(map[string]struct{}, len(ids))
		for _, findingID := range ids {
			if !validFindingID(findingID) {
				return nil, nil, fmt.Errorf("role finding reference is invalid")
			}
			if _, duplicate := seenIDs[findingID]; duplicate {
				return nil, nil, fmt.Errorf("role finding reference is duplicated")
			}
			seenIDs[findingID] = struct{}{}
		}
		attemptID := ""
		providerInstance := ""
		selectedVia := ""
		if value.Outcome == "skipped" {
			if value.AttemptID != nil || value.ProviderInstance != nil || value.SelectedVia != nil {
				return nil, nil, fmt.Errorf("skipped role has an attempt binding")
			}
			if len(ids) != 0 {
				return nil, nil, fmt.Errorf("skipped role has findings")
			}
			if value.FailureReason != nil && *value.FailureReason == "" {
				return nil, nil, fmt.Errorf("skipped role failure reason is invalid")
			}
		} else {
			if value.AttemptID == nil || value.ProviderInstance == nil || value.SelectedVia == nil ||
				*value.ProviderInstance == "" || (*value.SelectedVia != "primary" && *value.SelectedVia != "fallback") {
				return nil, nil, fmt.Errorf("final role attempt binding is invalid")
			}
			if _, err := domain.ParseAttemptID(*value.AttemptID); err != nil {
				return nil, nil, fmt.Errorf("final role attempt identity is invalid")
			}
			attemptID = *value.AttemptID
			providerInstance = *value.ProviderInstance
			selectedVia = *value.SelectedVia
			if value.Outcome == "failed" {
				if value.FailureReason == nil || *value.FailureReason == "" {
					return nil, nil, fmt.Errorf("failed role is missing a failure reason")
				}
				if len(ids) != 0 {
					return nil, nil, fmt.Errorf("failed role has findings")
				}
			} else if value.FailureReason != nil {
				return nil, nil, fmt.Errorf("successful role has a failure reason")
			}
		}
		findingIDs[role] = ids
		roles[index] = Role{
			role: role, required: value.Required, outcome: value.Outcome, attemptID: attemptID,
			providerInstance: providerInstance, selectedVia: selectedVia,
			findingIDs: ids, limitations: append([]string(nil), value.Limitations...),
		}
		if value.FailureReason != nil {
			roles[index].failureReason = *value.FailureReason
		}
	}
	return roles, findingIDs, nil
}

func validateManifestRoleAttemptBindings(attempts []manifestAttemptDTO, roles []Role) error {
	roleIndexes := make(map[domain.Role]int, len(roles))
	for index, role := range roles {
		roleIndexes[role.Name()] = index
	}
	attemptsByRole := make(map[domain.Role][]manifestAttemptDTO, len(roles))
	seenAttemptIDs := make(map[string]struct{}, len(attempts))
	previousRoleIndex := -1
	for _, attempt := range attempts {
		role := domain.Role(attempt.Role)
		state := domain.AttemptState(attempt.State)
		if _, err := domain.ParseAttemptID(attempt.AttemptID); err != nil ||
			!role.Valid() ||
			strings.TrimSpace(attempt.ProviderInstance) == "" ||
			!terminalManifestAttemptState(state) ||
			state == domain.AttemptCancelled ||
			!domain.ParseState(attempt.ParseState).Valid() ||
			!domain.ValidationState(attempt.ValidationState).Valid() ||
			attempt.Path != "attempts/"+attempt.AttemptID+"/status.json" ||
			attempt.InvocationCount < 1 {
			return fmt.Errorf("manifest attempt is invalid")
		}
		roleIndex, selected := roleIndexes[role]
		if !selected || roleIndex < previousRoleIndex {
			return fmt.Errorf("manifest attempts are not in selected fixed-role order")
		}
		if _, duplicate := seenAttemptIDs[attempt.AttemptID]; duplicate {
			return fmt.Errorf("manifest attempt identity is duplicated")
		}
		roleAttempts := attemptsByRole[role]
		switch len(roleAttempts) {
		case 0:
			if attempt.SelectedAs != "primary" {
				return fmt.Errorf("role attempt sequence must begin with primary")
			}
		case 1:
			if attempt.SelectedAs != "fallback" {
				return fmt.Errorf("role fallback attempt is invalid")
			}
			if roleAttempts[0].State == string(domain.AttemptSucceeded) {
				return fmt.Errorf("role has an attempt after successful primary")
			}
			if roleAttempts[0].ProviderInstance == attempt.ProviderInstance {
				return fmt.Errorf("role fallback provider duplicates primary")
			}
		default:
			return fmt.Errorf("role has more than primary and fallback attempts")
		}
		seenAttemptIDs[attempt.AttemptID] = struct{}{}
		attemptsByRole[role] = append(roleAttempts, attempt)
		previousRoleIndex = roleIndex
	}
	for _, role := range roles {
		roleAttempts := attemptsByRole[role.Name()]
		if role.Outcome() == "skipped" {
			if len(roleAttempts) != 0 {
				return fmt.Errorf("skipped role has a selected manifest attempt")
			}
			continue
		}
		if len(roleAttempts) == 0 {
			return fmt.Errorf("non-skipped role has no manifest attempt")
		}
		selected := roleAttempts[len(roleAttempts)-1]
		attemptID, present := role.AttemptID()
		provider, providerPresent := role.ProviderInstance()
		selectedVia, selectionPresent := role.SelectedVia()
		if !present || !providerPresent || !selectionPresent ||
			selected.AttemptID != attemptID.String() ||
			selected.ProviderInstance != provider ||
			selected.SelectedAs != selectedVia {
			return fmt.Errorf("role does not bind to the deterministic terminal manifest attempt")
		}
		if (role.Outcome() == "completed" || role.Outcome() == "degraded") &&
			selected.State != string(domain.AttemptSucceeded) {
			return fmt.Errorf("successful role has a non-successful manifest attempt")
		}
		if (role.Outcome() == "completed" || role.Outcome() == "degraded") &&
			(selected.ParseState != string(domain.ParseValid) ||
				(selected.ValidationState != string(domain.ValidationValid) &&
					selected.ValidationState != string(domain.ValidationRepairedValid))) {
			return fmt.Errorf("successful role has an invalid manifest attempt result")
		}
		if role.Outcome() == "failed" && selected.State == string(domain.AttemptSucceeded) {
			return fmt.Errorf("failed role has a successful deterministic terminal attempt")
		}
	}
	return nil
}

func validateManifestFailures(
	failures []manifestFailureDTO,
	attempts []manifestAttemptDTO,
	roles []Role,
) error {
	terminalFailures := make(map[string]domain.AttemptState, len(attempts))
	failedAttemptIDs := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		state := domain.AttemptState(attempt.State)
		if state == domain.AttemptSucceeded {
			continue
		}
		if state == domain.AttemptCancelled {
			return fmt.Errorf("committed manifest contains a cancelled attempt")
		}
		terminalFailures[attempt.AttemptID] = state
		failedAttemptIDs = append(failedAttemptIDs, attempt.AttemptID)
	}

	failedRoleReasons := make(map[string]string, len(roles))
	for _, role := range roles {
		if role.Outcome() != "failed" {
			continue
		}
		attemptID, attemptPresent := role.AttemptID()
		reason, reasonPresent := role.FailureReason()
		if !attemptPresent || !reasonPresent {
			return fmt.Errorf("failed role has no terminal failure binding")
		}
		failedRoleReasons[attemptID.String()] = reason
	}

	if len(failures) != len(terminalFailures) {
		return fmt.Errorf("manifest failure count does not match failed terminal attempts")
	}
	seen := make(map[string]struct{}, len(failures))
	for index, failure := range failures {
		class := domain.FailureClass(failure.Class)
		if failure.AttemptID == nil || failure.Stage != "review" ||
			!publishableQueryFailureClass(class) || failure.ReasonCode == "" {
			return fmt.Errorf("manifest failure is invalid or non-publishable")
		}
		if *failure.AttemptID != failedAttemptIDs[index] {
			return fmt.Errorf("manifest failures are not in canonical failed-attempt order")
		}
		state, present := terminalFailures[*failure.AttemptID]
		if !present {
			return fmt.Errorf("manifest failure does not bind a failed terminal attempt")
		}
		if _, duplicate := seen[*failure.AttemptID]; duplicate {
			return fmt.Errorf("manifest failure duplicates a failed terminal attempt")
		}
		if state == domain.AttemptTimedOut && class != domain.FailureTimeout {
			return fmt.Errorf("timed out manifest attempt has a non-timeout failure fact")
		}
		if state != domain.AttemptTimedOut && class == domain.FailureTimeout {
			return fmt.Errorf("non-timeout manifest attempt has a timeout failure fact")
		}
		if reason, selected := failedRoleReasons[*failure.AttemptID]; selected && failure.ReasonCode != reason {
			return fmt.Errorf("manifest failure reason does not match failed role")
		}
		seen[*failure.AttemptID] = struct{}{}
	}
	return nil
}

func publishableQueryFailureClass(class domain.FailureClass) bool {
	if !class.Valid() {
		return false
	}
	switch class {
	case domain.FailureSecurityPolicy,
		domain.FailureConfiguration,
		domain.FailureArtifact,
		domain.FailureInternal,
		domain.FailureCancelled:
		return false
	default:
		return true
	}
}

func terminalManifestAttemptState(state domain.AttemptState) bool {
	switch state {
	case domain.AttemptSucceeded,
		domain.AttemptFailed,
		domain.AttemptTimedOut,
		domain.AttemptCancelled,
		domain.AttemptBlocked:
		return true
	default:
		return false
	}
}

func buildFindings(
	values []finalFindingDTO,
	sessionID domain.SessionID,
	runID domain.RunID,
	reviewID domain.ReviewID,
	targetSHA256 string,
	runType domain.RunType,
	lineage lineageDTO,
	expectedRoleFindingIDs map[domain.Role][]string,
	roles []Role,
) ([]Finding, error) {
	findings := make([]Finding, len(values))
	actualRoleFindingIDs := make(map[domain.Role][]string, len(expectedRoleFindingIDs))
	roleOutcomes := make(map[domain.Role]Role, len(roles))
	for _, role := range roles {
		roleOutcomes[role.Name()] = role
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if value.ID != expectedID || !validFindingID(value.ID) {
			return nil, fmt.Errorf("final finding order is invalid")
		}
		if _, duplicate := seen[value.ID]; duplicate {
			return nil, fmt.Errorf("final finding identity is duplicated")
		}
		seen[value.ID] = struct{}{}
		role := domain.Role(value.Role)
		severity := domain.Severity(value.Severity)
		confidence := domain.Confidence(value.Confidence)
		lifecycle := domain.FindingLifecycle(value.Lifecycle)
		if _, selected := expectedRoleFindingIDs[role]; !selected {
			return nil, fmt.Errorf("finding role has no committed role outcome")
		}
		roleOutcome, present := roleOutcomes[role]
		if !present ||
			(roleOutcome.Outcome() != "completed" && roleOutcome.Outcome() != "degraded") {
			return nil, fmt.Errorf("finding role has no successful producing attempt")
		}
		providerInstance, available := roleOutcome.ProviderInstance()
		if !available || providerInstance != value.ProviderInstance {
			return nil, fmt.Errorf("finding provider does not match role outcome")
		}
		if _, available := roleOutcome.AttemptID(); !available {
			return nil, fmt.Errorf("finding role has no producing attempt")
		}
		if !role.Valid() || !severity.Valid() || !confidence.Valid() || !lifecycle.Valid() ||
			!validSHA256(value.Fingerprint) || value.ProviderInstance == "" || value.Title == "" ||
			value.Description == "" || value.Recommendation == "" {
			return nil, fmt.Errorf("final finding fields are invalid")
		}
		evidenceViews := make([]Evidence, len(value.Evidence))
		for evidenceIndex, item := range value.Evidence {
			sourceSessionID, err := domain.ParseSessionID(item.Source.SessionID)
			expectedSourceRunID, expectedSourceReviewID, expectedSourceFindingID := runID, reviewID, value.ID
			if runType == domain.RunTypeFollowup {
				if lineage.SourceRunID == nil || lineage.SourceReviewID == nil || lineage.SourceFindingRef == nil {
					return nil, fmt.Errorf("followup source lineage is absent")
				}
				expectedSourceRunID, err = domain.ParseRunID(*lineage.SourceRunID)
				if err != nil {
					return nil, fmt.Errorf("followup source run lineage is invalid")
				}
				expectedSourceReviewID, err = domain.ParseReviewID(*lineage.SourceReviewID)
				if err != nil {
					return nil, fmt.Errorf("followup source review lineage is invalid")
				}
				expectedSourceFindingID = *lineage.SourceFindingRef
			}
			if err != nil || sourceSessionID != sessionID {
				return nil, fmt.Errorf("source evidence session binding is invalid")
			}
			sourceRunID, err := domain.ParseRunID(item.Source.RunID)
			if err != nil || sourceRunID != expectedSourceRunID {
				return nil, fmt.Errorf("source evidence run binding is invalid")
			}
			sourceReviewID, err := domain.ParseReviewID(item.Source.ReviewID)
			if err != nil || sourceReviewID != expectedSourceReviewID || item.Source.FindingID != expectedSourceFindingID ||
				!validSHA256(item.Source.SourceTargetSHA256) ||
				!validSHA256(item.Source.SourceExcerptSHA256) ||
				!validSHA256(item.Current.CurrentExcerptSHA256) ||
				(runType != domain.RunTypeFollowup && item.Source.SourceTargetSHA256 != targetSHA256) {
				return nil, fmt.Errorf("source evidence finding binding is invalid")
			}
			if item.Current.Verification != string(evidence.ReceiptVerified) || item.Current.TargetSHA256 != targetSHA256 {
				return nil, fmt.Errorf("current evidence binding is invalid")
			}
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
				TargetSHA256: item.Current.TargetSHA256,
				Side:         evidence.Side(item.Current.Side),
				Path:         item.Current.Path,
				LineStart:    item.Current.LineStart,
				LineEnd:      item.Current.LineEnd,
				Quote:        item.Current.Quote,
			})
			if err != nil {
				return nil, fmt.Errorf("current evidence claim is invalid")
			}
			currentExcerptSHA256, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
			if err != nil || currentExcerptSHA256 != item.Current.CurrentExcerptSHA256 {
				return nil, fmt.Errorf("current evidence excerpt identity is invalid")
			}
			evidenceViews[evidenceIndex] = Evidence{
				sourceSessionID: sourceSessionID, sourceRunID: sourceRunID, sourceReviewID: sourceReviewID,
				sourceFindingID: item.Source.FindingID, sourceTargetSHA256: item.Source.SourceTargetSHA256,
				sourceExcerptSHA256: item.Source.SourceExcerptSHA256, currentExcerptSHA256: item.Current.CurrentExcerptSHA256,
				targetSHA256: claim.TargetSHA256(), side: claim.Side(), path: claim.Path(), lineStart: claim.LineStart(),
				lineEnd: claim.LineEnd(), quote: claim.Quote(), verification: evidence.ReceiptVerified,
			}
		}
		orderedEvidence, err := canonicalEvidenceItems(evidenceViews)
		if err != nil {
			return nil, fmt.Errorf("final finding evidence identity is invalid: %w", err)
		}
		actualRoleFindingIDs[role] = append(actualRoleFindingIDs[role], value.ID)
		findings[index] = Finding{
			id: value.ID, fingerprint: value.Fingerprint, role: role, providerInstance: value.ProviderInstance,
			severity: severity, title: value.Title, description: value.Description,
			recommendation: value.Recommendation, confidence: confidence, lifecycle: lifecycle,
			evidence: orderedEvidence,
		}
	}
	for role, expected := range expectedRoleFindingIDs {
		actual := actualRoleFindingIDs[role]
		if len(actual) != len(expected) {
			return nil, fmt.Errorf("role finding binding is incomplete")
		}
		for index := range expected {
			if actual[index] != expected[index] {
				return nil, fmt.Errorf("role finding binding order is invalid")
			}
		}
	}
	return findings, nil
}
func canonicalEvidenceItems(items []Evidence) ([]Evidence, error) {
	if len(items) == 0 || len(items) > 20 {
		return nil, fmt.Errorf("evidence count must be between 1 and 20")
	}
	ordered := append([]Evidence(nil), items...)
	sort.Slice(ordered, func(left, right int) bool {
		return canonicalEvidenceKey(ordered[left]) < canonicalEvidenceKey(ordered[right])
	})
	for index := range items {
		if canonicalEvidenceKey(items[index]) != canonicalEvidenceKey(ordered[index]) {
			return nil, fmt.Errorf("evidence order is not canonical")
		}
	}
	for index := 1; index < len(ordered); index++ {
		if canonicalEvidenceKey(ordered[index-1]) == canonicalEvidenceKey(ordered[index]) {
			return nil, fmt.Errorf("evidence tuple is duplicated")
		}
	}
	return ordered, nil
}

func canonicalEvidenceKey(item Evidence) string {
	fields := []string{
		item.SourceSessionID().String(),
		item.SourceRunID().String(),
		item.SourceReviewID().String(),
		item.SourceFindingID(),
		item.SourceTargetSHA256(),
		item.SourceExcerptSHA256(),
		item.CurrentExcerptSHA256(),
		item.TargetSHA256(),
		string(item.Side()),
		item.Path().String(),
		strconv.Itoa(item.LineStart()),
		strconv.Itoa(item.LineEnd()),
		string(item.Verification()),
	}
	var key strings.Builder
	for _, field := range fields {
		key.WriteString(strconv.Itoa(len(field)))
		key.WriteByte(':')
		key.WriteString(field)
		key.WriteByte('|')
	}
	return key.String()
}

func validateOutcomeProjection(
	final finalDTO,
	manifest manifestDTO,
	roles []Role,
	findings []Finding,
	content domain.ContentVerdict,
	coverage domain.CoverageStatus,
	ci domain.CIDecision,
	decision domain.PublicationDecision,
) error {
	threshold := domain.Severity(final.SeverityThreshold.RequestChangesAtOrAbove)
	if !threshold.Valid() || final.SeverityThreshold.PolicySource != "project_local" {
		return fmt.Errorf("severity threshold is invalid")
	}
	expectedContent := domain.ContentNoFindings
	if len(findings) > 0 {
		expectedContent = domain.ContentFindingsPresent
		for _, finding := range findings {
			if finding.Severity().Rank() >= threshold.Rank() {
				expectedContent = domain.ContentRequestChanges
			}
		}
	}
	if final.FollowupOutcome != nil &&
		final.FollowupOutcome.Resolution == string(domain.FollowupStillOpen) &&
		len(findings) == 0 {
		expectedContent = domain.ContentRequestChanges
	}
	if content != expectedContent {
		return fmt.Errorf("content axis does not match findings")
	}
	expectedCoverage := domain.CoverageComplete
	for _, role := range roles {
		switch role.Outcome() {
		case "failed", "skipped":
			if role.Required() {
				expectedCoverage = domain.CoverageIncomplete
			} else if expectedCoverage == domain.CoverageComplete {
				expectedCoverage = domain.CoverageDegraded
			}
		case "degraded":
			if expectedCoverage == domain.CoverageComplete {
				expectedCoverage = domain.CoverageDegraded
			}
		}
	}
	if coverage != expectedCoverage {
		return fmt.Errorf("coverage axis does not match role outcomes")
	}
	expectedCI := domain.CIPass
	if expectedContent == domain.ContentRequestChanges || expectedCoverage == domain.CoverageDegraded || expectedCoverage == domain.CoverageIncomplete {
		expectedCI = domain.CIFail
	}
	if ci != expectedCI {
		return fmt.Errorf("CI axis does not match trusted projection")
	}
	expectedReasons := make([]string, 0, 2)
	if expectedContent == domain.ContentRequestChanges {
		expectedReasons = append(expectedReasons, "request_changes_threshold")
	}
	if expectedCoverage == domain.CoverageIncomplete {
		expectedReasons = append(expectedReasons, "required_role_incomplete")
	} else if expectedCoverage == domain.CoverageDegraded {
		expectedReasons = append(expectedReasons, "degraded_coverage")
	}
	if len(expectedReasons) == 0 {
		expectedReasons = append(expectedReasons, "policy_evaluated")
	}
	if !sameStrings(final.CIReasonCodes, expectedReasons) || !sameStrings(manifest.CIReasonCodes, expectedReasons) {
		return fmt.Errorf("CI reason codes do not match trusted projection")
	}
	expectedExit := domain.ExitCommittedPass
	if expectedCoverage == domain.CoverageIncomplete {
		expectedExit = domain.ExitIncompleteCoverage
	} else if expectedCI == domain.CIFail {
		expectedExit = domain.ExitCommittedCIRejected
	}
	storedExit, ok := decision.ExitCode()
	if !ok || storedExit != expectedExit || manifest.ExitCode != int(expectedExit) {
		return fmt.Errorf("committed exit projection is invalid")
	}
	return nil
}

func sameRoles(values []string, roles []Role, requiredOnly bool) bool {
	expected := make([]string, 0, len(roles))
	for _, role := range roles {
		if !requiredOnly || role.Required() {
			expected = append(expected, string(role.Name()))
		}
	}
	return sameStrings(values, expected)
}
func consistentCommittedRunState(state domain.RunState, roles []Role, coverage domain.CoverageStatus) bool {
	failedAny := false
	failedRequired := false
	for _, role := range roles {
		if role.Outcome() == "failed" || role.Outcome() == "skipped" {
			failedAny = true
			failedRequired = failedRequired || role.Required()
		}
	}
	switch state {
	case domain.RunCompleted:
		return !failedAny
	case domain.RunDegraded:
		return failedAny && !failedRequired
	case domain.RunFailed:
		return failedRequired && coverage == domain.CoverageIncomplete
	default:
		return false
	}
}
func matchesArtifactPath(reference string, actual ports.SafeRelativePath, run ports.PublicationRun) bool {
	if _, err := ports.NewSafeRelativePath(reference); err != nil {
		return false
	}
	if reference == actual.String() {
		return true
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/"
	return strings.HasPrefix(actual.String(), prefix) && reference == strings.TrimPrefix(actual.String(), prefix)
}

func sameLineage(first, second lineageDTO) bool {
	return sameOptionalString(first.ParentRunID, second.ParentRunID) &&
		sameOptionalString(first.SourceRunID, second.SourceRunID) &&
		sameOptionalString(first.SourceReviewID, second.SourceReviewID) &&
		sameOptionalString(first.SourceFindingRef, second.SourceFindingRef) &&
		sameOptionalString(first.ReplayMode, second.ReplayMode) &&
		first.LineageEdgePath == second.LineageEdgePath && first.LineageEdgeSHA == second.LineageEdgeSHA
}

func sameOptionalString(first, second *string) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func sameStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func roleOrdinal(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if role == candidate {
			return index
		}
	}
	return -1
}

func statusFromDecision(run ports.PublicationRun, decision domain.PublicationDecision) RunStatus {
	return RunStatus{
		sessionID: run.SessionID(), runID: run.RunID(), publication: decision.Status(),
		authority: decision.Authority(), action: decision.Action(),
	}
}

func corruptStatus(run ports.PublicationRun) RunStatus {
	return RunStatus{
		sessionID: run.SessionID(), runID: run.RunID(), publication: domain.PublicationCorrupt,
		authority: domain.PublicationAuthorityNone, action: domain.RecoveryActionEmitImmutableCorruptionDiagnostic,
	}
}
func (service *Service) preflight(ctx context.Context, stage string) error {
	if missingDependency(service) || missingDependency(service.store) || missingDependency(service.validator) {
		return typedFailure(stage, domain.FailureArtifact, "query dependencies are unavailable", nil)
	}
	return contextFailure(ctx, stage)
}

func dependencyFailure(
	ctx context.Context,
	stage string,
	fallback domain.FailureClass,
	reason string,
	cause error,
) error {
	class := reduceDependencyFailureClass(ctx, cause, fallback)
	if ctx != nil && ctx.Err() != nil {
		cause = errors.Join(cause, ctx.Err())
	}
	return typedFailure(stage, class, reason, cause)
}

func reduceDependencyFailureClass(
	ctx context.Context,
	cause error,
	fallback domain.FailureClass,
) domain.FailureClass {
	classes := make([]domain.FailureClass, 0, 4)
	var visit func(error, bool)
	visit = func(current error, classifiedByAncestor bool) {
		if current == nil {
			return
		}
		classified := false
		if failure, ok := current.(*domain.Failure); ok && failure.Class().Valid() {
			classes = append(classes, failure.Class())
			classified = true
		}
		if carrier, ok := current.(interface {
			PublicationFailureClass() domain.FailureClass
		}); ok && carrier.PublicationFailureClass().Valid() {
			classes = append(classes, carrier.PublicationFailureClass())
			classified = true
		}

		hasChildren := false
		switch unwrapped := current.(type) {
		case interface{ Unwrap() []error }:
			hasChildren = true
			for _, nested := range unwrapped.Unwrap() {
				visit(nested, classifiedByAncestor || classified)
			}
		case interface{ Unwrap() error }:
			if nested := unwrapped.Unwrap(); nested != nil {
				hasChildren = true
				visit(nested, classifiedByAncestor || classified)
			}
		}
		if hasChildren {
			return
		}
		if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
			classes = append(classes, domain.FailureCancelled)
			return
		}
		if !classified && !classifiedByAncestor {
			classes = append(classes, fallback)
		}
	}
	visit(cause, false)
	if ctx != nil && ctx.Err() != nil {
		classes = append(classes, domain.FailureCancelled)
	}
	if len(classes) == 0 {
		classes = append(classes, fallback)
	}
	selected := fallback
	selectedRank := -1
	for _, class := range classes {
		if rank := coreapp.FailurePrecedence(class); rank > selectedRank {
			selected = class
			selectedRank = rank
		}
	}
	return selected
}

func samePublicationDecision(first, second domain.PublicationDecision) bool {
	if first.Status() != second.Status() ||
		first.Authority() != second.Authority() ||
		first.Action() != second.Action() {
		return false
	}
	firstExit, firstHasExit := first.ExitCode()
	secondExit, secondHasExit := second.ExitCode()
	if firstHasExit != secondHasExit || (firstHasExit && firstExit != secondExit) {
		return false
	}
	return sameStrings(first.Reasons(), second.Reasons())
}

func sameCommittedSnapshot(left, right ports.CommittedPublicationSnapshot) bool {
	if !left.Valid() || !right.Valid() ||
		left.Final().Identity() != right.Final().Identity() ||
		left.Manifest().Path() != right.Manifest().Path() ||
		left.Manifest().SHA256() != right.Manifest().SHA256() ||
		left.LineageEdge().Path() != right.LineageEdge().Path() ||
		left.LineageEdge().SHA256() != right.LineageEdge().SHA256() ||
		left.Epoch().Value() != right.Epoch().Value() ||
		left.Epoch().Record().Path() != right.Epoch().Record().Path() ||
		left.Epoch().Record().SHA256() != right.Epoch().Record().SHA256() {
		return false
	}
	return bytes.Equal(left.Final().Bytes(), right.Final().Bytes()) &&
		bytes.Equal(left.Manifest().Bytes(), right.Manifest().Bytes()) &&
		bytes.Equal(left.LineageEdge().Bytes(), right.LineageEdge().Bytes()) &&
		bytes.Equal(left.Epoch().Record().Bytes(), right.Epoch().Record().Bytes())
}
func contextFailure(ctx context.Context, stage string) error {
	if ctx == nil {
		return typedFailure(stage, domain.FailureConfiguration, "query context is nil", nil)
	}
	if err := ctx.Err(); err != nil {
		return typedFailure(stage, domain.FailureCancelled, "query request was cancelled", err)
	}
	return nil
}

func typedFailure(stage string, class domain.FailureClass, reason string, cause error) error {
	failure, err := domain.NewFailure(stage, class, reason, cause)
	if err != nil {
		return err
	}
	return failure
}

func missingDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func requiredSchemaAsset(value string) ports.AssetID {
	asset, err := ports.ParseAssetID(value)
	if err != nil {
		panic(err)
	}
	return asset
}

func validFindingID(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' &&
			character != '-' {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	_, ok := canonicalSHA256(value)
	return ok && strings.HasPrefix(value, "sha256:")
}

func canonicalSHA256(value string) (string, bool) {
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != 64 {
		return "", false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return "", false
		}
	}
	return "sha256:" + value, true
}
