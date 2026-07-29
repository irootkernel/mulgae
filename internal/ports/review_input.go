package ports

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

type ReviewTargetSelectorKind string

const (
	ReviewTargetWorkspace ReviewTargetSelectorKind = "workspace"
	ReviewTargetStage     ReviewTargetSelectorKind = "stage"
	ReviewTargetDirty     ReviewTargetSelectorKind = "dirty"
	ReviewTargetDiff      ReviewTargetSelectorKind = "diff"
	ReviewTargetPatch     ReviewTargetSelectorKind = "patch"
	ReviewTargetStdin     ReviewTargetSelectorKind = "stdin"
)

type ReviewTargetSelector struct {
	kind  ReviewTargetSelectorKind
	value string
}

func NewReviewTargetSelector(kind ReviewTargetSelectorKind, value string) (ReviewTargetSelector, error) {
	if strings.TrimSpace(value) == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return ReviewTargetSelector{}, fmt.Errorf("review target selector: invalid value")
	}
	switch kind {
	case ReviewTargetWorkspace, ReviewTargetStage, ReviewTargetDirty, ReviewTargetDiff, ReviewTargetPatch, ReviewTargetStdin:
	default:
		return ReviewTargetSelector{}, fmt.Errorf("review target selector: invalid kind")
	}
	return ReviewTargetSelector{kind: kind, value: value}, nil
}
func (selector ReviewTargetSelector) Kind() ReviewTargetSelectorKind { return selector.kind }
func (selector ReviewTargetSelector) Value() string                  { return selector.value }
func (selector ReviewTargetSelector) Valid() bool {
	_, err := NewReviewTargetSelector(selector.kind, selector.value)
	return err == nil
}

type ReviewInputChannel string

const (
	ReviewInputTarget    ReviewInputChannel = "review_target"
	ReviewInputReference ReviewInputChannel = "reference_snapshot"
	ReviewInputObjective ReviewInputChannel = "objective"
	ReviewInputPacket    ReviewInputChannel = "provider_packet"
)

func (channel ReviewInputChannel) Valid() bool {
	switch channel {
	case ReviewInputTarget, ReviewInputReference, ReviewInputObjective, ReviewInputPacket:
		return true
	default:
		return false
	}
}

type ReviewInputVerdict string

const (
	ReviewInputClean   ReviewInputVerdict = "clean"
	ReviewInputBlocked ReviewInputVerdict = "blocked"
)

type ReviewInputDetection struct {
	verdict      ReviewInputVerdict
	detectorCode string
	count        int
}

func NewReviewInputDetection(verdict ReviewInputVerdict, detectorCode string, count int) (ReviewInputDetection, error) {
	switch verdict {
	case ReviewInputClean:
		if detectorCode != "" || count != 0 {
			return ReviewInputDetection{}, fmt.Errorf("review input detection: clean result carries findings")
		}
	case ReviewInputBlocked:
		if detectorCode == "" || count < 1 || len(detectorCode) > 128 || strings.ContainsAny(detectorCode, "\x00\r\n") {
			return ReviewInputDetection{}, fmt.Errorf("review input detection: invalid blocked result")
		}
	default:
		return ReviewInputDetection{}, fmt.Errorf("review input detection: invalid verdict")
	}
	return ReviewInputDetection{verdict: verdict, detectorCode: detectorCode, count: count}, nil
}
func (detection ReviewInputDetection) Verdict() ReviewInputVerdict { return detection.verdict }
func (detection ReviewInputDetection) DetectorCode() string        { return detection.detectorCode }
func (detection ReviewInputDetection) Count() int                  { return detection.count }
func (detection ReviewInputDetection) Valid() bool {
	_, err := NewReviewInputDetection(detection.verdict, detection.detectorCode, detection.count)
	return err == nil
}

type ReviewInputContentDetector interface {
	DetectReviewInput(context.Context, ReviewInputChannel, string, []byte) (ReviewInputDetection, error)
}

// ReviewInputContentDetectorIdentity identifies the fixed detector policy that
// admitted captured review bytes. Production capture rejects detectors that do
// not provide this immutable identity.
type ReviewInputContentDetectorIdentity interface {
	ReviewInputDetectorIdentity() string
}

type CapturedStdinStore interface {
	TakeCapturedStdin(context.Context, string) ([]byte, error)
}

const ReviewTargetMaxBytes = 180000

// CapturedReviewTarget is an immutable review input with an identity bound to
// its exact captured bytes. Git targets additionally retain resolved Git facts.
type CapturedReviewTarget struct {
	kind         domain.TargetKind
	identity     domain.TargetIdentity
	bytes        []byte
	repository   string
	base         GitObjectID
	head         GitObjectID
	headTree     GitObjectID
	indexTree    GitObjectID
	hasIndexTree bool
	gitMode      domain.GitTargetMode
}

// NewCapturedReviewGitTarget captures a Git target using the exact canonical
// diff bytes. Empty diffs are valid and represent a no-change Git review.
func NewCapturedReviewGitTarget(repositoryID string, baseObjectID, headObjectID, headTreeID GitObjectID, indexTreeID *GitObjectID, bytes []byte) (CapturedReviewTarget, error) {
	return NewCapturedReviewGitTargetWithMode(domain.GitTargetDiff, repositoryID, baseObjectID, headObjectID, headTreeID, indexTreeID, bytes)
}

func NewCapturedReviewGitTargetWithMode(mode domain.GitTargetMode, repositoryID string, baseObjectID, headObjectID, headTreeID GitObjectID, indexTreeID *GitObjectID, bytes []byte) (CapturedReviewTarget, error) {
	if err := validateCapturedReviewBytes(bytes, true); err != nil {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: %w", err)
	}
	if err := validateRedactedText(repositoryID, 4096); err != nil || repositoryID == "" {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: repository ID must be non-empty and safe")
	}
	if !baseObjectID.Valid() || !headObjectID.Valid() || !headTreeID.Valid() {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: base, head, and head tree object IDs are required")
	}
	if indexTreeID != nil && !indexTreeID.Valid() {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: invalid index tree object ID")
	}
	identityInput := domain.TargetIdentityInput{
		Kind: domain.TargetGit, SHA256: strings.TrimPrefix(sha256Identifier(bytes), "sha256:"),
		RepositoryID: repositoryID, BaseObjectID: baseObjectID.String(), HeadObjectID: headObjectID.String(), HeadTreeObjectID: headTreeID.String(),
		GitMode: mode,
	}
	if indexTreeID != nil {
		identityInput.IndexTreeObjectID = indexTreeID.String()
	}
	identity, err := domain.NewTargetIdentity(identityInput)
	if err != nil {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: %w", err)
	}
	target := CapturedReviewTarget{kind: domain.TargetGit, identity: identity, bytes: cloneBytes(bytes), repository: repositoryID, base: baseObjectID, head: headObjectID, headTree: headTreeID, gitMode: mode}
	if indexTreeID != nil {
		target.indexTree = *indexTreeID
		target.hasIndexTree = true
	}
	return target, nil
}

// NewCapturedReviewPatchTarget captures a non-empty patch input.
func NewCapturedReviewPatchTarget(bytes []byte) (CapturedReviewTarget, error) {
	return newCapturedReviewTarget(domain.TargetPatch, bytes)
}

// NewCapturedReviewStdinTarget captures a non-empty stdin input.
func NewCapturedReviewStdinTarget(bytes []byte) (CapturedReviewTarget, error) {
	return newCapturedReviewTarget(domain.TargetStdin, bytes)
}

// NewCapturedReviewWorkspaceTarget binds a workspace descriptor to its exact
// immutable snapshot identity. Source files are carried by the accompanying
// WorkspaceSnapshotRequest rather than duplicated into the prompt payload.
func NewCapturedReviewWorkspaceTarget(bytes []byte) (CapturedReviewTarget, error) {
	return newCapturedReviewTarget(domain.TargetWorkspace, bytes)
}

// NewCapturedReviewTargetFromIdentity reconstructs a trusted immutable target
// from P2-bound bytes and their complete persisted identity.
func NewCapturedReviewTargetFromIdentity(identity domain.TargetIdentity, bytes []byte) (CapturedReviewTarget, error) {
	if identity.Kind() == "" {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: persisted identity is required")
	}
	var target CapturedReviewTarget
	var err error
	switch identity.Kind() {
	case domain.TargetWorkspace:
		target, err = NewCapturedReviewWorkspaceTarget(bytes)
	case domain.TargetPatch:
		target, err = NewCapturedReviewPatchTarget(bytes)
	case domain.TargetStdin:
		target, err = NewCapturedReviewStdinTarget(bytes)
	case domain.TargetGit:
		base, baseErr := ParseGitObjectID(identity.BaseObjectID())
		head, headErr := ParseGitObjectID(identity.HeadObjectID())
		tree, treeErr := ParseGitObjectID(identity.HeadTreeObjectID())
		if baseErr != nil || headErr != nil || treeErr != nil {
			return CapturedReviewTarget{}, fmt.Errorf("captured review target: persisted Git identity is invalid")
		}
		var index *GitObjectID
		if value := identity.IndexTreeObjectID(); value != "" {
			parsed, parseErr := ParseGitObjectID(value)
			if parseErr != nil {
				return CapturedReviewTarget{}, fmt.Errorf("captured review target: persisted index identity is invalid")
			}
			index = &parsed
		}
		target, err = NewCapturedReviewGitTargetWithMode(identity.GitMode(), identity.RepositoryID(), base, head, tree, index, bytes)
	default:
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: persisted kind is invalid")
	}
	if err != nil {
		return CapturedReviewTarget{}, err
	}
	if target.Identity() != identity {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: persisted identity does not match bytes")
	}
	return target, nil
}

func newCapturedReviewTarget(kind domain.TargetKind, bytes []byte) (CapturedReviewTarget, error) {
	if err := validateCapturedReviewBytes(bytes, false); err != nil {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: %w", err)
	}
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: kind, SHA256: strings.TrimPrefix(sha256Identifier(bytes), "sha256:")})
	if err != nil {
		return CapturedReviewTarget{}, fmt.Errorf("captured review target: %w", err)
	}
	return CapturedReviewTarget{kind: kind, identity: identity, bytes: cloneBytes(bytes)}, nil
}

func validateCapturedReviewBytes(bytes []byte, allowEmpty bool) error {
	if !allowEmpty && len(bytes) == 0 {
		return fmt.Errorf("bytes must be non-empty")
	}
	if len(bytes) > ReviewTargetMaxBytes {
		return fmt.Errorf("bytes exceed %d-byte limit", ReviewTargetMaxBytes)
	}
	if !utf8.Valid(bytes) {
		return fmt.Errorf("bytes must be valid UTF-8")
	}
	if containsNUL(bytes) {
		return fmt.Errorf("bytes must not contain NUL")
	}
	return nil
}

func containsNUL(bytes []byte) bool {
	for _, value := range bytes {
		if value == 0 {
			return true
		}
	}
	return false
}

// Bytes returns a caller-owned copy of the exact captured input bytes.
func (target CapturedReviewTarget) Bytes() []byte { return cloneBytes(target.bytes) }

// Identity returns the immutable domain identity derived from the exact bytes.
func (target CapturedReviewTarget) Identity() domain.TargetIdentity { return target.identity }

// Kind returns the selected review target kind.
func (target CapturedReviewTarget) Kind() domain.TargetKind { return target.kind }

// NoChange reports only an empty Git diff; patch and stdin inputs are non-empty.
func (target CapturedReviewTarget) NoChange() bool {
	return target.kind == domain.TargetGit && len(target.bytes) == 0
}

// Valid reports whether the target could have been produced by its constructor.
func (target CapturedReviewTarget) Valid() bool {
	allowEmpty := target.kind == domain.TargetGit
	if err := validateCapturedReviewBytes(target.bytes, allowEmpty); err != nil {
		return false
	}
	if target.identity.Kind() != target.kind || target.identity.SHA256() != strings.TrimPrefix(sha256Identifier(target.bytes), "sha256:") {
		return false
	}
	switch target.kind {
	case domain.TargetGit:
		repository, ok := target.RepositoryID()
		if !ok {
			return false
		}
		var index *GitObjectID
		if target.hasIndexTree {
			value := target.indexTree
			index = &value
		}
		rebuilt, err := NewCapturedReviewGitTargetWithMode(target.gitMode, repository, target.base, target.head, target.headTree, index, target.bytes)
		return err == nil && rebuilt.identity == target.identity
	case domain.TargetWorkspace, domain.TargetPatch, domain.TargetStdin:
		if target.repository != "" || target.base.Valid() || target.head.Valid() || target.headTree.Valid() || target.indexTree.Valid() || target.hasIndexTree {
			return false
		}
		rebuilt, err := newCapturedReviewTarget(target.kind, target.bytes)
		return err == nil && rebuilt.identity == target.identity
	default:
		return false
	}
}

// RepositoryID returns the Git repository identity when this is a Git target.
func (target CapturedReviewTarget) RepositoryID() (string, bool) {
	return target.repository, target.kind == domain.TargetGit
}

// BaseObjectID returns the Git base object ID when this is a Git target.
func (target CapturedReviewTarget) BaseObjectID() (GitObjectID, bool) {
	return target.base, target.kind == domain.TargetGit
}

// HeadObjectID returns the Git head object ID when this is a Git target.
func (target CapturedReviewTarget) HeadObjectID() (GitObjectID, bool) {
	return target.head, target.kind == domain.TargetGit
}

// HeadTreeID returns the Git head tree ID when this is a Git target.
func (target CapturedReviewTarget) HeadTreeID() (GitObjectID, bool) {
	return target.headTree, target.kind == domain.TargetGit
}

// IndexTreeID returns the optional Git index tree ID.
func (target CapturedReviewTarget) IndexTreeID() (GitObjectID, bool) {
	return target.indexTree, target.kind == domain.TargetGit && target.hasIndexTree
}

// CapturedEvidenceSide identifies a captured immutable file namespace.
type CapturedEvidenceSide string

const (
	CapturedEvidenceBase     CapturedEvidenceSide = "base"
	CapturedEvidenceHead     CapturedEvidenceSide = "head"
	CapturedEvidenceWorktree CapturedEvidenceSide = "worktree"
	CapturedEvidenceIndex    CapturedEvidenceSide = "index"
)

func (side CapturedEvidenceSide) Valid() bool {
	switch side {
	case CapturedEvidenceBase, CapturedEvidenceHead, CapturedEvidenceWorktree, CapturedEvidenceIndex:
		return true
	default:
		return false
	}
}

// CapturedTargetEvidence retains source bytes captured with a target without
// retaining any authority to reopen the source repository.
type CapturedTargetEvidence struct {
	sides map[CapturedEvidenceSide][]WorkspaceSnapshotFile
}

func NewCapturedTargetEvidence(sides map[CapturedEvidenceSide][]WorkspaceSnapshotFile) (CapturedTargetEvidence, error) {
	if len(sides) == 0 {
		return CapturedTargetEvidence{}, fmt.Errorf("captured target evidence: no captured sides")
	}
	copied := make(map[CapturedEvidenceSide][]WorkspaceSnapshotFile, len(sides))
	for side, files := range sides {
		if !side.Valid() {
			return CapturedTargetEvidence{}, fmt.Errorf("captured target evidence: invalid side")
		}
		validated, err := NewWorkspaceSnapshotRequest(files, "captured-evidence-v1")
		if err != nil {
			return CapturedTargetEvidence{}, fmt.Errorf("captured target evidence: %w", err)
		}
		copied[side] = validated.Files()
	}
	return CapturedTargetEvidence{sides: copied}, nil
}

// Files returns a caller-owned copy of the exact files captured for side.
func (evidence CapturedTargetEvidence) Files(side CapturedEvidenceSide) ([]WorkspaceSnapshotFile, bool) {
	files, ok := evidence.sides[side]
	if !ok {
		return nil, false
	}
	copied := make([]WorkspaceSnapshotFile, len(files))
	for index, file := range files {
		copied[index] = file
		copied[index].bytes = cloneBytes(file.bytes)
	}
	return copied, true
}

func (evidence CapturedTargetEvidence) Valid() bool {
	_, err := NewCapturedTargetEvidence(evidence.sides)
	return err == nil
}

// CapturedReviewMaterial is the complete clean, immutable capture handed to the
// workspace materializer. It carries no live-root authority.
type CapturedReviewMaterial struct {
	target            CapturedReviewTarget
	snapshot          WorkspaceSnapshotRequest
	projectContext    []byte
	hasProjectContext bool
	evidence          CapturedTargetEvidence
}

func NewCapturedReviewMaterial(target CapturedReviewTarget, snapshot WorkspaceSnapshotRequest, projectContext []byte) (CapturedReviewMaterial, error) {
	return NewCapturedReviewMaterialWithProjectContext(target, snapshot, projectContext, projectContext != nil)
}

func NewCapturedReviewMaterialWithProjectContext(target CapturedReviewTarget, snapshot WorkspaceSnapshotRequest, projectContext []byte, hasProjectContext bool) (CapturedReviewMaterial, error) {
	return NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, projectContext, hasProjectContext, CapturedTargetEvidence{})
}

func NewCapturedReviewMaterialWithEvidence(target CapturedReviewTarget, snapshot WorkspaceSnapshotRequest, projectContext []byte, evidence CapturedTargetEvidence) (CapturedReviewMaterial, error) {
	return NewCapturedReviewMaterialWithEvidenceAndProjectContext(target, snapshot, projectContext, projectContext != nil, evidence)
}

func NewCapturedReviewMaterialWithEvidenceAndProjectContext(target CapturedReviewTarget, snapshot WorkspaceSnapshotRequest, projectContext []byte, hasProjectContext bool, evidence CapturedTargetEvidence) (CapturedReviewMaterial, error) {
	if !target.Valid() || !snapshot.Valid() || (!hasProjectContext && len(projectContext) != 0) || !utf8.Valid(projectContext) || containsNUL(projectContext) {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review material: invalid target, snapshot, or context")
	}
	if !target.NoChange() && !evidence.Valid() {
		return CapturedReviewMaterial{}, fmt.Errorf("captured review material: changed target requires immutable evidence")
	}
	return CapturedReviewMaterial{
		target:            target,
		snapshot:          snapshot,
		projectContext:    cloneBytes(projectContext),
		hasProjectContext: hasProjectContext,
		evidence:          evidence,
	}, nil
}

func (material CapturedReviewMaterial) Target() CapturedReviewTarget { return material.target }
func (material CapturedReviewMaterial) Snapshot() WorkspaceSnapshotRequest {
	return material.snapshot
}
func (material CapturedReviewMaterial) HasProjectContext() bool {
	return material.hasProjectContext
}
func (material CapturedReviewMaterial) ProjectContext() []byte {
	return cloneBytes(material.projectContext)
}
func (material CapturedReviewMaterial) Evidence() CapturedTargetEvidence {
	evidence, _ := NewCapturedTargetEvidence(material.evidence.sides)
	return evidence
}
func (material CapturedReviewMaterial) Valid() bool {
	_, err := NewCapturedReviewMaterialWithEvidenceAndProjectContext(material.target, material.snapshot, material.projectContext, material.hasProjectContext, material.evidence)
	return err == nil
}

type ReviewTargetCapturer interface {
	CaptureReviewTarget(context.Context, AnchoredRoot, ReviewTargetSelector) (CapturedReviewMaterial, error)
}

// ArtistReviewInputs identifies one review-scoped brief and bounded visual
// reference selection. Paths remain project-relative and are interpreted by
// the target capturer against the selected immutable snapshot.
type ArtistReviewInputs struct {
	briefPath       string
	designSpecGlobs []string
}

func NewArtistReviewInputs(briefPath string, designSpecGlobs []string) (ArtistReviewInputs, error) {
	if briefPath == "" || len(designSpecGlobs) == 0 || len(designSpecGlobs) > 16 {
		return ArtistReviewInputs{}, fmt.Errorf("artist review inputs: brief and visual references are required")
	}
	return ArtistReviewInputs{briefPath: briefPath, designSpecGlobs: append([]string(nil), designSpecGlobs...)}, nil
}

func (inputs ArtistReviewInputs) BriefPath() string { return inputs.briefPath }
func (inputs ArtistReviewInputs) DesignSpecGlobs() []string {
	return append([]string(nil), inputs.designSpecGlobs...)
}
func (inputs ArtistReviewInputs) Valid() bool {
	_, err := NewArtistReviewInputs(inputs.briefPath, inputs.designSpecGlobs)
	return err == nil
}

// ArtistReviewTargetCapturer is the optional review-scoped artist extension.
// Ordinary captures retain the smaller ReviewTargetCapturer contract.
type ArtistReviewTargetCapturer interface {
	CaptureReviewTargetWithArtistInputs(context.Context, AnchoredRoot, ReviewTargetSelector, ArtistReviewInputs) (CapturedReviewMaterial, error)
}
