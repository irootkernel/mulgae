// Package publication builds deterministic, schema-validated publication records.
package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/app/validation"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	finalReviewSchemaAsset = "https://mulgae.local/schemas/mulgae-review-artifact.v1.schema.json"
	runManifestSchemaAsset = "https://mulgae.local/schemas/mulgae-run-manifest.v1.schema.json"

	targetManifestPath   = "target/target-manifest.json"
	aggregationPath      = "aggregation.json"
	finalValidationPath  = "validation/final-validation.json"
	publicationJournalV1 = "mulgae-publication-journal.v1"
	publicationStatusV1  = "mulgae-publication-status.v1"
	lineageEdgeV1        = "mulgae-lineage-edge.v1"
	publicationEpochV1   = "mulgae-publication-epoch.v1"
)

// SchemaValidator validates bytes against one embedded schema asset. It is
// consumer-owned because publication owns byte construction, not schema lookup.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// PreparedCandidate is a fully semantically validated terminal review result.
// It deliberately has no ReviewID. A ReviewID is supplied only after this
// pre-publication validation has completed.
type PreparedCandidate struct {
	sessionID          domain.SessionID
	runID              domain.RunID
	runState           domain.RunState
	target             preparedTarget
	threshold          domain.Severity
	mulgae             preparedMulgae
	production         *ProductionReviewProvenance
	axes               preparedAxes
	roles              []preparedRole
	findings           []preparedFinding
	failures           []preparedFailure
	limits             []string
	reasons            []string
	exitCode           int
	lineage            preparedLineage
	followup           *preparedFollowupOutcome
	noChange           bool
	noChangeProvenance *NoChangeProvenance
}
type preparedLineage struct {
	runType          domain.RunType
	parentRunID      *domain.RunID
	sourceRunID      *domain.RunID
	sourceReviewID   *domain.ReviewID
	sourceFindingRef *string
	replayMode       *ReplayMode
}

// ReplayMode describes how a rerun obtains its prompt material.
type ReplayMode string

const (
	ReplayModeExact     ReplayMode = "exact"
	ReplayModeRecompose ReplayMode = "recompose"
)

// RunPublicationContext binds a candidate to its immutable run lineage.
// The zero value is the byte-compatible root review context.
type RunPublicationContext struct {
	lineage    preparedLineage
	production *ProductionReviewProvenance
}

// ProductionReviewProvenance is the immutable closure authority for a changed
// root review. It retains canonical receipt IDs rather than credentials,
// settings, or mutable workspace paths.
type ProductionReviewProvenance struct {
	BuildProduct             string
	BuildVersion             string
	BuildCommit              string
	ObjectiveSHA256          string
	HasObjective             bool
	SnapshotManifestSHA256   string
	Providers                []ProductionProviderProvenance
	WorkspaceTerminalReceipt string
}

type NoChangeProvenance struct {
	BuildProduct             string
	BuildVersion             string
	BuildCommit              string
	ObjectiveSHA256          string
	HasObjective             bool
	SnapshotManifestSHA256   string
	WorkspaceTerminalReceipt string
}

type ProductionProviderProvenance struct {
	Family                    string
	Instance                  string
	Version                   string
	Executable                string
	ExecutableSHA256          string
	Launcher                  string
	LauncherSHA256            string
	ProfileGeneration         string
	AdapterProfile            string
	QualificationReceiptIDs   []string
	PacketTransportReceiptIDs []string
	NamespaceTerminalReceipt  string // Canonical receipt ID.
}

// NewProductionPublicationContext creates the root-only context for a normal
// production review and defensively owns every caller-provided slice.
func NewProductionPublicationContext(provenance ProductionReviewProvenance) (RunPublicationContext, error) {
	copied := cloneProductionReviewProvenance(provenance)
	context := RunPublicationContext{lineage: preparedLineage{runType: domain.RunTypeReview}, production: &copied}
	if err := context.validate(); err != nil {
		return RunPublicationContext{}, fmt.Errorf("production publication context: %w", err)
	}
	return context, nil
}

// NewChildPublicationContext validates the complete immutable lineage for a
// followup, delta, or rerun publication.
func NewChildPublicationContext(
	runType domain.RunType,
	parentRunID domain.RunID,
	sourceRunID domain.RunID,
	sourceReviewID domain.ReviewID,
	sourceFindingRef *string,
	replayMode *ReplayMode,
) (RunPublicationContext, error) {
	parent := parentRunID
	source := sourceRunID
	review := sourceReviewID
	context := RunPublicationContext{lineage: preparedLineage{
		runType: runType, parentRunID: &parent, sourceRunID: &source, sourceReviewID: &review,
	}}
	if sourceFindingRef != nil {
		value := *sourceFindingRef
		context.lineage.sourceFindingRef = &value
	}
	if replayMode != nil {
		value := *replayMode
		context.lineage.replayMode = &value
	}
	if err := context.validate(); err != nil {
		return RunPublicationContext{}, fmt.Errorf("child publication context: %w", err)
	}
	return context, nil
}

func rootPublicationContext() RunPublicationContext {
	return RunPublicationContext{lineage: preparedLineage{runType: domain.RunTypeReview}}
}

func (context RunPublicationContext) validate() error {
	lineage := context.lineage
	if lineage.runType == "" {
		if lineage.parentRunID != nil || lineage.sourceRunID != nil || lineage.sourceReviewID != nil ||
			lineage.sourceFindingRef != nil || lineage.replayMode != nil {
			return fmt.Errorf("root lineage cannot contain child fields")
		}
		return nil
	}
	if !lineage.runType.Valid() {
		return fmt.Errorf("invalid run type %q", lineage.runType)
	}
	if lineage.runType == domain.RunTypeReview {
		if lineage.parentRunID != nil || lineage.sourceRunID != nil || lineage.sourceReviewID != nil ||
			lineage.sourceFindingRef != nil || lineage.replayMode != nil {
			return fmt.Errorf("review lineage must be root")
		}
		if context.production != nil {
			if err := validateProductionReviewProvenance(*context.production); err != nil {
				return fmt.Errorf("production provenance: %w", err)
			}
		}
		return nil
	}
	if context.production != nil {
		return fmt.Errorf("child publication context cannot contain production provenance")
	}
	if lineage.parentRunID == nil || lineage.sourceRunID == nil || lineage.sourceReviewID == nil {
		return fmt.Errorf("%s lineage requires parent run, source run, and source review", lineage.runType)
	}
	if _, err := domain.ParseRunID(lineage.parentRunID.String()); err != nil {
		return fmt.Errorf("parent run ID: %w", err)
	}
	if _, err := domain.ParseRunID(lineage.sourceRunID.String()); err != nil {
		return fmt.Errorf("source run ID: %w", err)
	}
	if _, err := domain.ParseReviewID(lineage.sourceReviewID.String()); err != nil {
		return fmt.Errorf("source review ID: %w", err)
	}
	if lineage.sourceFindingRef != nil && !validFindingID(*lineage.sourceFindingRef) {
		return fmt.Errorf("source finding reference is invalid")
	}
	if lineage.replayMode != nil && *lineage.replayMode != ReplayModeExact && *lineage.replayMode != ReplayModeRecompose {
		return fmt.Errorf("replay mode is invalid")
	}
	switch lineage.runType {
	case domain.RunTypeFollowup:
		if lineage.sourceFindingRef == nil || lineage.replayMode != nil {
			return fmt.Errorf("followup lineage requires a source finding and forbids replay mode")
		}
	case domain.RunTypeDelta:
		if lineage.sourceFindingRef != nil || lineage.replayMode != nil {
			return fmt.Errorf("delta lineage forbids source finding and replay mode")
		}
	case domain.RunTypeRerun:
		if lineage.sourceFindingRef != nil || lineage.replayMode == nil {
			return fmt.Errorf("rerun lineage requires replay mode and forbids source finding")
		}
	}
	return nil
}

func (context RunPublicationContext) runType() domain.RunType { return context.lineage.runType }

func (context RunPublicationContext) immutableLineage() preparedLineage {
	lineage := context.lineage
	if lineage.parentRunID != nil {
		value := *lineage.parentRunID
		lineage.parentRunID = &value
	}
	if lineage.sourceRunID != nil {
		value := *lineage.sourceRunID
		lineage.sourceRunID = &value
	}
	if lineage.sourceReviewID != nil {
		value := *lineage.sourceReviewID
		lineage.sourceReviewID = &value
	}
	if lineage.sourceFindingRef != nil {
		value := *lineage.sourceFindingRef
		lineage.sourceFindingRef = &value
	}
	if lineage.replayMode != nil {
		value := *lineage.replayMode
		lineage.replayMode = &value
	}
	return lineage
}
func (candidate PreparedCandidate) publicationLineage() preparedLineage {
	if candidate.lineage.runType == "" {
		return rootPublicationContext().lineage
	}
	return RunPublicationContext{lineage: candidate.lineage}.immutableLineage()
}

func (context RunPublicationContext) immutableProductionProvenance() *ProductionReviewProvenance {
	if context.production == nil {
		return nil
	}
	provenance := cloneProductionReviewProvenance(*context.production)
	return &provenance
}

func cloneProductionReviewProvenance(value ProductionReviewProvenance) ProductionReviewProvenance {
	result := value
	result.Providers = make([]ProductionProviderProvenance, len(value.Providers))
	for index, provider := range value.Providers {
		result.Providers[index] = provider
		result.Providers[index].QualificationReceiptIDs = append([]string(nil), provider.QualificationReceiptIDs...)
		result.Providers[index].PacketTransportReceiptIDs = append([]string(nil), provider.PacketTransportReceiptIDs...)
	}
	return result
}

func validateProductionReviewProvenance(value ProductionReviewProvenance) error {
	if !safeText(value.BuildProduct, 128, true) || !safeText(value.BuildVersion, 128, true) ||
		!safeText(value.BuildCommit, 128, true) || !validSHA256(value.SnapshotManifestSHA256) ||
		!validReceiptID(value.WorkspaceTerminalReceipt) || len(value.Providers) == 0 {
		return fmt.Errorf("build, snapshot, workspace, or providers are incomplete")
	}
	if value.HasObjective {
		if !validSHA256(value.ObjectiveSHA256) {
			return fmt.Errorf("objective identity is invalid")
		}
	} else if value.ObjectiveSHA256 != "" {
		return fmt.Errorf("absent objective cannot have an identity")
	}
	seen := make(map[string]struct{}, len(value.Providers))
	for index, provider := range value.Providers {
		if !safeText(provider.Family, 64, true) || !validProviderInstance(provider.Instance) ||
			!safeText(provider.Version, 128, true) || !safeText(provider.Executable, 1024, true) ||
			!validSHA256(provider.ExecutableSHA256) || !safeText(provider.ProfileGeneration, 256, true) ||
			!safeText(provider.AdapterProfile, 256, true) || !validReceiptID(provider.NamespaceTerminalReceipt) ||
			len(provider.QualificationReceiptIDs) == 0 || len(provider.PacketTransportReceiptIDs) == 0 {
			return fmt.Errorf("provider %d is incomplete", index)
		}
		if (provider.Launcher == "") != (provider.LauncherSHA256 == "") ||
			provider.Launcher != "" && (!safeText(provider.Launcher, 1024, true) || !validSHA256(provider.LauncherSHA256)) {
			return fmt.Errorf("provider %d launcher identity is invalid", index)
		}
		key := provider.Family + "\x00" + provider.Instance
		if _, duplicate := seen[key]; duplicate || index > 0 && key <= value.Providers[index-1].Family+"\x00"+value.Providers[index-1].Instance {
			return fmt.Errorf("providers are duplicated or unordered")
		}
		seen[key] = struct{}{}
		for _, receipts := range [][]string{provider.QualificationReceiptIDs, provider.PacketTransportReceiptIDs} {
			for receiptIndex, receipt := range receipts {
				if !validReceiptID(receipt) {
					return fmt.Errorf("provider receipt identity is invalid")
				}
				if receiptIndex > 0 && receipts[receiptIndex-1] >= receipt {
					return fmt.Errorf("provider receipt identities are not ordered")
				}
			}
		}
	}
	return nil
}

type preparedTarget struct {
	sha256  string
	baseOID string
	headOID string
}

type preparedMulgae struct {
	version string
	commit  string
}

type preparedAxes struct {
	content  domain.ContentVerdict
	coverage domain.CoverageStatus
	ci       domain.CIDecision
}

type preparedRole struct {
	role            domain.Role
	required        bool
	state           domain.RoleTaskState
	valid           bool
	degraded        bool
	repaired        bool
	failureClass    domain.FailureClass
	failureReason   string
	attempts        []preparedAttempt
	validFindingIDs []string
	outcome         string
	limitations     []string
}

type preparedAttempt struct {
	id          domain.AttemptID
	kind        review.AttemptKind
	provider    string
	state       domain.AttemptState
	invocations []preparedInvocation
}

// AttemptArtifactInput binds one captured provider stream to an immutable
// attempt invocation. Rejected streams retain no bytes and are never persisted.
type AttemptArtifactInput struct {
	AttemptID          domain.AttemptID
	InvocationSequence uint64
	Artifact           ports.CapturedAttemptArtifact
}

// FollowupRuntimeArtifactInput is the complete immutable runtime inventory for
// the specialized followup invocation. Its fields intentionally mirror the
// coordinator runtime inventory so followups use the same P2 retention rules.
type FollowupRuntimeArtifactInput struct {
	RuntimeRunID                 domain.RunID
	RuntimeAttemptID             domain.AttemptID
	RuntimeSequence              uint64
	RuntimePurpose               domain.InvocationPurpose
	RuntimeRole                  domain.Role
	RuntimeTarget                []byte
	RuntimeCapturedArchive       []byte
	RuntimeTargetIdentity        domain.TargetIdentity
	RuntimeStdin                 []byte
	RuntimeStdinSHA256           string
	RuntimeTemplateID            string
	RuntimeTemplateVersion       string
	RuntimeTemplateSHA256        string
	RuntimeSourceInvocationID    string
	RuntimeExecutionInvocationID string
	RuntimeScope                 string
	RuntimeAdapterProfile        string
	RuntimeAdapterParameters     map[string]string
	RuntimeCaptures              []ports.CapturedAttemptArtifact
}

type runtimeArtifactInventory interface {
	RunID() domain.RunID
	AttemptID() domain.AttemptID
	Sequence() uint64
	Purpose() domain.InvocationPurpose
	Role() domain.Role
	Target() []byte
	CapturedArchive() []byte
	TargetIdentity() domain.TargetIdentity
	Stdin() []byte
	StdinSHA256() string
	TemplateID() string
	TemplateVersion() string
	TemplateSHA256() string
	SourceInvocationID() string
	ExecutionInvocationID() string
	Scope() string
	AdapterProfile() string
	AdapterParameters() map[string]string
	Captures() []ports.CapturedAttemptArtifact
}

func (input FollowupRuntimeArtifactInput) RunID() domain.RunID         { return input.RuntimeRunID }
func (input FollowupRuntimeArtifactInput) AttemptID() domain.AttemptID { return input.RuntimeAttemptID }
func (input FollowupRuntimeArtifactInput) Sequence() uint64            { return input.RuntimeSequence }
func (input FollowupRuntimeArtifactInput) Purpose() domain.InvocationPurpose {
	return input.RuntimePurpose
}
func (input FollowupRuntimeArtifactInput) Role() domain.Role { return input.RuntimeRole }
func (input FollowupRuntimeArtifactInput) Target() []byte    { return cloneBytes(input.RuntimeTarget) }
func (input FollowupRuntimeArtifactInput) CapturedArchive() []byte {
	return cloneBytes(input.RuntimeCapturedArchive)
}
func (input FollowupRuntimeArtifactInput) TargetIdentity() domain.TargetIdentity {
	return input.RuntimeTargetIdentity
}
func (input FollowupRuntimeArtifactInput) Stdin() []byte       { return cloneBytes(input.RuntimeStdin) }
func (input FollowupRuntimeArtifactInput) StdinSHA256() string { return input.RuntimeStdinSHA256 }
func (input FollowupRuntimeArtifactInput) TemplateID() string  { return input.RuntimeTemplateID }
func (input FollowupRuntimeArtifactInput) TemplateVersion() string {
	return input.RuntimeTemplateVersion
}
func (input FollowupRuntimeArtifactInput) TemplateSHA256() string { return input.RuntimeTemplateSHA256 }
func (input FollowupRuntimeArtifactInput) SourceInvocationID() string {
	return input.RuntimeSourceInvocationID
}
func (input FollowupRuntimeArtifactInput) ExecutionInvocationID() string {
	return input.RuntimeExecutionInvocationID
}
func (input FollowupRuntimeArtifactInput) Scope() string          { return input.RuntimeScope }
func (input FollowupRuntimeArtifactInput) AdapterProfile() string { return input.RuntimeAdapterProfile }
func (input FollowupRuntimeArtifactInput) AdapterParameters() map[string]string {
	result := make(map[string]string, len(input.RuntimeAdapterParameters))
	for key, value := range input.RuntimeAdapterParameters {
		result[key] = value
	}
	return result
}
func (input FollowupRuntimeArtifactInput) Captures() []ports.CapturedAttemptArtifact {
	return append([]ports.CapturedAttemptArtifact(nil), input.RuntimeCaptures...)
}

type preparedAttemptArtifact struct {
	kind             ports.AttemptArtifactKind
	bytes            []byte
	securityRejected bool
}

type preparedInvocation struct {
	sequence  uint64
	purpose   domain.InvocationPurpose
	state     domain.InvocationState
	artifacts []preparedAttemptArtifact
	runtime   *preparedRuntimeArtifact
}

type preparedRuntimeArtifact struct {
	target                []byte
	capturedArchive       []byte
	targetSHA256          string
	targetKind            domain.TargetKind
	targetRepository      string
	targetBaseOID         string
	targetHeadOID         string
	targetHeadTreeOID     string
	targetIndexTreeOID    string
	targetGitMode         domain.GitTargetMode
	stdin                 []byte
	stdinSHA256           string
	templateID            string
	templateVersion       string
	templateSHA256        string
	sourceInvocationID    string
	executionInvocationID string
	scope                 string
	role                  domain.Role
	adapterProfile        string
	adapterParameters     map[string]string
}

type preparedFinding struct {
	id             string
	fingerprint    string
	role           domain.Role
	provider       string
	severity       domain.Severity
	title          string
	description    string
	recommendation string
	confidence     domain.Confidence
	lifecycle      domain.FindingLifecycle
	evidence       []preparedEvidence
}

type preparedEvidence struct {
	targetSHA256         string
	side                 evidence.Side
	path                 string
	lineStart            int
	lineEnd              int
	quote                string
	currentExcerptSHA256 string
	excerpt              []byte
	sourceSessionID      string
	sourceRunID          string
	sourceReviewID       string
	sourceFindingID      string
	sourceTargetSHA256   string
	sourceExcerptSHA256  string
	visual               *preparedVisualEvidence
}

type preparedVisualEvidence struct {
	path   string
	sha256 string
	x      int
	y      int
	width  int
	height int
}
type preparedFollowupOutcome struct {
	resolution domain.FollowupResolution
	rationale  string
	evidence   []preparedEvidence
}

type preparedFailure struct {
	class     domain.FailureClass
	stage     string
	reason    string
	attemptID *domain.AttemptID
}

// PublicationDocument is an exact mutable publication record. Bytes returns a
// caller-owned copy; its path and digest identify the complete replacement.
type PublicationDocument struct {
	path   ports.SafeRelativePath
	sha256 string
	bytes  []byte
}

// Path returns the canonical mutable record path.
func (document PublicationDocument) Path() ports.SafeRelativePath { return document.path }

// SHA256 returns the canonical exact-byte digest.
func (document PublicationDocument) SHA256() string { return document.sha256 }

// Bytes returns a caller-owned copy of the exact record bytes.
func (document PublicationDocument) Bytes() []byte { return cloneBytes(document.bytes) }

// Valid reports whether this document has a coherent immutable identity.
func (document PublicationDocument) Valid() bool {
	return document.path.Valid() && validSHA256(document.sha256) &&
		document.sha256 == sha256Identifier(document.bytes)
}

// RunSupportArtifactIdentity is the exact immutable identity of one
// run-support artifact re-read by publication before P2. It has no public
// constructor so callers cannot present synthesized support identities as
// persisted evidence.
type RunSupportArtifactIdentity struct {
	path   ports.SafeRelativePath
	sha256 string
}

// Path returns the exact persisted support-artifact path.
func (identity RunSupportArtifactIdentity) Path() ports.SafeRelativePath { return identity.path }

// SHA256 returns the exact persisted support-artifact hash.
func (identity RunSupportArtifactIdentity) SHA256() string { return identity.sha256 }

func (identity RunSupportArtifactIdentity) valid() bool {
	return identity.path.Valid() && validSHA256(identity.sha256)
}

func runSupportArtifactIdentity(artifact ports.ImmutablePublicationArtifact) RunSupportArtifactIdentity {
	return RunSupportArtifactIdentity{path: artifact.Path(), sha256: artifact.SHA256()}
}

func (identity RunSupportArtifactIdentity) promptManifestBinding() (domain.AttemptID, uint64, bool) {
	if !identity.valid() {
		return domain.AttemptID{}, 0, false
	}
	parts := strings.Split(identity.path.String(), "/")
	if len(parts) != 5 || parts[2] != "prompts" {
		return domain.AttemptID{}, 0, false
	}
	attemptID, err := domain.ParseAttemptID(parts[3])
	if err != nil {
		return domain.AttemptID{}, 0, false
	}
	sequence, suffix, ok := strings.Cut(parts[4], "-")
	if !ok || (suffix != "initial.manifest.json" && suffix != "repair.manifest.json") {
		return domain.AttemptID{}, 0, false
	}
	if len(sequence) < 3 {
		return domain.AttemptID{}, 0, false
	}
	for _, digit := range sequence {
		if digit < '0' || digit > '9' {
			return domain.AttemptID{}, 0, false
		}
	}
	value, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil || value == 0 {
		return domain.AttemptID{}, 0, false
	}
	return attemptID, value, true
}

// PublicationBundle is the defensive publication payload for one P2 composite.
// Its authority is represented solely by serialized records; this Go value has
// no authority flag or authorization accessor.
type PublicationBundle struct {
	final       ports.FinalReviewArtifact
	manifest    ports.ImmutablePublicationArtifact
	lineageEdge ports.ImmutablePublicationArtifact
	epoch       ports.PublicationEpoch
	staged      ports.ImmutablePublicationArtifact
	journal     PublicationDocument
	status      PublicationDocument
	excerpts    []ports.ImmutablePublicationArtifact
}

// Final returns the final review artifact with defensive byte accessors.
func (bundle PublicationBundle) Final() ports.FinalReviewArtifact { return bundle.final }

// Manifest returns the immutable committed manifest.
func (bundle PublicationBundle) Manifest() ports.ImmutablePublicationArtifact { return bundle.manifest }

// LineageEdge returns the immutable publication lineage edge.
func (bundle PublicationBundle) LineageEdge() ports.ImmutablePublicationArtifact {
	return bundle.lineageEdge
}

// Epoch returns the positive immutable epoch record.
func (bundle PublicationBundle) Epoch() ports.PublicationEpoch { return bundle.epoch }

// StagedFinal returns final bytes at their required staged temporary identity.
func (bundle PublicationBundle) StagedFinal() ports.ImmutablePublicationArtifact {
	return bundle.staged
}

// Journal returns the exact mutable journal replacement.
func (bundle PublicationBundle) Journal() PublicationDocument { return bundle.journal }

// Status returns the exact mutable status replacement.
func (bundle PublicationBundle) Status() PublicationDocument { return bundle.status }

// Excerpts returns caller-owned immutable excerpt artifact values.
func (bundle PublicationBundle) Excerpts() []ports.ImmutablePublicationArtifact {
	return append([]ports.ImmutablePublicationArtifact(nil), bundle.excerpts...)
}

// SupportArtifacts returns caller-owned immutable excerpts and attempt-capture
// artifacts. Their paths are validated against the closed run-support grammar
// by the persistence boundary.
func (bundle PublicationBundle) SupportArtifacts() []ports.ImmutablePublicationArtifact {
	return append([]ports.ImmutablePublicationArtifact(nil), bundle.excerpts...)
}

// Valid reports whether every bundle member remains self-consistent. It does
// not assert reader authority; only the serialized P2 records can do that.
func (bundle PublicationBundle) Valid() bool {
	if !bundle.final.Valid() || !bundle.manifest.Valid() || !bundle.lineageEdge.Valid() ||
		!bundle.epoch.Valid() || !bundle.staged.Valid() || !bundle.journal.Valid() || !bundle.status.Valid() {
		return false
	}
	for _, excerpt := range bundle.excerpts {
		if !excerpt.Valid() {
			return false
		}
	}
	return validatePublicationBundleSemantics(bundle) == nil
}

// PrepareCandidate validates every semantic fact available before a ReviewID is
// issued. It preserves the root-review API and its serialized bytes.
func PrepareCandidate(
	result review.CoordinatorResult,
	target domain.TargetIdentity,
	severityThreshold domain.Severity,
	mulgaeVersion string,
	mulgaeCommit string,
) (PreparedCandidate, error) {
	return PrepareCandidateWithContext(
		result, target, severityThreshold, mulgaeVersion, mulgaeCommit, rootPublicationContext(),
	)
}

// PrepareNoChangeCandidate constructs the provider-free P2 candidate for an
// empty Git capture. Patch and stdin targets are deliberately ineligible.
func PrepareNoChangeCandidate(
	sessionID domain.SessionID,
	runID domain.RunID,
	target domain.TargetIdentity,
	selectedRoles []domain.Role,
	severityThreshold domain.Severity,
	provenance NoChangeProvenance,
) (PreparedCandidate, error) {
	if err := validateIdentity(sessionID, runID); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication no-change candidate: identity: %w", err)
	}
	if err := validateNoChangeProvenance(provenance); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication no-change candidate: provenance: %w", err)
	}
	if err := validateTarget(target); err != nil || target.Kind() != domain.TargetGit ||
		target.SHA256() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return PreparedCandidate{}, fmt.Errorf("publication no-change candidate: target is not an empty Git capture")
	}
	if severityThreshold == "" {
		severityThreshold = domain.SeverityHigh
	}
	if !severityThreshold.Valid() || len(selectedRoles) == 0 {
		return PreparedCandidate{}, fmt.Errorf("publication no-change candidate: invalid metadata or selected roles")
	}
	roles := make([]preparedRole, len(selectedRoles))
	for index, role := range selectedRoles {
		if !role.Valid() || index > 0 && roleOrdinal(selectedRoles[index-1]) >= roleOrdinal(role) {
			return PreparedCandidate{}, fmt.Errorf("publication no-change candidate: selected roles are invalid")
		}
		roles[index] = preparedRole{
			role: role, required: role == domain.RoleLogic,
			state: domain.RoleTaskSucceeded, valid: true, outcome: "not_applicable",
			limitations: []string{"No Git changes were captured."},
		}
	}
	copied := provenance
	candidate := PreparedCandidate{
		sessionID: sessionID, runID: runID, runState: domain.RunCompleted,
		target:    preparedTarget{sha256: "sha256:" + target.SHA256(), baseOID: target.BaseObjectID(), headOID: target.HeadObjectID()},
		threshold: severityThreshold, mulgae: preparedMulgae{version: provenance.BuildVersion, commit: provenance.BuildCommit},
		axes:  preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass},
		roles: roles, findings: []preparedFinding{}, failures: []preparedFailure{}, limits: []string{},
		reasons: []string{"policy_evaluated"}, exitCode: int(domain.ExitCommittedPass),
		lineage: rootPublicationContext().lineage, noChange: true, noChangeProvenance: &copied,
	}
	if err := candidate.validate(); err != nil {
		return PreparedCandidate{}, err
	}
	return candidate, nil
}

// PrepareCandidateWithContext validates a root or child publication candidate.
func PrepareCandidateWithContext(
	result review.CoordinatorResult,
	target domain.TargetIdentity,
	severityThreshold domain.Severity,
	mulgaeVersion string,
	mulgaeCommit string,
	context RunPublicationContext,
) (PreparedCandidate, error) {
	if err := context.validate(); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: context: %w", err)
	}
	if err := validateIdentity(result.SessionID(), result.RunID()); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: result identity: %w", err)
	}
	if err := validateTarget(target); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: target: %w", err)
	}
	if severityThreshold == "" {
		severityThreshold = domain.SeverityHigh
	}
	if !severityThreshold.Valid() {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: invalid severity threshold %q", severityThreshold)
	}
	if err := validateBuildMetadata(mulgaeVersion, mulgaeCommit); err != nil {
		return PreparedCandidate{}, fmt.Errorf("publication candidate: build metadata: %w", err)
	}

	roles, failures, err := prepareRoles(result.RoleSummaries())
	if err != nil {
		return PreparedCandidate{}, err
	}
	findings, err := prepareFindings(result.Findings(), result.Evidence(), target, roles)
	if err != nil {
		return PreparedCandidate{}, err
	}
	bindFindingIDs(roles, findings)
	for index := range roles {
		if err := validatePreparedRole(roles[index]); err != nil {
			return PreparedCandidate{}, fmt.Errorf("publication candidate: role %q: %w", roles[index].role, err)
		}
	}

	axes, reasons, exitCode, limits, err := validateOutcomeAxes(result, roles, findings, severityThreshold, context)
	if err != nil {
		return PreparedCandidate{}, err
	}
	if err := validateTerminalRun(result.RunState(), roles, axes.coverage); err != nil {
		return PreparedCandidate{}, err
	}

	candidate := PreparedCandidate{
		sessionID: result.SessionID(),
		runID:     result.RunID(),
		runState:  result.RunState(),
		target: preparedTarget{
			sha256:  "sha256:" + target.SHA256(),
			baseOID: target.BaseObjectID(),
			headOID: target.HeadObjectID(),
		},
		threshold: severityThreshold,
		mulgae: preparedMulgae{
			version: mulgaeVersion,
			commit:  mulgaeCommit,
		},
		axes:       axes,
		roles:      clonePreparedRoles(roles),
		findings:   clonePreparedFindings(findings),
		failures:   clonePreparedFailures(failures),
		limits:     append([]string(nil), limits...),
		reasons:    append([]string(nil), reasons...),
		exitCode:   exitCode,
		lineage:    context.immutableLineage(),
		production: context.immutableProductionProvenance(),
	}
	if err := candidate.validate(); err != nil {
		return PreparedCandidate{}, err
	}
	return candidate, nil
}

// PrepareCandidateWithRuntimeArtifacts binds one complete immutable runtime
// inventory to every coordinator invocation and rejects missing source material
// before P2 publication.
func PrepareCandidateWithRuntimeArtifacts(
	result review.CoordinatorResult,
	target domain.TargetIdentity,
	severityThreshold domain.Severity,
	mulgaeVersion string,
	mulgaeCommit string,
	context RunPublicationContext,
	inputs []review.RuntimeArtifactInventory,
) (PreparedCandidate, error) {
	candidate, err := PrepareCandidateWithContext(
		result, target, severityThreshold, mulgaeVersion, mulgaeCommit, context,
	)
	if err != nil {
		return PreparedCandidate{}, err
	}
	runtimeInputs := make([]runtimeArtifactInventory, len(inputs))
	for index := range inputs {
		runtimeInputs[index] = inputs[index]
	}
	if err := candidate.bindRuntimeArtifactInventories(runtimeInputs); err != nil {
		return PreparedCandidate{}, err
	}
	return candidate, nil
}

func (candidate *PreparedCandidate) bindRuntimeArtifactInventories(inputs []runtimeArtifactInventory) error {
	if len(inputs) == 0 {
		return fmt.Errorf("publication candidate: runtime artifact inventory is absent")
	}
	seen := make(map[string]struct{}, len(inputs))
	captures := make([]AttemptArtifactInput, 0)
	for _, input := range inputs {
		if input.RunID() != candidate.runID || input.AttemptID().String() == "" ||
			input.Sequence() == 0 || input.Role() == "" ||
			sha256Identifier(input.Target()) != "sha256:"+input.TargetIdentity().SHA256() ||
			"sha256:"+input.TargetIdentity().SHA256() != candidate.target.sha256 ||
			input.StdinSHA256() != prompt.CompleteStdinSHA256(input.Stdin()) ||
			input.TemplateID() == "" || input.TemplateVersion() == "" ||
			input.TemplateSHA256() == "" || input.SourceInvocationID() == "" ||
			input.ExecutionInvocationID() == "" || input.Scope() == "" ||
			input.AdapterProfile() == "" {
			return fmt.Errorf("publication candidate: invalid runtime artifact inventory for run=%s attempt=%s sequence=%d role=%s target=%s/%s stdin=%s/%s template=%s/%s/%s source=%s execution=%s scope=%s profile=%s",
				input.RunID(), input.AttemptID(), input.Sequence(), input.Role(),
				sha256Identifier(input.Target()), input.TargetIdentity().SHA256(),
				input.StdinSHA256(), prompt.CompleteStdinSHA256(input.Stdin()),
				input.TemplateID(), input.TemplateVersion(), input.TemplateSHA256(),
				input.SourceInvocationID(), input.ExecutionInvocationID(), input.Scope(), input.AdapterProfile())
		}
		key := input.AttemptID().String() + fmt.Sprintf("/%020d", input.Sequence())
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("publication candidate: duplicate runtime artifact inventory")
		}
		seen[key] = struct{}{}
		bound := false
		for roleIndex := range candidate.roles {
			for attemptIndex := range candidate.roles[roleIndex].attempts {
				attempt := &candidate.roles[roleIndex].attempts[attemptIndex]
				if attempt.id != input.AttemptID() {
					continue
				}
				for invocationIndex := range attempt.invocations {
					invocation := &attempt.invocations[invocationIndex]
					if invocation.sequence != input.Sequence() || invocation.purpose != input.Purpose() ||
						candidate.roles[roleIndex].role != input.Role() {
						continue
					}
					identity := input.TargetIdentity()
					invocation.runtime = &preparedRuntimeArtifact{
						target: input.Target(), targetSHA256: identity.SHA256(), targetKind: identity.Kind(),
						capturedArchive:  input.CapturedArchive(),
						targetRepository: identity.RepositoryID(), targetBaseOID: identity.BaseObjectID(),
						targetHeadOID: identity.HeadObjectID(), stdin: input.Stdin(),
						targetHeadTreeOID: identity.HeadTreeObjectID(), targetIndexTreeOID: identity.IndexTreeObjectID(),
						targetGitMode: identity.GitMode(),
						stdinSHA256:   input.StdinSHA256(), templateID: input.TemplateID(),
						templateVersion: input.TemplateVersion(), templateSHA256: input.TemplateSHA256(),
						sourceInvocationID: input.SourceInvocationID(), executionInvocationID: input.ExecutionInvocationID(),
						scope: input.Scope(), role: input.Role(), adapterProfile: input.AdapterProfile(),
						adapterParameters: input.AdapterParameters(),
					}
					for _, capture := range input.Captures() {
						captures = append(captures, AttemptArtifactInput{
							AttemptID: input.AttemptID(), InvocationSequence: input.Sequence(), Artifact: capture,
						})
					}
					bound = true
					break
				}
			}
		}
		if !bound {
			return fmt.Errorf("publication candidate: runtime artifact does not bind an invocation")
		}
	}
	for roleIndex := range candidate.roles {
		for attemptIndex := range candidate.roles[roleIndex].attempts {
			for invocationIndex := range candidate.roles[roleIndex].attempts[attemptIndex].invocations {
				attempt := candidate.roles[roleIndex].attempts[attemptIndex]
				invocation := attempt.invocations[invocationIndex]
				if invocation.runtime == nil {
					return fmt.Errorf(
						"publication candidate: runtime artifact inventory is incomplete for role=%s attempt=%s sequence=%d purpose=%s",
						candidate.roles[roleIndex].role, attempt.id, invocation.sequence, invocation.purpose,
					)
				}
			}
		}
	}
	if err := candidate.bindAttemptArtifacts(captures); err != nil {
		return err
	}
	return candidate.validate()
}

func (candidate *PreparedCandidate) bindAttemptArtifacts(inputs []AttemptArtifactInput) error {
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if _, err := domain.ParseAttemptID(input.AttemptID.String()); err != nil ||
			input.InvocationSequence == 0 || !input.Artifact.Valid() {
			return fmt.Errorf("publication candidate: invalid attempt artifact input")
		}
		key := input.AttemptID.String() + fmt.Sprintf("/%020d/", input.InvocationSequence) + string(input.Artifact.Kind())
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("publication candidate: duplicate attempt artifact input")
		}
		seen[key] = struct{}{}
		bound := false
		for roleIndex := range candidate.roles {
			for attemptIndex := range candidate.roles[roleIndex].attempts {
				attempt := &candidate.roles[roleIndex].attempts[attemptIndex]
				if attempt.id != input.AttemptID {
					continue
				}
				for invocationIndex := range attempt.invocations {
					invocation := &attempt.invocations[invocationIndex]
					if invocation.sequence != input.InvocationSequence {
						continue
					}
					if input.Artifact.Kind() == ports.AttemptArtifactInitialCandidate &&
						invocation.purpose != domain.InvocationInitial {
						return fmt.Errorf("publication candidate: initial capture is bound to a repair invocation")
					}
					if input.Artifact.Kind() == ports.AttemptArtifactRepairedCandidate &&
						invocation.purpose != domain.InvocationRepair {
						return fmt.Errorf("publication candidate: repaired capture is bound to an initial invocation")
					}
					invocation.artifacts = append(invocation.artifacts, preparedAttemptArtifact{
						kind: input.Artifact.Kind(), bytes: input.Artifact.Bytes(),
						securityRejected: input.Artifact.SecurityRejected(),
					})
					bound = true
					break
				}
			}
		}
		if !bound {
			return fmt.Errorf("publication candidate: attempt artifact does not bind an invocation")
		}
	}
	return candidate.validate()
}

// Valid reports whether this value is a complete semantic pre-publication
// candidate. A zero value is never valid.
func (candidate PreparedCandidate) Valid() bool { return candidate.validate() == nil }

// SessionID returns the immutable review-session identity bound by validation.
func (candidate PreparedCandidate) SessionID() domain.SessionID { return candidate.sessionID }

// RunID returns the immutable review-run identity bound by validation.
func (candidate PreparedCandidate) RunID() domain.RunID { return candidate.runID }

// ValidatedCandidateSHA256 returns a deterministic, domain-separated identity
// over every semantic input validated before ReviewID issuance. It returns an
// empty string for an invalid candidate.
func (candidate PreparedCandidate) ValidatedCandidateSHA256() string {
	if !candidate.Valid() {
		return ""
	}
	digest := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(value))
	}
	write("Mulgae-PUBLICATION-CANDIDATE/1")
	write(candidate.sessionID.String())
	write(candidate.runID.String())
	write(string(candidate.runState))
	lineage := candidate.publicationLineage()
	if lineage.runType != domain.RunTypeReview {
		write(string(lineage.runType))
		if lineage.parentRunID != nil {
			write(lineage.parentRunID.String())
		}
		if lineage.sourceRunID != nil {
			write(lineage.sourceRunID.String())
		}
		if lineage.sourceReviewID != nil {
			write(lineage.sourceReviewID.String())
		}
		if lineage.sourceFindingRef != nil {
			write(*lineage.sourceFindingRef)
		}
		if lineage.replayMode != nil {
			write(string(*lineage.replayMode))
		}
	}
	if candidate.followup != nil {
		write(string(candidate.followup.resolution))
		write(candidate.followup.rationale)
		for _, item := range candidate.followup.evidence {
			write(item.targetSHA256)
			write(string(item.side))
			write(item.path)
			write(fmt.Sprintf("%d", item.lineStart))
			write(fmt.Sprintf("%d", item.lineEnd))
			write(item.quote)
			write(item.currentExcerptSHA256)
			write(string(item.excerpt))
			write(item.sourceSessionID)
			write(item.sourceRunID)
			write(item.sourceReviewID)
			write(item.sourceFindingID)
			write(item.sourceTargetSHA256)
			write(item.sourceExcerptSHA256)
		}
	}
	write(candidate.target.sha256)
	write(candidate.target.baseOID)
	write(candidate.target.headOID)
	write(string(candidate.threshold))
	write(candidate.mulgae.version)
	write(candidate.mulgae.commit)
	if candidate.production == nil {
		write("production:absent")
	} else {
		production := candidate.production
		write("production:present")
		write(production.BuildProduct)
		write(production.BuildVersion)
		write(production.BuildCommit)
		write(production.ObjectiveSHA256)
		write(fmt.Sprintf("%t", production.HasObjective))
		write(production.SnapshotManifestSHA256)
		write(production.WorkspaceTerminalReceipt)
		write(fmt.Sprintf("%d", len(production.Providers)))
		for _, provider := range production.Providers {
			write(provider.Family)
			write(provider.Instance)
			write(provider.Version)
			write(provider.Executable)
			write(provider.ExecutableSHA256)
			write(provider.Launcher)
			write(provider.LauncherSHA256)
			write(provider.ProfileGeneration)
			write(provider.AdapterProfile)
			write(fmt.Sprintf("%d", len(provider.QualificationReceiptIDs)))
			for _, receipt := range provider.QualificationReceiptIDs {
				write(receipt)
			}
			write(fmt.Sprintf("%d", len(provider.PacketTransportReceiptIDs)))
			for _, receipt := range provider.PacketTransportReceiptIDs {
				write(receipt)
			}
			write(provider.NamespaceTerminalReceipt)
		}
	}
	if candidate.noChangeProvenance == nil {
		write("no-change-provenance:absent")
	} else {
		provenance := candidate.noChangeProvenance
		write("no-change-provenance:present")
		write(provenance.BuildProduct)
		write(provenance.BuildVersion)
		write(provenance.BuildCommit)
		write(provenance.ObjectiveSHA256)
		write(fmt.Sprintf("%t", provenance.HasObjective))
		write(provenance.SnapshotManifestSHA256)
		write(provenance.WorkspaceTerminalReceipt)
	}
	write(string(candidate.axes.content))
	write(string(candidate.axes.coverage))
	write(string(candidate.axes.ci))
	for _, role := range candidate.roles {
		write(string(role.role))
		write(fmt.Sprintf("%t", role.required))
		write(string(role.state))
		write(fmt.Sprintf("%t", role.valid))
		write(fmt.Sprintf("%t", role.degraded))
		write(fmt.Sprintf("%t", role.repaired))
		write(role.outcome)
		write(string(role.failureClass))
		write(role.failureReason)
		for _, attempt := range role.attempts {
			write(attempt.id.String())
			write(string(attempt.kind))
			write(attempt.provider)
			write(string(attempt.state))
			for _, invocation := range attempt.invocations {
				write(fmt.Sprintf("%d", invocation.sequence))
				write(string(invocation.purpose))
				write(string(invocation.state))
				if invocation.runtime == nil {
					write("runtime:absent")
				} else {
					runtime := invocation.runtime
					write("runtime:present")
					write(string(runtime.target))
					write(runtime.targetSHA256)
					write(string(runtime.targetKind))
					write(runtime.targetRepository)
					write(runtime.targetBaseOID)
					write(runtime.targetHeadOID)
					write(runtime.targetHeadTreeOID)
					write(runtime.targetIndexTreeOID)
					write(string(runtime.stdin))
					write(runtime.stdinSHA256)
					write(runtime.templateID)
					write(runtime.templateVersion)
					write(runtime.templateSHA256)
					write(runtime.sourceInvocationID)
					write(runtime.executionInvocationID)
					write(runtime.scope)
					write(string(runtime.role))
					write(runtime.adapterProfile)
					keys := make([]string, 0, len(runtime.adapterParameters))
					for key := range runtime.adapterParameters {
						keys = append(keys, key)
					}
					sort.Strings(keys)
					for _, key := range keys {
						write(key)
						write(runtime.adapterParameters[key])
					}
				}
				for _, artifact := range invocation.artifacts {
					write(string(artifact.kind))
					write(fmt.Sprintf("%t", artifact.securityRejected))
					write(string(artifact.bytes))
				}
			}
		}
		for _, findingID := range role.validFindingIDs {
			write(findingID)
		}
		for _, limitation := range role.limitations {
			write(limitation)
		}
	}
	for _, finding := range candidate.findings {
		write(finding.id)
		write(finding.fingerprint)
		write(string(finding.role))
		write(finding.provider)
		write(string(finding.severity))
		write(finding.title)
		write(finding.description)
		write(finding.recommendation)
		write(string(finding.confidence))
		write(string(finding.lifecycle))
		for _, item := range finding.evidence {
			write(item.targetSHA256)
			write(string(item.side))
			write(item.path)
			write(fmt.Sprintf("%d", item.lineStart))
			write(fmt.Sprintf("%d", item.lineEnd))
			write(item.quote)
			write(item.currentExcerptSHA256)
			write(string(item.excerpt))
			write(item.sourceSessionID)
			write(item.sourceRunID)
			write(item.sourceReviewID)
			write(item.sourceFindingID)
			write(item.sourceTargetSHA256)
			write(item.sourceExcerptSHA256)
		}
	}
	for _, failure := range candidate.failures {
		write(string(failure.class))
		write(failure.stage)
		write(failure.reason)
		if failure.attemptID == nil {
			write("")
		} else {
			write(failure.attemptID.String())
		}
	}
	for _, limitation := range candidate.limits {
		write(limitation)
	}
	for _, reason := range candidate.reasons {
		write(reason)
	}
	write(fmt.Sprintf("%d", candidate.exitCode))
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func (candidate PreparedCandidate) validate() error {
	if err := validateIdentity(candidate.sessionID, candidate.runID); err != nil {
		return err
	}
	if err := (RunPublicationContext{lineage: candidate.publicationLineage()}).validate(); err != nil {
		return fmt.Errorf("lineage: %w", err)
	}
	lineage := candidate.publicationLineage()
	if lineage.parentRunID != nil && *lineage.parentRunID == candidate.runID {
		return fmt.Errorf("lineage parent cannot be the child run")
	}
	if lineage.sourceRunID != nil && *lineage.sourceRunID == candidate.runID {
		return fmt.Errorf("lineage source cannot be the child run")
	}
	if candidate.runState != domain.RunCompleted && candidate.runState != domain.RunDegraded && candidate.runState != domain.RunFailed {
		return fmt.Errorf("run state %q is not publishable", candidate.runState)
	}
	if !candidate.threshold.Valid() || !validSHA256(candidate.target.sha256) ||
		!validOptionalOID(candidate.target.baseOID) || !validOptionalOID(candidate.target.headOID) {
		return fmt.Errorf("target or threshold is invalid")
	}
	if err := validateBuildMetadata(candidate.mulgae.version, candidate.mulgae.commit); err != nil {
		return err
	}
	if !candidate.axes.content.Valid() || !candidate.axes.coverage.Valid() || !candidate.axes.ci.Valid() {
		return fmt.Errorf("outcome axes are invalid")
	}
	if candidate.lineage.runType == domain.RunTypeFollowup {
		if candidate.followup == nil || !candidate.followup.resolution.Valid() ||
			!safeText(candidate.followup.rationale, 12000, false) ||
			len(candidate.followup.evidence) == 0 {
			return fmt.Errorf("followup outcome is incomplete")
		}
		if err := validatePreparedEvidence(candidate.followup.evidence, candidate.target.sha256); err != nil {
			return fmt.Errorf("followup outcome evidence: %w", err)
		}
	} else if candidate.followup != nil {
		return fmt.Errorf("non-followup candidate has followup outcome")
	}
	if candidate.production != nil {
		if candidate.publicationLineage().runType != domain.RunTypeReview || candidate.noChange {
			return fmt.Errorf("production provenance is only valid for changed root candidates")
		}
		if candidate.mulgae.version != candidate.production.BuildVersion || candidate.mulgae.commit != candidate.production.BuildCommit {
			return fmt.Errorf("production provenance build metadata does not match candidate")
		}
		if err := validateProductionReviewProvenance(*candidate.production); err != nil {
			return fmt.Errorf("normal production provenance: %w", err)
		}
	}
	if candidate.noChange {
		return candidate.validateNoChange()
	}
	if len(candidate.roles) == 0 || len(candidate.reasons) == 0 || !validNormalExit(candidate.exitCode) {
		return fmt.Errorf("candidate has incomplete role, reason, or exit data")
	}
	seenRoles := make(map[domain.Role]struct{}, len(candidate.roles))
	for index := range candidate.roles {
		role := candidate.roles[index]
		if _, duplicate := seenRoles[role.role]; duplicate {
			return fmt.Errorf("duplicate role %q", role.role)
		}
		seenRoles[role.role] = struct{}{}
		if err := validatePreparedRole(role); err != nil {
			return fmt.Errorf("role %q: %w", role.role, err)
		}
		if index > 0 && roleOrdinal(candidate.roles[index-1].role) >= roleOrdinal(role.role) {
			return fmt.Errorf("roles are not in deterministic order")
		}
	}
	if err := validatePreparedFindings(candidate.findings, candidate.roles, candidate.target.sha256); err != nil {
		return err
	}
	if err := validatePreparedFailures(candidate.failures, candidate.roles); err != nil {
		return err
	}
	if err := validateStringSlice(candidate.limits, 100, 2000, true); err != nil {
		return fmt.Errorf("limitations: %w", err)
	}
	if err := validateReasonCodes(candidate.reasons); err != nil {
		return err
	}
	if err := validateTerminalRun(candidate.runState, candidate.roles, candidate.axes.coverage); err != nil {
		return err
	}
	return nil
}

func prepareRoles(summaries []review.CoordinatorRoleSummary) ([]preparedRole, []preparedFailure, error) {
	if len(summaries) == 0 {
		return nil, nil, fmt.Errorf("publication candidate: result has no role summaries")
	}
	roles := make([]preparedRole, 0, len(summaries))
	failures := make([]preparedFailure, 0)
	seen := make(map[domain.Role]struct{}, len(summaries))
	seenAttempts := make(map[string]struct{})
	for index, summary := range summaries {
		role := summary.Role()
		if !role.Valid() {
			return nil, nil, fmt.Errorf("publication candidate: role summary %d has invalid role", index)
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, nil, fmt.Errorf("publication candidate: duplicate role %q", role)
		}
		seen[role] = struct{}{}
		if index > 0 && roleOrdinal(summaries[index-1].Role()) >= roleOrdinal(role) {
			return nil, nil, fmt.Errorf("publication candidate: role summaries are not in fixed order")
		}
		if !terminalRoleState(summary.State()) {
			return nil, nil, fmt.Errorf("publication candidate: role %q is not terminal", role)
		}
		attempts := summary.Attempts()
		if len(attempts) == 0 {
			return nil, nil, fmt.Errorf("publication candidate: role %q has no terminal attempt", role)
		}
		preparedAttempts := make([]preparedAttempt, len(attempts))
		for attemptIndex, attempt := range attempts {
			if _, err := domain.ParseAttemptID(attempt.ID().String()); err != nil {
				return nil, nil, fmt.Errorf("publication candidate: role %q attempt %d: invalid ID", role, attemptIndex)
			}
			if _, duplicate := seenAttempts[attempt.ID().String()]; duplicate {
				return nil, nil, fmt.Errorf("publication candidate: duplicate attempt ID %q", attempt.ID())
			}
			seenAttempts[attempt.ID().String()] = struct{}{}
			if !attempt.Kind().Valid() || !attempt.Route().Valid() || !terminalAttemptState(attempt.State()) {
				return nil, nil, fmt.Errorf("publication candidate: role %q has invalid terminal attempt", role)
			}
			invocations := attempt.Invocations()
			if len(invocations) == 0 {
				return nil, nil, fmt.Errorf("publication candidate: role %q attempt %q has no invocations", role, attempt.ID())
			}
			preparedInvocations := make([]preparedInvocation, len(invocations))
			for invocationIndex, invocation := range invocations {
				if invocation.Sequence() != uint64(invocationIndex+1) || !invocation.Purpose().Valid() || !terminalInvocationState(invocation.State()) {
					return nil, nil, fmt.Errorf("publication candidate: role %q attempt %q has inconsistent invocation %d", role, attempt.ID(), invocationIndex)
				}
				preparedInvocations[invocationIndex] = preparedInvocation{
					sequence: invocation.Sequence(), purpose: invocation.Purpose(), state: invocation.State(),
				}
			}
			preparedAttempts[attemptIndex] = preparedAttempt{
				id: attempt.ID(), kind: attempt.Kind(), provider: attempt.Route().ProviderInstance(), state: attempt.State(), invocations: preparedInvocations,
			}
			if attempt.State() == domain.AttemptSucceeded {
				if attempt.FailureClass() != "" || attempt.ReasonCode() != "" {
					return nil, nil, fmt.Errorf("publication candidate: successful role %q attempt %q has failure facts", role, attempt.ID())
				}
				continue
			}
			if !attempt.FailureClass().Valid() || forbiddenPublicationFailure(attempt.FailureClass()) ||
				!validReasonCode(attempt.ReasonCode()) ||
				(attempt.State() == domain.AttemptTimedOut) != (attempt.FailureClass() == domain.FailureTimeout) {
				return nil, nil, fmt.Errorf("publication candidate: role %q attempt %q has invalid failure facts", role, attempt.ID())
			}
			attemptID := attempt.ID()
			failures = append(failures, preparedFailure{
				class: attempt.FailureClass(), stage: "review", reason: attempt.ReasonCode(), attemptID: &attemptID,
			})
		}

		finalAttempt := preparedAttempts[len(preparedAttempts)-1]
		roleResult := preparedRole{
			role:          role,
			required:      summary.Required() || role == domain.RoleLogic,
			state:         summary.State(),
			valid:         summary.Valid(),
			degraded:      summary.Degraded(),
			repaired:      summary.Repaired(),
			failureClass:  summary.FailureClass(),
			failureReason: summary.ReasonCode(),
			attempts:      preparedAttempts,
		}
		if summary.Valid() {
			if summary.State() != domain.RoleTaskSucceeded || finalAttempt.state != domain.AttemptSucceeded ||
				summary.FailureClass() != "" || summary.ReasonCode() != "" {
				return nil, nil, fmt.Errorf("publication candidate: successful role %q is inconsistent", role)
			}
			if summary.Degraded() {
				roleResult.outcome = "degraded"
				roleResult.limitations = []string{"Role coverage is degraded."}
			} else {
				roleResult.outcome = "completed"
				roleResult.limitations = []string{}
			}
		} else {
			if summary.State() != domain.RoleTaskFailed || !summary.FailureClass().Valid() ||
				!validReasonCode(summary.ReasonCode()) || finalAttempt.state == domain.AttemptSucceeded {
				return nil, nil, fmt.Errorf("publication candidate: failed role %q is inconsistent", role)
			}
			if forbiddenPublicationFailure(summary.FailureClass()) {
				return nil, nil, fmt.Errorf("publication candidate: role %q has non-publishable failure %q", role, summary.FailureClass())
			}
			roleResult.outcome = "failed"
			roleResult.limitations = []string{"Role coverage is incomplete due to a terminal provider failure."}
			if summary.FailureClass() != attempts[len(attempts)-1].FailureClass() ||
				summary.ReasonCode() != attempts[len(attempts)-1].ReasonCode() {
				return nil, nil, fmt.Errorf("publication candidate: failed role %q does not match its final attempt failure", role)
			}
		}
		roles = append(roles, roleResult)
	}
	return roles, failures, nil
}

func prepareFindings(
	findings []domain.Finding,
	groups []review.VerifiedFindingEvidence,
	target domain.TargetIdentity,
	roles []preparedRole,
) ([]preparedFinding, error) {
	if len(findings) != len(groups) {
		return nil, fmt.Errorf("publication candidate: finding and evidence counts differ")
	}
	byRole := make(map[domain.Role]preparedRole, len(roles))
	for _, role := range roles {
		byRole[role.role] = role
	}
	prepared := make([]preparedFinding, 0, len(findings))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID() != expectedID || finding.Validate() != nil || groups[index].FindingID() != expectedID {
			return nil, fmt.Errorf("publication candidate: finding %d does not have exact ordered evidence binding", index)
		}
		role, exists := byRole[finding.Role()]
		if !exists || !role.valid || role.attempts[len(role.attempts)-1].provider != finding.ProviderInstance() {
			return nil, fmt.Errorf("publication candidate: finding %q has inconsistent role or provider binding", expectedID)
		}
		if err := validateFindingStrings(finding); err != nil {
			return nil, fmt.Errorf("publication candidate: finding %q: %w", expectedID, err)
		}
		receipts := groups[index].Receipts()
		visuals := groups[index].VisualReferences()
		if len(receipts) == 0 {
			return nil, fmt.Errorf("publication candidate: finding %q has no current evidence receipts", expectedID)
		}
		preparedReceipts, authoritative, err := reducePublicationEvidence(receipts, visuals, finding, target, expectedID)
		if err != nil {
			return nil, err
		}
		if !authoritative {
			continue
		}
		prepared = append(prepared, preparedFinding{
			id: expectedID, fingerprint: "sha256:" + finding.Fingerprint(), role: finding.Role(), provider: finding.ProviderInstance(),
			severity: finding.Severity(), title: finding.Title(), description: finding.Description(), recommendation: finding.Recommendation(),
			confidence: finding.Confidence(), lifecycle: finding.Lifecycle(), evidence: preparedReceipts,
		})
	}
	for index := range prepared {
		prepared[index].id = fmt.Sprintf("F%03d", index+1)
	}
	return prepared, nil
}
func reducePublicationEvidence(
	receipts []evidence.CurrentReceipt,
	visuals []validation.VerifiedVisualReference,
	finding domain.Finding,
	target domain.TargetIdentity,
	findingID string,
) ([]preparedEvidence, bool, error) {
	if len(receipts) == 0 || len(receipts) > 20 || len(visuals) != len(receipts) {
		return nil, false, fmt.Errorf("publication candidate: finding %q evidence count must be between 1 and 20", findingID)
	}

	verified := 0
	allowedException := 0
	rejected := 0
	for _, receipt := range receipts {
		switch {
		case receipt.Status() == evidence.ReceiptVerified && receipt.ReasonCode() == evidence.ReasonVerified:
			verified++
		case receipt.Status() == evidence.ReceiptUnverifiable &&
			receipt.ReasonCode() == evidence.ReasonTargetUnavailable &&
			finding.Severity() == domain.SeverityLow &&
			(target.Kind() == domain.TargetWorkspace || target.Kind() == domain.TargetPatch || target.Kind() == domain.TargetStdin):
			allowedException++
		default:
			rejected++
		}
	}
	if verified+allowedException+rejected != len(receipts) {
		return nil, false, fmt.Errorf("publication candidate: finding %q evidence counts do not partition receipts", findingID)
	}
	if rejected != 0 {
		if finding.Severity().Rank() < domain.SeverityHigh.Rank() {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("publication candidate: finding %q has non-authoritative evidence", findingID)
	}
	if verified != 0 && allowedException != 0 {
		return nil, false, fmt.Errorf("publication candidate: finding %q has mixed evidence authority", findingID)
	}
	if allowedException == len(receipts) {
		return nil, false, nil
	}
	if verified != len(receipts) {
		return nil, false, fmt.Errorf("publication candidate: finding %q evidence reduction is incomplete", findingID)
	}

	prepared := make([]preparedEvidence, len(receipts))
	for receiptIndex, receipt := range receipts {
		claim := receipt.Claim()
		if claim.TargetSHA256() != "sha256:"+target.SHA256() || !claim.Side().Valid() || !claim.Path().Valid() ||
			claim.LineStart() < 1 || claim.LineEnd() < claim.LineStart() || !safeText(claim.Quote(), 8000, false) {
			return nil, false, fmt.Errorf("publication candidate: finding %q receipt %d has invalid current claim", findingID, receiptIndex)
		}
		excerpt := receipt.Excerpt()
		if len(excerpt) == 0 || !utf8.Valid(excerpt) || !bytes.Equal(claim.QuoteBytes(), excerpt) {
			return nil, false, fmt.Errorf("publication candidate: finding %q receipt %d has inconsistent verified excerpt", findingID, receiptIndex)
		}
		excerptSHA256, err := claim.ExcerptSHA256(excerpt)
		if err != nil || receipt.ExcerptSHA256() != excerptSHA256 {
			return nil, false, fmt.Errorf("publication candidate: finding %q receipt %d has inconsistent excerpt identity", findingID, receiptIndex)
		}
		prepared[receiptIndex] = preparedEvidence{
			targetSHA256: claim.TargetSHA256(), side: claim.Side(), path: claim.Path().String(), lineStart: claim.LineStart(),
			lineEnd: claim.LineEnd(), quote: claim.Quote(), currentExcerptSHA256: receipt.ExcerptSHA256(), excerpt: cloneBytes(excerpt),
		}
		if visual := visuals[receiptIndex]; visual.Valid() {
			prepared[receiptIndex].visual = &preparedVisualEvidence{
				path: visual.Path().String(), sha256: visual.SHA256(), x: visual.X(), y: visual.Y(),
				width: visual.Width(), height: visual.Height(),
			}
		} else if visual != (validation.VerifiedVisualReference{}) {
			return nil, false, fmt.Errorf("publication candidate: finding %q receipt %d has invalid visual reference", findingID, receiptIndex)
		}
	}
	if err := canonicalizePreparedEvidence(prepared); err != nil {
		return nil, false, fmt.Errorf("publication candidate: finding %q evidence ordering: %w", findingID, err)
	}
	return prepared, true, nil
}

func canonicalizePreparedEvidence(items []preparedEvidence) error {
	if len(items) == 0 || len(items) > 20 {
		return fmt.Errorf("evidence count must be between 1 and 20")
	}
	sort.Slice(items, func(left, right int) bool {
		return canonicalPreparedEvidenceKey(items[left]) < canonicalPreparedEvidenceKey(items[right])
	})
	for index := 1; index < len(items); index++ {
		if canonicalPreparedEvidenceKey(items[index-1]) == canonicalPreparedEvidenceKey(items[index]) {
			return fmt.Errorf("evidence tuple is duplicated")
		}
	}
	return nil
}

func canonicalPreparedEvidenceKey(item preparedEvidence) string {
	fields := []string{
		item.sourceSessionID,
		item.sourceRunID,
		item.sourceReviewID,
		item.sourceFindingID,
		item.sourceTargetSHA256,
		item.sourceExcerptSHA256,
		item.currentExcerptSHA256,
		item.targetSHA256,
		string(item.side),
		item.path,
		strconv.Itoa(item.lineStart),
		strconv.Itoa(item.lineEnd),
		"verified",
	}
	if item.visual != nil {
		fields = append(fields, item.visual.path, item.visual.sha256, strconv.Itoa(item.visual.x), strconv.Itoa(item.visual.y),
			strconv.Itoa(item.visual.width), strconv.Itoa(item.visual.height), "verified")
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

func bindFindingIDs(roles []preparedRole, findings []preparedFinding) {
	for roleIndex := range roles {
		ids := make([]string, 0)
		for _, finding := range findings {
			if finding.role == roles[roleIndex].role {
				ids = append(ids, finding.id)
			}
		}
		roles[roleIndex].validFindingIDs = ids
	}
}

func validateOutcomeAxes(
	result review.CoordinatorResult,
	roles []preparedRole,
	findings []preparedFinding,
	threshold domain.Severity,
	context RunPublicationContext,
) (preparedAxes, []string, int, []string, error) {
	outcomes := result.Outcomes()
	if !outcomes.ContentVerdict().Valid() || !outcomes.CoverageStatus().Valid() || !outcomes.CIDecision().Valid() ||
		outcomes.PublicationStatus() != domain.PublicationNotPublished {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: result outcome axes are not pre-publication")
	}
	roleResults := make([]domain.RoleResultSummary, len(roles))
	for index, role := range roles {
		roleResults[index] = domain.RoleResultSummary{
			Role: role.role, Selected: true, Required: role.required, Valid: role.valid, Degraded: role.degraded,
		}
	}
	domainFindings := result.Findings()
	expected, err := domain.ComputeOutcomeAxes(domainFindings, roleResults, threshold, domain.PublicationNotPublished, nil)
	if err != nil {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: recompute axes: %w", err)
	}
	expectedCoverage := expected.CoverageStatus()
	expectedCI := expected.CIDecision()
	recomposeRerun := context.lineage.runType == domain.RunTypeRerun &&
		context.lineage.replayMode != nil && *context.lineage.replayMode == ReplayModeRecompose
	if recomposeRerun {
		expectedCoverage = coverageForSelectedPreparedRoles(roles)
		expectedCI = domain.CIPass
		if expected.ContentVerdict() == domain.ContentRequestChanges || expectedCoverage != domain.CoverageComplete {
			expectedCI = domain.CIFail
		}
	}
	if outcomes.ContentVerdict() != expected.ContentVerdict() ||
		(!recomposeRerun && (outcomes.CoverageStatus() != expectedCoverage || outcomes.CIDecision() != expectedCI)) {
		return preparedAxes{}, nil, 0, nil, fmt.Errorf("publication candidate: result outcome axes do not match trusted policy")
	}
	content := expected.ContentVerdict()
	coverage := expectedCoverage
	ci := expectedCI
	reasons := make([]string, 0, 2)
	if content == domain.ContentRequestChanges {
		reasons = append(reasons, "request_changes_threshold")
	}
	switch coverage {
	case domain.CoverageIncomplete:
		reasons = append(reasons, "required_role_incomplete")
	case domain.CoverageDegraded:
		reasons = append(reasons, "degraded_coverage")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "policy_evaluated")
	}
	exitCode := 0
	if coverage == domain.CoverageIncomplete {
		exitCode = int(domain.ExitIncompleteCoverage)
	} else if ci == domain.CIFail {
		exitCode = int(domain.ExitCommittedCIRejected)
	}
	limits := make([]string, 0, 1)
	if coverage == domain.CoverageIncomplete {
		limits = append(limits, "Required review coverage is incomplete.")
	} else if coverage == domain.CoverageDegraded {
		limits = append(limits, "Review coverage is degraded.")
	}
	return preparedAxes{content: content, coverage: coverage, ci: ci}, reasons, exitCode, limits, nil
}

func coverageForSelectedPreparedRoles(roles []preparedRole) domain.CoverageStatus {
	coverage := domain.CoverageComplete
	for _, role := range roles {
		if !role.valid {
			return domain.CoverageIncomplete
		}
		if role.degraded {
			coverage = domain.CoverageDegraded
		}
	}
	return coverage
}

func validateTerminalRun(state domain.RunState, roles []preparedRole, coverage domain.CoverageStatus) error {
	if state != domain.RunCompleted && state != domain.RunDegraded && state != domain.RunFailed {
		return fmt.Errorf("publication candidate: run state %q is not terminal and publishable", state)
	}
	failedAny := false
	for _, role := range roles {
		if role.outcome != "failed" {
			continue
		}
		failedAny = true
		if forbiddenPublicationFailure(role.failureClass) {
			return fmt.Errorf("publication candidate: non-publishable failure %q", role.failureClass)
		}
	}
	switch state {
	case domain.RunCompleted:
		if failedAny {
			return fmt.Errorf("publication candidate: completed run has failed role")
		}
	case domain.RunDegraded:
		if !failedAny {
			return fmt.Errorf("publication candidate: degraded run has inconsistent failed roles")
		}
	case domain.RunFailed:
		if !failedAny || coverage != domain.CoverageIncomplete {
			return fmt.Errorf("publication candidate: failed run does not represent incomplete coverage")
		}
		for _, role := range roles {
			if role.outcome == "failed" && !role.failureClass.FallbackAllowed() {
				return fmt.Errorf("publication candidate: failed run contains non-fallback-eligible failure %q", role.failureClass)
			}
		}
	}
	return nil
}

func validateNoChangeProvenance(value NoChangeProvenance) error {
	if validateBuildMetadata(value.BuildVersion, value.BuildCommit) != nil ||
		!safeText(value.BuildProduct, 128, true) ||
		!validSHA256(value.SnapshotManifestSHA256) ||
		!validReceiptID(value.WorkspaceTerminalReceipt) ||
		value.HasObjective != (value.ObjectiveSHA256 != "") ||
		value.HasObjective && !validSHA256(value.ObjectiveSHA256) {
		return fmt.Errorf("no-change provenance is incomplete")
	}
	return nil
}
func (candidate PreparedCandidate) validateNoChange() error {
	if candidate.production != nil || candidate.noChangeProvenance == nil ||
		validateNoChangeProvenance(*candidate.noChangeProvenance) != nil ||
		candidate.mulgae.version != candidate.noChangeProvenance.BuildVersion ||
		candidate.mulgae.commit != candidate.noChangeProvenance.BuildCommit ||
		candidate.lineage.runType != domain.RunTypeReview || candidate.runState != domain.RunCompleted ||
		candidate.target.sha256 != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ||
		candidate.axes != (preparedAxes{content: domain.ContentNoFindings, coverage: domain.CoverageComplete, ci: domain.CIPass}) ||
		len(candidate.findings) != 0 || len(candidate.failures) != 0 || len(candidate.limits) != 0 ||
		!reflect.DeepEqual(candidate.reasons, []string{"policy_evaluated"}) || candidate.exitCode != int(domain.ExitCommittedPass) {
		return fmt.Errorf("no-change values are inconsistent")
	}
	if len(candidate.roles) == 0 {
		return fmt.Errorf("no-change candidate has no selected roles")
	}
	seenRoles := make(map[domain.Role]struct{}, len(candidate.roles))
	for index, role := range candidate.roles {
		if !role.role.Valid() || role.required != (role.role == domain.RoleLogic) ||
			role.state != domain.RoleTaskSucceeded || !role.valid || role.degraded || role.repaired ||
			role.failureClass != "" || role.failureReason != "" || role.outcome != "not_applicable" ||
			len(role.attempts) != 0 || len(role.validFindingIDs) != 0 ||
			!reflect.DeepEqual(role.limitations, []string{"No Git changes were captured."}) {
			return fmt.Errorf("no-change role values are inconsistent")
		}
		if _, exists := seenRoles[role.role]; exists {
			return fmt.Errorf("no-change roles are duplicated")
		}
		seenRoles[role.role] = struct{}{}
		if index > 0 && roleOrdinal(candidate.roles[index-1].role) >= roleOrdinal(role.role) {
			return fmt.Errorf("no-change roles are not ordered")
		}
	}
	return nil
}

func validatePreparedRole(role preparedRole) error {
	if !role.role.Valid() || !terminalRoleState(role.state) || len(role.attempts) == 0 {
		return fmt.Errorf("identity, state, or attempts are invalid")
	}
	if role.role == domain.RoleLogic && !role.required {
		return fmt.Errorf("required role state is inconsistent")
	}
	seenAttempts := make(map[string]struct{}, len(role.attempts))
	for index, attempt := range role.attempts {
		if _, err := domain.ParseAttemptID(attempt.id.String()); err != nil {
			return fmt.Errorf("attempt %d ID is invalid", index)
		}
		if _, duplicate := seenAttempts[attempt.id.String()]; duplicate {
			return fmt.Errorf("duplicate attempt ID %q", attempt.id)
		}
		seenAttempts[attempt.id.String()] = struct{}{}
		switch index {
		case 0:
			if attempt.kind != review.AttemptKindPrimary {
				return fmt.Errorf("attempt sequence must begin with primary")
			}
		case 1:
			if attempt.kind != review.AttemptKindFallback || role.attempts[0].state == domain.AttemptSucceeded {
				return fmt.Errorf("fallback attempt is not a canonical continuation")
			}
		default:
			return fmt.Errorf("role has more than primary and fallback attempts")
		}
		if !attempt.kind.Valid() || !validProviderInstance(attempt.provider) || !terminalAttemptState(attempt.state) || len(attempt.invocations) == 0 {
			return fmt.Errorf("attempt %q is invalid", attempt.id)
		}
		for invocationIndex, invocation := range attempt.invocations {
			if invocation.sequence != uint64(invocationIndex+1) || !invocation.purpose.Valid() || !terminalInvocationState(invocation.state) {
				return fmt.Errorf("attempt %q invocation %d is invalid", attempt.id, invocationIndex)
			}
			seenArtifacts := make(map[ports.AttemptArtifactKind]struct{}, len(invocation.artifacts))
			for _, artifact := range invocation.artifacts {
				if !artifact.kind.Valid() || (artifact.securityRejected && len(artifact.bytes) != 0) ||
					(!artifact.securityRejected && len(artifact.bytes) == 0) {
					return fmt.Errorf("attempt %q invocation %d artifact is invalid", attempt.id, invocationIndex)
				}
				if _, duplicate := seenArtifacts[artifact.kind]; duplicate {
					return fmt.Errorf("attempt %q invocation %d has duplicate artifact kind", attempt.id, invocationIndex)
				}
				seenArtifacts[artifact.kind] = struct{}{}
			}
		}
	}
	if role.outcome == "not_applicable" {
		if len(role.attempts) != 0 || role.state != domain.RoleTaskSucceeded || !role.valid || role.degraded ||
			role.repaired || role.failureClass != "" || role.failureReason != "" ||
			!reflect.DeepEqual(role.limitations, []string{"No Git changes were captured."}) {
			return fmt.Errorf("not-applicable role values are inconsistent")
		}
		return nil
	}
	finalAttempt := role.attempts[len(role.attempts)-1]
	switch role.outcome {
	case "completed", "degraded":
		if !role.valid || role.state != domain.RoleTaskSucceeded || finalAttempt.state != domain.AttemptSucceeded ||
			role.failureClass != "" || role.failureReason != "" {
			return fmt.Errorf("successful role values are inconsistent")
		}
		if role.outcome == "completed" && role.degraded {
			return fmt.Errorf("completed role is marked degraded")
		}
		if role.outcome == "degraded" && !role.degraded {
			return fmt.Errorf("degraded role is not marked degraded")
		}
	case "failed":
		if role.valid || role.degraded || role.state != domain.RoleTaskFailed || !role.failureClass.Valid() ||
			!validReasonCode(role.failureReason) || finalAttempt.state == domain.AttemptSucceeded ||
			forbiddenPublicationFailure(role.failureClass) {
			return fmt.Errorf("failed role values are inconsistent")
		}
	default:
		return fmt.Errorf("unknown outcome %q", role.outcome)
	}
	if err := validateStringSlice(role.limitations, 20, 2000, true); err != nil {
		return err
	}
	for index, id := range role.validFindingIDs {
		if !validFindingID(id) || (index > 0 && role.validFindingIDs[index-1] >= id) {
			return fmt.Errorf("valid finding IDs are not ordered")
		}
	}
	return nil
}

func validatePreparedFindings(findings []preparedFinding, roles []preparedRole, targetSHA256 string) error {
	roleByName := make(map[domain.Role]preparedRole, len(roles))
	for _, role := range roles {
		roleByName[role.role] = role
	}
	expectedFindingIDs := make(map[domain.Role][]string, len(roles))
	for index, finding := range findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.id != expectedID || !validSHA256(finding.fingerprint) || !finding.role.Valid() ||
			!validProviderInstance(finding.provider) || !finding.severity.Valid() || !finding.confidence.Valid() || !finding.lifecycle.Valid() {
			return fmt.Errorf("finding %d identity is invalid", index)
		}
		role, exists := roleByName[finding.role]
		if !exists || !role.valid || role.attempts[len(role.attempts)-1].provider != finding.provider {
			return fmt.Errorf("finding %q has inconsistent role binding", finding.id)
		}
		if !safeText(finding.title, 300, true) || !safeText(finding.description, 12000, false) || !safeText(finding.recommendation, 12000, false) || len(finding.evidence) == 0 || len(finding.evidence) > 20 {
			return fmt.Errorf("finding %q text or evidence is invalid", finding.id)
		}
		for evidenceIndex, item := range finding.evidence {
			hasSource := item.sourceSessionID != "" || item.sourceRunID != "" || item.sourceReviewID != "" || item.sourceFindingID != "" ||
				item.sourceTargetSHA256 != "" || item.sourceExcerptSHA256 != ""
			if item.targetSHA256 != targetSHA256 || !item.side.Valid() || !safePath(item.path) || item.lineStart < 1 ||
				item.lineEnd < item.lineStart || !safeText(item.quote, 8000, false) || !validSHA256(item.currentExcerptSHA256) ||
				len(item.excerpt) == 0 || !utf8.Valid(item.excerpt) ||
				(hasSource && (item.sourceSessionID == "" || item.sourceRunID == "" || item.sourceReviewID == "" || item.sourceFindingID == "" ||
					!validSHA256(item.sourceTargetSHA256) || !validSHA256(item.sourceExcerptSHA256))) {
				return fmt.Errorf("finding %q evidence %d is invalid", finding.id, evidenceIndex)
			}
			claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
				TargetSHA256: item.targetSHA256,
				Side:         item.side,
				Path:         item.path,
				LineStart:    item.lineStart,
				LineEnd:      item.lineEnd,
				Quote:        item.quote,
			})
			if err != nil || !bytes.Equal(claim.QuoteBytes(), item.excerpt) {
				return fmt.Errorf("finding %q evidence %d does not match its verified excerpt", finding.id, evidenceIndex)
			}
			currentExcerptSHA256, err := claim.ExcerptSHA256(item.excerpt)
			if err != nil || currentExcerptSHA256 != item.currentExcerptSHA256 {
				return fmt.Errorf("finding %q evidence %d current excerpt identity is invalid", finding.id, evidenceIndex)
			}
			if item.visual != nil && (!safePath(item.visual.path) || !validSHA256(item.visual.sha256) ||
				item.visual.x < 0 || item.visual.y < 0 || item.visual.width < 1 || item.visual.height < 1) {
				return fmt.Errorf("finding %q evidence %d visual reference is invalid", finding.id, evidenceIndex)
			}
		}
		expectedFindingIDs[finding.role] = append(expectedFindingIDs[finding.role], finding.id)
	}
	for _, role := range roles {
		expected := expectedFindingIDs[role.role]
		if len(role.validFindingIDs) != len(expected) {
			return fmt.Errorf("role %q finding binding count is inconsistent", role.role)
		}
		for index := range expected {
			if role.validFindingIDs[index] != expected[index] {
				return fmt.Errorf("role %q finding binding is inconsistent", role.role)
			}
		}
	}
	return nil
}

func validatePreparedEvidence(items []preparedEvidence, targetSHA256 string) error {
	for index, item := range items {
		if item.targetSHA256 != targetSHA256 || !item.side.Valid() || !safePath(item.path) || item.lineStart < 1 ||
			item.lineEnd < item.lineStart || !safeText(item.quote, 8000, false) || !validSHA256(item.currentExcerptSHA256) ||
			len(item.excerpt) == 0 || !utf8.Valid(item.excerpt) || item.sourceSessionID == "" || item.sourceRunID == "" ||
			item.sourceReviewID == "" || item.sourceFindingID == "" || !validSHA256(item.sourceTargetSHA256) ||
			!validSHA256(item.sourceExcerptSHA256) {
			return fmt.Errorf("evidence %d is invalid", index)
		}
		claim, err := evidence.NewCurrentClaim(evidence.CurrentClaimInput{
			TargetSHA256: item.targetSHA256, Side: item.side, Path: item.path,
			LineStart: item.lineStart, LineEnd: item.lineEnd, Quote: item.quote,
		})
		if err != nil || !bytes.Equal(claim.QuoteBytes(), item.excerpt) {
			return fmt.Errorf("evidence %d does not match its verified excerpt", index)
		}
		currentExcerptSHA256, err := claim.ExcerptSHA256(item.excerpt)
		if err != nil || currentExcerptSHA256 != item.currentExcerptSHA256 {
			return fmt.Errorf("evidence %d current excerpt identity is invalid", index)
		}
		if item.visual != nil && (!safePath(item.visual.path) || !validSHA256(item.visual.sha256) ||
			item.visual.x < 0 || item.visual.y < 0 || item.visual.width < 1 || item.visual.height < 1) {
			return fmt.Errorf("evidence %d visual reference is invalid", index)
		}
	}
	return nil
}
func validatePreparedFailures(failures []preparedFailure, roles []preparedRole) error {
	failedAttempts := make([]preparedAttempt, 0)
	for _, role := range roles {
		for _, attempt := range role.attempts {
			if attempt.state != domain.AttemptSucceeded {
				failedAttempts = append(failedAttempts, attempt)
			}
		}
	}
	if len(failures) != len(failedAttempts) {
		return fmt.Errorf("failure projection count does not match failed terminal attempts")
	}
	for index, failure := range failures {
		if !failure.class.Valid() || forbiddenPublicationFailure(failure.class) || !safeText(failure.stage, 128, true) ||
			!validReasonCode(failure.reason) || failure.attemptID == nil {
			return fmt.Errorf("failure %d is invalid", index)
		}
		if _, err := domain.ParseAttemptID(failure.attemptID.String()); err != nil {
			return fmt.Errorf("failure %d has invalid attempt ID", index)
		}
		if *failure.attemptID != failedAttempts[index].id {
			return fmt.Errorf("failures are not in canonical failed-attempt order")
		}
		if (failedAttempts[index].state == domain.AttemptTimedOut) != (failure.class == domain.FailureTimeout) {
			return fmt.Errorf("failure %d class does not match attempt state", index)
		}
	}
	return nil
}

func validateIdentity(sessionID domain.SessionID, runID domain.RunID) error {
	if _, err := domain.ParseSessionID(sessionID.String()); err != nil {
		return err
	}
	if _, err := domain.ParseRunID(runID.String()); err != nil {
		return err
	}
	return nil
}

func validateTarget(target domain.TargetIdentity) error {
	canonical, err := domain.NewTargetIdentity(domain.TargetIdentityInput{
		Kind: target.Kind(), SHA256: target.SHA256(), RepositoryID: target.RepositoryID(), BaseObjectID: target.BaseObjectID(),
		HeadObjectID: target.HeadObjectID(), HeadTreeObjectID: target.HeadTreeObjectID(), IndexTreeObjectID: target.IndexTreeObjectID(),
		GitMode: target.GitMode(),
	})
	if err != nil || canonical != target {
		return fmt.Errorf("target identity is invalid")
	}
	return nil
}

func validateBuildMetadata(version, commit string) error {
	if !safeText(version, 128, true) {
		return fmt.Errorf("Mulgae version is invalid")
	}
	if commit != "" && !safeText(commit, 128, true) {
		return fmt.Errorf("Mulgae commit is invalid")
	}
	return nil
}

func validateFindingStrings(finding domain.Finding) error {
	if !safePath(finding.Path()) || !safeText(finding.ProviderInstance(), 128, true) || !safeText(finding.Title(), 300, true) ||
		!safeText(finding.Description(), 12000, false) || !safeText(finding.Recommendation(), 12000, false) {
		return fmt.Errorf("unsafe finding strings")
	}
	return nil
}

func validProviderInstance(value string) bool {
	if !safeText(value, 128, true) || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeText(value string, maximum int, singleLine bool) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == 0 || unicode.IsControl(character) && character != '\n' && character != '\t' {
			return false
		}
		if singleLine && (character == '\n' || character == '\t') {
			return false
		}
	}
	return true
}

func safePath(value string) bool {
	path, err := ports.NewSafeRelativePath(value)
	return err == nil && path.String() == value
}

func validOptionalOID(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validReceiptID(value string) bool {
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || len(value) != separator+1+64 {
		return false
	}
	for _, character := range value[:separator] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != ':' && character != '-' {
			return false
		}
	}
	for _, character := range value[separator+1:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validReasonCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateReasonCodes(values []string) error {
	if len(values) == 0 || len(values) > 32 {
		return fmt.Errorf("reason codes are empty or exceed the limit")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validReasonCode(value) {
			return fmt.Errorf("invalid reason code %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate reason code %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateStringSlice(values []string, maximumItems, maximumBytes int, allowEmpty bool) error {
	if len(values) > maximumItems || (!allowEmpty && len(values) == 0) {
		return fmt.Errorf("invalid item count")
	}
	for _, value := range values {
		if !safeText(value, maximumBytes, false) {
			return fmt.Errorf("unsafe text")
		}
	}
	return nil
}

func validFindingID(value string) bool {
	if len(value) < 4 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validNormalExit(code int) bool {
	return code == int(domain.ExitCommittedPass) || code == int(domain.ExitCommittedCIRejected) || code == int(domain.ExitIncompleteCoverage)
}
func validatePublicationBundleSemantics(bundle PublicationBundle) error {
	normalExit, err := validatePublicationCompositeSemantics(
		bundle.final,
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	)
	if err != nil {
		return err
	}
	var finalWire finalReviewWire
	if err := unmarshalCanonicalPublicationRecord(bundle.final.Bytes(), &finalWire, "final review"); err != nil {
		return err
	}
	sessionID, err := domain.ParseSessionID(finalWire.SessionID)
	if err != nil {
		return err
	}
	runID, err := domain.ParseRunID(finalWire.RunID)
	if err != nil {
		return err
	}
	paths, err := publicationPaths(sessionID, runID, bundle.final.Identity().ReviewID(), bundle.epoch.Value())
	if err != nil {
		return err
	}
	if bundle.staged.Path() != paths.staged ||
		bundle.staged.SHA256() != bundle.final.Identity().SHA256() ||
		!bytes.Equal(bundle.staged.Bytes(), bundle.final.Bytes()) {
		return fmt.Errorf("staged final does not match the exact final review")
	}
	if err := validateBundleExcerptBindings(bundle.excerpts, finalWire, paths); err != nil {
		return err
	}
	var manifestWire runManifestWire
	if err := unmarshalCanonicalPublicationRecord(bundle.manifest.Bytes(), &manifestWire, "run manifest"); err != nil {
		return err
	}
	if err := validateBundleSupportIndex(bundle.excerpts, manifestWire.CompositeIdentity.SupportIndex); err != nil {
		return err
	}

	var journal publicationJournalWire
	if err := unmarshalCanonicalPublicationRecord(bundle.journal.Bytes(), &journal, "publication journal"); err != nil {
		return err
	}
	if journal.SchemaVersion != publicationJournalV1 {
		return fmt.Errorf("publication journal schema version is invalid")
	}
	if err := validateRestartStateSemantics(
		journal.restartStateWire,
		domain.JournalManifestCommitted,
		normalExit,
		bundle.final.Identity(),
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	); err != nil {
		return fmt.Errorf("publication journal: %w", err)
	}

	var status publicationStatusWire
	if err := unmarshalCanonicalPublicationRecord(bundle.status.Bytes(), &status, "publication status"); err != nil {
		return err
	}
	if status.SchemaVersion != publicationStatusV1 ||
		status.PublicationStatus != string(domain.PublicationCommitted) ||
		status.PublicationAuthority != string(domain.PublicationAuthorityP2) {
		return fmt.Errorf("publication status does not grant the exact P2 projection")
	}
	if err := validateRestartStateSemantics(
		status.restartStateWire,
		domain.JournalManifestCommitted,
		normalExit,
		bundle.final.Identity(),
		bundle.manifest,
		bundle.lineageEdge,
		bundle.epoch,
	); err != nil {
		return fmt.Errorf("publication status: %w", err)
	}
	return nil
}

func validateBundleExcerptBindings(
	excerpts []ports.ImmutablePublicationArtifact,
	final finalReviewWire,
	paths publicationPathsSet,
) error {
	expectedCount := 0
	for _, finding := range final.Findings {
		expectedCount += len(finding.Evidence)
	}
	if len(excerpts) < expectedCount {
		return fmt.Errorf("excerpt count is smaller than final evidence")
	}
	index := 0
	for _, finding := range final.Findings {
		for evidenceIndex, item := range finding.Evidence {
			expectedPath, err := ports.NewSafeRelativePath(
				fmt.Sprintf("%s/%s_%d.md", paths.excerptsDir, finding.ID, evidenceIndex+1),
			)
			if err != nil {
				return err
			}
			artifact := excerpts[index]
			if artifact.Path() != expectedPath ||
				!bytes.Equal(artifact.Bytes(), []byte(item.Current.Quote)) {
				return fmt.Errorf("excerpt %q/%d does not match final evidence", finding.ID, evidenceIndex+1)
			}
			index++
		}
	}
	sessionID, err := domain.ParseSessionID(final.SessionID)
	if err != nil {
		return fmt.Errorf("final session ID is invalid: %w", err)
	}
	runID, err := domain.ParseRunID(final.RunID)
	if err != nil {
		return fmt.Errorf("final run ID is invalid: %w", err)
	}
	for _, artifact := range excerpts[index:] {
		if _, err := ports.ClassifyRunSupportArtifactPath(sessionID, runID, artifact.Path()); err != nil {
			return fmt.Errorf("auxiliary artifact path %q is not canonical: %w", artifact.Path().String(), err)
		}
	}
	return nil
}

func validateBundleSupportIndex(
	artifacts []ports.ImmutablePublicationArtifact,
	identity artifactIdentityWire,
) error {
	var indexArtifact *ports.ImmutablePublicationArtifact
	expected := make(map[string]string, len(artifacts))
	for artifactIndex := range artifacts {
		artifact := &artifacts[artifactIndex]
		if artifact.Path().String() == identity.Path {
			if indexArtifact != nil || artifact.SHA256() != identity.SHA256 {
				return fmt.Errorf("support index identity is invalid")
			}
			indexArtifact = artifact
			continue
		}
		if _, duplicate := expected[artifact.Path().String()]; duplicate {
			return fmt.Errorf("support artifact path is duplicated")
		}
		expected[artifact.Path().String()] = artifact.SHA256()
	}
	if indexArtifact == nil {
		return fmt.Errorf("support index artifact is absent")
	}
	var index runSupportIndexWire
	if err := unmarshalCanonicalPublicationRecord(indexArtifact.Bytes(), &index, "support index"); err != nil {
		return err
	}
	if index.SchemaVersion != "mulgae-run-support-index.v1" || len(index.Artifacts) != len(expected) {
		return fmt.Errorf("support index contents are invalid")
	}
	for _, item := range index.Artifacts {
		digest, ok := expected[item.Path]
		if !ok || digest != item.SHA256 {
			return fmt.Errorf("support index artifact binding is invalid")
		}
		delete(expected, item.Path)
	}
	if len(expected) != 0 {
		return fmt.Errorf("support index omits generated artifacts")
	}
	return nil
}
func validateCommittedSnapshotSemantics(
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
) (domain.OperationalExitCode, error) {
	if !run.Valid() || !snapshot.Valid() {
		return 0, fmt.Errorf("invalid run or committed snapshot")
	}
	final := snapshot.Final()
	if final.Identity().Path().String() != run.SessionID().String()+"/"+run.RunID().String()+"/review_"+final.Identity().ReviewID().String()+".json" {
		return 0, fmt.Errorf("committed final path is not canonical for the observed run")
	}
	return validatePublicationCompositeSemantics(
		final,
		snapshot.Manifest(),
		snapshot.LineageEdge(),
		snapshot.Epoch(),
	)
}

func validateFinalProductionProvenance(final finalReviewWire) error {
	production := final.Provenance.Production
	runType := domain.RunType(final.RunType)
	if runType != domain.RunTypeReview {
		if production != nil {
			return fmt.Errorf("child final review cannot contain production provenance")
		}
		return nil
	}
	if production == nil {
		return nil
	}
	if final.Target.ContentSHA256 == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return fmt.Errorf("no-change final review cannot contain production provenance")
	}
	if production.ObjectivePresent != (production.ObjectiveSHA256 != nil) {
		return fmt.Errorf("production objective presence does not match identity")
	}
	value := ProductionReviewProvenance{
		BuildProduct: production.BuildProduct, BuildVersion: production.BuildVersion, BuildCommit: production.BuildCommit,
		HasObjective: production.ObjectivePresent, SnapshotManifestSHA256: production.SnapshotManifestSHA256,
		WorkspaceTerminalReceipt: production.WorkspaceTerminalReceipt,
		Providers:                make([]ProductionProviderProvenance, len(production.Providers)),
	}
	if production.ObjectiveSHA256 != nil {
		value.ObjectiveSHA256 = *production.ObjectiveSHA256
	}
	for index, provider := range production.Providers {
		value.Providers[index] = ProductionProviderProvenance{
			Family: provider.Family, Instance: provider.Instance, Version: provider.Version,
			Executable: provider.Executable, ExecutableSHA256: provider.ExecutableSHA256,
			Launcher: provider.Launcher, LauncherSHA256: provider.LauncherSHA256,
			ProfileGeneration: provider.ProfileGeneration, AdapterProfile: provider.AdapterProfile,
			QualificationReceiptIDs:   append([]string(nil), provider.QualificationReceiptIDs...),
			PacketTransportReceiptIDs: append([]string(nil), provider.PacketTransportReceiptIDs...),
			NamespaceTerminalReceipt:  provider.NamespaceTerminalReceipt,
		}
	}
	if err := validateProductionReviewProvenance(value); err != nil {
		return fmt.Errorf("final review production provenance: %w", err)
	}
	commit := ""
	if final.Mulgae.Commit != nil {
		commit = *final.Mulgae.Commit
	}
	if final.Mulgae.Version != value.BuildVersion || commit != value.BuildCommit {
		return fmt.Errorf("final review production build metadata does not match Mulgae")
	}
	return nil
}
func validatePublicationCompositeSemantics(
	final ports.FinalReviewArtifact,
	manifestArtifact ports.ImmutablePublicationArtifact,
	lineageArtifact ports.ImmutablePublicationArtifact,
	epoch ports.PublicationEpoch,
) (domain.OperationalExitCode, error) {
	if !final.Valid() || !manifestArtifact.Valid() || !lineageArtifact.Valid() || !epoch.Valid() {
		return 0, fmt.Errorf("invalid immutable publication member")
	}

	var finalWire finalReviewWire
	if err := unmarshalCanonicalPublicationRecord(final.Bytes(), &finalWire, "final review"); err != nil {
		return 0, err
	}
	var manifest runManifestWire
	if err := unmarshalCanonicalPublicationRecord(manifestArtifact.Bytes(), &manifest, "run manifest"); err != nil {
		return 0, err
	}
	var lineage lineageEdgeWire
	if err := unmarshalCanonicalPublicationRecord(lineageArtifact.Bytes(), &lineage, "lineage edge"); err != nil {
		return 0, err
	}
	var epochWire publicationEpochWire
	if err := unmarshalCanonicalPublicationRecord(epoch.Record().Bytes(), &epochWire, "publication epoch"); err != nil {
		return 0, err
	}

	sessionID, err := domain.ParseSessionID(finalWire.SessionID)
	if err != nil {
		return 0, fmt.Errorf("final review session ID: %w", err)
	}
	runID, err := domain.ParseRunID(finalWire.RunID)
	if err != nil {
		return 0, fmt.Errorf("final review run ID: %w", err)
	}
	reviewID, err := domain.ParseReviewID(finalWire.ReviewID)
	if err != nil {
		return 0, fmt.Errorf("final review ID: %w", err)
	}
	paths, err := publicationPaths(sessionID, runID, reviewID, epoch.Value())
	if err != nil {
		return 0, err
	}
	if finalWire.SchemaVersion != "mulgae-review-artifact.v1" ||
		!domain.RunType(finalWire.RunType).Valid() ||
		final.Identity().ReviewID() != reviewID ||
		final.Identity().Path() != paths.final ||
		finalWire.PublicationStatus != string(domain.PublicationCommitted) ||
		(finalWire.Validation.Status != "valid" && finalWire.Validation.Status != "repaired_valid") ||
		finalWire.Validation.SchemaValidation != "passed" ||
		finalWire.Validation.SemanticValidation != "passed" ||
		finalWire.Validation.EvidenceValidation != "passed" ||
		finalWire.Target.ManifestPath != targetManifestPath ||
		!validSHA256(finalWire.Target.ContentSHA256) ||
		!domain.ContentVerdict(finalWire.ContentVerdict).Valid() ||
		!domain.CoverageStatus(finalWire.CoverageStatus).Valid() ||
		!domain.CIDecision(finalWire.CIDecision).Valid() ||
		finalWire.Provenance.AggregationPath != aggregationPath ||
		finalWire.Provenance.FinalValidationPath != finalValidationPath ||
		finalWire.Provenance.ManifestPath != "manifest.json" {
		return 0, fmt.Errorf("final review has invalid publication semantics")
	}
	mulgaeCommit := ""
	if finalWire.Mulgae.Commit != nil {
		mulgaeCommit = *finalWire.Mulgae.Commit
	}
	if err := validateBuildMetadata(finalWire.Mulgae.Version, mulgaeCommit); err != nil ||
		(finalWire.Mulgae.Commit != nil && mulgaeCommit == "") ||
		(finalWire.Target.BaseOID != nil &&
			(*finalWire.Target.BaseOID == "" || !validOptionalOID(*finalWire.Target.BaseOID))) ||
		(finalWire.Target.HeadOID != nil &&
			(*finalWire.Target.HeadOID == "" || !validOptionalOID(*finalWire.Target.HeadOID))) {
		return 0, fmt.Errorf("final review build metadata or target identity is invalid")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, finalWire.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("final review creation time: %w", err)
	}
	canonicalCreatedAt, err := canonicalTime(createdAt)
	if err != nil || canonicalCreatedAt != finalWire.CreatedAt {
		return 0, fmt.Errorf("final review creation time is not canonical")
	}
	if err := validateReasonCodes(finalWire.CIReasonCodes); err != nil {
		return 0, fmt.Errorf("final review CI reasons: %w", err)
	}
	if err := validatePublicationLineage(
		domain.RunType(finalWire.RunType), finalWire.ImmutableLineage, lineage, lineageArtifact, sessionID, runID, reviewID,
	); err != nil {
		return 0, fmt.Errorf("final review lineage: %w", err)
	}
	if err := validateFinalProductionProvenance(finalWire); err != nil {
		return 0, err
	}
	content, coverage, ci, err := validateFinalOutcomeSemantics(domain.RunType(finalWire.RunType), finalWire.ImmutableLineage.ReplayMode, finalWire)
	if err != nil {
		return 0, err
	}
	if err := validateFinalReportSemantics(finalWire, content, coverage, ci); err != nil {
		return 0, err
	}

	if manifest.SchemaVersion != "mulgae-run-manifest.v1" ||
		manifest.SessionID != finalWire.SessionID ||
		manifest.RunID != finalWire.RunID ||
		manifest.RunType != finalWire.RunType ||
		(manifest.State != string(domain.RunCompleted) &&
			manifest.State != string(domain.RunDegraded) &&
			manifest.State != string(domain.RunFailed)) ||
		!manifest.Sealed ||
		manifest.CreatedAt != finalWire.CreatedAt ||
		manifest.StartedAt == nil || *manifest.StartedAt != finalWire.CreatedAt ||
		manifest.CompletedAt == nil || *manifest.CompletedAt != finalWire.CreatedAt ||
		manifest.MulgaeVersion != finalWire.Mulgae.Version ||
		!reflect.DeepEqual(manifest.ImmutableLineage, finalWire.ImmutableLineage) ||
		manifest.Target.ManifestPath != finalWire.Target.ManifestPath ||
		manifest.Target.ContentSHA256 != finalWire.Target.ContentSHA256 ||
		manifest.ContentVerdict != string(content) ||
		manifest.CoverageStatus != string(coverage) ||
		manifest.PublicationStatus != string(domain.PublicationCommitted) ||
		manifest.CIDecision != string(ci) ||
		!reflect.DeepEqual(manifest.CIReasonCodes, finalWire.CIReasonCodes) ||
		manifest.PersistedJournalState != string(domain.JournalManifestCommitted) ||
		manifest.DurableObservationClass != string(domain.DurableObservationP2Committed) ||
		manifest.DerivedPublicationStatus != string(domain.PublicationCommitted) ||
		manifest.PublicationAuthority != string(domain.PublicationAuthorityP2) ||
		manifest.RecoveryAction != string(domain.RecoveryActionReconstructCompletedStatus) ||
		manifest.FinalReview.ReviewID != reviewID.String() ||
		manifest.FinalReview.Path != final.Identity().Path().String() ||
		manifest.FinalReview.SHA256 != final.Identity().SHA256() ||
		manifest.RecoveryJournal.ExpectedStaged.Path != paths.staged.String() ||
		manifest.RecoveryJournal.ExpectedStaged.SHA256 != final.Identity().SHA256() ||
		manifest.RecoveryJournal.ExpectedFinal.Path != final.Identity().Path().String() ||
		manifest.RecoveryJournal.ExpectedFinal.SHA256 != final.Identity().SHA256() ||
		!validSHA256(manifest.RecoveryJournal.ValidatedCandidateSHA256) ||
		manifest.CompositeIdentity.Manifest.Path != manifestArtifact.Path().String() ||
		manifest.CompositeIdentity.LineageEdge.Path != lineageArtifact.Path().String() ||
		manifest.CompositeIdentity.LineageEdge.SHA256 != lineageArtifact.SHA256() ||
		manifest.CompositeIdentity.Epoch.Path != epoch.Record().Path().String() ||
		manifest.CompositeIdentity.SupportIndex.Path != paths.supportIndex.String() ||
		!validSHA256(manifest.CompositeIdentity.SupportIndex.SHA256) {
		return 0, fmt.Errorf("manifest does not match the final review and immutable composite")
	}
	repaired, err := validateManifestRoleBindings(manifest, finalWire)
	if err != nil {
		return 0, err
	}
	expectedValidationStatus := "valid"
	if repaired {
		expectedValidationStatus = "repaired_valid"
	}
	if finalWire.Validation.Status != expectedValidationStatus {
		return 0, fmt.Errorf("final review validation status does not match repaired attempt facts")
	}

	normalExit := normalExitForPublicationAxes(coverage, ci)
	if manifest.ExitCode != int(normalExit) {
		return 0, fmt.Errorf("manifest normal exit does not match final outcome axes")
	}
	if epochWire.SchemaVersion != publicationEpochV1 ||
		epochWire.StoreEpoch != epoch.Value() ||
		epoch.Record().Path() != paths.epoch ||
		epochWire.Manifest.Path != manifestArtifact.Path().String() ||
		epochWire.Manifest.SHA256 != manifestArtifact.SHA256() ||
		epochWire.LineageEdge.Path != lineageArtifact.Path().String() ||
		epochWire.LineageEdge.SHA256 != lineageArtifact.SHA256() ||
		epochWire.FinalReview.Path != final.Identity().Path().String() ||
		epochWire.FinalReview.SHA256 != final.Identity().SHA256() {
		return 0, fmt.Errorf("epoch does not bind the exact immutable composite")
	}
	return normalExit, nil
}

func unmarshalCanonicalPublicationRecord(data []byte, value any, name string) error {
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	canonical, err := marshalCanonical(value)
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", name, err)
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("%s is not canonical", name)
	}
	return nil
}

func validatePublicationLineage(
	runType domain.RunType,
	lineage immutableLineageWire,
	edge lineageEdgeWire,
	edgeArtifact ports.ImmutablePublicationArtifact,
	sessionID domain.SessionID,
	runID domain.RunID,
	reviewID domain.ReviewID,
) error {
	expectedPath := mustPublicationPath("store/lineage-edges/e_" + reviewID.String() + ".json")
	if edgeArtifact.Path() != expectedPath ||
		lineage.LineageEdgePath != edgeArtifact.Path().String() || lineage.LineageEdgeSHA256 != edgeArtifact.SHA256() {
		return fmt.Errorf("lineage does not bind the canonical immutable edge")
	}
	if edge.SchemaVersion != lineageEdgeV1 || edge.EdgeID != "e_"+reviewID.String() ||
		edge.Child.SessionID != sessionID.String() || edge.Child.RunID != runID.String() || edge.Child.ReviewID != reviewID.String() ||
		!reflect.DeepEqual(edge.ParentRunID, lineage.ParentRunID) ||
		!reflect.DeepEqual(edge.SourceRunID, lineage.SourceRunID) ||
		!reflect.DeepEqual(edge.SourceReviewID, lineage.SourceReviewID) ||
		!reflect.DeepEqual(edge.SourceFindingRef, lineage.SourceFindingRef) ||
		!reflect.DeepEqual(edge.ReplayMode, lineage.ReplayMode) {
		return fmt.Errorf("lineage edge does not match final lineage")
	}
	context := RunPublicationContext{lineage: preparedLineage{runType: runType}}
	if lineage.ParentRunID != nil {
		value, err := domain.ParseRunID(*lineage.ParentRunID)
		if err != nil {
			return fmt.Errorf("parent run ID: %w", err)
		}
		context.lineage.parentRunID = &value
	}
	if lineage.SourceRunID != nil {
		value, err := domain.ParseRunID(*lineage.SourceRunID)
		if err != nil {
			return fmt.Errorf("source run ID: %w", err)
		}
		context.lineage.sourceRunID = &value
	}
	if lineage.SourceReviewID != nil {
		value, err := domain.ParseReviewID(*lineage.SourceReviewID)
		if err != nil {
			return fmt.Errorf("source review ID: %w", err)
		}
		context.lineage.sourceReviewID = &value
	}
	context.lineage.sourceFindingRef = cloneOptionalString(lineage.SourceFindingRef)
	if lineage.ReplayMode != nil {
		value := ReplayMode(*lineage.ReplayMode)
		context.lineage.replayMode = &value
	}
	return context.validate()
}

func validateFinalOutcomeSemantics(runType domain.RunType, replayMode *string, final finalReviewWire) (domain.ContentVerdict, domain.CoverageStatus, domain.CIDecision, error) {
	threshold := domain.Severity(final.SeverityThreshold.RequestChangesAtOrAbove)
	if !threshold.Valid() || final.SeverityThreshold.PolicySource != "project_local" {
		return "", "", "", fmt.Errorf("final review severity threshold is invalid")
	}
	roles := make([]domain.RoleResultSummary, len(final.RoleOutcomes))
	seenRoles := make(map[domain.Role]struct{}, len(final.RoleOutcomes))
	for index, role := range final.RoleOutcomes {
		parsedRole := domain.Role(role.Role)
		if !parsedRole.Valid() ||
			(index > 0 && roleOrdinal(domain.Role(final.RoleOutcomes[index-1].Role)) >= roleOrdinal(parsedRole)) {
			return "", "", "", fmt.Errorf("final review role outcomes are invalid or unordered")
		}
		if _, duplicate := seenRoles[parsedRole]; duplicate {
			return "", "", "", fmt.Errorf("final review role outcomes are duplicated")
		}
		seenRoles[parsedRole] = struct{}{}
		if !validReasonPointer(role.FailureReason) ||
			validateStringSlice(role.ValidFindingIDs, 1000, 64, true) != nil ||
			validateStringSlice(role.Limitations, 20, 2000, true) != nil {
			return "", "", "", fmt.Errorf("final review role outcome %q is malformed", role.Role)
		}
		if role.Outcome == "skipped" || role.Outcome == "not_applicable" {
			if role.AttemptID != nil || role.ProviderInstance != nil || role.SelectedVia != nil ||
				len(role.ValidFindingIDs) != 0 || role.FailureReason != nil {
				return "", "", "", fmt.Errorf("non-attempt role outcome %q has attempt-owned content", role.Role)
			}
			roles[index] = domain.RoleResultSummary{
				Role: parsedRole, Selected: true, Required: role.Required, Valid: role.Outcome == "not_applicable",
			}
			continue
		}
		if role.Outcome != "completed" && role.Outcome != "degraded" && role.Outcome != "failed" {
			return "", "", "", fmt.Errorf("final review role outcome %q is invalid", role.Outcome)
		}
		if role.AttemptID == nil || role.ProviderInstance == nil || role.SelectedVia == nil ||
			!validProviderInstance(*role.ProviderInstance) || !review.AttemptKind(*role.SelectedVia).Valid() {
			return "", "", "", fmt.Errorf("final review role outcome %q has no valid attempt binding", role.Role)
		}
		if _, err := domain.ParseAttemptID(*role.AttemptID); err != nil {
			return "", "", "", fmt.Errorf("final review role outcome %q attempt ID: %w", role.Role, err)
		}
		if role.Outcome == "failed" && role.FailureReason == nil {
			return "", "", "", fmt.Errorf("failed role outcome omits its failure reason")
		}
		if role.Outcome != "failed" && role.FailureReason != nil {
			return "", "", "", fmt.Errorf("successful role outcome carries a failure reason")
		}
		roles[index] = domain.RoleResultSummary{
			Role:     parsedRole,
			Selected: true,
			Required: role.Required,
			Valid:    role.Outcome != "failed",
			Degraded: role.Outcome == "degraded",
		}
	}
	var coverage domain.CoverageStatus
	if runType == domain.RunTypeFollowup ||
		(runType == domain.RunTypeRerun && replayMode != nil && *replayMode == string(ReplayModeRecompose)) {
		coverage = coverageForSelectedFinalRoles(roles)
	} else {
		axes, err := domain.ComputeOutcomeAxes(nil, roles, threshold, domain.PublicationCommitted, nil)
		if err != nil {
			return "", "", "", fmt.Errorf("final review coverage: %w", err)
		}
		coverage = axes.CoverageStatus()
	}
	content := domain.ContentNoFindings
	for _, finding := range final.Findings {
		severity := domain.Severity(finding.Severity)
		if !severity.Valid() {
			return "", "", "", fmt.Errorf("final review finding severity is invalid")
		}
		if content == domain.ContentNoFindings {
			content = domain.ContentFindingsPresent
		}
		if severity.Rank() >= threshold.Rank() {
			content = domain.ContentRequestChanges
		}
	}
	if runType == domain.RunTypeFollowup && final.FollowupOutcome != nil &&
		final.FollowupOutcome.Resolution == string(domain.FollowupStillOpen) {
		content = domain.ContentRequestChanges
	}
	ci := domain.CIPass
	if content == domain.ContentRequestChanges || coverage != domain.CoverageComplete {
		ci = domain.CIFail
	}
	if domain.ContentVerdict(final.ContentVerdict) != content ||
		domain.CoverageStatus(final.CoverageStatus) != coverage ||
		domain.CIDecision(final.CIDecision) != ci {
		return "", "", "", fmt.Errorf("final review outcome axes are inconsistent")
	}
	return content, coverage, ci, nil
}
func coverageForSelectedFinalRoles(roles []domain.RoleResultSummary) domain.CoverageStatus {
	coverage := domain.CoverageComplete
	for _, role := range roles {
		if !role.Valid {
			return domain.CoverageIncomplete
		}
		if role.Degraded {
			coverage = domain.CoverageDegraded
		}
	}
	return coverage
}

func validateFinalReportSemantics(
	final finalReviewWire,
	content domain.ContentVerdict,
	coverage domain.CoverageStatus,
	ci domain.CIDecision,
) error {
	expectedReasons := ciReasonCodesForPublicationAxes(content, coverage)
	if !reflect.DeepEqual(final.CIReasonCodes, expectedReasons) {
		return fmt.Errorf("final review CI reasons do not match publication axes")
	}
	if ci != domain.CIPass && len(expectedReasons) == 0 {
		return fmt.Errorf("final review failing CI omits reasons")
	}
	expectedLimitations := publicationLimitationsForCoverage(coverage)
	if !reflect.DeepEqual(final.Limitations, expectedLimitations) {
		return fmt.Errorf("final review limitations do not match coverage")
	}
	return validateFinalFindingBindings(final)
}

func ciReasonCodesForPublicationAxes(
	content domain.ContentVerdict,
	coverage domain.CoverageStatus,
) []string {
	reasons := make([]string, 0, 2)
	if content == domain.ContentRequestChanges {
		reasons = append(reasons, "request_changes_threshold")
	}
	switch coverage {
	case domain.CoverageIncomplete:
		reasons = append(reasons, "required_role_incomplete")
	case domain.CoverageDegraded:
		reasons = append(reasons, "degraded_coverage")
	}
	if len(reasons) == 0 {
		return []string{"policy_evaluated"}
	}
	return reasons
}

func publicationLimitationsForCoverage(coverage domain.CoverageStatus) []string {
	switch coverage {
	case domain.CoverageIncomplete:
		return []string{"Required review coverage is incomplete."}
	case domain.CoverageDegraded:
		return []string{"Review coverage is degraded."}
	default:
		return []string{}
	}
}

func roleLimitationsForOutcome(outcome string) ([]string, error) {
	switch outcome {
	case "completed":
		return []string{}, nil
	case "degraded":
		return []string{"Role coverage is degraded."}, nil
	case "failed":
		return []string{"Role coverage is incomplete due to a terminal provider failure."}, nil
	case "not_applicable":
		return []string{"No Git changes were captured."}, nil
	default:
		return nil, fmt.Errorf("unknown role outcome %q", outcome)
	}
}

func validateFinalFindingBindings(final finalReviewWire) error {
	roleByName := make(map[string]roleOutcomeWire, len(final.RoleOutcomes))
	expectedFindingIDs := make(map[string][]string, len(final.RoleOutcomes))
	for _, role := range final.RoleOutcomes {
		roleByName[role.Role] = role
		expectedFindingIDs[role.Role] = []string{}
	}
	for index, finding := range final.Findings {
		expectedID := fmt.Sprintf("F%03d", index+1)
		if finding.ID != expectedID ||
			!validSHA256(finding.Fingerprint) ||
			!domain.Severity(finding.Severity).Valid() ||
			!domain.Confidence(finding.Confidence).Valid() ||
			!domain.FindingLifecycle(finding.Lifecycle).Valid() ||
			!safeText(finding.Title, 300, true) ||
			!safeText(finding.Description, 12000, false) ||
			!safeText(finding.Recommendation, 12000, false) ||
			len(finding.Evidence) == 0 || len(finding.Evidence) > 20 {
			return fmt.Errorf("final finding %q is invalid", finding.ID)
		}
		role, ok := roleByName[finding.Role]
		if !ok || (role.Outcome != "completed" && role.Outcome != "degraded") ||
			role.ProviderInstance == nil || *role.ProviderInstance != finding.ProviderInstance ||
			!validProviderInstance(finding.ProviderInstance) {
			return fmt.Errorf("final finding %q does not bind to a valid role outcome", finding.ID)
		}
		for evidenceIndex, item := range finding.Evidence {
			followupSource := final.RunType == string(domain.RunTypeFollowup)
			sourceValid := item.Source.SessionID == final.SessionID &&
				item.Source.RunID == final.RunID &&
				item.Source.ReviewID == final.ReviewID &&
				item.Source.FindingID == finding.ID &&
				item.Source.SourceTargetSHA256 == final.Target.ContentSHA256
			if followupSource {
				sourceValid = final.ImmutableLineage.SourceRunID != nil && final.ImmutableLineage.SourceReviewID != nil &&
					final.ImmutableLineage.SourceFindingRef != nil &&
					item.Source.SessionID == final.SessionID &&
					item.Source.RunID == *final.ImmutableLineage.SourceRunID &&
					item.Source.ReviewID == *final.ImmutableLineage.SourceReviewID &&
					item.Source.FindingID == *final.ImmutableLineage.SourceFindingRef &&
					validSHA256(item.Source.SourceTargetSHA256)
			}
			if !sourceValid ||
				!validSHA256(item.Source.SourceExcerptSHA256) ||
				item.Current.TargetSHA256 != final.Target.ContentSHA256 ||
				!evidence.Side(item.Current.Side).Valid() ||
				!safePath(item.Current.Path) ||
				item.Current.LineStart < 1 ||
				item.Current.LineEnd < item.Current.LineStart ||
				!safeText(item.Current.Quote, 8000, false) ||
				!validSHA256(item.Current.CurrentExcerptSHA256) ||
				item.Current.Verification != "verified" {
				return fmt.Errorf("final finding %q evidence %d is invalid", finding.ID, evidenceIndex)
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
				return fmt.Errorf("final finding %q evidence %d claim: %w", finding.ID, evidenceIndex, err)
			}
			currentExcerptSHA256, err := claim.ExcerptSHA256([]byte(item.Current.Quote))
			if err != nil || currentExcerptSHA256 != item.Current.CurrentExcerptSHA256 {
				return fmt.Errorf("final finding %q evidence %d current excerpt identity is invalid", finding.ID, evidenceIndex)
			}
		}
		expectedFindingIDs[finding.Role] = append(expectedFindingIDs[finding.Role], finding.ID)
	}
	for _, role := range final.RoleOutcomes {
		if !reflect.DeepEqual(role.ValidFindingIDs, expectedFindingIDs[role.Role]) {
			return fmt.Errorf("final role outcome %q finding IDs do not match findings", role.Role)
		}
	}
	return nil
}

func validateManifestRoleBindings(manifest runManifestWire, final finalReviewWire) (bool, error) {
	if len(manifest.SelectedRoles) != len(final.RoleOutcomes) {
		return false, fmt.Errorf("manifest selected roles do not match final role outcomes")
	}
	selected := make(map[string]int, len(manifest.SelectedRoles))
	for index, role := range manifest.SelectedRoles {
		if !domain.Role(role).Valid() {
			return false, fmt.Errorf("manifest selected role %q is invalid", role)
		}
		if _, duplicate := selected[role]; duplicate {
			return false, fmt.Errorf("manifest selected role %q is duplicated", role)
		}
		if index > 0 && roleOrdinal(domain.Role(manifest.SelectedRoles[index-1])) >= roleOrdinal(domain.Role(role)) {
			return false, fmt.Errorf("manifest selected roles are not ordered")
		}
		selected[role] = index
	}
	lastAttemptByRole := make(map[string]manifestAttemptWire, len(manifest.SelectedRoles))
	attemptCountByRole := make(map[string]int, len(manifest.SelectedRoles))
	seenAttempts := make(map[string]struct{}, len(manifest.Attempts))
	lastRoleIndex := -1
	repaired := false
	for _, attempt := range manifest.Attempts {
		if _, err := domain.ParseAttemptID(attempt.AttemptID); err != nil ||
			!domain.Role(attempt.Role).Valid() ||
			!validProviderInstance(attempt.ProviderInstance) ||
			!review.AttemptKind(attempt.SelectedAs).Valid() ||
			!domain.AttemptState(attempt.State).Valid() ||
			!terminalAttemptState(domain.AttemptState(attempt.State)) ||
			attempt.Path != "attempts/"+attempt.AttemptID+"/status.json" ||
			attempt.InvocationCount < 1 {
			return false, fmt.Errorf("manifest attempt %q is invalid", attempt.AttemptID)
		}
		if _, duplicate := seenAttempts[attempt.AttemptID]; duplicate {
			return false, fmt.Errorf("manifest attempt %q is duplicated", attempt.AttemptID)
		}
		roleIndex, exists := selected[attempt.Role]
		if !exists || roleIndex < lastRoleIndex {
			return false, fmt.Errorf("manifest attempt %q has unordered or unselected role", attempt.AttemptID)
		}
		lastRoleIndex = roleIndex
		switch attemptCountByRole[attempt.Role] {
		case 0:
			if attempt.SelectedAs != string(review.AttemptKindPrimary) {
				return false, fmt.Errorf("manifest role %q does not begin with a primary attempt", attempt.Role)
			}
		case 1:
			previous := lastAttemptByRole[attempt.Role]
			if attempt.SelectedAs != string(review.AttemptKindFallback) ||
				previous.State == string(domain.AttemptSucceeded) {
				return false, fmt.Errorf("manifest role %q has a non-canonical fallback", attempt.Role)
			}
		default:
			return false, fmt.Errorf("manifest role %q has more than primary and fallback attempts", attempt.Role)
		}
		attemptCountByRole[attempt.Role]++
		if attempt.State == string(domain.AttemptSucceeded) {
			if attempt.ParseState != "valid" ||
				(attempt.ValidationState != "valid" && attempt.ValidationState != "repaired_valid") {
				return false, fmt.Errorf("successful manifest attempt %q has invalid validation facts", attempt.AttemptID)
			}
			repaired = repaired || attempt.ValidationState == "repaired_valid"
		} else if attempt.ParseState != "not_started" || attempt.ValidationState != "not_started" {
			return false, fmt.Errorf("failed manifest attempt %q has invalid validation facts", attempt.AttemptID)
		}
		seenAttempts[attempt.AttemptID] = struct{}{}
		lastAttemptByRole[attempt.Role] = attempt
	}

	required := make([]string, 0, len(final.RoleOutcomes))
	failedAny := false
	for index, outcome := range final.RoleOutcomes {
		if manifest.SelectedRoles[index] != outcome.Role {
			return false, fmt.Errorf("manifest selected role %d does not match final role outcome", index)
		}
		role := domain.Role(outcome.Role)
		if !role.Valid() || role == domain.RoleLogic && !outcome.Required {
			return false, fmt.Errorf("final role outcome %q has invalid required policy", outcome.Role)
		}
		expectedLimitations, err := roleLimitationsForOutcome(outcome.Outcome)
		if err != nil || !reflect.DeepEqual(outcome.Limitations, expectedLimitations) {
			return false, fmt.Errorf("final role outcome %q limitations are inconsistent", outcome.Role)
		}
		if outcome.Required {
			required = append(required, outcome.Role)
		}
		if outcome.Outcome == "not_applicable" {
			if outcome.AttemptID != nil || outcome.ProviderInstance != nil || outcome.SelectedVia != nil ||
				outcome.FailureReason != nil || attemptCountByRole[outcome.Role] != 0 {
				return false, fmt.Errorf("not-applicable role outcome %q has attempt-owned content", outcome.Role)
			}
			continue
		}
		attempt, ok := lastAttemptByRole[outcome.Role]
		if !ok || outcome.AttemptID == nil || outcome.ProviderInstance == nil || outcome.SelectedVia == nil ||
			attempt.AttemptID != *outcome.AttemptID ||
			attempt.ProviderInstance != *outcome.ProviderInstance ||
			attempt.SelectedAs != *outcome.SelectedVia {
			return false, fmt.Errorf("manifest final attempt does not match role outcome %q", outcome.Role)
		}
		switch outcome.Outcome {
		case "completed", "degraded":
			if attempt.State != string(domain.AttemptSucceeded) || outcome.FailureReason != nil {
				return false, fmt.Errorf("successful role outcome %q has inconsistent manifest attempt", outcome.Role)
			}
		case "failed":
			if attempt.State == string(domain.AttemptSucceeded) || outcome.FailureReason == nil ||
				!validReasonCode(*outcome.FailureReason) {
				return false, fmt.Errorf("failed role outcome %q has inconsistent manifest attempt", outcome.Role)
			}
			failedAny = true
		default:
			return false, fmt.Errorf("unknown role outcome %q", outcome.Outcome)
		}
	}
	if !reflect.DeepEqual(manifest.RequiredRoles, required) {
		return false, fmt.Errorf("manifest required roles do not match final role outcomes")
	}
	if err := validateManifestFailures(manifest, final.RoleOutcomes); err != nil {
		return false, err
	}
	if len(manifest.Warnings) != 0 {
		return false, fmt.Errorf("G006 manifest must not contain warnings")
	}
	switch manifest.State {
	case string(domain.RunCompleted):
		if failedAny {
			return false, fmt.Errorf("completed manifest has a failed role outcome")
		}
	case string(domain.RunDegraded):
		if !failedAny {
			return false, fmt.Errorf("degraded manifest has inconsistent failed role outcomes")
		}
	case string(domain.RunFailed):
		if !failedAny || manifest.CoverageStatus != string(domain.CoverageIncomplete) {
			return false, fmt.Errorf("failed manifest has inconsistent failed role outcomes")
		}
	}
	return repaired, nil
}

func validateManifestFailures(manifest runManifestWire, outcomes []roleOutcomeWire) error {
	failedAttemptIDs := make([]string, 0, len(manifest.Attempts))
	failedAttemptStates := make(map[string]domain.AttemptState, len(manifest.Attempts))
	for _, attempt := range manifest.Attempts {
		state := domain.AttemptState(attempt.State)
		if state != domain.AttemptSucceeded {
			failedAttemptIDs = append(failedAttemptIDs, attempt.AttemptID)
			failedAttemptStates[attempt.AttemptID] = state
		}
	}
	if len(manifest.Failures) != len(failedAttemptIDs) {
		return fmt.Errorf("manifest failures do not match failed terminal attempts")
	}
	failedRoleReasons := make(map[string]string)
	for _, outcome := range outcomes {
		if outcome.Outcome == "failed" && outcome.AttemptID != nil && outcome.FailureReason != nil {
			failedRoleReasons[*outcome.AttemptID] = *outcome.FailureReason
		}
	}
	seen := make(map[string]struct{}, len(manifest.Failures))
	for index, failure := range manifest.Failures {
		if !domain.FailureClass(failure.Class).Valid() ||
			forbiddenPublicationFailure(domain.FailureClass(failure.Class)) ||
			failure.Stage != "review" ||
			failure.AttemptID == nil ||
			!validReasonCode(failure.ReasonCode) {
			return fmt.Errorf("manifest failure is invalid")
		}
		if _, err := domain.ParseAttemptID(*failure.AttemptID); err != nil {
			return fmt.Errorf("manifest failure attempt ID: %w", err)
		}
		if *failure.AttemptID != failedAttemptIDs[index] {
			return fmt.Errorf("manifest failures are not in canonical failed-attempt order")
		}
		state, ok := failedAttemptStates[*failure.AttemptID]
		if !ok {
			return fmt.Errorf("manifest failure does not bind a failed terminal attempt")
		}
		class := domain.FailureClass(failure.Class)
		if (state == domain.AttemptTimedOut) != (class == domain.FailureTimeout) {
			return fmt.Errorf("manifest failure class does not match attempt state")
		}
		if failedRoleReason, ok := failedRoleReasons[*failure.AttemptID]; ok && failedRoleReason != failure.ReasonCode {
			return fmt.Errorf("manifest failure does not match failed role outcome")
		}
		if _, duplicate := seen[*failure.AttemptID]; duplicate {
			return fmt.Errorf("manifest failure attempt ID is duplicated")
		}
		if manifest.State == string(domain.RunFailed) &&
			!domain.FailureClass(failure.Class).FallbackAllowed() {
			return fmt.Errorf("failed manifest contains non-fallback-eligible failure")
		}
		seen[*failure.AttemptID] = struct{}{}
	}
	return nil
}

func validateRestartStateSemantics(
	restart restartStateWire,
	expectedState domain.PersistedJournalState,
	normalExit domain.OperationalExitCode,
	final ports.FinalReviewIdentity,
	manifest ports.ImmutablePublicationArtifact,
	lineage ports.ImmutablePublicationArtifact,
	epoch ports.PublicationEpoch,
) error {
	sessionID, err := domain.ParseSessionID(restart.SessionID)
	if err != nil {
		return fmt.Errorf("session ID: %w", err)
	}
	runID, err := domain.ParseRunID(restart.RunID)
	if err != nil {
		return fmt.Errorf("run ID: %w", err)
	}
	paths, err := publicationPaths(sessionID, runID, final.ReviewID(), epoch.Value())
	if err != nil {
		return err
	}
	var manifestWire runManifestWire
	if err := unmarshalCanonicalPublicationRecord(manifest.Bytes(), &manifestWire, "run manifest"); err != nil {
		return err
	}
	if paths.final != final.Path() ||
		restart.PersistedJournalState != string(expectedState) ||
		restart.ExpectedStaged.Path != paths.staged.String() ||
		restart.ExpectedStaged.SHA256 != final.SHA256() ||
		restart.ExpectedFinal.Path != final.Path().String() ||
		restart.ExpectedFinal.SHA256 != final.SHA256() ||
		!validSHA256(restart.ValidatedCandidateSHA256) ||
		restart.ValidatedCandidateSHA256 != manifestWire.RecoveryJournal.ValidatedCandidateSHA256 ||
		restart.StoreEpoch != epoch.Value() ||
		restart.NormalExit != int(normalExit) ||
		restart.ManifestPath != manifest.Path().String() ||
		restart.LineageEdgePath != lineage.Path().String() ||
		restart.EpochPath != epoch.Record().Path().String() {
		return fmt.Errorf("restart state does not match the immutable composite")
	}
	return nil
}

func normalExitForPublicationAxes(coverage domain.CoverageStatus, ci domain.CIDecision) domain.OperationalExitCode {
	if coverage == domain.CoverageIncomplete {
		return domain.ExitIncompleteCoverage
	}
	if ci == domain.CIFail {
		return domain.ExitCommittedCIRejected
	}
	return domain.ExitCommittedPass
}

func validReasonPointer(value *string) bool {
	return value == nil || validReasonCode(*value)
}

func roleOrdinal(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if candidate == role {
			return index
		}
	}
	return -1
}
func terminalRoleState(state domain.RoleTaskState) bool {
	return state == domain.RoleTaskSucceeded || state == domain.RoleTaskFailed
}

func terminalAttemptState(state domain.AttemptState) bool {
	return state == domain.AttemptSucceeded || state == domain.AttemptFailed || state == domain.AttemptTimedOut ||
		state == domain.AttemptCancelled || state == domain.AttemptBlocked
}

func terminalInvocationState(state domain.InvocationState) bool {
	return state == domain.InvocationSucceeded || state == domain.InvocationFailed || state == domain.InvocationTimedOut ||
		state == domain.InvocationCancelled || state == domain.InvocationBlocked
}

func forbiddenPublicationFailure(class domain.FailureClass) bool {
	switch class {
	case domain.FailureSecurityPolicy, domain.FailureConfiguration, domain.FailureArtifact, domain.FailureInternal, domain.FailureCancelled:
		return true
	default:
		return false
	}
}

func clonePreparedRoles(source []preparedRole) []preparedRole {
	cloned := make([]preparedRole, len(source))
	for index, role := range source {
		cloned[index] = role
		cloned[index].attempts = clonePreparedAttempts(role.attempts)
		cloned[index].validFindingIDs = append([]string(nil), role.validFindingIDs...)
		cloned[index].limitations = append([]string(nil), role.limitations...)
	}
	return cloned
}

func clonePreparedAttempts(source []preparedAttempt) []preparedAttempt {
	cloned := make([]preparedAttempt, len(source))
	for index, attempt := range source {
		cloned[index] = attempt
		cloned[index].invocations = clonePreparedInvocations(attempt.invocations)
	}
	return cloned
}
func clonePreparedInvocations(source []preparedInvocation) []preparedInvocation {
	cloned := make([]preparedInvocation, len(source))
	for index, invocation := range source {
		cloned[index] = invocation
		cloned[index].artifacts = make([]preparedAttemptArtifact, len(invocation.artifacts))
		for artifactIndex, artifact := range invocation.artifacts {
			cloned[index].artifacts[artifactIndex] = artifact
			cloned[index].artifacts[artifactIndex].bytes = cloneBytes(artifact.bytes)
		}
		if invocation.runtime != nil {
			runtime := *invocation.runtime
			runtime.target = cloneBytes(invocation.runtime.target)
			runtime.stdin = cloneBytes(invocation.runtime.stdin)
			runtime.adapterParameters = make(map[string]string, len(invocation.runtime.adapterParameters))
			for key, value := range invocation.runtime.adapterParameters {
				runtime.adapterParameters[key] = value
			}
			cloned[index].runtime = &runtime
		}
	}
	return cloned
}

func clonePreparedFindings(source []preparedFinding) []preparedFinding {
	cloned := make([]preparedFinding, len(source))
	for index, finding := range source {
		cloned[index] = finding
		cloned[index].evidence = make([]preparedEvidence, len(finding.evidence))
		for evidenceIndex, item := range finding.evidence {
			cloned[index].evidence[evidenceIndex] = item
			cloned[index].evidence[evidenceIndex].excerpt = cloneBytes(item.excerpt)
			if item.visual != nil {
				visual := *item.visual
				cloned[index].evidence[evidenceIndex].visual = &visual
			}
		}
	}
	return cloned
}

func clonePreparedFailures(source []preparedFailure) []preparedFailure {
	cloned := make([]preparedFailure, len(source))
	for index, failure := range source {
		cloned[index] = failure
		if failure.attemptID != nil {
			attemptID := *failure.attemptID
			cloned[index].attemptID = &attemptID
		}
	}
	return cloned
}

func cloneBytes(source []byte) []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source...)
}

func sha256Identifier(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nilSchemaValidator(validator SchemaValidator) bool {
	if validator == nil {
		return true
	}
	value := reflect.ValueOf(validator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func canonicalTime(value time.Time) (string, error) {
	if value.IsZero() {
		return "", fmt.Errorf("publication build: created time is required")
	}
	return value.UTC().Format(time.RFC3339Nano), nil
}
