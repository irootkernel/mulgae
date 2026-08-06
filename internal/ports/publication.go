package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ErrPublicationRunNotFound distinguishes an absent manifest-backed run from
// a corrupt or unsafe publication namespace.
var ErrPublicationRunNotFound = errors.New("publication run not found")

// PublicationRun identifies one run beneath an approved artifact root.
type PublicationRun struct {
	root      AnchoredRoot
	sessionID domain.SessionID
	runID     domain.RunID
}

// NewPublicationRun validates immutable publication scope.
func NewPublicationRun(root AnchoredRoot, sessionID domain.SessionID, runID domain.RunID) (PublicationRun, error) {
	run := PublicationRun{root: root, sessionID: sessionID, runID: runID}
	if err := run.validate(); err != nil {
		return PublicationRun{}, fmt.Errorf("publication run: %w", err)
	}
	return run, nil
}

// Root returns the approved artifact root.
func (run PublicationRun) Root() AnchoredRoot { return run.root }

// SessionID returns the exact session scope.
func (run PublicationRun) SessionID() domain.SessionID { return run.sessionID }

// RunID returns the exact run scope.
func (run PublicationRun) RunID() domain.RunID { return run.runID }

// Valid reports whether run is a valid publication scope.
func (run PublicationRun) Valid() bool { return run.validate() == nil }

func (run PublicationRun) validate() error {
	if !run.root.Valid() {
		return fmt.Errorf("invalid root")
	}
	if !validSessionID(run.sessionID) {
		return fmt.Errorf("invalid session ID")
	}
	if !validRunID(run.runID) {
		return fmt.Errorf("invalid run ID")
	}
	return nil
}

// ResolvePublicationRunRequest locates one canonical run ID beneath an approved
// artifact root without trusting directory modification times or caller-supplied
// session identity.
type ResolvePublicationRunRequest struct {
	root         AnchoredRoot
	runID        domain.RunID
	maxReadBytes int64
}

// NewResolvePublicationRunRequest validates a bounded run-resolution request.
func NewResolvePublicationRunRequest(
	root AnchoredRoot,
	runID domain.RunID,
	maxReadBytes int64,
) (ResolvePublicationRunRequest, error) {
	request := ResolvePublicationRunRequest{root: root, runID: runID, maxReadBytes: maxReadBytes}
	if !request.root.Valid() || !validRunID(request.runID) || request.maxReadBytes <= 0 {
		return ResolvePublicationRunRequest{}, fmt.Errorf("resolve publication run request: invalid root, run ID, or read limit")
	}
	return request, nil
}

// Root returns the approved artifact root.
func (request ResolvePublicationRunRequest) Root() AnchoredRoot { return request.root }

// RunID returns the canonical run ID to resolve.
func (request ResolvePublicationRunRequest) RunID() domain.RunID { return request.runID }

// MaxReadBytes returns the positive per-manifest resolution cap.
func (request ResolvePublicationRunRequest) MaxReadBytes() int64 { return request.maxReadBytes }

// IssuedReviewID binds a publisher-issued ReviewID to the semantic candidate
// identity that passed validation before final serialization.
type IssuedReviewID struct {
	reviewID                 domain.ReviewID
	validatedCandidateSHA256 string
}

// NewIssuedReviewID validates a publisher-issued post-validation ReviewID.
func NewIssuedReviewID(reviewID domain.ReviewID, validatedCandidateSHA256 string) (IssuedReviewID, error) {
	issued := IssuedReviewID{reviewID: reviewID, validatedCandidateSHA256: validatedCandidateSHA256}
	if err := issued.validate(); err != nil {
		return IssuedReviewID{}, fmt.Errorf("issued review ID: %w", err)
	}
	return issued, nil
}

// ReviewID returns the publisher-issued domain identifier.
func (issued IssuedReviewID) ReviewID() domain.ReviewID { return issued.reviewID }

// ValidatedCandidateSHA256 returns the semantic candidate identity bound at issuance.
func (issued IssuedReviewID) ValidatedCandidateSHA256() string {
	return issued.validatedCandidateSHA256
}

// Valid reports whether issuance is bound to a valid ReviewID and candidate hash.
func (issued IssuedReviewID) Valid() bool { return issued.validate() == nil }

func (issued IssuedReviewID) validate() error {
	if !validReviewID(issued.reviewID) {
		return fmt.Errorf("invalid review ID")
	}
	if err := validateSHA256(issued.validatedCandidateSHA256); err != nil {
		return fmt.Errorf("validated candidate SHA-256: %w", err)
	}
	return nil
}

// FinalReviewIdentity identifies the one immutable final review to be
// published. Its ReviewID is issued by PublicationStore only after final
// validation has succeeded.
type FinalReviewIdentity struct {
	reviewID domain.ReviewID
	path     SafeRelativePath
	sha256   string
}

// NewFinalReviewIdentity validates immutable final-review identity.
func NewFinalReviewIdentity(reviewID domain.ReviewID, path SafeRelativePath, sha256 string) (FinalReviewIdentity, error) {
	identity := FinalReviewIdentity{reviewID: reviewID, path: path, sha256: sha256}
	if err := identity.validate(); err != nil {
		return FinalReviewIdentity{}, fmt.Errorf("final review identity: %w", err)
	}
	return identity, nil
}

// ReviewID returns the publisher-issued review identity.
func (identity FinalReviewIdentity) ReviewID() domain.ReviewID { return identity.reviewID }

// Path returns the canonical final path beneath the run root.
func (identity FinalReviewIdentity) Path() SafeRelativePath { return identity.path }

// SHA256 returns the canonical final-byte integrity identifier.
func (identity FinalReviewIdentity) SHA256() string { return identity.sha256 }

// Valid reports whether identity is complete and canonical.
func (identity FinalReviewIdentity) Valid() bool { return identity.validate() == nil }

func (identity FinalReviewIdentity) validate() error {
	if !validReviewID(identity.reviewID) {
		return fmt.Errorf("invalid review ID")
	}
	if !identity.path.Valid() {
		return fmt.Errorf("invalid final path")
	}
	if err := validateSHA256(identity.sha256); err != nil {
		return fmt.Errorf("final SHA-256: %w", err)
	}
	return nil
}

// IssuedFinalBinding is the explicit relation between the semantic candidate
// identity bound at ReviewID issuance and the final artifact's raw-byte
// identity. The two SHA-256 values deliberately cover different
// representations and are never compared directly; the shared issued ReviewID
// is the validated join.
type IssuedFinalBinding struct {
	issued IssuedReviewID
	final  FinalReviewIdentity
}

// NewIssuedFinalBinding validates the only permitted semantic-candidate to
// final-artifact relation.
func NewIssuedFinalBinding(issued IssuedReviewID, final FinalReviewIdentity) (IssuedFinalBinding, error) {
	binding := IssuedFinalBinding{issued: issued, final: final}
	if err := binding.validate(); err != nil {
		return IssuedFinalBinding{}, fmt.Errorf("issued final binding: %w", err)
	}
	return binding, nil
}

// IssuedReviewID returns the post-validation issuance fact.
func (binding IssuedFinalBinding) IssuedReviewID() IssuedReviewID { return binding.issued }

// Final returns the exact immutable final identity joined to issuance.
func (binding IssuedFinalBinding) Final() FinalReviewIdentity { return binding.final }

// ValidatedCandidateSHA256 returns the semantic candidate identity.
func (binding IssuedFinalBinding) ValidatedCandidateSHA256() string {
	return binding.issued.ValidatedCandidateSHA256()
}

// FinalSHA256 returns the raw final-artifact identity.
func (binding IssuedFinalBinding) FinalSHA256() string { return binding.final.SHA256() }

// Valid reports whether the semantic candidate and final identities have an
// explicit, non-forgeable-in-ports ReviewID join.
func (binding IssuedFinalBinding) Valid() bool { return binding.validate() == nil }

func (binding IssuedFinalBinding) validate() error {
	if !binding.issued.Valid() || !binding.final.Valid() {
		return fmt.Errorf("invalid issuance or final")
	}
	if binding.issued.ReviewID() != binding.final.ReviewID() {
		return fmt.Errorf("issued review ID does not match final review ID")
	}
	return nil
}

// ImmutablePublicationArtifact is validated immutable artifact bytes. Bytes
// always returns a caller-owned copy.
type ImmutablePublicationArtifact struct {
	path   SafeRelativePath
	sha256 string
	bytes  []byte
}

// NewImmutablePublicationArtifact validates identity against exact immutable
// bytes and takes ownership of bytes.
func NewImmutablePublicationArtifact(path SafeRelativePath, sha256 string, bytes []byte) (ImmutablePublicationArtifact, error) {
	artifact := ImmutablePublicationArtifact{path: path, sha256: sha256, bytes: cloneBytes(bytes)}
	if err := artifact.validate(); err != nil {
		return ImmutablePublicationArtifact{}, fmt.Errorf("immutable publication artifact: %w", err)
	}
	return artifact, nil
}

// Path returns the canonical artifact path beneath the run root.
func (artifact ImmutablePublicationArtifact) Path() SafeRelativePath { return artifact.path }

// SHA256 returns the canonical exact-byte integrity identifier.
func (artifact ImmutablePublicationArtifact) SHA256() string { return artifact.sha256 }

// Bytes returns a caller-owned copy of the immutable artifact bytes.
func (artifact ImmutablePublicationArtifact) Bytes() []byte { return cloneBytes(artifact.bytes) }

// Valid reports whether identity and bytes are coherent.
func (artifact ImmutablePublicationArtifact) Valid() bool { return artifact.validate() == nil }

func (artifact ImmutablePublicationArtifact) validate() error {
	if !artifact.path.Valid() {
		return fmt.Errorf("invalid path")
	}
	if err := validateSHA256(artifact.sha256); err != nil {
		return fmt.Errorf("SHA-256: %w", err)
	}
	if len(artifact.bytes) == 0 {
		return fmt.Errorf("bytes must be non-empty")
	}
	if sha256Identifier(artifact.bytes) != artifact.sha256 {
		return fmt.Errorf("bytes do not match SHA-256")
	}
	return nil
}

// FinalReviewArtifact is one immutable final review and its exact bytes.
// AttemptArtifactKind identifies one captured provider byte stream.
type AttemptArtifactKind string

const (
	AttemptArtifactInitialCandidate  AttemptArtifactKind = "initial_candidate"
	AttemptArtifactRepairedCandidate AttemptArtifactKind = "repaired_candidate"
	AttemptArtifactStdout            AttemptArtifactKind = "stdout"
	AttemptArtifactStderr            AttemptArtifactKind = "stderr"
)

// Valid reports whether the kind is a persisted provider byte stream.
func (kind AttemptArtifactKind) Valid() bool {
	return kind == AttemptArtifactInitialCandidate ||
		kind == AttemptArtifactRepairedCandidate ||
		kind == AttemptArtifactStdout ||
		kind == AttemptArtifactStderr
}

// CapturedAttemptArtifact is a caller-owned captured provider byte stream.
// SecurityRejected means the bytes were rejected before persistence and must be
// empty; it deliberately carries no synthetic identity or receipt.
type CapturedAttemptArtifact struct {
	kind             AttemptArtifactKind
	bytes            []byte
	securityRejected bool
}

// NewCapturedAttemptArtifact takes ownership of permitted bytes. Rejected
// streams retain only their rejection state and can never be serialized.
func NewCapturedAttemptArtifact(
	kind AttemptArtifactKind,
	bytes []byte,
	securityRejected bool,
) (CapturedAttemptArtifact, error) {
	artifact := CapturedAttemptArtifact{
		kind: kind, bytes: cloneBytes(bytes), securityRejected: securityRejected,
	}
	if !artifact.Valid() {
		return CapturedAttemptArtifact{}, fmt.Errorf("captured attempt artifact: invalid kind or bytes")
	}
	return artifact, nil
}

// Kind returns the captured stream kind.
func (artifact CapturedAttemptArtifact) Kind() AttemptArtifactKind { return artifact.kind }

// Bytes returns a caller-owned copy of permitted captured bytes.
func (artifact CapturedAttemptArtifact) Bytes() []byte { return cloneBytes(artifact.bytes) }

// SecurityRejected reports whether capture policy rejected the stream.
func (artifact CapturedAttemptArtifact) SecurityRejected() bool { return artifact.securityRejected }

// Valid reports whether the artifact can be handled without persisting rejected bytes.
func (artifact CapturedAttemptArtifact) Valid() bool {
	if !artifact.kind.Valid() {
		return false
	}
	if artifact.securityRejected {
		return len(artifact.bytes) == 0
	}
	return len(artifact.bytes) > 0
}

type FinalReviewArtifact struct {
	identity FinalReviewIdentity
	bytes    []byte
}

// NewFinalReviewArtifact validates a final identity against exact bytes and
// takes ownership of bytes.
func NewFinalReviewArtifact(identity FinalReviewIdentity, bytes []byte) (FinalReviewArtifact, error) {
	artifact := FinalReviewArtifact{identity: identity, bytes: cloneBytes(bytes)}
	if err := artifact.validate(); err != nil {
		return FinalReviewArtifact{}, fmt.Errorf("final review artifact: %w", err)
	}
	return artifact, nil
}

// Identity returns the final review identity.
func (artifact FinalReviewArtifact) Identity() FinalReviewIdentity { return artifact.identity }

// Bytes returns a caller-owned copy of exact final review bytes.
func (artifact FinalReviewArtifact) Bytes() []byte { return cloneBytes(artifact.bytes) }

// Valid reports whether final identity and bytes are coherent.
func (artifact FinalReviewArtifact) Valid() bool { return artifact.validate() == nil }

func (artifact FinalReviewArtifact) validate() error {
	if !artifact.identity.Valid() {
		return fmt.Errorf("invalid identity")
	}
	if len(artifact.bytes) == 0 {
		return fmt.Errorf("bytes must be non-empty")
	}
	if sha256Identifier(artifact.bytes) != artifact.identity.sha256 {
		return fmt.Errorf("bytes do not match final SHA-256")
	}
	return nil
}

// ValidatedCandidatePath returns the canonical durable location for the exact
// post-validation final candidate. It is intentionally distinct from the final
// publication path so recovery never has to reconstruct candidate bytes.
func ValidatedCandidatePath(run PublicationRun) (SafeRelativePath, error) {
	if !run.Valid() {
		return SafeRelativePath{}, fmt.Errorf("validated candidate path: invalid run")
	}
	path, err := NewSafeRelativePath(
		run.SessionID().String() + "/" + run.RunID().String() + "/validation/final-candidate.json",
	)
	if err != nil {
		return SafeRelativePath{}, fmt.Errorf("validated candidate path: %w", err)
	}
	return path, nil
}

// PersistValidatedCandidateRequest persists the exact schema-validated final
// candidate before any recoverable publication journal hint is written.
type PersistValidatedCandidateRequest struct {
	run       PublicationRun
	candidate FinalReviewArtifact
	path      SafeRelativePath
}

// NewPersistValidatedCandidateRequest validates a no-replace candidate write.
func NewPersistValidatedCandidateRequest(
	run PublicationRun,
	candidate FinalReviewArtifact,
) (PersistValidatedCandidateRequest, error) {
	path, err := ValidatedCandidatePath(run)
	if err != nil {
		return PersistValidatedCandidateRequest{}, err
	}
	request := PersistValidatedCandidateRequest{
		run: run, candidate: cloneFinalReviewArtifact(candidate), path: path,
	}
	if err := request.validate(); err != nil {
		return PersistValidatedCandidateRequest{}, fmt.Errorf("persist validated candidate request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request PersistValidatedCandidateRequest) Run() PublicationRun { return request.run }

// Candidate returns exact final candidate bytes with defensive byte accessors.
func (request PersistValidatedCandidateRequest) Candidate() FinalReviewArtifact {
	return cloneFinalReviewArtifact(request.candidate)
}

// Path returns the canonical no-replace candidate destination.
func (request PersistValidatedCandidateRequest) Path() SafeRelativePath { return request.path }

func (request PersistValidatedCandidateRequest) validate() error {
	if !request.run.Valid() || !request.candidate.Valid() || !request.path.Valid() {
		return fmt.Errorf("invalid run, candidate, or path")
	}
	if err := validateCanonicalFinalPath(request.run, request.candidate.Identity()); err != nil {
		return err
	}
	expected, err := ValidatedCandidatePath(request.run)
	if err != nil {
		return err
	}
	if request.path != expected {
		return fmt.Errorf("candidate path %q is not canonical", request.path.String())
	}
	return nil
}

// ValidatedCandidateDurability distinguishes a completed candidate directory
// sync from an installed candidate whose durability outcome is unknown.
type ValidatedCandidateDurability string

const (
	ValidatedCandidateDurable   ValidatedCandidateDurability = "durable"
	ValidatedCandidateUndurable ValidatedCandidateDurability = "installed_undurable"
)

// Valid reports whether durability is an explicit candidate outcome.
func (durability ValidatedCandidateDurability) Valid() bool {
	return durability == ValidatedCandidateDurable || durability == ValidatedCandidateUndurable
}

// PersistValidatedCandidateResult exists only after exact candidate bytes were
// installed at Path. An undurable result must be re-observed, never retried.
type PersistValidatedCandidateResult struct {
	candidate  FinalReviewArtifact
	path       SafeRelativePath
	receipt    SecureWriteReceipt
	durability ValidatedCandidateDurability
}

// NewPersistValidatedCandidateResult validates an installed candidate receipt.
func NewPersistValidatedCandidateResult(
	candidate FinalReviewArtifact,
	path SafeRelativePath,
	receipt SecureWriteReceipt,
	durability ValidatedCandidateDurability,
) (PersistValidatedCandidateResult, error) {
	result := PersistValidatedCandidateResult{
		candidate: cloneFinalReviewArtifact(candidate), path: path, receipt: receipt, durability: durability,
	}
	if err := result.validate(); err != nil {
		return PersistValidatedCandidateResult{}, fmt.Errorf("persist validated candidate result: %w", err)
	}
	return result, nil
}

// Candidate returns exact installed candidate bytes with defensive accessors.
func (result PersistValidatedCandidateResult) Candidate() FinalReviewArtifact {
	return cloneFinalReviewArtifact(result.candidate)
}

// Path returns the installed canonical candidate destination.
func (result PersistValidatedCandidateResult) Path() SafeRelativePath { return result.path }

// Receipt returns the exact accepted no-replace receipt.
func (result PersistValidatedCandidateResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns the explicit post-install durability outcome.
func (result PersistValidatedCandidateResult) Durability() ValidatedCandidateDurability {
	return result.durability
}

// Valid reports whether result facts are coherent.
func (result PersistValidatedCandidateResult) Valid() bool { return result.validate() == nil }

func (result PersistValidatedCandidateResult) validate() error {
	if !result.candidate.Valid() || !result.path.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid candidate, path, or durability")
	}
	expected, err := validatedCandidatePathForFinal(result.candidate.Identity())
	if err != nil {
		return err
	}
	if result.path != expected {
		return fmt.Errorf("candidate path %q is not canonical", result.path.String())
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Destination() != result.path ||
		result.receipt.SHA256() != result.candidate.Identity().SHA256() ||
		result.receipt.ByteLength() != int64(len(result.candidate.Bytes())) {
		return fmt.Errorf("receipt does not match candidate")
	}
	return nil
}

func validatedCandidatePathForFinal(final FinalReviewIdentity) (SafeRelativePath, error) {
	suffix := "/review_" + final.ReviewID().String() + ".json"
	prefix, ok := strings.CutSuffix(final.Path().String(), suffix)
	if !ok {
		return SafeRelativePath{}, fmt.Errorf("final path does not have canonical review suffix")
	}
	return NewSafeRelativePath(prefix + "/validation/final-candidate.json")
}

// RunSupportArtifactStore persists and reads immutable, non-authoritative run
// support artifacts. It accepts only canonical excerpt and provider-attempt
// paths for its exact run and never replaces an existing artifact.
type RunSupportArtifactStore interface {
	PersistAuxiliaryArtifact(context.Context, PersistAuxiliaryArtifactRequest) (PersistAuxiliaryArtifactResult, error)
	ReadAuxiliaryArtifact(context.Context, ReadAuxiliaryArtifactRequest) (ImmutablePublicationArtifact, error)
}

// AuxiliaryArtifactStore is retained for consumers that only render excerpts.
// New publication code uses RunSupportArtifactStore terminology.
type AuxiliaryArtifactStore = RunSupportArtifactStore

// RunSupportArtifactKind identifies the closed support-artifact path grammar.
type RunSupportArtifactKind string

const (
	RunSupportArtifactExcerpt           RunSupportArtifactKind = "excerpt"
	RunSupportArtifactAttemptStatus     RunSupportArtifactKind = "attempt_status"
	RunSupportArtifactInitialCandidate  RunSupportArtifactKind = "initial_candidate"
	RunSupportArtifactRepairedCandidate RunSupportArtifactKind = "repaired_candidate"
	RunSupportArtifactInvocationStdout  RunSupportArtifactKind = "invocation_stdout"
	RunSupportArtifactInvocationStderr  RunSupportArtifactKind = "invocation_stderr"
	RunSupportArtifactTargetBytes       RunSupportArtifactKind = "target_bytes"
	RunSupportArtifactTargetManifest    RunSupportArtifactKind = "target_manifest"
	RunSupportArtifactCapturedArchive   RunSupportArtifactKind = "captured_archive"
	RunSupportArtifactArtistBrief       RunSupportArtifactKind = "artist_brief"
	RunSupportArtifactArtistVisuals     RunSupportArtifactKind = "artist_visual_assets"
	RunSupportArtifactPromptStdin       RunSupportArtifactKind = "prompt_stdin"
	RunSupportArtifactPromptManifest    RunSupportArtifactKind = "prompt_manifest"
	RunSupportArtifactSupportIndex      RunSupportArtifactKind = "support_index"
	RunSupportArtifactRoleReport        RunSupportArtifactKind = "role_report"
)

// Valid reports whether kind is a closed run-support artifact kind.
func (kind RunSupportArtifactKind) Valid() bool {
	switch kind {
	case RunSupportArtifactExcerpt, RunSupportArtifactAttemptStatus,
		RunSupportArtifactInitialCandidate, RunSupportArtifactRepairedCandidate,
		RunSupportArtifactInvocationStdout, RunSupportArtifactInvocationStderr,
		RunSupportArtifactTargetBytes, RunSupportArtifactTargetManifest,
		RunSupportArtifactCapturedArchive, RunSupportArtifactArtistBrief, RunSupportArtifactArtistVisuals,
		RunSupportArtifactPromptStdin, RunSupportArtifactPromptManifest,
		RunSupportArtifactSupportIndex, RunSupportArtifactRoleReport:
		return true
	default:
		return false
	}
}

// PersistAuxiliaryArtifactRequest binds one exact immutable run-support artifact
// to a run. Its kind is derived from the canonical path, never caller supplied.
type PersistAuxiliaryArtifactRequest struct {
	run      PublicationRun
	artifact ImmutablePublicationArtifact
	kind     RunSupportArtifactKind
}

// NewPersistAuxiliaryArtifactRequest validates a no-replace run-support write.
func NewPersistAuxiliaryArtifactRequest(
	run PublicationRun,
	artifact ImmutablePublicationArtifact,
) (PersistAuxiliaryArtifactRequest, error) {
	kind, err := classifyCanonicalRunSupportPath(run, artifact.Path())
	if err != nil {
		return PersistAuxiliaryArtifactRequest{}, fmt.Errorf("persist run support artifact: %w", err)
	}
	request := PersistAuxiliaryArtifactRequest{run: run, artifact: artifact, kind: kind}
	if err := request.validate(); err != nil {
		return PersistAuxiliaryArtifactRequest{}, fmt.Errorf("persist run support artifact request: %w", err)
	}
	return request, nil
}

// NewPersistRunSupportArtifactRequest is the canonical run-support constructor.
func NewPersistRunSupportArtifactRequest(
	run PublicationRun,
	artifact ImmutablePublicationArtifact,
) (PersistAuxiliaryArtifactRequest, error) {
	return NewPersistAuxiliaryArtifactRequest(run, artifact)
}

// Run returns the exact publication scope.
func (request PersistAuxiliaryArtifactRequest) Run() PublicationRun { return request.run }

// Artifact returns the exact immutable run-support artifact.
func (request PersistAuxiliaryArtifactRequest) Artifact() ImmutablePublicationArtifact {
	return request.artifact
}

// Kind returns the path-derived closed run-support artifact kind.
func (request PersistAuxiliaryArtifactRequest) Kind() RunSupportArtifactKind { return request.kind }

func (request PersistAuxiliaryArtifactRequest) validate() error {
	if !request.run.Valid() || !request.artifact.Valid() || !request.kind.Valid() {
		return fmt.Errorf("invalid run, artifact, or kind")
	}
	kind, err := classifyCanonicalRunSupportPath(request.run, request.artifact.Path())
	if err != nil || kind != request.kind {
		return fmt.Errorf("artifact path is not canonical run support")
	}
	return nil
}

// AuxiliaryArtifactDurability distinguishes a durable run-support artifact from
// one installed before its directory durability step reported an error.
type AuxiliaryArtifactDurability string

const (
	AuxiliaryArtifactDurable   AuxiliaryArtifactDurability = "durable"
	AuxiliaryArtifactUndurable AuxiliaryArtifactDurability = "installed_undurable"
)

// Valid reports whether durability is explicit.
func (durability AuxiliaryArtifactDurability) Valid() bool {
	return durability == AuxiliaryArtifactDurable || durability == AuxiliaryArtifactUndurable
}

// PersistAuxiliaryArtifactResult exists only after exact run-support bytes were
// installed. An undurable result must be followed by ObserveRun, not retried.
type PersistAuxiliaryArtifactResult struct {
	artifact   ImmutablePublicationArtifact
	receipt    SecureWriteReceipt
	durability AuxiliaryArtifactDurability
}

// NewPersistAuxiliaryArtifactResult validates an installed run-support receipt.
func NewPersistAuxiliaryArtifactResult(
	artifact ImmutablePublicationArtifact,
	receipt SecureWriteReceipt,
	durability AuxiliaryArtifactDurability,
) (PersistAuxiliaryArtifactResult, error) {
	result := PersistAuxiliaryArtifactResult{
		artifact: artifact, receipt: receipt, durability: durability,
	}
	if err := result.validate(); err != nil {
		return PersistAuxiliaryArtifactResult{}, fmt.Errorf("persist auxiliary artifact result: %w", err)
	}
	return result, nil
}

// Artifact returns the installed immutable run-support artifact.
func (result PersistAuxiliaryArtifactResult) Artifact() ImmutablePublicationArtifact {
	return result.artifact
}

// Receipt returns the exact no-replace receipt.
func (result PersistAuxiliaryArtifactResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns the explicit post-install durability outcome.
func (result PersistAuxiliaryArtifactResult) Durability() AuxiliaryArtifactDurability {
	return result.durability
}

// Valid reports whether result facts are coherent.
func (result PersistAuxiliaryArtifactResult) Valid() bool { return result.validate() == nil }

func (result PersistAuxiliaryArtifactResult) validate() error {
	if !result.artifact.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid artifact or durability")
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Destination() != result.artifact.Path() ||
		result.receipt.SHA256() != result.artifact.SHA256() ||
		result.receipt.ByteLength() != int64(len(result.artifact.Bytes())) {
		return fmt.Errorf("receipt does not match auxiliary artifact")
	}
	return nil
}

// ReadAuxiliaryArtifactRequest identifies one immutable run-support artifact by
// its canonical path, with an optional exact raw SHA-256. Adapters must always
// reject a different path and must reject a different artifact when a hash is
// supplied.
type ReadAuxiliaryArtifactRequest struct {
	run          PublicationRun
	path         SafeRelativePath
	kind         RunSupportArtifactKind
	sha256       string
	maxReadBytes int64
}

// NewReadAuxiliaryArtifactRequest validates one bounded run-support read. An
// empty SHA-256 requests a bounded canonical-path read; a non-empty SHA-256
// remains an exact raw-byte identity requirement.
func NewReadAuxiliaryArtifactRequest(
	run PublicationRun,
	path SafeRelativePath,
	sha256 string,
	maxReadBytes int64,
) (ReadAuxiliaryArtifactRequest, error) {
	kind, err := classifyCanonicalRunSupportPath(run, path)
	if err != nil {
		return ReadAuxiliaryArtifactRequest{}, fmt.Errorf("read run support artifact: %w", err)
	}
	request := ReadAuxiliaryArtifactRequest{
		run: run, path: path, kind: kind, sha256: sha256, maxReadBytes: maxReadBytes,
	}
	if err := request.validate(); err != nil {
		return ReadAuxiliaryArtifactRequest{}, fmt.Errorf("read run support artifact request: %w", err)
	}
	return request, nil
}

// NewReadRunSupportArtifactRequest is the canonical run-support constructor.
func NewReadRunSupportArtifactRequest(
	run PublicationRun,
	path SafeRelativePath,
	sha256 string,
	maxReadBytes int64,
) (ReadAuxiliaryArtifactRequest, error) {
	return NewReadAuxiliaryArtifactRequest(run, path, sha256, maxReadBytes)
}

// Run returns the exact publication scope.
func (request ReadAuxiliaryArtifactRequest) Run() PublicationRun { return request.run }

// Path returns the exact expected run-support path.
func (request ReadAuxiliaryArtifactRequest) Path() SafeRelativePath { return request.path }

// Kind returns the path-derived closed run-support artifact kind.
func (request ReadAuxiliaryArtifactRequest) Kind() RunSupportArtifactKind { return request.kind }

// ExpectedSHA256 returns the optional expected exact raw artifact hash.
func (request ReadAuxiliaryArtifactRequest) ExpectedSHA256() (string, bool) {
	return request.sha256, request.sha256 != ""
}

// MaxReadBytes returns the positive exact-read cap.
func (request ReadAuxiliaryArtifactRequest) MaxReadBytes() int64 { return request.maxReadBytes }

func (request ReadAuxiliaryArtifactRequest) validate() error {
	if !request.run.Valid() || !request.path.Valid() || !request.kind.Valid() || request.maxReadBytes <= 0 {
		return fmt.Errorf("invalid run, path, kind, or read cap")
	}
	if request.sha256 != "" && validateSHA256(request.sha256) != nil {
		return fmt.Errorf("invalid hash")
	}
	kind, err := classifyCanonicalRunSupportPath(request.run, request.path)
	if err != nil || kind != request.kind {
		return fmt.Errorf("path is not canonical run support")
	}
	return nil
}

func validateCanonicalExcerptPath(run PublicationRun, path SafeRelativePath) error {
	kind, err := classifyCanonicalRunSupportPath(run, path)
	if err != nil || kind != RunSupportArtifactExcerpt {
		return fmt.Errorf("artifact path %q is not a canonical excerpt", path.String())
	}
	return nil
}

// ClassifyRunSupportArtifactPath validates a canonical support-artifact path
// against its immutable session and run scope.
func ClassifyRunSupportArtifactPath(sessionID domain.SessionID, runID domain.RunID, path SafeRelativePath) (RunSupportArtifactKind, error) {
	if sessionID.String() == "" || runID.String() == "" || !path.Valid() {
		return "", fmt.Errorf("invalid run scope or path")
	}
	return classifyCanonicalRunSupportPathValues(sessionID, runID, path)
}

func classifyCanonicalRunSupportPath(run PublicationRun, path SafeRelativePath) (RunSupportArtifactKind, error) {
	if !run.Valid() || !path.Valid() {
		return "", fmt.Errorf("invalid run or path")
	}
	return classifyCanonicalRunSupportPathValues(run.SessionID(), run.RunID(), path)
}

func classifyCanonicalRunSupportPathValues(sessionID domain.SessionID, runID domain.RunID, path SafeRelativePath) (RunSupportArtifactKind, error) {
	prefix := sessionID.String() + "/" + runID.String() + "/"
	value := path.String()
	if !strings.HasPrefix(value, prefix) {
		return "", fmt.Errorf("artifact path %q is outside the run", value)
	}
	relative := strings.TrimPrefix(value, prefix)
	if name, ok := strings.CutPrefix(relative, "excerpts/"); ok {
		if canonicalExcerptName(name) {
			return RunSupportArtifactExcerpt, nil
		}
		return "", fmt.Errorf("excerpt path %q is not canonical", value)
	}
	if name, ok := strings.CutPrefix(relative, "attempts/"); ok {
		return classifyCanonicalAttemptSupportPath(name)
	}
	if relative == "target/target.bytes" {
		return RunSupportArtifactTargetBytes, nil
	}
	if relative == "target/target-manifest.json" {
		return RunSupportArtifactTargetManifest, nil
	}
	if relative == "target/captured-review.json" {
		return RunSupportArtifactCapturedArchive, nil
	}
	if relative == "inputs/artist-brief.md" {
		return RunSupportArtifactArtistBrief, nil
	}
	if relative == "inputs/artist-visual-assets.json" {
		return RunSupportArtifactArtistVisuals, nil
	}
	if relative == "support/index.json" {
		return RunSupportArtifactSupportIndex, nil
	}
	if name, ok := strings.CutPrefix(relative, "prompts/"); ok {
		return classifyCanonicalPromptSupportPath(name)
	}
	if name, ok := strings.CutPrefix(relative, "role-reports/"); ok {
		if canonicalRoleReportName(name) {
			return RunSupportArtifactRoleReport, nil
		}
		return "", fmt.Errorf("role report path %q is not canonical", value)
	}
	return "", fmt.Errorf("artifact path %q is not an allowed run-support path", value)
}

func canonicalRoleReportName(name string) bool {
	if strings.Contains(name, "/") || !strings.HasSuffix(name, ".md") {
		return false
	}
	roleName := strings.TrimSuffix(name, ".md")
	role := domain.Role(roleName)
	return role.Valid()
}

func canonicalExcerptName(name string) bool {
	if strings.Contains(name, "/") || !strings.HasPrefix(name, "F") {
		return false
	}
	stem := strings.TrimPrefix(name, "F")
	if strings.HasSuffix(stem, ".json") {
		return decimalDigits(strings.TrimSuffix(stem, ".json"), 1)
	}
	finding, position, ok := strings.Cut(stem, "_")
	return ok && strings.HasSuffix(position, ".md") &&
		decimalDigits(finding, 1) &&
		decimalDigits(strings.TrimSuffix(position, ".md"), 1)
}

func classifyCanonicalAttemptSupportPath(name string) (RunSupportArtifactKind, error) {
	parts := strings.Split(name, "/")
	if len(parts) < 2 || !validAttemptArtifactID(parts[0]) {
		return "", fmt.Errorf("attempt support path %q has an invalid attempt ID", name)
	}
	switch {
	case len(parts) == 2 && parts[1] == "status.json":
		return RunSupportArtifactAttemptStatus, nil
	case len(parts) == 2 && parts[1] == "candidate.initial.json":
		return RunSupportArtifactInitialCandidate, nil
	case len(parts) == 2 && strings.HasPrefix(parts[1], "candidate.repaired.") &&
		strings.HasSuffix(parts[1], ".json") &&
		decimalIdentifier(strings.TrimSuffix(strings.TrimPrefix(parts[1], "candidate.repaired."), ".json"), 3):
		return RunSupportArtifactRepairedCandidate, nil
	case len(parts) == 4 && parts[1] == "invocations" &&
		canonicalInvocationDirectory(parts[2]) && parts[3] == "stdout.raw":
		return RunSupportArtifactInvocationStdout, nil
	case len(parts) == 4 && parts[1] == "invocations" &&
		canonicalInvocationDirectory(parts[2]) && parts[3] == "stderr.raw":
		return RunSupportArtifactInvocationStderr, nil
	default:
		return "", fmt.Errorf("attempt support path %q is not canonical", name)
	}
}
func classifyCanonicalPromptSupportPath(name string) (RunSupportArtifactKind, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || !validAttemptArtifactID(parts[0]) {
		return "", fmt.Errorf("prompt support path %q is not canonical", name)
	}
	sequence, suffix, ok := strings.Cut(parts[1], "-")
	if !ok || !decimalIdentifier(sequence, 3) {
		return "", fmt.Errorf("prompt support path %q is not canonical", name)
	}
	switch suffix {
	case "initial.stdin", "repair.stdin":
		return RunSupportArtifactPromptStdin, nil
	case "initial.manifest.json", "repair.manifest.json":
		return RunSupportArtifactPromptManifest, nil
	default:
		return "", fmt.Errorf("prompt support path %q is not canonical", name)
	}
}

func validAttemptArtifactID(value string) bool {
	_, err := domain.ParseAttemptID(value)
	return err == nil
}

func canonicalInvocationDirectory(value string) bool {
	sequence, purpose, ok := strings.Cut(value, "-")
	return ok && decimalIdentifier(sequence, 3) && (purpose == "initial" || purpose == "repair")
}

func decimalIdentifier(value string, minimumWidth int) bool {
	if len(value) < minimumWidth || value == "" {
		return false
	}
	nonZero := false
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		nonZero = nonZero || character != '0'
	}
	return nonZero && (value[0] != '0' || len(value) == minimumWidth)
}
func decimalDigits(value string, minimumWidth int) bool {
	if len(value) < minimumWidth {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// IssueReviewIDRequest proves which final validated candidate is about to
// enter publication. PublicationStore issues its ReviewID after validation,
// rather than accepting a provider or caller-generated identifier.
type IssueReviewIDRequest struct {
	run                      PublicationRun
	validatedCandidateSHA256 string
}

// NewIssueReviewIDRequest validates post-validation ReviewID issuance input.
func NewIssueReviewIDRequest(run PublicationRun, validatedCandidateSHA256 string) (IssueReviewIDRequest, error) {
	request := IssueReviewIDRequest{run: run, validatedCandidateSHA256: validatedCandidateSHA256}
	if err := request.validate(); err != nil {
		return IssueReviewIDRequest{}, fmt.Errorf("issue review ID request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request IssueReviewIDRequest) Run() PublicationRun { return request.run }

// ValidatedCandidateSHA256 returns the validation-bound candidate identity.
func (request IssueReviewIDRequest) ValidatedCandidateSHA256() string {
	return request.validatedCandidateSHA256
}

func (request IssueReviewIDRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if err := validateSHA256(request.validatedCandidateSHA256); err != nil {
		return fmt.Errorf("validated candidate SHA-256: %w", err)
	}
	return nil
}

// ObserveRunRequest bounds one durable publication observation.
type ObserveRunRequest struct {
	run          PublicationRun
	maxReadBytes int64
}

// NewObserveRunRequest validates an observation scope and positive per-file
// observation limit.
func NewObserveRunRequest(run PublicationRun, maxReadBytes int64) (ObserveRunRequest, error) {
	request := ObserveRunRequest{run: run, maxReadBytes: maxReadBytes}
	if err := request.validate(); err != nil {
		return ObserveRunRequest{}, fmt.Errorf("observe run request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request ObserveRunRequest) Run() PublicationRun { return request.run }

// MaxReadBytes returns the positive per-file observation cap.
func (request ObserveRunRequest) MaxReadBytes() int64 { return request.maxReadBytes }

func (request ObserveRunRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if request.maxReadBytes <= 0 {
		return fmt.Errorf("max read bytes must be positive")
	}
	return nil
}

// ObservedMutablePublicationDocument is one exact mutable publication record
// observed during one atomic ObserveRun operation. Bytes always returns a
// caller-owned copy.
type ObservedMutablePublicationDocument struct {
	document MutablePublicationDocument
	path     SafeRelativePath
	sha256   string
	bytes    []byte
	present  bool
}

// NewObservedMutablePublicationDocument validates one closed mutable document
// kind against exact observed bytes and takes ownership of bytes.
func NewObservedMutablePublicationDocument(
	document MutablePublicationDocument,
	path SafeRelativePath,
	sha256 string,
	bytes []byte,
) (ObservedMutablePublicationDocument, error) {
	observed := ObservedMutablePublicationDocument{
		document: document,
		path:     path,
		sha256:   sha256,
		bytes:    cloneBytes(bytes),
		present:  true,
	}
	if err := observed.validate(); err != nil {
		return ObservedMutablePublicationDocument{}, fmt.Errorf("observed mutable publication document: %w", err)
	}
	return observed, nil
}

// NewMissingMutablePublicationDocument records that a canonical mutable path
// was absent during the same atomic observation as immutable P2 authority.
func NewMissingMutablePublicationDocument(
	document MutablePublicationDocument,
	path SafeRelativePath,
) (ObservedMutablePublicationDocument, error) {
	observed := ObservedMutablePublicationDocument{document: document, path: path}
	if err := observed.validate(); err != nil {
		return ObservedMutablePublicationDocument{}, fmt.Errorf("missing mutable publication document: %w", err)
	}
	return observed, nil
}

// Document returns the closed mutable publication document kind.
func (observed ObservedMutablePublicationDocument) Document() MutablePublicationDocument {
	return observed.document
}

// Path returns the canonical observed mutable-record path.
func (observed ObservedMutablePublicationDocument) Path() SafeRelativePath {
	return observed.path
}

// SHA256 returns the canonical exact-byte integrity identifier.
func (observed ObservedMutablePublicationDocument) SHA256() string { return observed.sha256 }

// Bytes returns a caller-owned copy of exact observed bytes.
func (observed ObservedMutablePublicationDocument) Bytes() []byte {
	return cloneBytes(observed.bytes)
}

// Present reports whether bytes existed at the canonical mutable path.
func (observed ObservedMutablePublicationDocument) Present() bool { return observed.present }

// Valid reports whether the closed document identity and bytes are coherent.
func (observed ObservedMutablePublicationDocument) Valid() bool {
	return observed.validate() == nil
}

func (observed ObservedMutablePublicationDocument) validate() error {
	if !observed.document.Valid() {
		return fmt.Errorf("invalid document")
	}
	if !observed.path.Valid() {
		return fmt.Errorf("invalid path")
	}
	if !observed.present {
		if observed.sha256 != "" || len(observed.bytes) != 0 {
			return fmt.Errorf("missing observation carries bytes or SHA-256")
		}
		return nil
	}
	if err := validateSHA256(observed.sha256); err != nil {
		return fmt.Errorf("SHA-256: %w", err)
	}
	if len(observed.bytes) == 0 && observed.document != MutablePublicationStatus {
		return fmt.Errorf("non-status bytes must be non-empty")
	}
	if sha256Identifier(observed.bytes) != observed.sha256 {
		return fmt.Errorf("bytes do not match SHA-256")
	}
	return nil
}

// PublicationRecoveryMaterial is exact durable material used to recover P0/P1
// effects or reconstruct P2 mutable status after restart. Its accessors return
// defensive values whose byte accessors copy.
type PublicationRecoveryMaterial struct {
	final              FinalReviewArtifact
	stagedPath         *SafeRelativePath
	journal            ObservedMutablePublicationDocument
	status             *ObservedMutablePublicationDocument
	validatedCandidate *FinalReviewArtifact
	preparedComposite  *PreparedComposite
	committedSnapshot  *CommittedPublicationSnapshot
}

func newPublicationRecoveryMaterial(
	final FinalReviewArtifact,
	stagedPath *SafeRelativePath,
	journal ObservedMutablePublicationDocument,
	status *ObservedMutablePublicationDocument,
) (PublicationRecoveryMaterial, error) {
	material := PublicationRecoveryMaterial{
		final:   cloneFinalReviewArtifact(final),
		journal: cloneObservedMutablePublicationDocument(journal),
	}
	if stagedPath != nil {
		stagedPathCopy := *stagedPath
		material.stagedPath = &stagedPathCopy
	}
	if status != nil {
		statusCopy := cloneObservedMutablePublicationDocument(*status)
		material.status = &statusCopy
	}
	if err := material.validate(); err != nil {
		return PublicationRecoveryMaterial{}, fmt.Errorf("publication recovery material: %w", err)
	}
	return material, nil
}

// NewPublicationRecoveryMaterialWithPrepared validates recovery material that
// carries the exact persisted candidate and prepared composite required by the
// recoverable P0/P1 paths.
func NewPublicationRecoveryMaterialWithPrepared(
	final FinalReviewArtifact,
	stagedPath *SafeRelativePath,
	journal ObservedMutablePublicationDocument,
	status *ObservedMutablePublicationDocument,
	validatedCandidate FinalReviewArtifact,
	preparedComposite PreparedComposite,
) (PublicationRecoveryMaterial, error) {
	material, err := newPublicationRecoveryMaterial(final, stagedPath, journal, status)
	if err != nil {
		return PublicationRecoveryMaterial{}, err
	}
	candidateCopy := cloneFinalReviewArtifact(validatedCandidate)
	preparedCopy := clonePreparedComposite(preparedComposite)
	material.validatedCandidate = &candidateCopy
	material.preparedComposite = &preparedCopy
	if err := material.validate(); err != nil {
		return PublicationRecoveryMaterial{}, fmt.Errorf("publication recovery material: %w", err)
	}
	return material, nil
}

// NewPublicationRecoveryMaterialWithCommittedSnapshot binds exact P2 immutable
// member identities and bytes to the same atomic observation as mutable hints.
func NewPublicationRecoveryMaterialWithCommittedSnapshot(
	final FinalReviewArtifact,
	journal ObservedMutablePublicationDocument,
	status ObservedMutablePublicationDocument,
	snapshot CommittedPublicationSnapshot,
) (PublicationRecoveryMaterial, error) {
	material, err := newPublicationRecoveryMaterial(final, nil, journal, &status)
	if err != nil {
		return PublicationRecoveryMaterial{}, err
	}
	if !snapshot.Valid() || !sameFinalReviewArtifactIdentity(snapshot.Final(), final) {
		return PublicationRecoveryMaterial{}, fmt.Errorf("publication recovery material: committed snapshot does not match final")
	}
	snapshotCopy := snapshot
	material.committedSnapshot = &snapshotCopy
	if err := material.validate(); err != nil {
		return PublicationRecoveryMaterial{}, fmt.Errorf("publication recovery material: %w", err)
	}
	return material, nil
}

// CommittedSnapshot returns the exact atomically observed P2 immutable members.
func (material PublicationRecoveryMaterial) CommittedSnapshot() (CommittedPublicationSnapshot, bool) {
	if material.committedSnapshot == nil {
		return CommittedPublicationSnapshot{}, false
	}
	return *material.committedSnapshot, true
}

// ValidatedCandidate returns exact persisted candidate bytes when recovery
// material was captured from a recovery-aware observation.
func (material PublicationRecoveryMaterial) ValidatedCandidate() (FinalReviewArtifact, bool) {
	if material.validatedCandidate == nil {
		return FinalReviewArtifact{}, false
	}
	return cloneFinalReviewArtifact(*material.validatedCandidate), true
}

// PreparedComposite returns exact prepared staged members when recovery material
// was captured from a recovery-aware observation.
func (material PublicationRecoveryMaterial) PreparedComposite() (PreparedComposite, bool) {
	if material.preparedComposite == nil {
		return PreparedComposite{}, false
	}
	return clonePreparedComposite(*material.preparedComposite), true
}

// Final returns the exact immutable final candidate and defensive bytes.
func (material PublicationRecoveryMaterial) Final() FinalReviewArtifact {
	return cloneFinalReviewArtifact(material.final)
}

// StagedPath returns the observed staged path when one exists.
func (material PublicationRecoveryMaterial) StagedPath() (SafeRelativePath, bool) {
	if material.stagedPath == nil {
		return SafeRelativePath{}, false
	}
	return *material.stagedPath, true
}

// Journal returns the required observed publication journal and defensive bytes.
func (material PublicationRecoveryMaterial) Journal() ObservedMutablePublicationDocument {
	return cloneObservedMutablePublicationDocument(material.journal)
}

// Status returns the observed publication status and defensive bytes when one
// exists.
func (material PublicationRecoveryMaterial) Status() (ObservedMutablePublicationDocument, bool) {
	if material.status == nil {
		return ObservedMutablePublicationDocument{}, false
	}
	return cloneObservedMutablePublicationDocument(*material.status), true
}

// Valid reports whether material is complete and exact.
func (material PublicationRecoveryMaterial) Valid() bool { return material.validate() == nil }

func (material PublicationRecoveryMaterial) validate() error {
	if !material.final.Valid() {
		return fmt.Errorf("invalid final")
	}
	expectedJournal, err := canonicalMutablePublicationPathForFinal(
		material.final.Identity(),
		MutablePublicationJournal,
	)
	if err != nil {
		return err
	}
	if material.journal.Path() != expectedJournal {
		return fmt.Errorf("journal path is not canonical for final")
	}
	if material.stagedPath != nil {
		expectedStaged, err := canonicalStagedFinalPathForFinal(material.final.Identity())
		if err != nil {
			return err
		}
		if *material.stagedPath != expectedStaged {
			return fmt.Errorf("staged path is not canonical for final")
		}
	}
	if !material.journal.Valid() {
		return fmt.Errorf("invalid journal")
	}
	if material.journal.Document() != MutablePublicationJournal {
		return fmt.Errorf("journal must be a journal document")
	}
	if material.status != nil {
		expectedStatus, err := canonicalMutablePublicationPathForFinal(
			material.final.Identity(),
			MutablePublicationStatus,
		)
		if err != nil {
			return err
		}
		if material.status.Path() != expectedStatus {
			return fmt.Errorf("status path is not canonical for final")
		}
		if !material.status.Valid() {
			return fmt.Errorf("invalid status")
		}
		if material.status.Document() != MutablePublicationStatus {
			return fmt.Errorf("status must be a status document")
		}
	}
	if material.validatedCandidate == nil != (material.preparedComposite == nil) {
		return fmt.Errorf("validated candidate and prepared composite must be present together")
	}
	if material.committedSnapshot != nil {
		if !material.committedSnapshot.Valid() ||
			!sameFinalReviewArtifactIdentity(material.committedSnapshot.Final(), material.final) {
			return fmt.Errorf("committed snapshot does not match final")
		}
	}
	if material.validatedCandidate != nil {
		if !material.journal.Present() {
			return fmt.Errorf("prepared recovery material requires an observed journal")
		}
		if !material.validatedCandidate.Valid() ||
			material.validatedCandidate.Identity() != material.final.Identity() {
			return fmt.Errorf("invalid validated candidate")
		}
		if !material.preparedComposite.Valid() ||
			material.preparedComposite.Composite().Final() != material.final.Identity() {
			return fmt.Errorf("invalid prepared composite")
		}
	}
	return nil
}

func cloneFinalReviewArtifact(artifact FinalReviewArtifact) FinalReviewArtifact {
	return FinalReviewArtifact{
		identity: artifact.identity,
		bytes:    cloneBytes(artifact.bytes),
	}
}

func cloneObservedMutablePublicationDocument(
	observed ObservedMutablePublicationDocument,
) ObservedMutablePublicationDocument {
	return ObservedMutablePublicationDocument{
		document: observed.document,
		path:     observed.path,
		sha256:   observed.sha256,
		present:  observed.present,
		bytes:    cloneBytes(observed.bytes),
	}
}
func clonePreparedComposite(prepared PreparedComposite) PreparedComposite {
	return PreparedComposite{
		request:        prepared.request,
		stagedManifest: prepared.stagedManifest,
		stagedLineage:  prepared.stagedLineage,
		stagedEpoch:    prepared.stagedEpoch,
		receipts:       cloneSecureWriteReceipts(prepared.receipts),
		durability:     prepared.durability,
	}
}

// PublicationObservation is raw durable evidence normalized into the domain's
// observation class. Application policy passes ClassifierInput to the domain;
// this port never chooses a recovery action.
type PublicationObservation struct {
	classifierInput  domain.PublicationClassifierInput
	storeEpoch       uint64
	recoveryMaterial *PublicationRecoveryMaterial
}

// NewPublicationObservation validates one immutable durable observation that
// does not expose recovery material.
func NewPublicationObservation(
	journalState domain.PersistedJournalState,
	observation domain.DurableObservationClass,
	storedNormalExit *domain.OperationalExitCode,
	ambiguityReasons []string,
	storeEpoch uint64,
) (PublicationObservation, error) {
	return newPublicationObservation(
		journalState,
		observation,
		storedNormalExit,
		ambiguityReasons,
		storeEpoch,
		nil,
	)
}

// NewPublicationObservationWithRecovery validates one immutable durable
// observation together with the exact material needed for P0/P1 recovery or P2
// mutable-status reconstruction.
func NewPublicationObservationWithRecovery(
	journalState domain.PersistedJournalState,
	observation domain.DurableObservationClass,
	storedNormalExit *domain.OperationalExitCode,
	ambiguityReasons []string,
	storeEpoch uint64,
	recoveryMaterial PublicationRecoveryMaterial,
) (PublicationObservation, error) {
	return newPublicationObservation(
		journalState,
		observation,
		storedNormalExit,
		ambiguityReasons,
		storeEpoch,
		&recoveryMaterial,
	)
}

func newPublicationObservation(
	journalState domain.PersistedJournalState,
	observation domain.DurableObservationClass,
	storedNormalExit *domain.OperationalExitCode,
	ambiguityReasons []string,
	storeEpoch uint64,
	recoveryMaterial *PublicationRecoveryMaterial,
) (PublicationObservation, error) {
	if storeEpoch == 0 {
		return PublicationObservation{}, fmt.Errorf("publication observation: store epoch must be positive")
	}
	input, err := domain.NewPublicationClassifierInput(
		journalState,
		observation,
		storedNormalExit,
		ambiguityReasons,
	)
	if err != nil {
		return PublicationObservation{}, fmt.Errorf("publication observation: %w", err)
	}
	result := PublicationObservation{
		classifierInput: input,
		storeEpoch:      storeEpoch,
	}
	if recoveryMaterial != nil {
		materialCopy := clonePublicationRecoveryMaterial(*recoveryMaterial)
		result.recoveryMaterial = &materialCopy
	}
	if err := result.validate(); err != nil {
		return PublicationObservation{}, fmt.Errorf("publication observation: %w", err)
	}
	return result, nil
}

// ClassifierInput returns a validated immutable domain classifier input.
func (observation PublicationObservation) ClassifierInput() domain.PublicationClassifierInput {
	return observation.classifierInput
}

// RecoveryMaterial returns the atomically observed exact recovery material when
// the durable class and journal hint require it.
func (observation PublicationObservation) RecoveryMaterial() (PublicationRecoveryMaterial, bool) {
	if observation.recoveryMaterial == nil {
		return PublicationRecoveryMaterial{}, false
	}
	return clonePublicationRecoveryMaterial(*observation.recoveryMaterial), true
}

// StoreEpoch returns the positive store epoch observed with the durable facts.
func (observation PublicationObservation) StoreEpoch() uint64 { return observation.storeEpoch }

// Valid reports whether observation is coherent.
func (observation PublicationObservation) Valid() bool { return observation.validate() == nil }

func (observation PublicationObservation) validate() error {
	if observation.storeEpoch == 0 {
		return fmt.Errorf("store epoch must be positive")
	}
	if !observation.classifierInput.Valid() {
		return fmt.Errorf("invalid classifier input")
	}
	if observation.recoveryMaterial != nil && !observation.recoveryMaterial.Valid() {
		return fmt.Errorf("invalid recovery material")
	}
	if observation.classifierInput.Observation() != domain.DurableObservationP2Committed &&
		observation.recoveryMaterial != nil {
		if _, present := observation.recoveryMaterial.CommittedSnapshot(); present {
			return fmt.Errorf("non-P2 observation must not expose a committed snapshot")
		}
	}

	switch observation.classifierInput.Observation() {
	case domain.DurableObservationP0Staged:
		if observation.recoveryMaterial == nil {
			return fmt.Errorf("P0 staged observation requires recovery material")
		}
		if _, ok := observation.recoveryMaterial.StagedPath(); !ok {
			return fmt.Errorf("P0 staged recovery material requires a staged path")
		}
		if _, ok := observation.recoveryMaterial.ValidatedCandidate(); !ok {
			return fmt.Errorf("P0 staged recovery material requires validated candidate")
		}
		if _, ok := observation.recoveryMaterial.PreparedComposite(); !ok {
			return fmt.Errorf("P0 staged recovery material requires prepared composite")
		}
	case domain.DurableObservationP1Installed:
		if observation.recoveryMaterial == nil {
			return fmt.Errorf("P1 installed observation requires recovery material")
		}
		if _, ok := observation.recoveryMaterial.StagedPath(); ok {
			return fmt.Errorf("P1 installed recovery material must not claim a staged path")
		}
		if _, ok := observation.recoveryMaterial.ValidatedCandidate(); !ok {
			return fmt.Errorf("P1 installed recovery material requires validated candidate")
		}
		if _, ok := observation.recoveryMaterial.PreparedComposite(); !ok {
			return fmt.Errorf("P1 installed recovery material requires prepared composite")
		}
	case domain.DurableObservationP0None:
		switch observation.classifierInput.JournalState() {
		case domain.JournalCollecting:
			if observation.recoveryMaterial != nil {
				return fmt.Errorf("collecting P0 none observation must not expose recovery material")
			}
		case domain.JournalContentValidated, domain.JournalFinalStaged:
			if observation.recoveryMaterial == nil {
				return fmt.Errorf("P0 none recovery observation requires recovery material")
			}
			if _, ok := observation.recoveryMaterial.StagedPath(); ok {
				return fmt.Errorf("P0 none recovery material must not claim a staged path")
			}
			if _, ok := observation.recoveryMaterial.ValidatedCandidate(); !ok {
				return fmt.Errorf("P0 none recovery material requires validated candidate")
			}
			if _, ok := observation.recoveryMaterial.PreparedComposite(); !ok {
				return fmt.Errorf("P0 none recovery material requires prepared composite")
			}
		case domain.JournalFinalFileInstalled, domain.JournalManifestCommitted, domain.JournalCompleted:
			if observation.recoveryMaterial != nil {
				return fmt.Errorf("impossible high-hint P0 none observation must not expose recovery material")
			}
		}
	case domain.DurableObservationP2Committed:
		if observation.recoveryMaterial == nil {
			return fmt.Errorf("P2 committed observation requires atomically observed mutable material")
		}
		if _, ok := observation.recoveryMaterial.StagedPath(); ok {
			return fmt.Errorf("P2 recovery material must not claim a staged path")
		}
		if _, ok := observation.recoveryMaterial.ValidatedCandidate(); ok {
			return fmt.Errorf("P2 recovery material must not claim a validated candidate")
		}
		if _, ok := observation.recoveryMaterial.PreparedComposite(); ok {
			return fmt.Errorf("P2 recovery material must not claim a prepared composite")
		}
		if _, ok := observation.recoveryMaterial.Status(); !ok {
			return fmt.Errorf("P2 recovery material must include an observed present-or-missing status")
		}
		if snapshot, ok := observation.recoveryMaterial.CommittedSnapshot(); !ok {
			return fmt.Errorf("P2 recovery material must include atomically observed immutable members")
		} else if snapshot.Epoch().Value() != observation.storeEpoch {
			return fmt.Errorf("P2 immutable snapshot epoch must match the observation")
		}
	case domain.DurableObservationAmbiguousOrMismatch:
		if observation.recoveryMaterial != nil {
			return fmt.Errorf("%s observation must not expose recovery material", observation.classifierInput.Observation())
		}
	}
	return nil
}

func clonePublicationRecoveryMaterial(
	material PublicationRecoveryMaterial,
) PublicationRecoveryMaterial {
	copyMaterial := PublicationRecoveryMaterial{
		final:   cloneFinalReviewArtifact(material.final),
		journal: cloneObservedMutablePublicationDocument(material.journal),
	}
	if material.stagedPath != nil {
		stagedPathCopy := *material.stagedPath
		copyMaterial.stagedPath = &stagedPathCopy
	}
	if material.status != nil {
		statusCopy := cloneObservedMutablePublicationDocument(*material.status)
		copyMaterial.status = &statusCopy
	}
	if material.validatedCandidate != nil {
		candidateCopy := cloneFinalReviewArtifact(*material.validatedCandidate)
		copyMaterial.validatedCandidate = &candidateCopy
	}
	if material.preparedComposite != nil {
		preparedCopy := clonePreparedComposite(*material.preparedComposite)
		copyMaterial.preparedComposite = &preparedCopy
	}
	if material.committedSnapshot != nil {
		snapshotCopy := *material.committedSnapshot
		copyMaterial.committedSnapshot = &snapshotCopy
	}
	return copyMaterial
}

// StageFinalRequest streams a validated final candidate to a distinct staged
// path. Source is one-shot and owned by the store; Abort must stop the source
// producer when the store rejects, overflows, or cannot persist the stream.
type StageFinalRequest struct {
	run                PublicationRun
	stagedPath         SafeRelativePath
	binding            IssuedFinalBinding
	source             io.Reader
	maxBytes           int64
	expectedByteLength int64
	sourceIDs          []string
	abort              func(error)
}

// NewStageFinalRequest validates a no-replace staging request and takes
// ownership of sourceIDs. It deliberately accepts no final bytes, so the store
// must validate the streamed bytes against Binding's final identity before
// exposing a receipt.
func NewStageFinalRequest(
	run PublicationRun,
	stagedPath SafeRelativePath,
	binding IssuedFinalBinding,
	source io.Reader,
	maxBytes int64,
	sourceIDs []string,
	abort func(error),
) (StageFinalRequest, error) {
	return newStageFinalRequest(
		run,
		stagedPath,
		binding,
		source,
		maxBytes,
		0,
		sourceIDs,
		abort,
	)
}

// NewStageFinalRequestWithExpectedByteLength additionally binds a stage
// receipt to the exact source byte length. It is additive so streaming callers
// that cannot know a length retain the original request contract.
func NewStageFinalRequestWithExpectedByteLength(
	run PublicationRun,
	stagedPath SafeRelativePath,
	binding IssuedFinalBinding,
	source io.Reader,
	maxBytes int64,
	expectedByteLength int64,
	sourceIDs []string,
	abort func(error),
) (StageFinalRequest, error) {
	if expectedByteLength <= 0 {
		return StageFinalRequest{}, fmt.Errorf("stage final request: expected byte length must be positive")
	}
	return newStageFinalRequest(
		run,
		stagedPath,
		binding,
		source,
		maxBytes,
		expectedByteLength,
		sourceIDs,
		abort,
	)
}

func newStageFinalRequest(
	run PublicationRun,
	stagedPath SafeRelativePath,
	binding IssuedFinalBinding,
	source io.Reader,
	maxBytes int64,
	expectedByteLength int64,
	sourceIDs []string,
	abort func(error),
) (StageFinalRequest, error) {
	request := StageFinalRequest{
		run:                run,
		stagedPath:         stagedPath,
		binding:            binding,
		source:             source,
		maxBytes:           maxBytes,
		expectedByteLength: expectedByteLength,
		sourceIDs:          cloneStrings(sourceIDs),
		abort:              abort,
	}
	if err := request.validate(); err != nil {
		return StageFinalRequest{}, fmt.Errorf("stage final request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request StageFinalRequest) Run() PublicationRun { return request.run }

// StagedPath returns the required distinct staged temporary path.
func (request StageFinalRequest) StagedPath() SafeRelativePath { return request.stagedPath }

// Binding returns the explicit issuance-to-final relation.
func (request StageFinalRequest) Binding() IssuedFinalBinding { return request.binding }

// Final returns the final review identity that staged bytes must match.
func (request StageFinalRequest) Final() FinalReviewIdentity { return request.binding.Final() }

// IssuedReviewID returns the post-validation issuance bound to Final.
func (request StageFinalRequest) IssuedReviewID() IssuedReviewID {
	return request.binding.IssuedReviewID()
}

// Source returns the one-shot validated candidate stream owned by the store.
func (request StageFinalRequest) Source() io.Reader { return request.source }

// MaxBytes returns the positive staging cap.
func (request StageFinalRequest) MaxBytes() int64 { return request.maxBytes }

// ExpectedByteLength returns the exact streamed byte length when the caller
// supplied one. Legacy streaming requests deliberately have no length binding.
func (request StageFinalRequest) ExpectedByteLength() (int64, bool) {
	return request.expectedByteLength, request.expectedByteLength > 0
}

// SourceIDs returns a caller-owned copy of staged input lineage identifiers.
func (request StageFinalRequest) SourceIDs() []string { return cloneStrings(request.sourceIDs) }

// Abort returns the required producer-cancellation callback.
func (request StageFinalRequest) Abort() func(error) { return request.abort }

// Valid reports whether request is a canonical stage request.
func (request StageFinalRequest) Valid() bool { return request.validate() == nil }
func (request StageFinalRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if !request.stagedPath.Valid() {
		return fmt.Errorf("invalid staged path")
	}
	if !request.binding.Valid() {
		return fmt.Errorf("invalid issued final binding")
	}
	if err := validateCanonicalFinalPath(request.run, request.binding.Final()); err != nil {
		return err
	}
	expectedStaged, err := canonicalStagedFinalPath(request.run, request.binding.Final())
	if err != nil {
		return err
	}
	if request.stagedPath != expectedStaged {
		return fmt.Errorf("staged path %q is not canonical for final", request.stagedPath.String())
	}
	if isNilReader(request.source) {
		return fmt.Errorf("source must be non-nil")
	}
	if request.maxBytes <= 0 {
		return fmt.Errorf("max bytes must be positive")
	}
	if request.expectedByteLength < 0 || request.expectedByteLength > request.maxBytes {
		return fmt.Errorf("expected byte length must be positive when provided and within max bytes")
	}
	if err := validateSourceIDs(request.sourceIDs); err != nil {
		return fmt.Errorf("source IDs: %w", err)
	}
	if request.abort == nil {
		return fmt.Errorf("abort callback must be non-nil")
	}
	return nil
}

// AdoptStagedFinalRequest identifies exact persisted staged bytes that must be
// re-opened, validated, and fsync-adopted before recovery may install them.
type AdoptStagedFinalRequest struct {
	run        PublicationRun
	stagedPath SafeRelativePath
	binding    IssuedFinalBinding
	final      FinalReviewArtifact
	maxBytes   int64
}

// NewAdoptStagedFinalRequest validates one staged durability-adoption request.
func NewAdoptStagedFinalRequest(
	run PublicationRun,
	stagedPath SafeRelativePath,
	binding IssuedFinalBinding,
	final FinalReviewArtifact,
	maxBytes int64,
) (AdoptStagedFinalRequest, error) {
	request := AdoptStagedFinalRequest{
		run: run, stagedPath: stagedPath, binding: binding,
		final: cloneFinalReviewArtifact(final), maxBytes: maxBytes,
	}
	if err := request.validate(); err != nil {
		return AdoptStagedFinalRequest{}, fmt.Errorf("adopt staged final request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request AdoptStagedFinalRequest) Run() PublicationRun { return request.run }

// StagedPath returns the exact canonical staged pathname to adopt.
func (request AdoptStagedFinalRequest) StagedPath() SafeRelativePath { return request.stagedPath }

// Binding returns the explicit issuance-to-final relation.
func (request AdoptStagedFinalRequest) Binding() IssuedFinalBinding { return request.binding }

// IssuedReviewID returns the issuance bound to the staged final.
func (request AdoptStagedFinalRequest) IssuedReviewID() IssuedReviewID {
	return request.binding.IssuedReviewID()
}

// Final returns defensive exact expected final bytes.
func (request AdoptStagedFinalRequest) Final() FinalReviewArtifact {
	return cloneFinalReviewArtifact(request.final)
}

// MaxBytes returns the positive adoption read cap.
func (request AdoptStagedFinalRequest) MaxBytes() int64 { return request.maxBytes }

func (request AdoptStagedFinalRequest) validate() error {
	if !request.run.Valid() || !request.stagedPath.Valid() || !request.binding.Valid() ||
		!request.final.Valid() || request.maxBytes <= 0 ||
		int64(len(request.final.Bytes())) > request.maxBytes {
		return fmt.Errorf("invalid run, staged path, binding, final, or read cap")
	}
	if request.binding.Final() != request.final.Identity() {
		return fmt.Errorf("final artifact does not match issued final binding")
	}
	if err := validateCanonicalFinalPath(request.run, request.final.Identity()); err != nil {
		return err
	}
	expected, err := canonicalStagedFinalPath(request.run, request.final.Identity())
	if err != nil {
		return err
	}
	if request.stagedPath != expected {
		return fmt.Errorf("staged path %q is not canonical for final", request.stagedPath.String())
	}
	return nil
}

// StageFinalDurability explicitly distinguishes a staged artifact whose
// directory sync completed from one installed before its durability error.
type StageFinalDurability string

const (
	StageFinalDurable   StageFinalDurability = "staged_durable"
	StageFinalUndurable StageFinalDurability = "staged_undurable"
)

// Valid reports whether durability is an explicit staging outcome.
func (durability StageFinalDurability) Valid() bool {
	return durability == StageFinalDurable || durability == StageFinalUndurable
}

// StageFinalResult exists only after bytes were installed at the staged path.
// A StageFinalUndurable result must be re-observed; it is never retry-safe.
type StageFinalResult struct {
	stagedPath SafeRelativePath
	final      FinalReviewIdentity
	receipt    SecureWriteReceipt
	durability StageFinalDurability
}

// NewStageFinalResult validates an installed staged-file receipt.
func NewStageFinalResult(stagedPath SafeRelativePath, final FinalReviewIdentity, receipt SecureWriteReceipt, durability StageFinalDurability) (StageFinalResult, error) {
	result := StageFinalResult{stagedPath: stagedPath, final: final, receipt: receipt, durability: durability}
	if err := result.validate(); err != nil {
		return StageFinalResult{}, fmt.Errorf("stage final result: %w", err)
	}
	return result, nil
}

// NewStageFinalResultForRequest validates a stage receipt against the exact
// request, including the optional source byte-length binding.
func NewStageFinalResultForRequest(
	request StageFinalRequest,
	receipt SecureWriteReceipt,
	durability StageFinalDurability,
) (StageFinalResult, error) {
	if !request.Valid() {
		return StageFinalResult{}, fmt.Errorf("stage final result for request: invalid request")
	}
	result, err := NewStageFinalResult(request.StagedPath(), request.Final(), receipt, durability)
	if err != nil {
		return StageFinalResult{}, err
	}
	if result.Receipt().Root() != request.Run().Root() {
		return StageFinalResult{}, fmt.Errorf("stage final result for request: receipt root does not match request")
	}
	if expectedByteLength, present := request.ExpectedByteLength(); present &&
		result.Receipt().ByteLength() != expectedByteLength {
		return StageFinalResult{}, fmt.Errorf("stage final result for request: receipt byte length does not match request")
	}
	return result, nil
}

// StagedPath returns the installed staged temporary path.
func (result StageFinalResult) StagedPath() SafeRelativePath { return result.stagedPath }

// Final returns the final identity matched by staged bytes.
func (result StageFinalResult) Final() FinalReviewIdentity { return result.final }

// Receipt returns the accepted staged-byte receipt.
func (result StageFinalResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns whether post-install durability completed.
func (result StageFinalResult) Durability() StageFinalDurability { return result.durability }

// Valid reports whether result is coherent.
func (result StageFinalResult) Valid() bool { return result.validate() == nil }

func (result StageFinalResult) validate() error {
	if !result.stagedPath.Valid() || !result.final.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid staged path, final, or durability")
	}
	if result.stagedPath == result.final.Path() {
		return fmt.Errorf("staged path must differ from final path")
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Destination() != result.stagedPath || result.receipt.SHA256() != result.final.SHA256() {
		return fmt.Errorf("receipt does not match staged path and final hash")
	}
	return nil
}

// InstallFinalRequest atomically moves a previously staged final to its final
// no-replace path. It can only be built from a validated staged result.
type InstallFinalRequest struct {
	run    PublicationRun
	staged StageFinalResult
}

// NewInstallFinalRequest validates an install request from exact staged facts.
func NewInstallFinalRequest(run PublicationRun, staged StageFinalResult) (InstallFinalRequest, error) {
	request := InstallFinalRequest{run: run, staged: staged}
	if err := request.validate(); err != nil {
		return InstallFinalRequest{}, fmt.Errorf("install final request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request InstallFinalRequest) Run() PublicationRun { return request.run }

// Staged returns the exact staged final to install.
func (request InstallFinalRequest) Staged() StageFinalResult { return request.staged }

// Valid reports whether request is a canonical final-install request.
func (request InstallFinalRequest) Valid() bool { return request.validate() == nil }

func (request InstallFinalRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if !request.staged.Valid() {
		return fmt.Errorf("invalid staged final")
	}
	if request.staged.Durability() != StageFinalDurable {
		return fmt.Errorf("final installation requires durable staged final")
	}
	if request.staged.Receipt().Root() != request.run.Root() {
		return fmt.Errorf("staged receipt root does not match run root")
	}
	if err := validateCanonicalFinalPath(request.run, request.staged.Final()); err != nil {
		return err
	}
	expectedStaged, err := canonicalStagedFinalPath(request.run, request.staged.Final())
	if err != nil {
		return err
	}
	if request.staged.StagedPath() != expectedStaged {
		return fmt.Errorf("staged final path is not canonical for install")
	}
	return nil
}

// InstallFinalDurability explicitly records whether a final was installed but
// its containing-directory durability step failed.
type InstallFinalDurability string

const (
	InstallFinalDurable   InstallFinalDurability = "final_installed_durable"
	InstallFinalUndurable InstallFinalDurability = "final_installed_undurable"
)

// Valid reports whether durability is an explicit final-install outcome.
func (durability InstallFinalDurability) Valid() bool {
	return durability == InstallFinalDurable || durability == InstallFinalUndurable
}

// InstallFinalResult exists only after the immutable final path was installed.
// InstallFinalUndurable must be followed by ObserveRun, never blind retry.
type InstallFinalResult struct {
	final      FinalReviewIdentity
	receipt    SecureWriteReceipt
	durability InstallFinalDurability
}

// NewInstallFinalResult validates an installed final-file receipt.
func NewInstallFinalResult(final FinalReviewIdentity, receipt SecureWriteReceipt, durability InstallFinalDurability) (InstallFinalResult, error) {
	result := InstallFinalResult{final: final, receipt: receipt, durability: durability}
	if err := result.validate(); err != nil {
		return InstallFinalResult{}, fmt.Errorf("install final result: %w", err)
	}
	return result, nil
}

// NewInstallFinalResultForRequest validates an install receipt against the
// exact staged result carried by the install request.
func NewInstallFinalResultForRequest(
	request InstallFinalRequest,
	receipt SecureWriteReceipt,
	durability InstallFinalDurability,
) (InstallFinalResult, error) {
	if !request.Valid() {
		return InstallFinalResult{}, fmt.Errorf("install final result for request: invalid request")
	}
	result, err := NewInstallFinalResult(request.Staged().Final(), receipt, durability)
	if err != nil {
		return InstallFinalResult{}, err
	}
	if result.Receipt().Root() != request.Run().Root() {
		return InstallFinalResult{}, fmt.Errorf("install final result for request: receipt root does not match request")
	}
	if result.Receipt().ByteLength() != request.Staged().Receipt().ByteLength() {
		return InstallFinalResult{}, fmt.Errorf("install final result for request: receipt byte length does not match staged request")
	}
	return result, nil
}

// Final returns the installed final identity.
func (result InstallFinalResult) Final() FinalReviewIdentity { return result.final }

// Receipt returns the accepted final-byte receipt.
func (result InstallFinalResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns whether post-install durability completed.
func (result InstallFinalResult) Durability() InstallFinalDurability { return result.durability }

// Valid reports whether result is coherent.
func (result InstallFinalResult) Valid() bool { return result.validate() == nil }

func (result InstallFinalResult) validate() error {
	if !result.final.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid final or durability")
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Destination() != result.final.Path() || result.receipt.SHA256() != result.final.SHA256() {
		return fmt.Errorf("receipt does not match final path and hash")
	}
	return nil
}

// MutablePublicationDocument is the closed mutable publication record set.
type MutablePublicationDocument string

const (
	MutablePublicationStatus  MutablePublicationDocument = "status"
	MutablePublicationJournal MutablePublicationDocument = "journal"
)

// Valid reports whether document is an allowed mutable publication record.
func (document MutablePublicationDocument) Valid() bool {
	return document == MutablePublicationStatus || document == MutablePublicationJournal
}

// ErrMutableCASConflict reports that a mutable publication record changed after
// its caller's durable observation. Callers must re-observe instead of retrying
// the same replacement against altered state.
var ErrMutableCASConflict = errors.New("mutable publication compare-and-swap conflict")

// MutableCASExpectation states exactly whether a mutable record must be absent
// or match one expected prior SHA-256. It cannot represent both.
type MutableCASExpectation struct {
	mustBeAbsent bool
	sha256       string
}

// ExpectMutableAbsent creates an absence-only compare-and-swap expectation.
func ExpectMutableAbsent() MutableCASExpectation { return MutableCASExpectation{mustBeAbsent: true} }

// ExpectMutableSHA256 creates a hash-only compare-and-swap expectation.
func ExpectMutableSHA256(sha256 string) (MutableCASExpectation, error) {
	expectation := MutableCASExpectation{sha256: sha256}
	if err := expectation.validate(); err != nil {
		return MutableCASExpectation{}, fmt.Errorf("mutable CAS expectation: %w", err)
	}
	return expectation, nil
}

// MustBeAbsent reports whether the expected prior state is exact absence.
func (expectation MutableCASExpectation) MustBeAbsent() bool { return expectation.mustBeAbsent }

// ExpectedSHA256 returns the expected prior hash when the prior must exist.
func (expectation MutableCASExpectation) ExpectedSHA256() (string, bool) {
	if expectation.mustBeAbsent {
		return "", false
	}
	return expectation.sha256, true
}

// Valid reports whether expectation is one non-contradictory CAS state.
func (expectation MutableCASExpectation) Valid() bool { return expectation.validate() == nil }

func (expectation MutableCASExpectation) validate() error {
	if expectation.mustBeAbsent {
		if expectation.sha256 != "" {
			return fmt.Errorf("absence expectation must not include a hash")
		}
		return nil
	}
	if err := validateSHA256(expectation.sha256); err != nil {
		return fmt.Errorf("expected SHA-256: %w", err)
	}
	return nil
}

// MutableReplaceRequest atomically replaces one mutable status or journal
// record only when ExpectedPrior still matches. Replacement returns copied
// exact bytes so the adapter cannot retain caller-owned memory.
type MutableReplaceRequest struct {
	run           PublicationRun
	document      MutablePublicationDocument
	path          SafeRelativePath
	expectedPrior MutableCASExpectation
	replacement   []byte
	sha256        string
}

// NewMutableReplaceRequest validates exact mutable replacement bytes and CAS.
func NewMutableReplaceRequest(
	run PublicationRun,
	document MutablePublicationDocument,
	path SafeRelativePath,
	expectedPrior MutableCASExpectation,
	replacement []byte,
	sha256 string,
) (MutableReplaceRequest, error) {
	request := MutableReplaceRequest{
		run:           run,
		document:      document,
		path:          path,
		expectedPrior: expectedPrior,
		replacement:   cloneBytes(replacement),
		sha256:        sha256,
	}
	if err := request.validate(); err != nil {
		return MutableReplaceRequest{}, fmt.Errorf("mutable replace request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request MutableReplaceRequest) Run() PublicationRun { return request.run }

// Document returns the closed mutable record kind.
func (request MutableReplaceRequest) Document() MutablePublicationDocument { return request.document }

// Path returns the exact mutable record path.
func (request MutableReplaceRequest) Path() SafeRelativePath { return request.path }

// ExpectedPrior returns the exact compare-and-swap expectation.
func (request MutableReplaceRequest) ExpectedPrior() MutableCASExpectation {
	return request.expectedPrior
}

// Replacement returns a caller-owned copy of replacement bytes.
func (request MutableReplaceRequest) Replacement() []byte { return cloneBytes(request.replacement) }

// SHA256 returns the canonical replacement-byte integrity identifier.
func (request MutableReplaceRequest) SHA256() string { return request.sha256 }

// Valid reports whether the request is a canonical, byte-bound CAS replacement.
func (request MutableReplaceRequest) Valid() bool { return request.validate() == nil }

func (request MutableReplaceRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if !request.document.Valid() {
		return fmt.Errorf("invalid mutable document %q", request.document)
	}
	expectedPath, err := canonicalMutablePublicationPath(request.run, request.document)
	if err != nil {
		return err
	}
	if request.path != expectedPath {
		return fmt.Errorf("mutable path %q is not canonical for document %q", request.path.String(), request.document)
	}
	if !request.expectedPrior.Valid() {
		return fmt.Errorf("invalid expected prior")
	}
	if len(request.replacement) == 0 {
		return fmt.Errorf("replacement bytes must be non-empty")
	}
	if err := validateSHA256(request.sha256); err != nil {
		return fmt.Errorf("replacement SHA-256: %w", err)
	}
	if sha256Identifier(request.replacement) != request.sha256 {
		return fmt.Errorf("replacement bytes do not match SHA-256")
	}
	return nil
}

// MutableReplaceDurability explicitly records whether replacement occurred
// before a post-replacement durability failure.
type MutableReplaceDurability string

const (
	MutableReplaceDurable   MutableReplaceDurability = "replaced_durable"
	MutableReplaceUndurable MutableReplaceDurability = "replaced_undurable"
)

// Valid reports whether durability is an explicit mutable replacement outcome.
func (durability MutableReplaceDurability) Valid() bool {
	return durability == MutableReplaceDurable || durability == MutableReplaceUndurable
}

// MutableReplaceResult exists only when the exact request replacement occurred.
// An undurable result requires ObserveRun before another CAS attempt.
type MutableReplaceResult struct {
	request    MutableReplaceRequest
	receipt    SecureWriteReceipt
	durability MutableReplaceDurability
}

// NewMutableReplaceResult validates a receipt against the exact replacement
// request, including destination, SHA-256, and byte length.
func NewMutableReplaceResult(
	request MutableReplaceRequest,
	receipt SecureWriteReceipt,
	durability MutableReplaceDurability,
) (MutableReplaceResult, error) {
	result := MutableReplaceResult{
		request:    cloneMutableReplaceRequest(request),
		receipt:    receipt,
		durability: durability,
	}
	if err := result.validate(); err != nil {
		return MutableReplaceResult{}, fmt.Errorf("mutable replace result: %w", err)
	}
	return result, nil
}

// Document returns the replaced mutable document kind.
func (result MutableReplaceResult) Document() MutablePublicationDocument {
	return result.request.Document()
}

// Path returns the replaced mutable record path.
func (result MutableReplaceResult) Path() SafeRelativePath { return result.request.Path() }

// Receipt returns the accepted replacement-byte receipt.
func (result MutableReplaceResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns whether post-replacement durability completed.
func (result MutableReplaceResult) Durability() MutableReplaceDurability { return result.durability }

// Valid reports whether result is coherent.
func (result MutableReplaceResult) Valid() bool { return result.validate() == nil }

func (result MutableReplaceResult) validate() error {
	if !result.request.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid replacement request or durability")
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Root() != result.request.Run().Root() ||
		result.receipt.Destination() != result.request.Path() ||
		result.receipt.SHA256() != result.request.SHA256() ||
		result.receipt.ByteLength() != int64(len(result.request.replacement)) {
		return fmt.Errorf("receipt does not match exact replacement request")
	}
	return nil
}

func cloneMutableReplaceRequest(request MutableReplaceRequest) MutableReplaceRequest {
	return MutableReplaceRequest{
		run:           request.run,
		document:      request.document,
		path:          request.path,
		expectedPrior: request.expectedPrior,
		replacement:   cloneBytes(request.replacement),
		sha256:        request.sha256,
	}
}

// PublicationEpoch binds a positive store epoch to its immutable epoch record.
type PublicationEpoch struct {
	value  uint64
	record ImmutablePublicationArtifact
}

// NewPublicationEpoch validates a positive composite epoch and its record.
func NewPublicationEpoch(value uint64, record ImmutablePublicationArtifact) (PublicationEpoch, error) {
	epoch := PublicationEpoch{value: value, record: record}
	if err := epoch.validate(); err != nil {
		return PublicationEpoch{}, fmt.Errorf("publication epoch: %w", err)
	}
	return epoch, nil
}

// Value returns the positive composite epoch value.
func (epoch PublicationEpoch) Value() uint64 { return epoch.value }

// Record returns the immutable epoch record.
func (epoch PublicationEpoch) Record() ImmutablePublicationArtifact { return epoch.record }

// Valid reports whether epoch is coherent.
func (epoch PublicationEpoch) Valid() bool { return epoch.validate() == nil }

func (epoch PublicationEpoch) validate() error {
	if epoch.value == 0 {
		return fmt.Errorf("epoch must be positive")
	}
	if !epoch.record.Valid() {
		return fmt.Errorf("invalid epoch record")
	}
	return nil
}

// CommitCompositeRequest creates, in order, immutable manifest and lineage
// members followed by an epoch record. The store must never replace any member.
type CommitCompositeRequest struct {
	run         PublicationRun
	final       FinalReviewIdentity
	manifest    ImmutablePublicationArtifact
	lineageEdge ImmutablePublicationArtifact
	epoch       PublicationEpoch
}

// NewCommitCompositeRequest validates one complete immutable composite write.
func NewCommitCompositeRequest(
	run PublicationRun,
	final FinalReviewIdentity,
	manifest ImmutablePublicationArtifact,
	lineageEdge ImmutablePublicationArtifact,
	epoch PublicationEpoch,
) (CommitCompositeRequest, error) {
	request := CommitCompositeRequest{
		run:         run,
		final:       final,
		manifest:    manifest,
		lineageEdge: lineageEdge,
		epoch:       epoch,
	}
	if err := request.validate(); err != nil {
		return CommitCompositeRequest{}, fmt.Errorf("commit composite request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request CommitCompositeRequest) Run() PublicationRun { return request.run }

// Final returns the already installed final identity bound by the composite.
func (request CommitCompositeRequest) Final() FinalReviewIdentity { return request.final }

// Manifest returns exact immutable manifest bytes.
func (request CommitCompositeRequest) Manifest() ImmutablePublicationArtifact {
	return request.manifest
}

// LineageEdge returns exact immutable lineage-edge bytes.
func (request CommitCompositeRequest) LineageEdge() ImmutablePublicationArtifact {
	return request.lineageEdge
}

// Epoch returns exact positive epoch identity and bytes.
func (request CommitCompositeRequest) Epoch() PublicationEpoch { return request.epoch }

func (request CommitCompositeRequest) validate() error {
	if !request.run.Valid() || !request.final.Valid() || !request.manifest.Valid() || !request.lineageEdge.Valid() || !request.epoch.Valid() {
		return fmt.Errorf("invalid run, final, manifest, lineage edge, or epoch")
	}
	if err := validateCanonicalFinalPath(request.run, request.final); err != nil {
		return err
	}
	manifestPath, lineagePath, epochPath, err := canonicalCompositePaths(request.run, request.final, request.epoch.Value())
	if err != nil {
		return err
	}
	if request.manifest.Path() != manifestPath || request.lineageEdge.Path() != lineagePath || request.epoch.Record().Path() != epochPath {
		return fmt.Errorf("composite member paths are not canonical")
	}
	return nil
}

// PrepareCompositeRequest binds one complete immutable composite to its three
// canonical durable staging sources. The final commit may only consume a
// PreparedComposite returned for this exact request.
type PrepareCompositeRequest struct {
	composite      CommitCompositeRequest
	stagedManifest SafeRelativePath
	stagedLineage  SafeRelativePath
	stagedEpoch    SafeRelativePath
}

// NewPrepareCompositeRequest derives and validates the only permitted
// temporary-source paths for an immutable composite.
func NewPrepareCompositeRequest(composite CommitCompositeRequest) (PrepareCompositeRequest, error) {
	if err := composite.validate(); err != nil {
		return PrepareCompositeRequest{}, fmt.Errorf("prepare composite request: invalid composite: %w", err)
	}
	manifest, lineage, epoch, err := canonicalPreparedCompositePaths(composite.Run())
	if err != nil {
		return PrepareCompositeRequest{}, fmt.Errorf("prepare composite request: staged paths: %w", err)
	}
	request := PrepareCompositeRequest{
		composite: composite, stagedManifest: manifest, stagedLineage: lineage, stagedEpoch: epoch,
	}
	if err := request.validate(); err != nil {
		return PrepareCompositeRequest{}, fmt.Errorf("prepare composite request: %w", err)
	}
	return request, nil
}

// Composite returns the exact immutable composite whose members are staged.
func (request PrepareCompositeRequest) Composite() CommitCompositeRequest { return request.composite }

// StagedManifestPath returns the canonical manifest temporary source.
func (request PrepareCompositeRequest) StagedManifestPath() SafeRelativePath {
	return request.stagedManifest
}

// StagedLineageEdgePath returns the canonical lineage-edge temporary source.
func (request PrepareCompositeRequest) StagedLineageEdgePath() SafeRelativePath {
	return request.stagedLineage
}

// StagedEpochPath returns the canonical epoch temporary source.
func (request PrepareCompositeRequest) StagedEpochPath() SafeRelativePath { return request.stagedEpoch }

func (request PrepareCompositeRequest) validate() error {
	if err := request.composite.validate(); err != nil {
		return err
	}
	expectedManifest, expectedLineage, expectedEpoch, err := canonicalPreparedCompositePaths(request.composite.Run())
	if err != nil {
		return err
	}
	if request.stagedManifest != expectedManifest || request.stagedLineage != expectedLineage || request.stagedEpoch != expectedEpoch {
		return fmt.Errorf("staged source paths are not canonical")
	}
	return requireDistinctPublicationPaths(request.stagedManifest, request.stagedLineage, request.stagedEpoch)
}

// CompositePreparationDurability distinguishes a completed fsync of all staged
// members from an installed-but-undurable preparation outcome.
type CompositePreparationDurability string

const (
	CompositePreparationDurable   CompositePreparationDurability = "durable"
	CompositePreparationUndurable CompositePreparationDurability = "installed_undurable"
)

// Valid reports whether durability is an explicit preparation outcome.
func (durability CompositePreparationDurability) Valid() bool {
	return durability == CompositePreparationDurable || durability == CompositePreparationUndurable
}

// PreparedComposite is the exact, fsync-attempted temporary composite consumed
// by CommitPreparedComposite. It includes no authority or recovery policy.
type PreparedComposite struct {
	request        PrepareCompositeRequest
	stagedManifest ImmutablePublicationArtifact
	stagedLineage  ImmutablePublicationArtifact
	stagedEpoch    ImmutablePublicationArtifact
	receipts       []SecureWriteReceipt
	durability     CompositePreparationDurability
}

// NewPreparedComposite validates staged exact-byte artifacts and receipts.
func NewPreparedComposite(
	request PrepareCompositeRequest,
	stagedManifest ImmutablePublicationArtifact,
	stagedLineage ImmutablePublicationArtifact,
	stagedEpoch ImmutablePublicationArtifact,
	receipts []SecureWriteReceipt,
	durability CompositePreparationDurability,
) (PreparedComposite, error) {
	prepared := PreparedComposite{
		request:        request,
		stagedManifest: stagedManifest,
		stagedLineage:  stagedLineage,
		stagedEpoch:    stagedEpoch,
		receipts:       cloneSecureWriteReceipts(receipts),
		durability:     durability,
	}
	if err := prepared.validate(); err != nil {
		return PreparedComposite{}, fmt.Errorf("prepared composite: %w", err)
	}
	return prepared, nil
}

// Request returns the bound staged composite request.
func (prepared PreparedComposite) Request() PrepareCompositeRequest { return prepared.request }

// Composite returns the immutable composite that may be committed.
func (prepared PreparedComposite) Composite() CommitCompositeRequest {
	return prepared.request.Composite()
}

// StagedManifest returns exact staged manifest material.
func (prepared PreparedComposite) StagedManifest() ImmutablePublicationArtifact {
	return prepared.stagedManifest
}

// StagedLineageEdge returns exact staged lineage-edge material.
func (prepared PreparedComposite) StagedLineageEdge() ImmutablePublicationArtifact {
	return prepared.stagedLineage
}

// StagedEpoch returns exact staged epoch material.
func (prepared PreparedComposite) StagedEpoch() ImmutablePublicationArtifact {
	return prepared.stagedEpoch
}

// Receipts returns caller-owned preparation receipts in canonical source order.
func (prepared PreparedComposite) Receipts() []SecureWriteReceipt {
	return cloneSecureWriteReceipts(prepared.receipts)
}

// Durability returns the explicit preparation durability outcome.
func (prepared PreparedComposite) Durability() CompositePreparationDurability {
	return prepared.durability
}

// Valid reports whether the exact staged material is coherent.
func (prepared PreparedComposite) Valid() bool { return prepared.validate() == nil }

func (prepared PreparedComposite) validate() error {
	if err := prepared.request.validate(); err != nil {
		return err
	}
	if !prepared.stagedManifest.Valid() || !prepared.stagedLineage.Valid() ||
		!prepared.stagedEpoch.Valid() || !prepared.durability.Valid() {
		return fmt.Errorf("invalid staged artifact or durability")
	}
	composite := prepared.request.Composite()
	if !sameArtifactBytes(prepared.stagedManifest, composite.Manifest()) ||
		!sameArtifactBytes(prepared.stagedLineage, composite.LineageEdge()) ||
		!sameArtifactBytes(prepared.stagedEpoch, composite.Epoch().Record()) {
		return fmt.Errorf("staged artifact does not match bound composite")
	}
	if prepared.stagedManifest.Path() != prepared.request.StagedManifestPath() ||
		prepared.stagedLineage.Path() != prepared.request.StagedLineageEdgePath() ||
		prepared.stagedEpoch.Path() != prepared.request.StagedEpochPath() {
		return fmt.Errorf("staged artifact path is not canonical")
	}
	if len(prepared.receipts) != 3 {
		return fmt.Errorf("requires three staged receipts")
	}
	staged := []ImmutablePublicationArtifact{
		prepared.stagedManifest, prepared.stagedLineage, prepared.stagedEpoch,
	}
	for index, receipt := range prepared.receipts {
		if err := validateSecureWriteReceipt(receipt); err != nil {
			return fmt.Errorf("receipt %d: %w", index, err)
		}
		if receipt.Destination() != staged[index].Path() ||
			receipt.SHA256() != staged[index].SHA256() ||
			receipt.ByteLength() != int64(len(staged[index].Bytes())) {
			return fmt.Errorf("receipt %d does not match staged artifact", index)
		}
	}
	return nil
}

func sameArtifactBytes(left, right ImmutablePublicationArtifact) bool {
	return left.SHA256() == right.SHA256()
}

// CompositeCommitPhase explicitly reports how far a no-replace composite write
// reached. A non-durable phase is a re-observe boundary, never a retry signal.
type CompositeCommitPhase string

const (
	CompositeManifestInstalled       CompositeCommitPhase = "manifest_installed"
	CompositeMembersInstalled        CompositeCommitPhase = "members_installed_epoch_absent"
	CompositeEpochInstalledUndurable CompositeCommitPhase = "epoch_installed_undurable"
	CompositeCommittedDurable        CompositeCommitPhase = "committed_durable"
)

// Valid reports whether phase is a closed composite outcome.
func (phase CompositeCommitPhase) Valid() bool {
	switch phase {
	case CompositeManifestInstalled, CompositeMembersInstalled, CompositeEpochInstalledUndurable, CompositeCommittedDurable:
		return true
	default:
		return false
	}
}

// CompositeCommitResult records installed composite-member receipts in commit
// order. Receipts contains one entry after the manifest move, two when the
// epoch is absent, and three after epoch installation.
type CompositeCommitResult struct {
	phase    CompositeCommitPhase
	receipts []SecureWriteReceipt
}

// NewCompositeCommitResult validates installed composite member receipts and
// takes ownership of receipts.
func NewCompositeCommitResult(phase CompositeCommitPhase, receipts []SecureWriteReceipt) (CompositeCommitResult, error) {
	result := CompositeCommitResult{phase: phase, receipts: cloneSecureWriteReceipts(receipts)}
	if err := result.validate(); err != nil {
		return CompositeCommitResult{}, fmt.Errorf("composite commit result: %w", err)
	}
	return result, nil
}

// Phase returns the explicit composite progress outcome.
func (result CompositeCommitResult) Phase() CompositeCommitPhase { return result.phase }

// Receipts returns caller-owned installed-member receipts in commit order.
func (result CompositeCommitResult) Receipts() []SecureWriteReceipt {
	return cloneSecureWriteReceipts(result.receipts)
}

// Valid reports whether result is coherent.
func (result CompositeCommitResult) Valid() bool { return result.validate() == nil }

func (result CompositeCommitResult) validate() error {
	if !result.phase.Valid() {
		return fmt.Errorf("invalid composite phase %q", result.phase)
	}
	wantCount := 3
	switch result.phase {
	case CompositeManifestInstalled:
		wantCount = 1
	case CompositeMembersInstalled:
		wantCount = 2
	}
	if len(result.receipts) != wantCount {
		return fmt.Errorf("phase %q requires %d receipts", result.phase, wantCount)
	}
	paths := make([]SafeRelativePath, len(result.receipts))
	for index, receipt := range result.receipts {
		if err := validateSecureWriteReceipt(receipt); err != nil {
			return fmt.Errorf("receipt %d: %w", index, err)
		}
		paths[index] = receipt.Destination()
	}
	return requireDistinctPublicationPaths(paths...)
}

// ReadCommittedSnapshotRequest reads only one P2-authoritative committed
// snapshot, bounded by a positive per-member byte cap.
type ReadCommittedSnapshotRequest struct {
	run          PublicationRun
	maxReadBytes int64
}

// NewReadCommittedSnapshotRequest validates a P2 snapshot read request.
func NewReadCommittedSnapshotRequest(run PublicationRun, maxReadBytes int64) (ReadCommittedSnapshotRequest, error) {
	request := ReadCommittedSnapshotRequest{run: run, maxReadBytes: maxReadBytes}
	if err := request.validate(); err != nil {
		return ReadCommittedSnapshotRequest{}, fmt.Errorf("read committed snapshot request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request ReadCommittedSnapshotRequest) Run() PublicationRun { return request.run }

// MaxReadBytes returns the positive per-member read cap.
func (request ReadCommittedSnapshotRequest) MaxReadBytes() int64 { return request.maxReadBytes }

func (request ReadCommittedSnapshotRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if request.maxReadBytes <= 0 {
		return fmt.Errorf("max read bytes must be positive")
	}
	return nil
}

// CommittedPublicationSnapshot is exact P2 snapshot data. It is constructed
// only after the store verifies composite linkage, paths, hashes, schemas,
// regular-file type, and no-symlink containment.
type CommittedPublicationSnapshot struct {
	final       FinalReviewArtifact
	manifest    ImmutablePublicationArtifact
	lineageEdge ImmutablePublicationArtifact
	epoch       PublicationEpoch
}

// NewCommittedPublicationSnapshot validates a complete immutable P2 snapshot.
func NewCommittedPublicationSnapshot(
	final FinalReviewArtifact,
	manifest ImmutablePublicationArtifact,
	lineageEdge ImmutablePublicationArtifact,
	epoch PublicationEpoch,
) (CommittedPublicationSnapshot, error) {
	snapshot := CommittedPublicationSnapshot{
		final:       final,
		manifest:    manifest,
		lineageEdge: lineageEdge,
		epoch:       epoch,
	}
	if err := snapshot.validate(); err != nil {
		return CommittedPublicationSnapshot{}, fmt.Errorf("committed publication snapshot: %w", err)
	}
	return snapshot, nil
}

// Final returns a defensive final artifact value whose Bytes accessor copies.
func (snapshot CommittedPublicationSnapshot) Final() FinalReviewArtifact { return snapshot.final }

// Manifest returns a defensive immutable artifact value whose Bytes copies.
func (snapshot CommittedPublicationSnapshot) Manifest() ImmutablePublicationArtifact {
	return snapshot.manifest
}

// LineageEdge returns a defensive immutable artifact value whose Bytes copies.
func (snapshot CommittedPublicationSnapshot) LineageEdge() ImmutablePublicationArtifact {
	return snapshot.lineageEdge
}

// Epoch returns the positive composite epoch.
func (snapshot CommittedPublicationSnapshot) Epoch() PublicationEpoch { return snapshot.epoch }

// Valid reports whether snapshot has complete, distinct immutable members.
func (snapshot CommittedPublicationSnapshot) Valid() bool { return snapshot.validate() == nil }

func (snapshot CommittedPublicationSnapshot) validate() error {
	if !snapshot.final.Valid() || !snapshot.manifest.Valid() || !snapshot.lineageEdge.Valid() || !snapshot.epoch.Valid() {
		return fmt.Errorf("invalid final, manifest, lineage edge, or epoch")
	}
	return requireDistinctPublicationPaths(snapshot.final.Identity().Path(), snapshot.manifest.Path(), snapshot.lineageEdge.Path(), snapshot.epoch.Record().Path())
}

// ErrCorruptionObservationStale reports that the live durable classifier facts
// no longer match the observation that authorized a diagnostic write.
var ErrCorruptionObservationStale = errors.New("corruption observation is stale")

// CorruptionObservationCAS is an opaque, exact snapshot of the durable
// classifier facts that selected immutable corruption diagnostics.
type CorruptionObservationCAS struct {
	journalState     domain.PersistedJournalState
	observation      domain.DurableObservationClass
	storedNormalExit *domain.OperationalExitCode
	ambiguityReasons []string
	reasonCodes      []string
	storeEpoch       uint64
}

// NewCorruptionObservationCAS captures only a valid corrupt publication
// observation. It records both raw classifier input and the classifier-derived
// reason codes so every corrupt branch can be matched under the write lock.
func NewCorruptionObservationCAS(observation PublicationObservation) (CorruptionObservationCAS, error) {
	if !observation.Valid() {
		return CorruptionObservationCAS{}, fmt.Errorf("corruption observation CAS: invalid observation")
	}
	input := observation.ClassifierInput()
	decision, err := domain.ClassifyPublication(input)
	if err != nil {
		return CorruptionObservationCAS{}, fmt.Errorf("corruption observation CAS: %w", err)
	}
	if decision.Status() != domain.PublicationCorrupt ||
		decision.Action() != domain.RecoveryActionEmitImmutableCorruptionDiagnostic {
		return CorruptionObservationCAS{}, fmt.Errorf("corruption observation CAS: observation is not corrupt")
	}
	cas := CorruptionObservationCAS{
		journalState:     input.JournalState(),
		observation:      input.Observation(),
		ambiguityReasons: input.AmbiguityReasons(),
		reasonCodes:      decision.Reasons(),
		storeEpoch:       observation.StoreEpoch(),
	}
	if exit, present := input.StoredNormalExit(); present {
		exitCopy := exit
		cas.storedNormalExit = &exitCopy
	}
	if !cas.Valid() {
		return CorruptionObservationCAS{}, fmt.Errorf("corruption observation CAS: invalid captured facts")
	}
	return cas, nil
}

// StoreEpoch returns the exact observed store epoch.
func (cas CorruptionObservationCAS) StoreEpoch() uint64 { return cas.storeEpoch }

// ReasonCodes returns the classifier-derived corruption reason codes.
func (cas CorruptionObservationCAS) ReasonCodes() []string { return cloneStrings(cas.reasonCodes) }

// Valid reports whether the CAS contains a complete corrupt classifier snapshot.
func (cas CorruptionObservationCAS) Valid() bool {
	if cas.storeEpoch == 0 || !cas.journalState.Valid() || !cas.observation.Valid() {
		return false
	}
	var storedNormalExit *domain.OperationalExitCode
	if cas.storedNormalExit != nil {
		exitCopy := *cas.storedNormalExit
		storedNormalExit = &exitCopy
	}
	input, err := domain.NewPublicationClassifierInput(
		cas.journalState,
		cas.observation,
		storedNormalExit,
		cas.ambiguityReasons,
	)
	if err != nil {
		return false
	}
	decision, err := domain.ClassifyPublication(input)
	if err != nil ||
		decision.Status() != domain.PublicationCorrupt ||
		decision.Action() != domain.RecoveryActionEmitImmutableCorruptionDiagnostic {
		return false
	}
	decisionReasons := decision.Reasons()
	if len(decisionReasons) != len(cas.reasonCodes) {
		return false
	}
	for index := range decisionReasons {
		if decisionReasons[index] != cas.reasonCodes[index] {
			return false
		}
	}
	return true
}

// Matches reports whether observation is exactly the same durable classifier
// snapshot. Stores call this only against a re-read made under their write lock.
func (cas CorruptionObservationCAS) Matches(observation PublicationObservation) bool {
	if !cas.Valid() || !observation.Valid() || observation.StoreEpoch() != cas.storeEpoch {
		return false
	}
	input := observation.ClassifierInput()
	if input.JournalState() != cas.journalState || input.Observation() != cas.observation {
		return false
	}
	actualExit, actualExitPresent := input.StoredNormalExit()
	if actualExitPresent != (cas.storedNormalExit != nil) {
		return false
	}
	if actualExitPresent && actualExit != *cas.storedNormalExit {
		return false
	}
	actualReasons := input.AmbiguityReasons()
	if len(actualReasons) != len(cas.ambiguityReasons) {
		return false
	}
	for index := range actualReasons {
		if actualReasons[index] != cas.ambiguityReasons[index] {
			return false
		}
	}
	return true
}

// CorruptionDiagnosticRequest writes one immutable, append-only corruption
// diagnostic. It has no mutable status or recovery-adoption capability.
type CorruptionDiagnosticRequest struct {
	run         PublicationRun
	observation CorruptionObservationCAS
	diagnostic  ImmutablePublicationArtifact
}

// NewCorruptionDiagnosticRequest validates immutable diagnostic contents and
// binds them to one opaque corrupt-observation CAS snapshot.
func NewCorruptionDiagnosticRequest(
	run PublicationRun,
	observation CorruptionObservationCAS,
	diagnostic ImmutablePublicationArtifact,
) (CorruptionDiagnosticRequest, error) {
	request := CorruptionDiagnosticRequest{
		run:         run,
		observation: observation,
		diagnostic:  diagnostic,
	}
	if err := request.validate(); err != nil {
		return CorruptionDiagnosticRequest{}, fmt.Errorf("corruption diagnostic request: %w", err)
	}
	return request, nil
}

// Run returns the exact publication scope.
func (request CorruptionDiagnosticRequest) Run() PublicationRun { return request.run }

// Observation returns the exact opaque corruption observation CAS.
func (request CorruptionDiagnosticRequest) Observation() CorruptionObservationCAS {
	return request.observation
}

// ObservationEpoch returns the CAS-bound store epoch.
func (request CorruptionDiagnosticRequest) ObservationEpoch() uint64 {
	return request.observation.StoreEpoch()
}

// Diagnostic returns exact immutable diagnostic bytes.
func (request CorruptionDiagnosticRequest) Diagnostic() ImmutablePublicationArtifact {
	return request.diagnostic
}

// ReasonCodes returns caller-owned stable corruption reason codes.
func (request CorruptionDiagnosticRequest) ReasonCodes() []string {
	return request.observation.ReasonCodes()
}

// Valid reports whether request is fully bound to a corrupt observation.
func (request CorruptionDiagnosticRequest) Valid() bool { return request.validate() == nil }

func (request CorruptionDiagnosticRequest) validate() error {
	if !request.run.Valid() {
		return fmt.Errorf("invalid run")
	}
	if !request.observation.Valid() {
		return fmt.Errorf("invalid corruption observation CAS")
	}
	if !request.diagnostic.Valid() {
		return fmt.Errorf("invalid diagnostic")
	}
	if err := validateDiagnosticReasonCodes(request.observation.ReasonCodes()); err != nil {
		return err
	}
	expectedPath, err := canonicalCorruptionDiagnosticPath(request.run, request.observation.StoreEpoch())
	if err != nil {
		return err
	}
	if request.diagnostic.Path() != expectedPath {
		return fmt.Errorf("diagnostic path %q is not canonical", request.diagnostic.Path().String())
	}
	if err := validateCorruptionDiagnosticPayload(
		request.diagnostic.Bytes(),
		request.run,
		request.observation.StoreEpoch(),
		request.observation.ReasonCodes(),
	); err != nil {
		return err
	}
	return nil
}

// CorruptionDiagnosticDurability explicitly records whether an immutable
// diagnostic was installed before a post-install durability failure.
type CorruptionDiagnosticDurability string

const (
	CorruptionDiagnosticDurable   CorruptionDiagnosticDurability = "diagnostic_durable"
	CorruptionDiagnosticUndurable CorruptionDiagnosticDurability = "diagnostic_undurable"
)

// Valid reports whether durability is an explicit diagnostic outcome.
func (durability CorruptionDiagnosticDurability) Valid() bool {
	return durability == CorruptionDiagnosticDurable || durability == CorruptionDiagnosticUndurable
}

// CorruptionDiagnosticResult exists only after immutable diagnostic bytes were
// installed. An undurable diagnostic must be re-observed, not retried blindly.
type CorruptionDiagnosticResult struct {
	diagnostic ImmutablePublicationArtifact
	receipt    SecureWriteReceipt
	durability CorruptionDiagnosticDurability
}

// NewCorruptionDiagnosticResult validates an installed diagnostic receipt.
func NewCorruptionDiagnosticResult(diagnostic ImmutablePublicationArtifact, receipt SecureWriteReceipt, durability CorruptionDiagnosticDurability) (CorruptionDiagnosticResult, error) {
	result := CorruptionDiagnosticResult{diagnostic: diagnostic, receipt: receipt, durability: durability}
	if err := result.validate(); err != nil {
		return CorruptionDiagnosticResult{}, fmt.Errorf("corruption diagnostic result: %w", err)
	}
	return result, nil
}

// NewCorruptionDiagnosticResultForRequest validates a diagnostic receipt
// against the exact immutable diagnostic carried by its write request.
func NewCorruptionDiagnosticResultForRequest(
	request CorruptionDiagnosticRequest,
	receipt SecureWriteReceipt,
	durability CorruptionDiagnosticDurability,
) (CorruptionDiagnosticResult, error) {
	if !request.Valid() {
		return CorruptionDiagnosticResult{}, fmt.Errorf("corruption diagnostic result for request: invalid request")
	}
	result, err := NewCorruptionDiagnosticResult(request.Diagnostic(), receipt, durability)
	if err != nil {
		return CorruptionDiagnosticResult{}, err
	}
	if result.Receipt().Root() != request.Run().Root() {
		return CorruptionDiagnosticResult{}, fmt.Errorf("corruption diagnostic result for request: receipt root does not match request")
	}
	return result, nil
}

// Diagnostic returns the immutable installed diagnostic identity and bytes.
func (result CorruptionDiagnosticResult) Diagnostic() ImmutablePublicationArtifact {
	return result.diagnostic
}

// Receipt returns the accepted diagnostic-byte receipt.
func (result CorruptionDiagnosticResult) Receipt() SecureWriteReceipt { return result.receipt }

// Durability returns whether post-install durability completed.
func (result CorruptionDiagnosticResult) Durability() CorruptionDiagnosticDurability {
	return result.durability
}

// Valid reports whether result is coherent.
func (result CorruptionDiagnosticResult) Valid() bool { return result.validate() == nil }

func (result CorruptionDiagnosticResult) validate() error {
	if !result.diagnostic.Valid() || !result.durability.Valid() {
		return fmt.Errorf("invalid diagnostic or durability")
	}
	if err := validateSecureWriteReceipt(result.receipt); err != nil {
		return err
	}
	if result.receipt.Destination() != result.diagnostic.Path() || result.receipt.SHA256() != result.diagnostic.SHA256() {
		return fmt.Errorf("receipt does not match diagnostic identity")
	}
	if result.receipt.ByteLength() != int64(len(result.diagnostic.Bytes())) {
		return fmt.Errorf("receipt byte length does not match diagnostic bytes")
	}
	return nil
}

// PublicationEpochCommitStore holds one root-scoped durable publication
// transaction from epoch selection through the callback. It must select an epoch
// greater than every epoch previously committed beneath root and must not release
// its cross-process authority until callback returns. The callback may use the
// same store's PublicationStore methods to complete the publication.
type PublicationEpochCommitStore interface {
	WithNextPublicationEpoch(context.Context, AnchoredRoot, func(context.Context, uint64) error) error
}

// PublicationStore is a persistence-only publication boundary. Its adapter
// validates physical safety and exact durable facts, but does not classify,
// choose a recovery action, synthesize a final, or project an exit. Callers
// sequence ObserveRun, PersistValidatedCandidate, PrepareComposite,
// StageFinal/InstallFinal, CommitPreparedComposite, and ObserveRun again under
// app-owned recovery policy.
//
// A result with an Undurable state is returned with a non-nil error after the
// corresponding installation or replacement occurred. Callers must re-observe
// rather than retry it. A non-nil error paired with any valid result or an
// explicit durability or composite phase that indicates an installed effect
// likewise requires observation, even when request binding does not match. A
// failed operation with no installed effect returns the zero result and a
// non-nil error.

type PublicationStore interface {
	IssueReviewID(context.Context, IssueReviewIDRequest) (IssuedReviewID, error)
	ResolveRun(context.Context, ResolvePublicationRunRequest) (PublicationRun, error)
	// ObserveRun returns classifier input and any permitted recovery material from
	// one atomic durable observation; adapters must not split that observation
	// across a second racing read.
	ObserveRun(context.Context, ObserveRunRequest) (PublicationObservation, error)
	PersistValidatedCandidate(context.Context, PersistValidatedCandidateRequest) (PersistValidatedCandidateResult, error)
	PersistAuxiliaryArtifact(context.Context, PersistAuxiliaryArtifactRequest) (PersistAuxiliaryArtifactResult, error)
	ReadAuxiliaryArtifact(context.Context, ReadAuxiliaryArtifactRequest) (ImmutablePublicationArtifact, error)
	PrepareComposite(context.Context, PrepareCompositeRequest) (PreparedComposite, error)
	StageFinal(context.Context, StageFinalRequest) (StageFinalResult, error)
	AdoptStagedFinal(context.Context, AdoptStagedFinalRequest) (StageFinalResult, error)
	InstallFinal(context.Context, InstallFinalRequest) (InstallFinalResult, error)
	ReplaceMutable(context.Context, MutableReplaceRequest) (MutableReplaceResult, error)
	CommitPreparedComposite(context.Context, PreparedComposite) (CompositeCommitResult, error)
	ReadCommittedSnapshot(context.Context, ReadCommittedSnapshotRequest) (CommittedPublicationSnapshot, error)
	WriteCorruptionDiagnostic(context.Context, CorruptionDiagnosticRequest) (CorruptionDiagnosticResult, error)
}

func validSessionID(id domain.SessionID) bool {
	_, err := domain.ParseSessionID(id.String())
	return err == nil
}

func validRunID(id domain.RunID) bool {
	_, err := domain.ParseRunID(id.String())
	return err == nil
}

func validReviewID(id domain.ReviewID) bool {
	_, err := domain.ParseReviewID(id.String())
	return err == nil
}
func validateCanonicalFinalPath(run PublicationRun, final FinalReviewIdentity) error {
	expected, err := NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/review_" + final.ReviewID().String() + ".json")
	if err != nil {
		return fmt.Errorf("canonical final path: %w", err)
	}
	if final.Path() != expected {
		return fmt.Errorf("final path %q is not canonical for review ID", final.Path().String())
	}
	return nil
}
func canonicalStagedFinalPath(run PublicationRun, final FinalReviewIdentity) (SafeRelativePath, error) {
	if !run.Valid() || !final.Valid() {
		return SafeRelativePath{}, fmt.Errorf("invalid run or final")
	}
	return NewSafeRelativePath(
		run.SessionID().String() + "/" + run.RunID().String() +
			"/publication/staged/review_" + final.ReviewID().String() + ".json.tmp",
	)
}
func canonicalStagedFinalPathForFinal(final FinalReviewIdentity) (SafeRelativePath, error) {
	sessionID, runID, err := publicationScopeForFinal(final)
	if err != nil {
		return SafeRelativePath{}, err
	}
	return NewSafeRelativePath(
		sessionID.String() + "/" + runID.String() +
			"/publication/staged/review_" + final.ReviewID().String() + ".json.tmp",
	)
}

func canonicalMutablePublicationPathForFinal(
	final FinalReviewIdentity,
	document MutablePublicationDocument,
) (SafeRelativePath, error) {
	sessionID, runID, err := publicationScopeForFinal(final)
	if err != nil {
		return SafeRelativePath{}, err
	}
	switch document {
	case MutablePublicationStatus:
		return NewSafeRelativePath(sessionID.String() + "/" + runID.String() + "/status.json")
	case MutablePublicationJournal:
		return NewSafeRelativePath(sessionID.String() + "/" + runID.String() + "/publication/journal.json")
	default:
		return SafeRelativePath{}, fmt.Errorf("invalid mutable document %q", document)
	}
}

func publicationScopeForFinal(final FinalReviewIdentity) (domain.SessionID, domain.RunID, error) {
	if !final.Valid() {
		return domain.SessionID{}, domain.RunID{}, fmt.Errorf("invalid final")
	}
	parts := strings.Split(final.Path().String(), "/")
	if len(parts) != 3 || parts[2] != "review_"+final.ReviewID().String()+".json" {
		return domain.SessionID{}, domain.RunID{}, fmt.Errorf("final path is not canonical")
	}
	sessionID, err := domain.ParseSessionID(parts[0])
	if err != nil {
		return domain.SessionID{}, domain.RunID{}, fmt.Errorf("final path session ID: %w", err)
	}
	runID, err := domain.ParseRunID(parts[1])
	if err != nil {
		return domain.SessionID{}, domain.RunID{}, fmt.Errorf("final path run ID: %w", err)
	}
	return sessionID, runID, nil
}

func canonicalMutablePublicationPath(run PublicationRun, document MutablePublicationDocument) (SafeRelativePath, error) {
	if !run.Valid() || !document.Valid() {
		return SafeRelativePath{}, fmt.Errorf("invalid run or mutable document")
	}
	switch document {
	case MutablePublicationStatus:
		return NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/status.json")
	case MutablePublicationJournal:
		return NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/publication/journal.json")
	default:
		return SafeRelativePath{}, fmt.Errorf("invalid mutable document %q", document)
	}
}

func canonicalCompositePaths(
	run PublicationRun,
	final FinalReviewIdentity,
	epoch uint64,
) (SafeRelativePath, SafeRelativePath, SafeRelativePath, error) {
	if err := validateCanonicalFinalPath(run, final); err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	if epoch == 0 {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, fmt.Errorf("epoch must be positive")
	}
	manifest, err := NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/manifest.json")
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	lineage, err := NewSafeRelativePath("store/lineage-edges/e_" + final.ReviewID().String() + ".json")
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	epochPath, err := NewSafeRelativePath(fmt.Sprintf("store/epochs/epoch_%020d.json", epoch))
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	return manifest, lineage, epochPath, nil
}

func canonicalPreparedCompositePaths(run PublicationRun) (SafeRelativePath, SafeRelativePath, SafeRelativePath, error) {
	if !run.Valid() {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, fmt.Errorf("invalid run")
	}
	prefix := run.SessionID().String() + "/" + run.RunID().String() + "/publication/staged/"
	manifest, err := NewSafeRelativePath(prefix + "manifest.json.tmp")
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	lineage, err := NewSafeRelativePath(prefix + "lineage-edge.json.tmp")
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	epoch, err := NewSafeRelativePath(prefix + "epoch.json.tmp")
	if err != nil {
		return SafeRelativePath{}, SafeRelativePath{}, SafeRelativePath{}, err
	}
	return manifest, lineage, epoch, nil
}

func canonicalCorruptionDiagnosticPath(run PublicationRun, observationEpoch uint64) (SafeRelativePath, error) {
	if !run.Valid() || observationEpoch == 0 {
		return SafeRelativePath{}, fmt.Errorf("invalid run or observation epoch")
	}
	return NewSafeRelativePath(fmt.Sprintf(
		"%s/%s/recovery/diagnostics/publication-corrupt_%d.json",
		run.SessionID().String(),
		run.RunID().String(),
		observationEpoch,
	))
}

type corruptionDiagnosticWire struct {
	SchemaVersion    string   `json:"schema_version"`
	SessionID        string   `json:"session_id"`
	RunID            string   `json:"run_id"`
	ObservationEpoch uint64   `json:"observation_epoch"`
	ReasonCodes      []string `json:"reason_codes"`
}

func validateCorruptionDiagnosticPayload(
	payload []byte,
	run PublicationRun,
	observationEpoch uint64,
	reasonCodes []string,
) error {
	if err := rejectDuplicateDiagnosticJSONKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var wire corruptionDiagnosticWire
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("diagnostic payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("diagnostic payload has trailing data")
	}
	if wire.SchemaVersion != "mulgae-publication-corruption.v1" ||
		wire.SessionID != run.SessionID().String() ||
		wire.RunID != run.RunID().String() ||
		wire.ObservationEpoch != observationEpoch {
		return fmt.Errorf("diagnostic payload does not match request identity")
	}
	if len(wire.ReasonCodes) != len(reasonCodes) {
		return fmt.Errorf("diagnostic payload reason codes do not match request")
	}
	for index := range reasonCodes {
		if wire.ReasonCodes[index] != reasonCodes[index] {
			return fmt.Errorf("diagnostic payload reason codes do not match request")
		}
	}
	return nil
}
func rejectDuplicateDiagnosticJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("diagnostic payload: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("diagnostic payload must be an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("diagnostic payload: %w", err)
		}
		name, ok := key.(string)
		if !ok {
			return fmt.Errorf("diagnostic payload has an invalid key")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("diagnostic payload has duplicate key %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("diagnostic payload: %w", err)
		}
	}
	if token, err := decoder.Token(); err != nil {
		return fmt.Errorf("diagnostic payload: %w", err)
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return fmt.Errorf("diagnostic payload has an invalid object terminator")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("diagnostic payload has trailing data")
	}
	return nil
}

func validateSecureWriteReceipt(receipt SecureWriteReceipt) error {
	_, err := NewSecureWriteReceipt(
		receipt.Root(),
		receipt.Destination(),
		receipt.SHA256(),
		receipt.ByteLength(),
		receipt.Channel(),
		receipt.SourceIDs(),
	)
	if err != nil {
		return fmt.Errorf("invalid secure write receipt: %w", err)
	}
	return nil
}

func cloneSecureWriteReceipts(receipts []SecureWriteReceipt) []SecureWriteReceipt {
	if receipts == nil {
		return nil
	}
	cloned := make([]SecureWriteReceipt, len(receipts))
	copy(cloned, receipts)
	return cloned
}

func requireDistinctPublicationPaths(paths ...SafeRelativePath) error {
	seen := make(map[SafeRelativePath]struct{}, len(paths))
	for _, path := range paths {
		if !path.Valid() {
			return fmt.Errorf("invalid path")
		}
		if _, exists := seen[path]; exists {
			return fmt.Errorf("duplicate immutable path %q", path.String())
		}
		seen[path] = struct{}{}
	}
	return nil
}

func validateDiagnosticReasonCodes(reasonCodes []string) error {
	if len(reasonCodes) == 0 {
		return fmt.Errorf("must contain at least one reason code")
	}
	seen := make(map[string]struct{}, len(reasonCodes))
	for _, reasonCode := range reasonCodes {
		if err := validateDiagnosticReasonCode(reasonCode); err != nil {
			return err
		}
		if _, duplicate := seen[reasonCode]; duplicate {
			return fmt.Errorf("duplicate reason code %q", reasonCode)
		}
		seen[reasonCode] = struct{}{}
	}
	return nil
}

func validateDiagnosticReasonCode(reasonCode string) error {
	if len(reasonCode) == 0 || len(reasonCode) > 64 {
		return fmt.Errorf("reason code must be 1 through 64 bytes")
	}
	for index, character := range reasonCode {
		if index == 0 {
			if character < 'a' || character > 'z' {
				return fmt.Errorf("reason code must begin with lowercase ASCII letter")
			}
			continue
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return fmt.Errorf("reason code must contain lowercase ASCII letters, digits, or underscores")
	}
	return nil
}

func sameFinalReviewArtifactIdentity(left, right FinalReviewArtifact) bool {
	return left.Valid() && right.Valid() &&
		left.Identity() == right.Identity() &&
		bytes.Equal(left.Bytes(), right.Bytes())
}
