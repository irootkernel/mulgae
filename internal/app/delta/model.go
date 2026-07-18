// Package delta starts immutable A-to-B child review runs.
package delta

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	// MaxTargetBytes is the fixed review-target cap. Targets are rejected rather
	// than truncated so their identity always describes the exact captured bytes.
	MaxTargetBytes = 180000
	maxTargetValue = 4096
)

// TargetKind identifies the canonical input selected for the current target
// capture. Diff is a Git-backed capture; patch and stdin are byte captures.
type TargetKind string

const (
	TargetDiff  TargetKind = "diff"
	TargetPatch TargetKind = "patch"
	TargetStdin TargetKind = "stdin"
)

// TargetRequest contains only an untrusted selector. Capturers must resolve it
// to a materialized immutable target before returning.
type TargetRequest struct {
	Kind  TargetKind
	Value string
}

func (request TargetRequest) validate() error {
	switch request.Kind {
	case TargetDiff, TargetPatch, TargetStdin:
	default:
		return fmt.Errorf("delta target: unsupported kind %q", request.Kind)
	}
	if len(request.Value) == 0 || len(request.Value) > maxTargetValue || strings.TrimSpace(request.Value) == "" || strings.ContainsAny(request.Value, "\x00\r\n") {
		return fmt.Errorf("delta target: value is required and must be a safe bounded string")
	}
	return nil
}

// ImmutableTarget preserves the request kind, exact bounded captured bytes, and
// canonical domain identity. Git metadata is retained only for a diff capture.
type ImmutableTarget struct {
	kind        TargetKind
	value       string
	bytes       []byte
	sha256      string
	identity    domain.TargetIdentity
	persistedP2 bool
}

// NewGitImmutableTarget materializes a diff request from a resolved Git capture.
func NewGitImmutableTarget(value string, captured ports.CapturedGitTarget) (ImmutableTarget, error) {
	request := TargetRequest{Kind: TargetDiff, Value: value}
	if err := request.validate(); err != nil {
		return ImmutableTarget{}, err
	}
	targetBytes := captured.Bytes()
	if err := validTargetBytes(targetBytes); err != nil {
		return ImmutableTarget{}, err
	}
	hash := targetDigest(targetBytes)
	if strings.TrimPrefix(captured.SHA256(), "sha256:") != hash {
		return ImmutableTarget{}, fmt.Errorf("delta target: Git capture hash does not match bytes")
	}
	input := domain.TargetIdentityInput{
		Kind: domain.TargetGit, SHA256: hash, RepositoryID: captured.RepositoryID(),
		BaseObjectID: captured.BaseObjectID().String(), HeadObjectID: captured.HeadObjectID().String(),
		HeadTreeObjectID: captured.HeadTreeID().String(),
	}
	if index, exists := captured.IndexTreeID(); exists {
		input.IndexTreeObjectID = index.String()
	}
	identity, err := domain.NewTargetIdentity(input)
	if err != nil {
		return ImmutableTarget{}, fmt.Errorf("delta target: invalid Git identity: %w", err)
	}
	return ImmutableTarget{kind: request.Kind, value: request.Value, bytes: append([]byte(nil), targetBytes...), sha256: hash, identity: identity}, nil
}

// NewByteImmutableTarget materializes a patch or stdin request without assigning
// Git object identities to non-Git input.
func NewByteImmutableTarget(kind TargetKind, value string, targetBytes []byte) (ImmutableTarget, error) {
	request := TargetRequest{Kind: kind, Value: value}
	if err := request.validate(); err != nil {
		return ImmutableTarget{}, err
	}
	if kind != TargetPatch && kind != TargetStdin {
		return ImmutableTarget{}, fmt.Errorf("delta target: byte capture kind must be patch or stdin")
	}
	if err := validTargetBytes(targetBytes); err != nil {
		return ImmutableTarget{}, err
	}
	hash := targetDigest(targetBytes)
	identityKind := domain.TargetPatch
	if kind == TargetStdin {
		identityKind = domain.TargetStdin
	}
	identity, err := domain.NewTargetIdentity(domain.TargetIdentityInput{Kind: identityKind, SHA256: hash})
	if err != nil {
		return ImmutableTarget{}, fmt.Errorf("delta target: invalid non-Git identity: %w", err)
	}
	return ImmutableTarget{kind: kind, value: value, bytes: append([]byte(nil), targetBytes...), sha256: hash, identity: identity}, nil
}

// NewP2ImmutableTarget reconstructs an immutable target from P2-bound bytes and
// identity. Persisted targets intentionally have no mutable input selector.
func NewP2ImmutableTarget(identity domain.TargetIdentity, targetBytes []byte) (ImmutableTarget, error) {
	if err := validTargetBytes(targetBytes); err != nil {
		return ImmutableTarget{}, err
	}
	hash := targetDigest(targetBytes)
	if identity.SHA256() != hash {
		return ImmutableTarget{}, fmt.Errorf("delta target: P2 identity does not match bytes")
	}
	kind := TargetPatch
	switch identity.Kind() {
	case domain.TargetGit:
		kind = TargetDiff
	case domain.TargetPatch:
	case domain.TargetStdin:
		kind = TargetStdin
	default:
		return ImmutableTarget{}, fmt.Errorf("delta target: unsupported P2 target identity")
	}
	return ImmutableTarget{kind: kind, bytes: append([]byte(nil), targetBytes...), sha256: hash, identity: identity, persistedP2: true}, nil
}

func (target ImmutableTarget) Kind() TargetKind                { return target.kind }
func (target ImmutableTarget) Value() string                   { return target.value }
func (target ImmutableTarget) Bytes() []byte                   { return append([]byte(nil), target.bytes...) }
func (target ImmutableTarget) SHA256() string                  { return target.sha256 }
func (target ImmutableTarget) Identity() domain.TargetIdentity { return target.identity }
func (target ImmutableTarget) clone() ImmutableTarget {
	target.bytes = append([]byte(nil), target.bytes...)
	return target
}

func (target ImmutableTarget) validate(name string) error {
	if !target.persistedP2 {
		request := TargetRequest{Kind: target.kind, Value: target.value}
		if err := request.validate(); err != nil {
			return fmt.Errorf("delta %s target: %w", name, err)
		}
	}
	if err := validTargetBytes(target.bytes); err != nil {
		return fmt.Errorf("delta %s target: %w", name, err)
	}
	if target.sha256 != targetDigest(target.bytes) {
		return fmt.Errorf("delta %s target has invalid immutable hash", name)
	}
	identity := target.identity
	if identity.SHA256() != target.sha256 {
		return fmt.Errorf("delta %s target identity does not match bytes", name)
	}
	switch target.kind {
	case TargetDiff:
		if identity.Kind() != domain.TargetGit {
			return fmt.Errorf("delta %s target diff is not a Git identity", name)
		}
	case TargetPatch:
		if identity.Kind() != domain.TargetPatch {
			return fmt.Errorf("delta %s target patch is not a patch identity", name)
		}
	case TargetStdin:
		if identity.Kind() != domain.TargetStdin {
			return fmt.Errorf("delta %s target stdin is not a stdin identity", name)
		}
	default:
		return fmt.Errorf("delta %s target kind is invalid", name)
	}
	return nil
}

func validTargetBytes(value []byte) error {
	if len(value) > MaxTargetBytes {
		return fmt.Errorf("delta target: bytes exceed %d", MaxTargetBytes)
	}
	return nil
}

func targetDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func validSourceSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// SourceSnapshot is the verified P2 source authority used by delta. Every
// identity and artifact operand is read explicitly from the persisted source;
// no in-memory run is accepted as substitute authority.
type SourceSnapshot struct {
	SessionID      domain.SessionID
	RunID          domain.RunID
	ReviewID       domain.ReviewID
	Roles          []domain.RoleTask
	Target         ImmutableTarget
	FinalSHA256    string
	ManifestSHA256 string
	Receipt        string
}

func (snapshot SourceSnapshot) normalized() (SourceSnapshot, error) {
	snapshot.Roles = append([]domain.RoleTask(nil), snapshot.Roles...)
	return snapshot, nil
}

func (snapshot SourceSnapshot) validate(sourceRunID domain.RunID) error {
	if snapshot.RunID != sourceRunID {
		return fmt.Errorf("delta source: reader returned a different run")
	}
	if _, err := domain.ParseSessionID(snapshot.SessionID.String()); err != nil {
		return fmt.Errorf("delta source: invalid source session ID: %w", err)
	}
	if _, err := domain.ParseReviewID(snapshot.ReviewID.String()); err != nil {
		return fmt.Errorf("delta source: invalid source review ID: %w", err)
	}
	if !validSourceSHA256(snapshot.FinalSHA256) {
		return fmt.Errorf("delta source: final artifact hash is required")
	}
	if !validSourceSHA256(snapshot.ManifestSHA256) {
		return fmt.Errorf("delta source: manifest hash is required")
	}
	if strings.TrimSpace(snapshot.Receipt) == "" {
		return fmt.Errorf("delta source: source invariance receipt is required")
	}
	if err := snapshot.Target.validate("source"); err != nil {
		return err
	}
	if !snapshot.Target.persistedP2 {
		return fmt.Errorf("delta source: source target must be persisted P2 authority")
	}
	if _, err := childRoles(snapshot.Roles, sourceRoles(snapshot.Roles)); err != nil {
		return fmt.Errorf("delta source: source roles are invalid: %w", err)
	}
	return nil
}

func sourceRoles(roles []domain.RoleTask) []domain.Role {
	result := make([]domain.Role, len(roles))
	for index, role := range roles {
		result[index] = role.Role()
	}
	return result
}

// SourceReader reads only a semantically verified P2 source snapshot. It must
// not derive authority from artifact filenames or mutable references.
type SourceReader interface {
	ReadSource(context.Context, domain.RunID) (SourceSnapshot, error)
}

// TargetCapturer captures the requested current target to immutable bytes and a
// kind-appropriate domain identity.
type TargetCapturer interface {
	CaptureTarget(context.Context, TargetRequest) (ImmutableTarget, error)
}

// Comparator compares exactly the two materialized snapshots. Delta may be
// empty; a nil error always denotes a comparable result.
type Comparator interface {
	Compare(context.Context, ImmutableTarget, ImmutableTarget) (Delta, error)
}

// Delta is comparator-owned opaque A-to-B material. Empty is valid.
type Delta struct {
	Bytes []byte
}

func (delta Delta) clone() Delta { return Delta{Bytes: append([]byte(nil), delta.Bytes...)} }

// IdentityGenerator supplies the fresh child run identity.
type IdentityGenerator interface {
	NewRunID(time.Time) (domain.RunID, error)
}

// ChildExecutor executes and publishes a child run. It owns provider execution
// and P2 publication, while this service owns the child/source invariants.
type ChildExecutor interface {
	ExecuteDelta(context.Context, ChildRequest) (ExecutionResult, error)
}

// ChildRequest is the fully trusted input supplied to child execution.
type ChildRequest struct {
	Run            domain.Run
	SourceReviewID domain.ReviewID
	SourceTarget   ImmutableTarget
	CurrentTarget  ImmutableTarget
	Delta          Delta
}

func (request ChildRequest) clone() ChildRequest {
	request.SourceTarget = request.SourceTarget.clone()
	request.CurrentTarget = request.CurrentTarget.clone()
	request.Delta = request.Delta.clone()
	return request
}

// ExecutionResult binds the published artifact to the child run identity and
// retains the verified P2 terminal exit decision.
type ExecutionResult struct {
	SessionID         domain.SessionID
	RunID             domain.RunID
	ReviewArtifactURI string
	terminalExit      *domain.OperationalExitDecision
}

// NewExecutionResult validates and binds the verified P2 terminal exit to one
// published delta child run.
func NewExecutionResult(sessionID domain.SessionID, runID domain.RunID, reviewArtifactURI string, terminalExit domain.OperationalExitDecision) (ExecutionResult, error) {
	result := ExecutionResult{SessionID: sessionID, RunID: runID, ReviewArtifactURI: reviewArtifactURI, terminalExit: &terminalExit}
	if err := result.ValidateTerminalExit(); err != nil {
		return ExecutionResult{}, fmt.Errorf("delta execution result: %w", err)
	}
	return result, nil
}

// TerminalExit returns the immutable, verified P2 terminal exit decision.
func (result ExecutionResult) TerminalExit() (domain.OperationalExitDecision, bool) {
	if result.terminalExit == nil {
		return domain.OperationalExitDecision{}, false
	}
	return *result.terminalExit, true
}

// ValidateTerminalExit rejects results without a verified committed terminal exit.
func (result ExecutionResult) ValidateTerminalExit() error {
	return validateCommittedTerminalExit(result.terminalExit)
}

// StartRequest is the bounded delta workflow request.
type StartRequest struct {
	SourceRunID domain.RunID
	Target      TargetRequest
	Roles       []domain.Role
}

// Result is the exact child identity, published review artifact, and verified
// P2 terminal exit decision.
type Result struct {
	SessionID         domain.SessionID
	RunID             domain.RunID
	ReviewArtifactURI string
	terminalExit      *domain.OperationalExitDecision
}

// NewResult validates and binds the verified P2 terminal exit to the bounded
// delta application result.
func NewResult(sessionID domain.SessionID, runID domain.RunID, reviewArtifactURI string, terminalExit domain.OperationalExitDecision) (Result, error) {
	result := Result{SessionID: sessionID, RunID: runID, ReviewArtifactURI: reviewArtifactURI, terminalExit: &terminalExit}
	if err := result.ValidateTerminalExit(); err != nil {
		return Result{}, fmt.Errorf("delta result: %w", err)
	}
	return result, nil
}

// TerminalExit returns the immutable, verified P2 terminal exit decision.
func (result Result) TerminalExit() (domain.OperationalExitDecision, bool) {
	if result.terminalExit == nil {
		return domain.OperationalExitDecision{}, false
	}
	return *result.terminalExit, true
}

// ValidateTerminalExit rejects results without a verified committed terminal exit.
func (result Result) ValidateTerminalExit() error {
	return validateCommittedTerminalExit(result.terminalExit)
}

func validateCommittedTerminalExit(exit *domain.OperationalExitDecision) error {
	if exit == nil {
		return fmt.Errorf("terminal exit is required")
	}
	reasons := exit.Reasons()
	if len(reasons) == 0 {
		return fmt.Errorf("terminal exit authority is empty")
	}
	input, err := domain.NewOperationalExitInput(reasons)
	if err != nil {
		return fmt.Errorf("terminal exit authority is invalid: %w", err)
	}
	reduced, err := domain.ReduceOperationalExit(input)
	if err != nil || reduced.Code() != exit.Code() {
		return fmt.Errorf("terminal exit authority is not a reduced operational decision")
	}
	switch exit.Code() {
	case domain.ExitCommittedPass, domain.ExitCommittedCIRejected, domain.ExitIncompleteCoverage:
		return nil
	default:
		return fmt.Errorf("terminal exit %d is not a committed P2 outcome", exit.Code())
	}
}
