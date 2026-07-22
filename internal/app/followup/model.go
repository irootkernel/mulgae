// Package followup starts one immutable, finding-scoped child workflow.
package followup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/kkachi-agent-review/internal/app/validation"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// TargetKind is the literal target selector accepted by a followup request.
type TargetKind string

const (
	TargetDiff  TargetKind = "diff"
	TargetPatch TargetKind = "patch"
	TargetStdin TargetKind = "stdin"
)

func (kind TargetKind) valid() bool {
	return kind == TargetDiff || kind == TargetPatch || kind == TargetStdin
}

// Target is untrusted current-target input. Capture binds it to immutable bytes.
type Target struct {
	Kind  TargetKind
	Value string
}

// Request selects exactly one finding from a committed source run.
type Request struct {
	SourceRunID domain.RunID
	FindingID   string
	Target      Target
	Objective   *string
	Role        *domain.Role
}

// SourceReceipt binds every source byte read by this workflow. The values are
// SHA-256 digests of exact source final, manifest, finding, and excerpt bytes.
type SourceReceipt struct {
	FinalSHA256    string
	ManifestSHA256 string
	FindingSHA256  string
	ExcerptSHA256  string
}

// SourceFinding is the normalized, run-scoped finding used to focus the child.
type SourceFinding struct {
	ID         string
	Role       domain.Role
	Normalized []byte
	Excerpt    []byte
}

// VerifiedSource is a P2-authoritative source view. SourceReader must expose
// only verified data; Service verifies its identity and byte receipts again.
type VerifiedSource struct {
	P2Verified       bool
	ProviderInstance string
	SessionID        domain.SessionID
	RunID            domain.RunID
	ReviewID         domain.ReviewID
	Target           domain.TargetIdentity
	Finding          SourceFinding
	Final            []byte
	Manifest         []byte
	Receipt          SourceReceipt
}

// CurrentTarget is the freshly captured immutable target and its exact bytes.
type CurrentTarget struct {
	Identity domain.TargetIdentity
	Bytes    []byte
}

// SourceReader reads one validated P2 source and its run-scoped finding.
type SourceReader interface {
	ReadFollowupSource(context.Context, domain.RunID, string) (VerifiedSource, error)
}

// CurrentTargetCapturer captures the selected current target before child
// execution. It has no source-write authority.
type CurrentTargetCapturer interface {
	CaptureFollowupTarget(context.Context, Target) (CurrentTarget, error)
}

// Execution contains only the immutable source/current material an executor
// needs to create and publish a fresh child run.
type Execution struct {
	SessionID domain.SessionID
	Source    VerifiedSource
	Current   CurrentTarget
	Objective string
	Role      *domain.Role
}

// ChildExecutor creates and publishes one new child run. It must not mutate
// the source.
type ChildExecutor interface {
	ExecuteFollowup(context.Context, Execution) (ExecutionResult, error)
}

// ExecutionResult identifies one published child run, its validator-owned
// followup material, and its verified P2 terminal exit decision.
type ExecutionResult struct {
	SessionID           domain.SessionID
	RunID               domain.RunID
	FollowupArtifactURI string
	ValidatedOutput     validation.ValidatedFollowup
	terminalExit        *domain.OperationalExitDecision
}

// NewExecutionResult validates and binds the verified P2 terminal exit to one
// published followup child run.
func NewExecutionResult(sessionID domain.SessionID, runID domain.RunID, followupArtifactURI string, validatedOutput validation.ValidatedFollowup, terminalExit domain.OperationalExitDecision) (ExecutionResult, error) {
	result := ExecutionResult{SessionID: sessionID, RunID: runID, FollowupArtifactURI: followupArtifactURI, ValidatedOutput: validatedOutput, terminalExit: &terminalExit}
	if err := result.ValidateTerminalExit(); err != nil {
		return ExecutionResult{}, fmt.Errorf("followup execution result: %w", err)
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

// Result is the immutable caller-owned projection of a started followup.
type Result struct {
	sessionID           domain.SessionID
	runID               domain.RunID
	followupArtifactURI string
	validatedOutput     validation.ValidatedFollowup
	terminalExit        *domain.OperationalExitDecision
}

func (result Result) SessionID() domain.SessionID                   { return result.sessionID }
func (result Result) RunID() domain.RunID                           { return result.runID }
func (result Result) FollowupArtifactURI() string                   { return result.followupArtifactURI }
func (result Result) ValidatedOutput() validation.ValidatedFollowup { return result.validatedOutput }

// NewResult validates and binds the verified P2 terminal exit to the bounded
// followup application result.
func NewResult(sessionID domain.SessionID, runID domain.RunID, followupArtifactURI string, validatedOutput validation.ValidatedFollowup, terminalExit domain.OperationalExitDecision) (Result, error) {
	result := Result{sessionID: sessionID, runID: runID, followupArtifactURI: followupArtifactURI, validatedOutput: validatedOutput, terminalExit: &terminalExit}
	if err := result.ValidateTerminalExit(); err != nil {
		return Result{}, fmt.Errorf("followup result: %w", err)
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

// ErrorKind classifies fail-closed workflow failures without lending provider
// output authority over source or evidence state.
type ErrorKind string

const (
	ErrorInvalidRequest ErrorKind = "invalid_request"
	ErrorSource         ErrorKind = "source"
	ErrorMutation       ErrorKind = "source_mutation"
	ErrorCancellation   ErrorKind = "cancelled"
	ErrorExecution      ErrorKind = "execution"
	ErrorInvariant      ErrorKind = "invariant"
)

// Error retains a machine-readable failure class and the underlying cause.
type Error struct {
	Kind  ErrorKind
	Stage string
	Err   error
}

func (err *Error) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("followup %s: %v", err.Stage, err.Err)
}
func (err *Error) Unwrap() error { return err.Err }

func fail(kind ErrorKind, stage, message string, cause error) error {
	if kind == ErrorMutation {
		failure, err := domain.NewFailure("followup."+stage, domain.FailureSecurityPolicy, message, cause)
		if err != nil {
			return &Error{Kind: ErrorInvariant, Stage: stage, Err: fmt.Errorf("classify source mutation: %w", err)}
		}
		return &Error{Kind: kind, Stage: stage, Err: failure}
	}
	if cause != nil {
		return &Error{Kind: kind, Stage: stage, Err: fmt.Errorf("%s: %w", message, cause)}
	}
	return &Error{Kind: kind, Stage: stage, Err: fmt.Errorf("%s", message)}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value && strings.Trim(value, "0") != ""
}

func digest(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func validURI(value string) bool {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	uri, err := url.Parse(value)
	return err == nil && uri.String() == value
}
