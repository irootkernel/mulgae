// Package rerun starts immutable child runs that replay a verified source attempt.
package rerun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
)

// RoleReportURI is one trusted project-relative role-report identity projected
// from a committed PublicationResult support inventory by childrun.
type RoleReportURI struct {
	Role string
	URI  string
}

var (
	// ErrInvalidRequest identifies an invalid rerun request.
	ErrInvalidRequest = errors.New("invalid rerun request")
	// ErrSourceCorrupt identifies a source whose immutable replay material is not intact.
	ErrSourceCorrupt = errors.New("corrupt rerun source")
	// ErrSourceMutated identifies a source changed while its child was started.
	ErrSourceMutated = errors.New("rerun source mutated")
	// ErrInvalidChild identifies a replay executor result that violates child invariants.
	ErrInvalidChild = errors.New("invalid rerun child")
)

// ReplayMode controls whether source provider wire bytes are replayed or a new
// prompt is composed from current trusted configuration.
type ReplayMode string

const (
	ExactReplay     ReplayMode = "exact"
	RecomposeReplay ReplayMode = "recompose"
)

func (mode ReplayMode) Valid() bool {
	return mode == ExactReplay || mode == RecomposeReplay
}

// Request identifies the immutable source attempt to rerun.
type Request struct {
	SourceRunID     domain.RunID
	SourceAttemptID domain.AttemptID
	ReplayMode      ReplayMode
}

// Parameter is one immutable adapter parameter captured with an attempt.
type Parameter struct {
	Name  string
	Value string
}

// Target is a captured immutable target. Identity and bytes are copied at
// package boundaries so neither readers nor executors can modify source material.
type Target struct {
	Identity        domain.TargetIdentity
	Bytes           []byte
	SHA256          string
	CapturedArchive []byte
}

// PromptManifest is the verified source prompt material needed for exact
// replay. Source manifest identity binds the child prompt to its authority.
type PromptManifest struct {
	URI                   string
	SHA256                string
	ComposedStdin         []byte
	ComposedStdinSHA256   string
	CompleteStdinSHA256   string
	SourceInvocationID    string
	ExecutionInvocationID string
	TemplateID            string
	TemplateVersion       string
	TemplateSHA256        string
	AdapterProfile        string
	Parameters            []Parameter
	Scope                 string
	Role                  string
}

// SourceAttempt is a verified immutable source attempt. ImmutableSHA256 must
// change whenever any source bytes or replay-relevant identity changes.
type SourceAttempt struct {
	SessionID        domain.SessionID
	RunID            domain.RunID
	ReviewID         domain.ReviewID
	AttemptID        domain.AttemptID
	ProviderInstance string
	Target           Target
	Prompt           PromptManifest
	ImmutableSHA256  string
}

// SourceReader is the narrow authority for verified source attempt, target,
// and prompt-manifest reads. Implementations must reject non-P2 sources.
type SourceReader interface {
	ReadRerunSource(context.Context, domain.RunID, domain.AttemptID) (SourceAttempt, error)
}

// ChildReplay contains defensive copies of verified source authority and a
// freshly constructed lineage/publication context for one child execution.
type ChildReplay struct {
	SessionID       domain.SessionID
	ParentRunID     domain.RunID
	SourceRunID     domain.RunID
	SourceReviewID  domain.ReviewID
	SourceAttemptID domain.AttemptID
	Mode            ReplayMode
	Target          Target
	Scope           string
	Role            string
	Publication     ChildPublicationContext
	Run             domain.Run
	Assignments     []review.Assignment

	// Exact is populated only for exact replay. It deliberately includes the
	// original adapter profile and parameters, plus source prompt authority.
	Exact *ExactInput
}

// ChildPublicationContext binds a new child publication to the immutable
// source authority. The executor must preserve every field in its result.
type ChildPublicationContext struct {
	SessionID            domain.SessionID
	ParentRunID          domain.RunID
	SourceRunID          domain.RunID
	SourceReviewID       domain.ReviewID
	SourceAttemptID      domain.AttemptID
	SourceManifestURI    string
	SourceManifestSHA256 string
	ReplayMode           ReplayMode
}

// ExactInput is the exact replay-only provider wire contract.
type ExactInput struct {
	ComposedStdin               []byte
	ComposedStdinSHA256         string
	CompleteStdinSHA256         string
	SourceInvocationID          string
	SourceExecutionInvocationID string
	TemplateID                  string
	TemplateVersion             string
	TemplateSHA256              string
	AdapterProfile              string
	SourceProviderInstance      string
	Parameters                  []Parameter
	SourceManifestURI           string
	SourceManifestSHA256        string
}

// ChildReplayExecutor creates and executes a child replay. A successful result
// must contain a new run and execution identity in the source session.
type ChildReplayExecutor interface {
	ExecuteChildReplay(context.Context, ChildReplay) (ChildReplayResult, error)
}

// ChildReplayResult is the child identity, persisted prompt-manifest view,
// verified committed role-report URIs, and verified P2 terminal exit decision.
type ChildReplayResult struct {
	SessionID             domain.SessionID
	RunID                 domain.RunID
	ParentRunID           domain.RunID
	SourceRunID           domain.RunID
	SourceReviewID        domain.ReviewID
	SourceAttemptID       domain.AttemptID
	ExecutionInvocationID string
	PromptIdentity        string
	PromptManifestURI     string
	PromptManifestSHA256  string
	ReplayMode            ReplayMode
	ExactReplay           bool
	RoleReportURIs        []RoleReportURI
	terminalExit          *domain.OperationalExitDecision
}

// NewChildReplayResult validates and binds the verified P2 terminal exit to
// one published rerun child.
func NewChildReplayResult(sessionID domain.SessionID, runID, parentRunID, sourceRunID domain.RunID, sourceReviewID domain.ReviewID, sourceAttemptID domain.AttemptID, executionInvocationID, promptIdentity, promptManifestURI, promptManifestSHA256 string, replayMode ReplayMode, exactReplay bool, roleReportURIs []RoleReportURI, terminalExit domain.OperationalExitDecision) (ChildReplayResult, error) {
	result := ChildReplayResult{
		SessionID: sessionID, RunID: runID, ParentRunID: parentRunID, SourceRunID: sourceRunID,
		SourceReviewID: sourceReviewID, SourceAttemptID: sourceAttemptID,
		ExecutionInvocationID: executionInvocationID, PromptIdentity: promptIdentity,
		PromptManifestURI: promptManifestURI, PromptManifestSHA256: promptManifestSHA256,
		ReplayMode: replayMode, ExactReplay: exactReplay,
		RoleReportURIs: append([]RoleReportURI(nil), roleReportURIs...), terminalExit: &terminalExit,
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return ChildReplayResult{}, fmt.Errorf("rerun child result: %w", err)
	}
	if err := validateRoleReportURIs(sessionID, runID, result.RoleReportURIs); err != nil {
		return ChildReplayResult{}, fmt.Errorf("rerun child result: %w", err)
	}
	return result, nil
}

// TerminalExit returns the immutable, verified P2 terminal exit decision.
func (result ChildReplayResult) TerminalExit() (domain.OperationalExitDecision, bool) {
	if result.terminalExit == nil {
		return domain.OperationalExitDecision{}, false
	}
	return *result.terminalExit, true
}

// ValidateTerminalExit rejects results without a verified committed terminal exit.
func (result ChildReplayResult) ValidateTerminalExit() error {
	return validateCommittedTerminalExit(result.terminalExit)
}

// Result is the bounded application result exposed to command wiring, including
// verified committed role-report URIs and the verified P2 terminal exit.
type Result struct {
	SessionID         domain.SessionID
	RunID             domain.RunID
	PromptManifestURI string
	RoleReportURIs    []RoleReportURI
	terminalExit      *domain.OperationalExitDecision
}

// NewResult validates and binds the verified P2 terminal exit to the bounded
// rerun application result.
func NewResult(sessionID domain.SessionID, runID domain.RunID, promptManifestURI string, roleReportURIs []RoleReportURI, terminalExit domain.OperationalExitDecision) (Result, error) {
	result := Result{
		SessionID: sessionID, RunID: runID, PromptManifestURI: promptManifestURI,
		RoleReportURIs: append([]RoleReportURI(nil), roleReportURIs...), terminalExit: &terminalExit,
	}
	if err := result.ValidateTerminalExit(); err != nil {
		return Result{}, fmt.Errorf("rerun result: %w", err)
	}
	if err := validateRoleReportURIs(sessionID, runID, result.RoleReportURIs); err != nil {
		return Result{}, fmt.Errorf("rerun result: %w", err)
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

func validateRoleReportURIs(sessionID domain.SessionID, runID domain.RunID, reports []RoleReportURI) error {
	prefix := ".mulgae/" + sessionID.String() + "/" + runID.String() + "/role-reports/"
	seen := make(map[string]struct{}, len(reports))
	for _, report := range reports {
		if !domain.Role(report.Role).Valid() || report.URI != prefix+report.Role+".md" ||
			strings.TrimSpace(report.URI) == "" || strings.ContainsAny(report.URI, "\x00\r\n") {
			return fmt.Errorf("role report URI is invalid")
		}
		if _, duplicate := seen[report.Role]; duplicate {
			return fmt.Errorf("role report URI is duplicated")
		}
		seen[report.Role] = struct{}{}
	}
	return nil
}
