package mcpentry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
)

const (
	toolRunReview    = "run_review"
	toolStartReview  = "start_review"
	toolAwaitReview  = "await_review"
	toolCancelReview = "cancel_review"
	toolPreflight    = "preflight_review"
	toolListRuns     = "list_runs"
	toolGetRun       = "get_run"
	toolListFindings = "list_findings"

	maxToolArgumentsBytes = 64 << 10
	maxToolResultBytes    = 1 << 20
)

// Backend is the application-facing MCP tool boundary. Implementations own
// project-root confinement and return only public, bounded values.
type Backend interface {
	RunReview(context.Context, string, RunReviewInput) (BackendResult, error)
	PreflightReview(context.Context, string, RunReviewInput) (BackendResult, error)
	ListRuns(context.Context, ListRunsInput) (map[string]any, error)
	GetRun(context.Context, GetRunInput) (map[string]any, error)
	ListFindings(context.Context, ListFindingsInput) (map[string]any, error)
	ReadResource(context.Context, ResourceRequest) (ResourceContent, error)
}

// BackendResult carries a successful tool outcome and its public data object.
type BackendResult struct {
	Outcome string
	Data    map[string]any
}

// RunReviewInput selects one immutable review target and optional review
// guidance. MCP transport stdin is never a review target.
type RunReviewInput struct {
	Target    ReviewTarget `json:"target"`
	Objective string       `json:"objective,omitempty"`
	Roles     []string     `json:"roles,omitempty"`
}

// ReviewTarget is one non-stdin Mulgae target selector.
type ReviewTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

// ListRunsInput selects a bounded page ordered newest first.
type ListRunsInput struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// GetRunInput selects one canonical run identity.
type GetRunInput struct {
	RunID string `json:"run_id"`
}

// ListFindingsInput selects committed findings at or above one severity.
type ListFindingsInput struct {
	RunID           string `json:"run_id"`
	MinimumSeverity string `json:"minimum_severity,omitempty"`
}

// InvocationInput selects one exact invocation owned by the current MCP
// server process.
type InvocationInput struct {
	InvocationID string `json:"invocation_id"`
}

func registerTools(server *mcpsdk.Server, backend Backend, registry *invocationRegistry, newRequestID func() (string, error), outputSchema json.RawMessage) {
	if server == nil || backend == nil || registry == nil || newRequestID == nil || len(outputSchema) == 0 {
		return
	}
	addTool(server, toolRunReview, "Capture and run one foreground Mulgae review for this server's fixed project root.", json.RawMessage(runReviewInputSchema), outputSchema, false, false,
		func(ctx context.Context, requestID string, raw json.RawMessage, startProgress func()) (string, map[string]any, error) {
			var input RunReviewInput
			if err := decodeArguments(raw, &input); err != nil {
				return "", nil, err
			}
			if err := validateRunReviewInput(input); err != nil {
				return "", nil, err
			}
			startProgress()
			result, err := backend.RunReview(ctx, requestID, input)
			return result.Outcome, result.Data, err
		}, newRequestID)
	addTool(server, toolStartReview, "Start one session-local Mulgae review without waiting for provider completion.", json.RawMessage(runReviewInputSchema), outputSchema, false, false,
		func(_ context.Context, requestID string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			var input RunReviewInput
			if err := decodeArguments(raw, &input); err != nil {
				return "", nil, err
			}
			if err := validateRunReviewInput(input); err != nil {
				return "", nil, err
			}
			snapshot, err := registry.Start(requestID, input)
			return toolOutcomeSuccess, invocationSnapshotData(snapshot), err
		}, newRequestID)
	addTool(server, toolAwaitReview, "Wait for one exact session-local review invocation without cancelling its execution when this wait ends.", json.RawMessage(invocationInputSchema), outputSchema, true, true,
		func(ctx context.Context, _ string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			input, err := decodeInvocationInput(raw)
			if err != nil {
				return "", nil, err
			}
			snapshot, err := registry.Await(ctx, input.InvocationID)
			if err != nil {
				if registry.SessionEnded() && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
					return "", nil, errInvocationRegistryClosed
				}
				return "", nil, err
			}
			if snapshot.Phase != invocationTerminal {
				return "", nil, errInvocationStateInvalid
			}
			if snapshot.Err != nil {
				return "", nil, &invocationExecutionError{id: snapshot.ID, err: snapshot.Err}
			}
			data := snapshot.Result.Data
			if data == nil {
				return "", nil, errInvocationStateInvalid
			}
			data["invocation_id"] = snapshot.ID
			return snapshot.Result.Outcome, data, nil
		}, newRequestID)
	addTool(server, toolCancelReview, "Request cancellation of one active session-local review invocation; acknowledgement is not terminal completion.", json.RawMessage(invocationInputSchema), outputSchema, false, true,
		func(_ context.Context, _ string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			input, err := decodeInvocationInput(raw)
			if err != nil {
				return "", nil, err
			}
			snapshot, accepted, err := registry.Cancel(input.InvocationID)
			data := invocationSnapshotData(snapshot)
			if data != nil {
				data["cancellation_accepted"] = accepted
			}
			return toolOutcomeSuccess, data, err
		}, newRequestID)
	addTool(server, toolPreflight, "Capture and summarize an execution-free Mulgae review plan without invoking providers or publishing a run.", json.RawMessage(runReviewInputSchema), outputSchema, true, true,
		func(ctx context.Context, requestID string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			var input RunReviewInput
			if err := decodeArguments(raw, &input); err != nil {
				return "", nil, err
			}
			if err := validateRunReviewInput(input); err != nil {
				return "", nil, err
			}
			result, err := backend.PreflightReview(ctx, requestID, input)
			return result.Outcome, result.Data, err
		}, newRequestID)
	addTool(server, toolListRuns, "List a bounded page of safely admitted Mulgae runs for this server's fixed project root.", json.RawMessage(listRunsInputSchema), outputSchema, true, true,
		func(ctx context.Context, _ string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			input := ListRunsInput{Limit: 20}
			if err := decodeArguments(raw, &input); err != nil {
				return "", nil, err
			}
			if input.Limit < 1 || input.Limit > 100 || input.Cursor != "" && !matches(runCursorPattern, input.Cursor) {
				return "", nil, errInvalidToolArguments
			}
			data, err := backend.ListRuns(ctx, input)
			return toolOutcomeSuccess, data, err
		}, newRequestID)
	addTool(server, toolGetRun, "Get the safely verified publication or bounded diagnostic status for one Mulgae run.", json.RawMessage(getRunInputSchema), outputSchema, true, true,
		func(ctx context.Context, _ string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			var input GetRunInput
			if err := decodeArguments(raw, &input); err != nil || !matches(runIDPattern, input.RunID) {
				return "", nil, errInvalidToolArguments
			}
			data, err := backend.GetRun(ctx, input)
			return toolOutcomeSuccess, data, err
		}, newRequestID)
	addTool(server, toolListFindings, "List bounded committed finding summaries without returning report or source bodies.", json.RawMessage(listFindingsInputSchema), outputSchema, true, true,
		func(ctx context.Context, _ string, raw json.RawMessage, _ func()) (string, map[string]any, error) {
			input := ListFindingsInput{MinimumSeverity: "low"}
			if err := decodeArguments(raw, &input); err != nil || !matches(runIDPattern, input.RunID) ||
				!oneOf(input.MinimumSeverity, "low", "medium", "high", "critical", "blocker") {
				return "", nil, errInvalidToolArguments
			}
			data, err := backend.ListFindings(ctx, input)
			return toolOutcomeSuccess, data, err
		}, newRequestID)
}

type toolCall func(context.Context, string, json.RawMessage, func()) (string, map[string]any, error)

func addTool(
	server *mcpsdk.Server,
	name, description string,
	inputSchema, outputSchema json.RawMessage,
	readOnly, idempotent bool,
	call toolCall,
	newRequestID func() (string, error),
) {
	closedWorld := false
	nonDestructive := false
	server.AddTool(&mcpsdk.Tool{
		Name:         name,
		Description:  description,
		InputSchema:  inputSchema,
		OutputSchema: outputSchema,
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: &nonDestructive,
			IdempotentHint:  idempotent,
			OpenWorldHint:   &closedWorld,
			ReadOnlyHint:    readOnly,
		},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		requestID, err := newRequestID()
		if err != nil || !matches(requestIDPattern, requestID) {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Mulgae request identity is unavailable"}
		}
		finishProgress := func(string) {}
		startProgress := func() {
			finishProgress = startReviewProgress(ctx, request)
		}
		outcome, data, callErr := call(ctx, requestID, request.Params.Arguments, startProgress)
		if callErr != nil {
			finishProgress("Mulgae review stopped.")
		} else {
			finishProgress("Mulgae review completed.")
		}
		var result ToolResult
		if callErr != nil {
			result, err = newToolFailure(name, requestID, publicToolError(callErr, name))
		} else {
			result, err = newToolSuccess(name, requestID, outcome, data)
		}
		if err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Mulgae tool result is unavailable"}
		}
		return renderToolResult(result)
	})
}

func renderToolResult(result ToolResult) (*mcpsdk.CallToolResult, error) {
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > maxToolResultBytes {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Mulgae tool result is unavailable"}
	}
	return &mcpsdk.CallToolResult{
		Content:           []mcpsdk.Content{&mcpsdk.TextContent{Text: string(raw)}},
		StructuredContent: result,
		IsError:           result.Outcome == toolOutcomeError,
	}, nil
}

var (
	errInvalidToolArguments = errors.New("invalid MCP tool arguments")
	// ErrRunStatusUnavailable identifies a run identity with neither publication
	// nor a completed diagnostic failure status safe for recovery.
	ErrRunStatusUnavailable   = errors.New("run status unavailable")
	errInvocationStateInvalid = errors.New("MCP invocation state is invalid")
)

type invocationExecutionError struct {
	id  string
	err error
}

func (failure *invocationExecutionError) Error() string { return failure.err.Error() }
func (failure *invocationExecutionError) Unwrap() error { return failure.err }

func decodeArguments(raw json.RawMessage, destination any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > maxToolArgumentsBytes {
		return errInvalidToolArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errInvalidToolArguments
	}
	if err := consumeEOF(decoder); err != nil {
		return errInvalidToolArguments
	}
	return nil
}

func consumeEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateRunReviewInput(input RunReviewInput) error {
	if !oneOf(input.Target.Kind, "workspace", "stage", "dirty", "diff", "patch") {
		return errInvalidToolArguments
	}
	requiresValue := input.Target.Kind == "diff" || input.Target.Kind == "patch"
	if requiresValue != (strings.TrimSpace(input.Target.Value) != "") || len(input.Target.Value) > 4096 || len(input.Objective) > 4096 {
		return errInvalidToolArguments
	}
	if len(input.Roles) > 7 {
		return errInvalidToolArguments
	}
	seen := make(map[string]struct{}, len(input.Roles))
	for _, role := range input.Roles {
		if !oneOf(role, "logic", "security", "maintainability", "product", "documentation", "testing", "artist") {
			return errInvalidToolArguments
		}
		if _, duplicate := seen[role]; duplicate {
			return errInvalidToolArguments
		}
		seen[role] = struct{}{}
	}
	return nil
}

func decodeInvocationInput(raw json.RawMessage) (InvocationInput, error) {
	var input InvocationInput
	if err := decodeArguments(raw, &input); err != nil || !matches(requestIDPattern, input.InvocationID) {
		return InvocationInput{}, errInvalidToolArguments
	}
	return input, nil
}

func invocationSnapshotData(snapshot invocationSnapshot) map[string]any {
	if snapshot.ID == "" {
		return nil
	}
	return map[string]any{
		"invocation_id":          snapshot.ID,
		"state":                  string(snapshot.Phase),
		"cancellation_requested": snapshot.CancellationRequested,
	}
}

func publicToolError(err error, tool string) ToolError {
	if errors.Is(err, errInvocationNotFound) {
		return ToolError{Class: "usage", Code: "invocation_not_found", Stage: "query", Message: "The invocation is not available in this MCP server session.", Retryable: false}
	}
	if errors.Is(err, errInvocationLimitReached) {
		return ToolError{Class: "readiness", Code: "invocation_limit_reached", Stage: "admission", Message: "The MCP server session cannot admit another review invocation.", Retryable: false}
	}
	if errors.Is(err, errInvocationRegistryClosed) {
		return ToolError{Class: "internal", Code: "invocation_registry_closed", Stage: "transport", Message: "The MCP server invocation registry is closed.", Retryable: false}
	}
	if errors.Is(err, errInvocationAlreadyExists) || errors.Is(err, errInvocationStateInvalid) {
		return ToolError{Class: "internal", Code: "invocation_state_invalid", Stage: "execution", Message: "The MCP invocation state is invalid.", Retryable: false}
	}
	if errors.Is(err, ErrRunStatusUnavailable) {
		return finalizePublicToolError(err, tool, ToolError{Class: "artifact", Code: "run_status_unavailable", Stage: "query", Message: "No published or diagnostic status is available for the requested run.", Retryable: false})
	}
	if errors.Is(err, errInvalidToolArguments) {
		return finalizePublicToolError(err, tool, ToolError{Class: "usage", Code: "invalid_arguments", Stage: "admission", Message: "The tool arguments are invalid.", Retryable: false})
	}
	stage := "query"
	if tool == toolRunReview || tool == toolAwaitReview {
		stage = "execution"
	}
	var terminal *invocationExecutionError
	terminalFailure := errors.As(err, &terminal)
	if tool == toolAwaitReview && !terminalFailure && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return ToolError{Class: "cancellation", Code: "await_cancelled", Stage: "query", Message: "The invocation wait ended without cancelling the review.", Retryable: true}
	}
	if class, available := reducedToolFailureClass(err); available {
		switch class {
		case domain.FailureSecurityPolicy:
			return finalizePublicToolError(err, tool, ToolError{Class: "security", Code: "security_rejected", Stage: "admission", Message: "Mulgae rejected the request at a security boundary.", Retryable: false})
		case domain.FailureConfiguration:
			return finalizePublicToolError(err, tool, ToolError{Class: "usage", Code: "configuration_rejected", Stage: "admission", Message: "The project configuration or request is invalid.", Retryable: false})
		case domain.FailureArtifact:
			return finalizePublicToolError(err, tool, ToolError{Class: "artifact", Code: "artifact_unavailable", Stage: stage, Message: "The requested verified artifact is unavailable.", Retryable: false})
		case domain.FailureCancelled:
			return finalizePublicToolError(err, tool, ToolError{Class: "cancellation", Code: "request_cancelled", Stage: stage, Message: "The tool request was cancelled.", Retryable: false})
		case domain.FailureProviderUnavailable, domain.FailureInvalidOutput, domain.FailureTimeout,
			domain.FailureAuthentication, domain.FailureQuota, domain.FailureRateLimit:
			return finalizePublicToolError(err, tool, ToolError{Class: "readiness", Code: "review_unavailable", Stage: "execution", Message: "The review could not complete with the configured provider.", Retryable: true})
		}
	}
	return finalizePublicToolError(err, tool, ToolError{Class: "internal", Code: "internal_failure", Stage: stage, Message: "Mulgae could not complete the tool request.", Retryable: false})
}

func finalizePublicToolError(err error, tool string, failure ToolError) ToolError {
	if tool != toolRunReview && tool != toolAwaitReview {
		return failure
	}
	failure.Retryable = false
	if sessionID, runID, ok := reviewrun.RuntimeDiagnosticIdentityFromError(err); ok {
		session, run := sessionID.String(), runID.String()
		failure.SessionID, failure.RunID = &session, &run
	}
	var terminal *invocationExecutionError
	if tool == toolAwaitReview && errors.As(err, &terminal) && matches(requestIDPattern, terminal.id) {
		invocationID := terminal.id
		failure.InvocationID = &invocationID
	}
	return failure
}

func reducedToolFailureClass(err error) (domain.FailureClass, bool) {
	classes := make([]domain.FailureClass, 0, 3)
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if failure, ok := current.(*domain.Failure); ok && failure != nil && failure.Class().Valid() {
			classes = append(classes, failure.Class())
			visit(failure.Unwrap())
			return
		}
		switch nested := current.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range nested.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(nested.Unwrap())
		default:
			if errors.Is(current, context.Canceled) || errors.Is(current, context.DeadlineExceeded) {
				classes = append(classes, domain.FailureCancelled)
			}
		}
	}
	visit(err)
	if len(classes) == 0 {
		return "", false
	}
	selected := classes[0]
	for _, class := range classes[1:] {
		if app.FailurePrecedence(class) > app.FailurePrecedence(selected) {
			selected = class
		}
	}
	return selected, true
}

const (
	requestIDPattern = `^i_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	runIDPattern     = `^r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	runCursorPattern = `^s_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

	runReviewInputSchema    = `{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"oneOf":[{"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"enum":["workspace","stage","dirty"]}}},{"type":"object","additionalProperties":false,"required":["kind","value"],"properties":{"kind":{"enum":["diff","patch"]},"value":{"type":"string","minLength":1,"maxLength":4096}}}]},"objective":{"type":"string","maxLength":4096},"roles":{"type":"array","maxItems":7,"uniqueItems":true,"items":{"enum":["logic","security","maintainability","product","documentation","testing","artist"]}}}}`
	invocationInputSchema   = `{"type":"object","additionalProperties":false,"required":["invocation_id"],"properties":{"invocation_id":{"type":"string","pattern":"^i_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}}}`
	listRunsInputSchema     = `{"type":"object","additionalProperties":false,"properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20},"cursor":{"type":"string","pattern":"^s_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}}}`
	getRunInputSchema       = `{"type":"object","additionalProperties":false,"required":["run_id"],"properties":{"run_id":{"type":"string","pattern":"^r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}}}`
	listFindingsInputSchema = `{"type":"object","additionalProperties":false,"required":["run_id"],"properties":{"run_id":{"type":"string","pattern":"^r_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},"minimum_severity":{"enum":["low","medium","high","critical","blocker"],"default":"low"}}}`
)
