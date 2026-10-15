package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type cursorACPError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (failure *cursorACPError) Error() string { return failure.err.Error() }
func (failure *cursorACPError) Unwrap() error { return failure.err }
func (failure *cursorACPError) Cause() domain.RuntimeDiagnosticCause {
	return failure.cause
}
func (failure *cursorACPError) ProtocolFailureCause() domain.RuntimeDiagnosticCause {
	return failure.cause
}

func cursorACPFailure(cause domain.RuntimeDiagnosticCause, err error) error {
	return &cursorACPError{cause: cause, err: err}
}

type cursorACPProtocolSession struct {
	workspacePath  string
	prompt         string
	purpose        protocolInvocationPurpose
	liveReads      *cursorLiveReadAuthority
	assistant      []byte
	observation    ports.ProviderSessionObservation
	hasObservation bool
}

func newCursorACPProtocolSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, liveReads *cursorLiveReadAuthority) (*cursorACPProtocolSession, error) {
	if workspacePath == "" || len(prompt) == 0 {
		return nil, cursorACPFailure(domain.DiagnosticCauseObservationInvalid, errors.New("cursor ACP session is incomplete"))
	}
	if purpose == protocolPurposeLiveReview && liveReads == nil {
		return nil, cursorACPFailure(domain.DiagnosticCauseObservationInvalid, errors.New("cursor live review is missing its read plan"))
	}
	return &cursorACPProtocolSession{workspacePath: workspacePath, prompt: string(prompt), purpose: purpose, liveReads: liveReads}, nil
}

func (session *cursorACPProtocolSession) AssistantEvidenceText() []byte {
	return append([]byte(nil), session.assistant...)
}

func (session *cursorACPProtocolSession) SessionObservation() (ports.ProviderSessionObservation, bool) {
	return session.observation, session.hasObservation
}

type cursorACPMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func (message cursorACPMessage) failed() bool {
	raw := bytesTrim(message.Error)
	return len(raw) > 0 && string(raw) != "null"
}

func bytesTrim(raw json.RawMessage) json.RawMessage {
	return json.RawMessage(strings.TrimSpace(string(raw)))
}

type cursorToolState struct {
	kind, path, command, toolName string
	completed                     bool
	failed                        bool
}

func (session *cursorACPProtocolSession) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) (driveErr error) {
	state := &cursorACPConversation{session: session, tools: map[string]*cursorToolState{}, outstanding: "cursor-initialize"}
	defer func() {
		terminal := ports.ProviderSessionCompleted
		if driveErr != nil {
			terminal = ports.ProviderSessionFailed
			if state.sessionID != "" && !state.cancelled {
				_ = state.send(ctx, exchange, map[string]any{"jsonrpc": "2.0", "method": "session/cancel", "params": map[string]string{"sessionId": state.sessionID}})
				state.cancelled = true
			}
		}
		phase := state.phase
		if !phase.Valid() {
			phase = ports.ProviderSessionPhaseCreate
		}
		observation, err := ports.NewProviderSessionObservation(ports.ProviderSessionObservationInput{
			Phase: phase, Terminal: terminal,
			ProviderSessionID: state.sessionID,
			CreateAccepted:    state.sessionCreated,
			SendAccepted:      state.promptSent,
			TurnObserved:      state.promptCompleted,
			MessagesReceived:  state.promptCompleted && len(session.assistant) > 0,
			CloseSent:         state.cancelled,
		})
		session.observation = observation
		session.hasObservation = err == nil
		if err != nil {
			driveErr = errors.Join(driveErr, cursorACPFailure(domain.DiagnosticCauseObservationInvalid, err))
		}
	}()
	if err := state.send(ctx, exchange, map[string]any{
		"jsonrpc": "2.0", "id": "cursor-initialize", "method": "initialize",
		"params": map[string]any{
			"protocolVersion": 1,
			"clientCapabilities": map[string]any{
				"fs": map[string]bool{"readTextFile": false, "writeTextFile": false}, "terminal": false,
			},
			"clientInfo": map[string]string{"name": "mulgae", "version": "1"},
		},
	}); err != nil {
		return err
	}
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			return cursorACPFailure(domain.DiagnosticCauseProviderTurnFailed, fmt.Errorf("cursor ACP completion missing: %w", err))
		}
		var message cursorACPMessage
		if json.Unmarshal(line, &message) != nil || message.JSONRPC != "2.0" {
			return cursorACPFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("cursor ACP frame is not JSON-RPC 2.0"))
		}
		done, err := state.handle(ctx, exchange, message)
		if err != nil || done {
			return err
		}
	}
}

type cursorACPConversation struct {
	session         *cursorACPProtocolSession
	phase           ports.ProviderSessionPhase
	sessionID       string
	sessionCreated  bool
	askAcknowledged bool
	promptSent      bool
	promptCompleted bool
	cancelled       bool
	outstanding     string
	tools           map[string]*cursorToolState
}

func (state *cursorACPConversation) handle(ctx context.Context, exchange ports.ProviderSessionExchange, message cursorACPMessage) (bool, error) {
	if message.Method != "" && len(bytesTrim(message.ID)) > 0 {
		return false, state.handleServerRequest(ctx, exchange, message)
	}
	if message.Method == "session/update" {
		return false, state.handleUpdate(ctx, exchange, message)
	}
	if message.Method != "" {
		return true, cursorACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("cursor ACP notification %s is rejected", message.Method))
	}
	if message.failed() {
		return true, cursorACPFailure(domain.DiagnosticCauseProviderExecutionFailed, errors.New("cursor ACP request failed"))
	}
	switch messageIDText(message.ID) {
	case "cursor-initialize":
		if state.outstanding != "cursor-initialize" || state.sessionCreated {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP initialize was not outstanding"))
		}
		var payload struct {
			ProtocolVersion int `json:"protocolVersion"`
		}
		if json.Unmarshal(message.Result, &payload) != nil || payload.ProtocolVersion != 1 {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP initialize did not report protocol version 1"))
		}
		state.outstanding = "cursor-new"
		return false, state.send(ctx, exchange, map[string]any{
			"jsonrpc": "2.0", "id": "cursor-new", "method": "session/new",
			"params": map[string]any{"cwd": state.session.workspacePath, "mcpServers": []any{}},
		})
	case "cursor-new":
		if state.outstanding != "cursor-new" || state.sessionCreated {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP session/new was not outstanding"))
		}
		var payload struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(message.Result, &payload) != nil || payload.SessionID == "" {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP session/new lacked a session id"))
		}
		state.sessionID = payload.SessionID
		state.sessionCreated = true
		state.phase = ports.ProviderSessionPhaseCreate
		state.outstanding = "cursor-mode"
		return false, state.send(ctx, exchange, map[string]any{
			"jsonrpc": "2.0", "id": "cursor-mode", "method": "session/set_mode",
			"params": map[string]any{"sessionId": state.sessionID, "modeId": "ask"},
		})
	case "cursor-mode":
		if state.outstanding != "cursor-mode" || !state.sessionCreated {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP set_mode was not outstanding"))
		}
		if state.modeResultNamesAsk(message.Result) {
			state.askAcknowledged = true
		}
		state.outstanding = ""
		if err := state.maybePrompt(ctx, exchange); err != nil {
			return true, err
		}
		if state.promptSent {
			state.outstanding = "cursor-prompt"
		}
		return false, nil
	case "cursor-prompt":
		if state.outstanding != "cursor-prompt" || !state.promptSent {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP prompt result was uncorrelated"))
		}
		var payload struct {
			StopReason string `json:"stopReason"`
		}
		if json.Unmarshal(message.Result, &payload) != nil || payload.StopReason != "end_turn" {
			return true, cursorACPFailure(domain.DiagnosticCauseProviderTurnFailed, fmt.Errorf("cursor ACP stopped with %q", payload.StopReason))
		}
		if err := state.finishTools(ctx); err != nil {
			return true, err
		}
		if len(state.session.assistant) == 0 {
			return true, cursorACPFailure(domain.DiagnosticCauseOutputMissing, errors.New("cursor ACP assistant text is missing"))
		}
		state.promptCompleted = true
		state.phase = ports.ProviderSessionPhaseTurn
		state.outstanding = ""
		return true, nil
	default:
		return true, cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP result is uncorrelated"))
	}
}

func (state *cursorACPConversation) modeResultNamesAsk(result json.RawMessage) bool {
	var payload struct {
		CurrentModeID string `json:"currentModeId"`
	}
	if json.Unmarshal(result, &payload) != nil {
		return false
	}
	return payload.CurrentModeID == "ask"
}

func (state *cursorACPConversation) maybePrompt(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if state.promptSent || !state.askAcknowledged || state.sessionID == "" {
		return nil
	}
	state.promptSent = true
	state.phase = ports.ProviderSessionPhaseSend
	if state.outstanding == "" {
		state.outstanding = "cursor-prompt"
	}
	return state.send(ctx, exchange, map[string]any{
		"jsonrpc": "2.0", "id": "cursor-prompt", "method": "session/prompt",
		"params": map[string]any{"sessionId": state.sessionID, "prompt": []map[string]string{{"type": "text", "text": state.session.prompt}}},
	})
}

func (state *cursorACPConversation) handleUpdate(ctx context.Context, exchange ports.ProviderSessionExchange, message cursorACPMessage) error {
	var params struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			SessionUpdate string `json:"sessionUpdate"`
			CurrentModeID string `json:"currentModeId"`
			Kind          string `json:"kind"`
			Status        string `json:"status"`
			ToolCallID    string `json:"toolCallId"`
			Title         string `json:"title"`
			Locations     []struct {
				Path string `json:"path"`
			} `json:"locations"`
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
			RawInput map[string]any `json:"rawInput"`
		} `json:"update"`
	}
	if json.Unmarshal(message.Params, &params) != nil || params.SessionID == "" || state.sessionID == "" || params.SessionID != state.sessionID {
		return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP update is uncorrelated"))
	}
	update := params.Update
	if update.SessionUpdate == "current_mode_update" && update.CurrentModeID == "ask" {
		state.askAcknowledged = true
		return state.maybePrompt(ctx, exchange)
	}
	if update.SessionUpdate == "agent_message_chunk" {
		if !state.promptSent {
			return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP assistant text arrived before the prompt"))
		}
		state.session.assistant = append(state.session.assistant, []byte(update.Content.Text)...)
		return nil
	}
	if update.SessionUpdate != "tool_call" && update.SessionUpdate != "tool_call_update" {
		return nil
	}
	return state.observeTool(ctx, update.ToolCallID, update.Kind, update.Status, cursorPath(update.Locations, update.RawInput), cursorCommand(update.RawInput), cursorToolName(update.RawInput))
}

func cursorPath(locations []struct {
	Path string `json:"path"`
}, raw map[string]any) string {
	if path, _ := raw["path"].(string); path != "" {
		return path
	}
	if len(locations) > 0 {
		return locations[0].Path
	}
	return ""
}

func cursorCommand(raw map[string]any) string {
	command, _ := raw["command"].(string)
	return command
}

func cursorToolName(raw map[string]any) string {
	name, _ := raw["_toolName"].(string)
	return name
}

func (state *cursorACPConversation) observeTool(ctx context.Context, id, kind, status, path, command, toolName string) error {
	if state.session.purpose == protocolPurposeQualification || state.session.purpose == protocolPurposeExtraction || state.session.purpose == protocolPurposeLiveExtraction {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool call is closed for this purpose"))
	}
	if kind == "other" && toolName == "task" || toolName == "task" {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP subagent is rejected"))
	}
	if kind == "edit" || kind == "delete" {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP write is rejected"))
	}
	if id == "" {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool identity is missing"))
	}
	observed := state.tools[id]
	if observed == nil {
		observed = &cursorToolState{}
		state.tools[id] = observed
	}
	if observed.completed || observed.failed {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP terminal tool cannot reopen"))
	}
	if kind != "" {
		if observed.kind != "" && observed.kind != kind {
			return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP tool kind is uncorrelated"))
		}
		observed.kind = kind
	}
	if path != "" {
		if observed.path != "" && observed.path != path {
			return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP tool path is uncorrelated"))
		}
		observed.path = path
	}
	if command != "" {
		if observed.command != "" && observed.command != command {
			return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP tool command is uncorrelated"))
		}
		observed.command = command
	}
	if toolName != "" {
		if observed.toolName != "" && observed.toolName != toolName {
			return cursorACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("cursor ACP tool name is uncorrelated"))
		}
		observed.toolName = toolName
	}
	if observed.kind != "" && observed.kind != "read" && observed.kind != "execute" {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("cursor ACP tool %s is rejected", observed.kind))
	}
	if strings.EqualFold(status, "failed") {
		observed.failed = true
		return cursorACPFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("cursor ACP failed tool is not a selected read"))
	}
	if strings.EqualFold(status, "completed") {
		if observed.kind == "" {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool kind is missing"))
		}
		observed.completed = true
		return state.admitTool(ctx, observed)
	}
	return nil
}

func (state *cursorACPConversation) admitTool(ctx context.Context, observed *cursorToolState) error {
	if observed != nil && observed.failed {
		return cursorACPFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("cursor ACP failed tool is not a selected read"))
	}
	if state.session.liveReads == nil {
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool is outside a read plan"))
	}
	switch observed.kind {
	case "execute":
		if err := state.session.liveReads.allowGit(observed.command); err != nil {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, err)
		}
	case "read":
		if err := state.session.liveReads.allowWorkspacePath(ctx, observed.path); err != nil {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, err)
		}
	default:
		if observed.kind == "" {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool kind is missing"))
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("cursor ACP tool %s is rejected", observed.kind))
	}
	return nil
}

func (state *cursorACPConversation) finishTools(ctx context.Context) error {
	if state.session.purpose != protocolPurposeLiveReview {
		if len(state.tools) != 0 {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool call is closed for this purpose"))
		}
		return nil
	}
	for _, observed := range state.tools {
		if observed.failed {
			return cursorACPFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("cursor ACP failed tool is not a selected read"))
		}
		if !observed.completed {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool completion is missing"))
		}
		if err := state.admitTool(ctx, observed); err != nil {
			return err
		}
	}
	return nil
}

func (state *cursorACPConversation) handleServerRequest(ctx context.Context, exchange ports.ProviderSessionExchange, message cursorACPMessage) error {
	var params struct {
		SessionID string `json:"sessionId"`
		ToolCall  struct {
			ToolCallID string         `json:"toolCallId"`
			Kind       string         `json:"kind"`
			RawInput   map[string]any `json:"rawInput"`
			Locations  []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(message.Params, &params)
	switch message.Method {
	case "cursor/ask_question", "cursor/create_plan":
		return state.respond(ctx, exchange, message.ID, map[string]any{"outcome": map[string]any{"outcome": "cancelled"}})
	case "session/request_permission":
		return state.answerPermission(ctx, exchange, message, params.SessionID, params.ToolCall.ToolCallID, params.ToolCall.Kind, cursorPath(params.ToolCall.Locations, params.ToolCall.RawInput), cursorCommand(params.ToolCall.RawInput), cursorToolName(params.ToolCall.RawInput), params.Options)
	default:
		if state.sessionID != "" && params.SessionID != "" && params.SessionID != state.sessionID {
			return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP server request is for another session"))
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("cursor ACP unknown server request %s", message.Method))
	}
}

func (state *cursorACPConversation) correlatedExecuteCommand(toolCallID, permissionCommand string) (string, bool) {
	return state.correlatedToolValue(toolCallID, permissionCommand, func(observed *cursorToolState) string { return observed.command })
}

func (state *cursorACPConversation) correlatedReadPath(toolCallID, permissionPath string) (string, bool) {
	return state.correlatedToolValue(toolCallID, permissionPath, func(observed *cursorToolState) string { return observed.path })
}

func (state *cursorACPConversation) correlatedToolValue(toolCallID, permissionValue string, stored func(*cursorToolState) string) (string, bool) {
	observed := state.tools[toolCallID]
	if observed == nil || stored(observed) == "" {
		return permissionValue, true
	}
	if permissionValue != "" && permissionValue != stored(observed) {
		return "", false
	}
	return stored(observed), true
}

func (state *cursorACPConversation) liveGrantOpen(requestSessionID string) bool {
	return state.promptSent && requestSessionID != "" && requestSessionID == state.sessionID
}

func (state *cursorACPConversation) answerPermission(ctx context.Context, exchange ports.ProviderSessionExchange, message cursorACPMessage, requestSessionID, toolCallID, kind, path, command, toolName string, options []struct {
	OptionID string `json:"optionId"`
	Kind     string `json:"kind"`
}) error {
	if state.session.purpose == protocolPurposeQualification || state.session.purpose == protocolPurposeExtraction || state.session.purpose == protocolPurposeLiveExtraction {
		if err := state.rejectPermission(ctx, exchange, message.ID, options); err != nil {
			return err
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP tool call is closed for this purpose"))
	}
	if toolName == "task" || kind == "other" || kind == "edit" || kind == "delete" {
		if err := state.rejectPermission(ctx, exchange, message.ID, options); err != nil {
			return err
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP forbidden permission is rejected"))
	}
	if kind == "execute" && state.session.liveReads != nil {
		correlated, matched := state.correlatedExecuteCommand(toolCallID, command)
		planned := matched && state.session.liveReads.allowGit(correlated) == nil
		if planned && state.liveGrantOpen(requestSessionID) {
			authorized, err := state.allowOnce(ctx, exchange, message, toolCallID, kind, path, correlated, toolName, options)
			if err != nil || authorized {
				return err
			}
			return nil
		}
		if err := state.rejectPermission(ctx, exchange, message.ID, options); err != nil {
			return err
		}
		if planned {
			return nil
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP unplanned execute is rejected"))
	}
	if kind == "read" && state.session.liveReads != nil {
		correlated, matched := state.correlatedReadPath(toolCallID, path)
		planned := matched && state.session.liveReads.allowWorkspacePath(ctx, correlated) == nil
		if err := state.rejectPermission(ctx, exchange, message.ID, options); err != nil {
			return err
		}
		if planned {
			return nil
		}
		return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP unplanned read is rejected"))
	}
	if err := state.rejectPermission(ctx, exchange, message.ID, options); err != nil {
		return err
	}
	return cursorACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("cursor ACP forbidden permission is rejected"))
}

func (state *cursorACPConversation) allowOnce(ctx context.Context, exchange ports.ProviderSessionExchange, message cursorACPMessage, toolCallID, kind, path, command, toolName string, options []struct {
	OptionID string `json:"optionId"`
	Kind     string `json:"kind"`
}) (bool, error) {
	for _, option := range options {
		if option.Kind == "allow_always" {
			continue
		}
		if option.Kind == "allow_once" && option.OptionID != "" {
			if err := state.observeTool(ctx, toolCallID, kind, "", path, command, toolName); err != nil {
				return false, err
			}
			return true, state.respond(ctx, exchange, message.ID, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": option.OptionID}})
		}
	}
	return false, state.rejectPermission(ctx, exchange, message.ID, options)
}

func (state *cursorACPConversation) rejectPermission(ctx context.Context, exchange ports.ProviderSessionExchange, id json.RawMessage, options []struct {
	OptionID string `json:"optionId"`
	Kind     string `json:"kind"`
}) error {
	for _, option := range options {
		if option.OptionID == "" {
			continue
		}
		if option.Kind == "reject_once" || option.OptionID == "reject-once" {
			return state.respond(ctx, exchange, id, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": option.OptionID}})
		}
	}
	return state.respond(ctx, exchange, id, map[string]any{"outcome": map[string]any{"outcome": "cancelled"}})
}

func messageIDText(id json.RawMessage) string {
	return strings.Trim(string(bytesTrim(id)), `"`)
}

func (state *cursorACPConversation) respond(ctx context.Context, exchange ports.ProviderSessionExchange, id json.RawMessage, result any) error {
	return state.send(ctx, exchange, map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
}

func (state *cursorACPConversation) send(ctx context.Context, exchange ports.ProviderSessionExchange, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return cursorACPFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	if err := exchange.SendLine(ctx, payload); err != nil {
		return cursorACPFailure(domain.DiagnosticCauseProviderExecutionFailed, err)
	}
	return nil
}
