package providercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	grokACPProtocolVersion = 1

	grokACPInitializeID = "mulgae-initialize"
	grokACPAuthID       = "mulgae-authenticate"
	grokACPNewID        = "mulgae-session-new"
	grokACPPromptID     = "mulgae-session-prompt"
	grokACPCloseID      = "mulgae-session-close"

	grokACPAuthMethod          = "authenticate"
	grokACPInitializeMethod    = "initialize"
	grokACPSessionNewMethod    = "session/new"
	grokACPSessionPromptMethod = "session/prompt"
	grokACPSessionCloseMethod  = "session/close"
	grokACPSessionUpdateMethod = "session/update"
	grokACPRequestPermission   = "session/request_permission"
	grokACPMCPServersUpdated   = "_x.ai/mcp/servers_updated"
	grokACPMCPInitialized      = "_x.ai/mcp_initialized"

	grokACPAgentMessageChunk = "agent_message_chunk"
	grokACPToolCall          = "tool_call"
	grokACPToolCallUpdate    = "tool_call_update"
)

type grokACPError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (failure *grokACPError) Error() string {
	if failure == nil {
		return "grok ACP failure"
	}
	return "grok ACP failure: " + failure.err.Error()
}
func (failure *grokACPError) Unwrap() error { return failure.err }
func (failure *grokACPError) Cause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.cause
}
func (failure *grokACPError) ProtocolFailureCause() domain.RuntimeDiagnosticCause {
	return failure.Cause()
}

func grokACPFailure(cause domain.RuntimeDiagnosticCause, err error) *grokACPError {
	return &grokACPError{cause: cause, err: err}
}

// grokACPProtocolSession implements the deterministic ACP v1 client contract
// without registering Grok as a production provider. TASK-012 can bind this
// constructor only after the live gate and public contracts are complete.
type grokACPProtocolSession struct {
	workspacePath  string
	prompt         string
	purpose        protocolInvocationPurpose
	writeAuthority protocolWriteAuthority

	assistantEvidence []string
	observation       ports.ProviderSessionObservation
	toolVariants      map[string]bool
	deniedLocations   map[string]bool
	mcpObserved       bool
}

func newGrokACPProtocolSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority) (*grokACPProtocolSession, error) {
	if !validCanonicalAbsolute(workspacePath) || len(prompt) == 0 {
		return nil, fmt.Errorf("grok ACP: invalid session request")
	}
	switch purpose {
	case protocolPurposeReview:
		if writeAuthority == nil {
			return nil, fmt.Errorf("grok ACP: review requires an exact staged destination")
		}
	case protocolPurposeExtraction, protocolPurposeQualification:
		if writeAuthority != nil {
			return nil, fmt.Errorf("grok ACP: non-review purpose cannot receive a staged destination")
		}
	default:
		return nil, fmt.Errorf("grok ACP: unsupported invocation purpose")
	}
	return &grokACPProtocolSession{
		workspacePath:  workspacePath,
		prompt:         string(prompt),
		purpose:        purpose,
		writeAuthority: writeAuthority,
	}, nil
}

func (session *grokACPProtocolSession) AssistantEvidenceText() []byte {
	if session == nil || len(session.assistantEvidence) == 0 {
		return nil
	}
	return []byte(strings.Join(session.assistantEvidence, ""))
}

func (session *grokACPProtocolSession) SessionObservation() (ports.ProviderSessionObservation, bool) {
	if session == nil || !session.observation.Valid() {
		return ports.ProviderSessionObservation{}, false
	}
	return session.observation, true
}

func (session *grokACPProtocolSession) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) (driveErr error) {
	if session == nil || exchange == nil {
		return grokACPFailure(domain.DiagnosticCauseObservationInvalid, errors.New("invalid ACP conversation"))
	}
	state := grokACPConversation{
		purpose: session.purpose, prompt: session.prompt, workspacePath: session.workspacePath,
		writeAuthority: session.writeAuthority, phase: ports.ProviderSessionPhaseCreate,
		toolLocations: make(map[string]string), toolVariants: make(map[string]bool), deniedLocations: make(map[string]bool),
	}
	defer func() {
		terminal := ports.ProviderSessionCompleted
		if driveErr != nil {
			terminal = ports.ProviderSessionFailed
		}
		observation, err := ports.NewProviderSessionObservation(ports.ProviderSessionObservationInput{
			Phase: state.phase, Terminal: terminal,
			ProviderSessionID: safeZcodeDiagnosticIdentifier(state.sessionID),
			ProviderTurnID:    safeZcodeDiagnosticIdentifier(state.turnID),
			CreateAccepted:    state.sessionCreated,
			SendAccepted:      state.promptSent,
			TurnObserved:      state.promptCompleted,
			MessagesReceived:  state.messageReceived,
			CloseSent:         state.closeSent,
			CloseAccepted:     state.closeAccepted,
			ProviderErrorCode: state.providerErrorCode, HasProviderErrorCode: state.hasProviderErrorCode,
		})
		session.observation = observation
		if err != nil {
			driveErr = errors.Join(driveErr, grokACPFailure(domain.DiagnosticCauseObservationInvalid, err))
		}
	}()
	if err := sendGrokACPRequest(ctx, exchange, grokACPInitializeID, grokACPInitializeMethod, map[string]any{
		"protocolVersion": grokACPProtocolVersion,
		"clientCapabilities": map[string]any{
			"fs":       map[string]bool{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
		"clientInfo": map[string]string{"name": "mulgae", "title": "Mulgae", "version": "1"},
	}); err != nil {
		return err
	}
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return grokACPFailure(domain.DiagnosticCauseProviderTurnFailed, fmt.Errorf("ACP completion missing: %w", err))
		}
		message, err := parseGrokACPMessage(line)
		if err != nil {
			return grokACPFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
		}
		done, err := state.handle(ctx, exchange, message)
		if done || err != nil {
			if err == nil {
				session.assistantEvidence = append([]string(nil), state.assistantEvidence...)
				session.toolVariants = cloneBoolMap(state.toolVariants)
				session.deniedLocations = cloneBoolMap(state.deniedLocations)
				session.mcpObserved = state.mcpObserved
			}
			return err
		}
	}
}

type grokACPConversation struct {
	purpose        protocolInvocationPurpose
	prompt         string
	workspacePath  string
	writeAuthority protocolWriteAuthority
	phase          ports.ProviderSessionPhase

	initialized, authenticated, sessionCreated, promptSent bool
	promptCompleted, messageReceived, closeSent            bool
	closeAccepted, permissionGranted                       bool
	sessionID, turnID                                      string
	providerErrorCode                                      int
	hasProviderErrorCode                                   bool
	assistantEvidence                                      []string
	toolLocations                                          map[string]string
	toolVariants                                           map[string]bool
	deniedLocations                                        map[string]bool
	mcpObserved                                            bool
}

func (state *grokACPConversation) handle(ctx context.Context, exchange ports.ProviderSessionExchange, message grokACPMessage) (bool, error) {
	if message.Method != "" {
		if len(message.ID) != 0 {
			return false, state.handleServerRequest(ctx, exchange, message)
		}
		return false, state.handleNotification(message)
	}
	if message.Error != nil {
		if !message.correlatesTo(grokACPInitializeID, grokACPAuthID, grokACPNewID, grokACPPromptID, grokACPCloseID) {
			return false, nil
		}
		state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
		return true, grokACPFailure(domain.DiagnosticCauseProviderExecutionFailed,
			fmt.Errorf("ACP request failed: %s", message.Error.Message))
	}
	switch {
	case message.isResponseID(grokACPInitializeID):
		if err := state.acceptInitialize(message.Result); err != nil {
			return true, grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		return false, sendGrokACPRequest(ctx, exchange, grokACPAuthID, grokACPAuthMethod, map[string]any{"methodId": "cached_token"})
	case message.isResponseID(grokACPAuthID):
		if !state.initialized || state.authenticated {
			return true, grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected authentication response"))
		}
		state.authenticated = true
		return false, sendGrokACPRequest(ctx, exchange, grokACPNewID, grokACPSessionNewMethod, map[string]any{
			"cwd": state.workspacePath, "mcpServers": []any{},
		})
	case message.isResponseID(grokACPNewID):
		if err := state.acceptSessionNew(message.Result); err != nil {
			return true, grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		state.phase = ports.ProviderSessionPhaseSend
		if err := sendGrokACPRequest(ctx, exchange, grokACPPromptID, grokACPSessionPromptMethod, map[string]any{
			"sessionId": state.sessionID,
			"prompt":    []map[string]string{{"type": "text", "text": state.prompt}},
		}); err != nil {
			return true, err
		}
		state.promptSent = true
		state.phase = ports.ProviderSessionPhaseTurn
		return false, nil
	case message.isResponseID(grokACPPromptID):
		if err := state.acceptPrompt(message.Result); err != nil {
			return true, grokACPFailure(domain.DiagnosticCauseProviderTurnFailed, err)
		}
		state.promptCompleted = true
		if (state.purpose == protocolPurposeExtraction || state.purpose == protocolPurposeQualification) && !state.messageReceived {
			return true, grokACPFailure(domain.DiagnosticCauseOutputMissing, errors.New("matching assistant message is missing"))
		}
		state.phase = ports.ProviderSessionPhaseClose
		state.closeSent = true
		return false, sendGrokACPRequest(ctx, exchange, grokACPCloseID, grokACPSessionCloseMethod, map[string]any{"sessionId": state.sessionID})
	case message.isResponseID(grokACPCloseID):
		if !state.closeSent || !state.promptCompleted {
			return true, grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected close response"))
		}
		state.closeAccepted = true
		return true, nil
	default:
		return false, nil
	}
}

func (state *grokACPConversation) acceptInitialize(result json.RawMessage) error {
	if state.initialized {
		return errors.New("duplicate initialize response")
	}
	var payload struct {
		ProtocolVersion int `json:"protocolVersion"`
		AuthMethods     []struct {
			ID string `json:"id"`
		} `json:"authMethods"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable initialize result: %w", err)
	}
	if payload.ProtocolVersion != grokACPProtocolVersion {
		return fmt.Errorf("incompatible ACP protocol version")
	}
	for _, method := range payload.AuthMethods {
		if method.ID == "cached_token" {
			state.initialized = true
			return nil
		}
	}
	return errors.New("cached_token authentication is unavailable")
}

func (state *grokACPConversation) acceptSessionNew(result json.RawMessage) error {
	if !state.authenticated || state.sessionCreated {
		return errors.New("unexpected session/new response")
	}
	var payload struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session/new result: %w", err)
	}
	if safeZcodeDiagnosticIdentifier(payload.SessionID) == "" {
		return errors.New("session/new result without a safe session id")
	}
	state.sessionID = payload.SessionID
	state.sessionCreated = true
	return nil
}

func (state *grokACPConversation) acceptPrompt(result json.RawMessage) error {
	if !state.sessionCreated || !state.promptSent || state.promptCompleted {
		return errors.New("unexpected session/prompt response")
	}
	var payload struct {
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session/prompt result: %w", err)
	}
	if payload.StopReason != "end_turn" {
		return fmt.Errorf("session/prompt stopped with %q", payload.StopReason)
	}
	return nil
}

func (state *grokACPConversation) handleNotification(message grokACPMessage) error {
	switch message.Method {
	case grokACPMCPServersUpdated:
		var params struct {
			MCPServers []json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(message.Params, &params); err != nil || len(params.MCPServers) != 0 {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("active ACP MCP server rejected"))
		}
		state.mcpObserved = true
		return nil
	case grokACPMCPInitialized:
		var params struct {
			SessionID    string `json:"sessionId"`
			MCPToolCount int    `json:"mcpToolCount"`
		}
		if err := json.Unmarshal(message.Params, &params); err != nil || params.SessionID != state.sessionID || params.MCPToolCount != 0 {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("active ACP MCP tool rejected"))
		}
		state.mcpObserved = true
		return nil
	case grokACPSessionUpdateMethod:
	default:
		return nil
	}
	var params struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			SessionUpdate string          `json:"sessionUpdate"`
			ToolCallID    string          `json:"toolCallId"`
			Kind          string          `json:"kind"`
			Content       json.RawMessage `json:"content"`
			RawInput      json.RawMessage `json:"rawInput"`
			Status        string          `json:"status"`
			Locations     []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"update"`
	}
	if err := json.Unmarshal(message.Params, &params); err != nil {
		return grokACPFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("unreadable ACP session update"))
	}
	if !state.sessionCreated || params.SessionID != state.sessionID {
		return grokACPFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("uncorrelated ACP session update"))
	}
	switch params.Update.SessionUpdate {
	case grokACPAgentMessageChunk:
		var content struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(params.Update.Content, &content); err != nil {
			return grokACPFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("unreadable ACP assistant message"))
		}
		if (state.purpose == protocolPurposeExtraction || state.purpose == protocolPurposeQualification) && content.Type == "text" && content.Text != "" {
			state.assistantEvidence = append(state.assistantEvidence, content.Text)
			state.messageReceived = true
			state.phase = ports.ProviderSessionPhaseMessages
		}
	case grokACPToolCall, grokACPToolCallUpdate:
		var input struct {
			Variant string `json:"variant"`
		}
		if len(params.Update.RawInput) != 0 && string(params.Update.RawInput) != "null" {
			if err := json.Unmarshal(params.Update.RawInput, &input); err != nil {
				return grokACPFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("unreadable ACP tool input"))
			}
			if input.Variant != "" {
				switch input.Variant {
				case "ReadFile", "Grep", "ListDir", "Write":
					state.toolVariants[input.Variant] = true
				default:
					return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("unexpected ACP tool variant"))
				}
			}
		}
		if params.Update.ToolCallID != "" && len(params.Update.Locations) == 1 {
			state.toolLocations[params.Update.ToolCallID] = params.Update.Locations[0].Path
		}
		if strings.EqualFold(params.Update.Status, "failed") {
			if location := state.toolLocations[params.Update.ToolCallID]; location != "" {
				state.deniedLocations[location] = true
			}
		}
		if params.Update.Kind == "" || params.Update.Kind == "read" || params.Update.Kind == "search" || params.Update.Kind == "other" {
			return nil
		}
		if params.Update.ToolCallID == "" || params.Update.Kind != "edit" || len(params.Update.Locations) != 1 {
			return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("invalid ACP tool update"))
		}
		state.toolLocations[params.Update.ToolCallID] = params.Update.Locations[0].Path
	}
	return nil
}

func cloneBoolMap(source map[string]bool) map[string]bool {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]bool, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (state *grokACPConversation) handleServerRequest(ctx context.Context, exchange ports.ProviderSessionExchange, message grokACPMessage) error {
	if message.Method != grokACPRequestPermission {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("unexpected ACP server request"))
	}
	var params struct {
		SessionID string `json:"sessionId"`
		ToolCall  struct {
			ToolCallID string `json:"toolCallId"`
			Kind       string `json:"kind"`
			RawInput   struct {
				Variant  string `json:"variant"`
				FilePath string `json:"file_path"`
			} `json:"rawInput"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	if err := json.Unmarshal(message.Params, &params); err != nil {
		return grokACPFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("unreadable ACP permission request"))
	}
	allowOption := ""
	for _, option := range params.Options {
		if option.Kind == "allow_once" {
			allowOption = option.OptionID
			break
		}
	}
	want := ""
	if state.writeAuthority != nil {
		destination, err := state.writeAuthority.Destination()
		if err == nil {
			want = destination.AbsolutePath()
		}
	}
	location := state.toolLocations[params.ToolCall.ToolCallID]
	valid := state.purpose == protocolPurposeReview && !state.permissionGranted &&
		params.SessionID == state.sessionID && params.ToolCall.ToolCallID != "" &&
		params.ToolCall.Kind == "edit" && params.ToolCall.RawInput.Variant == "Write" &&
		validCanonicalAbsolute(params.ToolCall.RawInput.FilePath) && params.ToolCall.RawInput.FilePath == want &&
		location == want && allowOption != ""
	if !valid {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("ACP write permission rejected"))
	}
	if err := state.writeAuthority.AuthorizeWriteOnce(params.ToolCall.RawInput.FilePath); err != nil {
		return grokACPFailure(domain.DiagnosticCausePermissionDenied, errors.New("ACP staged write authority rejected"))
	}
	if err := sendGrokACPResponse(ctx, exchange, message.ID, map[string]any{
		"outcome": map[string]string{"outcome": "selected", "optionId": allowOption},
	}); err != nil {
		return err
	}
	state.permissionGranted = true
	return nil
}

type grokACPMessage struct {
	JSONRPC string
	ID      json.RawMessage
	Method  string
	Params  json.RawMessage
	Result  json.RawMessage
	Error   *grokACPWireError
}

type grokACPWireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func parseGrokACPMessage(line []byte) (grokACPMessage, error) {
	var decoded struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      json.RawMessage   `json:"id"`
		Method  string            `json:"method"`
		Params  json.RawMessage   `json:"params"`
		Result  json.RawMessage   `json:"result"`
		Error   *grokACPWireError `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	if err := decoder.Decode(&decoded); err != nil {
		return grokACPMessage{}, fmt.Errorf("grok ACP: decode message: %w", err)
	}
	if decoded.JSONRPC != "2.0" || (len(decoded.ID) == 0 && decoded.Method == "") {
		return grokACPMessage{}, errors.New("grok ACP: invalid JSON-RPC message")
	}
	return grokACPMessage(decoded), nil
}

func (message grokACPMessage) isResponseID(id string) bool {
	if len(message.ID) == 0 || message.Method != "" {
		return false
	}
	var decoded string
	return json.Unmarshal(message.ID, &decoded) == nil && decoded == id
}

func (message grokACPMessage) correlatesTo(ids ...string) bool {
	for _, id := range ids {
		if message.isResponseID(id) {
			return true
		}
	}
	return false
}

func sendGrokACPRequest(ctx context.Context, exchange ports.ProviderSessionExchange, id, method string, params any) error {
	return sendGrokACPMessage(ctx, exchange, map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
}

func sendGrokACPResponse(ctx context.Context, exchange ports.ProviderSessionExchange, id json.RawMessage, result any) error {
	return sendGrokACPMessage(ctx, exchange, map[string]any{
		"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result,
	})
}

func sendGrokACPMessage(ctx context.Context, exchange ports.ProviderSessionExchange, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return grokACPFailure(domain.DiagnosticCauseObservationInvalid, fmt.Errorf("grok ACP: encode message: %w", err))
	}
	if err := exchange.SendLine(ctx, payload); err != nil {
		return grokACPFailure(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("grok ACP: send message: %w", err))
	}
	return nil
}
