package providercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ZCode Protocol v1 framing and session facts originated in the bundled launcher
// protocol 0.16.5 spike. Account configuration, exact model selection, and
// independent thought-level selection are certified against the supported ZCode
// app bundle, as recorded in the ADR zcode-app-server-transport. The protocol is
// newline-delimited JSON over the child stdin and stdout pipes. Requests carry
// {"id","method","params"} without a JSON-RPC envelope, responses echo the
// request id with either "result" or "error", and notifications carry
// {"method","params"} without an id.
const (
	zcodeProtocolCreateMethod     = "session/create"
	zcodeProtocolAccountMethod    = "provider/updateAccountConfig"
	zcodeProtocolSetModelMethod   = "session/setModel"
	zcodeProtocolSetThoughtMethod = "session/setThoughtLevel"
	zcodeProtocolSendMethod       = "session/send"
	zcodeProtocolCloseMethod      = "session/close"
	// zcodeProtocolMessagesMethod reads the conversation's messages after a
	// completed turn; the assistant text parts carry the qualification probe's
	// controlled evidence, which never appears in the protocol transcript
	// itself.
	zcodeProtocolMessagesMethod = "session/messages"

	zcodeProtocolCreateID     = "mulgae-create"
	zcodeProtocolAccountID    = "mulgae-account"
	zcodeProtocolSetModelID   = "mulgae-model-0"
	zcodeProtocolSetThoughtID = "mulgae-thought"
	zcodeProtocolSendID       = "mulgae-send"
	zcodeProtocolCloseID      = "mulgae-close"
	zcodeProtocolMessagesID   = "mulgae-messages"

	// zcodeProtocolMessageLimit bounds the message read to the completed
	// conversation's own turn.
	zcodeProtocolMessageLimit = 8

	zcodeProtocolRequestRuntimePreferencesMethod     = "session/requestRuntimePreferences"
	zcodeProtocolRequestProviderRuntimeHeadersMethod = "interaction/requestProviderRuntimeHeaders"

	zcodeProtocolTurnCompletedKind = "turn-completed"
	zcodeProtocolTurnFailedKind    = "turn-failed"
)

var errZCodeSelectedModelUnavailable = errors.New("selected ZCode model is unavailable")

// zcodeProtocolError is the typed fail-closed classification for a protocol
// conversation that ended without a complete provider turn.
type zcodeProtocolError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

// protocolConversationFailure keeps the driver's bounded session facts attached
// while the process observation travels through workspace revalidation.
type protocolConversationFailure struct {
	observation ports.ProviderSessionObservation
	err         error
}

func (failure *protocolConversationFailure) Error() string { return "provider conversation failed" }
func (failure *protocolConversationFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}
func (failure *protocolConversationFailure) SessionObservation() ports.ProviderSessionObservation {
	if failure == nil {
		return ports.ProviderSessionObservation{}
	}
	return failure.observation
}

func zcodeProtocolFailure(cause domain.RuntimeDiagnosticCause, err error) *zcodeProtocolError {
	return &zcodeProtocolError{cause: cause, err: err}
}

func (failure *zcodeProtocolError) Error() string {
	if failure == nil {
		return "zcode protocol failure"
	}
	return "zcode protocol failure: " + failure.err.Error()
}

func (failure *zcodeProtocolError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func (failure *zcodeProtocolError) Cause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.cause
}
func (failure *zcodeProtocolError) ProtocolFailureCause() domain.RuntimeDiagnosticCause {
	return failure.Cause()
}

// zcodeProtocolSession drives one ZCode review or qualification conversation:
// create the session, deliver the packet as the single turn's content, await
// the turn's terminal notification, optionally read the assistant response
// text, close the session, and await the close response. Protocol semantics
// beyond this exchange stay with the server; the conversation runner owns the
// process, its group, the timeout budget, and teardown.
type zcodeProtocolSession struct {
	workspacePath string
	mode          string
	toolDenylist  []string
	prompt        string
	// captureAssistantText enables the post-turn message read that collects
	// the assistant text parts into assistantEvidence.
	captureAssistantText bool
	assistantEvidence    []string
	observation          ports.ProviderSessionObservation
	modelSelection       *zcodeModelSelection
	reasoningEffort      string
	account              *zcodeAccountRuntime
}

func newZcodeReviewProtocolSession(workspacePath string, prompt []byte, selection ...*zcodeModelSelection) (*zcodeProtocolSession, error) {
	return newZcodeProtocolSession(workspacePath, "yolo", zcodeReviewProtocolDenylist, prompt, firstZCodeModelSelection(selection))
}

func newZcodeCapabilityProtocolSession(workspacePath string, prompt []byte, selection ...*zcodeModelSelection) (*zcodeProtocolSession, error) {
	session, err := newZcodeProtocolSession(workspacePath, "plan", zcodeCapabilityProtocolDenylist, prompt, firstZCodeModelSelection(selection))
	if err != nil {
		return nil, err
	}
	session.captureAssistantText = true
	return session, nil
}

// newZcodeExtractionProtocolSession runs the structured extraction trailer in
// the review posture and captures the assistant text, which carries the exact
// JSON the extraction contract demands.
func newZcodeExtractionProtocolSession(workspacePath string, prompt []byte, selection ...*zcodeModelSelection) (*zcodeProtocolSession, error) {
	session, err := newZcodeProtocolSession(workspacePath, "yolo", zcodeReviewProtocolDenylist, prompt, firstZCodeModelSelection(selection))
	if err != nil {
		return nil, err
	}
	session.captureAssistantText = true
	return session, nil
}

func firstZCodeModelSelection(selections []*zcodeModelSelection) *zcodeModelSelection {
	if len(selections) == 0 {
		return nil
	}
	return cloneZCodeModelSelection(selections[0])
}

func newZcodeProtocolSession(workspacePath, mode string, denylist []string, prompt []byte, selection *zcodeModelSelection) (*zcodeProtocolSession, error) {
	if !validCanonicalAbsolute(workspacePath) || len(prompt) == 0 || len(denylist) == 0 {
		return nil, fmt.Errorf("zcode protocol: invalid session request")
	}
	if selection != nil && (strings.TrimSpace(selection.ProviderID) == "" || strings.TrimSpace(selection.ModelID) == "") {
		return nil, fmt.Errorf("zcode protocol: invalid model selection")
	}
	return &zcodeProtocolSession{
		workspacePath:  workspacePath,
		mode:           mode,
		toolDenylist:   append([]string(nil), denylist...),
		prompt:         string(prompt),
		modelSelection: cloneZCodeModelSelection(selection),
	}, nil
}

// assistantEvidenceText returns the captured assistant response text joined
// by newlines, or nil when the conversation did not capture it.
func (session *zcodeProtocolSession) assistantEvidenceText() []byte {
	if session == nil || len(session.assistantEvidence) == 0 {
		return nil
	}
	return []byte(strings.Join(session.assistantEvidence, "\n"))
}

func (session *zcodeProtocolSession) AssistantEvidenceText() []byte {
	return session.assistantEvidenceText()
}

func (session *zcodeProtocolSession) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) (driveErr error) {
	state := &zcodeProtocolConversation{prompt: session.prompt, workspacePath: session.workspacePath, mode: session.mode, toolDenylist: append([]string(nil), session.toolDenylist...), captureAssistantText: session.captureAssistantText, phase: ports.ProviderSessionPhaseCreate, modelSelection: cloneZCodeModelSelection(session.modelSelection), reasoningEffort: session.reasoningEffort, account: session.account}
	defer func() {
		terminal := ports.ProviderSessionCompleted
		if driveErr != nil {
			terminal = ports.ProviderSessionFailed
		}
		input := ports.ProviderSessionObservationInput{
			Phase: state.phase, Terminal: terminal,
			ProviderSessionID: safeZcodeDiagnosticIdentifier(state.sessionID),
			ProviderTurnID:    safeZcodeDiagnosticIdentifier(state.turnID),
			CreateAccepted:    state.createAccepted, SendAccepted: state.sendAccepted, TurnObserved: state.turnObserved,
			MessagesReceived: state.messagesReceived, CloseSent: state.closeSent, CloseAccepted: state.closeAccepted,
			ProviderErrorCode: state.providerErrorCode, HasProviderErrorCode: state.hasProviderErrorCode,
		}
		var observationErr error
		observation, observationErr := ports.NewProviderSessionObservation(input)
		session.observation = observation
		if observationErr != nil {
			driveErr = errors.Join(driveErr, zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid, observationErr))
		}
	}()
	if err := state.start(ctx, exchange); err != nil {
		driveErr = err
		return
	}
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				driveErr = err
				return
			}
			if state.turnCompleted {
				// The provider turn already completed; a stream that ends
				// between the closing requests and their responses ends the
				// driver while the conversation runner's teardown ends the
				// child. The captured assistant evidence stays usable.
				session.assistantEvidence = state.assistantEvidence
				return
			}
			driveErr = zcodeProtocolFailure(domain.DiagnosticCauseProviderTurnFailed,
				fmt.Errorf("turn completion missing: %w", err))
			return
		}
		message, err := parseZcodeProtocolMessage(line)
		if err != nil {
			driveErr = zcodeProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
			return
		}
		if done, err := state.handle(ctx, exchange, message); done || err != nil {
			if err == nil {
				session.assistantEvidence = state.assistantEvidence
			}
			driveErr = err
			return
		}
	}
}

func (session *zcodeProtocolSession) SessionObservation() (ports.ProviderSessionObservation, bool) {
	if session == nil || !session.observation.Valid() {
		return ports.ProviderSessionObservation{}, false
	}
	return session.observation, true
}

func safeZcodeDiagnosticIdentifier(value string) string {
	if len(value) > 512 || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

// zcodeProtocolConversation tracks one conversation's request correlation and
// turn completion.
type zcodeProtocolConversation struct {
	prompt                string
	workspacePath         string
	mode                  string
	toolDenylist          []string
	sessionID             string
	turnID                string
	phase                 ports.ProviderSessionPhase
	createAccepted        bool
	sendAccepted          bool
	turnObserved          bool
	turnCompleted         bool
	messagesRequested     bool
	messagesReceived      bool
	closeSent             bool
	closeAccepted         bool
	providerErrorCode     int
	hasProviderErrorCode  bool
	captureAssistantText  bool
	assistantEvidence     []string
	modelSelection        *zcodeModelSelection
	modelDefaultReasoning string
	reasoningEffort       string
	account               *zcodeAccountRuntime
	accountPending        bool
	modelRequestPending   bool
	modelAccepted         bool
	thoughtRequestPending bool
	thoughtAccepted       bool
}

func (state *zcodeProtocolConversation) start(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if state.account == nil {
		return state.sendCreate(ctx, exchange)
	}
	state.accountPending = true
	return sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolAccountID, zcodeProtocolAccountMethod, state.account.accountConfigParams())
}

func (state *zcodeProtocolConversation) sendCreate(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	return sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolCreateID, zcodeProtocolCreateMethod, map[string]any{
		"workspace": map[string]string{"workspacePath": state.workspacePath, "workspaceKey": state.workspacePath},
		"mode":      state.mode, "toolDenylist": state.toolDenylist, "titleGenerationEnabled": false,
	})
}

func (state *zcodeProtocolConversation) handle(ctx context.Context, exchange ports.ProviderSessionExchange, message zcodeProtocolMessage) (bool, error) {
	if message.Method != "" {
		if len(message.ID) == 0 {
			return state.handleNotification(ctx, exchange, message.Method, message.Params)
		}
		return false, state.handleServerRequest(ctx, exchange, message)
	}
	if state.closeSent {
		if !message.isResponseID(zcodeProtocolCloseID) {
			return false, nil
		}
		if message.Error != nil {
			state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
			return true, zcodeProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed,
				fmt.Errorf("session close failed: %s", message.Error.Message))
		}
		state.closeAccepted = true
		return true, nil
	}
	if state.accountPending && message.isResponseID(zcodeProtocolAccountID) {
		state.accountPending = false
		if message.Error != nil {
			state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
			return true, zcodeProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("account configuration failed: %s", message.Error.Message))
		}
		var result struct {
			ReceivedRevision string `json:"receivedRevision"`
			ProviderCount    int    `json:"providerCount"`
		}
		if json.Unmarshal(message.Result, &result) != nil || result.ReceivedRevision != state.account.revision || result.ProviderCount != 1 {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("account configuration result is invalid"))
		}
		return false, state.sendCreate(ctx, exchange)
	}
	if state.isModelSelectionResponse(message) {
		state.modelRequestPending = false
		if message.Error != nil {
			if message.Error.modelSelectionUnavailable() {
				state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
				return true, zcodeModelSelectionFailure()
			}
			state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
			return true, zcodeProtocolFailure(message.Error.modelSelectionFailureCause(),
				fmt.Errorf("session model selection failed: %s", message.Error.Message))
		}
		if err := state.acceptModelSelection(message.Result); err != nil {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		state.modelAccepted = true
		if state.reasoningEffort != "" {
			return false, state.sendThoughtLevel(ctx, exchange)
		}
		return false, state.sendPrompt(ctx, exchange)
	}
	if state.thoughtRequestPending && message.isResponseID(zcodeProtocolSetThoughtID) {
		state.thoughtRequestPending = false
		if message.Error != nil {
			state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
			return true, zcodeModelSelectionFailure()
		}
		if err := state.acceptThoughtLevel(message.Result); err != nil {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		state.thoughtAccepted = true
		return false, state.sendPrompt(ctx, exchange)
	}
	if message.Error != nil && message.correlatesTo(zcodeProtocolCreateID, zcodeProtocolSendID, zcodeProtocolMessagesID, zcodeProtocolCloseID) {
		state.providerErrorCode, state.hasProviderErrorCode = message.Error.Code, true
		return true, zcodeProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed,
			fmt.Errorf("request %s failed: %s", string(message.ID), message.Error.Message))
	}
	if message.Error != nil {
		// Error responses outside this conversation's own requests are inert
		// protocol facts, exactly like uncorrelated success responses.
		return false, nil
	}
	switch {
	case message.isResponseID(zcodeProtocolCreateID):
		if err := state.acceptCreate(message.Result); err != nil {
			if errors.Is(err, errZCodeSelectedModelUnavailable) {
				return true, zcodeModelSelectionFailure()
			}
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		if state.modelSelection != nil {
			return false, state.sendModelSelection(ctx, exchange)
		}
		if state.reasoningEffort != "" {
			return false, state.sendThoughtLevel(ctx, exchange)
		}
		return false, state.sendPrompt(ctx, exchange)
	case message.isResponseID(zcodeProtocolSendID):
		if err := state.acceptSend(message.Result); err != nil {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		state.phase = ports.ProviderSessionPhaseTurn
		return false, nil
	case message.isResponseID(zcodeProtocolMessagesID):
		if err := state.acceptMessages(message.Result); err != nil {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, err)
		}
		state.messagesReceived = true
		return false, state.sendClose(ctx, exchange)
	default:
		// Uncorrelated responses are inert protocol facts; the turn's own
		// terminal notification decides the conversation.
		return false, nil
	}
}

func zcodeModelSelectionFailure() error {
	failure, err := domain.NewFailure("zcode_model_selection", domain.FailureConfiguration, "selected ZCode model is unavailable", errZCodeSelectedModelUnavailable)
	if err != nil {
		return zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	return failure
}

func (state *zcodeProtocolConversation) isModelSelectionResponse(message zcodeProtocolMessage) bool {
	return state.modelSelection != nil && state.modelRequestPending && !state.modelAccepted && message.isResponseID(zcodeProtocolSetModelID)
}

func (state *zcodeProtocolConversation) sendModelSelection(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if state.modelSelection == nil || state.sessionID == "" {
		return zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid, errors.New("invalid model selection state"))
	}
	selection := map[string]any{
		"providerId": state.modelSelection.ProviderID, "modelId": state.modelSelection.ModelID,
		"options": map[string]string{"reasoningLevel": state.modelDefaultReasoning},
	}
	state.phase = ports.ProviderSessionPhaseModel
	if err := sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolSetModelID, zcodeProtocolSetModelMethod, map[string]any{
		"sessionId":                  state.sessionID,
		"model":                      selection,
		"persistAsWorkspaceLastUsed": false,
	}); err != nil {
		return err
	}
	state.modelRequestPending = true
	return nil
}

func (state *zcodeProtocolConversation) acceptModelSelection(result json.RawMessage) error {
	if len(result) == 0 || bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
		return errors.New("session model selection result is missing")
	}
	type wireSelection struct {
		ProviderID string `json:"providerId"`
		ModelID    string `json:"modelId"`
		Options    struct {
			ReasoningLevel string `json:"reasoningLevel"`
		} `json:"options"`
	}
	var payload struct {
		Protocol struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"protocol"`
		Session struct {
			SessionID string `json:"sessionId"`
			Model     struct {
				ProviderID string `json:"providerId"`
				ModelID    string `json:"modelId"`
			} `json:"model"`
		} `json:"session"`
		Settings struct {
			Model struct {
				Current wireSelection `json:"current"`
			} `json:"model"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session model selection result: %w", err)
	}
	if payload.Protocol.Name != "ZCode Protocol" || payload.Protocol.Version != 1 || payload.Session.SessionID != state.sessionID {
		return errors.New("session model selection result has mismatched protocol or session identity")
	}
	want := wireSelection{ProviderID: state.modelSelection.ProviderID, ModelID: state.modelSelection.ModelID}
	if payload.Settings.Model.Current.ProviderID != want.ProviderID || payload.Settings.Model.Current.ModelID != want.ModelID {
		return errors.New("session model selection result has mismatched model identity")
	}
	if payload.Settings.Model.Current.Options.ReasoningLevel != state.modelDefaultReasoning {
		return errors.New("session model selection result has mismatched default reasoning level")
	}
	if payload.Session.Model.ProviderID != want.ProviderID || payload.Session.Model.ModelID != want.ModelID {
		return errors.New("session model selection result has mismatched session model identity")
	}
	return nil
}

func (state *zcodeProtocolConversation) sendThoughtLevel(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if state.sessionID == "" || state.reasoningEffort == "" {
		return zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid, errors.New("invalid thought level state"))
	}
	state.phase = ports.ProviderSessionPhaseModel
	if err := sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolSetThoughtID, zcodeProtocolSetThoughtMethod, map[string]any{
		"sessionId": state.sessionID, "thoughtLevel": state.reasoningEffort, "persistAsWorkspaceLastUsed": false,
	}); err != nil {
		return err
	}
	state.thoughtRequestPending = true
	return nil
}

func (state *zcodeProtocolConversation) acceptThoughtLevel(result json.RawMessage) error {
	if len(result) == 0 || bytes.Equal(bytes.TrimSpace(result), []byte("null")) {
		return errors.New("session thought level result is missing")
	}
	var payload struct {
		Protocol struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"protocol"`
		Session struct {
			SessionID string              `json:"sessionId"`
			Model     zcodeModelSelection `json:"model"`
		} `json:"session"`
		Settings struct {
			Model struct {
				Current struct {
					ProviderID string `json:"providerId"`
					ModelID    string `json:"modelId"`
					Options    struct {
						ReasoningLevel string `json:"reasoningLevel"`
					} `json:"options"`
				} `json:"current"`
			} `json:"model"`
		} `json:"settings"`
	}
	if json.Unmarshal(result, &payload) != nil || payload.Protocol.Name != "ZCode Protocol" || payload.Protocol.Version != 1 || payload.Session.SessionID != state.sessionID || payload.Settings.Model.Current.Options.ReasoningLevel != state.reasoningEffort {
		return errors.New("session thought level result has mismatched identity")
	}
	if state.modelSelection != nil && (payload.Session.Model != *state.modelSelection || payload.Settings.Model.Current.ProviderID != state.modelSelection.ProviderID || payload.Settings.Model.Current.ModelID != state.modelSelection.ModelID) {
		return errors.New("session thought level result has mismatched model identity")
	}
	return nil
}

func (state *zcodeProtocolConversation) sendPrompt(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	state.phase = ports.ProviderSessionPhaseSend
	return sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolSendID, zcodeProtocolSendMethod, map[string]any{
		"sessionId": state.sessionID,
		"content":   state.prompt,
	})
}

func (state *zcodeProtocolConversation) sendClose(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	state.closeSent = true
	state.phase = ports.ProviderSessionPhaseClose
	return sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolCloseID, zcodeProtocolCloseMethod, map[string]any{
		"sessionId": state.sessionID,
	})
}

func (state *zcodeProtocolConversation) handleNotification(ctx context.Context, exchange ports.ProviderSessionExchange, method string, params json.RawMessage) (bool, error) {
	if method != "computer-use/operation-event" {
		return false, nil
	}
	var event struct {
		Kind      string `json:"kind"`
		TurnID    string `json:"turnId"`
		SessionID string `json:"sessionId"`
	}
	if len(params) > 0 && json.Unmarshal(params, &event) != nil {
		return true, zcodeProtocolFailure(domain.DiagnosticCauseProtocolEventDecodeFailed,
			errors.New("unreadable protocol event payload"))
	}
	switch event.Kind {
	case zcodeProtocolTurnCompletedKind:
		if !state.createAccepted || !state.sendAccepted || state.sessionID == "" {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid,
				errors.New("turn completed before the conversation was established"))
		}
		if event.SessionID != "" && event.SessionID != state.sessionID {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid,
				errors.New("turn session id does not match the established conversation"))
		}
		if !state.turnObserved {
			state.turnID = event.TurnID
		}
		state.turnObserved = true
		state.turnCompleted = true
		if state.captureAssistantText && !state.messagesReceived {
			state.messagesRequested = true
			state.phase = ports.ProviderSessionPhaseMessages
			return false, sendZcodeProtocolRequest(ctx, exchange, zcodeProtocolMessagesID, zcodeProtocolMessagesMethod, map[string]any{
				"sessionId": state.sessionID,
				"limit":     zcodeProtocolMessageLimit,
			})
		}
		return false, state.sendClose(ctx, exchange)
	case zcodeProtocolTurnFailedKind:
		if !state.createAccepted || !state.sendAccepted || state.sessionID == "" {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid,
				errors.New("turn failed before the conversation was established"))
		}
		if event.SessionID != "" && event.SessionID != state.sessionID {
			return true, zcodeProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid,
				errors.New("failed turn session id does not match the established conversation"))
		}
		if !state.turnObserved {
			state.turnID = event.TurnID
		}
		state.turnObserved = true
		return true, zcodeProtocolFailure(domain.DiagnosticCauseProviderTurnFailed,
			fmt.Errorf("provider turn %s failed", event.TurnID))
	default:
		return false, nil
	}
}

// handleServerRequest answers the runtime-preferences request the server
// blocks session materialization on. Every other server-initiated request is
// deliberately left unanswered: the pinned wire behavior shows non-essential
// interaction requests such as official MCP auth-header requests time out
// harmlessly, while a turn that never completes fails closed through the
// conversation's own terminal classification.
func (state *zcodeProtocolConversation) handleServerRequest(ctx context.Context, exchange ports.ProviderSessionExchange, message zcodeProtocolMessage) error {
	switch message.Method {
	case zcodeProtocolRequestRuntimePreferencesMethod:
		return sendZcodeProtocolResponse(ctx, exchange, message.ID, map[string]any{
			"nativeSearchEnhancementsEnabled": false, "memoryEnabled": false, "askUserQuestionAutoResolutionEnabled": true,
		})
	case zcodeProtocolRequestProviderRuntimeHeadersMethod:
		if state.account == nil {
			return sendZcodeProtocolResponse(ctx, exchange, message.ID, map[string]any{"headersApplied": false, "errorMessage": "ZCode account runtime is unavailable"})
		}
		var params struct {
			ProviderID    string                                   `json:"providerId"`
			AccountAccess struct{ Type, Mode, AccountType string } `json:"accountAccess"`
		}
		if json.Unmarshal(message.Params, &params) != nil || params.ProviderID != state.account.providerID || params.AccountAccess.Type != "zhipu-account" || params.AccountAccess.Mode != "individual-coding-plan" || params.AccountAccess.AccountType != "zai" {
			return sendZcodeProtocolResponse(ctx, exchange, message.ID, map[string]any{"headersApplied": false, "errorMessage": "ZCode account request identity is invalid"})
		}
		apiKey, err := state.account.apiKey(params.ProviderID)
		if err != nil {
			return sendZcodeProtocolResponse(ctx, exchange, message.ID, map[string]any{"headersApplied": false, "errorMessage": "ZCode account credential is unavailable"})
		}
		return sendZcodeProtocolResponse(ctx, exchange, message.ID, map[string]any{"headersApplied": true, "requestAuth": map[string]string{"apiKey": apiKey}})
	default:
		return nil
	}
}

func (state *zcodeProtocolConversation) acceptCreate(result json.RawMessage) error {
	if state.createAccepted {
		return errors.New("duplicate session create response")
	}
	var payload struct {
		Session struct {
			SessionID string `json:"sessionId"`
		} `json:"session"`
		Settings struct {
			Model struct {
				Available []struct {
					Ref       zcodeModelSelection `json:"ref"`
					Reasoning struct {
						DefaultLevel string `json:"defaultLevel"`
					} `json:"reasoning"`
				} `json:"available"`
			} `json:"model"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session create result: %w", err)
	}
	if payload.Session.SessionID == "" {
		return errors.New("session create result without a session id")
	}
	state.sessionID = payload.Session.SessionID
	state.createAccepted = true
	if state.modelSelection != nil {
		for _, available := range payload.Settings.Model.Available {
			if available.Ref.ProviderID != state.modelSelection.ProviderID || available.Ref.ModelID != state.modelSelection.ModelID {
				continue
			}
			if state.modelDefaultReasoning != "" || !validZCodeSettings("", available.Reasoning.DefaultLevel) || available.Reasoning.DefaultLevel == "" {
				return errZCodeSelectedModelUnavailable
			}
			state.modelDefaultReasoning = available.Reasoning.DefaultLevel
		}
		if state.modelDefaultReasoning == "" {
			return errZCodeSelectedModelUnavailable
		}
	}
	return nil
}

func (state *zcodeProtocolConversation) acceptSend(result json.RawMessage) error {
	if state.sendAccepted {
		return errors.New("duplicate session send response")
	}
	if !state.createAccepted || state.sessionID == "" {
		return errors.New("session send response before the conversation was established")
	}
	var payload struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session send result: %w", err)
	}
	if !payload.Accepted {
		return errors.New("session send was not accepted")
	}
	state.sendAccepted = true
	return nil
}

// acceptMessages collects the assistant text parts of the completed turn. The
// controlled qualification evidence travels in these parts; message metadata
// is deliberately ignored.
func (state *zcodeProtocolConversation) acceptMessages(result json.RawMessage) error {
	if !state.messagesRequested || state.messagesReceived {
		return errors.New("unexpected session messages response")
	}
	var payload struct {
		Messages []struct {
			Info struct {
				Role string `json:"role"`
			} `json:"info"`
			Parts []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		return fmt.Errorf("unreadable session messages result: %w", err)
	}
	for _, message := range payload.Messages {
		if message.Info.Role != "assistant" {
			continue
		}
		for _, part := range message.Parts {
			if part.Type == "text" && part.Text != "" {
				state.assistantEvidence = append(state.assistantEvidence, part.Text)
			}
		}
	}
	return nil
}

// zcodeProtocolMessage is one decoded wire message. A request has method and
// id, a notification has method without id, and a response has id with either
// result or error.
type zcodeProtocolMessage struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  *zcodeProtocolWireError
}

type zcodeProtocolWireError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (failure *zcodeProtocolWireError) detailCode() string {
	if failure == nil || len(failure.Data) == 0 {
		return ""
	}
	var detail struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(failure.Data, &detail) != nil {
		return ""
	}
	return detail.Code
}

func (failure *zcodeProtocolWireError) retryableModelReasoningRejection() bool {
	return failure != nil && failure.detailCode() == "invalid_model_request" &&
		(strings.HasPrefix(failure.Message, "Reasoning effort ") || strings.HasPrefix(failure.Message, "Reasoning level "))
}

func (failure *zcodeProtocolWireError) modelSelectionUnavailable() bool {
	if failure == nil {
		return false
	}
	switch failure.detailCode() {
	case "invalid_model_selection", "model_config_missing", "provider_not_found", "provider_not_configured", "model_not_found":
		return true
	default:
		return false
	}
}

func (failure *zcodeProtocolWireError) modelSelectionFailureCause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return domain.DiagnosticCauseProviderExecutionFailed
	}
	switch failure.detailCode() {
	case "model_request_auth_missing":
		return domain.DiagnosticCauseAuthenticationFailed
	case "model_rate_limited":
		return domain.DiagnosticCauseRateLimited
	case "model_request_timeout":
		return domain.DiagnosticCauseTimedOut
	default:
		return domain.DiagnosticCauseProviderExecutionFailed
	}
}

func (message zcodeProtocolMessage) isResponseID(id string) bool {
	if len(message.ID) == 0 || message.Method != "" {
		return false
	}
	var decoded string
	return json.Unmarshal(message.ID, &decoded) == nil && decoded == id
}

// correlatesTo reports whether the message is a response to one of this
// conversation's own requests.
func (message zcodeProtocolMessage) correlatesTo(ids ...string) bool {
	for _, id := range ids {
		if message.isResponseID(id) {
			return true
		}
	}
	return false
}

func parseZcodeProtocolMessage(line []byte) (zcodeProtocolMessage, error) {
	var decoded struct {
		ID     json.RawMessage         `json:"id"`
		Method string                  `json:"method"`
		Params json.RawMessage         `json:"params"`
		Result json.RawMessage         `json:"result"`
		Error  *zcodeProtocolWireError `json:"error"`
	}
	if err := json.NewDecoder(bytes.NewReader(line)).Decode(&decoded); err != nil {
		return zcodeProtocolMessage{}, fmt.Errorf("zcode protocol: decode message: %w", err)
	}
	if len(decoded.ID) == 0 && decoded.Method == "" {
		return zcodeProtocolMessage{}, errors.New("zcode protocol: message without id or method")
	}
	return zcodeProtocolMessage{
		ID:     decoded.ID,
		Method: decoded.Method,
		Params: decoded.Params,
		Result: decoded.Result,
		Error:  decoded.Error,
	}, nil
}

func sendZcodeProtocolRequest(ctx context.Context, exchange ports.ProviderSessionExchange, id, method string, params map[string]any) error {
	payload, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid,
			fmt.Errorf("zcode protocol: encode %s request: %w", method, err))
	}
	if err := exchange.SendLine(ctx, payload); err != nil {
		return zcodeProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed,
			fmt.Errorf("zcode protocol: send %s request: %w", method, err))
	}
	return nil
}

func sendZcodeProtocolResponse(ctx context.Context, exchange ports.ProviderSessionExchange, id json.RawMessage, result map[string]any) error {
	payload, err := json.Marshal(map[string]any{"id": json.RawMessage(id), "result": result})
	if err != nil {
		return zcodeProtocolFailure(domain.DiagnosticCauseObservationInvalid,
			fmt.Errorf("zcode protocol: encode response: %w", err))
	}
	if err := exchange.SendLine(ctx, payload); err != nil {
		return zcodeProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed,
			fmt.Errorf("zcode protocol: send response: %w", err))
	}
	return nil
}
