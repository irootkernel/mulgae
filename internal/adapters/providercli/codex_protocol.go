package providercli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Each invocation owns one ephemeral Codex thread and one turn. The process
// runner owns the server lifetime; no thread or provider process is reused.
type codexProtocolSession struct {
	workspacePath string
	prompt        string
	purpose       protocolInvocationPurpose
	observation   ports.ProviderSessionObservation
	evidence      []byte
}

type codexProtocolError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (failure *codexProtocolError) Error() string { return "codex app-server: " + failure.err.Error() }
func (failure *codexProtocolError) Unwrap() error { return failure.err }
func (failure *codexProtocolError) Cause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.cause
}
func (failure *codexProtocolError) ProtocolFailureCause() domain.RuntimeDiagnosticCause {
	return failure.Cause()
}

func codexProtocolFailure(cause domain.RuntimeDiagnosticCause, err error) error {
	return &codexProtocolError{cause: cause, err: err}
}

func newCodexProtocolSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority) (providerProtocolSession, error) {
	// The registry passes its typed staging pointer through an interface even
	// for stdout routes. A nil pointer grants no write authority.
	authority := reflect.ValueOf(writeAuthority)
	hasWriteAuthority := writeAuthority != nil && (authority.Kind() != reflect.Pointer || !authority.IsNil())
	if !validCanonicalAbsolute(workspacePath) || len(prompt) == 0 || hasWriteAuthority {
		return nil, fmt.Errorf("codex app-server: invalid session request")
	}
	switch purpose {
	case protocolPurposeReview, protocolPurposeExtraction, protocolPurposeQualification, protocolPurposeLiveReview, protocolPurposeLiveExtraction:
	default:
		return nil, fmt.Errorf("codex app-server: unsupported purpose")
	}
	return &codexProtocolSession{workspacePath: workspacePath, prompt: string(prompt), purpose: purpose}, nil
}

func (session *codexProtocolSession) AssistantEvidenceText() []byte {
	return append([]byte(nil), session.evidence...)
}

func (session *codexProtocolSession) SessionObservation() (ports.ProviderSessionObservation, bool) {
	if session == nil || !session.observation.Valid() {
		return ports.ProviderSessionObservation{}, false
	}
	return session.observation, true
}

type codexWireMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func sendCodexRequest(ctx context.Context, exchange ports.ProviderSessionExchange, id int, method string, params any) error {
	frame, err := json.Marshal(struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params"`
	}{id, method, params})
	if err != nil {
		return codexProtocolFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	if err := exchange.SendLine(ctx, frame); err != nil {
		return codexProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, err)
	}
	return nil
}

func (session *codexProtocolSession) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) (driveErr error) {
	if session == nil || exchange == nil {
		return codexProtocolFailure(domain.DiagnosticCauseObservationInvalid, errors.New("invalid conversation"))
	}
	state := codexConversation{phase: ports.ProviderSessionPhaseCreate}
	defer func() {
		terminal := ports.ProviderSessionCompleted
		if driveErr != nil {
			terminal = ports.ProviderSessionFailed
		}
		input := ports.ProviderSessionObservationInput{
			Phase: state.phase, Terminal: terminal,
			ProviderSessionID: safeZcodeDiagnosticIdentifier(state.threadID),
			ProviderTurnID:    safeZcodeDiagnosticIdentifier(state.turnID),
			CreateAccepted:    state.threadStarted, SendAccepted: state.turnStarted,
			TurnObserved: state.turnCompleted, MessagesReceived: state.turnCompleted && state.messageReceived,
			ProviderErrorCode: state.errorCode, HasProviderErrorCode: state.hasErrorCode,
		}
		observation, err := ports.NewProviderSessionObservation(input)
		session.observation = observation
		if err != nil {
			driveErr = errors.Join(driveErr, codexProtocolFailure(domain.DiagnosticCauseObservationInvalid, err))
		}
	}()
	if err := sendCodexRequest(ctx, exchange, 1, "initialize", map[string]any{
		"clientInfo": map[string]string{"name": "mulgae", "title": "Mulgae", "version": "0.1.0"},
	}); err != nil {
		return err
	}
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			cause := domain.DiagnosticCauseProviderExecutionFailed
			if state.turnStarted {
				cause = domain.DiagnosticCauseProviderTurnFailed
			}
			return codexProtocolFailure(cause, fmt.Errorf("conversation ended before turn completion: %w", err))
		}
		if len(bytes.TrimSpace(line)) == 0 || !bytes.HasPrefix(bytes.TrimSpace(line), []byte{'{'}) {
			return codexProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("invalid protocol frame"))
		}
		var message codexWireMessage
		if err := json.Unmarshal(line, &message); err != nil {
			return codexProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
		}
		if len(message.ID) != 0 && message.Method != "" {
			return codexProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, errors.New("unexpected server request"))
		}
		if len(message.ID) != 0 {
			if err := state.handleResponse(ctx, exchange, session, message); err != nil {
				return err
			}
			continue
		}
		if message.Method == "" {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("protocol frame without method or id"))
		}
		done, err := state.handleNotification(message)
		if err != nil {
			return err
		}
		if done {
			session.evidence = []byte(state.finalText)
			return nil
		}
	}
}

type codexConversation struct {
	phase           ports.ProviderSessionPhase
	threadID        string
	turnID          string
	threadStarted   bool
	initialized     bool
	turnStarted     bool
	turnCompleted   bool
	messageReceived bool
	finalPhaseSeen  bool
	finalText       string
	errorCode       int
	hasErrorCode    bool
}

func (state *codexConversation) handleResponse(ctx context.Context, exchange ports.ProviderSessionExchange, session *codexProtocolSession, message codexWireMessage) error {
	var id int
	if err := json.Unmarshal(message.ID, &id); err != nil || id < 1 || id > 3 {
		return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unknown response id"))
	}
	if message.Error != nil {
		state.errorCode, state.hasErrorCode = message.Error.Code, true
		return codexProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, fmt.Errorf("request %d failed: %s", id, message.Error.Message))
	}
	if len(message.Result) == 0 {
		return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("response without result"))
	}
	switch id {
	case 1:
		if state.initialized || state.phase != ports.ProviderSessionPhaseCreate {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected initialize response"))
		}
		state.initialized = true
		initialized, _ := json.Marshal(map[string]any{"method": "initialized", "params": map[string]any{}})
		if err := exchange.SendLine(ctx, initialized); err != nil {
			return codexProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, err)
		}
		return sendCodexRequest(ctx, exchange, 2, "thread/start", map[string]any{
			"cwd": session.workspacePath, "approvalPolicy": "never", "ephemeral": true,
		})
	case 2:
		if !state.initialized || state.threadStarted || state.phase != ports.ProviderSessionPhaseCreate {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected thread response"))
		}
		var result struct {
			Thread struct {
				ID        string `json:"id"`
				Ephemeral bool   `json:"ephemeral"`
			} `json:"thread"`
			InstructionSources []string `json:"instructionSources"`
		}
		if json.Unmarshal(message.Result, &result) != nil || safeZcodeDiagnosticIdentifier(result.Thread.ID) == "" || !result.Thread.Ephemeral || len(result.InstructionSources) != 0 {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("thread isolation receipt invalid"))
		}
		state.threadID, state.threadStarted = result.Thread.ID, true
		state.phase = ports.ProviderSessionPhaseSend
		params := map[string]any{"threadId": state.threadID, "input": []any{map[string]string{"type": "text", "text": session.prompt}}}
		if session.purpose == protocolPurposeQualification {
			var schema any
			if err := json.Unmarshal([]byte(probeFixtureOutputSchema), &schema); err != nil {
				return codexProtocolFailure(domain.DiagnosticCauseObservationInvalid, err)
			}
			params["outputSchema"] = schema
		}
		return sendCodexRequest(ctx, exchange, 3, "turn/start", params)
	case 3:
		if !state.threadStarted || state.turnStarted || state.phase != ports.ProviderSessionPhaseSend {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected turn response"))
		}
		var result struct {
			Turn struct {
				ID string `json:"id"`
			} `json:"turn"`
		}
		if json.Unmarshal(message.Result, &result) != nil || safeZcodeDiagnosticIdentifier(result.Turn.ID) == "" {
			return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("turn response without id"))
		}
		state.turnID, state.turnStarted = result.Turn.ID, true
		state.phase = ports.ProviderSessionPhaseTurn
		return nil
	}
	return codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unexpected response"))
}

func (state *codexConversation) handleNotification(message codexWireMessage) (bool, error) {
	switch message.Method {
	case "item/completed":
		var event struct {
			ThreadID string `json:"threadId"`
			TurnID   string `json:"turnId"`
			Item     struct {
				Type  string `json:"type"`
				Text  string `json:"text"`
				Phase string `json:"phase"`
			} `json:"item"`
		}
		if json.Unmarshal(message.Params, &event) != nil {
			return false, codexProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("invalid item event"))
		}
		if event.ThreadID != state.threadID || event.TurnID != state.turnID || !state.turnStarted {
			return false, codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("item correlation mismatch"))
		}
		if event.Item.Type == "agentMessage" && (event.Item.Phase == "final_answer" || event.Item.Phase == "") {
			if event.Item.Phase == "final_answer" || !state.finalPhaseSeen {
				state.finalText = event.Item.Text
				state.messageReceived = true
				state.finalPhaseSeen = event.Item.Phase == "final_answer"
			}
		}
	case "turn/completed":
		var event struct {
			ThreadID string `json:"threadId"`
			Turn     struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"turn"`
		}
		if json.Unmarshal(message.Params, &event) != nil {
			return false, codexProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("invalid turn event"))
		}
		if event.ThreadID != state.threadID || event.Turn.ID != state.turnID || !state.turnStarted || state.turnCompleted {
			return false, codexProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("turn correlation mismatch"))
		}
		if event.Turn.Status != "completed" {
			return false, codexProtocolFailure(domain.DiagnosticCauseProviderTurnFailed, fmt.Errorf("turn status %q", event.Turn.Status))
		}
		state.turnCompleted = true
		if !state.messageReceived || strings.TrimSpace(state.finalText) == "" {
			return false, codexProtocolFailure(domain.DiagnosticCauseOutputMissing, errors.New("final assistant message missing"))
		}
		return true, nil
	}
	return false, nil
}
