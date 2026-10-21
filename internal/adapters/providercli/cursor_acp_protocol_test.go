package providercli

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

type cursorScriptExchange struct {
	inbox     [][]byte
	sent      [][]byte
	sentAfter []int
	at        int
}

func (exchange *cursorScriptExchange) ReceiveLine(context.Context) ([]byte, error) {
	if exchange.at >= len(exchange.inbox) {
		return nil, io.EOF
	}
	line := exchange.inbox[exchange.at]
	exchange.at++
	return line, nil
}

func (exchange *cursorScriptExchange) SendLine(_ context.Context, line []byte) error {
	exchange.sent = append(exchange.sent, append([]byte(nil), line...))
	exchange.sentAfter = append(exchange.sentAfter, exchange.at)
	return nil
}

func (exchange *cursorScriptExchange) CloseInput(context.Context) error {
	return nil
}

func cursorFrame(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}

func TestCursorQualificationRejectsToolCallBeforePromptCompletion(t *testing.T) {
	session, err := newCursorACPProtocolSession("/neutral", []byte("root=a\nlink=b\nrole=logic\n"), protocolPurposeQualification, nil)
	if err != nil {
		t.Fatal(err)
	}
	exchange := &cursorScriptExchange{inbox: [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "read", "rawInput": map[string]any{"path": "/repo/roadmap.md"}, "status": "pending"}}}),
	}}
	if err := session.Drive(context.Background(), exchange); err == nil {
		t.Fatal("qualification tool call was accepted")
	}
	promptAt := -1
	for index, line := range exchange.sent {
		if strings.Contains(string(line), "session/prompt") {
			promptAt = index
		}
		if strings.Contains(string(line), "session/prompt") && !strings.Contains(strings.Join(stringify(exchange.sent[:index]), "\n"), "currentModeId") && !strings.Contains(string(exchange.inbox[2]), "ask") {
			t.Fatal("prompt was not gated by the scripted ask acknowledgement")
		}
	}
	if promptAt < 0 {
		t.Fatal("prompt was not sent after ask acknowledgement")
	}
}

func stringify(lines [][]byte) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = string(line)
	}
	return out
}

func TestCursorPermissionCorrelatesExecuteCommandFromToolCall(t *testing.T) {
	const (
		planned    = "git --no-pager show ':target.txt'"
		toolCallID = "tool-call-9"
		requestID  = "permission-9"
		allowOnce  = "allow-once-9"
	)
	session, err := newCursorACPProtocolSession("/neutral", []byte("review the planned git object"), protocolPurposeLiveReview, &cursorLiveReadAuthority{
		gitCommands: map[string]bool{planned: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := &cursorScriptExchange{inbox: [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{
			"sessionUpdate": "tool_call", "toolCallId": toolCallID, "kind": "execute", "status": "pending",
			"rawInput": map[string]any{"command": planned},
		}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": requestID, "method": "session/request_permission", "params": map[string]any{
			"sessionId": "session-1",
			"toolCall":  map[string]any{"toolCallId": toolCallID, "kind": "execute"},
			"options": []map[string]string{
				{"optionId": "allow-always-9", "kind": "allow_always"},
				{"optionId": allowOnce, "kind": "allow_once"},
			},
		}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{
			"sessionUpdate": "tool_call_update", "toolCallId": toolCallID, "kind": "execute", "status": "completed",
		}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "selected side"}}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "end_turn"}}),
	}}
	if err := session.Drive(context.Background(), exchange); err != nil {
		t.Fatal(err)
	}
	var matched bool
	for _, line := range exchange.sent {
		var message struct {
			ID     string `json:"id"`
			Result struct {
				Outcome struct {
					Outcome  string `json:"outcome"`
					OptionID string `json:"optionId"`
				} `json:"outcome"`
			} `json:"result"`
		}
		if json.Unmarshal(line, &message) != nil || message.ID != requestID {
			continue
		}
		matched = true
		if message.ID == toolCallID || message.Result.Outcome.Outcome != "selected" || message.Result.Outcome.OptionID != allowOnce {
			t.Fatalf("permission response = %s", line)
		}
	}
	if !matched {
		t.Fatal("permission response id did not stay the request id")
	}
}

func TestCursorFailedExecuteIsNotASelectedRead(t *testing.T) {
	const planned = "git --no-pager show ':target.txt'"
	session, err := newCursorACPProtocolSession("/neutral", []byte("review the planned git object"), protocolPurposeLiveReview, &cursorLiveReadAuthority{
		gitCommands: map[string]bool{planned: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := &cursorScriptExchange{inbox: [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{
			"sessionUpdate": "tool_call", "toolCallId": "tool-failed", "kind": "execute", "status": "failed",
			"rawInput": map[string]any{"command": planned},
		}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "selected side"}}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "end_turn"}}),
	}}
	err = session.Drive(context.Background(), exchange)
	if err == nil || !strings.Contains(err.Error(), "not a selected read") {
		t.Fatalf("failed execute was counted as a read: %v", err)
	}
	if string(session.AssistantEvidenceText()) != "" {
		t.Fatal("failed execute still produced assistant evidence")
	}
}

// TestCursorSessionObservationAdmitsUnsafeDiagnosticIdentifiers proves an
// unsafe diagnostic session identifier never invalidates an otherwise valid
// observation: the identifier is emptied while native correlation keeps the
// raw value, across completed and failed turns.
func TestCursorSessionObservationAdmitsUnsafeDiagnosticIdentifiers(t *testing.T) {
	unsafeIDs := map[string]string{
		"oversized":  strings.Repeat("s", 513),
		"whitespace": " session-1 ",
		"control":    "session-\u0001-1",
	}
	safeID := "session-1"
	for name, unsafeID := range unsafeIDs {
		for _, outcome := range []string{"completed", "failed"} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				session, err := newCursorACPProtocolSession("/neutral", []byte("review the target"), protocolPurposeQualification, nil)
				if err != nil {
					t.Fatal(err)
				}
				inbox := [][]byte{
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": unsafeID}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": unsafeID, "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
				}
				if outcome == "completed" {
					inbox = append(inbox,
						cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": unsafeID, "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "done"}}}}),
						cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "end_turn"}}),
					)
				}
				exchange := &cursorScriptExchange{inbox: inbox}
				driveErr := session.Drive(context.Background(), exchange)
				if outcome == "completed" && driveErr != nil {
					t.Fatalf("completed turn drive error = %v", driveErr)
				}
				if outcome == "failed" && driveErr == nil {
					t.Fatal("failed turn unexpectedly succeeded")
				}
				observation, present := session.SessionObservation()
				if !present || !observation.Valid() {
					t.Fatalf("session observation = (%#v, %t), want a present valid observation despite the unsafe identifier", observation, present)
				}
				if observation.ProviderSessionID() != "" {
					t.Fatalf("diagnostic session id = %q, want the emptied admission value", observation.ProviderSessionID())
				}
				createAccepted, sendAccepted, _, _, _, _ := observation.Receipts()
				if !createAccepted || !sendAccepted {
					t.Fatalf("observation protocol facts = %#v, want create and send accepted", observation)
				}
				if outcome == "completed" {
					_, _, turnObserved, _, _, _ := observation.Receipts()
					if observation.Terminal() != ports.ProviderSessionCompleted || !turnObserved {
						t.Fatalf("completed observation = %#v", observation)
					}
				} else {
					_, _, _, _, closeSent, _ := observation.Receipts()
					if observation.Terminal() != ports.ProviderSessionFailed || !closeSent {
						t.Fatalf("failed observation = %#v, want terminal failed with close sent", observation)
					}
					var cancelledWithRawID bool
					for _, line := range exchange.sent {
						var message struct {
							Method string          `json:"method"`
							Params json.RawMessage `json:"params"`
						}
						if json.Unmarshal(line, &message) != nil || message.Method != "session/cancel" {
							continue
						}
						var params struct {
							SessionID string `json:"sessionId"`
						}
						if json.Unmarshal(message.Params, &params) == nil && params.SessionID == unsafeID {
							cancelledWithRawID = true
						}
					}
					if !cancelledWithRawID {
						t.Fatalf("session/cancel did not carry the raw unsafe identifier: sent = %q", exchange.sent)
					}
				}
			})
		}
	}

	t.Run("valid identifier passes through", func(t *testing.T) {
		for _, outcome := range []string{"completed", "failed"} {
			t.Run(outcome, func(t *testing.T) {
				session, err := newCursorACPProtocolSession("/neutral", []byte("review the target"), protocolPurposeQualification, nil)
				if err != nil {
					t.Fatal(err)
				}
				inbox := [][]byte{
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": safeID}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": safeID, "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
					cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
				}
				if outcome == "completed" {
					inbox = append(inbox,
						cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": safeID, "update": map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": "done"}}}}),
						cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "end_turn"}}),
					)
				}
				exchange := &cursorScriptExchange{inbox: inbox}
				driveErr := session.Drive(context.Background(), exchange)
				if (outcome == "completed") != (driveErr == nil) {
					t.Fatalf("drive error = %v for outcome %q", driveErr, outcome)
				}
				observation, present := session.SessionObservation()
				if !present || !observation.Valid() || observation.ProviderSessionID() != safeID {
					t.Fatalf("session observation = (%#v, %t), want the valid identifier retained", observation, present)
				}
			})
		}
	})
}

// TestSanitizeCursorDiagnosticSessionIDGrammar pins the sanitizer grammar
// directly, including raw invalid UTF-8 that the JSON driver cannot deliver,
// and proves every helper output satisfies the shared observation admission.
func TestSanitizeCursorDiagnosticSessionIDGrammar(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty stays empty", value: "", want: ""},
		{name: "raw invalid UTF-8 run", value: "\xff\xfe", want: ""},
		{name: "raw invalid UTF-8 embedded", value: "a\xffb", want: ""},
		{name: "512 bytes pass", value: strings.Repeat("s", 512), want: strings.Repeat("s", 512)},
		{name: "513 bytes emptied", value: strings.Repeat("s", 513), want: ""},
		{name: "surrounding whitespace emptied", value: " session-1 ", want: ""},
		{name: "control character emptied", value: "session-\u0001-1", want: ""},
		{name: "trimmed valid identifier passes", value: "session-1", want: "session-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sanitizeCursorDiagnosticSessionID(test.value); got != test.want {
				t.Fatalf("sanitizeCursorDiagnosticSessionID(%q) = %q, want %q", test.value, got, test.want)
			}
			observation, err := ports.NewProviderSessionObservation(ports.ProviderSessionObservationInput{
				Phase: ports.ProviderSessionPhaseCreate, Terminal: ports.ProviderSessionCompleted,
				ProviderSessionID: sanitizeCursorDiagnosticSessionID(test.value),
			})
			if err != nil || !observation.Valid() {
				t.Fatalf("helper output rejected by shared admission: %v", err)
			}
		})
	}
}
