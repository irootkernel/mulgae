package providercli

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
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
