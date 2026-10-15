//go:build darwin && arm64

package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gittargetadapter "github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func cursorMatrixAuthority(commands ...string) *cursorLiveReadAuthority {
	allowed := make(map[string]bool, len(commands))
	for _, command := range commands {
		allowed[command] = true
	}
	return &cursorLiveReadAuthority{gitCommands: allowed}
}

func cursorMatrixSession(t *testing.T, authority *cursorLiveReadAuthority) *cursorACPProtocolSession {
	t.Helper()
	if authority == nil {
		authority = cursorMatrixAuthority()
	}
	session, err := newCursorACPProtocolSession("/neutral", []byte("review the planned source"), protocolPurposeLiveReview, authority)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func cursorMatrixDrive(session *cursorACPProtocolSession, frames ...[]byte) (*cursorScriptExchange, error) {
	exchange := &cursorScriptExchange{inbox: frames}
	return exchange, session.Drive(context.Background(), exchange)
}

func cursorMatrixPrefix(ask bool) [][]byte {
	frames := [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
	}
	if !ask {
		return frames
	}
	return append(frames,
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
	)
}

func cursorMatrixAppend(prefix [][]byte, frames ...[]byte) [][]byte {
	return append(append([][]byte{}, prefix...), frames...)
}

func cursorMatrixUpdate(update map[string]any) []byte {
	return cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": update}})
}

func cursorMatrixMessage(text string) []byte {
	return cursorMatrixUpdate(map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": text}})
}

func cursorMatrixEndTurn() []byte {
	return cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "end_turn"}})
}

func cursorMatrixPermission(requestID, toolCallID, kind string, rawInput map[string]any, options []map[string]string) []byte {
	tool := map[string]any{"toolCallId": toolCallID, "kind": kind}
	if rawInput != nil {
		tool["rawInput"] = rawInput
	}
	return cursorFrame(map[string]any{
		"jsonrpc": "2.0", "id": requestID, "method": "session/request_permission",
		"params": map[string]any{"sessionId": "session-1", "toolCall": tool, "options": options},
	})
}

func cursorMatrixReply(t *testing.T, sent [][]byte, requestID string) (string, string) {
	t.Helper()
	for _, line := range sent {
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
		return message.Result.Outcome.Outcome, message.Result.Outcome.OptionID
	}
	t.Fatalf("missing permission response %s", requestID)
	return "", ""
}

func cursorMatrixPromptSentAfter(t *testing.T, exchange *cursorScriptExchange) int {
	t.Helper()
	sentAt := -1
	for index, line := range exchange.sent {
		if strings.Contains(string(line), "session/prompt") {
			if sentAt >= 0 {
				t.Fatal("session/prompt was sent more than once")
			}
			sentAt = exchange.sentAfter[index]
		}
	}
	return sentAt
}

func TestCursorMatrixAskBeforePrompt(t *testing.T) {
	t.Run("empty-result-and-plan-do-not-prompt", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixPrefix(false)
		frames = append(frames,
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "plan"}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		askIndex := 4
		exchange, err := cursorMatrixDrive(session, frames...)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(session.AssistantEvidenceText()); got != "visible report" {
			t.Fatalf("assistant text = %q", got)
		}
		if sentAt := cursorMatrixPromptSentAfter(t, exchange); sentAt <= askIndex {
			t.Fatalf("prompt sent at inbox %d, ask frame is %d", sentAt, askIndex)
		}
	})

	t.Run("mode-id-echo-does-not-prompt", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixPrefix(false)
		frames = append(frames,
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{"modeId": "ask"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil {
			t.Fatal("modeId ask echo completed a turn")
		}
		if cursorMatrixPromptSentAfter(t, exchange) >= 0 {
			t.Fatal("modeId ask echo sent session/prompt")
		}
	})

	t.Run("plan-result-does-not-prompt", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixPrefix(false)
		frames = append(frames,
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{"currentModeId": "plan"}}),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil {
			t.Fatal("plan mode completed a turn")
		}
		if cursorMatrixPromptSentAfter(t, exchange) >= 0 {
			t.Fatal("plan mode sent session/prompt")
		}
	})
}

func TestCursorMatrixSessionAndTurnCorrelation(t *testing.T) {
	t.Run("update-session", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(false),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-other", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "uncorrelated") {
			t.Fatalf("other session update = %v", err)
		}
	})

	t.Run("permission-session", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(false),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "permission-other", "method": "session/request_permission", "params": map[string]any{"sessionId": "session-other", "toolCall": map[string]any{"toolCallId": "tool-1", "kind": "execute"}}}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "unplanned execute") {
			t.Fatalf("other session permission = %v", err)
		}
	})

	t.Run("assistant-before-prompt", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(false), cursorMatrixMessage("too early"))
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "before the prompt") {
			t.Fatalf("early assistant text = %v", err)
		}
	})

	t.Run("prompt-result-before-prompt", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(false), cursorMatrixEndTurn())
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "uncorrelated") {
			t.Fatalf("early prompt result = %v", err)
		}
	})

	t.Run("other-turn-id", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixMessage("visible report"),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "stray-turn", "result": map[string]any{"stopReason": "end_turn"}}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil {
			t.Fatal("stray turn id completed the prompt")
		}
		receipt, ok := session.SessionObservation()
		if !ok || receipt.Input().TurnObserved {
			t.Fatal("stray turn id was observed as the prompt turn")
		}
	})
}

func TestCursorMatrixEndTurnAndAssistantTextOnly(t *testing.T) {
	t.Run("end-turn", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "agent_thought_chunk", "content": map[string]string{"type": "text", "text": "THOUGHT_LEAK"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixMessage(" continued"),
			cursorMatrixEndTurn(),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(session.AssistantEvidenceText()); got != "visible report continued" {
			t.Fatalf("assistant text = %q", got)
		}
		receipt, ok := session.SessionObservation()
		if !ok || !receipt.Input().TurnObserved {
			t.Fatal("end_turn was not observed")
		}
	})

	t.Run("other-stop-reason", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixMessage("visible report"),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-prompt", "result": map[string]any{"stopReason": "max_tokens"}}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "max_tokens") {
			t.Fatalf("max_tokens = %v", err)
		}
	})

	t.Run("missing-assistant-text", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true), cursorMatrixEndTurn())
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "assistant text is missing") {
			t.Fatalf("empty assistant = %v", err)
		}
	})
}

func TestCursorMatrixExactCommandAndOption(t *testing.T) {
	const planned = "git --no-pager show ':target.txt'"
	session := cursorMatrixSession(t, cursorMatrixAuthority(planned, "git --no-pager show 'HEAD:target.txt'"))
	frames := cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-index", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
		cursorMatrixPermission("permission-index", "tool-index", "execute", nil, []map[string]string{
			{"optionId": "always-index", "kind": "allow_always"},
			{"optionId": "once-index", "kind": "allow_once"},
		}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-head", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": "git --no-pager show 'HEAD:target.txt'"}}),
		cursorMatrixPermission("permission-head", "tool-head", "execute", nil, []map[string]string{
			{"optionId": "always-head", "kind": "allow_always"},
			{"optionId": "once-head", "kind": "allow_once"},
		}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-index", "kind": "execute", "status": "completed"}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-head", "kind": "execute", "status": "completed"}),
		cursorMatrixMessage("selected commands"),
		cursorMatrixEndTurn(),
	)
	exchange, err := cursorMatrixDrive(session, frames...)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-index"); outcome != "selected" || optionID != "once-index" {
		t.Fatalf("index permission = %s %s", outcome, optionID)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-head"); outcome != "selected" || optionID != "once-head" {
		t.Fatalf("head permission = %s %s", outcome, optionID)
	}
}

func TestCursorMatrixCommandCorrelationRejectsMutation(t *testing.T) {
	const planned = "git --no-pager show ':target.txt'"
	t.Run("other-tool-command", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-planned", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixPermission("permission-planned", "tool-planned", "execute", nil, []map[string]string{{"optionId": "once-planned", "kind": "allow_once"}, {"optionId": "reject-planned", "kind": "reject_once"}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-other", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": "git status --short"}}),
			cursorMatrixPermission("permission-other", "tool-other", "execute", nil, []map[string]string{{"optionId": "once-other", "kind": "allow_once"}, {"optionId": "reject-other", "kind": "reject_once"}}),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil {
			t.Fatal("unplanned command was admitted")
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-planned"); outcome != "selected" || optionID != "once-planned" {
			t.Fatalf("planned permission = %s %s", outcome, optionID)
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-other"); outcome != "selected" || optionID != "reject-other" {
			t.Fatalf("mutated permission = %s %s", outcome, optionID)
		}
	})

	t.Run("permission-command-disagrees", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixPermission("permission-1", "tool-1", "execute", map[string]any{"command": planned + " --stat"}, []map[string]string{{"optionId": "once-1", "kind": "allow_once"}, {"optionId": "reject-1", "kind": "reject_once"}}),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil {
			t.Fatal("disagreed permission command was allowed")
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-1"); outcome != "selected" || optionID != "reject-1" {
			t.Fatalf("disagreed permission = %s %s", outcome, optionID)
		}
	})

	t.Run("completion-command-changes", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-1", "kind": "execute", "status": "completed", "rawInput": map[string]any{"command": planned + " --stat"}}),
			cursorMatrixMessage("selected"),
			cursorMatrixEndTurn(),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "uncorrelated") {
			t.Fatalf("changed completion command = %v", err)
		}
	})
}

func TestCursorMatrixPathAndOption(t *testing.T) {
	ctx := context.Background()
	workspace, outside := cursorMatrixWorkspace(t)
	authority, err := newCursorLiveReadAuthority(ctx, workspace)
	if err != nil {
		t.Fatal(err)
	}
	exact := cursorMatrixTargetPath(t, workspace)
	session := cursorMatrixSession(t, authority)
	frames := cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{
			"sessionUpdate": "tool_call", "toolCallId": "tool-read", "kind": "read", "status": "pending",
			"rawInput":  map[string]any{"path": exact},
			"locations": []map[string]string{{"path": outside}},
		}),
		cursorMatrixPermission("permission-read", "tool-read", "read", nil, []map[string]string{
			{"optionId": "always-read", "kind": "allow_always"},
			{"optionId": "once-read", "kind": "allow_once"},
		}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-read", "kind": "read", "status": "completed"}),
		cursorMatrixMessage("selected path"),
		cursorMatrixEndTurn(),
	)
	exchange, err := cursorMatrixDrive(session, frames...)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-read"); outcome != "cancelled" || optionID != "" {
		t.Fatalf("path permission = %s %s", outcome, optionID)
	}

	rejected := cursorMatrixSession(t, authority)
	frames = cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-outside", "kind": "read", "status": "pending", "locations": []map[string]string{{"path": outside}}}),
		cursorMatrixPermission("permission-outside", "tool-outside", "read", nil, []map[string]string{{"optionId": "once-outside", "kind": "allow_once"}, {"optionId": "reject-outside", "kind": "reject_once"}}),
		cursorMatrixMessage("outside report"),
		cursorMatrixEndTurn(),
	)
	exchange, err = cursorMatrixDrive(rejected, frames...)
	if err == nil || strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), "unplanned read") {
		t.Fatalf("outside path = %v", err)
	}
	if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
		t.Fatalf("outside cause = %v", err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-outside"); outcome != "selected" || optionID != "reject-outside" {
		t.Fatalf("outside path = %s %s", outcome, optionID)
	}
	cursorMatrixAssertNoReport(t, rejected)

	stage := cursorMatrixStage(t)
	stageAuthority, err := newCursorLiveReadAuthority(ctx, stage.execution)
	if err != nil {
		t.Fatal(err)
	}
	stageSession := cursorMatrixSession(t, stageAuthority)
	frames = cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-stage", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": stage.command}}),
		cursorMatrixPermission("permission-stage", "tool-stage", "execute", nil, []map[string]string{{"optionId": "always-stage", "kind": "allow_always"}, {"optionId": "once-stage", "kind": "allow_once"}}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-worktree", "kind": "read", "status": "pending", "rawInput": map[string]any{"path": stage.worktree}}),
		cursorMatrixPermission("permission-worktree", "tool-worktree", "read", nil, []map[string]string{{"optionId": "once-worktree", "kind": "allow_once"}, {"optionId": "reject-worktree", "kind": "reject_once"}}),
		cursorMatrixMessage("worktree report"),
		cursorMatrixEndTurn(),
	)
	exchange, err = cursorMatrixDrive(stageSession, frames...)
	if err == nil || strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), "unplanned read") {
		t.Fatalf("worktree path = %v", err)
	}
	if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
		t.Fatalf("worktree cause = %v", err)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-stage"); outcome != "selected" || optionID != "once-stage" {
		t.Fatalf("stage command = %s %s", outcome, optionID)
	}
	if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-worktree"); outcome != "selected" || optionID != "reject-worktree" {
		t.Fatalf("worktree substitute = %s %s", outcome, optionID)
	}
	cursorMatrixAssertNoReport(t, stageSession)
}

func TestCursorMatrixUnsafeUnknownAndTask(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  string
	}{
		{name: "edit", want: "write is rejected", frame: cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-edit", "kind": "edit", "status": "pending"})},
		{name: "delete", want: "write is rejected", frame: cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-delete", "kind": "delete", "status": "pending"})},
		{name: "web", want: "tool other is rejected", frame: cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-web", "kind": "other", "status": "completed", "rawInput": map[string]any{"_toolName": "web"}})},
		{name: "mcp", want: "tool other is rejected", frame: cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-mcp", "kind": "other", "status": "completed", "rawInput": map[string]any{"_toolName": "mcp"}})},
		{name: "unknown-method", want: "unknown server request", frame: cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "unknown-1", "method": "cursor/web_search", "params": map[string]any{"sessionId": "session-1"}})},
		{name: "task-without-permission", want: "subagent is rejected", frame: cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-task", "kind": "other", "status": "pending", "rawInput": map[string]any{"_toolName": "task"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := cursorMatrixSession(t, nil)
			frames := cursorMatrixAppend(cursorMatrixPrefix(true), tc.frame, cursorMatrixMessage("visible report"), cursorMatrixEndTurn())
			exchange, err := cursorMatrixDrive(session, frames...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v", err)
			}
			for _, line := range exchange.sent {
				if strings.Contains(string(line), "allow_once") || strings.Contains(string(line), "allow-once") {
					t.Fatalf("unsafe request was allowed: %s", line)
				}
			}
		})
	}
}

func TestCursorMatrixRejectedOrCancelledBlockers(t *testing.T) {
	t.Run("reject-once", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority("git --no-pager show ':target.txt'"))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixPermission("permission-shell", "tool-shell", "execute", map[string]any{"command": "sh -c 'rm -rf /'"}, []map[string]string{{"optionId": "once-shell", "kind": "allow_once"}, {"optionId": "reject-4", "kind": "reject_once"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "unplanned execute") {
			t.Fatalf("unplanned shell = %v", err)
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-shell"); outcome != "selected" || optionID != "reject-4" {
			t.Fatalf("shell permission = %s %s", outcome, optionID)
		}
		cursorMatrixAssertNoReport(t, session)
	})

	t.Run("cancelled", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixPermission("permission-diff", "tool-diff", "execute", map[string]any{"command": "git --no-pager diff"}, []map[string]string{{"optionId": "once-diff", "kind": "allow_once"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "unplanned execute") {
			t.Fatalf("unplanned diff = %v", err)
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-diff"); outcome != "cancelled" || optionID != "" {
			t.Fatalf("unplanned permission = %s %s", outcome, optionID)
		}
		cursorMatrixAssertNoReport(t, session)
	})

	t.Run("ask-and-plan-cancelled", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "question-3", "method": "cursor/ask_question", "params": map[string]any{"sessionId": "session-1"}}),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "plan-3", "method": "cursor/create_plan", "params": map[string]any{"sessionId": "session-1"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err != nil {
			t.Fatal(err)
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "question-3"); outcome != "cancelled" || optionID != "" {
			t.Fatalf("ask_question = %s %s", outcome, optionID)
		}
		if outcome, optionID := cursorMatrixReply(t, exchange.sent, "plan-3"); outcome != "cancelled" || optionID != "" {
			t.Fatalf("create_plan = %s %s", outcome, optionID)
		}
		if got := string(session.AssistantEvidenceText()); got != "visible report" {
			t.Fatalf("assistant text = %q", got)
		}
	})
}

func cursorPermissionCause(t *testing.T, err error) domain.RuntimeDiagnosticCause {
	t.Helper()
	var failure *cursorACPError
	if !errors.As(err, &failure) {
		t.Fatalf("permission cause = %v", err)
	}
	return failure.Cause()
}

func cursorMatrixAssertNoReport(t *testing.T, session *cursorACPProtocolSession) {
	t.Helper()
	if string(session.AssistantEvidenceText()) != "" {
		t.Fatalf("assistant report = %q", session.AssistantEvidenceText())
	}
	receipt, ok := session.SessionObservation()
	if !ok || receipt.Input().TurnObserved {
		t.Fatal("forbidden execute produced a final report")
	}
}

func cursorMatrixWorkspace(t *testing.T) (ports.LiveReviewExecution, string) {
	t.Helper()
	execution, outside := cursorMatrixExecution(t, domain.LiveSourceWorkspace)
	return execution, outside
}

type cursorMatrixStagePlan struct {
	execution ports.LiveReviewExecution
	command   string
	worktree  string
}

func cursorMatrixStage(t *testing.T) cursorMatrixStagePlan {
	t.Helper()
	execution, _ := cursorMatrixExecution(t, domain.LiveSourceStage)
	planned := ""
	for _, read := range execution.Reads() {
		if strings.Contains(read.GitCommand(), "show ':target.txt'") {
			planned = read.GitCommand()
		}
	}
	if planned == "" || strings.Contains(planned, "--git-dir=") || strings.Contains(planned, "--work-tree=") {
		t.Fatal("stage plan lacked the index command")
	}
	return cursorMatrixStagePlan{execution: execution, command: planned, worktree: cursorMatrixTargetPath(t, execution)}
}

func cursorMatrixTargetPath(t *testing.T, execution ports.LiveReviewExecution) string {
	t.Helper()
	for _, read := range execution.Reads() {
		if read.Path().String() == "target.txt" {
			return filepath.Join(execution.Binding().Root.String(), read.Path().String())
		}
	}
	t.Fatal("plan lacked target.txt")
	return ""
}

func cursorMatrixExecution(t *testing.T, scope domain.LiveSourceScope) (ports.LiveReviewExecution, string) {
	t.Helper()
	ctx := context.Background()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	operator := filepath.Join(base, "operator")
	credentials := filepath.Join(base, "credentials")
	for _, path := range []string{project, operator, credentials} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(project, "target.txt")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(target, "committed-bytes\n")
	write(filepath.Join(credentials, "secret.txt"), "credential-bytes\n")
	git := func(args ...string) {
		t.Helper()
		command := exec.Command("/usr/bin/git", append([]string{"-C", project}, args...)...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("fixture git %v: %v (%s)", args, err, output)
		}
	}
	git("init", "--quiet")
	git("add", "target.txt")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Baseline")
	write(target, "index-bytes\n")
	git("add", "target.txt")
	write(target, "worktree-bytes\n")
	operatorRoot, err := ports.NewAnchoredRoot(operator)
	if err != nil {
		t.Fatal(err)
	}
	home, err := OpenReviewerHome(operatorRoot, []byte("shared guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = home.Close() })
	credentialRoot, err := ports.NewAnchoredRoot(credentials)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := gittargetadapter.NewLiveSourceAdapter(gittargetadapter.NewExecRunner(), []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	projectRoot, err := ports.NewAnchoredRoot(project)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(scope, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := adapter.OpenLiveSource(ctx, projectRoot, selector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	execution, err := ports.NewLiveReviewExecution(ctx, source, home, []ports.AnchoredRoot{credentialRoot})
	if err != nil {
		t.Fatal(err)
	}
	return execution, filepath.Join(credentials, "secret.txt")
}
