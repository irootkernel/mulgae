//go:build darwin && arm64

package providercli

import (
	"context"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestCursorProtocolForbiddenPermissionFailsTurn(t *testing.T) {
	cases := []struct {
		name string
		kind string
		raw  map[string]any
	}{
		{name: "edit", kind: "edit", raw: map[string]any{"path": "/tmp/target.txt"}},
		{name: "other", kind: "other", raw: map[string]any{"_toolName": "web"}},
		{name: "task", kind: "other", raw: map[string]any{"_toolName": "task"}},
		{name: "unplanned-execute", kind: "execute", raw: map[string]any{"command": "sh -c rm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := cursorMatrixSession(t, cursorMatrixAuthority("git --no-pager show ':target.txt'"))
			frames := cursorMatrixAppend(cursorMatrixPrefix(true),
				cursorMatrixPermission("permission-forbidden", "tool-forbidden", tc.kind, tc.raw, []map[string]string{{"optionId": "once-forbidden", "kind": "allow_once"}, {"optionId": "reject-forbidden", "kind": "reject_once"}}),
				cursorMatrixMessage("visible report"),
				cursorMatrixEndTurn(),
			)
			exchange, err := cursorMatrixDrive(session, frames...)
			if err == nil || !strings.Contains(err.Error(), "rejected") {
				t.Fatalf("%s = %v", tc.name, err)
			}
			outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-forbidden")
			if outcome != "selected" || optionID != "reject-forbidden" {
				t.Fatalf("%s reply = %s %s", tc.name, outcome, optionID)
			}
			cursorMatrixAssertNoReport(t, session)
		})
	}
}

func TestCursorProtocolEarlyAskDoesNotLatch(t *testing.T) {
	session := cursorMatrixSession(t, nil)
	frames := [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-early", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
		cursorMatrixMessage("visible report"),
		cursorMatrixEndTurn(),
	}
	exchange, err := cursorMatrixDrive(session, frames...)
	if err == nil || !strings.Contains(err.Error(), "uncorrelated") {
		t.Fatalf("early ask = %v", err)
	}
	if cursorMatrixPromptSentAfter(t, exchange) >= 0 {
		t.Fatal("early ask latched a later session")
	}
}

func TestCursorClosedPurposePermissionFailsTurn(t *testing.T) {
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeQualification, protocolPurposeExtraction, protocolPurposeLiveExtraction} {
		t.Run(string(purpose), func(t *testing.T) {
			session, err := newCursorACPProtocolSession("/neutral", []byte("root=a\nlink=b\nrole=logic\n"), purpose, nil)
			if err != nil {
				t.Fatal(err)
			}
			exchange := &cursorScriptExchange{inbox: [][]byte{
				cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
				cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
				cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
				cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
				cursorMatrixPermission("permission-closed", "tool-closed", "execute", nil, []map[string]string{{"optionId": "once-closed", "kind": "allow_once"}, {"optionId": "reject-closed", "kind": "reject_once"}}),
				cursorMatrixMessage(`{"root":"a","link":"b","role":"logic"}`),
				cursorMatrixEndTurn(),
			}}
			err = session.Drive(context.Background(), exchange)
			if err == nil || !strings.Contains(err.Error(), "closed for this purpose") {
				t.Fatalf("closed permission = %v", err)
			}
			outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-closed")
			if outcome != "selected" || optionID != "reject-closed" {
				t.Fatalf("closed reply = %s %s", outcome, optionID)
			}
			receipt, ok := session.SessionObservation()
			if (ok && receipt.Input().TurnObserved) || string(session.AssistantEvidenceText()) != "" {
				t.Fatal("closed permission qualified")
			}
		})
	}
}

func TestCursorLiveGrantRequiresPromptPhase(t *testing.T) {
	const planned = "git --no-pager show ':target.txt'"
	options := []map[string]string{{"optionId": "always-git", "kind": "allow_always"}, {"optionId": "once-git", "kind": "allow_once"}, {"optionId": "reject-git", "kind": "reject_once"}}
	session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
	frames := [][]byte{
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		cursorMatrixPermission("permission-before", "tool-before", "execute", map[string]any{"command": planned}, options),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-1"}}),
		cursorMatrixPermission("permission-early", "tool-early", "execute", map[string]any{"command": planned}, options),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "session-1", "update": map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "ask"}}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "permission-foreign", "method": "session/request_permission", "params": map[string]any{"sessionId": "session-other", "toolCall": map[string]any{"toolCallId": "tool-foreign", "kind": "execute", "rawInput": map[string]any{"command": planned}}, "options": options}}),
		cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "permission-blank", "method": "session/request_permission", "params": map[string]any{"toolCall": map[string]any{"toolCallId": "tool-blank", "kind": "execute", "rawInput": map[string]any{"command": planned}}, "options": options}}),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-live", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
		cursorMatrixPermission("permission-live", "tool-live", "execute", nil, options),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-live", "kind": "execute", "status": "completed"}),
		cursorMatrixMessage("selected index"),
		cursorMatrixEndTurn(),
	}
	exchange, err := cursorMatrixDrive(session, frames...)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"permission-before", "permission-early", "permission-foreign", "permission-blank"} {
		outcome, optionID := cursorMatrixReply(t, exchange.sent, id)
		if outcome == "selected" && optionID == "once-git" {
			t.Fatalf("%s received allow_once", id)
		}
	}
	outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-live")
	if outcome != "selected" || optionID != "once-git" {
		t.Fatalf("prompt-phase grant = %s %s", outcome, optionID)
	}
}

func TestCursorProtocolNegativeNotificationWithoutID(t *testing.T) {
	for _, method := range []string{"cursor/task", "cursor/noise"} {
		t.Run(method, func(t *testing.T) {
			session := cursorMatrixSession(t, nil)
			frames := cursorMatrixAppend(cursorMatrixPrefix(true),
				cursorFrame(map[string]any{"jsonrpc": "2.0", "method": method}),
				cursorMatrixMessage("visible report"),
				cursorMatrixEndTurn(),
			)
			_, err := cursorMatrixDrive(session, frames...)
			if err == nil || !strings.Contains(err.Error(), "notification") {
				t.Fatalf("notification %s = %v", method, err)
			}
			cursorMatrixAssertNoReport(t, session)
		})
	}
}

func TestCursorProtocolNegativeEmptyKind(t *testing.T) {
	session := cursorMatrixSession(t, cursorMatrixAuthority("git --no-pager show ':target.txt'"))
	frames := cursorMatrixAppend(cursorMatrixPrefix(true),
		cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-empty", "status": "completed"}),
		cursorMatrixMessage("visible report"),
		cursorMatrixEndTurn(),
	)
	_, err := cursorMatrixDrive(session, frames...)
	if err == nil || !strings.Contains(err.Error(), "kind is missing") {
		t.Fatalf("empty kind = %v", err)
	}
	cursorMatrixAssertNoReport(t, session)
}

func TestCursorProtocolNegativeToolIdentityStaysContinuous(t *testing.T) {
	const planned = "git --no-pager show ':target.txt'"
	t.Run("kind", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-1", "kind": "read", "status": "pending"}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "kind is uncorrelated") {
			t.Fatalf("kind change = %v", err)
		}
		cursorMatrixAssertNoReport(t, session)
	})
	t.Run("tool-name", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned, "_toolName": "git"}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"_toolName": "shell"}}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "tool name is uncorrelated") {
			t.Fatalf("tool name change = %v", err)
		}
		cursorMatrixAssertNoReport(t, session)
	})
	t.Run("terminal-reopen", func(t *testing.T) {
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-1", "kind": "execute", "status": "completed", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-1", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned + " --stat"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "cannot reopen") {
			t.Fatalf("reopen = %v", err)
		}
		cursorMatrixAssertNoReport(t, session)
	})
}

func TestCursorProtocolNegativeOutstandingResults(t *testing.T) {
	t.Run("session-new-before-initialize", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := [][]byte{
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-new", "result": map[string]any{"sessionId": "session-early"}}),
			cursorMatrixMessage("visible report"),
			cursorMatrixEndTurn(),
		}
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "session/new was not outstanding") {
			t.Fatalf("early session/new = %v", err)
		}
		for _, line := range exchange.sent {
			if strings.Contains(string(line), "session/set_mode") || strings.Contains(string(line), "session/prompt") {
				t.Fatalf("unsolicited session/new advanced the session: %s", line)
			}
		}
		cursorMatrixAssertNoReport(t, session)
	})
	t.Run("set-mode-before-initialize", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		_, err := cursorMatrixDrive(session, cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-mode", "result": map[string]any{"modeId": "ask"}}))
		if err == nil || !strings.Contains(err.Error(), "set_mode was not outstanding") {
			t.Fatalf("early set_mode = %v", err)
		}
		cursorMatrixAssertNoReport(t, session)
	})
	t.Run("initialize-after-it-was-accepted", func(t *testing.T) {
		session := cursorMatrixSession(t, nil)
		frames := [][]byte{
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
			cursorFrame(map[string]any{"jsonrpc": "2.0", "id": "cursor-initialize", "result": map[string]any{"protocolVersion": 1}}),
		}
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || !strings.Contains(err.Error(), "initialize was not outstanding") {
			t.Fatalf("repeated initialize = %v", err)
		}
		receipt, ok := session.SessionObservation()
		if !ok || receipt.Input().CreateAccepted || receipt.Input().TurnObserved {
			t.Fatal("repeated initialize created a session")
		}
	})
}

func TestCursorStandaloneForbiddenPermissionFailsTurn(t *testing.T) {
	cases := []struct {
		name string
		kind string
	}{
		{name: "web", kind: "web"},
		{name: "mcp", kind: "mcp"},
		{name: "unknown", kind: "fetch"},
		{name: "empty-kind", kind: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := cursorMatrixSession(t, nil)
			frames := cursorMatrixAppend(cursorMatrixPrefix(true),
				cursorMatrixPermission("permission-standalone", "tool-standalone", tc.kind, nil, []map[string]string{{"optionId": "once-standalone", "kind": "allow_once"}, {"optionId": "reject-standalone", "kind": "reject_once"}}),
				cursorMatrixMessage("visible report"),
				cursorMatrixEndTurn(),
			)
			exchange, err := cursorMatrixDrive(session, frames...)
			if err == nil || strings.Contains(err.Error(), "EOF") {
				t.Fatalf("standalone %s = %v", tc.name, err)
			}
			if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
				t.Fatalf("standalone cause = %v", err)
			}
			outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-standalone")
			if outcome == "selected" && optionID == "once-standalone" {
				t.Fatal("standalone permission was granted")
			}
			cursorMatrixAssertNoReport(t, session)
		})
	}
}

func TestCursorReadPermissionCorrelationAndCancellation(t *testing.T) {
	workspace, outside := cursorMatrixWorkspace(t)
	authority, err := newCursorLiveReadAuthority(context.Background(), workspace)
	if err != nil {
		t.Fatal(err)
	}
	exact := cursorMatrixTargetPath(t, workspace)

	t.Run("mismatched-path", func(t *testing.T) {
		session := cursorMatrixSession(t, authority)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-read", "kind": "read", "status": "pending", "rawInput": map[string]any{"path": exact}}),
			cursorMatrixPermission("permission-mismatch", "tool-read", "read", map[string]any{"path": outside}, []map[string]string{{"optionId": "once-mismatch", "kind": "allow_once"}, {"optionId": "reject-mismatch", "kind": "reject_once"}}),
			cursorMatrixMessage("mismatch report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err == nil || strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), "unplanned read") {
			t.Fatalf("mismatched read = %v", err)
		}
		if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
			t.Fatalf("mismatch cause = %v", err)
		}
		outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-mismatch")
		if outcome != "selected" || optionID != "reject-mismatch" {
			t.Fatalf("mismatch reply = %s %s", outcome, optionID)
		}
		cursorMatrixAssertNoReport(t, session)
	})

	t.Run("planned-read-cancelled", func(t *testing.T) {
		session := cursorMatrixSession(t, authority)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixPermission("permission-planned", "tool-planned", "read", map[string]any{"path": exact}, []map[string]string{{"optionId": "once-planned", "kind": "allow_once"}, {"optionId": "reject-planned", "kind": "reject_once"}}),
			cursorMatrixMessage("planned report"),
			cursorMatrixEndTurn(),
		)
		exchange, err := cursorMatrixDrive(session, frames...)
		if err != nil {
			t.Fatal(err)
		}
		outcome, optionID := cursorMatrixReply(t, exchange.sent, "permission-planned")
		if outcome == "selected" && optionID == "once-planned" {
			t.Fatal("planned read was granted")
		}
		if string(session.AssistantEvidenceText()) != "planned report" {
			t.Fatalf("assistant = %q", session.AssistantEvidenceText())
		}
	})

	t.Run("pending-web-fails", func(t *testing.T) {
		session := cursorMatrixSession(t, authority)
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-web", "kind": "web", "status": "pending"}),
		)
		_, err := cursorMatrixDrive(session, frames...)
		if err == nil || strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), "tool web is rejected") {
			t.Fatalf("pending web = %v", err)
		}
		if cursorPermissionCause(t, err) != domain.DiagnosticCausePermissionDenied {
			t.Fatalf("pending web cause = %v", err)
		}
	})

	t.Run("known-tool-empty-kind-continues", func(t *testing.T) {
		const planned = "git --no-pager show ':target.txt'"
		session := cursorMatrixSession(t, cursorMatrixAuthority(planned))
		frames := cursorMatrixAppend(cursorMatrixPrefix(true),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call", "toolCallId": "tool-known", "kind": "execute", "status": "pending", "rawInput": map[string]any{"command": planned}}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-known", "kind": "", "status": "pending"}),
			cursorMatrixUpdate(map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "tool-known", "kind": "execute", "status": "completed"}),
			cursorMatrixMessage("known tool"),
			cursorMatrixEndTurn(),
		)
		if _, err := cursorMatrixDrive(session, frames...); err != nil {
			t.Fatal(err)
		}
	})
}
