package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	grokInitializeResult = `{"jsonrpc":"2.0","id":"mulgae-initialize","result":{"protocolVersion":1,"authMethods":[{"id":"cached_token","name":"Cached token"}],"agentCapabilities":{"promptCapabilities":{"image":false}}}}`
	grokAuthResult       = `{"jsonrpc":"2.0","id":"mulgae-authenticate","result":null}`
	grokNewResult        = `{"jsonrpc":"2.0","id":"mulgae-session-new","result":{"sessionId":"session-script"}}`
	grokPromptResult     = `{"jsonrpc":"2.0","id":"mulgae-session-prompt","result":{"stopReason":"end_turn"}}`
	grokCloseResult      = `{"jsonrpc":"2.0","id":"mulgae-session-close","result":null}`
)

func mustGrokSession(t *testing.T, purpose protocolInvocationPurpose) *grokACPProtocolSession {
	t.Helper()
	var authority protocolWriteAuthority
	if purpose == protocolPurposeReview {
		root := t.TempDir()
		lease, err := createStagedOutputDirectory(root, "output")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lease.Cleanup() })
		authority = lease
	}
	session, err := newGrokACPProtocolSession("/private/work", []byte("review packet"), purpose, authority)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func driveGrokScripted(t *testing.T, session *grokACPProtocolSession, serverLines ...string) (error, [][]byte) {
	t.Helper()
	exchange := newScriptedProtocolExchange(serverLines...)
	err := session.Drive(context.Background(), exchange)
	return err, exchange.sentLines(t)
}

func grokCause(t *testing.T, err error) domain.RuntimeDiagnosticCause {
	t.Helper()
	var failure *grokACPError
	if !errors.As(err, &failure) {
		t.Fatalf("driver error = %#v, want typed Grok ACP failure", err)
	}
	return failure.Cause()
}

func TestGrokACPDriveRequestShapesAndExtractionSelection(t *testing.T) {
	session := mustGrokSession(t, protocolPurposeExtraction)
	foreign := `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"selected-before-completion"}}}}`
	err, sent := driveGrokScripted(t, session,
		grokInitializeResult, grokAuthResult, grokNewResult,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"agent_thought_chunk","content":{"type":"text","text":"private"}}}}`,
		foreign,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"-and-after"}}}}`,
		grokPromptResult, grokCloseResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(session.AssistantEvidenceText()); got != "selected-before-completion-and-after" {
		t.Fatalf("assistant evidence = %q", got)
	}
	if len(sent) != 5 {
		t.Fatalf("sent message count = %d, want 5", len(sent))
	}
	wantMethods := []string{grokACPInitializeMethod, grokACPAuthMethod, grokACPSessionNewMethod, grokACPSessionPromptMethod, grokACPSessionCloseMethod}
	for index, want := range wantMethods {
		var message struct {
			JSONRPC string         `json:"jsonrpc"`
			Method  string         `json:"method"`
			Params  map[string]any `json:"params"`
		}
		if err := json.Unmarshal(sent[index], &message); err != nil {
			t.Fatal(err)
		}
		if message.JSONRPC != "2.0" || message.Method != want {
			t.Fatalf("sent[%d] = %s", index, sent[index])
		}
		if want == grokACPSessionNewMethod {
			servers, ok := message.Params["mcpServers"].([]any)
			if !ok || len(servers) != 0 {
				t.Fatalf("session/new mcpServers = %#v", message.Params["mcpServers"])
			}
		}
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.Terminal() != ports.ProviderSessionCompleted {
		t.Fatalf("session observation = %#v, present=%t", observation.Input(), ok)
	}
}

func TestGrokACPDriveAllowsOneExactlyCorrelatedWrite(t *testing.T) {
	session := mustGrokSession(t, protocolPurposeReview)
	destination, err := session.writeAuthority.Destination()
	if err != nil {
		t.Fatal(err)
	}
	path := destination.AbsolutePath()
	toolUpdate := `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"tool_call","toolCallId":"tool-write","kind":"edit","locations":[{"path":` + strconvQuote(path) + `}]}}}`
	permission := `{"jsonrpc":"2.0","id":17,"method":"session/request_permission","params":{"sessionId":"session-script","toolCall":{"toolCallId":"tool-write","kind":"edit","rawInput":{"variant":"Write","file_path":` + strconvQuote(path) + `}},"options":[{"optionId":"allow-once-17","kind":"allow_once"},{"optionId":"reject-17","kind":"reject_once"}]}}`
	err, sent := driveGrokScripted(t, session, grokInitializeResult, grokAuthResult, grokNewResult, toolUpdate, permission, grokPromptResult, grokCloseResult)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 6 {
		t.Fatalf("sent message count = %d, want 6", len(sent))
	}
	var response struct {
		ID     int `json:"id"`
		Result struct {
			Outcome struct {
				Outcome  string `json:"outcome"`
				OptionID string `json:"optionId"`
			} `json:"outcome"`
		} `json:"result"`
	}
	if err := json.Unmarshal(sent[4], &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != 17 || response.Result.Outcome.Outcome != "selected" || response.Result.Outcome.OptionID != "allow-once-17" {
		t.Fatalf("permission response = %s", sent[4])
	}
}

func TestGrokACPDriveRejectsUncorrelatedAndRepeatedWrites(t *testing.T) {
	for _, test := range []struct {
		name        string
		updatePath  func(string) string
		requestPath func(string) string
		sessionID   string
		toolID      string
		kind        string
		variant     string
		prefix      []string
	}{
		{name: "sibling", updatePath: func(path string) string { return filepath.Join(filepath.Dir(path), "sibling.md") }},
		{name: "traversal-cleaned", requestPath: func(path string) string {
			return filepath.Dir(path) + "/nested/../" + filepath.Base(path)
		}},
		{name: "session mismatch", sessionID: "session-other"},
		{name: "tool mismatch", toolID: "tool-other"},
		{name: "wrong kind", kind: "execute"},
		{name: "wrong variant", variant: "Edit"},
		{name: "second write", prefix: []string{"allow"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := mustGrokSession(t, protocolPurposeReview)
			destination, err := session.writeAuthority.Destination()
			if err != nil {
				t.Fatal(err)
			}
			want := destination.AbsolutePath()
			updatePath, requestPath := want, want
			if test.updatePath != nil {
				updatePath = test.updatePath(want)
			}
			if test.requestPath != nil {
				requestPath = test.requestPath(want)
			}
			sessionID, toolID, kind, variant := "session-script", "tool-write", "edit", "Write"
			if test.sessionID != "" {
				sessionID = test.sessionID
			}
			if test.toolID != "" {
				toolID = test.toolID
			}
			if test.kind != "" {
				kind = test.kind
			}
			if test.variant != "" {
				variant = test.variant
			}
			update := func(id, path string) string {
				return `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"session-script","update":{"sessionUpdate":"tool_call","toolCallId":"` + id + `","kind":"edit","locations":[{"path":` + strconvQuote(path) + `}]}}}`
			}
			permission := func(id, sid, callID, callKind, inputVariant, path string) string {
				return `{"jsonrpc":"2.0","id":` + id + `,"method":"session/request_permission","params":{"sessionId":"` + sid + `","toolCall":{"toolCallId":"` + callID + `","kind":"` + callKind + `","rawInput":{"variant":"` + inputVariant + `","file_path":` + strconvQuote(path) + `}},"options":[{"optionId":"allow","kind":"allow_once"}]}}`
			}
			lines := []string{grokInitializeResult, grokAuthResult, grokNewResult}
			if len(test.prefix) != 0 {
				lines = append(lines, update("first", want), permission("1", "session-script", "first", "edit", "Write", want))
			}
			lines = append(lines, update("tool-write", updatePath), permission("2", sessionID, toolID, kind, variant, requestPath))
			err, _ = driveGrokScripted(t, session, lines...)
			if err == nil || grokCause(t, err) != domain.DiagnosticCausePermissionDenied {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestGrokACPDriveFailsClosedOnProtocolAndCancellationBranches(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		cause domain.RuntimeDiagnosticCause
	}{
		{"malformed", []string{"not-json"}, domain.DiagnosticCauseOutputDecodeFailed},
		{"wrong version", []string{`{"jsonrpc":"2.0","id":"mulgae-initialize","result":{"protocolVersion":2,"authMethods":[{"id":"cached_token"}]}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"missing cached token", []string{`{"jsonrpc":"2.0","id":"mulgae-initialize","result":{"protocolVersion":1,"authMethods":[]}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"uncorrelated update", []string{grokInitializeResult, grokAuthResult, grokNewResult, `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"other","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"bad"}}}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"cancelled prompt", []string{grokInitializeResult, grokAuthResult, grokNewResult, `{"jsonrpc":"2.0","id":"mulgae-session-prompt","result":{"stopReason":"cancelled"}}`}, domain.DiagnosticCauseProviderTurnFailed},
		{"unexpected request", []string{grokInitializeResult, grokAuthResult, grokNewResult, `{"jsonrpc":"2.0","id":9,"method":"fs/read_text_file","params":{}}`}, domain.DiagnosticCausePermissionDenied},
		{"active MCP server", []string{grokInitializeResult, `{"jsonrpc":"2.0","method":"_x.ai/mcp/servers_updated","params":{"mcpServers":[{"name":"hostile"}]}}`}, domain.DiagnosticCausePermissionDenied},
		{"active MCP tool", []string{grokInitializeResult, grokAuthResult, grokNewResult, `{"jsonrpc":"2.0","method":"_x.ai/mcp_initialized","params":{"sessionId":"session-script","mcpToolCount":1}}`}, domain.DiagnosticCausePermissionDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			err, _ := driveGrokScripted(t, mustGrokSession(t, protocolPurposeExtraction), test.lines...)
			if err == nil || grokCause(t, err) != test.cause {
				t.Fatalf("error = %v, want cause %q", err, test.cause)
			}
		})
	}
}
