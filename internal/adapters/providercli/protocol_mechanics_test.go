package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Exercise the original family methods before extracting their common mechanics.
func TestProtocolStringResponseMatches(t *testing.T) {
	for _, test := range []struct {
		name, raw, method string
		expected          []string
		want              bool
	}{
		{name: "absent", expected: []string{""}},
		{name: "malformed", raw: `"unfinished`, expected: []string{"unfinished"}},
		{name: "number", raw: `1`, expected: []string{"1"}},
		{name: "boolean", raw: `true`, expected: []string{"true"}},
		{name: "object", raw: `{}`, expected: []string{""}},
		{name: "array", raw: `[]`, expected: []string{""}},
		{name: "null is not a request", raw: `null`, expected: []string{"mulgae-create"}},
		{name: "null preserves empty string decode", raw: `null`, expected: []string{""}, want: true},
		{name: "empty string", raw: `""`, expected: []string{""}, want: true},
		{name: "matching", raw: `"mulgae-create"`, expected: []string{"mulgae-create"}, want: true},
		{name: "other request", raw: `"mulgae-send"`, expected: []string{"mulgae-create"}},
		{name: "other family prefix", raw: `"cursor-new"`, expected: []string{"mulgae-create"}},
		{name: "escaped equivalent", raw: `"mulgae-\u0063reate"`, expected: []string{"mulgae-create"}, want: true},
		{name: "surrounding JSON whitespace", raw: " \t\"mulgae-create\"\n", expected: []string{"mulgae-create"}, want: true},
		{name: "trailing value", raw: `"mulgae-create" {}`, expected: []string{"mulgae-create"}},
		{name: "server request", raw: `"mulgae-create"`, method: "session/request_permission", expected: []string{"mulgae-create"}},
		{name: "whitespace method remains a method", raw: `"mulgae-create"`, method: " ", expected: []string{"mulgae-create"}},
		{name: "no expected IDs", raw: `"mulgae-create"`},
		{name: "multiple", raw: `"mulgae-send"`, expected: []string{"mulgae-create", "mulgae-send"}, want: true},
		{name: "duplicate expected IDs", raw: `"mulgae-create"`, expected: []string{"mulgae-create", "mulgae-create"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			zcode := zcodeProtocolMessage{ID: json.RawMessage(test.raw), Method: test.method}
			grok := grokACPMessage{ID: json.RawMessage(test.raw), Method: test.method}
			for family, got := range map[string]bool{"zcode": zcode.correlatesTo(test.expected...), "grok": grok.correlatesTo(test.expected...)} {
				if got != test.want {
					t.Errorf("%s correlation = %t, want %t", family, got, test.want)
				}
			}
			if len(test.expected) == 1 && (zcode.isResponseID(test.expected[0]) != test.want || grok.isResponseID(test.expected[0]) != test.want) {
				t.Error("single-ID wrapper differs from expected correlation")
			}
		})
	}

	t.Run("cursor retains textual ID projection", func(t *testing.T) {
		for _, test := range []struct{ raw, want string }{
			{`17`, "17"}, {`"17"`, "17"}, {`null`, "null"}, {`"cursor-new"`, "cursor-new"},
			{`"cursor-\u006eew"`, `cursor-\u006eew`}, {" \"cursor-new\" \n", "cursor-new"},
		} {
			if got := messageIDText(json.RawMessage(test.raw)); got != test.want {
				t.Errorf("Cursor ID %q = %q, want %q", test.raw, got, test.want)
			}
		}
	})
	t.Run("codex retains integer response IDs", func(t *testing.T) {
		for _, raw := range []string{`1`, `"1"`, `null`, `0`, `4`, `1.0`, `true`, `{}`} {
			state := codexConversation{phase: ports.ProviderSessionPhaseCreate}
			exchange := &scriptedCodexExchange{}
			err := state.handleResponse(context.Background(), exchange, &codexProtocolSession{workspacePath: "/neutral"}, codexWireMessage{ID: json.RawMessage(raw), Result: json.RawMessage(`{}`)})
			if raw == "1" {
				if err != nil || !state.initialized || len(exchange.sent) != 2 {
					t.Fatalf("integer initialize response: initialized=%t sends=%d error=%v", state.initialized, len(exchange.sent), err)
				}
			} else {
				assertTask064ProtocolCause(t, err, domain.DiagnosticCauseOutputEnvelopeInvalid)
				if state.initialized || len(exchange.sent) != 0 {
					t.Fatalf("invalid native ID %s advanced initialization", raw)
				}
			}
		}
	})
	t.Run("agy retains integer step IDs", func(t *testing.T) {
		for _, test := range []struct {
			name, raw string
			want      bool
		}{
			{"zero", `0`, true}, {"positive", `2`, true}, {"absent", "", false}, {"null", `null`, false},
			{"negative", `-1`, false}, {"fraction", `1.5`, false}, {"string", `"2"`, false}, {"boolean", `true`, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				step := map[string]any{"conversation_id": "conversation-1", "step_type": "agent_response", "state": "DONE"}
				if test.raw != "" {
					step["step_index"] = json.RawMessage(test.raw)
				}
				state := agyConversation{initAccepted: true, conversationID: "conversation-1", stepTypes: make(map[int]string)}
				err := state.handleStepUpdate(context.Background(), nil, agyWireFrame{StepUpdate: agyTestJSON(step)})
				if test.want {
					if err != nil || !state.observedStep {
						t.Fatalf("valid native step rejected: %v", err)
					}
				} else {
					assertTask064ProtocolCause(t, err, domain.DiagnosticCauseOutputEnvelopeInvalid)
					if state.observedStep {
						t.Fatal("invalid step advanced observation")
					}
				}
			})
		}
	})
	t.Run("protocol line tolerance stays local", func(t *testing.T) {
		for _, test := range []struct {
			name, suffix string
		}{
			{"additive field", `,"extra":true}`},
			{"duplicate ID", `,"id":"own"}`},
			{"trailing JSON", `} {"unrelated":true}`},
		} {
			t.Run(test.name, func(t *testing.T) {
				zcode, err := parseZcodeProtocolMessage([]byte(`{"id":"own"` + test.suffix))
				if err != nil || !zcode.isResponseID("own") {
					t.Fatalf("ZCode existing line tolerance changed: %v", err)
				}
				grok, err := parseGrokACPMessage([]byte(`{"jsonrpc":"2.0","id":"own"` + test.suffix))
				if err != nil || !grok.isResponseID("own") {
					t.Fatalf("Grok existing line tolerance changed: %v", err)
				}
			})
		}
	})
}

func TestProtocolDiagnosticIdentifierGrammar(t *testing.T) {
	for _, test := range []struct {
		name, value string
		admitted    bool
	}{
		{"empty", "", true}, {"ASCII", "session-1", true}, {"Unicode", "session-물개", true},
		{"511 bytes", strings.Repeat("s", 511), true}, {"512 bytes", strings.Repeat("s", 512), true},
		{"513 bytes", strings.Repeat("s", 513), false},
		{"multibyte 511 bytes", strings.Repeat("é", 255) + "s", true},
		{"multibyte 512 bytes", strings.Repeat("é", 256), true},
		{"multibyte 513 bytes", strings.Repeat("é", 256) + "s", false},
		{"invalid UTF8", "a\xffb", false}, {"replacement rune", "a\ufffdb", true},
		{"leading space", " session", false}, {"trailing space", "session ", false},
		{"leading Unicode space", "\u2003session", false}, {"trailing Unicode space", "session\u00a0", false},
		{"interior space", "session one", true}, {"interior Unicode space", "session\u2003one", true},
		{"NUL", "session\x00one", false}, {"tab", "session\tone", false},
		{"newline", "session\none", false}, {"DEL", "session\x7fone", false}, {"C1", "session\u0085one", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := ""
			if test.admitted {
				want = test.value
			}
			for family, sanitize := range map[string]func(string) string{
				"zcode": sanitizeProtocolDiagnosticIdentifier, "cursor": sanitizeProtocolDiagnosticIdentifier, "agy": sanitizeProtocolDiagnosticIdentifier,
			} {
				got := sanitize(test.value)
				if got != want {
					t.Errorf("%s diagnostic = %q, want %q", family, got, want)
				}
				input := ports.ProviderSessionObservationInput{Phase: ports.ProviderSessionPhaseCreate, Terminal: ports.ProviderSessionCompleted, ProviderSessionID: got, ProviderTurnID: got}
				if _, err := ports.NewProviderSessionObservation(input); err != nil {
					t.Errorf("%s sanitizer result violates port grammar: %v", family, err)
				}
			}
			_, err := ports.NewProviderSessionObservation(ports.ProviderSessionObservationInput{Phase: ports.ProviderSessionPhaseCreate, Terminal: ports.ProviderSessionCompleted, ProviderSessionID: test.value})
			if (err == nil) != test.admitted {
				t.Fatalf("raw port admission = %v, want admitted=%t", err, test.admitted)
			}
		})
	}
	t.Run("grok authoritative session rejects unsafe ID", func(t *testing.T) {
		for _, id := range []string{"safe-session", "", " session", strings.Repeat("s", 513), "session\tprivate"} {
			raw, err := json.Marshal(map[string]string{"sessionId": id})
			if err != nil {
				t.Fatal(err)
			}
			state := grokACPConversation{authenticated: true}
			err = state.acceptSessionNew(raw)
			if id == "safe-session" {
				if err != nil || !state.sessionCreated || state.sessionID != id {
					t.Fatalf("safe authoritative Grok session rejected: %v", err)
				}
			} else if err == nil || state.sessionCreated || !strings.Contains(err.Error(), "safe session id") {
				t.Fatalf("unsafe authoritative Grok session lost its ID rejection: %q: %v", id, err)
			}
		}
	})
	t.Run("codex authoritative turn rejects unsafe ID", func(t *testing.T) {
		for _, id := range []string{"turn-1", "", " turn-1", strings.Repeat("t", 513), "turn\tprivate"} {
			session, err := newCodexProtocolSession("/neutral", []byte("review"), protocolPurposeReview, nil)
			if err != nil {
				t.Fatal(err)
			}
			frames := codexSuccessFrames()
			frame, err := json.Marshal(map[string]any{"id": 3, "result": map[string]any{"turn": map[string]string{"id": id}}})
			if err != nil {
				t.Fatal(err)
			}
			frames[2] = string(frame)
			err = session.Drive(context.Background(), &scriptedCodexExchange{lines: frames})
			if id == "turn-1" {
				if err != nil || string(session.AssistantEvidenceText()) != "review result" {
					t.Fatalf("safe Codex turn rejected: %v", err)
				}
			} else {
				assertTask064ProtocolCause(t, err, domain.DiagnosticCauseOutputEnvelopeInvalid)
				if !strings.Contains(err.Error(), "turn response without id") || len(session.AssistantEvidenceText()) != 0 {
					t.Fatalf("unsafe turn lost its authoritative ID rejection: %v", err)
				}
			}
		}
	})
	t.Run("agy raw correlation survives diagnostic omission", func(t *testing.T) {
		const rawID = " conversation-private"
		init := agyTestJSON(map[string]any{"event": "init", "conversation_id": rawID, "init": map[string]string{"agent": agyTestAgent, "permission_mode": "request-review"}})
		progress := agyTestStep(map[string]any{"conversation_id": rawID, "step_index": 1, "step_type": "agent_response", "state": "DONE"})
		session := agyTestSession(t)
		err := session.Drive(context.Background(), &agyTestExchange{frames: [][]byte{init, progress, agyTestResult(map[string]any{"conversation_id": rawID})}})
		if err != nil || string(session.AssistantEvidenceText()) != "actual final report" {
			t.Fatalf("diagnostic omission invalidated raw correlation: %v", err)
		}
		observation, ok := session.SessionObservation()
		if !ok || observation.ProviderSessionID() != "" || observation.Terminal() != ports.ProviderSessionCompleted {
			t.Fatalf("AGY sanitized observation = %#v, present=%t", observation, ok)
		}
	})
}

func assertTask064ProtocolCause(t *testing.T, err error, want domain.RuntimeDiagnosticCause) {
	t.Helper()
	var failure interface {
		ProtocolFailureCause() domain.RuntimeDiagnosticCause
	}
	if err == nil || !errors.As(err, &failure) || failure.ProtocolFailureCause() != want {
		t.Fatalf("protocol error = %v, want typed cause %s", err, want)
	}
}
