package providercli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

func liveZCodeProtocolSession(t *testing.T) *zcodeProtocolSession {
	t.Helper()
	session, err := (zcodeProtocolDriverConstructor{}).NewSession("/neutral", []byte("live packet"), protocolPurposeLiveReview, nil, protocolSessionConfiguration{})
	if err != nil {
		t.Fatal(err)
	}
	return session.(*zcodeProtocolSession)
}

func TestZCodeLiveProtocolCorrelatesOwnTurnAndCollectsCompleteReport(t *testing.T) {
	session := liveZCodeProtocolSession(t)
	foreign := `{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_foreign","sessionId":"sess_foreign"}}`
	foreignFailed := `{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_foreign","sessionId":"sess_foreign"}}`
	var messages []any
	var expected []string
	for i := 0; i < 12; i++ {
		text := strings.Repeat("complete report part", 4096)
		expected = append(expected, text)
		messages = append(messages, map[string]any{"info": map[string]string{"role": "assistant"}, "parts": []any{map[string]string{"type": "text", "text": text}}})
	}
	encoded, err := json.Marshal(map[string]any{"id": zcodeProtocolMessagesID, "result": map[string]any{"messages": messages}})
	if err != nil {
		t.Fatal(err)
	}
	err, requests := driveScripted(t, session, protocolCreateResult, protocolSendAck, foreign, foreignFailed, protocolTurnDone, string(encoded), protocolCloseResult)
	if err != nil {
		t.Fatal(err)
	}
	if string(session.AssistantEvidenceText()) != strings.Join(expected, "\n") {
		t.Fatal("complete native assistant report shortened")
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.ProviderSessionID() != "sess_script" || observation.ProviderTurnID() != "turn_script" {
		t.Fatal("foreign terminal event supplied report identity")
	}
	for _, request := range requests {
		var message struct {
			Method string
			Params map[string]json.RawMessage
		}
		if err := json.Unmarshal(request, &message); err != nil {
			t.Fatal(err)
		}
		switch message.Method {
		case zcodeProtocolCreateMethod:
			var allowed, denied []string
			if err := json.Unmarshal(message.Params["toolAllowlist"], &allowed); err != nil || !reflect.DeepEqual(allowed, []string{"Read", "Grep", "Glob", "Bash"}) {
				t.Fatalf("live tool selection: %v, %v", allowed, err)
			}
			if err := json.Unmarshal(message.Params["toolDenylist"], &denied); err != nil || !reflect.DeepEqual(denied, []string{"Write", "Edit", "ApplyPatch", "NotebookEdit", "WebSearch", "WebFetch", "EnterPlanMode", "ExitPlanMode"}) {
				t.Fatalf("live tool denial: %v, %v", denied, err)
			}
		case zcodeProtocolMessagesMethod:
			if _, limited := message.Params["limit"]; limited {
				t.Fatal("live report has a message-count ceiling")
			}
		}
	}
}

func TestZCodeLiveExtractionKeepsToolsDisabled(t *testing.T) {
	session, err := (zcodeProtocolDriverConstructor{}).NewSession("/neutral", []byte("extraction packet"), protocolPurposeLiveExtraction, nil, protocolSessionConfiguration{})
	if err != nil {
		t.Fatal(err)
	}
	err, requests := driveScripted(t, session.(*zcodeProtocolSession), protocolCreateResult, protocolSendAck, protocolTurnDone, protocolMessagesResult("extracted report"), protocolCloseResult)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		var message struct {
			Method string
			Params map[string]json.RawMessage
		}
		if err := json.Unmarshal(request, &message); err != nil {
			t.Fatal(err)
		}
		if message.Method == zcodeProtocolCreateMethod {
			if _, present := message.Params["toolAllowlist"]; present {
				t.Fatal("tool-free live extraction admitted review tools")
			}
			if string(message.Params["toolDenylist"]) != `["*"]` {
				t.Fatalf("extraction tool denial: %s", message.Params["toolDenylist"])
			}
			return
		}
	}
	t.Fatal("missing extraction create request")
}

func TestZCodeLiveProtocolRejectsMissingOwnCompletionAndReport(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		cause domain.RuntimeDiagnosticCause
	}{
		{"foreign-only", []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_foreign","sessionId":"sess_foreign"}}`}, domain.DiagnosticCauseProviderTurnFailed},
		{"missing-report", []string{protocolCreateResult, protocolSendAck, protocolTurnDone}, domain.DiagnosticCauseProviderTurnFailed},
		{"missing-correlation", []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_script"}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			err, _ := driveScripted(t, session, test.lines...)
			if err == nil || protocolCause(t, err) != test.cause || session.AssistantEvidenceText() != nil {
				t.Fatalf("invalid live completion: %v", err)
			}
		})
	}
}
