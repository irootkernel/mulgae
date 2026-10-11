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

func TestZCodeExtractionOmitsToolCallNarration(t *testing.T) {
	message := func(finish string, texts ...string) any {
		parts := make([]any, 0, len(texts))
		for _, text := range texts {
			parts = append(parts, map[string]string{"type": "text", "text": text})
		}
		info := map[string]string{"role": "assistant"}
		if finish != "" {
			info["finish"] = finish
		}
		return map[string]any{"info": info, "parts": parts}
	}
	const candidate = `{"schema_version":"mulgae-provider-review-output.v1","findings":[]}`
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeExtraction, protocolPurposeLiveExtraction} {
		t.Run(string(purpose), func(t *testing.T) {
			for _, test := range []struct {
				name     string
				messages []any
				want     string
			}{
				{"narration-then-json", []any{message("tool-calls", "I will transcribe the report."), message("stop", candidate)}, candidate},
				{"multiple-final-parts", []any{message("tool-calls", "Working."), message("stop", "{", `"findings":[]}`)}, "{\n\"findings\":[]}"},
				{"missing-finish", []any{message("", candidate)}, candidate},
				{"unknown-finish", []any{message("future-value", candidate)}, candidate},
				{"only-narration", []any{message("tool-calls", candidate)}, ""},
				{"malformed-final", []any{message("tool-calls", "Working."), message("stop", "{broken")}, "{broken"},
				{"multiple-candidates", []any{message("stop", candidate), message("stop", candidate)}, candidate + "\n" + candidate},
				{"unmarked-prefix", []any{message("", "Unmarked narration."), message("stop", candidate)}, "Unmarked narration.\n" + candidate},
			} {
				t.Run(test.name, func(t *testing.T) {
					session, err := (zcodeProtocolDriverConstructor{}).NewSession("/neutral", []byte("extract"), purpose, nil, protocolSessionConfiguration{})
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := json.Marshal(map[string]any{"id": zcodeProtocolMessagesID, "result": map[string]any{"messages": test.messages}})
					if err != nil {
						t.Fatal(err)
					}
					err, _ = driveScripted(t, session.(*zcodeProtocolSession), protocolCreateResult, protocolSendAck, protocolTurnDone, string(encoded), protocolCloseResult)
					if err != nil {
						t.Fatal(err)
					}
					if got := string(session.AssistantEvidenceText()); got != test.want {
						t.Fatalf("extraction text = %q, want %q", got, test.want)
					}
				})
			}
		})
	}
}

func TestZCodeNonExtractionPreservesToolCallNarration(t *testing.T) {
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeQualification, protocolPurposeLiveReview} {
		t.Run(string(purpose), func(t *testing.T) {
			session, err := (zcodeProtocolDriverConstructor{}).NewSession("/neutral", []byte("report"), purpose, nil, protocolSessionConfiguration{})
			if err != nil {
				t.Fatal(err)
			}
			messages := `{"id":"mulgae-messages","result":{"messages":[{"info":{"role":"assistant","finish":"tool-calls"},"parts":[{"type":"text","text":"Intermediate observation."}]},{"info":{"role":"assistant","finish":"stop"},"parts":[{"type":"text","text":"Final report."}]}]}}`
			err, _ = driveScripted(t, session.(*zcodeProtocolSession), protocolCreateResult, protocolSendAck, protocolTurnDone, messages, protocolCloseResult)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(session.AssistantEvidenceText()); got != "Intermediate observation.\nFinal report." {
				t.Fatalf("complete report text = %q", got)
			}
		})
	}
}

func TestZCodeExtractionRejectsMalformedFinish(t *testing.T) {
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeExtraction, protocolPurposeLiveExtraction} {
		t.Run(string(purpose), func(t *testing.T) {
			session, err := (zcodeProtocolDriverConstructor{}).NewSession("/neutral", []byte("extract"), purpose, nil, protocolSessionConfiguration{})
			if err != nil {
				t.Fatal(err)
			}
			messages := `{"id":"mulgae-messages","result":{"messages":[{"info":{"role":"assistant","finish":{}},"parts":[{"type":"text","text":"{}"}]}]}}`
			err, _ = driveScripted(t, session.(*zcodeProtocolSession), protocolCreateResult, protocolSendAck, protocolTurnDone, messages)
			if err == nil || protocolCause(t, err) != domain.DiagnosticCauseOutputEnvelopeInvalid || session.AssistantEvidenceText() != nil {
				t.Fatalf("malformed extraction finish: error=%v text=%q", err, session.AssistantEvidenceText())
			}
		})
	}
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
