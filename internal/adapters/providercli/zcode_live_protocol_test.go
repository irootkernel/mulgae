package providercli

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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
			if string(message.Params["toolAllowlist"]) != `[]` {
				t.Fatalf("extraction tool allowlist: %s", message.Params["toolAllowlist"])
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

func TestZCodeLiveReviewToolAllowlistByLiveSourceScope(t *testing.T) {
	wantWorkspace := []string{"Read", "Grep", "Glob", "Bash"}
	wantGit := []string{"Read", "Bash"}
	for _, tc := range []struct {
		name  string
		scope domain.LiveSourceScope
		want  []string
	}{
		{name: "workspace", scope: domain.LiveSourceWorkspace, want: wantWorkspace},
		{name: "unset", scope: "", want: wantWorkspace},
		{name: "stage", scope: domain.LiveSourceStage, want: wantGit},
		{name: "head", scope: domain.LiveSourceHead, want: wantGit},
		{name: "commit", scope: domain.LiveSourceCommit, want: wantGit},
		{name: "diff", scope: domain.LiveSourceDiff, want: wantGit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver, err := (zcodeProtocolDriverConstructor{}).NewSession(
				"/neutral", []byte("live packet"), protocolPurposeLiveReview, nil,
				protocolSessionConfiguration{liveSourceScope: tc.scope},
			)
			if err != nil {
				t.Fatalf("NewSession(%q) failed: %v", tc.scope, err)
			}
			err, requests := driveScripted(t, driver.(*zcodeProtocolSession),
				protocolCreateResult, protocolSendAck, protocolTurnDone, protocolMessagesResult("report"), protocolCloseResult,
			)
			if err != nil {
				t.Fatalf("Drive(%q) failed: %v", tc.scope, err)
			}
			var foundCreate bool
			for _, request := range requests {
				var message struct {
					Method string
					Params map[string]json.RawMessage
				}
				if err := json.Unmarshal(request, &message); err != nil {
					t.Fatal(err)
				}
				if message.Method != zcodeProtocolCreateMethod {
					continue
				}
				foundCreate = true
				var allowed, denied []string
				if err := json.Unmarshal(message.Params["toolAllowlist"], &allowed); err != nil || !reflect.DeepEqual(allowed, tc.want) {
					t.Fatalf("scope %q toolAllowlist = %v (err=%v), want %v", tc.scope, allowed, err, tc.want)
				}
				if err := json.Unmarshal(message.Params["toolDenylist"], &denied); err != nil || !reflect.DeepEqual(denied, zcodeLiveReviewProtocolDenylist) {
					t.Fatalf("scope %q toolDenylist = %v (err=%v), want %v", tc.scope, denied, err, zcodeLiveReviewProtocolDenylist)
				}
			}
			if !foundCreate {
				t.Fatalf("scope %q missing session/create request", tc.scope)
			}
		})
	}

	t.Run("invalid non-empty scope rejected by NewSession", func(t *testing.T) {
		if _, err := (zcodeProtocolDriverConstructor{}).NewSession(
			"/neutral", []byte("live packet"), protocolPurposeLiveReview, nil,
			protocolSessionConfiguration{liveSourceScope: domain.LiveSourceScope("invalid-scope")},
		); err == nil {
			t.Fatal("NewSession accepted invalid live source scope")
		}
	})

	t.Run("invalid non-empty scope rejected fail-closed in sendCreate", func(t *testing.T) {
		session := liveZCodeProtocolSession(t)
		session.liveSourceScope = domain.LiveSourceScope("invalid-scope")
		driveErr, requests := driveScripted(t, session)
		if driveErr == nil || protocolCause(t, driveErr) != domain.DiagnosticCauseObservationInvalid || len(requests) != 0 {
			t.Fatalf("invalid liveSourceScope in sendCreate: err=%v requests=%d", driveErr, len(requests))
		}
	})

	t.Run("live extraction keeps toolAllowlist empty regardless of scope", func(t *testing.T) {
		for _, scope := range []domain.LiveSourceScope{"", domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead, domain.LiveSourceCommit, domain.LiveSourceDiff} {
			driver, err := (zcodeProtocolDriverConstructor{}).NewSession(
				"/neutral", []byte("extraction packet"), protocolPurposeLiveExtraction, nil,
				protocolSessionConfiguration{liveSourceScope: scope},
			)
			if err != nil {
				t.Fatalf("extraction NewSession(%q) failed: %v", scope, err)
			}
			err, requests := driveScripted(t, driver.(*zcodeProtocolSession),
				protocolCreateResult, protocolSendAck, protocolTurnDone, protocolMessagesResult("extracted"), protocolCloseResult,
			)
			if err != nil {
				t.Fatalf("extraction Drive(%q) failed: %v", scope, err)
			}
			var foundCreate bool
			for _, request := range requests {
				var message struct {
					Method string
					Params map[string]json.RawMessage
				}
				if err := json.Unmarshal(request, &message); err != nil {
					t.Fatal(err)
				}
				if message.Method != zcodeProtocolCreateMethod {
					continue
				}
				foundCreate = true
				if string(message.Params["toolAllowlist"]) != `[]` || string(message.Params["toolDenylist"]) != `["*"]` {
					t.Fatalf("extraction scope %q allow=%s deny=%s", scope, message.Params["toolAllowlist"], message.Params["toolDenylist"])
				}
			}
			if !foundCreate {
				t.Fatalf("extraction scope %q missing session/create", scope)
			}
		}
	})
}

func TestZCodeProtocolAccountAndModelConfigurationFailures(t *testing.T) {
	home, builtin := writeZCodeAccountFixture(t, "account-one", "key-one")
	account, err := loadZCodeAccountRuntime(home, builtin, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name             string
		configureSession func(*zcodeProtocolSession)
		lines            []string
		wantStage        string
		wantErrorCode    int
		hasErrorCode     bool
	}{
		{
			name: "account error response",
			configureSession: func(s *zcodeProtocolSession) {
				s.account = account
			},
			lines:         []string{`{"id":"mulgae-account","error":{"code":-32001,"message":"account rejected"}}`},
			wantStage:     "zcode_account_configuration",
			wantErrorCode: -32001,
			hasErrorCode:  true,
		},
		{
			name: "account revision mismatch",
			configureSession: func(s *zcodeProtocolSession) {
				s.account = account
			},
			lines:     []string{`{"id":"mulgae-account","result":{"receivedRevision":"stale-revision","providerCount":1}}`},
			wantStage: "zcode_account_configuration",
		},
		{
			name: "account provider count mismatch",
			configureSession: func(s *zcodeProtocolSession) {
				s.account = account
			},
			lines:     []string{`{"id":"mulgae-account","result":{"receivedRevision":` + strconvQuote(account.revision) + `,"providerCount":0}}`},
			wantStage: "zcode_account_configuration",
		},
		{
			name: "setModel unavailable",
			configureSession: func(s *zcodeProtocolSession) {
				s.modelSelection = &zcodeModelSelection{ProviderID: "selected", ModelID: "missing"}
			},
			lines: []string{
				protocolCreateResult,
				`{"id":"mulgae-model-0","error":{"code":-32603,"message":"missing","data":{"code":"model_not_found"}}}`,
			},
			wantStage:     "zcode_model_selection",
			wantErrorCode: -32603,
			hasErrorCode:  true,
		},
		{
			name: "setThoughtLevel error",
			configureSession: func(s *zcodeProtocolSession) {
				s.reasoningEffort = "high"
			},
			lines: []string{
				protocolCreateResult,
				`{"id":"mulgae-thought","error":{"code":-32602,"message":"unsupported thought level"}}`,
			},
			wantStage:     "zcode_model_selection",
			wantErrorCode: -32602,
			hasErrorCode:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			tc.configureSession(session)
			driveErr, sent := driveScripted(t, session, tc.lines...)
			var failure *domain.Failure
			if !errors.As(driveErr, &failure) || failure.Class() != domain.FailureConfiguration || failure.Stage() != tc.wantStage {
				t.Fatalf("Drive error = %v, want FailureConfiguration stage %q", driveErr, tc.wantStage)
			}
			if session.AssistantEvidenceText() != nil {
				t.Fatalf("configuration failure retained report bytes: %q", session.AssistantEvidenceText())
			}
			for _, line := range sent {
				if strings.Contains(string(line), `"method":"session/send"`) {
					t.Fatalf("prompt sent after configuration failure: %s", line)
				}
			}
			obs, ok := session.SessionObservation()
			if !ok || obs.Terminal() != ports.ProviderSessionFailed {
				t.Fatalf("observation = %#v, present = %t", obs.Input(), ok)
			}
			if obs.Input().HasProviderErrorCode != tc.hasErrorCode || (tc.hasErrorCode && obs.Input().ProviderErrorCode != tc.wantErrorCode) {
				t.Fatalf("provider error code = (%t, %d), want (%t, %d)", obs.Input().HasProviderErrorCode, obs.Input().ProviderErrorCode, tc.hasErrorCode, tc.wantErrorCode)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		response string
	}{
		{name: "null result", response: `{"id":"mulgae-account","result":null}`},
		{name: "missing result", response: `{"id":"mulgae-account"}`},
		{name: "malformed result", response: `{"id":"mulgae-account","result":"ok"}`},
	} {
		t.Run("account envelope "+tc.name, func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			session.account = account
			driveErr, sent := driveScripted(t, session, tc.response)
			if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseOutputEnvelopeInvalid {
				t.Fatalf("cause = %q, want %q (err=%v)", cause, domain.DiagnosticCauseOutputEnvelopeInvalid, driveErr)
			}
			var failure *domain.Failure
			if errors.As(driveErr, &failure) {
				t.Fatalf("envelope failure was misclassified as domain.Failure: %v", driveErr)
			}
			if len(sent) != 1 || session.AssistantEvidenceText() != nil {
				t.Fatalf("unexpected continuation after invalid account envelope: sent=%d text=%q", len(sent), session.AssistantEvidenceText())
			}
		})
	}
}

func TestZCodeProtocolGuardsPrematureCreateAndSendDuringConfiguration(t *testing.T) {
	home, builtin := writeZCodeAccountFixture(t, "account-one", "key-one")
	account, err := loadZCodeAccountRuntime(home, builtin, "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("premature create result while accountPending fails closed", func(t *testing.T) {
		session := liveZCodeProtocolSession(t)
		session.account = account
		driveErr, sent := driveScripted(t, session,
			protocolCreateResult,
			protocolSendAck,
			protocolTurnDone,
			protocolMessagesResult("spoofed"),
			protocolCloseResult,
		)
		if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseOutputEnvelopeInvalid {
			t.Fatalf("cause = %q, want %q (err=%v)", cause, domain.DiagnosticCauseOutputEnvelopeInvalid, driveErr)
		}
		if len(sent) != 1 || !strings.Contains(string(sent[0]), `"method":"provider/updateAccountConfig"`) {
			t.Fatalf("sent = %q, want only provider/updateAccountConfig", sent)
		}
		if obs, ok := session.SessionObservation(); !ok || obs.Input().CreateAccepted || obs.Input().SendAccepted {
			t.Fatalf("observation = %#v (ok=%t), want CreateAccepted=false SendAccepted=false", obs.Input(), ok)
		}
		if session.AssistantEvidenceText() != nil {
			t.Fatalf("premature create retained evidence: %q", session.AssistantEvidenceText())
		}
	})

	t.Run("premature create error while accountPending cannot override account failure", func(t *testing.T) {
		session := liveZCodeProtocolSession(t)
		session.account = account
		driveErr, sent := driveScripted(t, session,
			`{"id":"mulgae-create","error":{"code":-32099,"message":"premature create"}}`,
			`{"id":"mulgae-account","error":{"code":-32001,"message":"account rejected"}}`,
		)
		var failure *domain.Failure
		if !errors.As(driveErr, &failure) || failure.Class() != domain.FailureConfiguration || failure.Stage() != "zcode_account_configuration" {
			t.Fatalf("Drive error = %v, want FailureConfiguration stage zcode_account_configuration", driveErr)
		}
		if obs, ok := session.SessionObservation(); !ok || !obs.Input().HasProviderErrorCode || obs.Input().ProviderErrorCode != -32001 {
			t.Fatalf("observation = %#v (ok=%t), want providerErrorCode=-32001", obs.Input(), ok)
		}
		if len(sent) != 1 || session.AssistantEvidenceText() != nil {
			t.Fatalf("unexpected sent=%d or evidence=%q", len(sent), session.AssistantEvidenceText())
		}
	})

	t.Run("premature create error alone while accountPending fails closed without create", func(t *testing.T) {
		session := liveZCodeProtocolSession(t)
		session.account = account
		driveErr, sent := driveScripted(t, session,
			`{"id":"mulgae-create","error":{"code":-32099,"message":"premature create"}}`,
		)
		if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseProviderTurnFailed {
			t.Fatalf("cause = %q, want %q (err=%v)", cause, domain.DiagnosticCauseProviderTurnFailed, driveErr)
		}
		if obs, ok := session.SessionObservation(); !ok || obs.Input().HasProviderErrorCode || obs.Input().CreateAccepted {
			t.Fatalf("observation = %#v (ok=%t), want uncorrelated error ignored", obs.Input(), ok)
		}
		if len(sent) != 1 || session.AssistantEvidenceText() != nil {
			t.Fatalf("unexpected sent=%d or evidence=%q", len(sent), session.AssistantEvidenceText())
		}
	})

	for _, tc := range []struct {
		name             string
		configureSession func(*zcodeProtocolSession)
		realConfigError  string
		wantErrorCode    int
	}{
		{
			name: "modelRequestPending",
			configureSession: func(s *zcodeProtocolSession) {
				s.modelSelection = &zcodeModelSelection{ProviderID: "selected", ModelID: "missing"}
			},
			realConfigError: `{"id":"mulgae-model-0","error":{"code":-32603,"message":"missing","data":{"code":"model_not_found"}}}`,
			wantErrorCode:   -32603,
		},
		{
			name: "thoughtRequestPending",
			configureSession: func(s *zcodeProtocolSession) {
				s.reasoningEffort = "high"
			},
			realConfigError: `{"id":"mulgae-thought","error":{"code":-32602,"message":"unsupported thought level"}}`,
			wantErrorCode:   -32602,
		},
	} {
		t.Run("premature send result while "+tc.name+" fails closed", func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			tc.configureSession(session)
			driveErr, sent := driveScripted(t, session,
				protocolCreateResult,
				protocolSendAck,
				protocolTurnDone,
				protocolMessagesResult("spoofed"),
				protocolCloseResult,
			)
			if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseOutputEnvelopeInvalid {
				t.Fatalf("cause = %q, want %q (err=%v)", cause, domain.DiagnosticCauseOutputEnvelopeInvalid, driveErr)
			}
			if len(sent) != 2 {
				t.Fatalf("sent = %d (%q), want create + pending configuration request only", len(sent), sent)
			}
			for _, line := range sent {
				if strings.Contains(string(line), `"method":"session/send"`) {
					t.Fatalf("prompt sent prematurely: %s", line)
				}
			}
			if obs, ok := session.SessionObservation(); !ok || obs.Input().SendAccepted {
				t.Fatalf("observation = %#v (ok=%t), want SendAccepted=false", obs.Input(), ok)
			}
			if session.AssistantEvidenceText() != nil {
				t.Fatalf("premature send retained evidence: %q", session.AssistantEvidenceText())
			}
		})

		t.Run("premature send error while "+tc.name+" cannot override config failure", func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			tc.configureSession(session)
			driveErr, sent := driveScripted(t, session,
				protocolCreateResult,
				`{"id":"mulgae-send","error":{"code":-32098,"message":"premature send"}}`,
				tc.realConfigError,
			)
			var failure *domain.Failure
			if !errors.As(driveErr, &failure) || failure.Class() != domain.FailureConfiguration || failure.Stage() != "zcode_model_selection" {
				t.Fatalf("Drive error = %v, want FailureConfiguration stage zcode_model_selection", driveErr)
			}
			if obs, ok := session.SessionObservation(); !ok || !obs.Input().HasProviderErrorCode || obs.Input().ProviderErrorCode != tc.wantErrorCode {
				t.Fatalf("observation = %#v (ok=%t), want providerErrorCode=%d", obs.Input(), ok, tc.wantErrorCode)
			}
			if len(sent) != 2 || session.AssistantEvidenceText() != nil {
				t.Fatalf("unexpected sent=%d or evidence=%q", len(sent), session.AssistantEvidenceText())
			}
		})

		t.Run("premature send error alone while "+tc.name+" fails closed without send", func(t *testing.T) {
			session := liveZCodeProtocolSession(t)
			tc.configureSession(session)
			driveErr, sent := driveScripted(t, session,
				protocolCreateResult,
				`{"id":"mulgae-send","error":{"code":-32098,"message":"premature send"}}`,
			)
			if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseProviderTurnFailed {
				t.Fatalf("cause = %q, want %q (err=%v)", cause, domain.DiagnosticCauseProviderTurnFailed, driveErr)
			}
			if obs, ok := session.SessionObservation(); !ok || obs.Input().HasProviderErrorCode || obs.Input().SendAccepted {
				t.Fatalf("observation = %#v (ok=%t), want uncorrelated error ignored", obs.Input(), ok)
			}
			if len(sent) != 2 || session.AssistantEvidenceText() != nil {
				t.Fatalf("unexpected sent=%d or evidence=%q", len(sent), session.AssistantEvidenceText())
			}
		})
	}
}
