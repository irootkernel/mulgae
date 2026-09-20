package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// driveScripted runs one driver against scripted server lines and returns the
// driver error plus every client line the exchange recorded.
func driveScripted(t *testing.T, session *zcodeProtocolSession, serverLines ...string) (error, [][]byte) {
	t.Helper()
	exchange := newScriptedProtocolExchange(serverLines...)
	err := session.Drive(context.Background(), exchange)
	return err, exchange.sentLines(t)
}

func protocolCause(t *testing.T, err error) domain.RuntimeDiagnosticCause {
	t.Helper()
	var failure *zcodeProtocolError
	if !errors.As(err, &failure) {
		t.Fatalf("driver error = %#v, want a typed protocol failure", err)
	}
	return failure.Cause()
}

const (
	protocolCreateResult = `{"id":"mulgae-create","result":{"session":{"sessionId":"sess_script"}}}`
	protocolSendAck      = `{"id":"mulgae-send","result":{"accepted":true,"sessionId":"sess_script","stateRevision":1}}`
	protocolTurnDone     = `{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_script","sessionId":"sess_script"}}`
	protocolCloseResult  = `{"id":"mulgae-close","result":{"closed":true}}`
	protocolPrefsRequest = `{"id":"server-1","method":"session/requestRuntimePreferences","params":{"sessionId":"sess_script","scope":"runtime-materialization"}}`
	proofText            = `{"root":"nonce","link":"linked","role":"logic"}`
)

func protocolMessagesResult(proof string) string {
	return `{"id":"mulgae-messages","result":{"messages":[{"info":{"role":"assistant"},"parts":[{"type":"text","text":` + strconvQuote(proof) + `}]},{"info":{"role":"user"},"parts":[{"type":"text","text":"prompt"}]}]}}`
}

func protocolModelResult(candidate int, reasoning string) string {
	selection := `{"providerId":"selected","modelId":"model","options":{"reasoningLevel":` + strconvQuote(reasoning) + `}}`
	sessionModel := `{"providerId":"selected","modelId":"model"}`
	return `{"id":"mulgae-model-` + fmt.Sprintf("%d", candidate) + `","result":{"protocol":{"name":"ZCode Protocol","version":1},"session":{"sessionId":"sess_script","model":` + sessionModel + `},"settings":{"model":{"current":` + selection + `}}}}`
}

func strconvQuote(value string) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(payload)
}

func mustReviewSession(t *testing.T) *zcodeProtocolSession {
	t.Helper()
	session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"))
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func mustCapabilitySession(t *testing.T) *zcodeProtocolSession {
	t.Helper()
	session, err := newZcodeCapabilityProtocolSession("/private/work", []byte("capability packet"))
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestZCodeProtocolPinsLegacySelectionBeforeSendingPrompt(t *testing.T) {
	session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "model"})
	if err != nil {
		t.Fatal(err)
	}
	err, sent := driveScripted(t, session,
		protocolCreateResult,
		`{"id":"mulgae-model-0","error":{"code":-32603,"message":"Reasoning effort \"max\" is not supported","data":{"code":"invalid_model_request"}}}`,
		`{"id":"mulgae-model-1","error":{"code":-32603,"message":"Reasoning effort \"xhigh\" is not supported","data":{"code":"invalid_model_request"}}}`,
		protocolModelResult(2, "high"),
		protocolSendAck, protocolTurnDone, protocolCloseResult,
	)
	if err != nil {
		t.Fatalf("Drive failed: %v", err)
	}
	if len(sent) != 6 {
		t.Fatalf("client lines = %d, want create, three model attempts, send, close: %s", len(sent), sent)
	}
	for index, reasoning := range []string{"max", "xhigh", "high"} {
		var request struct {
			Method string `json:"method"`
			Params struct {
				SessionID string `json:"sessionId"`
				Model     struct {
					ProviderID string `json:"providerId"`
					ModelID    string `json:"modelId"`
					Options    struct {
						ReasoningLevel string `json:"reasoningLevel"`
					} `json:"options"`
				} `json:"model"`
				Persist bool `json:"persistAsWorkspaceLastUsed"`
			} `json:"params"`
		}
		if err := json.Unmarshal(sent[index+1], &request); err != nil {
			t.Fatal(err)
		}
		if request.Method != zcodeProtocolSetModelMethod || request.Params.SessionID != "sess_script" ||
			request.Params.Model.ProviderID != "selected" || request.Params.Model.ModelID != "model" ||
			request.Params.Model.Options.ReasoningLevel != reasoning || request.Params.Persist {
			t.Fatalf("model request %d = %#v", index, request)
		}
	}
	var send struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(sent[4], &send); err != nil || send.Method != zcodeProtocolSendMethod {
		t.Fatalf("post-selection request = %s, %v", sent[4], err)
	}
}

func TestZCodeProtocolIgnoresModelResponseBeforeRequest(t *testing.T) {
	session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "model"})
	if err != nil {
		t.Fatal(err)
	}
	premature := strings.Replace(protocolModelResult(0, "max"), `"sessionId":"sess_script"`, `"sessionId":""`, 1)
	driveErr, sent := driveScripted(t, session,
		premature, protocolCreateResult, protocolModelResult(0, "max"),
		protocolSendAck, protocolTurnDone, protocolCloseResult,
	)
	if driveErr != nil {
		t.Fatalf("Drive failed after inert premature response: %v", driveErr)
	}
	if len(sent) != 4 {
		t.Fatalf("client lines = %d, want create, model, send, close: %s", len(sent), sent)
	}
	var modelRequest struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(sent[1], &modelRequest); err != nil || modelRequest.Method != zcodeProtocolSetModelMethod {
		t.Fatalf("request after create = %s, %v", sent[1], err)
	}
}

func TestZCodeProtocolRejectsUnavailableLegacySelectionBeforePrompt(t *testing.T) {
	session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{protocolCreateResult}
	for index, reasoning := range zcodeProtocolReasoningCandidates {
		lines = append(lines, `{"id":"mulgae-model-`+fmt.Sprintf("%d", index)+`","error":{"code":-32603,"message":"Reasoning effort `+reasoning+` is not supported","data":{"code":"invalid_model_request"}}}`)
	}
	err, sent := driveScripted(t, session, lines...)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
		t.Fatalf("Drive error = %v, want configuration_violation", err)
	}
	if len(sent) != 1+len(zcodeProtocolReasoningCandidates) {
		t.Fatalf("client lines = %d, want create plus bounded model attempts", len(sent))
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.Phase() != ports.ProviderSessionPhaseModel || observation.Terminal() != ports.ProviderSessionFailed {
		t.Fatalf("selection failure observation = %#v, present = %t", observation.Input(), ok)
	}
	for _, line := range sent {
		if strings.Contains(string(line), `"method":"session/send"`) {
			t.Fatalf("prompt sent after selection rejection: %s", line)
		}
	}
}

func TestZCodeProtocolDoesNotMisclassifyModelSelectionServerFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
	}{
		{
			name:     "missing model is configuration",
			response: `{"id":"mulgae-model-0","error":{"code":-32603,"message":"missing","data":{"code":"model_not_found"}}}`,
		},
		{name: "provider not configured is configuration", response: `{"id":"mulgae-model-0","error":{"code":-32603,"message":"missing","data":{"code":"provider_not_configured"}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "model"})
			if err != nil {
				t.Fatal(err)
			}
			err, sent := driveScripted(t, session, protocolCreateResult, test.response)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration {
				t.Fatalf("Drive error = %v, want configuration_violation", err)
			}
			if len(sent) != 2 {
				t.Fatalf("client lines = %d, want create plus one model request", len(sent))
			}
			if strings.Contains(string(sent[len(sent)-1]), `"method":"session/send"`) {
				t.Fatalf("prompt sent after selection rejection: %s", sent[len(sent)-1])
			}
		})
	}
}

func TestZCodeProtocolRejectsUnverifiedModelSelectionSuccess(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
	}{
		{name: "id only", response: `{"id":"mulgae-model-0"}`},
		{name: "null result", response: `{"id":"mulgae-model-0","result":null}`},
		{name: "malformed result", response: `{"id":"mulgae-model-0","result":"accepted"}`},
		{name: "wrong session", response: strings.Replace(protocolModelResult(0, "max"), "sess_script", "other", 1)},
		{name: "wrong model", response: strings.ReplaceAll(protocolModelResult(0, "max"), `"modelId":"model"`, `"modelId":"other"`)},
		{name: "missing session model", response: strings.Replace(protocolModelResult(0, "max"), `,"model":{"providerId":"selected","modelId":"model"}`, "", 1)},
		{name: "wrong session model", response: strings.Replace(protocolModelResult(0, "max"), `"modelId":"model"`, `"modelId":"other"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "model"})
			if err != nil {
				t.Fatal(err)
			}
			driveErr, sent := driveScripted(t, session, protocolCreateResult, test.response)
			if cause := protocolCause(t, driveErr); cause != domain.DiagnosticCauseOutputEnvelopeInvalid {
				t.Fatalf("cause = %q, want %q", cause, domain.DiagnosticCauseOutputEnvelopeInvalid)
			}
			for _, line := range sent {
				if strings.Contains(string(line), `"method":"session/send"`) {
					t.Fatalf("prompt sent after invalid model result: %s", line)
				}
			}
		})
	}
}

func TestZCodeProtocolClassifiesNonConfigurationModelSelectionFailures(t *testing.T) {
	for _, test := range []struct {
		code string
		want domain.RuntimeDiagnosticCause
	}{
		{code: "model_request_auth_missing", want: domain.DiagnosticCauseAuthenticationFailed},
		{code: "model_rate_limited", want: domain.DiagnosticCauseRateLimited},
		{code: "model_request_timeout", want: domain.DiagnosticCauseTimedOut},
		{code: "model_request_failed", want: domain.DiagnosticCauseProviderExecutionFailed},
		{code: "invalid_model_response", want: domain.DiagnosticCauseProviderExecutionFailed},
	} {
		t.Run(test.code, func(t *testing.T) {
			session, err := newZcodeReviewProtocolSession("/private/work", []byte("review packet"), &zcodeModelSelection{ProviderID: "selected", ModelID: "model"})
			if err != nil {
				t.Fatal(err)
			}
			response := `{"id":"mulgae-model-0","error":{"code":-32603,"message":"failure","data":{"code":` + strconvQuote(test.code) + `}}}`
			driveErr, _ := driveScripted(t, session, protocolCreateResult, response)
			if cause := protocolCause(t, driveErr); cause != test.want {
				t.Fatalf("cause = %q, want %q", cause, test.want)
			}
			var configuration *domain.Failure
			if errors.As(driveErr, &configuration) {
				t.Fatalf("non-configuration error was projected as configuration: %v", driveErr)
			}
		})
	}
}

// TestZCodeProtocolDriveClassifiesFailureBranches pins the typed cause of every
// protocol-native failure branch of the conversation state machine.
func TestZCodeProtocolDriveClassifiesFailureBranches(t *testing.T) {
	for _, test := range []struct {
		name string
		// review selects the review session; otherwise the capability session
		// with assistant capture drives the messages branch.
		review      bool
		serverLines []string
		wantCause   domain.RuntimeDiagnosticCause
		wantText    string
	}{
		{
			name:        "unparseable line is an output decode failure",
			review:      true,
			serverLines: []string{"not json at all"},
			wantCause:   domain.DiagnosticCauseOutputDecodeFailed,
			wantText:    "decode message",
		},
		{
			name:        "message without id or method is an output decode failure",
			review:      true,
			serverLines: []string{`{"unexpected":"shape"}`},
			wantCause:   domain.DiagnosticCauseOutputDecodeFailed,
			wantText:    "without id or method",
		},
		{
			name:        "stream end before turn completion is a provider turn failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolSendAck},
			wantCause:   domain.DiagnosticCauseProviderTurnFailed,
			wantText:    "turn completion missing",
		},
		{
			name:        "turn failed notification is a provider turn failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_1"}}`},
			wantCause:   domain.DiagnosticCauseProviderTurnFailed,
			wantText:    "provider turn turn_1 failed",
		},
		{
			name:        "create error response is a provider execution failure",
			review:      true,
			serverLines: []string{`{"id":"mulgae-create","error":{"code":-32000,"message":"workspace rejected"}}`},
			wantCause:   domain.DiagnosticCauseProviderExecutionFailed,
			wantText:    "request \"mulgae-create\" failed: workspace rejected",
		},
		{
			name:        "send error response is a provider execution failure",
			review:      true,
			serverLines: []string{protocolCreateResult, `{"id":"mulgae-send","error":{"code":-32000,"message":"prompt refused"}}`},
			wantCause:   domain.DiagnosticCauseProviderExecutionFailed,
			wantText:    "request \"mulgae-send\" failed: prompt refused",
		},
		{
			name:        "close error response is a provider execution failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolSendAck, protocolTurnDone, `{"id":"mulgae-close","error":{"code":-32000,"message":"close refused"}}`},
			wantCause:   domain.DiagnosticCauseProviderExecutionFailed,
			wantText:    "session close failed: close refused",
		},
		{
			name:        "create result without session id is an envelope failure",
			review:      true,
			serverLines: []string{`{"id":"mulgae-create","result":{"session":{}}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "without a session id",
		},
		{
			name:        "unreadable create result is an envelope failure",
			review:      true,
			serverLines: []string{`{"id":"mulgae-create","result":{"session":42}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "unreadable session create result",
		},
		{
			name:        "rejected send result is an envelope failure",
			review:      true,
			serverLines: []string{protocolCreateResult, `{"id":"mulgae-send","result":{"accepted":false}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "session send was not accepted",
		},
		{
			name:        "duplicate create response is an envelope failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolCreateResult},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "duplicate session create response",
		},
		{
			name:        "turn completed before establishment is an envelope failure",
			review:      true,
			serverLines: []string{protocolTurnDone},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "before the conversation was established",
		},
		{
			name:        "send response before create is an envelope failure",
			review:      true,
			serverLines: []string{protocolSendAck},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "before the conversation was established",
		},
		{
			name:        "turn failed before establishment is an envelope failure",
			review:      true,
			serverLines: []string{`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_1","sessionId":"sess_forged"}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "before the conversation was established",
		},
		{
			name:        "completed turn session mismatch is an envelope failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_1","sessionId":"sess_other"}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "does not match the established conversation",
		},
		{
			name:        "failed turn session mismatch is an envelope failure",
			review:      true,
			serverLines: []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_1","sessionId":"sess_other"}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "does not match the established conversation",
		},
		{
			name:        "unreadable messages result is an envelope failure",
			serverLines: []string{protocolCreateResult, protocolSendAck, protocolTurnDone, `{"id":"mulgae-messages","result":{"messages":"not-an-array"}}`},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "unreadable session messages result",
		},
		{
			name:        "unexpected messages response is an envelope failure",
			serverLines: []string{protocolCreateResult, protocolSendAck, protocolMessagesResult(proofText)},
			wantCause:   domain.DiagnosticCauseOutputEnvelopeInvalid,
			wantText:    "unexpected session messages response",
		},
		{
			name:        "unreadable recognized event params are a protocol event decode failure",
			serverLines: []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":42}}`},
			wantCause:   domain.DiagnosticCauseProtocolEventDecodeFailed,
			wantText:    "unreadable protocol event payload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := mustCapabilitySession(t)
			if test.review {
				session = mustReviewSession(t)
			}
			err, _ := driveScripted(t, session, test.serverLines...)
			if err == nil {
				t.Fatal("Drive succeeded for a failure script")
			}
			if cause := protocolCause(t, err); cause != test.wantCause {
				t.Fatalf("cause = %q, want %q (error %v)", cause, test.wantCause, err)
			}
			if !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("error %q does not contain %q", err.Error(), test.wantText)
			}
		})
	}
}

func TestZCodeProtocolFailurePreservesSessionCorrelation(t *testing.T) {
	session := mustReviewSession(t)
	err, _ := driveScripted(t, session, protocolCreateResult, protocolSendAck,
		`{"method":"computer-use/operation-event","params":{"kind":"turn-failed","turnId":"turn_private","sessionId":"sess_script"}}`)
	if err == nil {
		t.Fatal("Drive succeeded")
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.ProviderSessionID() != "sess_script" || observation.ProviderTurnID() != "turn_private" ||
		observation.Phase() != ports.ProviderSessionPhaseTurn || observation.Terminal() != ports.ProviderSessionFailed {
		t.Fatalf("observation = %#v, present = %t", observation.Input(), ok)
	}
	create, send, turn, messages, closeSent, closeAccepted := observation.Receipts()
	if !create || !send || !turn || messages || closeSent || closeAccepted {
		t.Fatalf("receipts = %t/%t/%t/%t/%t/%t", create, send, turn, messages, closeSent, closeAccepted)
	}
}

func TestSafeZCodeDiagnosticIdentifierMatchesPortAdmission(t *testing.T) {
	for _, value := range []string{
		" leading",
		"trailing ",
		"embedded\ttab",
		"embedded\u0085control",
	} {
		if got := safeZcodeDiagnosticIdentifier(value); got != "" {
			t.Fatalf("safe identifier %q = %q, want omitted", value, got)
		}
	}
	if got := safeZcodeDiagnosticIdentifier("session_safe"); got != "session_safe" {
		t.Fatalf("safe identifier = %q, want session_safe", got)
	}
}

func TestZCodeProtocolUnsafeCorrelationDoesNotFailCompletedReview(t *testing.T) {
	session := mustReviewSession(t)
	err, _ := driveScripted(t, session,
		`{"id":"mulgae-create","result":{"session":{"sessionId":" session_private"}}}`,
		`{"id":"mulgae-send","result":{"accepted":true,"sessionId":" session_private","stateRevision":1}}`,
		`{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn\tprivate","sessionId":" session_private"}}`,
		protocolCloseResult,
	)
	if err != nil {
		t.Fatalf("completed review failed on diagnostic-only correlation: %v", err)
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.Terminal() != ports.ProviderSessionCompleted || observation.ProviderSessionID() != "" || observation.ProviderTurnID() != "" {
		t.Fatalf("sanitized completed observation = %#v, present = %t", observation.Input(), ok)
	}
}

func TestZCodeProtocolPreservesFirstTerminalTurnCorrelation(t *testing.T) {
	session := mustReviewSession(t)
	err, _ := driveScripted(t, session,
		protocolCreateResult,
		protocolSendAck,
		protocolTurnDone,
		`{"method":"computer-use/operation-event","params":{"kind":"turn-completed","turnId":"turn_late","sessionId":"sess_script"}}`,
		protocolCloseResult,
	)
	if err != nil {
		t.Fatalf("Drive failed: %v", err)
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.ProviderTurnID() != "turn_script" {
		t.Fatalf("terminal turn correlation = %q, present = %t", observation.ProviderTurnID(), ok)
	}
}

// failingSendExchange accepts a fixed number of client sends and then fails
// every further send with a persistent pipe error.
type failingSendExchange struct {
	inner    *scriptedProtocolExchange
	succeeds int
	failures int
	failWith error
}

func (exchange *failingSendExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	return exchange.inner.ReceiveLine(ctx)
}

func (exchange *failingSendExchange) SendLine(ctx context.Context, line []byte) error {
	if exchange.succeeds > 0 {
		exchange.succeeds--
		return exchange.inner.SendLine(ctx, line)
	}
	exchange.failures++
	return exchange.failWith
}

// TestZCodeProtocolDriveClassifiesSendFailures pins the typed classification
// of client-side send failures inside the driver.
func TestZCodeProtocolDriveClassifiesSendFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		succeeds    int
		serverLines []string
		wantText    string
	}{
		{
			name:        "create send failure",
			succeeds:    0,
			serverLines: nil,
			wantText:    "zcode protocol: send session/create request",
		},
		{
			name:        "runtime-preferences response send failure",
			succeeds:    1,
			serverLines: []string{protocolPrefsRequest, protocolCreateResult},
			wantText:    "zcode protocol: send response",
		},
		{
			name:        "turn send failure",
			succeeds:    1,
			serverLines: []string{protocolCreateResult},
			wantText:    "zcode protocol: send session/send request",
		},
		{
			name:        "close send failure",
			succeeds:    2,
			serverLines: []string{protocolCreateResult, protocolSendAck, protocolTurnDone},
			wantText:    "zcode protocol: send session/close request",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchange := &failingSendExchange{
				inner:    newScriptedProtocolExchange(test.serverLines...),
				succeeds: test.succeeds,
				failWith: errors.New("broken pipe"),
			}
			session := mustReviewSession(t)
			err := session.Drive(context.Background(), exchange)
			if err == nil {
				t.Fatal("Drive succeeded with a failing send")
			}
			if cause := protocolCause(t, err); cause != domain.DiagnosticCauseProviderExecutionFailed {
				t.Fatalf("cause = %q, want provider execution failure (error %v)", cause, err)
			}
			if !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("error %q does not contain %q", err.Error(), test.wantText)
			}
			if exchange.failures == 0 {
				t.Fatal("exchange never observed the failing send")
			}
		})
	}
}

// TestZCodeProtocolDriveCompletesAndPreservesEvidence covers the happy path,
// the inertness of uncorrelated responses, and evidence preservation when the
// stream ends after turn completion instead of delivering the close response.
func TestZCodeProtocolDriveCompletesAndPreservesEvidence(t *testing.T) {
	t.Run("review conversation closes cleanly", func(t *testing.T) {
		session := mustReviewSession(t)
		err, _ := driveScripted(t, session, protocolCreateResult, protocolSendAck, protocolTurnDone, protocolCloseResult)
		if err != nil {
			t.Fatalf("Drive failed: %v", err)
		}
	})
	t.Run("uncorrelated responses stay inert", func(t *testing.T) {
		session := mustReviewSession(t)
		err, _ := driveScripted(t, session,
			protocolCreateResult,
			`{"id":"unrelated","result":{"ignored":true}}`,
			`{"id":"unrelated","error":{"code":-32000,"message":"someone else"}}`,
			protocolSendAck,
			protocolTurnDone,
			protocolCloseResult,
		)
		if err != nil {
			t.Fatalf("Drive failed with inert uncorrelated responses: %v", err)
		}
	})
	t.Run("additive telemetry notifications stay inert", func(t *testing.T) {
		session := mustReviewSession(t)
		err, _ := driveScripted(t, session,
			protocolCreateResult,
			protocolSendAck,
			`{"method":"process/resourceSample","params":{"rssKbTotal":1024}}`,
			`{"method":"process/mcpResourceSamples","params":[{"mcpId":"one"},{"mcpId":"two"},{"mcpId":"three"}]}`,
			protocolTurnDone,
			protocolCloseResult,
		)
		if err != nil {
			t.Fatalf("Drive failed with inert telemetry notifications: %v", err)
		}
	})
	t.Run("stream end after turn completion preserves captured evidence", func(t *testing.T) {
		session := mustCapabilitySession(t)
		// The stream ends after the messages result but before the close
		// response, so the driver ends through the stream-end path with the
		// captured assistant evidence intact.
		err, _ := driveScripted(t, session, protocolCreateResult, protocolSendAck, protocolTurnDone, protocolMessagesResult(proofText))
		if err != nil {
			t.Fatalf("Drive failed: %v", err)
		}
		if got := string(session.assistantEvidenceText()); got != proofText {
			t.Fatalf("assistant evidence = %q, want %q", got, proofText)
		}
	})
	t.Run("stream end before the messages response still ends cleanly", func(t *testing.T) {
		session := mustCapabilitySession(t)
		err, _ := driveScripted(t, session, protocolCreateResult, protocolSendAck, protocolTurnDone)
		if err != nil {
			t.Fatalf("Drive failed: %v", err)
		}
		if evidence := session.assistantEvidenceText(); evidence != nil {
			t.Fatalf("assistant evidence = %q, want none", evidence)
		}
	})
}

// TestZCodeProtocolDriveRequestShapes pins the exact client requests: the
// create parameters per session kind, the fixed runtime-preferences response,
// the send content binding, and the close request shape.
func TestZCodeProtocolDriveRequestShapes(t *testing.T) {
	assertJSONField := func(t *testing.T, raw []byte, path ...string) any {
		t.Helper()
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("client line %q is not JSON: %v", raw, err)
		}
		for _, key := range path {
			object, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("client line %q: %v is not an object at %v", raw, value, path)
			}
			value, ok = object[key]
			if !ok {
				t.Fatalf("client line %q: missing key %v in %v", raw, key, path)
			}
		}
		return value
	}
	t.Run("review conversation", func(t *testing.T) {
		session := mustReviewSession(t)
		err, sent := driveScripted(t, session, protocolPrefsRequest, protocolCreateResult, protocolSendAck, protocolTurnDone, protocolCloseResult)
		if err != nil {
			t.Fatalf("Drive failed: %v", err)
		}
		if len(sent) != 4 {
			t.Fatalf("client lines = %d, want 4 (create, preferences, send, close): %s", len(sent), sent)
		}
		if got := assertJSONField(t, sent[0], "method"); got != "session/create" {
			t.Fatalf("first request method = %v", got)
		}
		for key, want := range map[string]any{
			"mode":                   "yolo",
			"titleGenerationEnabled": false,
		} {
			if got := assertJSONField(t, sent[0], "params", key); got != want {
				t.Fatalf("create params %s = %v, want %v", key, got, want)
			}
		}
		if got := assertJSONField(t, sent[0], "params", "workspace", "workspacePath"); got != "/private/work" {
			t.Fatalf("workspace path = %v", got)
		}
		if got := assertJSONField(t, sent[0], "params", "workspace", "workspaceKey"); got != "/private/work" {
			t.Fatalf("workspace key = %v", got)
		}
		denylist, ok := assertJSONField(t, sent[0], "params", "toolDenylist").([]any)
		if !ok || len(denylist) != len(zcodeReviewProtocolDenylist) {
			t.Fatalf("denylist = %#v", denylist)
		}
		for index, denied := range zcodeReviewProtocolDenylist {
			if denylist[index] != denied {
				t.Fatalf("denylist[%d] = %v, want %q", index, denylist[index], denied)
			}
		}
		if got := assertJSONField(t, sent[1], "id"); got != "server-1" {
			t.Fatalf("preferences response id = %v", got)
		}
		if _, hasResult := any(assertJSONField(t, sent[1], "result")).(map[string]any); !hasResult {
			t.Fatalf("preferences response result = %#v", sent[1])
		}
		for key, want := range map[string]any{
			"nativeSearchEnhancementsEnabled":      false,
			"memoryEnabled":                        false,
			"askUserQuestionAutoResolutionEnabled": true,
		} {
			if got := assertJSONField(t, sent[1], "result", key); got != want {
				t.Fatalf("preferences %s = %v, want %v", key, got, want)
			}
		}
		if got := assertJSONField(t, sent[2], "method"); got != "session/send" {
			t.Fatalf("send request method = %v", got)
		}
		if got := assertJSONField(t, sent[2], "params", "sessionId"); got != "sess_script" {
			t.Fatalf("send session id = %v", got)
		}
		if got := assertJSONField(t, sent[2], "params", "content"); got != "review packet" {
			t.Fatalf("send content = %v", got)
		}
		if got := assertJSONField(t, sent[3], "method"); got != "session/close" {
			t.Fatalf("close request method = %v", got)
		}
		if got := assertJSONField(t, sent[3], "params", "sessionId"); got != "sess_script" {
			t.Fatalf("close session id = %v", got)
		}
		var closeParams struct {
			Params map[string]json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(sent[3], &closeParams); err != nil {
			t.Fatalf("close request is not JSON: %v", err)
		}
		if len(closeParams.Params) != 1 {
			t.Fatalf("close request carries unexpected fields: %s", sent[3])
		}
	})
	t.Run("capability conversation", func(t *testing.T) {
		session := mustCapabilitySession(t)
		err, sent := driveScripted(t, session, protocolCreateResult, protocolSendAck, protocolTurnDone, protocolMessagesResult(proofText), protocolCloseResult)
		if err != nil {
			t.Fatalf("Drive failed: %v", err)
		}
		if len(sent) != 4 {
			t.Fatalf("client lines = %d, want 4 (create, send, messages, close): %s", len(sent), sent)
		}
		if got := assertJSONField(t, sent[0], "params", "mode"); got != "plan" {
			t.Fatalf("capability mode = %v", got)
		}
		denylist, ok := assertJSONField(t, sent[0], "params", "toolDenylist").([]any)
		if !ok || len(denylist) != 1 || denylist[0] != "*" {
			t.Fatalf("capability denylist = %#v", denylist)
		}
		if got := assertJSONField(t, sent[2], "method"); got != "session/messages" {
			t.Fatalf("messages request method = %v", got)
		}
		if got := assertJSONField(t, sent[2], "params", "limit"); got != float64(8) {
			t.Fatalf("messages limit = %v", got)
		}
		if got := string(session.assistantEvidenceText()); got != proofText {
			t.Fatalf("assistant evidence = %q, want %q", got, proofText)
		}
	})
}
