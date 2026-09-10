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
			name:        "unreadable notification params are an output decode failure",
			serverLines: []string{protocolCreateResult, protocolSendAck, `{"method":"computer-use/operation-event","params":{"kind":42}}`},
			wantCause:   domain.DiagnosticCauseOutputDecodeFailed,
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
