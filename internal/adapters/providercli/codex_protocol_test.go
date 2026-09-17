package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
)

type scriptedCodexExchange struct {
	lines []string
	sent  [][]byte
}

func (exchange *scriptedCodexExchange) ReceiveLine(context.Context) ([]byte, error) {
	if len(exchange.lines) == 0 {
		return nil, io.EOF
	}
	line := exchange.lines[0]
	exchange.lines = exchange.lines[1:]
	return []byte(line), nil
}

func (exchange *scriptedCodexExchange) SendLine(_ context.Context, line []byte) error {
	exchange.sent = append(exchange.sent, append([]byte(nil), line...))
	return nil
}

func codexSuccessFrames() []string {
	return []string{
		`{"id":1,"result":{"userAgent":"mulgae"}}`,
		`{"id":2,"result":{"thread":{"id":"thread-1","ephemeral":true},"instructionSources":[]}}`,
		`{"id":3,"result":{"turn":{"id":"turn-1","status":"inProgress"}}}`,
		`{"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":"item-1","type":"agentMessage","phase":"final_answer","text":"review result"}}}`,
		`{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed"}}}`,
	}
}

func TestCodexProtocolCompletesOneEphemeralTurn(t *testing.T) {
	for _, purpose := range []protocolInvocationPurpose{protocolPurposeReview, protocolPurposeExtraction, protocolPurposeQualification} {
		t.Run(string(purpose), func(t *testing.T) {
			driver, err := newCodexProtocolSession("/private/work", []byte("review packet"), purpose, nil)
			if err != nil {
				t.Fatal(err)
			}
			exchange := &scriptedCodexExchange{lines: codexSuccessFrames()}
			if err := driver.Drive(context.Background(), exchange); err != nil {
				t.Fatal(err)
			}
			if got := string(driver.AssistantEvidenceText()); got != "review result" {
				t.Fatalf("assistant text = %q", got)
			}
			observation, ok := driver.SessionObservation()
			if !ok || observation.ProviderSessionID() != "thread-1" || observation.ProviderTurnID() != "turn-1" {
				t.Fatalf("session observation = %#v, present=%t", observation, ok)
			}
			if len(exchange.sent) != 4 {
				t.Fatalf("sent frame count = %d", len(exchange.sent))
			}
			var start struct {
				Params struct {
					ApprovalPolicy string `json:"approvalPolicy"`
					Ephemeral      bool   `json:"ephemeral"`
				} `json:"params"`
			}
			if err := json.Unmarshal(exchange.sent[2], &start); err != nil || start.Params.ApprovalPolicy != "never" || !start.Params.Ephemeral {
				t.Fatalf("thread start = %s, error=%v", exchange.sent[2], err)
			}
			var turn struct {
				Params struct {
					OutputSchema json.RawMessage `json:"outputSchema"`
					Input        []struct {
						Text string `json:"text"`
					} `json:"input"`
				} `json:"params"`
			}
			if err := json.Unmarshal(exchange.sent[3], &turn); err != nil || len(turn.Params.Input) != 1 || turn.Params.Input[0].Text != "review packet" {
				t.Fatalf("turn start = %s, error=%v", exchange.sent[3], err)
			}
			if (len(turn.Params.OutputSchema) != 0) != (purpose == protocolPurposeQualification) {
				t.Fatalf("qualification schema presence = %t", len(turn.Params.OutputSchema) != 0)
			}
		})
	}
}

func TestCodexProtocolPrefersExplicitFinalAnswer(t *testing.T) {
	frames := codexSuccessFrames()
	frames[3] = `{"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"type":"agentMessage","phase":"final_answer","text":"final report"}}}`
	frames = append(frames[:4], append([]string{`{"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"type":"agentMessage","text":"later commentary"}}}`}, frames[4:]...)...)
	driver, err := newCodexProtocolSession("/private/work", []byte("packet"), protocolPurposeReview, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Drive(context.Background(), &scriptedCodexExchange{lines: frames}); err != nil {
		t.Fatal(err)
	}
	if got := string(driver.AssistantEvidenceText()); got != "final report" {
		t.Fatalf("assistant text = %q", got)
	}
}

func TestCodexProtocolRejectsActualWriteAuthority(t *testing.T) {
	var absent *stagedOutputLease
	if _, err := newCodexProtocolSession("/private/work", []byte("packet"), protocolPurposeReview, absent); err != nil {
		t.Fatalf("typed nil staging pointer rejected: %v", err)
	}
	if _, err := newCodexProtocolSession("/private/work", []byte("packet"), protocolPurposeReview, &stagedOutputLease{}); err == nil {
		t.Fatal("Codex accepted a staged output lease")
	}
}

func TestCodexProtocolFailsClosedOnBrokenTurns(t *testing.T) {
	for _, test := range []struct {
		name  string
		lines []string
		cause domain.RuntimeDiagnosticCause
	}{
		{"missing completion", codexSuccessFrames()[:4], domain.DiagnosticCauseProviderTurnFailed},
		{"invalid frame", []string{`{"id":1,"result":{}}`, `not-json`}, domain.DiagnosticCauseOutputDecodeFailed},
		{"out-of-order thread", codexSuccessFrames()[1:2], domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"duplicate initialize", []string{`{"id":1,"result":{}}`, `{"id":1,"result":{}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"unsafe thread id", []string{`{"id":1,"result":{}}`, `{"id":2,"result":{"thread":{"id":"bad\nthread","ephemeral":true}}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"non-ephemeral thread", []string{`{"id":1,"result":{}}`, `{"id":2,"result":{"thread":{"id":"thread-1","ephemeral":false}}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"loaded instructions", []string{`{"id":1,"result":{}}`, `{"id":2,"result":{"thread":{"id":"thread-1","ephemeral":true},"instructionSources":["/private/work/AGENTS.md"]}}`}, domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"server request", []string{`{"id":1,"result":{}}`, `{"id":10,"method":"item/commandExecution/requestApproval","params":{}}`}, domain.DiagnosticCauseProviderExecutionFailed},
		{"failed turn", append(codexSuccessFrames()[:4], `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"failed"}}}`), domain.DiagnosticCauseProviderTurnFailed},
		{"wrong turn", append(codexSuccessFrames()[:4], `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"other","status":"completed"}}}`), domain.DiagnosticCauseOutputEnvelopeInvalid},
		{"missing answer", append(codexSuccessFrames()[:3], `{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed"}}}`), domain.DiagnosticCauseOutputMissing},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver, err := newCodexProtocolSession("/private/work", []byte("packet"), protocolPurposeReview, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = driver.Drive(context.Background(), &scriptedCodexExchange{lines: test.lines})
			var failure *codexProtocolError
			if err == nil || !strings.Contains(err.Error(), "codex app-server") || !errors.As(err, &failure) || failure.cause != test.cause {
				t.Fatalf("error = %v, want cause %q", err, test.cause)
			}
			if _, ok := driver.SessionObservation(); !ok {
				t.Fatal("failed conversation has no session observation")
			}
		})
	}
}
