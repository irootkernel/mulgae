package providercli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const agyTestAgent = "mulgae-agy-0123456789abcdef"

type agyTestExchange struct {
	frames [][]byte
	sent   [][]byte
	closed bool
	tail   error
}

func (e *agyTestExchange) ReceiveLine(context.Context) ([]byte, error) {
	if len(e.frames) == 0 {
		if e.tail != nil {
			return nil, e.tail
		}
		return nil, io.EOF
	}
	frame := e.frames[0]
	e.frames = e.frames[1:]
	return frame, nil
}
func (e *agyTestExchange) SendLine(_ context.Context, line []byte) error {
	e.sent = append(e.sent, append([]byte(nil), line...))
	return nil
}
func (e *agyTestExchange) CloseInput(context.Context) error { e.closed = true; return nil }
func agyTestJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
func agyTestInit() []byte {
	return agyTestJSON(map[string]any{"event": "init", "conversation_id": "conversation-1", "init": map[string]any{"agent": agyTestAgent, "permission_mode": "request-review"}})
}
func agyTestStep(step map[string]any) []byte {
	return agyTestJSON(map[string]any{"event": "step_update", "step_update": step})
}
func agyTestProgress() []byte {
	return agyTestStep(map[string]any{"conversation_id": "conversation-1", "step_index": 1, "step_type": "agent_response", "state": "DONE", "text_delta": "untrusted progress"})
}
func agyTestResult(fields map[string]any) []byte {
	result := map[string]any{"conversation_id": "conversation-1", "status": "SUCCESS", "response": "actual final report"}
	for k, v := range fields {
		result[k] = v
	}
	return agyTestJSON(map[string]any{"event": "result", "result": result})
}
func agyTestSession(t *testing.T) providerProtocolSession {
	t.Helper()
	s, err := newAgyProtocolSession("/neutral", []byte("private prompt"), protocolPurposeQualification, nil, protocolSessionConfiguration{agyAgentName: agyTestAgent})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestAgyProtocolSuccessDrainsAndReturnsOnlyFinalReport(t *testing.T) {
	session := agyTestSession(t)
	exchange := &agyTestExchange{frames: [][]byte{agyTestInit(), agyTestProgress(), agyTestResult(nil)}}
	if err := session.Drive(context.Background(), exchange); err != nil {
		t.Fatal(err)
	}
	if string(session.AssistantEvidenceText()) != "actual final report" || !exchange.closed || len(exchange.sent) != 1 {
		t.Fatalf("report=%q closed=%t sent=%d", session.AssistantEvidenceText(), exchange.closed, len(exchange.sent))
	}
	var user struct {
		Event   string `json:"event"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal(exchange.sent[0], &user) != nil || user.Event != "user" || user.Message.Content != "private prompt" {
		t.Fatal("prompt did not use one user frame")
	}
	observation, ok := session.SessionObservation()
	if !ok || observation.Terminal() != ports.ProviderSessionCompleted {
		t.Fatal("missing completed session receipt")
	}
}
func TestAgyProtocolRejectsInvalidFramesAndNeverReturnsPartialEvidence(t *testing.T) {
	tool := func(index any, state, name string, info any) []byte {
		step := map[string]any{"conversation_id": "conversation-1", "step_type": "tool", "state": state, "tool_name": name, "tool_info": info}
		if index != nil {
			step["step_index"] = index
		}
		return agyTestStep(step)
	}
	info := map[string]any{"name": "view_file", "parameters": map[string]string{"AbsolutePath": "/source/a"}, "output": "read"}
	cases := map[string][][]byte{
		"result before init":              {agyTestResult(nil)},
		"missing agent":                   {[]byte(`{"event":"init","conversation_id":"c","init":{"permission_mode":"request-review"}}`)},
		"wrong mode":                      {[]byte(`{"event":"init","conversation_id":"c","init":{"agent":"` + agyTestAgent + `","permission_mode":"yolo"}}`)},
		"empty conversation":              {[]byte(`{"event":"init","conversation_id":"","init":{"agent":"` + agyTestAgent + `","permission_mode":"request-review"}}`)},
		"duplicate init":                  {agyTestInit(), agyTestInit()},
		"duplicate keys":                  {[]byte(`{"event":"init","event":"result"}`)},
		"unknown event":                   {agyTestInit(), []byte(`{"event":"control_request"}`)},
		"diagnostic stdout":               {agyTestInit(), []byte("log: success")},
		"wrong session":                   {agyTestInit(), agyTestResult(map[string]any{"conversation_id": "other"})},
		"native failure":                  {agyTestInit(), agyTestResult(map[string]any{"status": "ERROR"})},
		"native error":                    {agyTestInit(), agyTestResult(map[string]any{"error": "private native error"})},
		"denial terminated empty SUCCESS": {agyTestInit(), agyTestResult(map[string]any{"response": "", "denied_actions": []string{"command"}})},
		"denied with report":              {agyTestInit(), agyTestResult(map[string]any{"denied_actions": []string{"command"}})},
		"empty response":                  {agyTestInit(), agyTestResult(map[string]any{"response": ""})},
		"reordered terminal":              {agyTestInit(), agyTestProgress(), agyTestResult(nil), agyTestProgress()},
		"step before init":                {agyTestProgress()},
		"missing step index":              {agyTestInit(), tool(nil, "ACTIVE", "view_file", info)},
		"null step index":                 {agyTestInit(), agyTestStep(map[string]any{"conversation_id": "conversation-1", "step_index": nil, "step_type": "agent_response", "state": "DONE"}), agyTestResult(nil)},
		"unknown tool":                    {agyTestInit(), tool(2, "ACTIVE", "write_to_file", info)},
		"contradictory nested name":       {agyTestInit(), tool(2, "ACTIVE", "run_command", info)},
		"completion without start":        {agyTestInit(), tool(2, "DONE", "view_file", info)},
		"unfinished operation":            {agyTestInit(), tool(2, "ACTIVE", "view_file", info), agyTestResult(nil)},
		"operand drift":                   {agyTestInit(), tool(2, "ACTIVE", "view_file", info), tool(2, "DONE", "view_file", map[string]any{"name": "view_file", "parameters": map[string]string{"AbsolutePath": "/source/b"}, "output": "read"})},
		"tool error on active":            {agyTestInit(), tool(2, "ACTIVE", "view_file", map[string]any{"parameters": map[string]string{"AbsolutePath": "/source/a"}, "error": "denied"})},
		"hidden tool in progress":         {agyTestInit(), agyTestStep(map[string]any{"conversation_id": "conversation-1", "step_index": 2, "step_type": "agent_response", "state": "DONE", "tool_name": "view_file", "tool_info": info})},
	}
	for name, frames := range cases {
		t.Run(name, func(t *testing.T) {
			session := agyTestSession(t)
			exchange := &agyTestExchange{frames: frames}
			err := session.Drive(context.Background(), exchange)
			if err == nil || len(session.AssistantEvidenceText()) != 0 {
				t.Fatalf("error=%v evidence=%q", err, session.AssistantEvidenceText())
			}
			if strings.Contains(name, "before init") && len(exchange.sent) != 0 {
				t.Fatal("user sent before init")
			}
		})
	}
	for _, tail := range []error{io.ErrUnexpectedEOF, context.Canceled} {
		session := agyTestSession(t)
		err := session.Drive(context.Background(), &agyTestExchange{frames: [][]byte{agyTestInit(), agyTestProgress(), agyTestResult(nil)}, tail: tail})
		if err == nil || len(session.AssistantEvidenceText()) != 0 {
			t.Fatal("failed EOF drain returned report")
		}
		if errors.Is(tail, context.Canceled) && !errors.Is(err, context.Canceled) {
			t.Fatal("lost cancellation")
		}
	}
}

func TestAgyMultipleUnfinishedStepsRetainSameRefusal(t *testing.T) {
	for _, indices := range [][]int{{2}, {2, 10}, {10, 2}} {
		session := agyTestSession(t)
		frames := [][]byte{agyTestInit()}
		for _, index := range indices {
			frames = append(frames, agyTestStep(map[string]any{
				"conversation_id": "conversation-1",
				"step_index":      index,
				"step_type":       "tool",
				"state":           "ACTIVE",
				"tool_name":       "view_file",
				"tool_info":       map[string]any{"parameters": map[string]string{"AbsolutePath": "/source/a"}},
			}))
		}
		frames = append(frames, agyTestResult(nil))
		err := session.Drive(context.Background(), &agyTestExchange{frames: frames})
		assertTask064ProtocolCause(t, err, domain.DiagnosticCauseProviderTurnFailed)
		if !strings.Contains(err.Error(), "unfinished tool operation at result") || len(session.AssistantEvidenceText()) != 0 {
			t.Fatalf("unfinished AGY steps %v changed acceptance: %v", indices, err)
		}
	}
}
func TestAgyCanonicalFileReadKeepsClosedOperandsAndPurpose(t *testing.T) {
	for _, test := range []struct {
		name       string
		parameters map[string]any
		accepted   bool
	}{
		{"Path", map[string]any{"Path": "/source/a"}, true},
		{"legacy field", map[string]any{"AbsolutePath": "/source/a"}, false},
		{"mixed fields", map[string]any{"Path": "/source/a", "AbsolutePath": "/source/b"}, false},
		{"command field", map[string]any{"Path": "/source/a", "CommandLine": "cat /source/a"}, false},
		{"non-string", map[string]any{"Path": 1}, false},
		{"missing", map[string]any{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info, err := parseAgyToolInfo(agyTestJSON(map[string]any{
				"name": "read_file", "parameters": test.parameters, "output": "fixture",
			}))
			if err != nil {
				t.Fatal(err)
			}
			state := &agyConversation{tools: make(map[int]*agyToolOperation)}
			session := &agyProtocolSession{}
			err = state.handleToolStep(context.Background(), session, 2, "ACTIVE", "read_file", info)
			if (err == nil) != test.accepted {
				t.Fatalf("start accepted=%t: %v", test.accepted, err)
			}
			if !test.accepted {
				if len(state.tools) != 0 {
					t.Fatal("invalid operand acquired a tool identity")
				}
				return
			}
			// A valid wire operand still grants no qualification/extraction read.
			err = state.handleToolStep(context.Background(), session, 2, "DONE", "read_file", info)
			var failure *agyProtocolError
			if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCausePermissionDenied || state.tools[2].done {
				t.Fatalf("prompt-bound purpose admitted a native file read: %v", err)
			}
		})
	}
}

func TestAgyCanonicalFileReadRetainsRawToolIdentity(t *testing.T) {
	state := &agyConversation{tools: make(map[int]*agyToolOperation)}
	session := &agyProtocolSession{}
	canonical, err := parseAgyToolInfo(agyTestJSON(map[string]any{
		"name": "read_file", "parameters": map[string]string{"Path": "/source/a"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.handleToolStep(context.Background(), session, 2, "ACTIVE", "read_file", canonical); err != nil {
		t.Fatal(err)
	}
	legacy, err := parseAgyToolInfo(agyTestJSON(map[string]any{
		"name": "view_file", "parameters": map[string]string{"AbsolutePath": "/source/a"}, "output": "fixture",
	}))
	if err != nil {
		t.Fatal(err)
	}
	err = state.handleToolStep(context.Background(), session, 2, "DONE", "view_file", legacy)
	var failure *agyProtocolError
	if !errors.As(err, &failure) || failure.Cause() != domain.DiagnosticCausePermissionDenied || state.tools[2].done {
		t.Fatalf("wire-format switch hid a tool identity change: %v", err)
	}
}

func TestAgySettingsAndArgvPreserveNativeSelection(t *testing.T) {
	for _, effort := range []string{"low", "medium", "high", "xhigh", "max"} {
		if !validAgySettings("model-1", effort) {
			t.Fatal(effort)
		}
	}
	for _, effort := range []string{"auto", "minimal", "MAX", " high", "unknown"} {
		if validAgySettings("", effort) {
			t.Fatal("accepted unsupported effort", effort)
		}
	}
	if agySettingsIdentity("", "") == agySettingsIdentity("model-1", "") || agySettingsIdentity("", "high") == agySettingsIdentity("", "max") {
		t.Fatal("settings identity collapsed")
	}
	d, err := NewRuntimeDefinition(FamilyAgy, "agy", "1.4.0", "/bin/agy", "", "agy", []string{"/bin/agy"}, nil, "/neutral", 1)
	if err != nil {
		t.Fatal(err)
	}
	d.agyModel = "model-1"
	d.agyReasoningEffort = "max"
	argv, err := agyProtocolArgv(d, "/source")
	if err != nil {
		t.Fatal(err)
	}
	argv, err = agyBindInvocationArgv(argv, "/namespace/home/.gemini", agyTestAgent)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--model model-1 --effort max") || !strings.Contains(joined, "--agent "+agyTestAgent) {
		t.Fatal(argv)
	}
	for _, arg := range argv {
		for _, bad := range []string{"-p", "--print", "--prompt", "--dangerously-skip-permissions", "--sandbox", "private prompt"} {
			if arg == bad {
				t.Fatal("unsafe argv", argv)
			}
		}
	}
}

func TestAgyRuntimeBuilderRejectsCrossFamilySettings(t *testing.T) {
	const identity = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, family := range []string{FamilyCodex, FamilyGrok, FamilyAgy} {
		t.Run(family, func(t *testing.T) {
			channel := ports.ProviderPacketChannelProtocol
			if family == FamilyGrok {
				channel = ports.ProviderPacketChannelTerminal
			}
			spec := ports.ProviderRuntimeSpec{Family: family, Instance: family, Executable: "/bin/provider", ExecutableSHA256: identity,
				Launcher: "/bin/provider", LauncherSHA256: identity, BaseArgv: []string{"/bin/provider"}, ProfileID: family,
				ProfileGeneration: "fixture", RuntimeSafetyPolicyIdentity: identity, WorkingDirectory: "/neutral", Timeout: time.Second,
				TransportChannel: channel, TransportArgvIndex: -1}
			if _, err := (RuntimeBuilder{}).BuildProductionRuntime(spec); err != nil {
				t.Fatal("invalid baseline fixture", err)
			}
			spec.AgyModel, spec.AgyReasoningEffort = "model-1", "max"
			result, err := (RuntimeBuilder{}).BuildProductionRuntime(spec)
			if family != FamilyAgy {
				if err == nil {
					t.Fatal("AGY settings silently accepted by another family")
				}
				return
			}
			if err != nil || result.(RuntimeDefinition).AgyModel() != "model-1" || result.(RuntimeDefinition).AgyReasoningEffort() != "max" {
				t.Fatal("AGY selection was not preserved", err)
			}
		})
	}
}
