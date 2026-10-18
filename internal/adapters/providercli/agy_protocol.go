package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// The AGY (Antigravity CLI) stream-json driver runs one single-turn NDJSON
// conversation per invocation: one authenticated init, one user frame, any
// number of step_update frames, and one correlated result, followed by an
// explicit stdin half-close and a clean stdout drain. Diagnostics on stderr
// are never report text.

var (
	agyModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

// agyInvocationSettings are the immutable operator-selected model settings for
// one AGY runtime. Empty fields mean "omitted", which is deliberately distinct
// from an explicit value.
type agyInvocationSettings struct {
	model           string
	reasoningEffort string
}

func newAgyInvocationSettings(model, reasoningEffort string) (agyInvocationSettings, error) {
	if !validAgySettings(model, reasoningEffort) {
		return agyInvocationSettings{}, errInvalidAgySettings
	}
	return agyInvocationSettings{model: model, reasoningEffort: reasoningEffort}, nil
}

func validAgySettings(model, reasoningEffort string) bool {
	return (model == "" || validAgyModel(model)) && (reasoningEffort == "" || validAgyReasoningEffort(reasoningEffort))
}

// validAgyReasoningEffort is the closed effort enum the installed native help
// lists for --effort. The empty value means omitted, never a default.
func validAgyReasoningEffort(value string) bool {
	switch value {
	case "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func validAgyModel(value string) bool {
	if !agyModelPattern.MatchString(value) || path.IsAbs(value) || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

// agySettingsIdentity binds the model and reasoning-effort pair, preserving
// the omitted-versus-explicit distinction.
func agySettingsIdentity(model, reasoningEffort string) string {
	sum := sha256.Sum256([]byte("Mulgae-AGY-SETTINGS/1\x00model\x00" + model + "\x00reasoning-effort\x00" + reasoningEffort))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type agySettingsError struct{}

func (agySettingsError) Error() string { return "invalid AGY settings" }

var errInvalidAgySettings error = agySettingsError{}

type agyProtocolError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func (failure *agyProtocolError) Error() string { return "agy stream-json: " + failure.err.Error() }
func (failure *agyProtocolError) Unwrap() error { return failure.err }
func (failure *agyProtocolError) Cause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.cause
}
func (failure *agyProtocolError) ProtocolFailureCause() domain.RuntimeDiagnosticCause {
	return failure.Cause()
}

func agyProtocolFailure(cause domain.RuntimeDiagnosticCause, err error) error {
	return &agyProtocolError{cause: cause, err: err}
}

// agyLiveReadAuthority admits exact native read operations for one live
// review. It grants no shell parsing, no path prefixes, and no write
// destination; every admitted operation is revalidated against the current
// application execution authority.
type agyLiveReadAuthority struct {
	execution   ports.LiveReviewExecution
	gitCommands map[string]bool
}

func newAgyLiveReadAuthority(ctx context.Context, execution ports.LiveReviewExecution) (*agyLiveReadAuthority, error) {
	if err := execution.Revalidate(ctx); err != nil {
		return nil, err
	}
	authority := &agyLiveReadAuthority{execution: execution, gitCommands: make(map[string]bool)}
	for _, read := range execution.Reads() {
		if command := read.GitCommand(); command != "" {
			authority.gitCommands[agyGuardedReadCommand(command)] = true
		}
	}
	return authority, nil
}

// allow admits one completed native tool operation. view_file is authorized
// through the source reader under the workspace scope only; run_command must
// match a trusted read-plan Git command byte for byte.
func (authority *agyLiveReadAuthority) allow(ctx context.Context, tool, operand string) error {
	if authority == nil {
		return fmt.Errorf("missing live read authority")
	}
	if err := authority.execution.Revalidate(ctx); err != nil {
		return err
	}
	switch tool {
	case "run_command":
		if operand == "" || !authority.gitCommands[operand] {
			return fmt.Errorf("native command is outside the live read plan")
		}
		return nil
	case "view_file":
		if authority.execution.Target().Selector().Scope() != domain.LiveSourceWorkspace || !validCanonicalAbsolute(operand) {
			return fmt.Errorf("native operation is outside the live read plan")
		}
		relative, err := filepath.Rel(authority.execution.Binding().Root.String(), operand)
		if err != nil {
			return err
		}
		selected, err := ports.NewSafeRelativePath(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		// The source reader owns runtime/credential exclusion and path safety.
		// This check grants no replacement policy and retains no snapshot.
		_, err = authority.execution.SourceReader().Read(ctx, domain.LiveSourceWorktree, selected)
		return err
	default:
		return fmt.Errorf("native tool is outside the live read plan")
	}
}

type agyProtocolSession struct {
	prompt      string
	purpose     protocolInvocationPurpose
	agentName   string
	liveReads   *agyLiveReadAuthority
	observation ports.ProviderSessionObservation
	evidence    []byte
}

func newAgyProtocolSession(workspacePath string, prompt []byte, purpose protocolInvocationPurpose, writeAuthority protocolWriteAuthority, configuration protocolSessionConfiguration) (providerProtocolSession, error) {
	// The registry passes its typed staging pointer through an interface even
	// for stdout routes. A nil pointer grants no write authority, and AGY
	// never accepts one: the report is the captured assistant response.
	authority := reflect.ValueOf(writeAuthority)
	hasWriteAuthority := writeAuthority != nil && (authority.Kind() != reflect.Pointer || !authority.IsNil())
	if !validCanonicalAbsolute(workspacePath) || len(prompt) == 0 || hasWriteAuthority {
		return nil, fmt.Errorf("agy stream-json: invalid session request")
	}
	switch purpose {
	case protocolPurposeReview, protocolPurposeExtraction, protocolPurposeQualification, protocolPurposeLiveReview, protocolPurposeLiveExtraction:
	default:
		return nil, fmt.Errorf("agy stream-json: unsupported purpose")
	}
	if !validAgyAgentName(configuration.agyAgentName) {
		return nil, fmt.Errorf("agy stream-json: missing invocation agent binding")
	}
	if !validAgySettings(configuration.agySettings.model, configuration.agySettings.reasoningEffort) {
		return nil, fmt.Errorf("agy stream-json: invalid invocation settings")
	}
	return &agyProtocolSession{
		prompt: string(prompt), purpose: purpose,
		agentName: configuration.agyAgentName, liveReads: configuration.agyLiveReads,
	}, nil
}

func (session *agyProtocolSession) AssistantEvidenceText() []byte {
	return append([]byte(nil), session.evidence...)
}

func (session *agyProtocolSession) SessionObservation() (ports.ProviderSessionObservation, bool) {
	if session == nil || !session.observation.Valid() {
		return ports.ProviderSessionObservation{}, false
	}
	return session.observation, true
}

type agyWireInit struct {
	Agent          string `json:"agent"`
	PermissionMode string `json:"permission_mode"`
}

// agyToolInfoFrame is a presence-aware decode of one native tool_info object.
// Presence is tracked explicitly so a missing step index, output field, or
// error carrier can never alias a zero value.
type agyToolInfoFrame struct {
	name         string
	hasName      bool
	output       string
	hasOutput    bool
	parameters   map[string]json.RawMessage
	errorPayload json.RawMessage
	fields       map[string]json.RawMessage
}

func parseAgyToolInfo(raw json.RawMessage) (*agyToolInfoFrame, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("invalid tool info")
	}
	frame := &agyToolInfoFrame{fields: fields, parameters: make(map[string]json.RawMessage)}
	if value, present := fields["name"]; present && string(value) != "null" {
		if err := json.Unmarshal(value, &frame.name); err != nil {
			return nil, err
		}
		frame.hasName = true
	}
	if value, present := fields["output"]; present && string(value) != "null" {
		if err := json.Unmarshal(value, &frame.output); err != nil {
			return nil, err
		}
		frame.hasOutput = true
	}
	if value, present := fields["error"]; present && string(value) != "null" {
		frame.errorPayload = value
	}
	if value, present := fields["parameters"]; present && string(value) != "null" {
		if err := json.Unmarshal(value, &frame.parameters); err != nil {
			return nil, err
		}
	}
	return frame, nil
}

type agyWireResult struct {
	ConversationID   string            `json:"conversation_id"`
	Status           string            `json:"status"`
	Response         string            `json:"response"`
	StructuredOutput json.RawMessage   `json:"structured_output"`
	Error            json.RawMessage   `json:"error"`
	DeniedActions    []json.RawMessage `json:"denied_actions"`
}

// agyWireFrame is one decoded NDJSON child frame. RawMessage fields keep
// presence information so unknown or reordered shapes fail closed.
type agyWireFrame struct {
	Event          json.RawMessage `json:"event"`
	ConversationID json.RawMessage `json:"conversation_id"`
	Init           json.RawMessage `json:"init"`
	StepUpdate     json.RawMessage `json:"step_update"`
	Result         json.RawMessage `json:"result"`
}

// agyToolOperation is one correlated native tool operation tracked by
// step_index across its ACTIVE and DONE frames.
type agyToolOperation struct {
	name    string
	operand string
	started bool
	done    bool
}

type agyConversation struct {
	phase          ports.ProviderSessionPhase
	conversationID string
	lastStepIndex  int
	observedStep   bool
	initAccepted   bool
	userSent       bool
	resultAccepted bool
	closeSent      bool
	drained        bool
	tools          map[int]*agyToolOperation
	stepTypes      map[int]string
	evidence       []byte
}

func (session *agyProtocolSession) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) (driveErr error) {
	if session == nil || exchange == nil {
		return agyProtocolFailure(domain.DiagnosticCauseObservationInvalid, errors.New("invalid conversation"))
	}
	state := agyConversation{phase: ports.ProviderSessionPhaseCreate, tools: make(map[int]*agyToolOperation), stepTypes: make(map[int]string), lastStepIndex: -1}
	defer func() {
		terminal := ports.ProviderSessionCompleted
		if driveErr != nil {
			terminal = ports.ProviderSessionFailed
		}
		input := ports.ProviderSessionObservationInput{
			Phase: state.phase, Terminal: terminal,
			ProviderSessionID: safeAgyDiagnosticIdentifier(state.conversationID),
			ProviderTurnID:    state.turnIdentifier(),
			CreateAccepted:    state.initAccepted, SendAccepted: state.userSent,
			TurnObserved:     state.observedStep,
			MessagesReceived: state.resultAccepted,
			CloseSent:        state.closeSent, CloseAccepted: state.drained,
		}
		observation, err := ports.NewProviderSessionObservation(input)
		session.observation = observation
		if err != nil {
			driveErr = errors.Join(driveErr, agyProtocolFailure(domain.DiagnosticCauseObservationInvalid, err))
		}
	}()
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, io.EOF) {
				if state.resultAccepted {
					// Clean stdout drain after the stdin half-close completes
					// the conversation; only now is the captured result
					// accepted as session evidence.
					session.evidence = append([]byte(nil), state.evidence...)
					state.drained = true
					state.phase = ports.ProviderSessionPhaseClose
					return nil
				}
				return agyProtocolFailure(domain.DiagnosticCauseProviderTurnFailed,
					fmt.Errorf("conversation ended before terminal result: %w", err))
			}
			cause := domain.DiagnosticCauseProviderExecutionFailed
			if state.initAccepted {
				cause = domain.DiagnosticCauseProviderTurnFailed
			}
			return agyProtocolFailure(cause, fmt.Errorf("conversation exchange failed: %w", err))
		}
		if state.resultAccepted {
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("frame after terminal result"))
		}
		if len(bytes.TrimSpace(line)) == 0 || !bytes.HasPrefix(bytes.TrimSpace(line), []byte{'{'}) {
			return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("invalid protocol frame"))
		}
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, fmt.Errorf("invalid protocol frame: %w", err))
		}
		var frame agyWireFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
		}
		var event string
		if err := json.Unmarshal(frame.Event, &event); err != nil || event == "" {
			return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, errors.New("protocol frame without event"))
		}
		switch event {
		case "init":
			if err := state.handleInit(ctx, exchange, session, frame); err != nil {
				return err
			}
		case "step_update":
			if err := state.handleStepUpdate(ctx, session, frame); err != nil {
				return err
			}
		case "result":
			if err := state.handleResult(ctx, exchange, session, frame); err != nil {
				return err
			}
		default:
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unknown AGY event"))
		}
	}
}

func (state *agyConversation) handleInit(ctx context.Context, exchange ports.ProviderSessionExchange, session *agyProtocolSession, frame agyWireFrame) error {
	if state.initAccepted {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("duplicate init frame"))
	}
	var conversationID string
	if err := json.Unmarshal(frame.ConversationID, &conversationID); err != nil || conversationID == "" {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("init frame without conversation id"))
	}
	if len(frame.Init) == 0 {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("init frame without acknowledgement"))
	}
	var ack agyWireInit
	if err := json.Unmarshal(frame.Init, &ack); err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
	}
	// The agent name and permission mode are provider configuration
	// acknowledgements of the app-authored invocation profile. A mismatch
	// means the profile was not applied and the turn must not start.
	if ack.Agent != session.agentName || ack.PermissionMode != "request-review" {
		return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("controlled agent initialization acknowledgement mismatch"))
	}
	state.conversationID = conversationID
	state.initAccepted = true
	state.phase = ports.ProviderSessionPhaseCreate
	message, err := json.Marshal(struct {
		Event   string `json:"event"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}{Event: "user", Message: struct {
		Content string `json:"content"`
	}{Content: session.prompt}})
	if err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseObservationInvalid, err)
	}
	if err := exchange.SendLine(ctx, message); err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, err)
	}
	state.userSent = true
	state.phase = ports.ProviderSessionPhaseSend
	return nil
}

func (state *agyConversation) handleStepUpdate(ctx context.Context, session *agyProtocolSession, frame agyWireFrame) error {
	if !state.initAccepted {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update before init"))
	}
	if len(frame.ConversationID) != 0 {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update carries unknown top-level fields"))
	}
	if len(frame.StepUpdate) == 0 {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update without body"))
	}
	var step struct {
		ConversationID string          `json:"conversation_id"`
		StepIndex      json.RawMessage `json:"step_index"`
		State          string          `json:"state"`
		StepType       string          `json:"step_type"`
		ToolName       string          `json:"tool_name"`
		ToolInfo       json.RawMessage `json:"tool_info"`
	}
	if err := json.Unmarshal(frame.StepUpdate, &step); err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
	}
	if step.ConversationID != state.conversationID {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update conversation mismatch"))
	}
	var stepIndex int
	if len(step.StepIndex) == 0 || bytes.Equal(bytes.TrimSpace(step.StepIndex), []byte("null")) {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update without step index"))
	}
	if err := json.Unmarshal(step.StepIndex, &stepIndex); err != nil || stepIndex < 0 {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step update without step index"))
	}
	if prior, ok := state.stepTypes[stepIndex]; ok && prior != step.StepType {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("step identity changed"))
	}
	state.stepTypes[stepIndex] = step.StepType
	state.lastStepIndex = stepIndex
	state.observedStep = true
	state.phase = ports.ProviderSessionPhaseTurn
	switch step.StepType {
	case "user_input", "agent_response":
		// Established non-authoritative progress variants: text deltas and
		// the echoed user input never carry authority, and neither may carry
		// tool metadata.
		if step.ToolName != "" || len(step.ToolInfo) != 0 {
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("progress step carries tool metadata"))
		}
		return nil
	case "tool":
		toolInfo, infoErr := parseAgyToolInfo(step.ToolInfo)
		if infoErr != nil {
			return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, infoErr)
		}
		return state.handleToolStep(ctx, session, stepIndex, step.State, step.ToolName, toolInfo)
	default:
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unknown AGY step type"))
	}
}

func (state *agyConversation) handleToolStep(ctx context.Context, session *agyProtocolSession, stepIndex int, stepState, toolName string, toolInfo *agyToolInfoFrame) error {
	if toolName != "view_file" && toolName != "run_command" {
		return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("disallowed native tool"))
	}
	if toolInfo != nil && toolInfo.hasName && toolInfo.name != toolName {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("tool identity drift between step and tool info"))
	}
	if toolInfo != nil && len(toolInfo.errorPayload) != 0 {
		return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("native tool operation failed"))
	}
	operand := ""
	if toolInfo != nil {
		var raw json.RawMessage
		var present bool
		if toolName == "view_file" {
			raw, present = toolInfo.parameters["AbsolutePath"]
		} else {
			raw, present = toolInfo.parameters["CommandLine"]
		}
		if present && len(raw) != 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &operand); err != nil {
				return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
			}
		}
	}
	operation, admitted := state.tools[stepIndex]
	switch stepState {
	case "ACTIVE":
		if admitted {
			if operation.done {
				return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("terminal tool operation was reopened"))
			}
			if operation.name != toolName || operation.operand != operand {
				return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("tool operation identity or operand drift"))
			}
			return nil
		}
		if operand == "" {
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("tool operation without operand"))
		}
		state.tools[stepIndex] = &agyToolOperation{name: toolName, operand: operand, started: true}
		return nil
	case "DONE":
		if !admitted {
			return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("tool completion without admitted start"))
		}
		if operation.done {
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("duplicate terminal tool operation"))
		}
		if operation.name != toolName || operation.operand != operand {
			return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("tool operation identity or operand drift"))
		}
		// A completed operation reports its output field; legitimately empty
		// tool output stays valid, but the field itself must be present.
		if toolInfo == nil || !toolInfo.hasOutput {
			return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("completed tool operation without output"))
		}
		if err := session.authorizeToolOperation(ctx, toolName, operand); err != nil {
			return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, fmt.Errorf("native tool operation rejected: %w", err))
		}
		operation.done = true
		return nil
	default:
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("unknown tool operation state"))
	}
}

func (session *agyProtocolSession) authorizeToolOperation(ctx context.Context, toolName, operand string) error {
	if session.liveReads == nil {
		// Qualification and extraction are prompt-bound: no native tool
		// operation is part of their bounded read plan.
		return fmt.Errorf("no native tool operation is admitted for this purpose")
	}
	return session.liveReads.allow(ctx, toolName, operand)
}

func (state *agyConversation) handleResult(ctx context.Context, exchange ports.ProviderSessionExchange, session *agyProtocolSession, frame agyWireFrame) error {
	if !state.initAccepted || !state.userSent {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("result before the turn request"))
	}
	if len(frame.Result) == 0 {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("result frame without body"))
	}
	var result agyWireResult
	if err := json.Unmarshal(frame.Result, &result); err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseOutputDecodeFailed, err)
	}
	if result.ConversationID != state.conversationID {
		return agyProtocolFailure(domain.DiagnosticCauseOutputEnvelopeInvalid, errors.New("result conversation mismatch"))
	}
	if len(result.Error) != 0 && string(result.Error) != "null" && string(result.Error) != `""` {
		return agyProtocolFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("native result error"))
	}
	if result.Status != "SUCCESS" {
		return agyProtocolFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("native result failed"))
	}
	if len(result.DeniedActions) != 0 {
		return agyProtocolFailure(domain.DiagnosticCausePermissionDenied, errors.New("native result reports denied actions"))
	}
	for _, operation := range state.tools {
		if !operation.done {
			return agyProtocolFailure(domain.DiagnosticCauseProviderTurnFailed, errors.New("unfinished tool operation at result"))
		}
	}
	evidence := []byte(result.Response)
	if session.purpose == protocolPurposeQualification && len(result.StructuredOutput) != 0 && string(result.StructuredOutput) != "null" {
		evidence = append([]byte(nil), result.StructuredOutput...)
	}
	if len(bytes.TrimSpace(evidence)) == 0 {
		// A denial-terminated or empty SUCCESS is never a valid report.
		return agyProtocolFailure(domain.DiagnosticCauseOutputMissing, errors.New("native result response is empty"))
	}
	state.evidence = evidence
	state.resultAccepted = true
	state.phase = ports.ProviderSessionPhaseMessages
	if err := exchange.CloseInput(ctx); err != nil {
		return agyProtocolFailure(domain.DiagnosticCauseProviderExecutionFailed, err)
	}
	state.closeSent = true
	return nil
}

func (state *agyConversation) turnIdentifier() string {
	if state.lastStepIndex < 0 {
		return ""
	}
	return strconv.Itoa(state.lastStepIndex)
}

func safeAgyDiagnosticIdentifier(value string) string {
	if len(value) > 512 || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

// agyProtocolArgv builds the family-closed static argv shared by every AGY
// protocol invocation. It never carries the prompt and never carries a
// permission bypass: no skip-permissions, nested-sandbox, or print-mode flag
// is part of this profile.
func agyProtocolArgv(definition RuntimeDefinition, addDir string) ([]string, error) {
	if !validCanonicalAbsolute(definition.Executable()) || !validCanonicalAbsolute(addDir) || addDir == string(filepath.Separator) {
		return nil, fmt.Errorf("agy invocation: invalid executable or admitted root")
	}
	argv := []string{
		definition.Executable(),
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--mode", "plan",
		"--disable-slash-commands",
		"--add-dir", addDir,
	}
	if model := definition.AgyModel(); model != "" {
		if !validAgyModel(model) {
			return nil, fmt.Errorf("agy invocation: invalid model")
		}
		argv = append(argv, "--model", model)
	}
	if effort := definition.AgyReasoningEffort(); effort != "" {
		if !validAgyReasoningEffort(effort) {
			return nil, fmt.Errorf("agy invocation: invalid reasoning effort")
		}
		argv = append(argv, "--effort", effort)
	}
	return argv, nil
}

// agyBindInvocationArgv appends the per-invocation namespace binding: the
// disposable projected Gemini home and the app-owned agent name. The returned
// argv is the exact argv the caller must launch and hash into qualification
// evidence.
func agyBindInvocationArgv(argv []string, geminiDir, agentName string) ([]string, error) {
	if len(argv) == 0 || !validCanonicalAbsolute(geminiDir) || geminiDir == string(filepath.Separator) || !validAgyAgentName(agentName) {
		return nil, fmt.Errorf("agy invocation: invalid namespace binding")
	}
	for _, argument := range argv {
		if argument == "" || strings.IndexByte(argument, 0) >= 0 {
			return nil, fmt.Errorf("agy invocation: invalid argv")
		}
	}
	return append(append([]string(nil), argv...), "--gemini_dir", geminiDir, "--agent", agentName), nil
}

// Unlike long-lived app servers, AGY must finish naturally after stdin EOF.
func agyNaturalExitObservation(observation ports.ProcessObservation) bool {
	code, exited := observation.ExitCode()
	lifecycle, present := observation.LifecycleReceipt()
	return observation.Valid() && observation.Succeeded() && exited && code == 0 && present && lifecycle.Valid() && lifecycle.ProcessGroupAbsent() && len(lifecycle.SignalRequests()) == 0
}
