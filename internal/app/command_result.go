package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

// CommandName is one command in the fixed Mulgae command surface.
type CommandName string

const (
	CommandInit      CommandName = "init"
	CommandDoctor    CommandName = "doctor"
	CommandReview    CommandName = "review"
	CommandFollowup  CommandName = "followup"
	CommandDelta     CommandName = "delta"
	CommandRerun     CommandName = "rerun"
	CommandStatus    CommandName = "status"
	CommandReport    CommandName = "report"
	CommandFindings  CommandName = "findings"
	CommandExcerpt   CommandName = "excerpt"
	CommandProviders CommandName = "providers"
	CommandRoles     CommandName = "roles"
	CommandConfig    CommandName = "config"
	CommandSchema    CommandName = "schema"
	CommandClean     CommandName = "clean"
	CommandExport    CommandName = "export"
	CommandHelp      CommandName = "help"
)

// ParseCommandName validates a command from the fixed command surface.
func ParseCommandName(value string) (CommandName, error) {
	command := CommandName(value)
	if !command.Valid() {
		return "", invalidCommandResult("unknown command %q", value)
	}
	return command, nil
}

// Valid reports whether command belongs to the fixed command surface.
func (command CommandName) Valid() bool {
	switch command {
	case CommandInit, CommandDoctor, CommandReview, CommandFollowup, CommandDelta,
		CommandRerun, CommandStatus, CommandReport, CommandFindings, CommandExcerpt,
		CommandProviders, CommandRoles, CommandConfig, CommandSchema, CommandClean,
		CommandExport, CommandHelp:
		return true
	default:
		return false
	}
}

// ExitCode is the process exit projection of a command result.
type ExitCode int

const (
	ExitCodeSuccess      ExitCode = 0
	ExitCodePolicy       ExitCode = 1
	ExitCodeUsage        ExitCode = 2
	ExitCodeReadiness    ExitCode = 4
	ExitCodeArtifact     ExitCode = 7
	ExitCodeSecurity     ExitCode = 8
	ExitCodeCancellation ExitCode = 9
	ExitCodeInternal     ExitCode = 10
)

// Valid reports whether code is an assigned Mulgae exit code.
func (code ExitCode) Valid() bool {
	switch code {
	case ExitCodeSuccess, ExitCodePolicy, ExitCodeUsage, ExitCodeReadiness,
		ExitCodeArtifact, ExitCodeSecurity, ExitCodeCancellation, ExitCodeInternal:
		return true
	default:
		return false
	}
}

// Diagnostic is a redacted, typed description of one user-facing failure. It
// deliberately carries neither a causal error nor arbitrary bytes, so adapters
// must redact any untrusted detail before constructing it.
type Diagnostic struct {
	stage                  string
	failureClass           domain.FailureClass
	machineCode            string
	message                string
	role                   string
	provider               string
	attemptID              domain.AttemptID
	fallbackAttempted      bool
	fallbackProhibited     bool
	artifactPath           string
	recommendedNextCommand string
	retryableOverride      *bool
}

// NewDiagnosticWithRetryable constructs a diagnostic whose command-envelope
// retryability is defined by a command-owned outcome contract rather than the
// generic provider fallback policy.
func NewDiagnosticWithRetryable(
	stage string,
	failureClass domain.FailureClass,
	machineCode string,
	message string,
	retryable bool,
) (Diagnostic, error) {
	diagnostic, err := NewDiagnostic(stage, failureClass, machineCode, message, "", "", domain.AttemptID{}, false, false, "", "")
	if err != nil {
		return Diagnostic{}, err
	}
	diagnostic.retryableOverride = new(bool)
	*diagnostic.retryableOverride = retryable
	return diagnostic, nil
}

// NewDiagnosticWithRetryableArtifactPath constructs a diagnostic with both a
// command-owned retryability override and an installed, redacted artifact path.
func NewDiagnosticWithRetryableArtifactPath(
	stage string,
	failureClass domain.FailureClass,
	machineCode string,
	message string,
	retryable bool,
	artifactPath string,
) (Diagnostic, error) {
	diagnostic, err := NewDiagnostic(stage, failureClass, machineCode, message, "", "", domain.AttemptID{}, false, false, artifactPath, "")
	if err != nil {
		return Diagnostic{}, err
	}
	diagnostic.retryableOverride = new(bool)
	*diagnostic.retryableOverride = retryable
	return diagnostic, nil
}

// NewDiagnosticWithRetryableDetails constructs a command-owned retryable
// diagnostic while retaining closed provider attribution and a redacted
// remediation command.
func NewDiagnosticWithRetryableDetails(
	stage string,
	failureClass domain.FailureClass,
	machineCode string,
	message string,
	retryable bool,
	role string,
	provider string,
	artifactPath string,
	recommendedNextCommand string,
) (Diagnostic, error) {
	diagnostic, err := NewDiagnostic(
		stage, failureClass, machineCode, message, role, provider,
		domain.AttemptID{}, false, false, artifactPath, recommendedNextCommand,
	)
	if err != nil {
		return Diagnostic{}, err
	}
	diagnostic.retryableOverride = new(bool)
	*diagnostic.retryableOverride = retryable
	return diagnostic, nil
}

// NewDiagnostic constructs a typed, redacted user-facing diagnostic. Empty
// role, provider, attempt ID, artifact path, and recommended command represent
// fields that are not applicable to this failure.
func NewDiagnostic(
	stage string,
	failureClass domain.FailureClass,
	machineCode string,
	message string,
	role string,
	provider string,
	attemptID domain.AttemptID,
	fallbackAttempted bool,
	fallbackProhibited bool,
	artifactPath string,
	recommendedNextCommand string,
) (Diagnostic, error) {
	diagnostic := Diagnostic{
		stage:                  stage,
		failureClass:           failureClass,
		machineCode:            machineCode,
		message:                message,
		role:                   role,
		provider:               provider,
		attemptID:              attemptID,
		fallbackAttempted:      fallbackAttempted,
		fallbackProhibited:     fallbackProhibited,
		artifactPath:           artifactPath,
		recommendedNextCommand: recommendedNextCommand,
	}
	if err := diagnostic.validate(); err != nil {
		return Diagnostic{}, err
	}
	return diagnostic, nil
}

// Stage returns the application stage that classified the failure.
func (diagnostic Diagnostic) Stage() string { return diagnostic.stage }

// FailureClass returns the typed domain failure class.
func (diagnostic Diagnostic) FailureClass() domain.FailureClass { return diagnostic.failureClass }

// MachineCode returns the stable machine-readable reason code.
func (diagnostic Diagnostic) MachineCode() string { return diagnostic.machineCode }

// Message returns the redacted user-facing explanation.
func (diagnostic Diagnostic) Message() string { return diagnostic.message }

// Role returns the optional functional role identifier.
func (diagnostic Diagnostic) Role() string { return diagnostic.role }

// Provider returns the optional provider instance identifier.
func (diagnostic Diagnostic) Provider() string { return diagnostic.provider }

// AttemptID returns the optional provider attempt identifier. Its zero value
// means no attempt applies to this diagnostic.
func (diagnostic Diagnostic) AttemptID() domain.AttemptID { return diagnostic.attemptID }

// FallbackAttempted reports whether a fallback was attempted for this failure.
func (diagnostic Diagnostic) FallbackAttempted() bool { return diagnostic.fallbackAttempted }

// FallbackProhibited reports whether policy prohibited fallback for this failure.
func (diagnostic Diagnostic) FallbackProhibited() bool { return diagnostic.fallbackProhibited }

// ArtifactPath returns the optional redacted diagnostic artifact path.
func (diagnostic Diagnostic) ArtifactPath() string { return diagnostic.artifactPath }

// RecommendedNextCommand returns the optional redacted next command.
func (diagnostic Diagnostic) RecommendedNextCommand() string {
	return diagnostic.recommendedNextCommand
}

// Retryable returns the command-owned retryability override when present and
// otherwise preserves the historical failure-class fallback mapping.
func (diagnostic Diagnostic) Retryable() bool {
	if diagnostic.retryableOverride != nil {
		return *diagnostic.retryableOverride
	}
	return diagnostic.failureClass.FallbackAllowed()
}

// CommandResult is the immutable application result consumed by a CLI adapter.
type CommandResult struct {
	command          CommandName
	ok               bool
	exitCode         ExitCode
	data             []byte
	diagnostics      []Diagnostic
	committedReasons []CommittedReason
}

// CommittedReason is one safe, stable reason attached to a data-bearing P2
// outcome. Message may be empty, in which case the CLI supplies its historical
// generic text for the code.
type CommittedReason struct {
	code    string
	message string
}

func NewCommittedReason(code, message string) (CommittedReason, error) {
	if !validMachineCode(code) {
		return CommittedReason{}, invalidCommandResult("committed reason code %q is invalid", code)
	}
	if err := validateText(message, 1024); err != nil {
		return CommittedReason{}, invalidCommandResult("committed reason message is unsafe")
	}
	return CommittedReason{code: code, message: message}, nil
}

func (reason CommittedReason) Code() string    { return reason.code }
func (reason CommittedReason) Message() string { return reason.message }

// NewCommandResult validates a command-result combination and takes ownership
// of data and diagnostics. Successful results must be success/0, carry no
// diagnostics, and provide exactly one non-null JSON object. Failed results
// must use a nonzero assigned exit, carry no data, and include at least one
// typed diagnostic with a machine code and message.
func NewCommandResult(command CommandName, ok bool, exitCode ExitCode, data []byte, diagnostics []Diagnostic) (CommandResult, error) {
	if !command.Valid() {
		return CommandResult{}, invalidCommandResult("unknown command %q", command)
	}
	if !exitCode.Valid() {
		return CommandResult{}, invalidCommandResult("unassigned exit code %d", exitCode)
	}
	if ok {
		if exitCode != ExitCodeSuccess {
			return CommandResult{}, invalidCommandResult("successful result must use exit 0")
		}
		if len(diagnostics) != 0 {
			return CommandResult{}, invalidCommandResult("successful result must not carry diagnostics")
		}
		if _, err := DecodeStrictJSONObject(data); err != nil {
			return CommandResult{}, invalidCommandResult("successful result data must be exactly one non-null JSON object: %v", err)
		}
		return CommandResult{command: command, ok: true, exitCode: ExitCodeSuccess, data: cloneBytes(data)}, nil
	}

	if exitCode == ExitCodeSuccess {
		return CommandResult{}, invalidCommandResult("failed result must use a nonzero exit")
	}
	if len(data) != 0 {
		return CommandResult{}, invalidCommandResult("failed result must not carry data")
	}
	if len(diagnostics) == 0 {
		return CommandResult{}, invalidCommandResult("failed result requires a diagnostic")
	}
	for index, diagnostic := range diagnostics {
		if err := diagnostic.validate(); err != nil {
			return CommandResult{}, invalidCommandResult("diagnostic %d: %v", index, err)
		}
	}
	return CommandResult{
		command:     command,
		ok:          false,
		exitCode:    exitCode,
		diagnostics: cloneDiagnostics(diagnostics),
	}, nil
}

// NewCommandSuccess creates an OK command result with caller-owned data that
// contains exactly one non-null JSON object.
func NewCommandSuccess(command CommandName, data []byte) (CommandResult, error) {
	return NewCommandResult(command, true, ExitCodeSuccess, data, nil)
}

// NewCommandFailure creates a typed failed command result. Every diagnostic is
// retained in order, allowing a command to preserve independent root causes.
func NewCommandFailure(command CommandName, exitCode ExitCode, diagnostics ...Diagnostic) (CommandResult, error) {
	return NewCommandResult(command, false, exitCode, nil, diagnostics)
}

// NewCommittedCommandOutcome creates a data-bearing child workflow outcome from
// verified terminal authority. Its policy and readiness exits are committed
// outcomes, not transport failures, and retain every stable terminal reason.
func NewCommittedCommandOutcome(command CommandName, exitCode ExitCode, data []byte, reasons []string) (CommandResult, error) {
	details := make([]CommittedReason, len(reasons))
	for index, reason := range reasons {
		parsed, err := NewCommittedReason(reason, "")
		if err != nil {
			return CommandResult{}, invalidCommandResult("committed terminal reason %d is invalid", index)
		}
		details[index] = parsed
	}
	return NewCommittedCommandOutcomeWithReasons(command, exitCode, data, details)
}

// NewCommittedCommandOutcomeWithReasons preserves safe attributed messages for
// each independent terminal reason without changing the v1 wire shape.
func NewCommittedCommandOutcomeWithReasons(command CommandName, exitCode ExitCode, data []byte, reasons []CommittedReason) (CommandResult, error) {
	if !command.Valid() {
		return CommandResult{}, invalidCommandResult("unknown command %q", command)
	}
	switch exitCode {
	case ExitCodeSuccess, ExitCodePolicy, ExitCodeReadiness:
	default:
		return CommandResult{}, invalidCommandResult("committed outcome must use exit 0, 1, or 4")
	}
	if _, err := DecodeStrictJSONObject(data); err != nil {
		return CommandResult{}, invalidCommandResult("committed outcome data must be exactly one non-null JSON object: %v", err)
	}
	if len(reasons) == 0 {
		return CommandResult{}, invalidCommandResult("committed outcome requires a terminal reason")
	}
	for index, reason := range reasons {
		if !validMachineCode(reason.code) || validateText(reason.message, 1024) != nil {
			return CommandResult{}, invalidCommandResult("committed terminal reason %d is invalid", index)
		}
	}
	return CommandResult{
		command:          command,
		ok:               exitCode == ExitCodeSuccess,
		exitCode:         exitCode,
		data:             cloneBytes(data),
		committedReasons: append([]CommittedReason(nil), reasons...),
	}, nil
}

// Command returns the command that produced this result.
func (result CommandResult) Command() CommandName { return result.command }

// OK reports whether the command completed with a success exit.
func (result CommandResult) OK() bool { return result.ok }

// ExitCode returns the assigned CLI exit projection.
func (result CommandResult) ExitCode() ExitCode { return result.exitCode }

// Data returns a caller-owned copy of successful or committed result data.
// Transport failures always return nil data.
func (result CommandResult) Data() []byte { return cloneBytes(result.data) }

// Diagnostics returns a caller-owned copy of the ordered typed diagnostics.
func (result CommandResult) Diagnostics() []Diagnostic { return cloneDiagnostics(result.diagnostics) }

// CommittedOutcome reports whether the result is a verified child workflow
// terminal outcome rather than an ordinary success or transport failure.
func (result CommandResult) CommittedOutcome() bool { return len(result.committedReasons) != 0 }

// CommittedReasons returns caller-owned stable terminal reasons.
func (result CommandResult) CommittedReasons() []CommittedReason {
	return append([]CommittedReason(nil), result.committedReasons...)
}

func (diagnostic Diagnostic) validate() error {
	if err := validateText(diagnostic.stage, 128); err != nil || diagnostic.stage == "" {
		return invalidCommandResult("diagnostic stage must be non-empty and safe")
	}
	if !diagnostic.failureClass.Valid() {
		return invalidCommandResult("diagnostic failure class %q is unknown", diagnostic.failureClass)
	}
	if !validMachineCode(diagnostic.machineCode) {
		return invalidCommandResult("diagnostic machine code %q is invalid", diagnostic.machineCode)
	}
	if err := validateText(diagnostic.message, 1024); err != nil || diagnostic.message == "" {
		return invalidCommandResult("diagnostic message must be non-empty and safe")
	}
	if diagnostic.role != "" && !validRole(diagnostic.role) {
		return invalidCommandResult("diagnostic role %q is invalid", diagnostic.role)
	}
	if diagnostic.provider != "" && !validProvider(diagnostic.provider) {
		return invalidCommandResult("diagnostic provider %q is invalid", diagnostic.provider)
	}
	if err := validateText(diagnostic.artifactPath, 4096); err != nil {
		return invalidCommandResult("diagnostic artifact path must be safe")
	}
	if err := validateText(diagnostic.recommendedNextCommand, 4096); err != nil {
		return invalidCommandResult("diagnostic recommended command must be safe")
	}
	return nil
}

func validMachineCode(value string) bool {
	if len(value) == 0 || len(value) > 64 || !isLowerLetter(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if !isLowerLetter(character) && !(character >= '0' && character <= '9') && character != '_' {
			return false
		}
	}
	return true
}

func validRole(value string) bool {
	if len(value) == 0 || len(value) > 64 || !isLowerLetter(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if !isLowerLetter(character) && !(character >= '0' && character <= '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validProvider(value string) bool {
	if len(value) == 0 || len(value) > 64 || !isLowerLetter(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if !isLowerLetter(character) && !(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func isLowerLetter(character rune) bool {
	return character >= 'a' && character <= 'z'
}

func validateText(value string, maximumLength int) error {
	if len(value) > maximumLength {
		return fmt.Errorf("contains more than %d bytes", maximumLength)
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("contains NUL or a line break")
	}
	return nil
}

// DecodeStrictJSONObject decodes raw JSON as exactly one non-null object. It
// rejects trailing values and duplicate object keys at every nesting level.
func DecodeStrictJSONObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("contains invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	value, err := decodeStrictJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("contains trailing JSON value")
		}
		return nil, fmt.Errorf("contains trailing data: %w", err)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be a non-null JSON object")
	}
	return object, nil
}

func decodeStrictJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("contains duplicate object key %q", key)
			}

			value, err := decodeStrictJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}

		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim('}') {
			return nil, fmt.Errorf("object is not terminated")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeStrictJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}

		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim(']') {
			return nil, fmt.Errorf("array is not terminated")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}
func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneDiagnostics(value []Diagnostic) []Diagnostic {
	if value == nil {
		return nil
	}
	copyValue := make([]Diagnostic, len(value))
	copy(copyValue, value)
	return copyValue
}
func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	copyValue := make([]string, len(value))
	copy(copyValue, value)
	return copyValue
}

func invalidCommandResult(format string, arguments ...any) error {
	return fmt.Errorf("command result: %w: %s", domain.ErrInvariant, fmt.Sprintf(format, arguments...))
}
