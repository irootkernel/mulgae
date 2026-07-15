package ports

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

// ConcurrencyKey is the stable, normalized identity of one serialized provider
// lane. It is opaque so every equal key compares equal without caller-defined
// spelling rules.
type ConcurrencyKey struct{ value string }

// ParseConcurrencyKey NFC-normalizes and ASCII-lowercases value before
// validating the canonical lane-key grammar. It never trims or otherwise
// aliases input.
func ParseConcurrencyKey(value string) (ConcurrencyKey, error) {
	normalized, err := normalizeConcurrencyKey(value)
	if err != nil {
		return ConcurrencyKey{}, fmt.Errorf("concurrency key: %w", err)
	}
	return ConcurrencyKey{value: normalized}, nil
}

// String returns the canonical lane-key value.
func (key ConcurrencyKey) String() string { return key.value }

// Valid reports whether key is a canonical concurrency key.
func (key ConcurrencyKey) Valid() bool { return validateCanonicalConcurrencyKey(key.value) == nil }

// ProviderRoute binds one safe provider instance to its normalized concurrency
// lane. It contains no provider-family or live-runtime authority.
type ProviderRoute struct {
	providerInstance string
	concurrencyKey   ConcurrencyKey
}

// NewProviderRoute validates an immutable provider-instance-to-lane binding.
func NewProviderRoute(providerInstance string, concurrencyKey ConcurrencyKey) (ProviderRoute, error) {
	if !validProviderInstanceID(providerInstance) {
		return ProviderRoute{}, fmt.Errorf("provider route: invalid provider instance %q", providerInstance)
	}
	if !concurrencyKey.Valid() {
		return ProviderRoute{}, fmt.Errorf("provider route: invalid concurrency key")
	}
	return ProviderRoute{providerInstance: providerInstance, concurrencyKey: concurrencyKey}, nil
}

// ProviderInstance returns the safe provider instance identifier.
func (route ProviderRoute) ProviderInstance() string { return route.providerInstance }

// ConcurrencyKey returns the normalized lane key selected for the provider.
func (route ProviderRoute) ConcurrencyKey() ConcurrencyKey { return route.concurrencyKey }

// Valid reports whether route is a valid provider-instance-to-lane binding.
func (route ProviderRoute) Valid() bool {
	return validProviderInstanceID(route.providerInstance) && route.concurrencyKey.Valid()
}

// EnvironmentVariable is one explicit, portable process-environment entry.
type EnvironmentVariable struct {
	name  string
	value string
}

// NewEnvironmentVariable validates a portable environment name and NUL-free
// value. The value is otherwise opaque to this provider-neutral port.
func NewEnvironmentVariable(name, value string) (EnvironmentVariable, error) {
	if err := validateEnvironmentVariable(name, value); err != nil {
		return EnvironmentVariable{}, fmt.Errorf("environment variable: %w", err)
	}
	return EnvironmentVariable{name: name, value: value}, nil
}

// Name returns the portable environment name.
func (variable EnvironmentVariable) Name() string { return variable.name }

// Value returns the NUL-free environment value.
func (variable EnvironmentVariable) Value() string { return variable.value }

// Valid reports whether variable has a portable name and NUL-free value.
func (variable EnvironmentVariable) Valid() bool {
	return validateEnvironmentVariable(variable.name, variable.value) == nil
}

// ProcessRequest is the complete direct-execution request for one child
// process. Its fields deliberately exclude shell commands, TTY settings, and
// inherited environment state. Environment is the complete environment actually
// supplied through exec.Cmd.Env. Slice accessors return caller-owned copies.
type ProcessRequest struct {
	executable       string
	argv             []string
	environment      []EnvironmentVariable
	workingDirectory string
	stdin            []byte
	timeout          time.Duration
	maxStdoutBytes   int64
	maxStderrBytes   int64
	concurrencyKey   ConcurrencyKey
}

// NewProcessRequest validates a direct child-process request and retains
// defensive copies of argv, environment, and stdin. Environment entries are
// completed with the exact working-directory PWD, sorted by portable name, and
// must be unique.
func NewProcessRequest(
	executable string,
	argv []string,
	environment []EnvironmentVariable,
	workingDirectory string,
	stdin []byte,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
	concurrencyKey ConcurrencyKey,
) (ProcessRequest, error) {
	if err := validateAbsoluteWorkingDirectory(workingDirectory); err != nil {
		return ProcessRequest{}, fmt.Errorf("process request: working directory: %w", err)
	}

	canonicalEnvironment := cloneEnvironmentVariables(environment)
	hasPWD := false
	for _, variable := range canonicalEnvironment {
		if variable.name != "PWD" {
			continue
		}
		if variable.value != workingDirectory {
			return ProcessRequest{}, fmt.Errorf("process request: environment: PWD must exactly equal working directory")
		}
		hasPWD = true
	}
	if !hasPWD {
		canonicalEnvironment = append(canonicalEnvironment, EnvironmentVariable{
			name:  "PWD",
			value: workingDirectory,
		})
	}
	sort.Slice(canonicalEnvironment, func(left, right int) bool {
		return canonicalEnvironment[left].name < canonicalEnvironment[right].name
	})

	request := ProcessRequest{
		executable:       executable,
		argv:             cloneStrings(argv),
		environment:      canonicalEnvironment,
		workingDirectory: workingDirectory,
		stdin:            cloneBytes(stdin),
		timeout:          timeout,
		maxStdoutBytes:   maxStdoutBytes,
		maxStderrBytes:   maxStderrBytes,
		concurrencyKey:   concurrencyKey,
	}
	if err := validateProcessRequest(request); err != nil {
		return ProcessRequest{}, fmt.Errorf("process request: %w", err)
	}
	return request, nil
}

// Executable returns the absolute, canonical resolved executable path.
func (request ProcessRequest) Executable() string { return request.executable }

// Argv returns a caller-owned copy of the exact direct-execution argv.
func (request ProcessRequest) Argv() []string { return cloneStrings(request.argv) }

// Environment returns a caller-owned copy of the sorted complete environment
// actually supplied through exec.Cmd.Env.
func (request ProcessRequest) Environment() []EnvironmentVariable {
	return cloneEnvironmentVariables(request.environment)
}

// WorkingDirectory returns the absolute process working directory.
func (request ProcessRequest) WorkingDirectory() string { return request.workingDirectory }

// Stdin returns a caller-owned copy of the exact process stdin bytes.
func (request ProcessRequest) Stdin() []byte { return cloneBytes(request.stdin) }

// Timeout returns the exact positive process deadline.
func (request ProcessRequest) Timeout() time.Duration { return request.timeout }

// MaxStdoutBytes returns the independent positive stdout capture cap.
func (request ProcessRequest) MaxStdoutBytes() int64 { return request.maxStdoutBytes }

// MaxStderrBytes returns the independent positive stderr capture cap.
func (request ProcessRequest) MaxStderrBytes() int64 { return request.maxStderrBytes }

// ConcurrencyKey returns the validated lane key for this process request.
func (request ProcessRequest) ConcurrencyKey() ConcurrencyKey { return request.concurrencyKey }

// Valid reports whether request remains a complete canonical direct-execution request.
func (request ProcessRequest) Valid() bool { return validateProcessRequest(request) == nil }

// ProcessTermination is the closed set of neutral child-process termination facts.
type ProcessTermination string

const (
	ProcessTerminationExited               ProcessTermination = "exited"
	ProcessTerminationSignaled             ProcessTermination = "signaled"
	ProcessTerminationStartFailed          ProcessTermination = "start_failed"
	ProcessTerminationStartUnavailable     ProcessTermination = "start_unavailable"
	ProcessTerminationStartConfiguration   ProcessTermination = "start_configuration"
	ProcessTerminationStartSecurity        ProcessTermination = "start_security"
	ProcessTerminationTimedOut             ProcessTermination = "timed_out"
	ProcessTerminationCancelled            ProcessTermination = "cancelled"
	ProcessTerminationStdoutLimit          ProcessTermination = "stdout_limit"
	ProcessTerminationStderrLimit          ProcessTermination = "stderr_limit"
	ProcessTerminationStdinIncomplete      ProcessTermination = "stdin_incomplete"
	ProcessTerminationResidualProcessGroup ProcessTermination = "residual_process_group"
	ProcessTerminationLockFailed           ProcessTermination = "lock_failed"
	ProcessTerminationLockUnavailable      ProcessTermination = "lock_unavailable"
	ProcessTerminationLockConfiguration    ProcessTermination = "lock_configuration"
	ProcessTerminationLockSecurity         ProcessTermination = "lock_security"
)

// Valid reports whether termination is one of the closed process facts.
func (termination ProcessTermination) Valid() bool {
	switch termination {
	case ProcessTerminationExited,
		ProcessTerminationSignaled,
		ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationTimedOut,
		ProcessTerminationCancelled,
		ProcessTerminationStdoutLimit,
		ProcessTerminationStderrLimit,
		ProcessTerminationStdinIncomplete,
		ProcessTerminationResidualProcessGroup,
		ProcessTerminationLockFailed,
		ProcessTerminationLockUnavailable,
		ProcessTerminationLockConfiguration,
		ProcessTerminationLockSecurity:
		return true
	default:
		return false
	}
}

// ProcessSignal is an immutable numeric and symbolic signal fact observed for
// a process that terminated because it received a signal.
type ProcessSignal struct {
	number int
	name   string
}

// NewProcessSignal validates one exact signal fact.
func NewProcessSignal(number int, name string) (ProcessSignal, error) {
	signal := ProcessSignal{number: number, name: name}
	if err := validateProcessSignal(signal); err != nil {
		return ProcessSignal{}, fmt.Errorf("process signal: %w", err)
	}
	return signal, nil
}

// Number returns the positive operating-system signal number.
func (signal ProcessSignal) Number() int { return signal.number }

// Name returns the canonical operating-system signal name.
func (signal ProcessSignal) Name() string { return signal.name }

// Valid reports whether signal remains a valid immutable signal fact.
func (signal ProcessSignal) Valid() bool { return validateProcessSignal(signal) == nil }

// StdinWriteReceipt is the immutable record of bytes successfully written to
// one child stdin pipe. SHA256 is the raw lower-case hexadecimal digest of
// "KAR-PROVIDER-STDIN/1" || 0x00 || those exact successful bytes.
type StdinWriteReceipt struct {
	intendedByteLength int64
	writtenByteCount   int64
	sha256             string
	complete           bool
}

// NewStdinWriteReceipt validates one stdin write fact. Complete must agree
// exactly with the intended and successfully written byte counts.
func NewStdinWriteReceipt(
	intendedByteLength, writtenByteCount int64,
	sha256 string,
	complete bool,
) (StdinWriteReceipt, error) {
	receipt := StdinWriteReceipt{
		intendedByteLength: intendedByteLength,
		writtenByteCount:   writtenByteCount,
		sha256:             sha256,
		complete:           complete,
	}
	if err := validateStdinWriteReceipt(receipt); err != nil {
		return StdinWriteReceipt{}, fmt.Errorf("stdin write receipt: %w", err)
	}
	return receipt, nil
}

// IntendedByteLength returns the exact requested stdin byte length.
func (receipt StdinWriteReceipt) IntendedByteLength() int64 {
	return receipt.intendedByteLength
}

// WrittenByteCount returns the exact number of bytes accepted by the child
// stdin pipe before it closed or the request completed.
func (receipt StdinWriteReceipt) WrittenByteCount() int64 {
	return receipt.writtenByteCount
}

// SHA256 returns the raw domain-separated digest of exactly the successfully
// written stdin bytes.
func (receipt StdinWriteReceipt) SHA256() string { return receipt.sha256 }

// Complete reports whether every intended stdin byte was successfully written.
func (receipt StdinWriteReceipt) Complete() bool { return receipt.complete }

// Valid reports whether receipt is a coherent immutable stdin write fact.
func (receipt StdinWriteReceipt) Valid() bool {
	return validateStdinWriteReceipt(receipt) == nil
}

// ProcessObservation is the immutable, provider-neutral fact record from one
// direct process attempt. It intentionally contains no repair, fallback,
// finding, validation, or outcome authority.
type ProcessObservation struct {
	stdout            []byte
	stderr            []byte
	exitCode          int
	hasExitCode       bool
	signal            ProcessSignal
	hasSignal         bool
	termination       ProcessTermination
	stdinWriteReceipt StdinWriteReceipt
	startedAt         time.Time
	endedAt           time.Time
}

// NewProcessObservation validates neutral process facts and retains defensive
// copies of stdout and stderr. An exited process has a nonnegative exit code
// and no signal; a signaled process has one valid signal and no exit code.
func NewProcessObservation(
	stdout, stderr []byte,
	exitCode *int,
	termination ProcessTermination,
	stdinWriteReceipt StdinWriteReceipt,
	startedAt, endedAt time.Time,
	signals ...ProcessSignal,
) (ProcessObservation, error) {
	signal, err := optionalProcessSignal(signals)
	if err != nil {
		return ProcessObservation{}, fmt.Errorf("process observation: %w", err)
	}
	if err := validateProcessObservation(exitCode, signal, termination, stdinWriteReceipt, startedAt, endedAt); err != nil {
		return ProcessObservation{}, fmt.Errorf("process observation: %w", err)
	}

	observation := ProcessObservation{
		stdout:            cloneBytes(stdout),
		stderr:            cloneBytes(stderr),
		termination:       termination,
		stdinWriteReceipt: stdinWriteReceipt,
		startedAt:         startedAt,
		endedAt:           endedAt,
	}
	if exitCode != nil {
		observation.exitCode = *exitCode
		observation.hasExitCode = true
	}
	if signal != nil {
		observation.signal = *signal
		observation.hasSignal = true
	}
	return observation, nil
}

// Stdout returns a caller-owned copy of captured stdout bytes.
func (observation ProcessObservation) Stdout() []byte { return cloneBytes(observation.stdout) }

// Stderr returns a caller-owned copy of captured stderr bytes.
func (observation ProcessObservation) Stderr() []byte { return cloneBytes(observation.stderr) }

// ExitCode returns the process exit code when the process terminated by exit.
func (observation ProcessObservation) ExitCode() (int, bool) {
	return observation.exitCode, observation.hasExitCode
}

// Signal returns the exact operating-system signal fact when the process
// terminated because it received a signal.
func (observation ProcessObservation) Signal() (number int, name string, ok bool) {
	return observation.signal.Number(), observation.signal.Name(), observation.hasSignal
}

// Termination returns the closed neutral termination fact.
func (observation ProcessObservation) Termination() ProcessTermination {
	return observation.termination
}

// StartedAt returns the observed UTC process-start time.
func (observation ProcessObservation) StartedAt() time.Time { return observation.startedAt }

// EndedAt returns the observed UTC process-end time.
func (observation ProcessObservation) EndedAt() time.Time { return observation.endedAt }

// StdinWriteReceipt returns the immutable exact-write fact for child stdin.
func (observation ProcessObservation) StdinWriteReceipt() StdinWriteReceipt {
	return observation.stdinWriteReceipt
}

// Succeeded reports the neutral direct-execution success fact: normal exit code
// zero after every intended stdin byte was successfully written.
func (observation ProcessObservation) Succeeded() bool {
	return observation.termination == ProcessTerminationExited &&
		observation.hasExitCode &&
		observation.exitCode == 0 &&
		observation.stdinWriteReceipt.Valid() &&
		observation.stdinWriteReceipt.Complete()
}

// Valid reports whether observation remains a coherent neutral process fact record.
func (observation ProcessObservation) Valid() bool {
	var exitCode *int
	if observation.hasExitCode {
		exitCode = &observation.exitCode
	}
	var signal *ProcessSignal
	if observation.hasSignal {
		signal = &observation.signal
	}
	return validateProcessObservation(
		exitCode,
		signal,
		observation.termination,
		observation.stdinWriteReceipt,
		observation.startedAt,
		observation.endedAt,
	) == nil
}

// ProcessRunner executes one direct process request. Implementations must
// reject a nil context and must never introduce shell or TTY behavior.
type ProcessRunner interface {
	Run(context.Context, ProcessRequest) (ProcessObservation, error)
}

// LaneAcquisitionFailureClass is the closed policy-relevant cause of a failed
// cross-process lane acquisition.
type LaneAcquisitionFailureClass string

const (
	LaneAcquisitionUnavailable   LaneAcquisitionFailureClass = "unavailable"
	LaneAcquisitionConfiguration LaneAcquisitionFailureClass = "configuration"
	LaneAcquisitionSecurity      LaneAcquisitionFailureClass = "security"
	LaneAcquisitionInternal      LaneAcquisitionFailureClass = "internal"
)

// Valid reports whether the class is a closed lane-acquisition cause.
func (class LaneAcquisitionFailureClass) Valid() bool {
	return class == LaneAcquisitionUnavailable ||
		class == LaneAcquisitionConfiguration ||
		class == LaneAcquisitionSecurity ||
		class == LaneAcquisitionInternal
}

// LaneAcquisitionFailure is implemented by adapter errors that carry a safe,
// policy-relevant acquisition class without exposing raw filesystem text.
type LaneAcquisitionFailure interface {
	error
	LaneAcquisitionFailureClass() LaneAcquisitionFailureClass
}

// ClassifyLaneAcquisitionFailure returns the closed class carried by err.
// Unknown adapter errors fail closed as internal rather than becoming
// fallback-eligible provider unavailability.
func ClassifyLaneAcquisitionFailure(err error) LaneAcquisitionFailureClass {
	if err == nil {
		return ""
	}
	var classified LaneAcquisitionFailure
	if errors.As(err, &classified) {
		class := classified.LaneAcquisitionFailureClass()
		if class.Valid() {
			return class
		}
	}
	return LaneAcquisitionInternal
}

// LaneLocker acquires authoritative cross-process serialization for one
// normalized lane key. Implementations must reject a nil context and must use
// the operating-system lock primitive as authority; stale lock metadata is
// diagnostic only and cannot block acquisition by itself.
type LaneLocker interface {
	Acquire(context.Context, ConcurrencyKey) (LaneLease, error)
}

// LaneLease is an acquired authoritative lane lock. The key identifies exactly
// the lane held by the lease; Release relinquishes that authority.
type LaneLease interface {
	Key() ConcurrencyKey
	Release() error
}

func normalizeConcurrencyKey(value string) (string, error) {
	normalized := norm.NFC.String(value)
	for index := 0; index < len(normalized); index++ {
		if normalized[index] > 0x7f {
			return "", fmt.Errorf("must contain ASCII characters only")
		}
	}
	normalized = asciiLower(normalized)
	if err := validateCanonicalConcurrencyKey(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

func validateCanonicalConcurrencyKey(value string) error {
	if len(value) == 0 || len(value) > 64 {
		return fmt.Errorf("must contain 1 through 64 characters")
	}
	if !asciiLowerAlphaNumeric(value[0]) || !asciiLowerAlphaNumeric(value[len(value)-1]) {
		return fmt.Errorf("must start and end with a lowercase ASCII letter or digit")
	}
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if asciiLowerAlphaNumeric(character) || character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("must match [a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")
	}
	return nil
}

func asciiLower(value string) string {
	for index := 0; index < len(value); index++ {
		if value[index] >= 'A' && value[index] <= 'Z' {
			bytes := []byte(value)
			for index := range bytes {
				if bytes[index] >= 'A' && bytes[index] <= 'Z' {
					bytes[index] += 'a' - 'A'
				}
			}
			return string(bytes)
		}
	}
	return value
}

func asciiLowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validateEnvironmentVariable(name, value string) error {
	if name == "" {
		return fmt.Errorf("name must be non-empty")
	}
	if !asciiEnvironmentNameStart(name[0]) {
		return fmt.Errorf("name must start with an ASCII letter or underscore")
	}
	for index := 1; index < len(name); index++ {
		if !asciiEnvironmentNamePart(name[index]) {
			return fmt.Errorf("name must contain only ASCII letters, digits, or underscores")
		}
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("value must not contain NUL")
	}
	return nil
}

func asciiEnvironmentNameStart(character byte) bool {
	return character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z' ||
		character == '_'
}

func asciiEnvironmentNamePart(character byte) bool {
	return asciiEnvironmentNameStart(character) || character >= '0' && character <= '9'
}

func cloneEnvironmentVariables(value []EnvironmentVariable) []EnvironmentVariable {
	copyValue := make([]EnvironmentVariable, len(value))
	copy(copyValue, value)
	return copyValue
}

func validateAbsoluteWorkingDirectory(value string) error {
	if value == "" {
		return fmt.Errorf("must be non-empty")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("must not contain NUL")
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("must be absolute")
	}
	return nil
}

func validateProcessRequest(request ProcessRequest) error {
	if err := validateAnchoredRoot(request.executable); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if len(request.argv) == 0 {
		return fmt.Errorf("argv must be non-empty")
	}
	if request.argv[0] != request.executable {
		return fmt.Errorf("argv[0] must exactly equal executable")
	}
	for index, argument := range request.argv {
		if strings.ContainsRune(argument, 0) {
			return fmt.Errorf("argv[%d] must not contain NUL", index)
		}
	}
	if err := validateProcessEnvironment(request.environment, request.workingDirectory); err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	if err := validateAbsoluteWorkingDirectory(request.workingDirectory); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	if request.timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if request.maxStdoutBytes <= 0 {
		return fmt.Errorf("maximum stdout bytes must be positive")
	}
	if request.maxStderrBytes <= 0 {
		return fmt.Errorf("maximum stderr bytes must be positive")
	}
	if !request.concurrencyKey.Valid() {
		return fmt.Errorf("invalid concurrency key")
	}
	return nil
}

func validateCanonicalEnvironment(environment []EnvironmentVariable) error {
	for index, variable := range environment {
		if !variable.Valid() {
			return fmt.Errorf("entry %d is invalid", index)
		}
		if index > 0 && environment[index-1].name >= variable.name {
			return fmt.Errorf("entries must be sorted by unique name")
		}
	}
	return nil
}
func validateProcessEnvironment(environment []EnvironmentVariable, workingDirectory string) error {
	if err := validateCanonicalEnvironment(environment); err != nil {
		return err
	}
	for _, variable := range environment {
		if variable.name == "PWD" {
			if variable.value != workingDirectory {
				return fmt.Errorf("PWD must exactly equal working directory")
			}
			return nil
		}
	}
	return fmt.Errorf("PWD is required")
}

func validateStdinWriteReceipt(receipt StdinWriteReceipt) error {
	if receipt.intendedByteLength < 0 {
		return fmt.Errorf("intended byte length must not be negative")
	}
	if receipt.writtenByteCount < 0 || receipt.writtenByteCount > receipt.intendedByteLength {
		return fmt.Errorf("written byte count must be within intended byte length")
	}
	if err := validateRawSHA256(receipt.sha256); err != nil {
		return fmt.Errorf("invalid SHA-256: %w", err)
	}
	if receipt.complete != (receipt.writtenByteCount == receipt.intendedByteLength) {
		return fmt.Errorf("complete must exactly match written and intended byte counts")
	}
	return nil
}

func optionalProcessSignal(signals []ProcessSignal) (*ProcessSignal, error) {
	switch len(signals) {
	case 0:
		return nil, nil
	case 1:
		return &signals[0], nil
	default:
		return nil, fmt.Errorf("at most one signal fact is allowed")
	}
}

func validateProcessSignal(signal ProcessSignal) error {
	if signal.number <= 0 {
		return fmt.Errorf("signal number must be positive")
	}
	if len(signal.name) <= len("SIG") || !strings.HasPrefix(signal.name, "SIG") {
		return fmt.Errorf("signal name must use the SIG prefix")
	}
	for index := len("SIG"); index < len(signal.name); index++ {
		character := signal.name[index]
		if character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '+' ||
			character == '-' {
			continue
		}
		return fmt.Errorf("signal name contains invalid character %q", character)
	}
	return nil
}

func validateProcessObservation(
	exitCode *int,
	signal *ProcessSignal,
	termination ProcessTermination,
	stdinWriteReceipt StdinWriteReceipt,
	startedAt, endedAt time.Time,
) error {
	if !termination.Valid() {
		return fmt.Errorf("invalid termination %q", termination)
	}
	if signal != nil && !signal.Valid() {
		return fmt.Errorf("invalid signal")
	}
	if !stdinWriteReceipt.Valid() {
		return fmt.Errorf("invalid stdin write receipt")
	}
	if startedAt.IsZero() || endedAt.IsZero() {
		return fmt.Errorf("start and end times must be non-zero")
	}
	if startedAt.Location() != time.UTC || endedAt.Location() != time.UTC {
		return fmt.Errorf("start and end times must use time.UTC")
	}
	if endedAt.Before(startedAt) {
		return fmt.Errorf("end time must not precede start time")
	}
	switch termination {
	case ProcessTerminationExited:
		if exitCode == nil {
			return fmt.Errorf("exited process must have an exit code")
		}
		if *exitCode < 0 {
			return fmt.Errorf("exit code must not be negative")
		}
		if signal != nil {
			return fmt.Errorf("exited process must not have a signal")
		}
		if !stdinWriteReceipt.Complete() {
			return fmt.Errorf("exited process must have a complete stdin write receipt")
		}
	case ProcessTerminationSignaled:
		if exitCode != nil {
			return fmt.Errorf("signaled process must not have an exit code")
		}
		if signal == nil {
			return fmt.Errorf("signaled process must have a signal")
		}
	default:
		if exitCode != nil {
			return fmt.Errorf("non-exited process must not have an exit code")
		}
		if signal != nil {
			return fmt.Errorf("non-signaled process must not have a signal")
		}
	}
	return nil
}
