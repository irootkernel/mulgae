package ports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

// ProviderExecutionStatus is the closed, provider-neutral execution outcome.
// It records execution facts only; it does not authorize repair, fallback,
// validation, or publication decisions.
type ProviderExecutionStatus string

const (
	ProviderExecutionStatusSucceeded              ProviderExecutionStatus = "succeeded"
	ProviderExecutionStatusUnavailable            ProviderExecutionStatus = "unavailable"
	ProviderExecutionStatusTimedOut               ProviderExecutionStatus = "timeout"
	ProviderExecutionStatusAuthentication         ProviderExecutionStatus = "auth"
	ProviderExecutionStatusQuota                  ProviderExecutionStatus = "quota"
	ProviderExecutionStatusRateLimit              ProviderExecutionStatus = "rate_limit"
	ProviderExecutionStatusSecurityViolation      ProviderExecutionStatus = "security_violation"
	ProviderExecutionStatusMutationViolation      ProviderExecutionStatus = "mutation_violation"
	ProviderExecutionStatusConfigurationViolation ProviderExecutionStatus = "configuration_violation"
	ProviderExecutionStatusArtifactFailure        ProviderExecutionStatus = "artifact_failure"
	ProviderExecutionStatusCancelled              ProviderExecutionStatus = "cancelled"
	ProviderExecutionStatusInternalFailure        ProviderExecutionStatus = "internal_failure"
)

// Valid reports whether status is a closed provider execution outcome.
func (status ProviderExecutionStatus) Valid() bool {
	switch status {
	case ProviderExecutionStatusSucceeded,
		ProviderExecutionStatusUnavailable,
		ProviderExecutionStatusTimedOut,
		ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusSecurityViolation,
		ProviderExecutionStatusMutationViolation,
		ProviderExecutionStatusConfigurationViolation,
		ProviderExecutionStatusArtifactFailure,
		ProviderExecutionStatusCancelled,
		ProviderExecutionStatusInternalFailure:
		return true
	default:
		return false
	}
}

// FailureClass maps a failed execution status to its domain failure class. It
// returns an empty class for a successful or invalid status.
func (status ProviderExecutionStatus) FailureClass() domain.FailureClass {
	switch status {
	case ProviderExecutionStatusUnavailable:
		return domain.FailureProviderUnavailable
	case ProviderExecutionStatusTimedOut:
		return domain.FailureTimeout
	case ProviderExecutionStatusAuthentication:
		return domain.FailureAuthentication
	case ProviderExecutionStatusQuota:
		return domain.FailureQuota
	case ProviderExecutionStatusRateLimit:
		return domain.FailureRateLimit
	case ProviderExecutionStatusSecurityViolation, ProviderExecutionStatusMutationViolation:
		return domain.FailureSecurityPolicy
	case ProviderExecutionStatusConfigurationViolation:
		return domain.FailureConfiguration
	case ProviderExecutionStatusArtifactFailure:
		return domain.FailureArtifact
	case ProviderExecutionStatusCancelled:
		return domain.FailureCancelled
	case ProviderExecutionStatusInternalFailure:
		return domain.FailureInternal
	default:
		return ""
	}
}

// ProviderExecutionObservation is immutable provider-neutral execution
// evidence. It binds a validated invocation identity to exactly one validated
// process observation and either a successful provider result or a classified
// failure. It intentionally grants no repair, fallback, finding, validation,
// or publication authority.
type ProviderExecutionObservation struct {
	status             ProviderExecutionStatus
	invocation         ProviderInvocation
	processObservation ProcessObservation
	result             ProviderResult
	hasResult          bool
	diagnosticCode     string
	stdoutLimit        int64
	stderrLimit        int64
}

// NewSuccessfulProviderExecutionObservation records a successful provider
// result bound to an exactly matching successful process observation.
func NewSuccessfulProviderExecutionObservation(
	invocation ProviderInvocation,
	result ProviderResult,
	processObservation ProcessObservation,
	stdoutLimit, stderrLimit int64,
) (ProviderExecutionObservation, error) {
	canonicalInvocation, err := canonicalProviderInvocation(invocation)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid invocation: %w", err)
	}
	canonicalResult, err := canonicalProviderResult(result)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid result: %w", err)
	}
	canonicalProcess, err := canonicalProcessObservation(processObservation)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid process observation: %w", err)
	}

	observation := ProviderExecutionObservation{
		status:             ProviderExecutionStatusSucceeded,
		invocation:         canonicalInvocation,
		processObservation: canonicalProcess,
		result:             canonicalResult,
		hasResult:          true,
		stdoutLimit:        stdoutLimit,
		stderrLimit:        stderrLimit,
	}
	if err := observation.Validate(); err != nil {
		return ProviderExecutionObservation{}, err
	}
	return observation, nil
}

// NewFailedProviderExecutionObservation records one classified process failure.
// It deliberately accepts no ProviderResult: process stdout and stderr remain
// neutral bounded evidence rather than a successful provider result.
func NewFailedProviderExecutionObservation(
	status ProviderExecutionStatus,
	invocation ProviderInvocation,
	processObservation ProcessObservation,
	diagnosticCode string,
	stdoutLimit, stderrLimit int64,
) (ProviderExecutionObservation, error) {
	canonicalInvocation, err := canonicalProviderInvocation(invocation)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid invocation: %w", err)
	}
	canonicalProcess, err := canonicalProcessObservation(processObservation)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid process observation: %w", err)
	}

	observation := ProviderExecutionObservation{
		status:             status,
		invocation:         canonicalInvocation,
		processObservation: canonicalProcess,
		diagnosticCode:     diagnosticCode,
		stdoutLimit:        stdoutLimit,
		stderrLimit:        stderrLimit,
	}
	if err := observation.Validate(); err != nil {
		return ProviderExecutionObservation{}, err
	}
	return observation, nil
}

// Status returns the closed provider execution outcome.
func (observation ProviderExecutionObservation) Status() ProviderExecutionStatus {
	return observation.status
}

// Succeeded reports whether the observation records a successful execution.
func (observation ProviderExecutionObservation) Succeeded() bool {
	return observation.status == ProviderExecutionStatusSucceeded
}

// Invocation returns a defensive copy of the invocation bound to this
// execution observation.
func (observation ProviderExecutionObservation) Invocation() ProviderInvocation {
	return ProviderInvocation{
		role:                  observation.invocation.role,
		providerInstance:      observation.invocation.providerInstance,
		attemptID:             observation.invocation.attemptID,
		purpose:               observation.invocation.purpose,
		stdin:                 cloneBytes(observation.invocation.stdin),
		sourceInvocationID:    observation.invocation.sourceInvocationID,
		executionInvocationID: observation.invocation.executionInvocationID,
		completeStdinSHA256:   observation.invocation.completeStdinSHA256,
	}
}

// ProcessObservation returns a validated defensive copy of the exact neutral
// process evidence bound to this provider execution observation.
func (observation ProviderExecutionObservation) ProcessObservation() ProcessObservation {
	return cloneProcessObservation(observation.processObservation)
}

// Termination returns the exact neutral process termination fact.
func (observation ProviderExecutionObservation) Termination() ProcessTermination {
	return observation.processObservation.Termination()
}

// ExitCode returns the exact process exit code when the process exited.
func (observation ProviderExecutionObservation) ExitCode() (int, bool) {
	return observation.processObservation.ExitCode()
}

// StartedAt returns the exact UTC process-start time.
func (observation ProviderExecutionObservation) StartedAt() time.Time {
	return observation.processObservation.StartedAt()
}

// EndedAt returns the exact UTC process-end time.
func (observation ProviderExecutionObservation) EndedAt() time.Time {
	return observation.processObservation.EndedAt()
}

// StdinWriteReceipt returns the exact immutable child-stdin write fact.
func (observation ProviderExecutionObservation) StdinWriteReceipt() StdinWriteReceipt {
	return observation.processObservation.StdinWriteReceipt()
}

// StdinByteLength returns the exact intended provider stdin length from the
// bound process write receipt.
func (observation ProviderExecutionObservation) StdinByteLength() int64 {
	return observation.processObservation.StdinWriteReceipt().IntendedByteLength()
}

// CompleteStdinSHA256 returns the write-receipt digest. It equals the
// invocation digest whenever the receipt is complete.
func (observation ProviderExecutionObservation) CompleteStdinSHA256() string {
	return observation.processObservation.StdinWriteReceipt().SHA256()
}

// Result returns a defensive copy of the successful provider result. Failed
// observations never return a result.
func (observation ProviderExecutionObservation) Result() (ProviderResult, bool) {
	if !observation.hasResult {
		return ProviderResult{}, false
	}
	return ProviderResult{
		stdout:              cloneBytes(observation.result.stdout),
		stdinByteLength:     observation.result.stdinByteLength,
		completeStdinSHA256: observation.result.completeStdinSHA256,
	}, true
}

// Stdout returns a caller-owned copy of the stdout captured by the bound
// process observation.
func (observation ProviderExecutionObservation) Stdout() []byte {
	return observation.processObservation.Stdout()
}

// Stderr returns a caller-owned copy of the stderr captured by the bound
// process observation.
func (observation ProviderExecutionObservation) Stderr() []byte {
	return observation.processObservation.Stderr()
}

// DiagnosticCode returns the safe, non-empty failure code. It is empty for a
// successful observation and never contains an underlying error string.
func (observation ProviderExecutionObservation) DiagnosticCode() string {
	return observation.diagnosticCode
}

// StdoutLimit returns the positive stdout capture limit bound to the
// observation.
func (observation ProviderExecutionObservation) StdoutLimit() int64 {
	return observation.stdoutLimit
}

// StderrLimit returns the positive stderr capture limit bound to the
// observation.
func (observation ProviderExecutionObservation) StderrLimit() int64 {
	return observation.stderrLimit
}

// FailureClass returns the exact domain failure class for a failed execution.
// It is empty for a successful observation.
func (observation ProviderExecutionObservation) FailureClass() domain.FailureClass {
	return observation.status.FailureClass()
}

// Validate reports whether the observation is coherent immutable execution
// evidence. Constructors always return an observation that validates.
func (observation ProviderExecutionObservation) Validate() error {
	if !observation.status.Valid() {
		return fmt.Errorf("provider execution observation: invalid status")
	}
	canonicalInvocation, err := canonicalProviderInvocation(observation.invocation)
	if err != nil {
		return fmt.Errorf("provider execution observation: invalid invocation: %w", err)
	}
	canonicalProcess, err := canonicalProcessObservation(observation.processObservation)
	if err != nil {
		return fmt.Errorf("provider execution observation: invalid process observation: %w", err)
	}
	if err := validateProviderExecutionLimits(observation.stdoutLimit, observation.stderrLimit); err != nil {
		return fmt.Errorf("provider execution observation: %w", err)
	}
	if err := validateProviderExecutionStdinReceipt(canonicalInvocation, canonicalProcess); err != nil {
		return fmt.Errorf("provider execution observation: %w", err)
	}
	if int64(len(canonicalProcess.stdout)) > observation.stdoutLimit {
		return fmt.Errorf("provider execution observation: stdout exceeds its limit")
	}
	if int64(len(canonicalProcess.stderr)) > observation.stderrLimit {
		return fmt.Errorf("provider execution observation: stderr exceeds its limit")
	}

	if observation.Succeeded() {
		if !canonicalProcess.Succeeded() {
			return fmt.Errorf("provider execution observation: successful status requires a successful process observation")
		}
		if !observation.hasResult {
			return fmt.Errorf("provider execution observation: successful status requires a result")
		}
		if observation.diagnosticCode != "" {
			return fmt.Errorf("provider execution observation: successful status must not have a diagnostic code")
		}
		result, err := canonicalProviderResult(observation.result)
		if err != nil {
			return fmt.Errorf("provider execution observation: invalid result: %w", err)
		}
		if int64(result.stdinByteLength) != canonicalProcess.StdinWriteReceipt().IntendedByteLength() ||
			result.completeStdinSHA256 != canonicalProcess.StdinWriteReceipt().SHA256() {
			return fmt.Errorf("provider execution observation: result stdin identity does not match process observation")
		}
		if !bytes.Equal(result.stdout, canonicalProcess.stdout) {
			return fmt.Errorf("provider execution observation: result stdout does not match process stdout")
		}
		return nil
	}

	if observation.hasResult || !providerResultIsZero(observation.result) {
		return fmt.Errorf("provider execution observation: failed status must not have a result")
	}
	if !validProviderExecutionDiagnosticCode(observation.diagnosticCode) {
		return fmt.Errorf("provider execution observation: diagnostic code must be non-empty and safe")
	}
	if observation.FailureClass() == "" {
		return fmt.Errorf("provider execution observation: failed status has no failure class")
	}
	if !providerExecutionStatusMatchesProcessObservation(observation.status, canonicalProcess) {
		return fmt.Errorf("provider execution observation: status does not match process termination")
	}
	return nil
}

// ObservedReviewProvider is the provider execution boundary that returns
// immutable provider-neutral execution facts. An ordinary provider or process
// failure must be returned as a failed observation with a nil error; error is
// reserved for a boundary or internal inability to produce a coherent
// observation. Calls for distinct coordinator concurrency lanes may occur
// concurrently, so implementations must be concurrency-safe or serialize
// internally.
type ObservedReviewProvider interface {
	Observe(context.Context, ProviderInvocation) (ProviderExecutionObservation, error)
}

func canonicalProviderInvocation(invocation ProviderInvocation) (ProviderInvocation, error) {
	return NewProviderInvocation(
		invocation.Role(),
		invocation.ProviderInstance(),
		invocation.AttemptID(),
		invocation.Purpose(),
		invocation.Stdin(),
		invocation.SourceInvocationID(),
		invocation.ExecutionInvocationID(),
		invocation.CompleteStdinSHA256(),
	)
}

func canonicalProviderResult(result ProviderResult) (ProviderResult, error) {
	return NewProviderResult(result.Stdout(), result.StdinByteLength(), result.CompleteStdinSHA256())
}
func canonicalProcessObservation(observation ProcessObservation) (ProcessObservation, error) {
	var exitCode *int
	if value, ok := observation.ExitCode(); ok {
		exitCode = &value
	}
	var signals []ProcessSignal
	if number, name, ok := observation.Signal(); ok {
		signal, err := NewProcessSignal(number, name)
		if err != nil {
			return ProcessObservation{}, fmt.Errorf("invalid process signal: %w", err)
		}
		signals = []ProcessSignal{signal}
	}
	return NewProcessObservation(
		observation.Stdout(),
		observation.Stderr(),
		exitCode,
		observation.Termination(),
		observation.StdinWriteReceipt(),
		observation.StartedAt(),
		observation.EndedAt(),
		signals...,
	)
}

func cloneProcessObservation(observation ProcessObservation) ProcessObservation {
	clone, err := canonicalProcessObservation(observation)
	if err != nil {
		return ProcessObservation{}
	}
	return clone
}

func validateProviderExecutionStdinReceipt(
	invocation ProviderInvocation,
	processObservation ProcessObservation,
) error {
	receipt := processObservation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != int64(len(invocation.stdin)) {
		return fmt.Errorf("stdin receipt intended length does not match invocation")
	}
	writtenByteCount := receipt.WrittenByteCount()
	if receipt.SHA256() != providerExecutionStdinDigest(invocation.stdin[:int(writtenByteCount)]) {
		return fmt.Errorf("stdin receipt digest does not match written invocation prefix")
	}
	switch processObservation.Termination() {
	case ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationLockFailed,
		ProcessTerminationLockUnavailable,
		ProcessTerminationLockConfiguration,
		ProcessTerminationLockSecurity:
		if writtenByteCount != 0 {
			return fmt.Errorf("start or lock failure must report zero written stdin bytes")
		}
		if len(invocation.stdin) != 0 && receipt.Complete() {
			return fmt.Errorf("start or lock failure must report incomplete stdin for non-empty invocation")
		}
	}
	return nil
}

func providerExecutionStdinDigest(stdin []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(stdin)
	return hex.EncodeToString(hash.Sum(nil))
}

func providerExecutionStatusMatchesProcessObservation(
	status ProviderExecutionStatus,
	processObservation ProcessObservation,
) bool {
	switch status {
	case ProviderExecutionStatusTimedOut:
		return processObservation.Termination() == ProcessTerminationTimedOut
	case ProviderExecutionStatusCancelled:
		return processObservation.Termination() == ProcessTerminationCancelled
	case ProviderExecutionStatusArtifactFailure:
		// Capture caps and incomplete stdin are process artifacts. A complete
		// stdin process exit may instead carry an artifact diagnostic from
		// post-exit output validation. No policy maps a signal to this status.
		switch processObservation.Termination() {
		case ProcessTerminationStdoutLimit,
			ProcessTerminationStderrLimit,
			ProcessTerminationStdinIncomplete:
			return true
		case ProcessTerminationExited:
			return processObservation.StdinWriteReceipt().Complete()
		default:
			return false
		}
	case ProviderExecutionStatusUnavailable:
		return processObservation.Termination() == ProcessTerminationStartUnavailable ||
			processObservation.Termination() == ProcessTerminationLockUnavailable
	case ProviderExecutionStatusSecurityViolation:
		switch processObservation.Termination() {
		case ProcessTerminationStartSecurity,
			ProcessTerminationLockSecurity,
			ProcessTerminationResidualProcessGroup:
			return true
		case ProcessTerminationExited:
			return processObservation.StdinWriteReceipt().Complete()
		default:
			return false
		}
	case ProviderExecutionStatusConfigurationViolation:
		switch processObservation.Termination() {
		case ProcessTerminationStartConfiguration, ProcessTerminationLockConfiguration:
			return true
		case ProcessTerminationExited:
			return processObservation.StdinWriteReceipt().Complete()
		default:
			return false
		}
	case ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusMutationViolation:
		return processObservation.Termination() == ProcessTerminationExited &&
			processObservation.StdinWriteReceipt().Complete()
	case ProviderExecutionStatusInternalFailure:
		// Signals and unclassified start/lock failures remain exact process
		// facts and fail closed as internal rather than becoming unavailable.
		return processObservation.Termination() == ProcessTerminationSignaled ||
			processObservation.Termination() == ProcessTerminationStartFailed ||
			processObservation.Termination() == ProcessTerminationLockFailed ||
			(processObservation.Termination() == ProcessTerminationExited &&
				processObservation.StdinWriteReceipt().Complete())
	default:
		return false
	}
}

func validateProviderExecutionLimits(stdoutLimit, stderrLimit int64) error {
	if stdoutLimit <= 0 {
		return fmt.Errorf("stdout limit must be positive")
	}
	if stderrLimit <= 0 {
		return fmt.Errorf("stderr limit must be positive")
	}
	return nil
}

func providerResultIsZero(result ProviderResult) bool {
	return result.stdout == nil && result.stdinByteLength == 0 && result.completeStdinSHA256 == ""
}

func validProviderExecutionDiagnosticCode(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}
