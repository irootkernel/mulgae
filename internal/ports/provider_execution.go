package ports

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
)

// ErrProviderLoginRequired marks an explicit native provider response that
// requires the installed user to authenticate outside Mulgae before retrying.
var ErrProviderLoginRequired = errors.New("provider login required")

// ProviderRuntimeError carries a closed detailed cause when the provider
// boundary itself fails. A caller may still receive a valid observation with
// this error and must preserve that evidence before applying policy.
type ProviderRuntimeError struct {
	cause domain.RuntimeDiagnosticCause
	err   error
}

func NewProviderRuntimeError(cause domain.RuntimeDiagnosticCause, err error) (*ProviderRuntimeError, error) {
	if !cause.Valid() {
		return nil, fmt.Errorf("provider runtime error: invalid cause")
	}
	return &ProviderRuntimeError{cause: cause, err: err}, nil
}

func (failure *ProviderRuntimeError) Error() string {
	if failure == nil || !failure.cause.Valid() {
		return "provider runtime failed"
	}
	return "provider runtime failed: " + string(failure.cause)
}
func (failure *ProviderRuntimeError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}
func (failure *ProviderRuntimeError) Cause() domain.RuntimeDiagnosticCause {
	if failure == nil {
		return ""
	}
	return failure.cause
}

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

// NativeHomeLaunchAuthority is the immutable installed-user HOME identity
// required by a descriptor-bound provider launch. It is intentionally absent
// from process observations and receipts.
type NativeHomeLaunchAuthority struct {
	path         string
	device       uint64
	inode        uint64
	effectiveUID uint32
}

// NewNativeHomeLaunchAuthority constructs an exact, canonical native-home
// identity captured by the composition root.
func NewNativeHomeLaunchAuthority(path string, device, inode uint64, effectiveUID uint32) (NativeHomeLaunchAuthority, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || device == 0 || inode == 0 {
		return NativeHomeLaunchAuthority{}, fmt.Errorf("native home launch authority: invalid identity")
	}
	return NativeHomeLaunchAuthority{path: path, device: device, inode: inode, effectiveUID: effectiveUID}, nil
}

// Valid reports whether authority has a complete canonical identity.
func (authority NativeHomeLaunchAuthority) Valid() bool {
	_, err := NewNativeHomeLaunchAuthority(authority.path, authority.device, authority.inode, authority.effectiveUID)
	return err == nil
}

// Path returns the canonical native-home path for the protected launch only.
func (authority NativeHomeLaunchAuthority) Path() string { return authority.path }

// Device returns the captured filesystem device.
func (authority NativeHomeLaunchAuthority) Device() uint64 { return authority.device }

// Inode returns the captured filesystem inode.
func (authority NativeHomeLaunchAuthority) Inode() uint64 { return authority.inode }

// EffectiveUID returns the captured installed-user effective UID.
func (authority NativeHomeLaunchAuthority) EffectiveUID() uint32 { return authority.effectiveUID }

// ProviderExecutionObservation is immutable provider-neutral execution
// evidence. It binds a validated invocation identity to exactly one validated
// process observation and either a successful provider result or a classified
// failure. It intentionally grants no repair, fallback, finding, validation,
// or publication authority.
type ProviderExecutionObservation struct {
	status             ProviderExecutionStatus
	invocation         ProviderInvocation
	processObservation ProcessObservation
	hasProcess         bool
	result             ProviderResult
	hasResult          bool
	diagnosticCode     string
	primaryCause       domain.RuntimeDiagnosticCause
	cleanupCause       domain.RuntimeDiagnosticCause
	stdout             []byte
	stderr             []byte
	stdoutLimit        int64
	stderrLimit        int64
	resultIsolated     bool
}

// NewSuccessfulProviderExecutionObservation records a successful provider
// result bound to an exactly matching successful process observation.
func NewSuccessfulProviderExecutionObservation(
	invocation ProviderInvocation,
	result ProviderResult,
	processObservation ProcessObservation,
	stdoutLimit, stderrLimit int64,
) (ProviderExecutionObservation, error) {
	return newSuccessfulProviderExecutionObservation(
		invocation, result, processObservation, stdoutLimit, stderrLimit, false,
	)
}

// NewIsolatedSuccessfulProviderExecutionObservation records a successful
// provider result deliberately derived from a structured process stdout stream.
// The raw stdout remains available through ProcessObservation and Stdout.
func NewIsolatedSuccessfulProviderExecutionObservation(
	invocation ProviderInvocation,
	result ProviderResult,
	processObservation ProcessObservation,
	stdoutLimit, stderrLimit int64,
) (ProviderExecutionObservation, error) {
	return newSuccessfulProviderExecutionObservation(
		invocation, result, processObservation, stdoutLimit, stderrLimit, true,
	)
}

func newSuccessfulProviderExecutionObservation(
	invocation ProviderInvocation,
	result ProviderResult,
	processObservation ProcessObservation,
	stdoutLimit, stderrLimit int64,
	resultIsolated bool,
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
		hasProcess:         true,
		result:             canonicalResult,
		hasResult:          true,
		stdout:             canonicalProcess.Stdout(),
		stderr:             canonicalProcess.Stderr(),
		resultIsolated:     resultIsolated,
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
	cause := providerExecutionCause(status, diagnosticCode, processObservation)
	return NewFailedProviderExecutionObservationWithCause(
		status, invocation, processObservation, diagnosticCode, cause, "", stdoutLimit, stderrLimit,
	)
}

// NewFailedProviderExecutionObservationWithCause records a failed provider
// observation with the exact detailed cause selected at the adapter boundary.
// cleanupCause is optional and can only supplement, never replace, cause.
func NewFailedProviderExecutionObservationWithCause(
	status ProviderExecutionStatus,
	invocation ProviderInvocation,
	processObservation ProcessObservation,
	diagnosticCode string,
	cause, cleanupCause domain.RuntimeDiagnosticCause,
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
		hasProcess:         true,
		diagnosticCode:     diagnosticCode,
		primaryCause:       cause,
		cleanupCause:       cleanupCause,
		stdout:             canonicalProcess.Stdout(),
		stderr:             canonicalProcess.Stderr(),
		stdoutLimit:        stdoutLimit,
		stderrLimit:        stderrLimit,
	}
	if err := observation.Validate(); err != nil {
		return ProviderExecutionObservation{}, err
	}
	return observation, nil
}

// NewPartialFailedProviderExecutionObservation retains bounded streams and a
// typed cause when process execution failed before a coherent neutral process
// observation could be assembled.
func NewPartialFailedProviderExecutionObservation(
	status ProviderExecutionStatus,
	invocation ProviderInvocation,
	stdout, stderr []byte,
	diagnosticCode string,
	cause, cleanupCause domain.RuntimeDiagnosticCause,
	stdoutLimit, stderrLimit int64,
) (ProviderExecutionObservation, error) {
	canonicalInvocation, err := canonicalProviderInvocation(invocation)
	if err != nil {
		return ProviderExecutionObservation{}, fmt.Errorf("provider execution observation: invalid invocation: %w", err)
	}
	observation := ProviderExecutionObservation{
		status: status, invocation: canonicalInvocation,
		diagnosticCode: diagnosticCode, primaryCause: cause, cleanupCause: cleanupCause,
		stdout: cloneBytes(stdout), stderr: cloneBytes(stderr),
		stdoutLimit: stdoutLimit, stderrLimit: stderrLimit,
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
	invocation, _ := canonicalProviderInvocation(observation.invocation)
	return invocation
}

// ProcessObservation returns a validated defensive copy of the exact neutral
// process evidence bound to this provider execution observation.
func (observation ProviderExecutionObservation) ProcessObservation() ProcessObservation {
	return cloneProcessObservation(observation.processObservation)
}

// AvailableProcessObservation returns coherent process evidence when one was
// available. Partial failures may retain streams and causes without one.
func (observation ProviderExecutionObservation) AvailableProcessObservation() (ProcessObservation, bool) {
	if !observation.hasProcess {
		return ProcessObservation{}, false
	}
	return cloneProcessObservation(observation.processObservation), true
}

// Termination returns the exact neutral process termination fact.
func (observation ProviderExecutionObservation) Termination() ProcessTermination {
	return observation.processObservation.Termination()
}
func (observation ProviderExecutionObservation) FinalTermination() (ProcessFinalTermination, bool) {
	return observation.processObservation.FinalTermination()
}
func (observation ProviderExecutionObservation) SignalRequests() []ProcessGroupSignalRequestReceipt {
	return observation.processObservation.SignalRequests()
}
func (observation ProviderExecutionObservation) OutputFrameReceipt() (ProcessOutputFrameReceipt, bool) {
	receipt, ok := observation.processObservation.LifecycleReceipt()
	if !ok {
		return ProcessOutputFrameReceipt{}, false
	}
	return receipt.OutputFrame()
}
func (observation ProviderExecutionObservation) ProcessGroupAbsent() bool {
	return observation.processObservation.ProcessGroupAbsent()
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
	result, err := canonicalProviderResult(observation.result)
	return result, err == nil
}

// Stdout returns a caller-owned copy of the stdout captured by the bound
// process observation.
func (observation ProviderExecutionObservation) Stdout() []byte {
	return cloneBytes(observation.stdout)
}

// Stderr returns a caller-owned copy of the stderr captured by the bound
// process observation.
func (observation ProviderExecutionObservation) Stderr() []byte {
	return cloneBytes(observation.stderr)
}

// DiagnosticCode returns the safe, non-empty failure code. It is empty for a
// successful observation and never contains an underlying error string.
func (observation ProviderExecutionObservation) DiagnosticCode() string {
	return observation.diagnosticCode
}

// PrimaryCause returns the detailed closed diagnostic cause for a failed
// observation. Successful observations have no cause.
func (observation ProviderExecutionObservation) PrimaryCause() domain.RuntimeDiagnosticCause {
	return observation.primaryCause
}

// CleanupCause returns the supplemental process-group cleanup cause, if any.
func (observation ProviderExecutionObservation) CleanupCause() (domain.RuntimeDiagnosticCause, bool) {
	return observation.cleanupCause, observation.cleanupCause != ""
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
	var canonicalProcess ProcessObservation
	if observation.hasProcess {
		canonicalProcess, err = canonicalProcessObservation(observation.processObservation)
		if err != nil {
			return fmt.Errorf("provider execution observation: invalid process observation: %w", err)
		}
	} else if observation.processObservation.Valid() {
		return fmt.Errorf("provider execution observation: unmarked process observation")
	}
	if err := validateProviderExecutionLimits(observation.stdoutLimit, observation.stderrLimit); err != nil {
		return fmt.Errorf("provider execution observation: %w", err)
	}
	if observation.hasProcess {
		if err := validateProviderExecutionStdinReceipt(canonicalInvocation, canonicalProcess); err != nil {
			return fmt.Errorf("provider execution observation: %w", err)
		}
		if !bytes.Equal(observation.stdout, canonicalProcess.stdout) || !bytes.Equal(observation.stderr, canonicalProcess.stderr) {
			return fmt.Errorf("provider execution observation: streams do not match process observation")
		}
	}
	if int64(len(observation.stdout)) > observation.stdoutLimit {
		return fmt.Errorf("provider execution observation: stdout exceeds its limit")
	}
	if int64(len(observation.stderr)) > observation.stderrLimit {
		return fmt.Errorf("provider execution observation: stderr exceeds its limit")
	}

	if observation.Succeeded() {
		if !observation.hasProcess {
			return fmt.Errorf("provider execution observation: successful status requires process observation")
		}
		if !canonicalProcess.Succeeded() {
			return fmt.Errorf("provider execution observation: successful status requires a successful process observation")
		}
		if !observation.hasResult {
			return fmt.Errorf("provider execution observation: successful status requires a result")
		}
		if observation.diagnosticCode != "" {
			return fmt.Errorf("provider execution observation: successful status must not have a diagnostic code")
		}
		if observation.primaryCause != "" || observation.cleanupCause != "" {
			return fmt.Errorf("provider execution observation: successful status must not have a cause")
		}
		result, err := canonicalProviderResult(observation.result)
		if err != nil {
			return fmt.Errorf("provider execution observation: invalid result: %w", err)
		}
		if result.InputIdentity() != canonicalInvocation.InputIdentity() {
			return fmt.Errorf("provider execution observation: result input identity does not match invocation")
		}
		if transport, ok := canonicalProcess.ProviderPacketTransportReceipt(); ok {
			if transport.Channel() == ProviderPacketChannelStdin && !canonicalProcess.StdinWriteReceipt().Complete() {
				return fmt.Errorf("provider execution observation: successful status requires complete packet transport")
			}
		} else if !canonicalProcess.StdinWriteReceipt().Complete() {
			return fmt.Errorf("provider execution observation: successful legacy stdin transport must be complete")
		}
		if !observation.resultIsolated && !bytes.Equal(result.stdout, canonicalProcess.stdout) {
			return fmt.Errorf("provider execution observation: result stdout does not match process stdout")
		}
		return nil
	}

	if observation.hasResult || !providerResultIsZero(observation.result) {
		return fmt.Errorf("provider execution observation: failed status must not have a result")
	}
	if observation.resultIsolated {
		return fmt.Errorf("provider execution observation: failed status must not have an isolated result")
	}
	if !validProviderExecutionDiagnosticCode(observation.diagnosticCode) {
		return fmt.Errorf("provider execution observation: diagnostic code must be non-empty and safe")
	}
	if !observation.primaryCause.Valid() {
		return fmt.Errorf("provider execution observation: failed status requires a typed cause")
	}
	if observation.cleanupCause != "" && observation.cleanupCause != domain.DiagnosticCauseProcessGroupCleanupFailed {
		return fmt.Errorf("provider execution observation: invalid cleanup cause")
	}
	if observation.FailureClass() == "" {
		return fmt.Errorf("provider execution observation: failed status has no failure class")
	}
	if observation.hasProcess && !providerExecutionStatusMatchesProcessObservation(observation.status, canonicalProcess) {
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
	if workspace, ok := invocation.ExecutionWorkspace(); ok {
		storedIdentity, hasStoredIdentity := invocation.WorkspaceSnapshotIdentity()
		if !hasStoredIdentity || workspace.WorkspaceSnapshotIdentity() != storedIdentity {
			return ProviderInvocation{}, fmt.Errorf("provider invocation workspace identity changed")
		}
		return NewProviderInvocationWithPacketInWorkspace(
			invocation.Role(), invocation.ProviderInstance(), invocation.AttemptID(),
			invocation.Purpose(), invocation.Packet(), invocation.SourceInvocationID(),
			invocation.ExecutionInvocationID(), workspace,
		)
	}
	return NewProviderInvocationWithPacket(
		invocation.Role(), invocation.ProviderInstance(), invocation.AttemptID(),
		invocation.Purpose(), invocation.Packet(), invocation.SourceInvocationID(),
		invocation.ExecutionInvocationID(),
	)
}

func canonicalProviderResult(result ProviderResult) (ProviderResult, error) {
	return NewProviderResultForInput(result.Stdout(), result.InputIdentity())
}
func canonicalProcessObservation(observation ProcessObservation) (ProcessObservation, error) {
	if lifecycle, ok := observation.LifecycleReceipt(); ok {
		if receipt, hasTransport := observation.ProviderPacketTransportReceipt(); hasTransport {
			return NewStartedProviderProcessObservation(
				observation.Stdout(), observation.Stderr(), observation.Termination(),
				observation.StdinWriteReceipt(), receipt, lifecycle,
				observation.StartedAt(), observation.EndedAt(),
			)
		}
		return NewStartedProcessObservation(
			observation.Stdout(), observation.Stderr(), observation.Termination(),
			observation.StdinWriteReceipt(), lifecycle, observation.StartedAt(), observation.EndedAt(),
		)
	}
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
	if receipt, ok := observation.ProviderPacketTransportReceipt(); ok {
		return NewProviderProcessObservation(
			observation.Stdout(), observation.Stderr(), exitCode, observation.Termination(),
			observation.StdinWriteReceipt(), receipt, observation.StartedAt(), observation.EndedAt(), signals...,
		)
	}
	return NewProcessObservation(
		observation.Stdout(), observation.Stderr(), exitCode, observation.Termination(),
		observation.StdinWriteReceipt(), observation.StartedAt(), observation.EndedAt(), signals...,
	)
}

func cloneProcessObservation(observation ProcessObservation) ProcessObservation {
	clone, err := canonicalProcessObservation(observation)
	if err != nil {
		return ProcessObservation{}
	}
	return clone
}

// providerExecutionCause keeps the legacy failed-observation constructor
// compatible while ensuring every failure has a closed detailed cause. New
// adapter code should select the exact cause explicitly with
// NewFailedProviderExecutionObservationWithCause.
func providerExecutionCause(
	status ProviderExecutionStatus,
	diagnosticCode string,
	processObservation ProcessObservation,
) domain.RuntimeDiagnosticCause {
	switch diagnosticCode {
	case "login_required":
		return domain.DiagnosticCauseLoginRequired
	case "provider_timeout", "process_timeout":
		return domain.DiagnosticCauseTimedOut
	case "provider_auth":
		return domain.DiagnosticCauseAuthenticationFailed
	case "provider_permission_denied":
		return domain.DiagnosticCausePermissionDenied
	case "provider_quota":
		return domain.DiagnosticCauseQuotaExceeded
	case "provider_rate_limit":
		return domain.DiagnosticCauseRateLimited
	case "invalid_provider_output":
		return domain.DiagnosticCauseOutputDecodeFailed
	case "provider_output_missing":
		return domain.DiagnosticCauseOutputMissing
	case "post_output_trailing_bytes":
		return domain.DiagnosticCauseOutputEnvelopeInvalid
	case "transport_verification":
		return domain.DiagnosticCauseTransportVerificationFailed
	}
	switch processObservation.Termination() {
	case ProcessTerminationStartFailed, ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration, ProcessTerminationStartSecurity:
		return domain.DiagnosticCauseProviderSpawnFailed
	case ProcessTerminationResidualProcessGroup:
		return domain.DiagnosticCauseProcessGroupCleanupFailed
	case ProcessTerminationTimedOut:
		return domain.DiagnosticCauseTimedOut
	}
	switch status {
	case ProviderExecutionStatusAuthentication:
		return domain.DiagnosticCauseAuthenticationFailed
	case ProviderExecutionStatusQuota:
		return domain.DiagnosticCauseQuotaExceeded
	case ProviderExecutionStatusRateLimit:
		return domain.DiagnosticCauseRateLimited
	case ProviderExecutionStatusTimedOut:
		return domain.DiagnosticCauseTimedOut
	default:
		return domain.DiagnosticCauseObservationInvalid
	}
}

func validateProviderExecutionStdinReceipt(invocation ProviderInvocation, processObservation ProcessObservation) error {
	receipt := processObservation.StdinWriteReceipt()
	transport, hasTransport := processObservation.ProviderPacketTransportReceipt()
	if !hasTransport {
		switch processObservation.Termination() {
		case ProcessTerminationStartFailed, ProcessTerminationStartUnavailable, ProcessTerminationStartConfiguration,
			ProcessTerminationStartSecurity, ProcessTerminationLockFailed, ProcessTerminationLockUnavailable,
			ProcessTerminationLockConfiguration, ProcessTerminationLockSecurity:
			if receipt.WrittenByteCount() != 0 {
				return fmt.Errorf("legacy stdin receipt claims delivery before process start")
			}
			if receipt.IntendedByteLength() == 0 && receipt.Complete() &&
				receipt.SHA256() == providerPacketDigest(nil) {
				return nil
			}
			if receipt.Complete() {
				return fmt.Errorf("legacy stdin receipt claims complete non-empty delivery before process start")
			}
		}
		if receipt.IntendedByteLength() != int64(invocation.InputIdentity().ByteLength()) {
			return fmt.Errorf("legacy stdin receipt intended length does not match packet")
		}
		writtenByteCount := receipt.WrittenByteCount()
		packet := invocation.PacketBytes()
		if writtenByteCount < 0 || writtenByteCount > int64(len(packet)) ||
			receipt.SHA256() != providerPacketDigest(packet[:int(writtenByteCount)]) {
			return fmt.Errorf("legacy stdin receipt digest does not match written packet prefix")
		}
		return nil
	}
	if transport.PacketIdentity() != invocation.InputIdentity() {
		return fmt.Errorf("transport packet identity does not match invocation")
	}
	switch transport.Channel() {
	case ProviderPacketChannelStdin:
		if receipt.IntendedByteLength() != int64(invocation.InputIdentity().ByteLength()) {
			return fmt.Errorf("stdin receipt intended length does not match packet")
		}
		writtenByteCount := receipt.WrittenByteCount()
		packet := invocation.PacketBytes()
		if receipt.SHA256() != providerPacketDigest(packet[:int(writtenByteCount)]) {
			return fmt.Errorf("stdin receipt digest does not match written packet prefix")
		}
	default:
		if receipt.IntendedByteLength() != 0 || receipt.WrittenByteCount() != 0 ||
			!receipt.Complete() || receipt.SHA256() != providerPacketDigest(nil) {
			return fmt.Errorf("non-stdin packet transport must have a complete empty stdin receipt")
		}
	}
	return nil
}

func providerExecutionStatusMatchesProcessObservation(
	status ProviderExecutionStatus,
	processObservation ProcessObservation,
) bool {
	switch status {
	case ProviderExecutionStatusTimedOut:
		return processObservation.Termination() == ProcessTerminationTimedOut ||
			(processObservation.Termination() == ProcessTerminationExited &&
				processObservation.StdinWriteReceipt().Complete())
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
	return result.stdout == nil && !result.inputIdentity.Valid()
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
