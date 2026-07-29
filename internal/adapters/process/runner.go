//go:build darwin && arm64

// Package process provides Darwin direct-process execution adapters for ports.
package process

import (
	"fmt"
	"reflect"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Runner executes direct process requests with an injected observation clock.
type Runner struct {
	clock ports.Clock
}

var _ ports.ProcessRunner = (*Runner)(nil)

// NewRunner constructs a direct-process runner. A clock is required because
// observations carry authoritative start and end timestamps.
func NewRunner(clock ports.Clock) (*Runner, error) {
	if nilClock(clock) {
		return nil, fmt.Errorf("process runner: nil clock")
	}
	return &Runner{clock: clock}, nil
}

func (runner *Runner) timestamp() (time.Time, error) {
	if runner == nil || nilClock(runner.clock) {
		return time.Time{}, fmt.Errorf("process runner: nil clock")
	}

	timestamp := runner.clock.Now().Round(0).UTC()
	if timestamp.IsZero() {
		return time.Time{}, fmt.Errorf("process runner: clock returned zero time")
	}
	return timestamp, nil
}

func processExecutionFailure(
	primaryCause domain.RuntimeDiagnosticCause,
	cleanupCause domain.RuntimeDiagnosticCause,
	stdout, stderr []byte,
	err error,
) (ports.ProcessObservation, error) {
	failure, constructErr := ports.NewProcessExecutionError(primaryCause, cleanupCause, stdout, stderr, err)
	if constructErr != nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: construct typed failure: %w", constructErr)
	}
	return ports.ProcessObservation{}, failure
}

// ClockRegressionError reports an observation clock moving backward after a
// process attempt has started. The runner rejects this fact rather than
// fabricating an end timestamp.
type ClockRegressionError struct {
	StartedAt time.Time
	EndedAt   time.Time
}

func (err *ClockRegressionError) Error() string {
	return fmt.Sprintf(
		"process runner: clock regression: ended at %s before started at %s",
		err.EndedAt.Format(time.RFC3339Nano),
		err.StartedAt.Format(time.RFC3339Nano),
	)
}

func (runner *Runner) observation(
	stdout, stderr []byte,
	exitCode *int,
	termination ports.ProcessTermination,
	stdinWriteReceipt ports.StdinWriteReceipt,
	startedAt time.Time,
) (ports.ProcessObservation, error) {
	return runner.observationWithTransport(
		stdout, stderr, exitCode, termination, stdinWriteReceipt, nil, startedAt,
	)
}

func (runner *Runner) observationWithTransport(
	stdout, stderr []byte,
	exitCode *int,
	termination ports.ProcessTermination,
	stdinWriteReceipt ports.StdinWriteReceipt,
	transportReceipt *ports.ProviderPacketTransportReceipt,
	startedAt time.Time,
) (ports.ProcessObservation, error) {
	endedAt, err := runner.timestamp()
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr, err)
	}
	if endedAt.Before(startedAt) {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr, &ClockRegressionError{
			StartedAt: startedAt,
			EndedAt:   endedAt,
		})
	}

	var observation ports.ProcessObservation
	if transportReceipt != nil {
		observation, err = ports.NewProviderProcessObservation(
			stdout,
			stderr,
			exitCode,
			termination,
			stdinWriteReceipt,
			*transportReceipt,
			startedAt,
			endedAt,
		)
	} else {
		observation, err = ports.NewProcessObservation(
			stdout,
			stderr,
			exitCode,
			termination,
			stdinWriteReceipt,
			startedAt,
			endedAt,
		)
	}
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr,
			fmt.Errorf("process runner: construct observation: %w", err))
	}
	return observation, nil
}
func (runner *Runner) observationWithLifecycleTransport(
	stdout, stderr []byte,
	termination ports.ProcessTermination,
	stdinWriteReceipt ports.StdinWriteReceipt,
	transportReceipt ports.ProviderPacketTransportReceipt,
	lifecycle ports.ProcessLifecycleReceipt,
	startedAt time.Time,
) (ports.ProcessObservation, error) {
	endedAt, err := runner.timestamp()
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr, err)
	}
	if endedAt.Before(startedAt) {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr,
			&ClockRegressionError{StartedAt: startedAt, EndedAt: endedAt})
	}
	observation, err := ports.NewStartedProviderProcessObservation(
		stdout, stderr, termination, stdinWriteReceipt, transportReceipt, lifecycle, startedAt, endedAt,
	)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr,
			fmt.Errorf("process runner: construct lifecycle observation: %w", err))
	}
	return observation, nil
}

func nilClock(clock ports.Clock) bool {
	if clock == nil {
		return true
	}

	value := reflect.ValueOf(clock)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
