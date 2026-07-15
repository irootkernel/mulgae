package ports

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func TestProviderExecutionStatusFailureClassMapping(t *testing.T) {
	tests := []struct {
		status    ProviderExecutionStatus
		wantClass domain.FailureClass
	}{
		{ProviderExecutionStatusSucceeded, ""},
		{ProviderExecutionStatusUnavailable, domain.FailureProviderUnavailable},
		{ProviderExecutionStatusTimedOut, domain.FailureTimeout},
		{ProviderExecutionStatusAuthentication, domain.FailureAuthentication},
		{ProviderExecutionStatusQuota, domain.FailureQuota},
		{ProviderExecutionStatusRateLimit, domain.FailureRateLimit},
		{ProviderExecutionStatusSecurityViolation, domain.FailureSecurityPolicy},
		{ProviderExecutionStatusMutationViolation, domain.FailureSecurityPolicy},
		{ProviderExecutionStatusConfigurationViolation, domain.FailureConfiguration},
		{ProviderExecutionStatusArtifactFailure, domain.FailureArtifact},
		{ProviderExecutionStatusCancelled, domain.FailureCancelled},
		{ProviderExecutionStatusInternalFailure, domain.FailureInternal},
	}

	for _, test := range tests {
		t.Run(string(test.status), func(t *testing.T) {
			if !test.status.Valid() {
				t.Fatalf("status %q is invalid", test.status)
			}
			if got := test.status.FailureClass(); got != test.wantClass {
				t.Fatalf("FailureClass() = %q, want %q", got, test.wantClass)
			}
		})
	}

	if ProviderExecutionStatus("unknown").Valid() {
		t.Fatal("unknown status is valid")
	}
	if got := ProviderExecutionStatus("unknown").FailureClass(); got != "" {
		t.Fatalf("unknown status FailureClass() = %q, want empty", got)
	}
}

func TestSuccessfulProviderExecutionObservationBindsExactProcessFacts(t *testing.T) {
	stdin := []byte("complete provider stdin")
	invocation := newProviderExecutionTestInvocationWithStdin(t, stdin)
	stdout := []byte(`{"findings":[]}`)
	stderr := []byte("safe diagnostic")
	startedAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	endedAt := startedAt.Add(time.Second)
	process := newProviderExecutionTestProcess(
		t,
		stdout,
		stderr,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeProviderExecutionReceipt(t, invocation),
		startedAt,
		endedAt,
	)
	result := newProviderExecutionTestResult(t, invocation, stdout)
	observation, err := NewSuccessfulProviderExecutionObservation(invocation, result, process, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}

	if !observation.Succeeded() || observation.Status() != ProviderExecutionStatusSucceeded {
		t.Fatalf("success = %t, status = %q", observation.Succeeded(), observation.Status())
	}
	if got := observation.Termination(); got != ProcessTerminationExited {
		t.Fatalf("Termination() = %q, want %q", got, ProcessTerminationExited)
	}
	if got, ok := observation.ExitCode(); !ok || got != 0 {
		t.Fatalf("ExitCode() = %d, %t; want 0, true", got, ok)
	}
	if got := observation.StartedAt(); !got.Equal(startedAt) || got.Location() != time.UTC {
		t.Fatalf("StartedAt() = %s (%s), want %s (UTC)", got, got.Location(), startedAt)
	}
	if got := observation.EndedAt(); !got.Equal(endedAt) || got.Location() != time.UTC {
		t.Fatalf("EndedAt() = %s (%s), want %s (UTC)", got, got.Location(), endedAt)
	}
	receipt := observation.StdinWriteReceipt()
	if !receipt.Complete() ||
		receipt.IntendedByteLength() != int64(len(stdin)) ||
		receipt.WrittenByteCount() != int64(len(stdin)) ||
		receipt.SHA256() != invocation.CompleteStdinSHA256() {
		t.Fatalf("StdinWriteReceipt() = %#v", receipt)
	}
	if observation.StdinByteLength() != int64(len(stdin)) ||
		observation.CompleteStdinSHA256() != invocation.CompleteStdinSHA256() {
		t.Fatal("observation does not expose the process stdin receipt identity")
	}
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() = %q, want %q", got, stdout)
	}
	if got := observation.Stderr(); !bytes.Equal(got, stderr) {
		t.Fatalf("Stderr() = %q, want %q", got, stderr)
	}
	if got := observation.ProcessObservation(); !got.Valid() ||
		got.Termination() != ProcessTerminationExited ||
		!bytes.Equal(got.Stdout(), stdout) ||
		!bytes.Equal(got.Stderr(), stderr) {
		t.Fatalf("ProcessObservation() = %#v", got)
	}
	if _, ok := observation.Result(); !ok {
		t.Fatal("successful observation returned no result")
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestSuccessfulProviderExecutionObservationRejectsIncoherentProcessEvidence(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	stdout := []byte(`{"findings":[]}`)
	result := newProviderExecutionTestResult(t, invocation, stdout)
	completeReceipt := completeProviderExecutionReceipt(t, invocation)

	nonzeroProcess := newProviderExecutionTestProcess(
		t,
		stdout,
		nil,
		providerExecutionTestExitCode(1),
		ProcessTerminationExited,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, result, nonzeroProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted a nonzero process exit")
	}

	timedOutProcess := newProviderExecutionTestProcess(
		t,
		stdout,
		nil,
		nil,
		ProcessTerminationTimedOut,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, result, timedOutProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted a timeout process")
	}

	mismatchedStdoutProcess := newProviderExecutionTestProcess(
		t,
		[]byte("different stdout"),
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, result, mismatchedStdoutProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted result/process stdout mismatch")
	}

	wrongDigestReceipt, err := NewStdinWriteReceipt(
		int64(len(invocation.Stdin())),
		int64(len(invocation.Stdin())),
		strings.Repeat("a", 64),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigestProcess := newProviderExecutionTestProcess(
		t,
		stdout,
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		wrongDigestReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, result, wrongDigestProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted a mismatched stdin receipt digest")
	}

	wrongLengthReceipt, err := NewStdinWriteReceipt(
		int64(len(invocation.Stdin())+1),
		int64(len(invocation.Stdin())+1),
		providerTestDigest([]byte("different provider stdin")),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongLengthProcess := newProviderExecutionTestProcess(
		t,
		stdout,
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		wrongLengthReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, result, wrongLengthProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted a mismatched stdin receipt length")
	}

	wrongReceiptTimedOutProcess := newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		nil,
		ProcessTerminationTimedOut,
		wrongLengthReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusTimedOut,
		invocation,
		wrongReceiptTimedOutProcess,
		"deadline_exceeded",
		1024,
		1024,
	); err == nil {
		t.Fatal("failed observation accepted a mismatched stdin receipt length")
	}

	wrongResultLength, err := NewProviderResult(stdout, len(invocation.Stdin())+1, invocation.CompleteStdinSHA256())
	if err != nil {
		t.Fatal(err)
	}
	zeroProcess := newProviderExecutionTestProcess(
		t,
		stdout,
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, wrongResultLength, zeroProcess, 1024, 1024); err == nil {
		t.Fatal("successful observation accepted a mismatched result stdin length")
	}
}

func TestProviderExecutionObservationStatusTerminationCrossProduct(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	statuses := []ProviderExecutionStatus{
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
		ProviderExecutionStatusInternalFailure,
	}
	terminations := []ProcessTermination{
		ProcessTerminationExited,
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
		ProcessTerminationLockSecurity,
	}

	for _, status := range statuses {
		for _, termination := range terminations {
			t.Run(string(status)+"/"+string(termination), func(t *testing.T) {
				diagnosticCode := "provider_failure"
				if status == ProviderExecutionStatusArtifactFailure &&
					termination == ProcessTerminationExited {
					diagnosticCode = "post_exit_artifact"
				}
				process := newProviderExecutionTestProcessForTermination(t, invocation, termination)
				_, err := NewFailedProviderExecutionObservation(
					status,
					invocation,
					process,
					diagnosticCode,
					1024,
					1024,
				)
				if got := err == nil; got != providerExecutionTestStatusMatchesTermination(status, termination) {
					t.Fatalf("accepted = %t for status %q and termination %q", got, status, termination)
				}
			})
		}
	}

	process := newProviderExecutionTestProcessForTermination(t, invocation, ProcessTerminationExited)
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusSucceeded,
		invocation,
		process,
		"provider_failure",
		1024,
		1024,
	); err == nil {
		t.Fatal("failure constructor accepted successful status")
	}
}

func TestSuccessfulProviderExecutionObservationTerminationCrossProduct(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	stdout := []byte(`{"findings":[]}`)
	result := newProviderExecutionTestResult(t, invocation, stdout)
	terminations := []ProcessTermination{
		ProcessTerminationExited,
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
		ProcessTerminationLockSecurity,
	}

	for _, termination := range terminations {
		t.Run(string(termination), func(t *testing.T) {
			process := newProviderExecutionTestProcessForTermination(t, invocation, termination)
			if termination == ProcessTerminationExited {
				process = newProviderExecutionTestProcess(
					t,
					stdout,
					nil,
					providerExecutionTestExitCode(0),
					ProcessTerminationExited,
					completeProviderExecutionReceipt(t, invocation),
					providerExecutionTestStartedAt,
					providerExecutionTestEndedAt,
				)
			}
			_, err := NewSuccessfulProviderExecutionObservation(invocation, result, process, 1024, 1024)
			if got := err == nil; got != (termination == ProcessTerminationExited) {
				t.Fatalf("accepted = %t for termination %q", got, termination)
			}
		})
	}
}

func TestFailedProviderExecutionObservationAllowsPostExitClassification(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	process := newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeProviderExecutionReceipt(t, invocation),
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	statuses := []ProviderExecutionStatus{
		ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusSecurityViolation,
		ProviderExecutionStatusMutationViolation,
		ProviderExecutionStatusConfigurationViolation,
		ProviderExecutionStatusArtifactFailure,
		ProviderExecutionStatusInternalFailure,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			diagnosticCode := "post_exit_classification"
			if status == ProviderExecutionStatusArtifactFailure {
				diagnosticCode = "post_exit_artifact"
			}
			observation, err := NewFailedProviderExecutionObservation(
				status,
				invocation,
				process,
				diagnosticCode,
				1024,
				1024,
			)
			if err != nil {
				t.Fatal(err)
			}
			if observation.Termination() != ProcessTerminationExited {
				t.Fatalf("Termination() = %q, want exited", observation.Termination())
			}
			if exitCode, ok := observation.ExitCode(); !ok || exitCode != 0 {
				t.Fatalf("ExitCode() = %d, %t, want 0, true", exitCode, ok)
			}
		})
	}
}

func TestFailedProviderExecutionObservationDistinguishesSignaledFromExited128PlusSignal(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	signal, err := NewProcessSignal(15, "SIGTERM")
	if err != nil {
		t.Fatal(err)
	}
	signaledProcess := newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		nil,
		ProcessTerminationSignaled,
		completeProviderExecutionReceipt(t, invocation),
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
		signal,
	)
	terminatedByExitProcess := newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		providerExecutionTestExitCode(128+signal.Number()),
		ProcessTerminationExited,
		completeProviderExecutionReceipt(t, invocation),
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	classifications := []ProviderExecutionStatus{
		ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusSecurityViolation,
		ProviderExecutionStatusMutationViolation,
		ProviderExecutionStatusConfigurationViolation,
		ProviderExecutionStatusArtifactFailure,
		ProviderExecutionStatusInternalFailure,
	}

	for _, status := range classifications {
		t.Run(string(status)+"/signaled", func(t *testing.T) {
			_, err := NewFailedProviderExecutionObservation(
				status,
				invocation,
				signaledProcess,
				"provider_failure",
				1024,
				1024,
			)
			if got := err == nil; got != (status == ProviderExecutionStatusInternalFailure) {
				t.Fatalf("accepted = %t for signaled status %q", got, status)
			}
		})
		t.Run(string(status)+"/exited_143", func(t *testing.T) {
			_, err := NewFailedProviderExecutionObservation(
				status,
				invocation,
				terminatedByExitProcess,
				"post_exit_artifact",
				1024,
				1024,
			)
			if err != nil {
				t.Fatalf("NewFailedProviderExecutionObservation() = %v", err)
			}
		})
	}

	observation, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusInternalFailure,
		invocation,
		signaledProcess,
		"provider_failure",
		1024,
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	process := observation.ProcessObservation()
	if process.Termination() != ProcessTerminationSignaled {
		t.Fatalf("ProcessObservation().Termination() = %q, want signaled", process.Termination())
	}
	if number, name, ok := process.Signal(); !ok || number != signal.Number() || name != signal.Name() {
		t.Fatalf("ProcessObservation().Signal() = (%d, %q, %t)", number, name, ok)
	}
	if _, ok := process.ExitCode(); ok {
		t.Fatal("ProcessObservation() gave signaled process an exit code")
	}
	exitedObservation, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusInternalFailure,
		invocation,
		terminatedByExitProcess,
		"provider_failure",
		1024,
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	exitedProcess := exitedObservation.ProcessObservation()
	if exitedProcess.Termination() != ProcessTerminationExited {
		t.Fatalf("ProcessObservation().Termination() = %q, want exited", exitedProcess.Termination())
	}
	if exitCode, ok := exitedProcess.ExitCode(); !ok || exitCode != 128+signal.Number() {
		t.Fatalf("ProcessObservation().ExitCode() = %d, %t", exitCode, ok)
	}
	if _, _, ok := exitedProcess.Signal(); ok {
		t.Fatal("ProcessObservation() gave exited process a signal")
	}
}

func TestFailedProviderExecutionObservationRetainsPartialProcessEvidence(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	stdout := []byte("partial stdout")
	stderr := []byte("partial stderr")
	partialStdin := invocation.Stdin()[:len(invocation.Stdin())-1]
	receipt, err := NewStdinWriteReceipt(
		int64(len(invocation.Stdin())),
		int64(len(partialStdin)),
		providerTestDigest(partialStdin),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	process := newProviderExecutionTestProcess(
		t,
		stdout,
		stderr,
		nil,
		ProcessTerminationStdinIncomplete,
		receipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	observation, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusArtifactFailure,
		invocation,
		process,
		"stdin_write_incomplete",
		int64(len(stdout)),
		int64(len(stderr)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if observation.Termination() != ProcessTerminationStdinIncomplete {
		t.Fatalf("Termination() = %q", observation.Termination())
	}
	if observation.StdinWriteReceipt().Complete() ||
		observation.StdinWriteReceipt().WrittenByteCount() != int64(len(partialStdin)) {
		t.Fatalf("StdinWriteReceipt() = %#v", observation.StdinWriteReceipt())
	}
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() = %q, want %q", got, stdout)
	}
	if got := observation.Stderr(); !bytes.Equal(got, stderr) {
		t.Fatalf("Stderr() = %q, want %q", got, stderr)
	}
	if _, ok := observation.Result(); ok {
		t.Fatal("failed observation returned a successful result")
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}
func TestFailedProviderExecutionObservationRejectsTamperedPartialStdinDigest(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	partialStdin := invocation.Stdin()[:len(invocation.Stdin())-1]
	tamperedPrefix := append([]byte(nil), partialStdin...)
	tamperedPrefix[0] ^= 1
	receipt, err := NewStdinWriteReceipt(
		int64(len(invocation.Stdin())),
		int64(len(partialStdin)),
		providerTestDigest(tamperedPrefix),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	process := newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		nil,
		ProcessTerminationStdinIncomplete,
		receipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusArtifactFailure,
		invocation,
		process,
		"stdin_write_incomplete",
		1024,
		1024,
	); err == nil {
		t.Fatal("failed observation accepted a partial stdin digest for different bytes")
	}
}

func TestFailedProviderExecutionObservationRejectsCompletedStdinBeforeStart(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	for _, termination := range []ProcessTermination{
		ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationLockFailed,
		ProcessTerminationLockUnavailable,
		ProcessTerminationLockConfiguration,
		ProcessTerminationLockSecurity,
	} {
		t.Run(string(termination), func(t *testing.T) {
			process := newProviderExecutionTestProcess(
				t,
				nil,
				nil,
				nil,
				termination,
				completeProviderExecutionReceipt(t, invocation),
				providerExecutionTestStartedAt,
				providerExecutionTestEndedAt,
			)
			if _, err := NewFailedProviderExecutionObservation(
				ProviderExecutionStatusUnavailable,
				invocation,
				process,
				"provider_start_failed",
				1024,
				1024,
			); err == nil {
				t.Fatal("failed observation accepted completed non-empty stdin before process start")
			}
		})
	}
}

func TestProviderExecutionObservationEnforcesCaptureLimits(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	completeReceipt := completeProviderExecutionReceipt(t, invocation)

	for _, test := range []struct {
		name      string
		stdout    []byte
		stderr    []byte
		stdoutCap int64
		stderrCap int64
	}{
		{
			name:      "stdout may exceed smaller stderr cap",
			stdout:    []byte("abcdef"),
			stderr:    []byte("x"),
			stdoutCap: 6,
			stderrCap: 1,
		},
		{
			name:      "stderr may exceed smaller stdout cap",
			stdout:    []byte("x"),
			stderr:    []byte("abcdef"),
			stdoutCap: 1,
			stderrCap: 6,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			failedProcess := newProviderExecutionTestProcess(
				t,
				test.stdout,
				test.stderr,
				nil,
				ProcessTerminationTimedOut,
				completeReceipt,
				providerExecutionTestStartedAt,
				providerExecutionTestEndedAt,
			)
			failed, err := NewFailedProviderExecutionObservation(
				ProviderExecutionStatusTimedOut,
				invocation,
				failedProcess,
				"deadline_exceeded",
				test.stdoutCap,
				test.stderrCap,
			)
			if err != nil {
				t.Fatalf("valid asymmetric failed observation: %v", err)
			}
			if !bytes.Equal(failed.Stdout(), test.stdout) ||
				!bytes.Equal(failed.Stderr(), test.stderr) {
				t.Fatalf("failed asymmetric streams changed: %#v", failed.ProcessObservation())
			}

			result := newProviderExecutionTestResult(t, invocation, test.stdout)
			successfulProcess := newProviderExecutionTestProcess(
				t,
				test.stdout,
				test.stderr,
				providerExecutionTestExitCode(0),
				ProcessTerminationExited,
				completeReceipt,
				providerExecutionTestStartedAt,
				providerExecutionTestEndedAt,
			)
			successful, err := NewSuccessfulProviderExecutionObservation(
				invocation,
				result,
				successfulProcess,
				test.stdoutCap,
				test.stderrCap,
			)
			if err != nil {
				t.Fatalf("valid asymmetric successful observation: %v", err)
			}
			if !bytes.Equal(successful.Stdout(), test.stdout) ||
				!bytes.Equal(successful.Stderr(), test.stderr) {
				t.Fatalf("successful asymmetric streams changed: %#v", successful.ProcessObservation())
			}
		})
	}

	tooLongStdout := []byte("too long")
	timedOutProcess := newProviderExecutionTestProcess(
		t,
		tooLongStdout,
		nil,
		nil,
		ProcessTerminationTimedOut,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusTimedOut,
		invocation,
		timedOutProcess,
		"deadline_exceeded",
		7,
		1,
	); err == nil {
		t.Fatal("failed observation accepted stdout above its limit")
	}

	tooLongStderr := []byte("too long")
	cancelledProcess := newProviderExecutionTestProcess(
		t,
		nil,
		tooLongStderr,
		nil,
		ProcessTerminationCancelled,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusCancelled,
		invocation,
		cancelledProcess,
		"cancelled_by_context",
		1,
		7,
	); err == nil {
		t.Fatal("failed observation accepted stderr above its limit")
	}

	tooLongResult := newProviderExecutionTestResult(t, invocation, tooLongStdout)
	successfulProcess := newProviderExecutionTestProcess(
		t,
		tooLongStdout,
		nil,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeReceipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	if _, err := NewSuccessfulProviderExecutionObservation(invocation, tooLongResult, successfulProcess, 7, 1); err == nil {
		t.Fatal("successful observation accepted stdout above its limit")
	}
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusTimedOut,
		invocation,
		timedOutProcess,
		"deadline_exceeded",
		0,
		1,
	); err == nil {
		t.Fatal("failed observation accepted a zero stdout limit")
	}
}

func TestProviderExecutionObservationDefensiveCopies(t *testing.T) {
	stdin := []byte("complete provider stdin")
	invocation := newProviderExecutionTestInvocationWithStdin(t, stdin)
	stdout := []byte(`{"findings":[]}`)
	stderr := []byte("safe diagnostic")
	process := newProviderExecutionTestProcess(
		t,
		stdout,
		stderr,
		providerExecutionTestExitCode(0),
		ProcessTerminationExited,
		completeProviderExecutionReceipt(t, invocation),
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
	)
	result := newProviderExecutionTestResult(t, invocation, stdout)
	observation, err := NewSuccessfulProviderExecutionObservation(invocation, result, process, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}

	process.stdout[0] = 'x'
	process.stderr[0] = 'x'
	result.stdout[0] = 'x'
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() after source mutation = %q", got)
	}
	if got := observation.Stderr(); !bytes.Equal(got, stderr) {
		t.Fatalf("Stderr() after source mutation = %q", got)
	}

	returnedInvocation := observation.Invocation()
	returnedInvocation.stdin[0] = 'x'
	if got := observation.Invocation().Stdin(); !bytes.Equal(got, stdin) {
		t.Fatalf("Invocation() after return mutation = %q", got)
	}
	returnedResult, ok := observation.Result()
	if !ok {
		t.Fatal("Result() missing")
	}
	returnedResult.stdout[0] = 'x'
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() after Result() return mutation = %q", got)
	}
	returnedProcess := observation.ProcessObservation()
	returnedProcess.stdout[0] = 'x'
	returnedProcess.stderr[0] = 'x'
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() after ProcessObservation() mutation = %q", got)
	}
	if got := observation.Stderr(); !bytes.Equal(got, stderr) {
		t.Fatalf("Stderr() after ProcessObservation() mutation = %q", got)
	}
	returnedStdout := observation.Stdout()
	returnedStdout[0] = 'y'
	if got := observation.Stdout(); !bytes.Equal(got, stdout) {
		t.Fatalf("Stdout() after getter mutation = %q", got)
	}
	returnedStderr := observation.Stderr()
	returnedStderr[0] = 'y'
	if got := observation.Stderr(); !bytes.Equal(got, stderr) {
		t.Fatalf("Stderr() after getter mutation = %q", got)
	}
}

func TestFailedProviderExecutionObservationRejectsUnsafeDiagnosticCode(t *testing.T) {
	invocation := newProviderExecutionTestInvocation(t)
	process := newProviderExecutionTestProcessForTermination(t, invocation, ProcessTerminationStartUnavailable)
	for _, code := range []string{
		"",
		" leading",
		"trailing ",
		"UPPERCASE",
		"with-dash",
		"with.dot",
		"with\nlinebreak",
		"with\x00nul",
		strings.Repeat("a", 65),
	} {
		t.Run("invalid", func(t *testing.T) {
			if _, err := NewFailedProviderExecutionObservation(
				ProviderExecutionStatusUnavailable,
				invocation,
				process,
				code,
				1,
				1,
			); err == nil {
				t.Fatalf("NewFailedProviderExecutionObservation(%q) succeeded", code)
			}
		})
	}
	if _, err := NewFailedProviderExecutionObservation(
		ProviderExecutionStatusUnavailable,
		invocation,
		process,
		"provider_start_failed",
		1,
		1,
	); err != nil {
		t.Fatalf("safe diagnostic code rejected: %v", err)
	}
}

type typedNilObservedReviewProvider struct{}

func (*typedNilObservedReviewProvider) Observe(context.Context, ProviderInvocation) (ProviderExecutionObservation, error) {
	return ProviderExecutionObservation{}, nil
}

var _ ObservedReviewProvider = (*typedNilObservedReviewProvider)(nil)

func TestObservedReviewProviderRetainsTypedNilInterface(t *testing.T) {
	var provider ObservedReviewProvider = (*typedNilObservedReviewProvider)(nil)
	if provider == nil {
		t.Fatal("typed nil provider lost its interface type")
	}
}

var (
	providerExecutionTestStartedAt = time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	providerExecutionTestEndedAt   = providerExecutionTestStartedAt.Add(time.Second)
)

func newProviderExecutionTestInvocation(t *testing.T) ProviderInvocation {
	t.Helper()
	return newProviderExecutionTestInvocationWithStdin(t, []byte("complete provider stdin"))
}

func newProviderExecutionTestInvocationWithStdin(t *testing.T, stdin []byte) ProviderInvocation {
	t.Helper()
	attempt, err := domain.ParseAttemptID("a_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := NewProviderInvocation(
		domain.RoleSecurity,
		"kimi-main",
		attempt,
		ProviderInvocationInitial,
		stdin,
		"i_019f596a-cf80-7c67-b265-f37053d51ccd",
		"019f596a-cf80-7c67-b265-f37053d51cce",
		providerTestDigest(stdin),
	)
	if err != nil {
		t.Fatal(err)
	}
	return invocation
}

func newProviderExecutionTestResult(t *testing.T, invocation ProviderInvocation, stdout []byte) ProviderResult {
	t.Helper()
	result, err := NewProviderResult(stdout, len(invocation.Stdin()), invocation.CompleteStdinSHA256())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func completeProviderExecutionReceipt(t *testing.T, invocation ProviderInvocation) StdinWriteReceipt {
	t.Helper()
	receipt, err := NewStdinWriteReceipt(
		int64(len(invocation.Stdin())),
		int64(len(invocation.Stdin())),
		invocation.CompleteStdinSHA256(),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func newProviderExecutionTestProcess(
	t *testing.T,
	stdout, stderr []byte,
	exitCode *int,
	termination ProcessTermination,
	receipt StdinWriteReceipt,
	startedAt, endedAt time.Time,
	signals ...ProcessSignal,
) ProcessObservation {
	t.Helper()
	process, err := NewProcessObservation(
		stdout,
		stderr,
		exitCode,
		termination,
		receipt,
		startedAt,
		endedAt,
		signals...,
	)
	if err != nil {
		t.Fatal(err)
	}
	return process
}

func newProviderExecutionTestProcessForTermination(
	t *testing.T,
	invocation ProviderInvocation,
	termination ProcessTermination,
) ProcessObservation {
	t.Helper()
	receipt := completeProviderExecutionReceipt(t, invocation)
	var signals []ProcessSignal
	if termination == ProcessTerminationStdinIncomplete {
		partialStdin := invocation.Stdin()[:len(invocation.Stdin())-1]
		var err error
		receipt, err = NewStdinWriteReceipt(
			int64(len(invocation.Stdin())),
			int64(len(partialStdin)),
			providerTestDigest(partialStdin),
			false,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	if processTerminationPrecedesStdin(termination) {
		var err error
		receipt, err = NewStdinWriteReceipt(
			int64(len(invocation.Stdin())),
			0,
			providerTestDigest(nil),
			len(invocation.Stdin()) == 0,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	if termination == ProcessTerminationSignaled {
		signal, err := NewProcessSignal(15, "SIGTERM")
		if err != nil {
			t.Fatal(err)
		}
		signals = []ProcessSignal{signal}
	}
	var exitCode *int
	if termination == ProcessTerminationExited {
		exitCode = providerExecutionTestExitCode(1)
	}
	return newProviderExecutionTestProcess(
		t,
		nil,
		nil,
		exitCode,
		termination,
		receipt,
		providerExecutionTestStartedAt,
		providerExecutionTestEndedAt,
		signals...,
	)
}

func providerExecutionTestExitCode(value int) *int {
	return &value
}

func providerExecutionTestStatusMatchesTermination(status ProviderExecutionStatus, termination ProcessTermination) bool {
	switch status {
	case ProviderExecutionStatusTimedOut:
		return termination == ProcessTerminationTimedOut
	case ProviderExecutionStatusCancelled:
		return termination == ProcessTerminationCancelled
	case ProviderExecutionStatusArtifactFailure:
		return termination == ProcessTerminationStdoutLimit ||
			termination == ProcessTerminationStderrLimit ||
			termination == ProcessTerminationStdinIncomplete ||
			termination == ProcessTerminationExited
	case ProviderExecutionStatusUnavailable:
		return termination == ProcessTerminationStartUnavailable ||
			termination == ProcessTerminationLockUnavailable
	case ProviderExecutionStatusSecurityViolation:
		return termination == ProcessTerminationStartSecurity ||
			termination == ProcessTerminationLockSecurity ||
			termination == ProcessTerminationResidualProcessGroup ||
			termination == ProcessTerminationExited
	case ProviderExecutionStatusConfigurationViolation:
		return termination == ProcessTerminationStartConfiguration ||
			termination == ProcessTerminationLockConfiguration ||
			termination == ProcessTerminationExited
	case ProviderExecutionStatusAuthentication,
		ProviderExecutionStatusQuota,
		ProviderExecutionStatusRateLimit,
		ProviderExecutionStatusMutationViolation:
		return termination == ProcessTerminationExited
	case ProviderExecutionStatusInternalFailure:
		return termination == ProcessTerminationExited ||
			termination == ProcessTerminationSignaled ||
			termination == ProcessTerminationStartFailed ||
			termination == ProcessTerminationLockFailed
	default:
		return false
	}
}

func processTerminationPrecedesStdin(termination ProcessTermination) bool {
	switch termination {
	case ProcessTerminationStartFailed,
		ProcessTerminationStartUnavailable,
		ProcessTerminationStartConfiguration,
		ProcessTerminationStartSecurity,
		ProcessTerminationLockFailed,
		ProcessTerminationLockUnavailable,
		ProcessTerminationLockConfiguration,
		ProcessTerminationLockSecurity:
		return true
	default:
		return false
	}
}
