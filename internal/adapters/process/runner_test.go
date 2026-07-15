//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const processTestExecutionTimeout = 5 * time.Second

type runnerTestClock struct {
	times []time.Time
	calls int
}

func (clock *runnerTestClock) Now() time.Time {
	index := clock.calls
	clock.calls++
	if index >= len(clock.times) {
		index = len(clock.times) - 1
	}
	return clock.times[index]
}

type nilRunnerTestClock struct{}

func (*nilRunnerTestClock) Now() time.Time { return time.Time{} }

func TestNewRunnerRejectsNilClock(t *testing.T) {
	if _, err := NewRunner(nil); err == nil {
		t.Fatal("NewRunner(nil) succeeded")
	}

	var clock *nilRunnerTestClock
	if _, err := NewRunner(clock); err == nil {
		t.Fatal("NewRunner(typed nil) succeeded")
	}
}

func TestRunnerExactArgvEnvironmentWorkingDirectoryAndStdin(t *testing.T) {
	startedAt := time.Date(2026, 7, 15, 10, 0, 0, 0, time.FixedZone("test", -7*60*60))
	endedAt := startedAt.Add(time.Second)
	clock := &runnerTestClock{times: []time.Time{startedAt, endedAt}}
	runner, err := NewRunner(clock)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("KAR_PROCESS_RUNNER_LEAK", "inherited-parent-value")
	workingDirectory := t.TempDir()
	input := []byte("copied stdin")
	literalArgument := "$(touch never-runs); * ; $HOME"
	request := newHelperRequest(
		t,
		workingDirectory,
		"record",
		[]string{"first", literalArgument},
		[]ports.EnvironmentVariable{mustEnvironment(t, "KAR_PROCESS_RUNNER_VALUE", "explicit-value")},
		input,
		processTestExecutionTimeout,
		1024,
		1024,
	)
	copy(input, []byte("mutated input"))

	observation := mustRun(t, runner, context.Background(), request)
	assertTermination(t, observation, ports.ProcessTerminationExited)
	assertExitCode(t, observation, 0)

	binary := helperBinary(t)
	want := fmt.Sprintf(
		"argv0=%q\nargs=%q\ncwd=%q\npwd=%q\nenv=%t:%q\nleaked=%q\nstdin=%q\n",
		binary,
		[]string{"first", literalArgument},
		workingDirectory,
		workingDirectory,
		true,
		"explicit-value",
		"",
		"copied stdin",
	)
	if got := string(observation.Stdout()); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got := observation.Stderr(); len(got) != 0 {
		t.Fatalf("stderr = %q, want empty", got)
	}
	if got := observation.StartedAt(); !got.Equal(startedAt.UTC()) || got.Location() != time.UTC {
		t.Fatalf("StartedAt() = %s (%s), want %s (UTC)", got, got.Location(), startedAt.UTC())
	}
	if got := observation.EndedAt(); !got.Equal(endedAt.UTC()) || got.Location() != time.UTC {
		t.Fatalf("EndedAt() = %s (%s), want %s (UTC)", got, got.Location(), endedAt.UTC())
	}
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != int64(len("copied stdin")) ||
		receipt.WrittenByteCount() != int64(len("copied stdin")) ||
		!receipt.Complete() ||
		receipt.SHA256() != runnerTestStdinDigest([]byte("copied stdin")) {
		t.Fatalf("stdin receipt = %#v", receipt)
	}
	if !observation.Valid() {
		t.Fatal("observation is invalid")
	}
}

func TestRunnerSeparatesStreamsAndDefensivelyCopiesObservation(t *testing.T) {
	runner := newTestRunner(t)
	request := newHelperRequest(t, t.TempDir(), "streams", nil, nil, nil, processTestExecutionTimeout, 1024, 1024)

	observation := mustRun(t, runner, context.Background(), request)
	assertTermination(t, observation, ports.ProcessTerminationExited)
	assertExitCode(t, observation, 0)
	if got := string(observation.Stdout()); got != "stdout" {
		t.Fatalf("stdout = %q, want %q", got, "stdout")
	}
	if got := string(observation.Stderr()); got != "stderr" {
		t.Fatalf("stderr = %q, want %q", got, "stderr")
	}

	stdout := observation.Stdout()
	stderr := observation.Stderr()
	stdout[0] = 'X'
	stderr[0] = 'Y'
	if got := string(observation.Stdout()); got != "stdout" {
		t.Fatalf("stdout changed through accessor: %q", got)
	}
	if got := string(observation.Stderr()); got != "stderr" {
		t.Fatalf("stderr changed through accessor: %q", got)
	}
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != 0 || receipt.WrittenByteCount() != 0 ||
		!receipt.Complete() || receipt.SHA256() != runnerTestStdinDigest(nil) {
		t.Fatalf("zero-length stdin receipt = %#v", receipt)
	}
}

func TestRunnerRejectsPrefixOnlyStdinEvenWhenChildExitsZero(t *testing.T) {
	runner := newTestRunner(t)
	input := bytes.Repeat([]byte("x"), 8<<20)
	request := newHelperRequest(
		t,
		t.TempDir(),
		"prefix-read",
		nil,
		nil,
		input,
		processTestExecutionTimeout,
		1024,
		1024,
	)

	observation := mustRun(t, runner, context.Background(), request)
	assertTermination(t, observation, ports.ProcessTerminationStdinIncomplete)
	if observation.Succeeded() {
		t.Fatal("prefix-only stdin was accepted as successful")
	}
	if _, ok := observation.ExitCode(); ok {
		t.Fatal("incomplete stdin observation has an exit code")
	}
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != int64(len(input)) ||
		receipt.WrittenByteCount() >= int64(len(input)) ||
		receipt.Complete() {
		t.Fatalf("stdin receipt = %#v, want incomplete prefix", receipt)
	}
	if got, want := receipt.SHA256(), runnerTestStdinDigest(input[:int(receipt.WrittenByteCount())]); got != want {
		t.Fatalf("stdin receipt digest = %q, want %q", got, want)
	}
}
func TestRunnerRecordsNonzeroExit(t *testing.T) {
	runner := newTestRunner(t)
	nonzero := newHelperRequest(t, t.TempDir(), "exit", nil, nil, nil, processTestExecutionTimeout, 1024, 1024)
	observation := mustRun(t, runner, context.Background(), nonzero)
	assertTermination(t, observation, ports.ProcessTerminationExited)
	assertExitCode(t, observation, 17)
}

func TestRunnerClassifiesStartFailures(t *testing.T) {
	runner := newTestRunner(t)
	missingExecutable := filepath.Join(t.TempDir(), "does-not-exist")
	nonExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingWorkingDirectory := filepath.Join(t.TempDir(), "does-not-exist")
	notDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(notDirectory, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		executable  string
		workingDir  string
		termination ports.ProcessTermination
	}{
		{
			name:        "missing executable",
			executable:  missingExecutable,
			workingDir:  t.TempDir(),
			termination: ports.ProcessTerminationStartUnavailable,
		},
		{
			name:        "permission denied",
			executable:  nonExecutable,
			workingDir:  t.TempDir(),
			termination: ports.ProcessTerminationStartSecurity,
		},
		{
			name:        "missing working directory",
			executable:  helperBinary(t),
			workingDir:  missingWorkingDirectory,
			termination: ports.ProcessTerminationStartConfiguration,
		},
		{
			name:        "working directory is not a directory",
			executable:  helperBinary(t),
			workingDir:  notDirectory,
			termination: ports.ProcessTerminationStartConfiguration,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := mustRun(
				t,
				runner,
				context.Background(),
				newStartFailureRequest(t, test.executable, test.workingDir),
			)
			assertTermination(t, observation, test.termination)
			if _, ok := observation.ExitCode(); ok {
				t.Fatal("start failure has an exit code")
			}
			if _, _, ok := observation.Signal(); ok {
				t.Fatal("start failure has a signal")
			}
		})
	}
}

func TestClassifyStartFailure(t *testing.T) {
	request := newStartFailureRequest(t, helperBinary(t), t.TempDir())
	for _, test := range []struct {
		name        string
		err         error
		termination ports.ProcessTermination
	}{
		{
			name:        "missing",
			err:         &os.PathError{Op: "fork/exec", Path: request.Executable(), Err: syscall.ENOENT},
			termination: ports.ProcessTerminationStartUnavailable,
		},
		{
			name:        "resource unavailable",
			err:         &os.PathError{Op: "fork/exec", Path: request.Executable(), Err: syscall.EAGAIN},
			termination: ports.ProcessTerminationStartUnavailable,
		},
		{
			name:        "permission denied",
			err:         &os.PathError{Op: "fork/exec", Path: request.Executable(), Err: syscall.EACCES},
			termination: ports.ProcessTerminationStartSecurity,
		},
		{
			name:        "malformed executable",
			err:         &os.PathError{Op: "fork/exec", Path: request.Executable(), Err: syscall.ENOEXEC},
			termination: ports.ProcessTerminationStartConfiguration,
		},
		{
			name:        "unknown",
			err:         &os.PathError{Op: "fork/exec", Path: request.Executable(), Err: syscall.EIO},
			termination: ports.ProcessTerminationStartFailed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyStartFailure(request, test.err); got != test.termination {
				t.Fatalf("classifyStartFailure() = %q, want %q", got, test.termination)
			}
		})
	}
}
func TestRunnerDistinguishesExitedSignalCodesFromSignals(t *testing.T) {
	for _, test := range []struct {
		name       string
		scenario   string
		arguments  []string
		exitCode   int
		signal     int
		signalName string
	}{
		{name: "explicit SIGTERM-style exit code", scenario: "exit-code", arguments: []string{"143"}, exitCode: 143},
		{name: "explicit SIGKILL-style exit code", scenario: "exit-code", arguments: []string{"137"}, exitCode: 137},
		{name: "SIGTERM", scenario: "signal-term", signal: int(syscall.SIGTERM), signalName: "SIGTERM"},
		{name: "SIGKILL", scenario: "signal-kill", signal: int(syscall.SIGKILL), signalName: "SIGKILL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newTestRunner(t)
			request := newHelperRequest(
				t,
				t.TempDir(),
				test.scenario,
				test.arguments,
				nil,
				nil,
				processTestExecutionTimeout,
				1024,
				1024,
			)

			observation := mustRun(t, runner, context.Background(), request)
			if test.signal == 0 {
				assertTermination(t, observation, ports.ProcessTerminationExited)
				assertExitCode(t, observation, test.exitCode)
				if _, _, ok := observation.Signal(); ok {
					t.Fatal("explicit exit code was recorded as a signal")
				}
				return
			}

			assertTermination(t, observation, ports.ProcessTerminationSignaled)
			if _, ok := observation.ExitCode(); ok {
				t.Fatal("signaled process has an exit code")
			}
			assertSignal(t, observation, test.signal, test.signalName)
		})
	}
}

func TestRunnerEnforcesIndependentOutputCaps(t *testing.T) {
	runner := newTestRunner(t)

	stdoutLimited := newHelperRequest(t, t.TempDir(), "stdout-large", nil, nil, nil, processTestExecutionTimeout, 3, 1024)
	observation := mustRun(t, runner, context.Background(), stdoutLimited)
	assertTermination(t, observation, ports.ProcessTerminationStdoutLimit)
	if got := string(observation.Stdout()); got != "abc" {
		t.Fatalf("stdout limit retained %q, want %q", got, "abc")
	}
	if got := observation.Stderr(); len(got) != 0 {
		t.Fatalf("stdout-limited stderr = %q, want empty", got)
	}
	if _, ok := observation.ExitCode(); ok {
		t.Fatal("stdout limit has an exit code")
	}

	stderrLimited := newHelperRequest(t, t.TempDir(), "stderr-large", nil, nil, nil, processTestExecutionTimeout, 1024, 3)
	observation = mustRun(t, runner, context.Background(), stderrLimited)
	assertTermination(t, observation, ports.ProcessTerminationStderrLimit)
	if got := string(observation.Stderr()); got != "abc" {
		t.Fatalf("stderr limit retained %q, want %q", got, "abc")
	}
	if got := observation.Stdout(); len(got) != 0 {
		t.Fatalf("stderr-limited stdout = %q, want empty", got)
	}
	if _, ok := observation.ExitCode(); ok {
		t.Fatal("stderr limit has an exit code")
	}

	for _, test := range []struct {
		name       string
		mode       string
		stdoutCap  int64
		stderrCap  int64
		wantStdout string
		wantStderr string
	}{
		{
			name:       "stdout may exceed smaller stderr cap",
			mode:       "stdout-heavy",
			stdoutCap:  6,
			stderrCap:  1,
			wantStdout: "abcdef",
			wantStderr: "x",
		},
		{
			name:       "stderr may exceed smaller stdout cap",
			mode:       "stderr-heavy",
			stdoutCap:  1,
			stderrCap:  6,
			wantStdout: "x",
			wantStderr: "abcdef",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := newHelperRequest(
				t,
				t.TempDir(),
				test.mode,
				nil,
				nil,
				nil,
				processTestExecutionTimeout,
				test.stdoutCap,
				test.stderrCap,
			)
			observation := mustRun(t, runner, context.Background(), request)
			assertTermination(t, observation, ports.ProcessTerminationExited)
			if exitCode, ok := observation.ExitCode(); !ok || exitCode != 0 {
				t.Fatalf("asymmetric stream exit = %d/%t, want 0/true", exitCode, ok)
			}
			if got := string(observation.Stdout()); got != test.wantStdout {
				t.Fatalf("asymmetric stdout = %q, want %q", got, test.wantStdout)
			}
			if got := string(observation.Stderr()); got != test.wantStderr {
				t.Fatalf("asymmetric stderr = %q, want %q", got, test.wantStderr)
			}
		})
	}
}

func TestRunnerTimesOutAndHonorsPreCancelledContext(t *testing.T) {
	runner := newTestRunner(t)

	timeout := newHelperRequest(t, t.TempDir(), "sleep", nil, nil, nil, 40*time.Millisecond, 1024, 1024)
	observation := mustRun(t, runner, context.Background(), timeout)
	assertTermination(t, observation, ports.ProcessTerminationTimedOut)
	if _, ok := observation.ExitCode(); ok {
		t.Fatal("timeout has an exit code")
	}

	marker := filepath.Join(t.TempDir(), "must-not-exist")
	preCancelled := newHelperRequest(t, t.TempDir(), "marker", []string{marker}, nil, nil, processTestExecutionTimeout, 1024, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	observation = mustRun(t, runner, ctx, preCancelled)
	assertTermination(t, observation, ports.ProcessTerminationCancelled)
	if _, ok := observation.ExitCode(); ok {
		t.Fatal("pre-cancelled request has an exit code")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-cancelled child created marker: %v", err)
	}
}

func TestRunnerKillsAndReapsDescendantProcessGroup(t *testing.T) {
	runner := newTestRunner(t)
	ready := filepath.Join(t.TempDir(), "descendant.pid")
	survived := filepath.Join(t.TempDir(), "descendant-survived")
	request := newHelperRequest(t, t.TempDir(), "spawn-child", []string{ready, survived}, nil, nil, 5*time.Second, 1024, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		observation ports.ProcessObservation
		err         error
	}
	done := make(chan result, 1)
	go func() {
		observation, err := runner.Run(ctx, request)
		done <- result{observation: observation, err: err}
	}()

	pidContents, err := waitForFile(ready, processTestExecutionTimeout)
	if err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(pidContents)))
	if err != nil || pid <= 0 {
		cancel()
		<-done
		t.Fatalf("descendant pid = %q: %v", pidContents, err)
	}
	processGroupID := processGroupForPID(t, pid)

	cancel()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		assertTermination(t, result.observation, ports.ProcessTerminationCancelled)
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not reap process group after cancellation")
	}
	assertNoLiveProcessGroup(t, processGroupID)
	if _, err := os.Stat(survived); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descendant survived process-group cancellation: %v", err)
	}
}

func TestRunnerReapsLeaderExitedDescendantsForEveryTerminalSignal(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        string
		timeout     time.Duration
		maxStdout   int64
		cancel      bool
		termination ports.ProcessTermination
		stdin       []byte
	}{
		{
			name:        "cancellation",
			mode:        "silent",
			timeout:     processTestExecutionTimeout,
			maxStdout:   1024,
			cancel:      true,
			termination: ports.ProcessTerminationCancelled,
		},
		{
			name:        "timeout",
			mode:        "silent",
			timeout:     time.Second,
			maxStdout:   1024,
			termination: ports.ProcessTerminationTimedOut,
		},
		{
			name:        "stdout cap",
			mode:        "stdout-large",
			timeout:     processTestExecutionTimeout,
			maxStdout:   3,
			termination: ports.ProcessTerminationStdoutLimit,
		},
		{
			name:        "stdin incomplete",
			mode:        "stdin-incomplete",
			stdin:       bytes.Repeat([]byte("x"), 8<<20),
			timeout:     processTestExecutionTimeout,
			maxStdout:   1024,
			termination: ports.ProcessTerminationStdinIncomplete,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newTestRunner(t)
			ready := filepath.Join(t.TempDir(), "descendant.pid")
			request := newHelperRequest(
				t,
				t.TempDir(),
				"spawn-exit",
				[]string{ready, test.mode},
				nil,
				test.stdin,
				test.timeout,
				test.maxStdout,
				1024,
			)
			ctx := context.Background()
			var cancel context.CancelFunc
			if test.cancel {
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}

			type result struct {
				observation ports.ProcessObservation
				err         error
			}
			done := make(chan result, 1)
			go func() {
				observation, err := runner.Run(ctx, request)
				done <- result{observation: observation, err: err}
			}()

			pidContents, err := waitForFile(ready, processTestExecutionTimeout)
			if err != nil {
				if cancel != nil {
					cancel()
				}
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(bytes.TrimSpace(pidContents)))
			if err != nil || pid <= 0 {
				if cancel != nil {
					cancel()
				}
				t.Fatalf("descendant pid = %q: %v", pidContents, err)
			}
			processGroupID := pid
			if cancel != nil {
				cancel()
			}

			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				assertTermination(t, result.observation, test.termination)
			case <-time.After(2 * time.Second):
				t.Fatal("runner did not return after leader exited before descendant")
			}
			assertNoLiveProcessGroup(t, processGroupID)
		})
	}
}
func TestRunnerClassifiesClosedStdioResidualProcessGroup(t *testing.T) {
	runner := newTestRunner(t)
	leaderReady := filepath.Join(t.TempDir(), "leader.pid")
	leaderExited := filepath.Join(t.TempDir(), "leader-exited")
	descendantGroup := filepath.Join(t.TempDir(), "descendant.pgid")
	request := newHelperRequest(
		t,
		t.TempDir(),
		"spawn-exit-close-stdio",
		[]string{leaderReady, leaderExited, descendantGroup},
		nil,
		nil,
		processTestExecutionTimeout,
		1024,
		1024,
	)

	killEntered, releaseKill := blockProcessGroupSignal(t)
	defer releaseKill()

	done := runRunnerAsync(runner, context.Background(), request)
	leaderPID := readHelperPID(t, leaderReady)
	processGroupID := readHelperPID(t, descendantGroup)
	if processGroupID != leaderPID {
		t.Fatalf("descendant process group = %d, want direct leader PID %d", processGroupID, leaderPID)
	}
	if _, err := waitForFile(leaderExited, processTestExecutionTimeout); err != nil {
		t.Fatal(err)
	}
	waitForChannel(t, killEntered, "residual-process-group teardown")

	membership, err := probeDarwinProcessGroup(processGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !membership.leaderZombie || membership.liveMembers == 0 {
		t.Fatalf("residual process group = %#v, want zombie leader and live descendant", membership)
	}

	releaseKill()
	result := waitForRunnerResult(t, done)
	assertTermination(t, result.observation, ports.ProcessTerminationResidualProcessGroup)
	if _, ok := result.observation.ExitCode(); ok {
		t.Fatal("residual process group observation has an exit code")
	}
	if _, _, ok := result.observation.Signal(); ok {
		t.Fatal("residual process group observation has a signal")
	}
	assertNoLiveProcessGroup(t, processGroupID)
}
func TestRunnerDoesNotInterpretShellMetacharactersAndSupportsRepeatedRuns(t *testing.T) {
	runner := newTestRunner(t)
	marker := filepath.Join(t.TempDir(), "shell-ran")
	literal := "$(touch " + marker + "); echo shell-ran"
	request := newHelperRequest(t, t.TempDir(), "record", []string{literal}, nil, nil, processTestExecutionTimeout, 4096, 1024)
	observation := mustRun(t, runner, context.Background(), request)
	assertTermination(t, observation, ports.ProcessTerminationExited)
	if !bytes.Contains(observation.Stdout(), []byte(literal)) {
		t.Fatalf("literal argument missing from stdout: %q", observation.Stdout())
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell metacharacters created marker: %v", err)
	}

	repeated := newHelperRequest(t, t.TempDir(), "streams", nil, nil, nil, processTestExecutionTimeout, 1024, 1024)
	for run := 0; run < 16; run++ {
		observation = mustRun(t, runner, context.Background(), repeated)
		assertTermination(t, observation, ports.ProcessTerminationExited)
		assertExitCode(t, observation, 0)
	}
}

func TestTerminationSignalsUseLinearizedPrecedence(t *testing.T) {
	for _, test := range []struct {
		name    string
		signals terminationSignals
		want    ports.ProcessTermination
	}{
		{
			name:    "cancel plus exit",
			signals: terminationSignals{cancelled: true},
			want:    ports.ProcessTerminationCancelled,
		},
		{
			name:    "timeout plus exit",
			signals: terminationSignals{timedOut: true},
			want:    ports.ProcessTerminationTimedOut,
		},
		{
			name:    "cancel plus stdout cap",
			signals: terminationSignals{cancelled: true, stdoutFull: true},
			want:    ports.ProcessTerminationCancelled,
		},
		{
			name:    "simultaneous caps",
			signals: terminationSignals{stdoutFull: true, stderrFull: true},
			want:    ports.ProcessTerminationStdoutLimit,
		},
		{
			name:    "stdin incomplete before normal completion",
			signals: terminationSignals{stdinIncomplete: true},
			want:    ports.ProcessTerminationStdinIncomplete,
		},
		{
			name:    "stdin incomplete before residual process group",
			signals: terminationSignals{stdinIncomplete: true, residualProcessGroup: true},
			want:    ports.ProcessTerminationStdinIncomplete,
		},
		{
			name:    "residual process group before normal completion",
			signals: terminationSignals{residualProcessGroup: true},
			want:    ports.ProcessTerminationResidualProcessGroup,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.signals.termination(); got != test.want {
				t.Fatalf("termination() = %q, want %q", got, test.want)
			}
		})
	}
}
func TestRunnerRunArbitratesConcurrentTerminalFacts(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        string
		timeout     time.Duration
		cancel      bool
		maxStdout   int64
		maxStderr   int64
		termination ports.ProcessTermination
	}{
		{
			name:        "cancel plus exit",
			mode:        "exit",
			timeout:     processTestExecutionTimeout,
			cancel:      true,
			maxStdout:   1024,
			maxStderr:   1024,
			termination: ports.ProcessTerminationCancelled,
		},
		{
			name:        "timeout plus exit",
			mode:        "exit",
			timeout:     40 * time.Millisecond,
			maxStdout:   1024,
			maxStderr:   1024,
			termination: ports.ProcessTerminationTimedOut,
		},
		{
			name:        "cancel plus stdout cap",
			mode:        "stdout",
			timeout:     processTestExecutionTimeout,
			cancel:      true,
			maxStdout:   3,
			maxStderr:   1024,
			termination: ports.ProcessTerminationCancelled,
		},
		{
			name:        "cancel plus stderr cap",
			mode:        "stderr",
			timeout:     processTestExecutionTimeout,
			cancel:      true,
			maxStdout:   1024,
			maxStderr:   3,
			termination: ports.ProcessTerminationCancelled,
		},
		{
			name:        "simultaneous caps",
			mode:        "both",
			timeout:     processTestExecutionTimeout,
			maxStdout:   3,
			maxStderr:   3,
			termination: ports.ProcessTerminationStdoutLimit,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := newTestRunner(t)
			ready := filepath.Join(t.TempDir(), "ready")
			releaseChild := filepath.Join(t.TempDir(), "release-child")
			emitted := filepath.Join(t.TempDir(), "emitted")
			request := newHelperRequest(
				t,
				t.TempDir(),
				"barrier",
				[]string{ready, releaseChild, emitted, test.mode},
				nil,
				nil,
				test.timeout,
				test.maxStdout,
				test.maxStderr,
			)
			ctx := context.Background()
			var cancel context.CancelFunc
			if test.cancel {
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}

			killEntered, releaseKill := blockProcessGroupSignal(t)
			defer releaseKill()
			done := runRunnerAsync(runner, ctx, request)

			pid := readHelperPID(t, ready)
			processGroupID := processGroupForPID(t, pid)
			switch {
			case test.cancel && test.mode == "exit":
				cancel()
				waitForChannel(t, killEntered, "cancellation teardown")
				releaseHelper(t, releaseChild)
			case test.timeout < processTestExecutionTimeout:
				waitForChannel(t, killEntered, "timeout teardown")
				releaseHelper(t, releaseChild)
			default:
				releaseHelper(t, releaseChild)
				waitForChannel(t, killEntered, "output-limit teardown")
				if test.cancel {
					cancel()
				}
			}
			if _, err := waitForFile(emitted, processTestExecutionTimeout); err != nil {
				t.Fatal(err)
			}
			if test.mode == "exit" &&
				!waitForProcessGroupLeaderZombie(processGroupID, processTestExecutionTimeout) {
				t.Fatalf("process-group leader %d did not become zombie before terminal arbitration", processGroupID)
			}
			releaseKill()

			result := waitForRunnerResult(t, done)
			assertTermination(t, result.observation, test.termination)
			switch test.mode {
			case "stdout":
				if got := string(result.observation.Stdout()); got != "abc" {
					t.Fatalf("stdout = %q, want capped output", got)
				}
			case "stderr":
				if got := string(result.observation.Stderr()); got != "abc" {
					t.Fatalf("stderr = %q, want capped output", got)
				}
			case "both":
				if got := string(result.observation.Stdout()); got != "abc" {
					t.Fatalf("stdout = %q, want capped output", got)
				}
				if got := string(result.observation.Stderr()); got != "abc" {
					t.Fatalf("stderr = %q, want capped output", got)
				}
			}
			if _, ok := result.observation.ExitCode(); ok {
				t.Fatal("arbitrated terminal observation has an exit code")
			}
			if _, _, ok := result.observation.Signal(); ok {
				t.Fatal("arbitrated terminal observation has a signal")
			}
			assertNoLiveProcessGroup(t, processGroupID)
		})
	}
}

func TestRunnerRunArbitratesLeaderExitedStderrCap(t *testing.T) {
	runner := newTestRunner(t)
	leaderReady := filepath.Join(t.TempDir(), "leader-ready")
	leaderExited := filepath.Join(t.TempDir(), "leader-exited")
	descendantReady := filepath.Join(t.TempDir(), "descendant-ready")
	releaseChild := filepath.Join(t.TempDir(), "release-child")
	emitted := filepath.Join(t.TempDir(), "emitted")
	request := newHelperRequest(
		t,
		t.TempDir(),
		"barrier-spawn-exit",
		[]string{leaderReady, leaderExited, descendantReady, releaseChild, emitted},
		nil,
		nil,
		processTestExecutionTimeout,
		1024,
		3,
	)

	killEntered, releaseKill := blockProcessGroupSignal(t)
	defer releaseKill()
	done := runRunnerAsync(runner, context.Background(), request)
	leaderPID := readHelperPID(t, leaderReady)
	descendantPID := readHelperPID(t, descendantReady)
	processGroupID := processGroupForPID(t, descendantPID)
	if _, err := waitForFile(leaderExited, processTestExecutionTimeout); err != nil {
		t.Fatal(err)
	}
	if !waitForProcessGroupLeaderZombie(processGroupID, processTestExecutionTimeout) {
		t.Fatalf("leader process %d did not become zombie before descendant output", leaderPID)
	}

	releaseHelper(t, releaseChild)
	waitForChannel(t, killEntered, "stderr-limit teardown")
	if _, err := waitForFile(emitted, processTestExecutionTimeout); err != nil {
		t.Fatal(err)
	}
	releaseKill()

	result := waitForRunnerResult(t, done)
	assertTermination(t, result.observation, ports.ProcessTerminationStderrLimit)
	if got := string(result.observation.Stderr()); got != "abc" {
		t.Fatalf("stderr = %q, want capped output", got)
	}
	if _, ok := result.observation.ExitCode(); ok {
		t.Fatal("leader-exited stderr-limit observation has an exit code")
	}
	if _, _, ok := result.observation.Signal(); ok {
		t.Fatal("leader-exited stderr-limit observation has a signal")
	}
	assertNoLiveProcessGroup(t, processGroupID)
}

func TestKillProcessGroupEPERMRequiresProvenZombieOnlyMembership(t *testing.T) {
	originalSignalProcessGroup := signalProcessGroup
	originalProbeProcessGroup := probeProcessGroup
	t.Cleanup(func() {
		signalProcessGroup = originalSignalProcessGroup
		probeProcessGroup = originalProbeProcessGroup
	})

	signalProcessGroup = func(int, syscall.Signal) error {
		return syscall.EPERM
	}
	for _, test := range []struct {
		name       string
		membership processGroupMembership
		wantOK     bool
	}{
		{name: "zombie only", membership: processGroupMembership{zombieMembers: 1}, wantOK: true},
		{name: "live member", membership: processGroupMembership{liveMembers: 1}},
		{name: "absent after EPERM", membership: processGroupMembership{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			probeProcessGroup = func(int) (processGroupMembership, error) {
				return test.membership, nil
			}
			err := killProcessGroup(987654)
			if test.wantOK {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("killProcessGroup() error = %v, want EPERM", err)
			}
		})
	}
}

func TestKillProcessGroupVerifiesNoLiveMembersAfterSIGKILL(t *testing.T) {
	originalSignalProcessGroup := signalProcessGroup
	originalProbeProcessGroup := probeProcessGroup
	t.Cleanup(func() {
		signalProcessGroup = originalSignalProcessGroup
		probeProcessGroup = originalProbeProcessGroup
	})

	signalProcessGroup = func(int, syscall.Signal) error {
		return nil
	}
	probeCalls := 0
	probeProcessGroup = func(int) (processGroupMembership, error) {
		probeCalls++
		if probeCalls == 1 {
			return processGroupMembership{liveMembers: 1}, nil
		}
		return processGroupMembership{zombieMembers: 1}, nil
	}
	if err := killProcessGroup(987654); err != nil {
		t.Fatal(err)
	}
	if probeCalls < 2 {
		t.Fatal("successful SIGKILL was not verified after a live-member probe")
	}
}

func TestRunnerRejectsClockRegression(t *testing.T) {
	startedAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	runner, err := NewRunner(&runnerTestClock{times: []time.Time{startedAt.Add(-time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ports.NewStdinWriteReceipt(0, 0, runnerTestStdinDigest(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runner.observation(
		nil,
		nil,
		nil,
		ports.ProcessTerminationStartFailed,
		receipt,
		startedAt,
	)
	var regression *ClockRegressionError
	if !errors.As(err, &regression) {
		t.Fatalf("observation error = %v, want ClockRegressionError", err)
	}
	if !regression.StartedAt.Equal(startedAt) || !regression.EndedAt.Equal(startedAt.Add(-time.Second)) {
		t.Fatalf("clock regression = %#v", regression)
	}
}

func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	runner, err := NewRunner(&runnerTestClock{times: []time.Time{time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}
func newStartFailureRequest(t *testing.T, executable, workingDirectory string) ports.ProcessRequest {
	t.Helper()
	key, err := ports.ParseConcurrencyKey("process-test")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProcessRequest(
		executable,
		[]string{executable, "-test.run=^$"},
		nil,
		workingDirectory,
		nil,
		processTestExecutionTimeout,
		1024,
		1024,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func newHelperRequest(
	t *testing.T,
	workingDirectory string,
	scenario string,
	arguments []string,
	environment []ports.EnvironmentVariable,
	stdin []byte,
	timeout time.Duration,
	maxStdoutBytes, maxStderrBytes int64,
) ports.ProcessRequest {
	t.Helper()
	binary := helperBinary(t)
	argv := []string{binary, "-test.run=^TestRunnerHelperProcess$", "--", scenario}
	argv = append(argv, arguments...)
	environment = append([]ports.EnvironmentVariable{
		mustEnvironment(t, "KAR_PROCESS_RUNNER_HELPER", "1"),
		mustEnvironment(t, "GOCOVERDIR", t.TempDir()),
	}, environment...)
	key, err := ports.ParseConcurrencyKey("process-test")
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewProcessRequest(
		binary,
		argv,
		environment,
		workingDirectory,
		stdin,
		timeout,
		maxStdoutBytes,
		maxStderrBytes,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func helperBinary(t *testing.T) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(binary)
}

func mustEnvironment(t *testing.T, name, value string) ports.EnvironmentVariable {
	t.Helper()
	variable, err := ports.NewEnvironmentVariable(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return variable
}

func mustRun(t *testing.T, runner *Runner, ctx context.Context, request ports.ProcessRequest) ports.ProcessObservation {
	t.Helper()
	observation, err := runner.Run(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

type runnerResult struct {
	observation ports.ProcessObservation
	err         error
}

func runRunnerAsync(runner *Runner, ctx context.Context, request ports.ProcessRequest) <-chan runnerResult {
	done := make(chan runnerResult, 1)
	go func() {
		observation, err := runner.Run(ctx, request)
		done <- runnerResult{observation: observation, err: err}
	}()
	return done
}

func waitForRunnerResult(t *testing.T, done <-chan runnerResult) runnerResult {
	t.Helper()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not return")
		return runnerResult{}
	}
}

func blockProcessGroupSignal(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	originalSignalProcessGroup := signalProcessGroup
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	signalProcessGroup = func(processGroupID int, signal syscall.Signal) error {
		enteredOnce.Do(func() {
			close(entered)
		})
		<-release
		return originalSignalProcessGroup(processGroupID, signal)
	}
	t.Cleanup(func() {
		signalProcessGroup = originalSignalProcessGroup
	})
	return entered, func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
}

func waitForChannel(t *testing.T, channel <-chan struct{}, event string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(processTestExecutionTimeout):
		t.Fatalf("timed out waiting for %s", event)
	}
}

func readHelperPID(t *testing.T, path string) int {
	t.Helper()
	contents, err := waitForFile(path, processTestExecutionTimeout)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(contents)))
	if err != nil || pid <= 0 {
		t.Fatalf("helper pid = %q: %v", contents, err)
	}
	return pid
}

func processGroupForPID(t *testing.T, pid int) int {
	t.Helper()
	processGroupID, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("get process group for %d: %v", pid, err)
	}
	if processGroupID <= 0 {
		t.Fatalf("process %d has invalid process group %d", pid, processGroupID)
	}
	return processGroupID
}

func assertNoLiveProcessGroup(t *testing.T, processGroupID int) {
	t.Helper()
	membership, err := probeDarwinProcessGroup(processGroupID)
	if err != nil {
		t.Fatalf("probe process group %d after runner return: %v", processGroupID, err)
	}
	if membership.liveMembers != 0 {
		t.Fatalf(
			"process group %d has %d live members after runner return (%d zombie)",
			processGroupID,
			membership.liveMembers,
			membership.zombieMembers,
		)
	}
}

func releaseHelper(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertTermination(t *testing.T, observation ports.ProcessObservation, want ports.ProcessTermination) {
	t.Helper()
	if got := observation.Termination(); got != want {
		t.Fatalf("termination = %q, want %q", got, want)
	}
	if !observation.Valid() {
		t.Fatalf("observation with termination %q is invalid", gotTermination(observation))
	}
}

func gotTermination(observation ports.ProcessObservation) ports.ProcessTermination {
	return observation.Termination()
}

func assertExitCode(t *testing.T, observation ports.ProcessObservation, want int) {
	t.Helper()
	got, ok := observation.ExitCode()
	if !ok || got != want {
		t.Fatalf("exit code = (%d, %t), want (%d, true)", got, ok, want)
	}
}
func assertSignal(t *testing.T, observation ports.ProcessObservation, wantNumber int, wantName string) {
	t.Helper()
	number, name, ok := observation.Signal()
	if !ok || number != wantNumber || name != wantName {
		t.Fatalf(
			"Signal() = (%d, %q, %t), want (%d, %q, true)",
			number,
			name,
			ok,
			wantNumber,
			wantName,
		)
	}
}

func runnerTestStdinDigest(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}
func waitForFile(path string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		contents, err := os.ReadFile(path)
		if err == nil && len(bytes.TrimSpace(contents)) > 0 {
			return contents, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForProcessGroupLeaderZombie(processGroupID int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		membership, err := probeDarwinProcessGroup(processGroupID)
		if err != nil {
			return false
		}
		if membership.leaderZombie {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunnerHelperProcess(t *testing.T) {
	if os.Getenv("KAR_PROCESS_RUNNER_HELPER") != "1" {
		return
	}

	arguments := helperArguments()
	if len(arguments) == 0 {
		os.Exit(2)
	}

	switch arguments[0] {
	case "record":
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(2)
		}
		workingDirectory, err := os.Getwd()
		if err != nil {
			os.Exit(2)
		}
		value, present := os.LookupEnv("KAR_PROCESS_RUNNER_VALUE")
		fmt.Fprintf(
			os.Stdout,
			"argv0=%q\nargs=%q\ncwd=%q\npwd=%q\nenv=%t:%q\nleaked=%q\nstdin=%q\n",
			os.Args[0],
			arguments[1:],
			workingDirectory,
			os.Getenv("PWD"),
			present,
			value,
			os.Getenv("KAR_PROCESS_RUNNER_LEAK"),
			stdin,
		)
		os.Exit(0)
	case "prefix-read":
		var one [1]byte
		if _, err := io.ReadFull(os.Stdin, one[:]); err != nil {
			os.Exit(2)
		}
		fmt.Fprint(os.Stdout, "unaccepted")
		os.Exit(0)
	case "streams":
		fmt.Fprint(os.Stdout, "stdout")
		fmt.Fprint(os.Stderr, "stderr")
		os.Exit(0)
	case "stdout-heavy":
		fmt.Fprint(os.Stdout, "abcdef")
		fmt.Fprint(os.Stderr, "x")
		os.Exit(0)
	case "stderr-heavy":
		fmt.Fprint(os.Stdout, "x")
		fmt.Fprint(os.Stderr, "abcdef")
		os.Exit(0)
	case "exit":
		os.Exit(17)
	case "exit-code":
		if len(arguments) != 2 {
			os.Exit(2)
		}
		code, err := strconv.Atoi(arguments[1])
		if err != nil || code < 0 || code > 255 {
			os.Exit(2)
		}
		os.Exit(code)
	case "signal-term":
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			os.Exit(2)
		}
		os.Exit(2)
	case "signal-kill":
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			os.Exit(2)
		}
		os.Exit(2)
	case "barrier":
		if len(arguments) != 5 || !helperWritePID(arguments[1]) || !waitForHelperRelease(arguments[2]) {
			os.Exit(2)
		}
		switch arguments[4] {
		case "exit":
			if !helperWriteMarker(arguments[3], "emitted") {
				os.Exit(2)
			}
			os.Exit(0)
		case "stdout":
			fmt.Fprint(os.Stdout, "abcdef")
		case "stderr":
			fmt.Fprint(os.Stderr, "abcdef")
		case "both":
			fmt.Fprint(os.Stdout, "abcdef")
			fmt.Fprint(os.Stderr, "abcdef")
		default:
			os.Exit(2)
		}
		if !helperWriteMarker(arguments[3], "emitted") {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "barrier-spawn-exit":
		if len(arguments) != 6 || !helperWritePID(arguments[1]) {
			os.Exit(2)
		}
		child := exec.Command(
			os.Args[0],
			"-test.run=^TestRunnerHelperProcess$",
			"--",
			"barrier-descendant",
			arguments[3],
			arguments[4],
			arguments[5],
		)
		child.Env = os.Environ()
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil || !helperWriteMarker(arguments[2], "exited") {
			os.Exit(2)
		}
		os.Exit(0)
	case "barrier-descendant":
		if len(arguments) != 4 || !helperWritePID(arguments[1]) || !waitForHelperRelease(arguments[2]) {
			os.Exit(2)
		}
		fmt.Fprint(os.Stderr, "abcdef")
		if !helperWriteMarker(arguments[3], "emitted") {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "stdout-large":
		fmt.Fprint(os.Stdout, "abcdef")
		os.Exit(0)
	case "stderr-large":
		fmt.Fprint(os.Stderr, "abcdef")
		os.Exit(0)
	case "sleep":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "marker":
		if len(arguments) != 2 || os.WriteFile(arguments[1], []byte("started"), 0o600) != nil {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "spawn-exit-close-stdio":
		if len(arguments) != 4 || !helperWritePID(arguments[1]) {
			os.Exit(2)
		}
		child := exec.Command(
			os.Args[0],
			"-test.run=^TestRunnerHelperProcess$",
			"--",
			"descendant-close-stdio",
			arguments[3],
		)
		child.Env = os.Environ()
		// Nil streams make os/exec attach /dev/null instead of inheriting leader pipes.
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if err := child.Start(); err != nil || !helperWriteMarker(arguments[2], "exited") {
			os.Exit(2)
		}
		os.Exit(0)
	case "descendant-close-stdio":
		if len(arguments) != 2 ||
			os.WriteFile(arguments[1], []byte(strconv.Itoa(syscall.Getpgrp())), 0o600) != nil {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "spawn-exit":
		if len(arguments) != 3 {
			os.Exit(2)
		}
		child := exec.Command(
			os.Args[0],
			"-test.run=^TestRunnerHelperProcess$",
			"--",
			"descendant-hold",
			arguments[1],
			arguments[2],
		)
		child.Env = os.Environ()
		if arguments[2] != "stdin-incomplete" {
			child.Stdin = os.Stdin
		}
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if arguments[2] == "stdin-incomplete" && !waitForHelperRelease(arguments[1]) {
			os.Exit(2)
		}
		os.Exit(0)
	case "descendant-hold":
		if len(arguments) != 3 {
			os.Exit(2)
		}
		if err := os.WriteFile(arguments[1], []byte(strconv.Itoa(syscall.Getpgrp())), 0o600); err != nil {
			os.Exit(2)
		}
		if arguments[2] == "stdout-large" {
			fmt.Fprint(os.Stdout, "abcdef")
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "spawn-child":
		if len(arguments) != 3 {
			os.Exit(2)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestRunnerHelperProcess$", "--", "descendant", arguments[1], arguments[2])
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "descendant":
		if len(arguments) != 3 {
			os.Exit(2)
		}
		if err := os.WriteFile(arguments[1], []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			os.Exit(2)
		}
		time.Sleep(300 * time.Millisecond)
		if err := os.WriteFile(arguments[2], []byte("survived"), 0o600); err != nil {
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
func helperWritePID(path string) bool {
	return helperWriteMarker(path, strconv.Itoa(os.Getpid()))
}

func helperWriteMarker(path, value string) bool {
	return os.WriteFile(path, []byte(value), 0o600) == nil
}

func waitForHelperRelease(path string) bool {
	deadline := time.Now().Add(processTestExecutionTimeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func helperArguments() []string {
	for index, argument := range os.Args {
		if argument == "--" && index+1 < len(os.Args) {
			return os.Args[index+1:]
		}
	}
	return nil
}
