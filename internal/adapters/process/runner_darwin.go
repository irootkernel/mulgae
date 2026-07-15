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
	"syscall"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	processGroupTeardownTimeout = time.Second
	processGroupProbeInterval   = 10 * time.Millisecond
	darwinProcessStateZombie    = 5
)

var (
	errOutputLimit = errors.New("process output exceeds configured limit")

	signalProcessGroup = func(processGroupID int, signal syscall.Signal) error {
		return syscall.Kill(-processGroupID, signal)
	}
	probeProcessGroup = probeDarwinProcessGroup
)

type processGroupMembership struct {
	leaderLive    bool
	leaderZombie  bool
	liveMembers   int
	zombieMembers int
}

func (membership processGroupMembership) absent() bool {
	return membership.liveMembers == 0 && membership.zombieMembers == 0
}

func (membership processGroupMembership) zombieOnly() bool {
	return membership.liveMembers == 0 && membership.zombieMembers > 0
}

func (membership processGroupMembership) leaderExitedWithLiveDescendants() bool {
	return membership.leaderZombie && membership.liveMembers > 0
}

func (membership processGroupMembership) leaderExitedWithNoLiveMembers() bool {
	return membership.leaderZombie && membership.liveMembers == 0
}

type streamKind uint8

const (
	stdoutStream streamKind = iota
	stderrStream
)

type streamResult struct {
	stream streamKind
	err    error
}

type stdinResult struct {
	receipt ports.StdinWriteReceipt
	err     error
}

type cappedCapture struct {
	limit    int64
	bytes    []byte
	exceeded bool
}

func (capture *cappedCapture) Write(value []byte) (int, error) {
	remaining := capture.limit - int64(len(capture.bytes))
	if remaining <= 0 {
		if len(value) == 0 {
			return 0, nil
		}
		capture.exceeded = true
		return 0, errOutputLimit
	}
	if int64(len(value)) > remaining {
		written := int(remaining)
		capture.bytes = append(capture.bytes, value[:written]...)
		capture.exceeded = true
		return written, errOutputLimit
	}
	capture.bytes = append(capture.bytes, value...)
	return len(value), nil
}

type terminationSignals struct {
	cancelled            bool
	timedOut             bool
	stdoutFull           bool
	stderrFull           bool
	stdinIncomplete      bool
	residualProcessGroup bool
	internal             error
}

func (signals *terminationSignals) record(result streamResult) {
	if result.err == nil {
		return
	}
	if errors.Is(result.err, errOutputLimit) {
		switch result.stream {
		case stdoutStream:
			signals.stdoutFull = true
		case stderrStream:
			signals.stderrFull = true
		}
		return
	}
	if signals.internal == nil {
		signals.internal = fmt.Errorf("process runner: capture stream: %w", result.err)
	}
}

func (signals *terminationSignals) recordStdin(result stdinResult) {
	if !result.receipt.Valid() {
		if signals.internal == nil {
			signals.internal = errors.New("process runner: invalid stdin write receipt")
		}
		return
	}
	if !result.receipt.Complete() {
		signals.stdinIncomplete = true
		return
	}
	if result.err != nil && signals.internal == nil {
		signals.internal = fmt.Errorf("process runner: record stdin write: %w", result.err)
	}
}

// termination applies the runner's explicit terminal precedence: caller
// cancellation, request timeout, stdout cap, stderr cap, stdin incompleteness,
// residual same-PGID membership, then normal process completion.
func (signals terminationSignals) termination() ports.ProcessTermination {
	switch {
	case signals.cancelled:
		return ports.ProcessTerminationCancelled
	case signals.timedOut:
		return ports.ProcessTerminationTimedOut
	case signals.stdoutFull:
		return ports.ProcessTerminationStdoutLimit
	case signals.stderrFull:
		return ports.ProcessTerminationStderrLimit
	case signals.stdinIncomplete:
		return ports.ProcessTerminationStdinIncomplete
	case signals.residualProcessGroup:
		return ports.ProcessTerminationResidualProcessGroup
	default:
		return ""
	}
}

// Run executes a ProcessRequest with direct argv and only its explicit
// environment. It owns and terminates a dedicated process group; it does not
// claim sandbox or process-tree containment against an executable that escapes
// that group. It records exactly what was written to the child stdin pipe
// before accepting a normal completion.
func (runner *Runner) Run(ctx context.Context, request ports.ProcessRequest) (ports.ProcessObservation, error) {
	if ctx == nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: nil context")
	}
	if runner == nil || nilClock(runner.clock) {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: nil clock")
	}
	if !request.Valid() {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: invalid process request")
	}

	stdin := request.Stdin()
	expectedStdinSHA256 := stdinWriteSHA256(stdin)
	initialReceipt, err := stdinReceipt(stdin, 0)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	startedAt, err := runner.timestamp()
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	timer := time.NewTimer(request.Timeout())
	defer timer.Stop()
	if ctx.Err() != nil {
		return runner.observation(nil, nil, nil, ports.ProcessTerminationCancelled, initialReceipt, startedAt)
	}

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: create stdout pipe: %w", err)
	}
	defer stdoutReader.Close()

	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutWriter.Close()
		return ports.ProcessObservation{}, fmt.Errorf("process runner: create stderr pipe: %w", err)
	}
	defer stderrReader.Close()

	argv := request.Argv()
	environment := explicitEnvironment(request.Environment())
	child := &exec.Cmd{
		Path:        request.Executable(),
		Args:        argv,
		Dir:         request.WorkingDirectory(),
		Env:         environment,
		Stdout:      stdoutWriter,
		Stderr:      stderrWriter,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	stdinWriter, err := child.StdinPipe()
	if err != nil {
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return ports.ProcessObservation{}, fmt.Errorf("process runner: create stdin pipe: %w", err)
	}
	if ctx.Err() != nil {
		_ = stdinWriter.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return runner.observation(nil, nil, nil, ports.ProcessTerminationCancelled, initialReceipt, startedAt)
	}
	if err := child.Start(); err != nil {
		_ = stdinWriter.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return runner.observation(nil, nil, nil, classifyStartFailure(request, err), initialReceipt, startedAt)
	}

	processGroupID, err := captureProcessGroup(child.Process.Pid)
	if err != nil {
		cleanupErr := cleanupStartedChild(child, child.Process.Pid, stdinWriter, stdoutWriter, stderrWriter)
		return ports.ProcessObservation{}, fmt.Errorf("process runner: capture child process group: %w", errors.Join(err, cleanupErr))
	}
	if err := errors.Join(stdoutWriter.Close(), stderrWriter.Close()); err != nil {
		cleanupErr := cleanupStartedChild(child, processGroupID, stdinWriter)
		return ports.ProcessObservation{}, fmt.Errorf("process runner: close parent output pipes: %w", errors.Join(err, cleanupErr))
	}

	stdout := cappedCapture{limit: request.MaxStdoutBytes()}
	stderr := cappedCapture{limit: request.MaxStderrBytes()}
	streamResults := make(chan streamResult, 2)
	go copyStream(stdoutStream, stdoutReader, &stdout, streamResults)
	go copyStream(stderrStream, stderrReader, &stderr, streamResults)

	stdinResults := make(chan stdinResult, 1)
	go copyStdin(stdinWriter, stdin, stdinResults)

	waitResult := make(chan error, 1)

	processGroupTicker := time.NewTicker(processGroupProbeInterval)
	defer processGroupTicker.Stop()

	var (
		waitStarted        bool
		waited             bool
		waitErr            error
		streamsRead        int
		stdinWritten       bool
		stdinReceipt       ports.StdinWriteReceipt
		groupDispositioned bool
		tearingDown        bool
		teardownErr        error
		teardownTimer      *time.Timer
		signals            terminationSignals
	)
	defer func() {
		if teardownTimer != nil {
			teardownTimer.Stop()
		}
	}()

	for {
		for consumeRunnerCompletion(
			&waited,
			&waitErr,
			&streamsRead,
			&stdinWritten,
			&stdinReceipt,
			waitResult,
			streamResults,
			stdinResults,
			&signals,
		) {
		}
		snapshotTerminalFacts(ctx, timer, &signals)
		if stdinWritten &&
			stdinReceipt.Valid() &&
			(!stdinReceipt.Complete() || stdinReceipt.SHA256() != expectedStdinSHA256) {
			signals.stdinIncomplete = true
		}

		if !tearingDown &&
			!groupDispositioned &&
			signals.termination() == "" &&
			signals.internal == nil &&
			streamsRead == 2 &&
			stdinWritten {
			membership, err := probeProcessGroup(processGroupID)
			if err != nil {
				signals.internal = fmt.Errorf("process runner: probe child process group: %w", err)
			} else {
				switch {
				case membership.leaderExitedWithLiveDescendants():
					signals.residualProcessGroup = true
				case membership.leaderExitedWithNoLiveMembers():
					groupDispositioned = true
				case !membership.leaderLive:
					signals.internal = fmt.Errorf(
						"process runner: child process-group leader %d is neither live nor zombie",
						processGroupID,
					)
				}
			}
		}

		if !tearingDown && (signals.termination() != "" || signals.internal != nil) {
			tearingDown = true
			teardownErr = killProcessGroup(processGroupID)
			if teardownErr == nil {
				groupDispositioned = true
			}
			_ = stdinWriter.Close()
			teardownTimer = time.NewTimer(processGroupTeardownTimeout)
		}
		if groupDispositioned && !waitStarted {
			waitStarted = true
			go func() {
				waitResult <- child.Wait()
			}()
		}
		if waited && streamsRead == 2 && stdinWritten {
			break
		}

		if tearingDown {
			select {
			case err := <-waitResult:
				waited = true
				waitErr = err
			case result := <-streamResults:
				streamsRead++
				signals.record(result)
			case result := <-stdinResults:
				stdinWritten = true
				stdinReceipt = result.receipt
				signals.recordStdin(result)
			case <-teardownTimer.C:
				closeErr := errors.Join(stdinWriter.Close(), stdoutReader.Close(), stderrReader.Close())
				return ports.ProcessObservation{}, fmt.Errorf(
					"process runner: bounded group teardown did not complete: %w",
					errors.Join(teardownErr, closeErr),
				)
			}
			continue
		}

		select {
		case err := <-waitResult:
			waited = true
			waitErr = err
		case result := <-streamResults:
			streamsRead++
			signals.record(result)
		case result := <-stdinResults:
			stdinWritten = true
			stdinReceipt = result.receipt
			signals.recordStdin(result)
		case <-ctx.Done():
			signals.cancelled = true
		case <-timer.C:
			signals.timedOut = true
		case <-processGroupTicker.C:
		}
	}

	for consumeRunnerCompletion(
		&waited,
		&waitErr,
		&streamsRead,
		&stdinWritten,
		&stdinReceipt,
		waitResult,
		streamResults,
		stdinResults,
		&signals,
	) {
	}
	snapshotTerminalFacts(ctx, timer, &signals)

	if teardownErr != nil {
		return ports.ProcessObservation{}, teardownErr
	}
	if signals.internal != nil {
		return ports.ProcessObservation{}, signals.internal
	}
	if termination := signals.termination(); termination != "" {
		return runner.observation(stdout.bytes, stderr.bytes, nil, termination, stdinReceipt, startedAt)
	}
	if err := normalWaitError(waitErr); err != nil {
		return ports.ProcessObservation{}, err
	}
	exitCode, signal, err := processExitStatus(child.ProcessState)
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	if signal != nil {
		return runner.signaledObservation(stdout.bytes, stderr.bytes, *signal, stdinReceipt, startedAt)
	}
	return runner.observation(stdout.bytes, stderr.bytes, exitCode, ports.ProcessTerminationExited, stdinReceipt, startedAt)
}
func (runner *Runner) signaledObservation(
	stdout, stderr []byte,
	signal ports.ProcessSignal,
	stdinWriteReceipt ports.StdinWriteReceipt,
	startedAt time.Time,
) (ports.ProcessObservation, error) {
	endedAt, err := runner.timestamp()
	if err != nil {
		return ports.ProcessObservation{}, err
	}
	if endedAt.Before(startedAt) {
		return ports.ProcessObservation{}, &ClockRegressionError{
			StartedAt: startedAt,
			EndedAt:   endedAt,
		}
	}
	observation, err := ports.NewProcessObservation(
		stdout,
		stderr,
		nil,
		ports.ProcessTerminationSignaled,
		stdinWriteReceipt,
		startedAt,
		endedAt,
		signal,
	)
	if err != nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: construct signaled observation: %w", err)
	}
	return observation, nil
}

func explicitEnvironment(environment []ports.EnvironmentVariable) []string {
	result := make([]string, 0, len(environment))
	for _, variable := range environment {
		result = append(result, variable.Name()+"="+variable.Value())
	}
	return result
}
func classifyStartFailure(request ports.ProcessRequest, startErr error) ports.ProcessTermination {
	if startRequestConfiguration(request) {
		return ports.ProcessTerminationStartConfiguration
	}

	switch {
	case errors.Is(startErr, exec.ErrNotFound),
		errors.Is(startErr, os.ErrNotExist),
		errors.Is(startErr, syscall.ENOENT),
		errors.Is(startErr, syscall.EAGAIN),
		errors.Is(startErr, syscall.ENOMEM),
		errors.Is(startErr, syscall.EMFILE),
		errors.Is(startErr, syscall.ENFILE),
		errors.Is(startErr, syscall.EBUSY),
		errors.Is(startErr, syscall.ETXTBSY),
		errors.Is(startErr, syscall.EPROCLIM):
		return ports.ProcessTerminationStartUnavailable
	case errors.Is(startErr, os.ErrPermission),
		errors.Is(startErr, syscall.EACCES),
		errors.Is(startErr, syscall.EPERM),
		errors.Is(startErr, syscall.EAUTH),
		errors.Is(startErr, syscall.ENEEDAUTH):
		return ports.ProcessTerminationStartSecurity
	case errors.Is(startErr, syscall.E2BIG),
		errors.Is(startErr, syscall.EBADEXEC),
		errors.Is(startErr, syscall.EBADARCH),
		errors.Is(startErr, syscall.EBADMACHO),
		errors.Is(startErr, syscall.EFTYPE),
		errors.Is(startErr, syscall.EINVAL),
		errors.Is(startErr, syscall.EISDIR),
		errors.Is(startErr, syscall.ELOOP),
		errors.Is(startErr, syscall.ENAMETOOLONG),
		errors.Is(startErr, syscall.ENOTDIR),
		errors.Is(startErr, syscall.ENOEXEC):
		return ports.ProcessTerminationStartConfiguration
	default:
		return ports.ProcessTerminationStartFailed
	}
}

func startRequestConfiguration(request ports.ProcessRequest) bool {
	workingDirectory, err := os.Stat(request.WorkingDirectory())
	if err == nil {
		return !workingDirectory.IsDir()
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	executable, err := os.Stat(request.Executable())
	return err == nil && executable.IsDir()
}

func copyStream(stream streamKind, reader *os.File, capture io.Writer, results chan<- streamResult) {
	_, err := io.Copy(capture, reader)
	closeErr := reader.Close()
	if err == nil {
		err = closeErr
	}
	results <- streamResult{stream: stream, err: err}
}

type stdinWriteCounter struct {
	writer  io.Writer
	written int
}

func (counter *stdinWriteCounter) Write(value []byte) (int, error) {
	written, err := counter.writer.Write(value)
	if written < 0 || written > len(value) {
		return 0, fmt.Errorf("process runner: invalid stdin write count %d", written)
	}
	counter.written += written
	return written, err
}

func copyStdin(writer io.WriteCloser, stdin []byte, results chan<- stdinResult) {
	counter := stdinWriteCounter{writer: writer}
	_, copyErr := io.Copy(&counter, bytes.NewReader(stdin))
	closeErr := writer.Close()

	receipt, receiptErr := stdinReceipt(stdin, counter.written)
	results <- stdinResult{receipt: receipt, err: errors.Join(copyErr, closeErr, receiptErr)}
}

func stdinReceipt(stdin []byte, written int) (ports.StdinWriteReceipt, error) {
	if written < 0 || written > len(stdin) {
		return ports.StdinWriteReceipt{}, fmt.Errorf("process runner: invalid stdin write count %d", written)
	}
	return ports.NewStdinWriteReceipt(
		int64(len(stdin)),
		int64(written),
		stdinWriteSHA256(stdin[:written]),
		written == len(stdin),
	)
}

func stdinWriteSHA256(value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func consumeRunnerCompletion(
	waited *bool,
	waitErr *error,
	streamsRead *int,
	stdinWritten *bool,
	stdinReceipt *ports.StdinWriteReceipt,
	waitResult <-chan error,
	streamResults <-chan streamResult,
	stdinResults <-chan stdinResult,
	signals *terminationSignals,
) bool {
	if !*waited {
		select {
		case err := <-waitResult:
			*waited = true
			*waitErr = err
			return true
		default:
		}
	}
	if *streamsRead < 2 {
		select {
		case result := <-streamResults:
			*streamsRead++
			signals.record(result)
			return true
		default:
		}
	}
	if !*stdinWritten {
		select {
		case result := <-stdinResults:
			*stdinWritten = true
			*stdinReceipt = result.receipt
			signals.recordStdin(result)
			return true
		default:
		}
	}
	return false
}

func snapshotTerminalFacts(ctx context.Context, timer *time.Timer, signals *terminationSignals) {
	if ctx.Err() != nil {
		signals.cancelled = true
	}
	select {
	case <-timer.C:
		signals.timedOut = true
	default:
	}
}

func captureProcessGroup(pid int) (int, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid child pid")
	}
	processGroupID, err := syscall.Getpgid(pid)
	if err != nil {
		return 0, fmt.Errorf("resolve child process group: %w", err)
	}
	if processGroupID != pid {
		return 0, fmt.Errorf("child did not receive dedicated process group %d", processGroupID)
	}
	if processGroupID == syscall.Getpgrp() {
		return 0, fmt.Errorf("child has unsafe process group %d", processGroupID)
	}
	return processGroupID, nil
}

func cleanupStartedChild(
	child *exec.Cmd,
	processGroupID int,
	stdinWriter io.WriteCloser,
	outputWriters ...*os.File,
) error {
	closeErrors := make([]error, 0, len(outputWriters)+1)
	closeErrors = append(closeErrors, stdinWriter.Close())
	for _, writer := range outputWriters {
		closeErrors = append(closeErrors, writer.Close())
	}
	return errors.Join(
		errors.Join(closeErrors...),
		killProcessGroup(processGroupID),
		child.Wait(),
	)
}

// killProcessGroup addresses the PGID captured immediately after Start. It
// deliberately never consults a leader PID, because that leader may already
// have exited while descendants retain inherited descriptors.
func killProcessGroup(processGroupID int) error {
	if processGroupID <= 0 {
		return fmt.Errorf("process runner: invalid child process group")
	}
	if processGroupID == syscall.Getpgrp() {
		return fmt.Errorf("process runner: child has unsafe process group %d", processGroupID)
	}

	if err := signalProcessGroup(processGroupID, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if errors.Is(err, syscall.EPERM) {
			if verifyErr := verifyProcessGroupZombieOnly(processGroupID); verifyErr == nil {
				return nil
			} else {
				return fmt.Errorf(
					"process runner: kill child process group: EPERM without zombie-only proof: %w",
					errors.Join(err, verifyErr),
				)
			}
		}
		return fmt.Errorf("process runner: kill child process group: %w", err)
	}
	if err := verifyProcessGroupTerminated(processGroupID); err != nil {
		return err
	}
	return nil
}
func verifyProcessGroupZombieOnly(processGroupID int) error {
	deadline := time.Now().Add(processGroupTeardownTimeout)
	observedMember := false
	for {
		membership, err := probeProcessGroup(processGroupID)
		if err != nil {
			return fmt.Errorf("probe child process group after EPERM: %w", err)
		}
		if membership.zombieOnly() {
			return nil
		}
		if membership.liveMembers > 0 || membership.zombieMembers > 0 {
			observedMember = true
		}
		if membership.absent() {
			if observedMember {
				return nil
			}
			return fmt.Errorf("child process group was never observed after EPERM")
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"child process group %d remains live after EPERM (%d live, %d zombie)",
				processGroupID,
				membership.liveMembers,
				membership.zombieMembers,
			)
		}
		time.Sleep(processGroupProbeInterval)
	}
}

func verifyProcessGroupTerminated(processGroupID int) error {
	deadline := time.Now().Add(processGroupTeardownTimeout)
	for {
		membership, err := probeProcessGroup(processGroupID)
		if err != nil {
			return fmt.Errorf("process runner: probe child process group after SIGKILL: %w", err)
		}
		if membership.absent() || membership.zombieOnly() {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"process runner: child process group %d remains live after SIGKILL (%d live, %d zombie)",
				processGroupID,
				membership.liveMembers,
				membership.zombieMembers,
			)
		}
		time.Sleep(processGroupProbeInterval)
	}
}

// probeDarwinProcessGroup inspects every kernel-reported member of the
// captured group. It records the direct leader separately while retaining
// membership facts for every process in the group.
func probeDarwinProcessGroup(processGroupID int) (processGroupMembership, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", processGroupID)
	if err != nil {
		return processGroupMembership{}, err
	}
	membership := processGroupMembership{}
	for _, process := range processes {
		if int(process.Eproc.Pgid) != processGroupID {
			continue
		}

		isLeader := int(process.Proc.P_pid) == processGroupID
		if process.Proc.P_stat == darwinProcessStateZombie {
			membership.zombieMembers++
			if isLeader {
				membership.leaderZombie = true
			}
			continue
		}

		membership.liveMembers++
		if isLeader {
			membership.leaderLive = true
		}
	}
	return membership, nil
}

func normalWaitError(waitErr error) error {
	if waitErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return nil
	}
	return fmt.Errorf("process runner: wait for child: %w", waitErr)
}

func processExitStatus(state *os.ProcessState) (*int, *ports.ProcessSignal, error) {
	if state == nil {
		return nil, nil, fmt.Errorf("process runner: missing child process state")
	}
	if exitCode := state.ExitCode(); exitCode >= 0 {
		return &exitCode, nil, nil
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return nil, nil, fmt.Errorf("process runner: child ended without an exit status")
	}
	signal, err := ports.NewProcessSignal(int(status.Signal()), unix.SignalName(status.Signal()))
	if err != nil {
		return nil, nil, fmt.Errorf("process runner: record child signal: %w", err)
	}
	return nil, &signal, nil
}
