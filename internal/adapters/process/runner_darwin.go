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
	"strings"
	"syscall"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

const (
	// processGroupTeardownTimeout is the entire terminal-sequence budget,
	// measured once when terminal handling begins.
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

	binding, providerRequest := request.ProviderPacketBinding()
	stdin := request.Stdin()
	needsStdinPipe := !providerRequest || binding.Channel() == ports.ProviderPacketChannelStdin
	expectedStdinSHA256 := stdinWriteSHA256(stdin)
	initialReceipt, err := stdinReceipt(stdin, 0)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, nil, err)
	}
	var preStartIdentity ports.ProviderPacketIdentity
	if providerRequest && binding.Channel() == ports.ProviderPacketChannelPromptFile {
		preStartIdentity, err = promptFileIdentity(binding)
		if err != nil {
			return processExecutionFailure(domain.DiagnosticCauseTransportVerificationFailed, "", nil, nil,
				fmt.Errorf("process runner: verify prompt file before start: %w", err))
		}
	}
	startedAt, err := runner.timestamp()
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, nil, err)
	}
	timer := time.NewTimer(request.Timeout())
	defer timer.Stop()
	if ctx.Err() != nil {
		return runner.observation(nil, nil, nil, contextProcessTermination(ctx), initialReceipt, startedAt)
	}

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
			fmt.Errorf("process runner: create stdout pipe: %w", err))
	}
	defer stdoutReader.Close()

	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutWriter.Close()
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
			fmt.Errorf("process runner: create stderr pipe: %w", err))
	}
	defer stderrReader.Close()

	argv := request.Argv()
	environment := explicitEnvironment(request.Environment())
	child := &exec.Cmd{
		Env:         environment,
		Stdout:      stdoutWriter,
		Stderr:      stderrWriter,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	var launchDirectory *os.File
	if boundDirectory, root, bound := request.BoundLaunchDirectory(); bound {
		defer boundDirectory.Close()
		if root.Path() != request.WorkingDirectory() {
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			return processExecutionFailure(domain.DiagnosticCauseWorkspaceRevalidationFailed, "", nil, nil,
				fmt.Errorf("process runner: bound directory does not match diagnostic working directory"))
		}
		duplicate, err := unix.Dup(int(boundDirectory.Fd()))
		if err != nil {
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
				fmt.Errorf("process runner: duplicate bound launch directory: %w", err))
		}
		launchDirectory = os.NewFile(uintptr(duplicate), root.Path())
		karExecutable, err := os.Executable()
		if err != nil {
			_ = launchDirectory.Close()
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
				fmt.Errorf("process runner: resolve trusted KAR executable: %w", err))
		}
		karExecutable, err = filepath.Abs(karExecutable)
		if err != nil {
			_ = launchDirectory.Close()
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
				fmt.Errorf("process runner: canonicalize trusted KAR executable: %w", err))
		}
		if authority, protected := request.NativeHomeLaunchAuthority(); protected {
			child.Path = karExecutable
			child.Args = append([]string{
				karExecutable,
				fdExecNativeHomeHiddenArgument,
				strconv.Itoa(3),
				request.Executable(),
				authority.Path(),
				strconv.FormatUint(authority.Device(), 10),
				strconv.FormatUint(authority.Inode(), 10),
				strconv.FormatUint(uint64(authority.EffectiveUID()), 10),
			}, argv[1:]...)
			child.ExtraFiles = []*os.File{launchDirectory}
		} else {
			child.Path = karExecutable
			child.Args = append([]string{karExecutable, fdExecHiddenArgument, strconv.Itoa(3), request.Executable()}, argv[1:]...)
			child.ExtraFiles = []*os.File{launchDirectory}
		}
	} else {
		child.Path = request.Executable()
		child.Args = argv
		child.Dir = request.WorkingDirectory()
	}
	var stdinWriter io.WriteCloser
	if needsStdinPipe {
		stdinWriter, err = child.StdinPipe()
		if err != nil {
			if launchDirectory != nil {
				_ = launchDirectory.Close()
			}
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
				fmt.Errorf("process runner: create stdin pipe: %w", err))
		}
	}
	if ctx.Err() != nil {
		_ = closeStdin(stdinWriter)
		if launchDirectory != nil {
			_ = launchDirectory.Close()
		}
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return runner.observation(nil, nil, nil, contextProcessTermination(ctx), initialReceipt, startedAt)
	}
	if err := child.Start(); err != nil {
		_ = closeStdin(stdinWriter)
		if launchDirectory != nil {
			_ = launchDirectory.Close()
		}
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return runner.observation(nil, nil, nil, classifyStartFailure(request, err), initialReceipt, startedAt)
	}
	if launchDirectory != nil {
		if err := launchDirectory.Close(); err != nil {
			cleanupErr := cleanupStartedChild(child, child.Process.Pid, stdinWriter, stdoutWriter, stderrWriter)
			cleanupCause := domain.RuntimeDiagnosticCause("")
			if cleanupErr != nil {
				cleanupCause = domain.DiagnosticCauseProcessGroupCleanupFailed
			}
			return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, cleanupCause, nil, nil,
				fmt.Errorf("process runner: close bound launch directory: %w", errors.Join(err, cleanupErr)))
		}
	}

	processGroupID, err := captureProcessGroup(child.Process.Pid)
	if err != nil {
		cleanupErr := cleanupStartedChild(child, child.Process.Pid, stdinWriter, stdoutWriter, stderrWriter)
		cleanupCause := domain.RuntimeDiagnosticCause("")
		if cleanupErr != nil {
			cleanupCause = domain.DiagnosticCauseProcessGroupCleanupFailed
		}
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, cleanupCause, nil, nil,
			fmt.Errorf("process runner: capture child process group: %w", errors.Join(err, cleanupErr)))
	}
	if err := errors.Join(stdoutWriter.Close(), stderrWriter.Close()); err != nil {
		cleanupErr := cleanupStartedChild(child, processGroupID, stdinWriter)
		cleanupCause := domain.RuntimeDiagnosticCause("")
		if cleanupErr != nil {
			cleanupCause = domain.DiagnosticCauseProcessGroupCleanupFailed
		}
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, cleanupCause, nil, nil,
			fmt.Errorf("process runner: close parent output pipes: %w", errors.Join(err, cleanupErr)))
	}
	if lifecycle, ok := request.PostOutputLifecycle(); ok {
		return runner.runBoundedPostOutput(
			ctx, timer, request, child, processGroupID, stdoutReader, stderrReader, stdinWriter,
			stdin, initialReceipt, expectedStdinSHA256, binding, providerRequest,
			preStartIdentity, lifecycle, startedAt,
		)
	}

	stdout := cappedCapture{limit: request.MaxStdoutBytes()}
	stderr := cappedCapture{limit: request.MaxStderrBytes()}
	streamResults := make(chan streamResult, 2)
	go copyStream(stdoutStream, stdoutReader, &stdout, streamResults)
	go copyStream(stderrStream, stderrReader, &stderr, streamResults)

	stdinResults := make(chan stdinResult, 1)
	if needsStdinPipe {
		go copyStdin(stdinWriter, stdin, stdinResults)
	}

	waitResult := make(chan error, 1)

	processGroupTicker := time.NewTicker(processGroupProbeInterval)
	defer processGroupTicker.Stop()

	var (
		waitStarted        bool
		waited             bool
		waitErr            error
		streamsRead        int
		stdinWritten       = !needsStdinPipe
		stdinReceipt       = initialReceipt
		groupDispositioned bool
		tearingDown        bool
		teardownErr        error
		teardownDeadline   time.Time
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
			teardownDeadline = time.Now().Add(processGroupTeardownTimeout)
			switch err := signalProcessGroup(processGroupID, syscall.SIGKILL); {
			case err == nil, errors.Is(err, syscall.ESRCH):
				groupDispositioned = true
			case errors.Is(err, syscall.EPERM):
				// Darwin can report EPERM after the group has crossed into an
				// exiting state. Reap the direct child and require bounded
				// absence verification before accepting that race.
				groupDispositioned = true
			default:
				teardownErr = fmt.Errorf("process runner: kill child process group: %w", err)
			}
			_ = closeStdin(stdinWriter)
			teardownTimer = time.NewTimer(max(0, time.Until(teardownDeadline)))
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
				closeErr := errors.Join(closeStdin(stdinWriter), stdoutReader.Close(), stderrReader.Close())
				return processExecutionFailure(
					domain.DiagnosticCauseProviderProcessWaitFailed,
					domain.DiagnosticCauseProcessGroupCleanupFailed,
					stdout.bytes,
					stderr.bytes,
					fmt.Errorf(
						"process runner: bounded group teardown did not complete: %w",
						errors.Join(teardownErr, closeErr),
					),
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
			signals.recordContext(ctx)
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
	if tearingDown {
		if err := verifyProcessGroupAbsent(processGroupID, teardownDeadline); err != nil {
			return processExecutionFailure(domain.DiagnosticCauseProcessGroupCleanupFailed, "", stdout.bytes, stderr.bytes, err)
		}
	} else if err := verifyProcessGroupAbsentAfterNaturalCompletion(processGroupID); err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProcessGroupCleanupFailed, "", stdout.bytes, stderr.bytes, err)
	}

	if teardownErr != nil {
		return processExecutionFailure(domain.DiagnosticCauseProcessGroupCleanupFailed, "", stdout.bytes, stderr.bytes, teardownErr)
	}
	if signals.internal != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderProcessWaitFailed, "", stdout.bytes, stderr.bytes, signals.internal)
	}
	if termination := signals.termination(); termination != "" {
		transportReceipt, err := providerTransportReceipt(binding, providerRequest, preStartIdentity)
		if err != nil {
			return processExecutionFailure(domain.DiagnosticCauseTransportVerificationFailed, "", stdout.bytes, stderr.bytes, err)
		}
		return runner.observationWithTransport(stdout.bytes, stderr.bytes, nil, termination, stdinReceipt, transportReceipt, startedAt)
	}
	if err := normalWaitError(waitErr); err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderProcessWaitFailed, "", stdout.bytes, stderr.bytes, err)
	}
	exitCode, signal, err := processExitStatus(child.ProcessState)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderProcessWaitFailed, "", stdout.bytes, stderr.bytes, err)
	}
	transportReceipt, err := providerTransportReceipt(binding, providerRequest, preStartIdentity)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseTransportVerificationFailed, "", stdout.bytes, stderr.bytes, err)
	}
	if signal != nil {
		return runner.signaledObservation(stdout.bytes, stderr.bytes, *signal, stdinReceipt, transportReceipt, startedAt)
	}
	return runner.observationWithTransport(stdout.bytes, stderr.bytes, exitCode, ports.ProcessTerminationExited, stdinReceipt, transportReceipt, startedAt)
}
func (runner *Runner) signaledObservation(
	stdout []byte,
	stderr []byte,
	signal ports.ProcessSignal,
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
			nil,
			ports.ProcessTerminationSignaled,
			stdinWriteReceipt,
			*transportReceipt,
			startedAt,
			endedAt,
			signal,
		)
	} else {
		observation, err = ports.NewProcessObservation(
			stdout,
			stderr,
			nil,
			ports.ProcessTerminationSignaled,
			stdinWriteReceipt,
			startedAt,
			endedAt,
			signal,
		)
	}
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout, stderr,
			fmt.Errorf("process runner: construct signaled observation: %w", err))
	}
	return observation, nil
}

type outputChunk struct {
	stream streamKind
	bytes  []byte
	err    error
}

func readOutputChunks(stream streamKind, reader *os.File, output chan<- outputChunk, cancelled <-chan struct{}, complete chan<- struct{}) {
	defer func() {
		_ = reader.Close()
		complete <- struct{}{}
	}()
	buffer := make([]byte, 32768)
	send := func(chunk outputChunk) bool {
		select {
		case <-cancelled:
			return false
		default:
		}
		select {
		case <-cancelled:
			return false
		case output <- chunk:
			return true
		}
	}
	for {
		count, err := reader.Read(buffer)
		if count > 0 && !send(outputChunk{stream: stream, bytes: append([]byte(nil), buffer[:count]...)}) {
			return
		}
		if err != nil {
			select {
			case <-cancelled:
				return
			default:
			}
			if errors.Is(err, io.EOF) {
				send(outputChunk{stream: stream})
			} else {
				send(outputChunk{stream: stream, err: err})
			}
			return
		}
	}
}

func processSignalName(signal syscall.Signal) string {
	switch signal {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	default:
		return fmt.Sprintf("SIG%d", signal)
	}
}
func (runner *Runner) runBoundedPostOutput(ctx context.Context, outer *time.Timer, request ports.ProcessRequest, child *exec.Cmd, pgid int, out, errOut *os.File, in io.WriteCloser, stdin []byte, initial ports.StdinWriteReceipt, expected string, binding ports.ProviderPacketBinding, provider bool, pre ports.ProviderPacketIdentity, lifecycle ports.BoundedPostOutputLifecycle, started time.Time) (ports.ProcessObservation, error) {
	stdout, stderr := cappedCapture{limit: request.MaxStdoutBytes()}, cappedCapture{limit: request.MaxStderrBytes()}
	chunks := make(chan outputChunk, 8)
	producerCancelled := make(chan struct{})
	producerComplete := make(chan struct{}, 2)
	go readOutputChunks(stdoutStream, out, chunks, producerCancelled, producerComplete)
	go readOutputChunks(stderrStream, errOut, chunks, producerCancelled, producerComplete)
	stdinResults := make(chan stdinResult, 1)
	needsStdin := !provider || binding.Channel() == ports.ProviderPacketChannelStdin
	stdinDone, outDone, errDone, waited := !needsStdin, false, false, false
	receipt := initial
	if needsStdin {
		go copyStdin(in, stdin, stdinResults)
	}
	waitResults := make(chan error, 1)
	go func() { waitResults <- child.Wait() }()
	var signals terminationSignals
	var requests []ports.ProcessGroupSignalRequestReceipt
	var frame ports.ProcessOutputFrameReceipt
	hasFrame, termSent, escalated, groupAbsent := false, false, false, false
	var waitErr, cleanupErr error
	var stable, termination, terminal *time.Timer
	var stableC, terminationC, terminalC <-chan time.Time
	var terminalDeadline time.Time
	beginTerminal := func() {
		if !terminalDeadline.IsZero() {
			return
		}
		terminalDeadline = time.Now().Add(processGroupTeardownTimeout)
		terminal = time.NewTimer(max(0, time.Until(terminalDeadline)))
		terminalC = terminal.C
	}
	remainingTerminalBudget := func() time.Duration {
		if terminalDeadline.IsZero() {
			panic("process runner: terminal deadline is not initialized")
		}
		return max(0, time.Until(terminalDeadline))
	}
	producersClosed, producersJoined := false, 0
	closeOwnedStreams := func() {
		if producersClosed {
			return
		}
		producersClosed = true
		close(producerCancelled)
		_ = out.Close()
		_ = errOut.Close()
		_ = closeStdin(in)
	}
	defer func() {
		if stable != nil {
			stable.Stop()
		}
		if termination != nil {
			termination.Stop()
		}
		if terminal != nil {
			terminal.Stop()
		}
		closeOwnedStreams()
	}()
	send := func(reason ports.ProcessGroupSignalRequestReason, signal syscall.Signal, post bool) error {
		if groupAbsent {
			return nil
		}
		err := signalProcessGroup(pgid, signal)
		if errors.Is(err, syscall.ESRCH) {
			groupAbsent = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("process runner: signal process group: %w", err)
		}
		fact, err := ports.NewProcessSignal(int(signal), processSignalName(signal))
		if err != nil {
			return err
		}
		var item ports.ProcessGroupSignalRequestReceipt
		if post {
			if reason == ports.ProcessGroupSignalRequestPostOutputEscalation {
				item, err = ports.NewAcceptedPostOutputEscalationProcessGroupSignalRequestReceipt(fact, binding.PacketIdentity(), frame)
			} else {
				item, err = ports.NewAcceptedPostOutputProcessGroupSignalRequestReceipt(fact, binding.PacketIdentity(), frame)
			}
		} else {
			item, err = ports.NewAcceptedProcessGroupSignalRequestReceipt(reason, fact)
		}
		if err == nil {
			requests = append(requests, item)
		}
		return err
	}
	for !(outDone && errDone && stdinDone && waited && producersJoined == 2) {
		if ctx.Err() != nil {
			signals.recordContext(ctx)
		}
		select {
		case <-outer.C:
			signals.timedOut = true
		default:
		}
		if stdinDone && receipt.Valid() && (!receipt.Complete() || receipt.SHA256() != expected) {
			signals.stdinIncomplete = true
		}
		if (signals.termination() != "" || signals.internal != nil) && !termSent {
			beginTerminal()
			if err := send(ports.ProcessGroupSignalRequestInternalTeardown, syscall.SIGKILL, false); err != nil {
				cleanupErr = errors.Join(cleanupErr, err)
				if signals.internal == nil {
					signals.internal = err
				}
			} else {
				escalated = true
			}
			termSent = true
			closeOwnedStreams()
		}
		select {
		case chunk := <-chunks:
			if chunk.err != nil {
				if signals.internal == nil {
					signals.internal = fmt.Errorf("process runner: capture stream: %w", chunk.err)
				}
				continue
			}
			if chunk.bytes == nil {
				if chunk.stream == stdoutStream {
					outDone = true
				} else {
					errDone = true
				}
				continue
			}
			capture := &stdout
			if chunk.stream == stderrStream {
				capture = &stderr
			}
			if _, err := capture.Write(chunk.bytes); err != nil {
				if chunk.stream == stdoutStream {
					signals.stdoutFull = true
				} else {
					signals.stderrFull = true
				}
				continue
			}
			if chunk.stream == stdoutStream && !termSent {
				hasFrame = false
				if stable != nil {
					stable.Stop()
				}
				stableC = nil
				if candidate, err := ports.NewProcessOutputFrameReceipt(lifecycle.Framing(), stdout.bytes, lifecycle.StabilityGrace()); err == nil {
					frame, hasFrame = candidate, true
					stable = time.NewTimer(lifecycle.StabilityGrace())
					stableC = stable.C
				}
			}
		case result := <-stdinResults:
			stdinDone, receipt = true, result.receipt
			signals.recordStdin(result)
		case waitErr = <-waitResults:
			waited = true
		case <-producerComplete:
			producersJoined++
		case <-stableC:
			stableC = nil
			if hasFrame && signals.termination() == "" && !termSent {
				before := len(requests)
				beginTerminal()
				if err := send(ports.ProcessGroupSignalRequestPostOutput, syscall.SIGTERM, true); err != nil {
					if signals.internal == nil {
						signals.internal = err
					}
				}
				termSent = true
				_ = closeStdin(in)
				if len(requests) > before {
					termination = time.NewTimer(min(lifecycle.TerminationGrace(), remainingTerminalBudget()))
					terminationC = termination.C
				}
			}
		case <-terminationC:
			terminationC = nil
			members, err := probeProcessGroup(pgid)
			if err != nil {
				if signals.internal == nil {
					signals.internal = fmt.Errorf("process runner: probe process group: %w", err)
				}
				continue
			}
			if members.absent() {
				groupAbsent = true
				closeOwnedStreams()
			} else {
				if err := send(ports.ProcessGroupSignalRequestPostOutputEscalation, syscall.SIGKILL, true); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
					if signals.internal == nil {
						signals.internal = err
					}
				} else {
					escalated = true
				}
				closeOwnedStreams()
			}
		case <-terminalC:
			terminalC = nil
			if termSent && !escalated && !groupAbsent {
				if err := send(ports.ProcessGroupSignalRequestPostOutputEscalation, syscall.SIGKILL, true); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
					if signals.internal == nil {
						signals.internal = err
					}
				} else {
					escalated = true
				}
			}
			closeOwnedStreams()
			if !stdinDone {
				select {
				case result := <-stdinResults:
					stdinDone, receipt = true, result.receipt
					signals.recordStdin(result)
				default:
				}
			}
			if !waited || producersJoined != 2 || !stdinDone {
				return processExecutionFailure(
					domain.DiagnosticCauseProviderProcessWaitFailed,
					domain.DiagnosticCauseProcessGroupCleanupFailed,
					stdout.bytes,
					stderr.bytes,
					errors.Join(
						signals.internal,
						cleanupErr,
						errors.New("process runner: terminal cleanup did not complete before terminal deadline"),
					),
				)
			}
			outDone, errDone = true, true
		case <-ctx.Done():
			signals.recordContext(ctx)
		case <-outer.C:
			signals.timedOut = true
		}
	}
	var absenceErr error
	if terminalDeadline.IsZero() {
		absenceErr = verifyProcessGroupAbsentAfterNaturalCompletion(pgid)
	} else if !groupAbsent {
		absenceErr = verifyProcessGroupAbsent(pgid, terminalDeadline)
	}
	if signals.internal != nil || cleanupErr != nil || absenceErr != nil {
		primary := domain.DiagnosticCauseProviderProcessWaitFailed
		cleanup := domain.RuntimeDiagnosticCause("")
		if signals.internal == nil {
			primary = domain.DiagnosticCauseProcessGroupCleanupFailed
		} else if cleanupErr != nil || absenceErr != nil {
			cleanup = domain.DiagnosticCauseProcessGroupCleanupFailed
		}
		return processExecutionFailure(primary, cleanup, stdout.bytes, stderr.bytes, errors.Join(signals.internal, cleanupErr, absenceErr))
	}
	if err := normalWaitError(waitErr); err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderProcessWaitFailed, "", stdout.bytes, stderr.bytes, err)
	}
	exit, signal, err := processExitStatus(child.ProcessState)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseProviderProcessWaitFailed, "", stdout.bytes, stderr.bytes, err)
	}
	var final ports.ProcessFinalTermination
	if signal != nil {
		final, err = ports.NewSignaledProcessFinalTermination(*signal)
	} else {
		final, err = ports.NewExitedProcessFinalTermination(*exit)
	}
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout.bytes, stderr.bytes, err)
	}
	disposition := signals.termination()
	if disposition == "" {
		if escalated {
			disposition = ports.ProcessTerminationSignaled
		} else if signal != nil {
			disposition = ports.ProcessTerminationSignaled
		} else {
			disposition = ports.ProcessTerminationExited
		}
	}
	transport, err := providerTransportReceipt(binding, provider, pre)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseTransportVerificationFailed, "", stdout.bytes, stderr.bytes, err)
	}
	frames := []ports.ProcessOutputFrameReceipt(nil)
	if hasFrame {
		frames = append(frames, frame)
	}
	lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(final, true, requests, frames...)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", stdout.bytes, stderr.bytes, err)
	}
	return runner.observationWithLifecycleTransport(
		stdout.bytes, stderr.bytes, disposition, receipt, *transport, lifecycleReceipt, started,
	)
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
func providerTransportReceipt(
	binding ports.ProviderPacketBinding,
	providerRequest bool,
	preStartIdentity ports.ProviderPacketIdentity,
) (*ports.ProviderPacketTransportReceipt, error) {
	if !providerRequest {
		return nil, nil
	}

	packetIdentity := binding.PacketIdentity()
	var (
		receipt ports.ProviderPacketTransportReceipt
		err     error
	)
	switch binding.Channel() {
	case ports.ProviderPacketChannelArgvLiteral, ports.ProviderPacketChannelStdin:
		receipt, err = ports.NewProviderPacketTransportReceipt(
			binding.Channel(), packetIdentity, "", "", ports.ProviderPacketIdentity{}, ports.ProviderPacketIdentity{},
		)
	case ports.ProviderPacketChannelPromptFile:
		postTerminationIdentity, identityErr := promptFileIdentity(binding)
		if identityErr != nil {
			return nil, fmt.Errorf("process runner: verify prompt file after termination: %w", identityErr)
		}
		receipt, err = ports.NewProviderPacketTransportReceipt(
			binding.Channel(),
			packetIdentity,
			binding.PromptFileReference(),
			binding.SnapshotCWD(),
			preStartIdentity,
			postTerminationIdentity,
		)
	default:
		return nil, fmt.Errorf("process runner: unsupported provider packet channel")
	}
	if err != nil {
		return nil, fmt.Errorf("process runner: construct provider transport receipt: %w", err)
	}
	return &receipt, nil
}

func promptFileIdentity(binding ports.ProviderPacketBinding) (ports.ProviderPacketIdentity, error) {
	reference := binding.PromptFileReference()
	path := strings.TrimPrefix(reference, "@")
	if reference == path || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || path == ".." ||
		strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return ports.ProviderPacketIdentity{}, errors.New("invalid prompt file reference")
	}

	directoryFD, err := unix.Open(binding.SnapshotCWD(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ProviderPacketIdentity{}, fmt.Errorf("open snapshot working directory: %w", err)
	}
	defer func() {
		_ = unix.Close(directoryFD)
	}()

	parts := strings.Split(path, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		nextDirectoryFD, openErr := unix.Openat(directoryFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return ports.ProviderPacketIdentity{}, fmt.Errorf("open prompt file directory: %w", openErr)
		}
		_ = unix.Close(directoryFD)
		directoryFD = nextDirectoryFD
	}

	fileFD, err := unix.Openat(directoryFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ports.ProviderPacketIdentity{}, fmt.Errorf("open prompt file: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), "prompt-file")
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return ports.ProviderPacketIdentity{}, fmt.Errorf("stat prompt file: %w", err)
	}
	expected := binding.PacketIdentity()
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ports.ProviderPacketIdentity{}, errors.New("prompt file is not regular")
	}
	if stat.Size != int64(expected.ByteLength()) {
		return ports.ProviderPacketIdentity{}, errors.New("prompt file size does not match packet identity")
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte("KAR-PROVIDER-STDIN/1"))
	_, _ = hash.Write([]byte{0})
	written, err := io.CopyN(hash, file, stat.Size)
	if err != nil {
		return ports.ProviderPacketIdentity{}, fmt.Errorf("read prompt file: %w", err)
	}
	if written != stat.Size {
		return ports.ProviderPacketIdentity{}, errors.New("prompt file size changed while reading")
	}
	var extra [1]byte
	extraBytes, readErr := file.Read(extra[:])
	if extraBytes != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return ports.ProviderPacketIdentity{}, errors.New("prompt file exceeds packet identity")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.CompleteSHA256() {
		return ports.ProviderPacketIdentity{}, errors.New("prompt file digest does not match packet identity")
	}
	return expected, nil
}

func closeStdin(writer io.WriteCloser) error {
	if writer == nil {
		return nil
	}
	return writer.Close()
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
		signals.recordContext(ctx)
	}
	select {
	case <-timer.C:
		signals.timedOut = true
	default:
	}
}

func (signals *terminationSignals) recordContext(ctx context.Context) {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		signals.timedOut = true
		return
	}
	if ctx != nil && ctx.Err() != nil {
		signals.cancelled = true
	}
}

func contextProcessTermination(ctx context.Context) ports.ProcessTermination {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ports.ProcessTerminationTimedOut
	}
	return ports.ProcessTerminationCancelled
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
	closeErrors = append(closeErrors, closeStdin(stdinWriter))
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
	return killProcessGroupBefore(processGroupID, time.Now().Add(processGroupTeardownTimeout))
}

func killProcessGroupBefore(processGroupID int, deadline time.Time) error {
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
			if verifyErr := verifyProcessGroupZombieOnlyBefore(processGroupID, deadline); verifyErr == nil {
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
	if err := verifyProcessGroupTerminatedBefore(processGroupID, deadline); err != nil {
		return err
	}
	return nil
}
func verifyProcessGroupZombieOnly(processGroupID int) error {
	return verifyProcessGroupZombieOnlyBefore(processGroupID, time.Now().Add(processGroupTeardownTimeout))
}

func verifyProcessGroupZombieOnlyBefore(processGroupID int, deadline time.Time) error {
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
	return verifyProcessGroupTerminatedBefore(processGroupID, time.Now().Add(processGroupTeardownTimeout))
}

func verifyProcessGroupTerminatedBefore(processGroupID int, deadline time.Time) error {
	for {
		membership, err := probeProcessGroup(processGroupID)
		if err != nil {
			return fmt.Errorf("process runner: probe child process group after SIGKILL: %w", err)
		}
		if membership.absent() {
			return nil
		}
		if membership.zombieOnly() {
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

func verifyProcessGroupAbsentAfterNaturalCompletion(processGroupID int) error {
	return verifyProcessGroupAbsent(processGroupID, time.Now().Add(processGroupTeardownTimeout))
}

func verifyProcessGroupAbsent(processGroupID int, deadline time.Time) error {
	if deadline.IsZero() {
		return errors.New("process runner: missing terminal deadline")
	}
	for {
		membership, err := probeProcessGroup(processGroupID)
		if err != nil {
			return fmt.Errorf("process runner: probe child process group after reap: %w", err)
		}
		if membership.absent() {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"process runner: child process group %d remains after reap (%d live, %d zombie)",
				processGroupID,
				membership.liveMembers,
				membership.zombieMembers,
			)
		}
		time.Sleep(min(processGroupProbeInterval, time.Until(deadline)))
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
