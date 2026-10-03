//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	// conversationNaturalExitGrace is the window after stdin closes in which
	// a child that ends on its own is classified from its natural exit
	// instead of the teardown signal.
	conversationNaturalExitGrace = 150 * time.Millisecond
	// conversationTeardownGrace is the graceful SIGTERM window inside the
	// process-group teardown budget before a conversation escalates to SIGKILL.
	conversationTeardownGrace = 300 * time.Millisecond
	// conversationLineBufferSize bounds buffered complete stdout lines between
	// the stdout feed and the session driver.
	conversationLineBufferSize = 64
)

// Converse executes one conversation-mode provider process request. The child
// is launched exactly like a direct run, including the fd-exec trampoline for
// descriptor-bound requests, and owns a dedicated process group. The session
// driver conducts a line-oriented protocol exchange over the child stdin and
// stdout pipes while every stdout byte is tee-spooled into a file-backed
// transcript artifact. The request timeout bounds the complete conversation;
// once the driver returns, the context ends, or the timeout fires, the runner
// closes the exchange, terminates the process group within its bounded
// teardown budget, and classifies the termination.
//
// The returned error is the driver's own error whenever one is reported, even
// when the process evidence is coherent; the observation then records the
// classified teardown of a failed conversation. A nil driver error with a
// successfully terminal observation records a conversation whose driver
// reached its own terminal completion.
func (runner *Runner) Converse(ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) (ports.ProcessObservation, error) {
	if ctx == nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: nil context")
	}
	if runner == nil || nilClock(runner.clock) {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: nil clock")
	}
	if !request.Valid() {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: invalid process request")
	}
	if boundDirectory, _, bound := request.LaunchDirectory(); bound {
		defer boundDirectory.Close()
	}
	binding, providerRequest := request.ProviderPacketBinding()
	if !providerRequest || binding.Channel() != ports.ProviderPacketChannelProtocol {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: conversation requires a protocol packet binding")
	}
	if _, hasLifecycle := request.PostOutputLifecycle(); hasLifecycle {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: conversation does not support a post-output lifecycle")
	}
	if driver == nil {
		return ports.ProcessObservation{}, fmt.Errorf("process runner: nil session driver")
	}

	initialReceipt, err := stdinReceipt(nil, 0)
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, nil, err)
	}
	startedAt, err := runner.timestamp()
	if err != nil {
		return processExecutionFailure(domain.DiagnosticCauseObservationInvalid, "", nil, nil, err)
	}
	timer := time.NewTimer(request.Timeout())
	defer timer.Stop()

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

	child, launchDirectory, assembleCause, assembleErr := assembleDirectChild(ctx, request, stdoutWriter, stderrWriter)
	if assembleErr != nil {
		_ = launchDirectory.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		if errors.Is(assembleErr, context.Canceled) || errors.Is(assembleErr, context.DeadlineExceeded) {
			termination := ports.ProcessTerminationTimedOut
			if errors.Is(assembleErr, context.Canceled) {
				termination = ports.ProcessTerminationCancelled
			}
			return runner.observation(nil, nil, nil, termination, initialReceipt, startedAt)
		}
		return processExecutionFailure(assembleCause, "", nil, nil, assembleErr)
	}
	stdinWriter, err := child.StdinPipe()
	if err != nil {
		_ = launchDirectory.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return processExecutionFailure(domain.DiagnosticCauseProviderSpawnFailed, "", nil, nil,
			fmt.Errorf("process runner: create stdin pipe: %w", err))
	}
	if ctx.Err() != nil {
		_ = closeStdin(stdinWriter)
		_ = launchDirectory.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
		return runner.observation(nil, nil, nil, contextProcessTermination(ctx), initialReceipt, startedAt)
	}
	if err := child.Start(); err != nil {
		_ = closeStdin(stdinWriter)
		_ = launchDirectory.Close()
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
		cleanupErr := cleanupStartedChild(child, child.Process.Pid, stdinWriter)
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

	spoolReader, spoolWriter := io.Pipe()
	spoolResults := make(chan contentSpoolResult, 1)
	go func() {
		spoolRequest, err := ports.NewContentSpoolRequest(spoolReader, "application/octet-stream")
		if err != nil {
			_ = spoolReader.CloseWithError(err)
			spoolResults <- contentSpoolResult{err: err}
			return
		}
		lease, err := runner.spooler.Spool(context.Background(), spoolRequest)
		closeErr := spoolReader.Close()
		spoolResults <- contentSpoolResult{artifact: lease, err: errors.Join(err, closeErr)}
	}()

	stderr := streamCapture{}
	stderrResults := make(chan streamResult, 1)
	go copyStream(stderrStream, stderrReader, &stderr, stderrResults)

	exchange := newConversationExchange(stdinWriter)
	stdoutResults := make(chan conversationStdoutResult, 1)
	sink := &conversationTranscriptSink{spoolWriter: spoolWriter, transcript: &streamCapture{}}
	go feedConversationStdout(stdoutReader, sink, exchange, stdoutResults)

	driverDone := make(chan error, 1)
	go func() { driverDone <- driver.Drive(ctx, exchange) }()

	var (
		signals          terminationSignals
		requests         []ports.ProcessGroupSignalRequestReceipt
		driverErr        error
		driverFinished   bool
		waitResult       = make(chan error, 1)
		waited           bool
		waitErr          error
		stdoutEnded      bool
		stderrDone       bool
		spoolDone        bool
		tearingDown      bool
		teardownErr      error
		naturalExitTimer *time.Timer
		escalationTimer  *time.Timer
		teardownDeadline time.Time
		escalated        bool
		groupAbsent      bool
		stdoutArtifact   ports.ContentArtifact
		artifactOwned    = true
		naturalExitC     <-chan time.Time
		escalationC      <-chan time.Time
	)
	defer func() {
		if naturalExitTimer != nil {
			naturalExitTimer.Stop()
		}
		if escalationTimer != nil {
			escalationTimer.Stop()
		}
		if artifactOwned {
			closeContentArtifact(stdoutArtifact)
		}
	}()
	beginTeardown := func() {
		if tearingDown {
			return
		}
		tearingDown = true
		exchange.close()
		_ = closeStdin(stdinWriter)
		teardownDeadline = time.Now().Add(processGroupTeardownTimeout)
		// The teardown budget bounds the stream waits themselves: a descendant
		// that outlives the child can keep the pipe write ends open past every
		// signal, and the read deadline is the only in-loop fact that unwinds
		// the blocked feeds. The deadline is best-effort: a feed that already
		// ended may have closed its reader, and the group teardown signals
		// remain the primary bounded cleanup.
		_ = stdoutReader.SetDeadline(teardownDeadline)
		_ = stderrReader.SetDeadline(teardownDeadline)
		go func() { waitResult <- child.Wait() }()
		naturalExitTimer = time.NewTimer(conversationNaturalExitGrace)
		naturalExitC = naturalExitTimer.C
	}
	sendTermination := func() {
		absent, err := appendConversationSignalReceipt(processGroupID, syscall.SIGTERM, ports.ProcessGroupSignalRequestConversationTeardown, &requests)
		if err != nil {
			teardownErr = errors.Join(teardownErr, err)
		}
		groupAbsent = absent
		escalationTimer = time.NewTimer(conversationTeardownGrace)
		escalationC = escalationTimer.C
	}

	for {
		if !tearingDown {
			snapshotTerminalFacts(ctx, timer, &signals)
			if signals.termination() != "" || signals.internal != nil {
				beginTeardown()
			}
		}
		if tearingDown && stdoutEnded && stderrDone && spoolDone && waited && driverFinished {
			break
		}
		if !tearingDown {
			select {
			case err := <-driverDone:
				driverFinished = true
				driverErr = err
				beginTeardown()
				continue
			case result := <-stdoutResults:
				stdoutEnded = true
				recordConversationStdoutEnd(result, &signals)
				continue
			case result := <-stderrResults:
				stderrDone = true
				signals.record(result)
				continue
			case spooled := <-spoolResults:
				spoolDone = true
				stdoutArtifact = spooled.artifact
				if spooled.err != nil && signals.internal == nil {
					signals.internal = fmt.Errorf("process runner: spool conversation stdout: %w", spooled.err)
				}
				continue
			case <-ctx.Done():
				signals.recordContext(ctx)
				continue
			case <-timer.C:
				signals.timedOut = true
				continue
			}
		}
		select {
		case err := <-driverDone:
			driverFinished = true
			driverErr = err
		case result := <-stdoutResults:
			stdoutEnded = true
			recordConversationStdoutEnd(result, &signals)
		case result := <-stderrResults:
			stderrDone = true
			signals.record(result)
		case spooled := <-spoolResults:
			spoolDone = true
			stdoutArtifact = spooled.artifact
			if spooled.err != nil && signals.internal == nil {
				signals.internal = fmt.Errorf("process runner: spool conversation stdout: %w", spooled.err)
			}
		case err := <-waitResult:
			waited = true
			waitErr = err
		case <-naturalExitC:
			// The direct child may have ended on its own while descendants
			// still hold the conversation pipes, so the remaining group is
			// torn down whether or not the child was already waited for. A
			// fully reaped group reports absence without a receipt.
			if !groupAbsent {
				sendTermination()
			}
		case <-escalationC:
			if !groupAbsent && !escalated {
				escalated = true
				absent, err := appendConversationSignalReceipt(processGroupID, syscall.SIGKILL, ports.ProcessGroupSignalRequestConversationTeardownEscalation, &requests)
				if err != nil {
					teardownErr = errors.Join(teardownErr, err)
				}
				groupAbsent = absent
			}
		case <-ctx.Done():
			signals.recordContext(ctx)
		case <-timer.C:
			signals.timedOut = true
		}
	}

	if _, _, incomplete := exchange.stdinSnapshot(); incomplete {
		signals.stdinIncomplete = true
	}
	if !groupAbsent {
		absenceDeadline := teardownDeadline
		if absenceDeadline.IsZero() {
			absenceDeadline = time.Now().Add(processGroupTeardownTimeout)
		}
		if err := verifyProcessGroupAbsent(processGroupID, absenceDeadline); err != nil {
			teardownErr = errors.Join(teardownErr, err)
		}
	}
	if teardownErr != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseProcessGroupCleanupFailed, "",
			sink.transcript.bytes, stderr.bytes, teardownErr,
		)
	}
	if signals.internal != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseProviderProcessWaitFailed, "",
			sink.transcript.bytes, stderr.bytes, signals.internal,
		)
	}
	if err := normalWaitError(waitErr); err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseProviderProcessWaitFailed, "",
			sink.transcript.bytes, stderr.bytes, err,
		)
	}
	exitCode, finalSignal, err := processExitStatus(child.ProcessState)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseProviderProcessWaitFailed, "",
			sink.transcript.bytes, stderr.bytes, err,
		)
	}
	var final ports.ProcessFinalTermination
	if finalSignal != nil {
		final, err = ports.NewSignaledProcessFinalTermination(*finalSignal)
	} else {
		final, err = ports.NewExitedProcessFinalTermination(*exitCode)
	}
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseObservationInvalid, "",
			sink.transcript.bytes, stderr.bytes, err,
		)
	}
	disposition := signals.termination()
	if disposition == "" {
		if finalSignal != nil {
			disposition = ports.ProcessTerminationSignaled
		} else {
			disposition = ports.ProcessTerminationExited
		}
	}
	transport, err := providerTransportReceipt(binding, true, ports.ProviderPacketIdentity{})
	if err != nil {
		return processExecutionFailure(providerTransportReceiptCause(binding), "",
			sink.transcript.bytes, stderr.bytes, err)
	}
	lifecycleReceipt, err := ports.NewProcessLifecycleReceipt(final, true, requests)
	if err != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseObservationInvalid, "",
			sink.transcript.bytes, stderr.bytes, err,
		)
	}
	stdinReceiptValue, receiptErr := exchange.stdinWriteReceipt()
	if receiptErr != nil {
		return processExecutionFailure(
			domain.DiagnosticCauseObservationInvalid, "",
			sink.transcript.bytes, stderr.bytes, receiptErr,
		)
	}
	observation, observationErr := runner.observationWithLifecycleTransport(
		sink.transcript.bytes, stderr.bytes, disposition, stdinReceiptValue, *transport, lifecycleReceipt, startedAt,
	)
	if observationErr != nil {
		return observation, observationErr
	}
	if stdoutArtifact != nil {
		bound, bindErr := bindProcessStdoutArtifact(observation, stdoutArtifact, false)
		if bindErr != nil {
			return bound, bindErr
		}
		artifactOwned = false
		return bound, driverErr
	}
	return observation, driverErr
}

func recordConversationStdoutEnd(result conversationStdoutResult, signals *terminationSignals) {
	if result.err == nil || errors.Is(result.err, io.EOF) || errors.Is(result.err, io.ErrUnexpectedEOF) {
		// A stream end, including a final partial line, is a protocol-level
		// fact surfaced to the driver through ReceiveLine; it does not by
		// itself fail the conversation.
		return
	}
	if signals.internal == nil {
		signals.internal = fmt.Errorf("process runner: capture conversation stdout: %w", result.err)
	}
}

// appendConversationSignalReceipt signals the conversation process group and
// records the accepted signal request. A group that already disappeared is
// reported as absent without a receipt. Darwin can report EPERM after the
// group has crossed into an exiting state; that race is not absence, so the
// caller still verifies bounded absence before accepting it.
func appendConversationSignalReceipt(processGroupID int, signal syscall.Signal, reason ports.ProcessGroupSignalRequestReason, requests *[]ports.ProcessGroupSignalRequestReceipt) (bool, error) {
	err := signalProcessGroup(processGroupID, signal)
	if errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("process runner: signal conversation process group: %w", err)
	}
	fact, err := ports.NewProcessSignal(int(signal), processSignalName(signal))
	if err != nil {
		return false, err
	}
	receipt, err := ports.NewAcceptedProcessGroupSignalRequestReceipt(reason, fact)
	if err != nil {
		return false, err
	}
	*requests = append(*requests, receipt)
	return false, nil
}

// conversationTranscriptSink tees every conversation stdout byte into the
// spool writer and the in-memory transcript. It is owned by the stdout feed
// goroutine and requires no locking.
type conversationTranscriptSink struct {
	spoolWriter *io.PipeWriter
	transcript  *streamCapture
}

func (sink *conversationTranscriptSink) write(chunk []byte) error {
	if sink.spoolWriter != nil {
		if _, err := sink.spoolWriter.Write(chunk); err != nil {
			return err
		}
	}
	_, _ = sink.transcript.Write(chunk)
	return nil
}

func (sink *conversationTranscriptSink) closeSpool() {
	if sink.spoolWriter != nil {
		_ = sink.spoolWriter.Close()
		sink.spoolWriter = nil
	}
}

type conversationStdoutResult struct {
	err error
}

// feedConversationStdout reads the child stdout until the stream ends,
// spooling every byte, and delivers each complete line without its newline to
// the exchange. After the conversation begins tearing down, lines are dropped
// while the feed keeps spooling until the stream ends.
func feedConversationStdout(reader *os.File, sink *conversationTranscriptSink, exchange *conversationExchange, results chan<- conversationStdoutResult) {
	defer func() {
		_ = reader.Close()
		sink.closeSpool()
	}()
	endErr := error(io.EOF)
	var pending []byte
	buffer := make([]byte, 32768)
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			if err := sink.write(buffer[:count]); err != nil {
				err = fmt.Errorf("process runner: spool conversation stdout: %w", err)
				exchange.recordStreamEnd(err)
				results <- conversationStdoutResult{err: err}
				return
			}
			pending = append(pending, buffer[:count]...)
			// Deliver defensive copies before shifting the remainder to the
			// front of the pending buffer.
			complete, remainder := splitConversationLines(pending)
			for index := range complete {
				select {
				case exchange.lines <- append([]byte(nil), complete[index]...):
				case <-exchange.closed:
				}
			}
			pending = append(pending[:0], remainder...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if len(pending) > 0 {
					endErr = fmt.Errorf("process runner: conversation stdout ended with a partial line: %w", io.ErrUnexpectedEOF)
				}
			} else {
				endErr = fmt.Errorf("process runner: read conversation stdout: %w", readErr)
			}
			break
		}
	}
	exchange.recordStreamEnd(endErr)
	results <- conversationStdoutResult{err: endErr}
}

// splitConversationLines returns every complete newline-terminated line in
// pending without its newline and the unterminated remainder.
func splitConversationLines(pending []byte) ([][]byte, []byte) {
	var lines [][]byte
	for {
		index := bytes.IndexByte(pending, '\n')
		if index < 0 {
			return lines, pending
		}
		lines = append(lines, pending[:index])
		pending = pending[index+1:]
	}
}

// conversationExchange implements ports.ProviderSessionExchange for one
// conversation. It is safe for the runner to close it while the driver is
// blocked in either operation.
type conversationExchange struct {
	lines  chan []byte
	closed chan struct{}
	stdin  io.Writer

	closeOnce sync.Once
	endMu     sync.Mutex
	endErr    error
	endRecord bool

	counterMu  sync.Mutex
	intended   int64
	written    int64
	incomplete bool
	digest     hash.Hash
}

func newConversationExchange(stdin io.Writer) *conversationExchange {
	digest := sha256.New()
	_, _ = digest.Write([]byte("Mulgae-PROVIDER-STDIN/1"))
	_, _ = digest.Write([]byte{0})
	return &conversationExchange{
		lines:  make(chan []byte, conversationLineBufferSize),
		closed: make(chan struct{}),
		stdin:  stdin,
		digest: digest,
	}
}

func (exchange *conversationExchange) close() {
	exchange.closeOnce.Do(func() { close(exchange.closed) })
}

// recordStreamEnd publishes the terminal stream error to ReceiveLine callers
// and closes line delivery. It is called once by the stdout feed.
func (exchange *conversationExchange) recordStreamEnd(err error) {
	exchange.endMu.Lock()
	exchange.endErr = err
	exchange.endRecord = true
	exchange.endMu.Unlock()
	close(exchange.lines)
}

func (exchange *conversationExchange) streamEnd() error {
	exchange.endMu.Lock()
	defer exchange.endMu.Unlock()
	return exchange.endErr
}

func (exchange *conversationExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("provider session exchange: nil context")
	}
	select {
	case <-exchange.closed:
		return nil, fmt.Errorf("provider session exchange: receive line: %w", ports.ErrProviderSessionExchangeClosed)
	default:
	}
	select {
	case <-exchange.closed:
		return nil, fmt.Errorf("provider session exchange: receive line: %w", ports.ErrProviderSessionExchangeClosed)
	case line, ok := <-exchange.lines:
		if !ok {
			err := exchange.streamEnd()
			if err == nil {
				err = io.EOF
			}
			return nil, err
		}
		return line, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("provider session exchange: receive line: %w", ctx.Err())
	}
}

func (exchange *conversationExchange) SendLine(ctx context.Context, line []byte) error {
	if ctx == nil {
		return fmt.Errorf("provider session exchange: nil context")
	}
	if bytes.IndexByte(line, '\n') >= 0 || bytes.IndexByte(line, 0) >= 0 {
		return fmt.Errorf("provider session exchange: line must not contain newline or NUL")
	}
	select {
	case <-exchange.closed:
		return fmt.Errorf("provider session exchange: send line: %w", ports.ErrProviderSessionExchangeClosed)
	case <-ctx.Done():
		return fmt.Errorf("provider session exchange: send line: %w", ctx.Err())
	default:
	}
	exchange.counterMu.Lock()
	defer exchange.counterMu.Unlock()
	if exchange.incomplete {
		return fmt.Errorf("provider session exchange: send line after incomplete write: %w", io.ErrClosedPipe)
	}
	frame := make([]byte, 0, len(line)+1)
	frame = append(frame, line...)
	frame = append(frame, '\n')
	written, err := exchange.stdin.Write(frame)
	exchange.intended += int64(len(frame))
	exchange.written += int64(written)
	if written > 0 {
		_, _ = exchange.digest.Write(frame[:written])
	}
	if err == nil && written != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		exchange.incomplete = true
		return fmt.Errorf("provider session exchange: send line: %w", err)
	}
	return nil
}

func (exchange *conversationExchange) stdinSnapshot() (int64, int64, bool) {
	exchange.counterMu.Lock()
	defer exchange.counterMu.Unlock()
	return exchange.intended, exchange.written, exchange.incomplete
}

func (exchange *conversationExchange) stdinWriteReceipt() (ports.StdinWriteReceipt, error) {
	exchange.counterMu.Lock()
	defer exchange.counterMu.Unlock()
	complete := !exchange.incomplete && exchange.written == exchange.intended
	return ports.NewStdinWriteReceipt(exchange.intended, exchange.written, hex.EncodeToString(exchange.digest.Sum(nil)), complete)
}
