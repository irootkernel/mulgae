//go:build darwin && arm64

package process

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestSplitConversationLinesReturnsCompleteLinesAndRemainder(t *testing.T) {
	for _, test := range []struct {
		name      string
		pending   string
		wantLines []string
		wantTail  string
	}{
		{name: "empty", pending: "", wantLines: nil, wantTail: ""},
		{name: "single complete", pending: "first\n", wantLines: []string{"first"}, wantTail: ""},
		{name: "partial only", pending: "partial", wantLines: nil, wantTail: "partial"},
		{name: "split across chunk boundary", pending: "first\nsecond\npartial", wantLines: []string{"first", "second"}, wantTail: "partial"},
		{name: "blank line is a line", pending: "\nlast\n", wantLines: []string{"", "last"}, wantTail: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines, remainder := splitConversationLines([]byte(test.pending))
			if len(lines) != len(test.wantLines) {
				t.Fatalf("lines = %q, want %q", lines, test.wantLines)
			}
			for index, line := range lines {
				if string(line) != test.wantLines[index] {
					t.Fatalf("lines = %q, want %q", lines, test.wantLines)
				}
			}
			if string(remainder) != test.wantTail {
				t.Fatalf("remainder = %q, want %q", remainder, test.wantTail)
			}
		})
	}
}

func newFedConversationExchange(t *testing.T, stdout string) (*conversationExchange, *conversationTranscriptSink, chan conversationStdoutResult, *os.File) {
	t.Helper()
	streamReader, streamWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = streamReader.Close() })
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdinReader.Close() })
	exchange := newConversationExchange(stdinWriter)
	sink := &conversationTranscriptSink{transcript: &streamCapture{}}
	results := make(chan conversationStdoutResult, 1)
	go feedConversationStdout(streamReader, sink, exchange, results)
	if stdout != "" {
		if _, err := streamWriter.Write([]byte(stdout)); err != nil {
			t.Fatal(err)
		}
	}
	if err := streamWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return exchange, sink, results, stdinReader
}

func TestConversationExchangeDeliversLinesAndStreamEnd(t *testing.T) {
	for _, test := range []struct {
		name      string
		stdout    string
		wantLines []string
		wantEnd   error
	}{
		{name: "complete lines end cleanly", stdout: "first\nsecond\n", wantLines: []string{"first", "second"}, wantEnd: io.EOF},
		{name: "empty stream ends cleanly", stdout: "", wantLines: nil, wantEnd: io.EOF},
		{name: "partial tail is unexpected end", stdout: "first\npartial", wantLines: []string{"first"}, wantEnd: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchange, sink, results, _ := newFedConversationExchange(t, test.stdout)
			for index, want := range test.wantLines {
				line, err := exchange.ReceiveLine(context.Background())
				if err != nil {
					t.Fatalf("ReceiveLine() %d = %v", index, err)
				}
				if string(line) != want {
					t.Fatalf("ReceiveLine() %d = %q, want %q", index, line, want)
				}
			}
			if _, err := exchange.ReceiveLine(context.Background()); !errors.Is(err, test.wantEnd) {
				t.Fatalf("terminal ReceiveLine() = %v, want %v", err, test.wantEnd)
			}
			result := <-results
			if !errors.Is(result.err, test.wantEnd) {
				t.Fatalf("feed result = %v, want %v", result.err, test.wantEnd)
			}
			if got := string(sink.transcript.bytes); got != test.stdout {
				t.Fatalf("transcript = %q, want %q", got, test.stdout)
			}
		})
	}
}

func TestConversationExchangeSendsValidatedFramesAndFailsClosed(t *testing.T) {
	exchange, _, results, stdinReader := newFedConversationExchange(t, "\n")
	t.Cleanup(func() { _ = stdinReader.Close() })
	ctx := context.Background()

	if _, err := exchange.ReceiveLine(ctx); err != nil {
		t.Fatalf("blank line receive = %v", err)
	}
	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		t.Fatal(err)
	}
	if err := exchange.SendLine(ctx, []byte("bad\nline")); err == nil {
		t.Fatal("SendLine() accepted an embedded newline")
	}
	if err := exchange.SendLine(ctx, []byte("bad\x00line")); err == nil {
		t.Fatal("SendLine() accepted a NUL byte")
	}

	exchange.close()
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("ReceiveLine() after close = %v, want exchange closure", err)
	}
	if err := exchange.SendLine(ctx, []byte(`{"id":2}`)); !errors.Is(err, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("SendLine() after close = %v, want exchange closure", err)
	}

	receipt, err := exchange.stdinWriteReceipt()
	if err != nil {
		t.Fatal(err)
	}
	frame := "{\"id\":1,\"method\":\"session/create\"}\n"
	if receipt.IntendedByteLength() != int64(len(frame)) || receipt.WrittenByteCount() != int64(len(frame)) ||
		!receipt.Complete() || receipt.SHA256() != runnerTestStdinDigest([]byte(frame)) {
		t.Fatalf("stdin receipt = %#v", receipt)
	}
	written := make([]byte, len(frame))
	if _, err := io.ReadFull(stdinReader, written); err != nil {
		t.Fatal(err)
	}
	if string(written) != frame {
		t.Fatalf("child stdin = %q, want %q", written, frame)
	}
	<-results
}

func TestConversationExchangeHonorsDoneContext(t *testing.T) {
	exchange, _, results, _ := newFedConversationExchange(t, "never\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReceiveLine() = %v, want context.Canceled", err)
	}
	if err := exchange.SendLine(ctx, []byte("line")); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendLine() = %v, want context.Canceled", err)
	}
	exchange.close()
	<-results
}

func newConversationRequest(t *testing.T, scenario string, arguments []string, timeout time.Duration) (ports.ProcessRequest, ports.ProviderPacketIdentity) {
	t.Helper()
	packet := runnerTestProviderPacket(t, []byte(`{"packet":"protocol-prompt"}`))
	binding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	binary := helperBinary(t)
	argv := []string{binary, "-test.run=^TestRunnerHelperProcess$", "--", scenario}
	argv = append(argv, arguments...)
	request, err := ports.NewProviderProtocolProcessRequest(
		binary,
		argv,
		[]ports.EnvironmentVariable{
			mustEnvironment(t, "MULGAE_PROCESS_RUNNER_HELPER", "1"),
			mustEnvironment(t, "GOCOVERDIR", t.TempDir()),
		},
		t.TempDir(),
		binding,
		timeout,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request, packet.Identity()
}

// conversationEchoDriver performs one scripted create and send exchange and
// records each received line.
type conversationEchoDriver struct {
	received [][]byte
	err      error
}

func (driver *conversationEchoDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	for index, request := range []string{
		`{"id":1,"method":"session/create","params":{"mode":"yolo"}}`,
		`{"id":2,"method":"session/send","params":{"prompt":"review"}}`,
	} {
		if err := exchange.SendLine(ctx, []byte(request)); err != nil {
			driver.err = err
			return err
		}
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			driver.err = err
			return err
		}
		driver.received = append(driver.received, line)
		if index == 1 && string(line) != `{"method":"turn-completed","params":{"sessionId":"session"}}` {
			driver.err = fmt.Errorf("unexpected turn completion %q", line)
			return driver.err
		}
	}
	return nil
}

// conversationReceiveDriver consumes lines until the exchange ends and
// records the terminal error.
type conversationReceiveDriver struct {
	lines   [][]byte
	endErr  error
	endSeen bool
}

func (driver *conversationReceiveDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	for {
		line, err := exchange.ReceiveLine(ctx)
		if err != nil {
			driver.endErr = err
			driver.endSeen = true
			return err
		}
		driver.lines = append(driver.lines, line)
	}
}

// conversationSingleResponseDriver completes after one exchange while the
// child process remains live.
type conversationSingleResponseDriver struct {
	received []byte
}

func (driver *conversationSingleResponseDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		return err
	}
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	driver.received = line
	return nil
}

// conversationFailingDriver completes one exchange and then reports its
// scripted failure.
type conversationFailingDriver struct {
	failure  error
	received []byte
	err      error
}

func (driver *conversationFailingDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		driver.err = err
		return err
	}
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		driver.err = err
		return err
	}
	driver.received = line
	driver.err = driver.failure
	return driver.failure
}

type conversationResult struct {
	observation ports.ProcessObservation
	err         error
}

func converseAsync(runner *Runner, ctx context.Context, request ports.ProcessRequest, driver ports.ProviderSessionDriver) <-chan conversationResult {
	done := make(chan conversationResult, 1)
	go func() {
		observation, err := runner.Converse(ctx, request, driver)
		done <- conversationResult{observation: observation, err: err}
	}()
	return done
}

func waitForConversationResult(t *testing.T, done <-chan conversationResult) conversationResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(15 * time.Second):
		t.Fatal("conversation did not return")
		return conversationResult{}
	}
}

func TestRunnerConverseRejectsInvalidConversationInputs(t *testing.T) {
	runner := newTestRunner(t)
	request, _ := newConversationRequest(t, "conversation-echo", nil, processTestExecutionTimeout)
	driver := &conversationReceiveDriver{}

	if _, err := runner.Converse(nil, request, driver); err == nil {
		t.Fatal("Converse() accepted a nil context")
	}
	if _, err := runner.Converse(context.Background(), request, nil); err == nil {
		t.Fatal("Converse() accepted a nil driver")
	}
	if _, err := runner.Converse(context.Background(), ports.ProcessRequest{}, driver); err == nil {
		t.Fatal("Converse() accepted an invalid request")
	}

	packet := runnerTestProviderPacket(t, []byte("packet"))
	stdinBinding, err := ports.NewStdinProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	stdinRequest, err := ports.NewProviderProcessRequest(
		"/bin/true", []string{"/bin/true"}, nil, t.TempDir(), stdinBinding, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Converse(context.Background(), stdinRequest, driver); err == nil {
		t.Fatal("Converse() accepted a non-protocol packet binding")
	}

	protocolBinding, err := ports.NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := ports.NewBoundedPostOutputLifecycle(ports.ProcessOutputFramingStrictJSON, 50*time.Millisecond, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	postOutputRequest, err := ports.NewProviderProcessRequestWithPostOutputLifecycle(
		"/bin/true", []string{"/bin/true"}, nil, t.TempDir(), protocolBinding, lifecycle, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Converse(context.Background(), postOutputRequest, driver); err == nil {
		t.Fatal("Converse() accepted a post-output lifecycle request")
	}
}

func TestRunnerConverseCompletesScriptedProtocolExchange(t *testing.T) {
	request, packetIdentity := newConversationRequest(t, "conversation-echo", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationEchoDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	// The scripted server stays alive after turn completion, so the bounded
	// conversation teardown ends it with a recorded SIGTERM.
	assertTermination(t, observation, ports.ProcessTerminationSignaled)
	assertSignal(t, observation, 15, "SIGTERM")
	if len(driver.received) != 2 {
		t.Fatalf("driver received = %q", driver.received)
	}

	frames := "{\"id\":1,\"method\":\"session/create\",\"params\":{\"mode\":\"yolo\"}}\n" +
		"{\"id\":2,\"method\":\"session/send\",\"params\":{\"prompt\":\"review\"}}\n"
	transcript := "{\"id\":1,\"result\":{\"sessionId\":\"session\"}}\n" +
		"{\"method\":\"turn-completed\",\"params\":{\"sessionId\":\"session\"}}\n"
	if got := string(observation.Stdout()); got != transcript {
		t.Fatalf("transcript = %q, want %q", got, transcript)
	}
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != int64(len(frames)) || receipt.WrittenByteCount() != int64(len(frames)) ||
		!receipt.Complete() || receipt.SHA256() != runnerTestStdinDigest([]byte(frames)) {
		t.Fatalf("stdin receipt = %#v", receipt)
	}
	assertProviderTransport(t, observation, ports.ProviderPacketChannelProtocol, packetIdentity)

	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !observation.ProcessGroupAbsent() {
		t.Fatalf("lifecycle receipt = %#v, present=%t", lifecycle, ok)
	}
	artifact, ok := observation.StdoutArtifact()
	if !ok {
		t.Fatal("conversation transcript artifact is missing")
	}
	reader, err := artifact.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if string(artifactBytes) != transcript {
		t.Fatalf("spooled transcript = %q, want %q", artifactBytes, transcript)
	}
}

func TestRunnerConverseTearsDownLiveChildAfterDriverCompletion(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-hold", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationSingleResponseDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.received) == 0 {
		t.Fatal("driver received no response")
	}
	assertTermination(t, observation, ports.ProcessTerminationSignaled)
	assertSignal(t, observation, 15, "SIGTERM")
	if observation.Succeeded() {
		t.Fatal("teardown-signaled conversation claims process success")
	}
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !observation.ProcessGroupAbsent() {
		t.Fatalf("lifecycle receipt = %#v, present=%t", lifecycle, ok)
	}
	requests := observation.SignalRequests()
	if len(requests) != 1 || requests[0].Reason() != ports.ProcessGroupSignalRequestConversationTeardown ||
		requests[0].Signal().Name() != "SIGTERM" {
		t.Fatalf("signal requests = %#v", requests)
	}
}

func TestRunnerConverseSurfacesDriverErrorWithCoherentTeardown(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-hold", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	failure := errors.New("provider protocol rejected the turn")
	driver := &conversationFailingDriver{failure: failure}

	observation, err := runner.Converse(context.Background(), request, driver)
	if !errors.Is(err, failure) {
		t.Fatalf("Converse() error = %v, want driver failure", err)
	}
	assertTermination(t, observation, ports.ProcessTerminationSignaled)
	assertSignal(t, observation, 15, "SIGTERM")
	if !observation.Valid() {
		t.Fatal("failed-conversation observation is invalid")
	}
	if !observation.ProcessGroupAbsent() {
		t.Fatal("failed conversation left its process group live")
	}
}

func TestRunnerConverseReportsStreamEndToDriver(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-partial-line", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationReceiveDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err == nil {
		t.Fatal("Converse() hid the driver's stream-end error")
	}
	if !errors.Is(driver.endErr, io.ErrUnexpectedEOF) {
		t.Fatalf("driver end error = %v, want io.ErrUnexpectedEOF", driver.endErr)
	}
	assertTermination(t, observation, ports.ProcessTerminationExited)
	assertExitCode(t, observation, 0)
	if got := string(observation.Stdout()); got != `{"partial":` {
		t.Fatalf("partial transcript = %q", got)
	}
}

func TestIntegrationRunnerConverseTimesOutAndTerminatesProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	request, _ := newConversationRequest(t, "conversation-quiet-descendant", []string{marker}, 400*time.Millisecond)
	runner := newTestRunner(t)
	driver := &conversationReceiveDriver{}

	started := time.Now()
	observation, err := runner.Converse(context.Background(), request, driver)
	if err == nil {
		t.Fatal("timed-out conversation hid the driver error")
	}
	if elapsed := time.Since(started); elapsed < 400*time.Millisecond {
		t.Fatalf("conversation returned after %s, before the timeout", elapsed)
	}
	assertTermination(t, observation, ports.ProcessTerminationTimedOut)
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !observation.ProcessGroupAbsent() {
		t.Fatalf("lifecycle receipt = %#v, present=%t", lifecycle, ok)
	}
	foundTeardown := false
	for _, request := range observation.SignalRequests() {
		if request.Reason() == ports.ProcessGroupSignalRequestConversationTeardown && request.Signal().Name() == "SIGTERM" {
			foundTeardown = true
		}
	}
	if !foundTeardown {
		t.Fatalf("signal requests = %#v, want a conversation teardown SIGTERM", observation.SignalRequests())
	}

	markerBytes, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	processGroupID, err := strconv.Atoi(strings.TrimSpace(string(markerBytes)))
	if err != nil {
		t.Fatal(err)
	}
	membership, err := probeProcessGroup(processGroupID)
	if err != nil {
		t.Fatal(err)
	}
	if !membership.absent() {
		t.Fatalf("process group %d remains live (%d live, %d zombie)", processGroupID, membership.liveMembers, membership.zombieMembers)
	}
}

func TestIntegrationRunnerConverseClassifiesContextCancellation(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-quiet", nil, 10*time.Second)
	runner := newTestRunner(t)
	driver := &conversationReceiveDriver{}
	ctx, cancel := context.WithCancel(context.Background())

	done := converseAsync(runner, ctx, request, driver)
	time.Sleep(200 * time.Millisecond)
	cancel()
	result := waitForConversationResult(t, done)

	if result.err == nil {
		t.Fatal("cancelled conversation hid the driver error")
	}
	assertTermination(t, result.observation, ports.ProcessTerminationCancelled)
	if !result.observation.ProcessGroupAbsent() {
		t.Fatal("cancelled conversation left its process group live")
	}
}
