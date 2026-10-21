//go:build darwin && arm64

package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestConversationLineAssemblerChunkingEquivalence(t *testing.T) {
	const stream = "alpha\nbeta\n\ngamma\n"
	wantLines := []string{"alpha", "beta", "", "gamma"}
	byteWise := make([]string, len(stream))
	for index := 0; index < len(stream); index++ {
		byteWise[index] = stream[index : index+1]
	}
	for _, test := range []struct {
		name        string
		chunks      []string
		copiedBytes int
	}{
		{name: "whole stream in one chunk", chunks: []string{stream}, copiedBytes: 0},
		{name: "byte-wise", chunks: byteWise, copiedBytes: 0},
		{name: "chunk boundaries at newlines", chunks: []string{"alpha\n", "beta\n", "\ngamma\n"}, copiedBytes: 0},
		{name: "one byte past newline", chunks: []string{"alpha\nb", "eta\n\ng", "amma\n"}, copiedBytes: 2},
		{name: "mid-word", chunks: []string{"al", "pha\nbe", "ta\n\ngam", "ma\n"}, copiedBytes: 5},
		{name: "several frames per chunk", chunks: []string{"alpha\nbeta\n", "\ngamma\n"}, copiedBytes: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembler := conversationLineAssembler{}
			var lines [][]byte
			for _, chunk := range test.chunks {
				lines = append(lines, assembler.appendChunk([]byte(chunk))...)
			}
			if assembler.unfinished() {
				t.Fatal("stream ended with an unfinished tail")
			}
			if len(lines) != len(wantLines) {
				t.Fatalf("lines = %q, want %q", lines, wantLines)
			}
			for index, line := range lines {
				if string(line) != wantLines[index] {
					t.Fatalf("line %d = %q, want %q", index, line, wantLines[index])
				}
			}
			if assembler.scannedBytes != len(stream) {
				t.Fatalf("scannedBytes = %d, want %d", assembler.scannedBytes, len(stream))
			}
			if assembler.copiedBytes != test.copiedBytes {
				t.Fatalf("copiedBytes = %d, want %d", assembler.copiedBytes, test.copiedBytes)
			}
		})
	}

	t.Run("1 MiB line in 64 KiB chunks", func(t *testing.T) {
		payload := bytes.Repeat([]byte("L"), 1<<20)
		assembler := conversationLineAssembler{}
		var lines [][]byte
		for offset := 0; offset < len(payload); offset += 65536 {
			end := offset + 65536
			if end > len(payload) {
				end = len(payload)
			}
			lines = append(lines, assembler.appendChunk(payload[offset:end])...)
		}
		lines = append(lines, assembler.appendChunk([]byte("\n"))...)
		if len(lines) != 1 || !bytes.Equal(lines[0], payload) {
			t.Fatalf("delivered %d lines (first length %d), want exactly the 1 MiB line", len(lines), len(lines[0]))
		}
		if assembler.scannedBytes != len(payload)+1 || assembler.copiedBytes != 0 {
			t.Fatalf("counters = scanned %d copied %d, want %d and 0", assembler.scannedBytes, assembler.copiedBytes, len(payload)+1)
		}
	})
}

func TestConversationLineAssemblerRetainsTailAndCompactsAmortized(t *testing.T) {
	assembler := conversationLineAssembler{}
	if lines := assembler.appendChunk([]byte("par")); len(lines) != 0 || !assembler.unfinished() {
		t.Fatalf("partial chunk delivered %d lines, unfinished %t", len(lines), assembler.unfinished())
	}
	if lines := assembler.appendChunk([]byte("tial\n")); len(lines) != 1 || string(lines[0]) != "partial" || assembler.unfinished() {
		t.Fatalf("completion delivered %q, unfinished %t", lines, assembler.unfinished())
	}

	compacting := conversationLineAssembler{}
	if lines := compacting.appendChunk([]byte("aaaa\nbbbb")); len(lines) != 1 || string(lines[0]) != "aaaa" || !compacting.unfinished() {
		t.Fatalf("first chunk delivered %q, unfinished %t", lines, compacting.unfinished())
	}
	if compacting.copiedBytes != 4 || compacting.scannedBytes != 9 {
		t.Fatalf("counters = copied %d scanned %d, want 4 and 9", compacting.copiedBytes, compacting.scannedBytes)
	}
	if lines := compacting.appendChunk([]byte("cccc\n")); len(lines) != 1 || string(lines[0]) != "bbbbcccc" {
		t.Fatalf("second chunk delivered %q", lines)
	}

	resetting := conversationLineAssembler{}
	resetting.appendChunk([]byte("x\n"))
	resetting.appendChunk([]byte("y\n"))
	if resetting.copiedBytes != 0 || resetting.scannedBytes != 4 {
		t.Fatalf("counters = copied %d scanned %d, want 0 and 4", resetting.copiedBytes, resetting.scannedBytes)
	}

	interleaved := conversationLineAssembler{}
	var lines [][]byte
	lines = append(lines, interleaved.appendChunk([]byte("one\ntw"))...)
	lines = append(lines, interleaved.appendChunk([]byte("o\nthree\n"))...)
	if len(lines) != 3 || string(lines[0]) != "one" || string(lines[1]) != "two" || string(lines[2]) != "three" {
		t.Fatalf("interleaved lines = %q", lines)
	}
	if interleaved.unfinished() {
		t.Fatal("interleaved stream ended with an unfinished tail")
	}
}

func TestConversationLineAssemblerDeliveredLinesOwnTheirBytes(t *testing.T) {
	assembler := conversationLineAssembler{}
	chunk := []byte("own")
	assembler.appendChunk(chunk)
	copy(chunk, "XXX")
	lines := assembler.appendChunk([]byte("ership\n"))
	if len(lines) != 1 || string(lines[0]) != "ownership" {
		t.Fatalf("line after input mutation = %q, want [ownership]", lines)
	}

	independent := conversationLineAssembler{}
	first := independent.appendChunk([]byte("first\nAAAA"))
	if len(first) != 1 || string(first[0]) != "first" {
		t.Fatalf("first line = %q, want [first]", first)
	}
	// The completed line above already forced the compaction copy over the
	// region that held its bytes; a large further append grows the buffer past
	// its current capacity before the second line completes.
	tail := bytes.Repeat([]byte("t"), 1<<17)
	independent.appendChunk(tail)
	second := independent.appendChunk([]byte("z\n"))
	if len(second) != 1 || string(second[0]) != "AAAA"+string(tail)+"z" {
		t.Fatalf("second line length = %d, want %d", len(second[0]), len("AAAA")+len(tail)+1)
	}
	if string(first[0]) != "first" {
		t.Fatalf("retained first line = %q, want [first]", first[0])
	}
}

func TestConversationLineAssemblerScansIncomingBytesOnce(t *testing.T) {
	t.Run("single line across 256 chunks", func(t *testing.T) {
		payload := bytes.Repeat([]byte("l"), 1<<20)
		assembler := conversationLineAssembler{}
		for index := 0; index < len(payload); index += 4096 {
			end := index + 4096
			if end > len(payload) {
				end = len(payload)
			}
			lines := assembler.appendChunk(payload[index:end])
			if len(lines) != 0 || !assembler.unfinished() {
				t.Fatalf("chunk at %d delivered %d lines, unfinished %t", index, len(lines), assembler.unfinished())
			}
		}
		lines := assembler.appendChunk([]byte("\n"))
		if len(lines) != 1 || assembler.unfinished() || !bytes.Equal(lines[0], payload) {
			t.Fatalf("final chunk delivered %d lines, unfinished %t, line length %d", len(lines), assembler.unfinished(), len(lines[0]))
		}
		if assembler.scannedBytes != len(payload)+1 {
			t.Fatalf("scannedBytes = %d, want %d (each byte examined exactly once)", assembler.scannedBytes, len(payload)+1)
		}
		if assembler.copiedBytes != 0 {
			t.Fatalf("copiedBytes = %d, want 0 (no per-chunk tail movement)", assembler.copiedBytes)
		}
	})

	t.Run("newline-aligned 16-byte frames across 64 KiB chunks", func(t *testing.T) {
		const frames = 65536
		expected := make([][]byte, 0, frames)
		stream := make([]byte, 0, frames*16)
		for index := 0; index < frames; index++ {
			frame := fmt.Sprintf("%015d\n", index)
			expected = append(expected, []byte(frame[:15]))
			stream = append(stream, frame...)
		}
		assembler := conversationLineAssembler{}
		delivered := 0
		for offset := 0; offset < len(stream); offset += 65536 {
			end := offset + 65536
			if end > len(stream) {
				end = len(stream)
			}
			lines := assembler.appendChunk(stream[offset:end])
			if len(lines) != 4096 {
				t.Fatalf("chunk at %d delivered %d lines, want 4096", offset, len(lines))
			}
			for _, line := range lines {
				if !bytes.Equal(line, expected[delivered]) {
					t.Fatalf("line %d = %q, want %q", delivered, line, expected[delivered])
				}
				delivered++
			}
			if assembler.unfinished() {
				t.Fatalf("chunk at %d left an unfinished tail", offset)
			}
		}
		if delivered != frames {
			t.Fatalf("delivered %d lines, want %d", delivered, frames)
		}
		if assembler.scannedBytes != len(stream) {
			t.Fatalf("scannedBytes = %d, want %d", assembler.scannedBytes, len(stream))
		}
		if assembler.copiedBytes != 0 {
			t.Fatalf("copiedBytes = %d, want 0 (newline-aligned chunks reset in place)", assembler.copiedBytes)
		}
	})
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

// newOpenConversationFeed mirrors the production feed wiring with a real
// spool pipe: an os.Pipe stdout whose writer stays open for the test, a real
// io.Pipe spool writer in the sink, and the feed goroutine running against
// them. The returned spool reader stays open so the test can drain it.
func newOpenConversationFeed(t *testing.T) (*conversationExchange, *conversationTranscriptSink, chan conversationStdoutResult, *os.File, *io.PipeReader) {
	t.Helper()
	streamReader, streamWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	spoolReader, spoolWriter := io.Pipe()
	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	exchange := newConversationExchange(stdinWriter)
	sink := &conversationTranscriptSink{spoolWriter: spoolWriter, transcript: &streamCapture{}}
	results := make(chan conversationStdoutResult, 1)
	go feedConversationStdout(streamReader, sink, exchange, results)
	t.Cleanup(func() {
		_ = streamReader.Close()
		_ = spoolReader.Close()
		_ = stdinReader.Close()
	})
	return exchange, sink, results, streamWriter, spoolReader
}

type spoolReadResult struct {
	data []byte
	err  error
}

func TestFeedConversationStdoutDropsLinesAndKeepsSpoolingAfterExchangeClose(t *testing.T) {
	exchange, sink, results, streamWriter, spoolReader := newOpenConversationFeed(t)
	spoolDone := make(chan spoolReadResult, 1)
	go func() {
		// EOF arrives only when the feed's deferred closeSpool closes the
		// spool writer, so this read blocks until the feed completes.
		data, err := io.ReadAll(spoolReader)
		spoolDone <- spoolReadResult{data: data, err: err}
	}()

	if _, err := streamWriter.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	line, err := exchange.ReceiveLine(context.Background())
	if err != nil || string(line) != "before" {
		t.Fatalf("ReceiveLine() = (%q, %v), want the pre-close line", line, err)
	}
	exchange.close()
	if _, err := streamWriter.Write([]byte("after\npartial")); err != nil {
		t.Fatal(err)
	}
	if err := streamWriter.Close(); err != nil {
		t.Fatal(err)
	}
	// The feed sends its result before its deferred closeSpool executes, so
	// the spool drain completes only after both waits.
	feedResult := <-results
	spoolRes := <-spoolDone

	if !errors.Is(feedResult.err, io.ErrUnexpectedEOF) {
		t.Fatalf("feed result = %v, want a wrapped io.ErrUnexpectedEOF", feedResult.err)
	}
	expected := "before\nafter\npartial"
	if string(sink.transcript.bytes) != expected {
		t.Fatalf("transcript = %q, want %q", sink.transcript.bytes, expected)
	}
	if spoolRes.err != nil {
		t.Fatalf("spool read = %v, want nil", spoolRes.err)
	}
	if !bytes.Equal(spoolRes.data, []byte(expected)) {
		t.Fatalf("spool bytes = %q, want %q", spoolRes.data, expected)
	}
	if _, err := exchange.ReceiveLine(context.Background()); !errors.Is(err, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("ReceiveLine() after close = %v, want exchange closure", err)
	}
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

func TestConversationExchangeHalfClosesInputAndKeepsReceiving(t *testing.T) {
	exchange, _, results, stdinReader := newFedConversationExchange(t, "first\nsecond\n")
	ctx := context.Background()

	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		t.Fatal(err)
	}
	if err := exchange.CloseInput(ctx); err != nil {
		t.Fatalf("CloseInput() = %v", err)
	}
	if err := exchange.CloseInput(ctx); err != nil {
		t.Fatalf("idempotent CloseInput() = %v", err)
	}
	// ReceiveLine must stay usable after the input half-close.
	line, err := exchange.ReceiveLine(ctx)
	if err != nil || string(line) != "first" {
		t.Fatalf("ReceiveLine() after half-close = (%q, %v)", line, err)
	}
	if err := exchange.SendLine(ctx, []byte(`{"id":2}`)); !errors.Is(err, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("SendLine() after half-close = %v, want exchange closure", err)
	}

	// The half-close reached the pipe: the sent frame is readable, then the
	// read side reports EOF because the write end is gone.
	frame := "{\"id\":1,\"method\":\"session/create\"}\n"
	written := make([]byte, len(frame))
	if _, err := io.ReadFull(stdinReader, written); err != nil || string(written) != frame {
		t.Fatalf("child stdin = (%q, %v), want %q", written, err, frame)
	}
	if _, err := stdinReader.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("stdin read after half-close = %v, want io.EOF", err)
	}

	receipt, err := exchange.stdinWriteReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.IntendedByteLength() != int64(len(frame)) || receipt.WrittenByteCount() != int64(len(frame)) ||
		!receipt.Complete() || receipt.SHA256() != runnerTestStdinDigest([]byte(frame)) {
		t.Fatalf("stdin receipt after half-close = %#v", receipt)
	}
	if line, err = exchange.ReceiveLine(ctx); err != nil || string(line) != "second" {
		t.Fatalf("second ReceiveLine() = (%q, %v)", line, err)
	}
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal ReceiveLine() = %v, want io.EOF", err)
	}
	exchange.close()
	<-results
}

func TestConversationExchangeCloseInputPreservesFirstError(t *testing.T) {
	closeErr := errors.New("synthetic stdin close failure")
	stdin := &failingCloseStdin{err: closeErr}
	exchange := newConversationExchange(stdin)
	ctx := context.Background()

	first := exchange.CloseInput(ctx)
	second := exchange.CloseInput(ctx)
	if !errors.Is(first, closeErr) || !errors.Is(second, closeErr) || first != second {
		t.Fatalf("CloseInput() = (%v, %v), want the preserved first close error", first, second)
	}
	if stdin.closes != 1 {
		t.Fatalf("stdin closed %d times, want exactly one", stdin.closes)
	}
	if err := exchange.SendLine(ctx, []byte("line")); !errors.Is(err, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("SendLine() after failed close = %v, want exchange closure", err)
	}
}

func TestConversationExchangeCloseInputHonorsDoneContext(t *testing.T) {
	exchange, _, results, stdinReader := newFedConversationExchange(t, "line\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := exchange.CloseInput(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CloseInput() with done context = %v, want context.Canceled", err)
	}
	// The refused close must leave the input usable and the pipe open.
	if err := exchange.SendLine(context.Background(), []byte("still-open")); err != nil {
		t.Fatalf("SendLine() after refused close = %v", err)
	}
	if _, err := stdinReader.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
		t.Fatal("refused close leaked an EOF to the child stdin pipe")
	}
	if err := exchange.CloseInput(context.Background()); err != nil {
		t.Fatalf("CloseInput() after refused close = %v", err)
	}
	exchange.close()
	<-results
}

// blockingEvictedStdin emulates a pollable pipe writer whose pending write is
// evicted, not queued, when the write end closes.
type blockingEvictedStdin struct {
	entered  chan struct{}
	closed   chan struct{}
	closeOne sync.Once
}

func newBlockingEvictedStdin() *blockingEvictedStdin {
	return &blockingEvictedStdin{entered: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (stdin *blockingEvictedStdin) Write(frame []byte) (int, error) {
	stdin.entered <- struct{}{}
	<-stdin.closed
	return 0, os.ErrClosed
}

func (stdin *blockingEvictedStdin) Close() error {
	stdin.closeOne.Do(func() { close(stdin.closed) })
	return nil
}

func TestConversationExchangeTeardownCloseUnblocksSendAndKeepsReceiptsTruthful(t *testing.T) {
	stdin := newBlockingEvictedStdin()
	exchange := newConversationExchange(stdin)
	frame := "blocked-frame\n"

	sendDone := make(chan error, 1)
	go func() { sendDone <- exchange.SendLine(context.Background(), []byte("blocked-frame")) }()
	<-stdin.entered

	// The shared teardown close must complete without waiting for the send.
	closed := make(chan error, 1)
	go func() { closed <- exchange.closeInput() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("closeInput() behind a blocked send = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closeInput() waited for the blocked send")
	}

	if err := <-sendDone; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("blocked SendLine() = %v, want os.ErrClosed", err)
	}
	if _, written, incomplete := exchange.stdinSnapshot(); !incomplete || written != 0 {
		t.Fatalf("stdin snapshot = written %d, incomplete %t, want 0 and true", written, incomplete)
	}
	receipt, err := exchange.stdinWriteReceipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.IntendedByteLength() != int64(len(frame)) || receipt.WrittenByteCount() != 0 || receipt.Complete() {
		t.Fatalf("partial-write receipt = %#v, want intended %d, written 0, incomplete", receipt, len(frame))
	}
}

// failingCloseStdin counts Close calls and fails every one of them.
type failingCloseStdin struct {
	err    error
	closes int
}

func (stdin *failingCloseStdin) Write(frame []byte) (int, error) {
	return len(frame), nil
}

func (stdin *failingCloseStdin) Close() error {
	stdin.closes++
	return stdin.err
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

// conversationHalfCloseDriver completes one exchange, half-closes child
// stdin, and drains the stream through its clean end before returning. This
// is the shutdown contract a child that exits on stdin EOF requires: the
// driver must not return before the child's own output has ended.
type conversationHalfCloseDriver struct {
	received [][]byte
	drained  bool
}

func (driver *conversationHalfCloseDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		return err
	}
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	driver.received = append(driver.received, line)
	if err := exchange.CloseInput(ctx); err != nil {
		return err
	}
	// ReceiveLine stays usable after the half-close and delivers the child's
	// post-EOF-exit line.
	line, err = exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	driver.received = append(driver.received, line)
	_, err = exchange.ReceiveLine(ctx)
	driver.drained = errors.Is(err, io.EOF)
	if !driver.drained {
		return fmt.Errorf("provider session exchange: drain to stream end: %w", err)
	}
	return nil
}

// conversationBlockingSendDriver issues one frame far larger than the pipe
// buffer while the child never reads, so its send blocks until teardown.
type conversationBlockingSendDriver struct {
	sendErr error
}

func (driver *conversationBlockingSendDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	driver.sendErr = exchange.SendLine(ctx, bytes.Repeat([]byte("a"), 512*1024))
	return driver.sendErr
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

// conversationGatedDriver completes one exchange, records the response, closes
// gated, then blocks on release while ignoring its context so the conversation
// loop's terminal handling, not the driver, must release it.
type conversationGatedDriver struct {
	gated    chan struct{}
	release  chan struct{}
	received []byte
}

func (driver *conversationGatedDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	if err := exchange.SendLine(ctx, []byte(`{"id":1,"method":"session/create"}`)); err != nil {
		return err
	}
	line, err := exchange.ReceiveLine(ctx)
	if err != nil {
		return err
	}
	driver.received = line
	close(driver.gated)
	<-driver.release
	return nil
}

// conversationStreamEndGatedDriver records the stream-end error, closes ended,
// blocks on release while ignoring its context, and reports the recorded error
// when released.
type conversationStreamEndGatedDriver struct {
	ended   chan struct{}
	release chan struct{}
	endErr  error
}

func (driver *conversationStreamEndGatedDriver) Drive(ctx context.Context, exchange ports.ProviderSessionExchange) error {
	_, err := exchange.ReceiveLine(ctx)
	driver.endErr = err
	close(driver.ended)
	<-driver.release
	return driver.endErr
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

func TestRunnerConverseHalfCloseAndDrainYieldsNaturalExit(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-eof-exit", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationHalfCloseDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	// The child stays alive well beyond the natural-exit grace after stdin
	// reaches EOF; only a driver that half-closes and drains through the
	// clean stream end returns after the natural exit, so the teardown ends
	// without any signal request.
	if len(driver.received) != 2 || !driver.drained {
		t.Fatalf("driver received = %q, drained = %t", driver.received, driver.drained)
	}
	assertTermination(t, observation, ports.ProcessTerminationExited)
	assertExitCode(t, observation, 0)
	if !observation.Succeeded() {
		t.Fatal("naturally exited conversation claims process failure")
	}
	if requests := observation.SignalRequests(); len(requests) != 0 {
		t.Fatalf("signal requests = %#v, want none for a natural exit", requests)
	}
	if !observation.ProcessGroupAbsent() {
		t.Fatal("naturally exited conversation left its process group live")
	}
	frames := "{\"id\":1,\"method\":\"session/create\"}\n"
	receipt := observation.StdinWriteReceipt()
	if receipt.IntendedByteLength() != int64(len(frames)) || receipt.WrittenByteCount() != int64(len(frames)) ||
		!receipt.Complete() || receipt.SHA256() != runnerTestStdinDigest([]byte(frames)) {
		t.Fatalf("stdin receipt = %#v", receipt)
	}
	transcript := "{\"id\":1,\"result\":{\"sessionId\":\"session\"}}\n" +
		"{\"method\":\"turn-completed\",\"params\":{\"sessionId\":\"session\"}}\n"
	if got := string(observation.Stdout()); got != transcript {
		t.Fatalf("transcript = %q, want %q", got, transcript)
	}
}

func TestRunnerConverseTeardownCloseUnblocksBlockedSend(t *testing.T) {
	// The quiet child never reads stdin, so the oversized frame blocks inside
	// the pipe write; only the teardown's shared stdin close can evict it.
	request, _ := newConversationRequest(t, "conversation-quiet", nil, 600*time.Millisecond)
	runner := newTestRunner(t)
	driver := &conversationBlockingSendDriver{}

	result := waitForConversationResult(t, converseAsync(runner, context.Background(), request, driver))
	if result.err == nil {
		t.Fatal("blocked-send conversation hid the driver error")
	}
	if !errors.Is(driver.sendErr, os.ErrClosed) && !errors.Is(driver.sendErr, ports.ErrProviderSessionExchangeClosed) {
		t.Fatalf("blocked send error = %v, want pipe closure", driver.sendErr)
	}
	assertTermination(t, result.observation, ports.ProcessTerminationTimedOut)
	if !result.observation.ProcessGroupAbsent() {
		t.Fatal("blocked-send conversation left its process group live")
	}
	receipt := result.observation.StdinWriteReceipt()
	if receipt.Complete() || receipt.WrittenByteCount() >= receipt.IntendedByteLength() {
		t.Fatalf("blocked-send receipt = %#v, want a truthful partial write", receipt)
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

func TestRunnerConverseTearsDownOrphanedGroupAfterNaturalChildExit(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-orphan-holder", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationSingleResponseDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.received) == 0 {
		t.Fatal("driver received no response")
	}
	// The child ended on its own while a descendant kept the conversation
	// pipes open; the remaining group is still torn down within the teardown
	// budget, so the conversation completes instead of waiting for the stream
	// ends forever. Whether the child's own end classifies as exited or
	// signaled depends on the natural-exit grace race, so only completion and
	// group cleanup are pinned here.
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

func TestRunnerConverseEscalatesOrphanedGroupThatIgnoresTermination(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-orphan-resistant", nil, processTestExecutionTimeout)
	runner := newTestRunner(t)
	driver := &conversationSingleResponseDriver{}

	observation, err := runner.Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.received) == 0 {
		t.Fatal("driver received no response")
	}
	lifecycle, ok := observation.LifecycleReceipt()
	if !ok || !lifecycle.Valid() || !observation.ProcessGroupAbsent() {
		t.Fatalf("lifecycle receipt = %#v, present=%t", lifecycle, ok)
	}
	requests := observation.SignalRequests()
	if len(requests) != 2 ||
		requests[0].Reason() != ports.ProcessGroupSignalRequestConversationTeardown ||
		requests[0].Signal().Name() != "SIGTERM" ||
		requests[1].Reason() != ports.ProcessGroupSignalRequestConversationTeardownEscalation ||
		requests[1].Signal().Name() != "SIGKILL" {
		t.Fatalf("signal requests = %#v", requests)
	}
}

func TestRunnerConverseEscalatesDetachedOrphanAfterStreamsClose(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ready")
	t.Cleanup(func() {
		if data, err := os.ReadFile(marker); err == nil {
			if group, err := strconv.Atoi(string(data)); err == nil && group > 0 {
				_ = syscall.Kill(-group, syscall.SIGKILL)
			}
		}
	})
	request, _ := newConversationRequest(t, "conversation-orphan-detached-resistant", []string{marker}, processTestExecutionTimeout)
	driver := &conversationSingleResponseDriver{}
	observation, err := newTestRunner(t).Converse(context.Background(), request, driver)
	if err != nil {
		t.Fatal(err)
	}
	if len(driver.received) == 0 || !observation.ProcessGroupAbsent() {
		t.Fatal("detached descendant escaped conversation teardown")
	}
	requests := observation.SignalRequests()
	if len(requests) != 2 || requests[0].Reason() != ports.ProcessGroupSignalRequestConversationTeardown ||
		requests[0].Signal().Name() != "SIGTERM" || requests[1].Reason() != ports.ProcessGroupSignalRequestConversationTeardownEscalation ||
		requests[1].Signal().Name() != "SIGKILL" {
		t.Fatalf("signal requests = %#v", requests)
	}
	assertNoLiveProcessGroup(t, readHelperPID(t, marker))
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

func TestIntegrationRunnerConverseConsumesCancellationExactlyOnceWithDelayedDriver(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-hold", nil, 300*time.Millisecond)
	runner := newTestRunner(t)
	driver := &conversationGatedDriver{gated: make(chan struct{}), release: make(chan struct{})}
	capture := captureNextTerminalWatch(t, driver.release)
	termReached, termRelease := interceptTeardownSIGTERM(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := converseAsync(runner, ctx, request, driver)
	waitForChannel(t, driver.gated, "driver exchange completion")
	// The 300ms request timeout is the only terminal fact, so teardown starts
	// deterministically; the natural-exit SIGTERM parks in the barrier while no
	// cancellation fact exists yet.
	waitForChannel(t, termReached, "teardown SIGTERM barrier")
	cancel()
	close(termRelease)
	result := waitForConversationResult(t, done)

	if result.err != nil {
		t.Fatalf("delayed driver conversation error: %v", result.err)
	}
	assertTermination(t, result.observation, ports.ProcessTerminationCancelled)
	if !capture.ctxDoneNilAtFirstObservation.Load() {
		t.Fatal("done-channel receive was not disabled at first cancellation observation")
	}
	// Active teardown skips loop-top polling, so the select branch is the only
	// possible observer and the run cannot complete without it firing once.
	if capture.watch == nil || capture.watch.receivesDone != 1 {
		t.Fatalf("done receives = %#v", capture.watch)
	}
	if capture.watch.receivesTimeout > 1 {
		t.Fatalf("timeout receives = %d", capture.watch.receivesTimeout)
	}
	receipts := result.observation.SignalRequests()
	if len(receipts) != 1 ||
		receipts[0].Reason() != ports.ProcessGroupSignalRequestConversationTeardown ||
		receipts[0].Signal().Name() != "SIGTERM" {
		t.Fatalf("signal requests = %#v, want exactly one conversation teardown SIGTERM", receipts)
	}
	if !result.observation.ProcessGroupAbsent() {
		t.Fatal("torn-down conversation left its process group live")
	}
	if string(driver.received) != `{"id":1,"result":{"sessionId":"session"}}` {
		t.Fatalf("driver received = %q", driver.received)
	}
}

func TestRunnerConverseClassifiesCancellationAgainstSimultaneousStreamEndAndExit(t *testing.T) {
	request, _ := newConversationRequest(t, "conversation-partial-line", nil, 10*time.Second)
	runner := newTestRunner(t)
	driver := &conversationStreamEndGatedDriver{ended: make(chan struct{}), release: make(chan struct{})}
	capture := captureNextTerminalWatch(t, make(chan struct{}))
	termReached, termRelease := interceptTeardownSIGTERM(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := converseAsync(runner, ctx, request, driver)
	// The child has exited and both stream-end facts exist; no terminal fact
	// exists yet.
	waitForChannel(t, driver.ended, "driver stream end")
	cancel()
	// Teardown is provably in progress with the cancellation recorded before
	// the driver is released.
	waitForChannel(t, termReached, "teardown SIGTERM barrier")
	close(termRelease)
	close(driver.release)
	result := waitForConversationResult(t, done)

	if result.err == nil || !errors.Is(result.err, io.ErrUnexpectedEOF) {
		t.Fatalf("conversation error = %v, want the driver's partial-line stream end", result.err)
	}
	if driver.endErr == nil || !errors.Is(driver.endErr, io.ErrUnexpectedEOF) {
		t.Fatalf("driver end error = %v, want io.ErrUnexpectedEOF", driver.endErr)
	}
	assertTermination(t, result.observation, ports.ProcessTerminationCancelled)
	if !capture.ctxDoneNilAtFirstObservation.Load() {
		t.Fatal("done-channel receive was not disabled at first cancellation observation")
	}
	if capture.watch == nil || capture.watch.receivesDone > 1 {
		t.Fatalf("done receives = %#v", capture.watch)
	}
	if got := string(result.observation.Stdout()); got != `{"partial":` {
		t.Fatalf("partial transcript = %q", got)
	}
	if len(result.observation.SignalRequests()) != 0 {
		t.Fatalf("signal requests = %#v, want none", result.observation.SignalRequests())
	}
	if !result.observation.ProcessGroupAbsent() {
		t.Fatal("cancelled conversation left its process group live")
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
