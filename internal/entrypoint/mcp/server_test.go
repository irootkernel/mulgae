package mcpentry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
)

func TestServeAdvertisesExplicitClientProtocolRange(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	output := serveRequest(t, request)
	response := decodeResponse(t, output)
	result := response["result"].(map[string]any)
	versions := result["supportedVersions"].([]any)
	wantVersions := []string{"2026-07-28", "2025-11-25", "2025-06-18"}
	if len(versions) != len(wantVersions) {
		t.Fatalf("supported versions = %#v, want %v", versions, wantVersions)
	}
	for index, want := range wantVersions {
		if versions[index] != want {
			t.Fatalf("supported versions = %#v, want %v", versions, wantVersions)
		}
	}
	if _, present := result["capabilities"].(map[string]any)["logging"]; present {
		t.Fatal("latest server unexpectedly advertises deprecated logging capability")
	}
	if strings.Contains(string(output), "level=") {
		t.Fatalf("stdout contains non-protocol logging: %q", output)
	}
}

func TestServeNegotiatesSupportedLegacyInitialize(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2025-06-18"} {
		t.Run(version, func(t *testing.T) {
			request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
			response := decodeResponse(t, serveRequest(t, request))
			result := response["result"].(map[string]any)
			if result["protocolVersion"] != version {
				t.Fatalf("initialize result = %#v, want protocol %q", result, version)
			}
		})
	}
}

func TestServeAcceptsInitializedNotificationWithoutParams(t *testing.T) {
	reader, input := io.Pipe()
	output := make(chan []byte, 2)
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, testConfig())
	}()
	write := func(message string) {
		t.Helper()
		if _, err := io.WriteString(input, message+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"codex-mcp-client","version":"0.147.0"}}}`)
	_ = receiveMCPMessage(t, output)
	write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"progressToken":0}}}`)
	if response := decodeResponse(t, receiveMCPMessage(t, output)); response["error"] != nil {
		t.Fatalf("tools/list after initialized notification = %#v", response)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServeRejectsProtocolBelowClientCompatibilityFloor(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
	response := decodeResponse(t, serveRequest(t, request))
	errorValue := response["error"].(map[string]any)
	if errorValue["code"] != float64(mcpsdk.CodeUnsupportedProtocolVersion) {
		t.Fatalf("error code = %v, want %d; response %#v", errorValue["code"], mcpsdk.CodeUnsupportedProtocolVersion, response)
	}
	data := errorValue["data"].(map[string]any)
	versions := data["supported"].([]any)
	if len(versions) != 3 || versions[0] != ProtocolVersion || versions[2] != "2025-06-18" || data["requested"] != "2025-03-26" {
		t.Fatalf("unsupported version data = %#v", data)
	}
}

func TestServeRejectsOlderPerRequestProtocol(t *testing.T) {
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	older := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	responses := serveRequests(t, discover, older)
	response := decodeResponse(t, responses[1])
	errorValue := response["error"].(map[string]any)
	if errorValue["code"] != float64(mcpsdk.CodeUnsupportedProtocolVersion) {
		t.Fatalf("error code = %v, want %d; response %#v", errorValue["code"], mcpsdk.CodeUnsupportedProtocolVersion, response)
	}
	data := errorValue["data"].(map[string]any)
	if data["requested"] != "2025-11-25" {
		t.Fatalf("requested version = %v, want 2025-11-25", data["requested"])
	}
}

func TestServeTreatsEOFAsCleanAndMalformedInputAsFailure(t *testing.T) {
	var output bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(""), &output, testConfig()); err != nil {
		t.Fatalf("empty input: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("empty input wrote %q", output.String())
	}

	if err := Serve(context.Background(), strings.NewReader("{\n"), &output, testConfig()); err == nil {
		t.Fatal("malformed input was accepted")
	}
}

func TestBoundedMCPReaderRejectsUnterminatedFrameAtEOF(t *testing.T) {
	reader := newBoundedMCPReader(io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0"}`)))
	data, err := io.ReadAll(reader)
	if !errors.Is(err, errMCPFrameTruncated) {
		t.Fatalf("unterminated frame = %q, %v; want %v", data, err, errMCPFrameTruncated)
	}
	if len(data) != 0 {
		t.Fatalf("unterminated frame leaked %q", data)
	}
}

func TestServeRejectsUnterminatedRunReviewBeforeDispatch(t *testing.T) {
	backend := &toolBackendFake{}
	discover := latestRequest(1, "server/discover", `{}`)
	call := strings.TrimSuffix(latestRequest(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"}}}`), "\n")
	var output bytes.Buffer
	err := Serve(context.Background(), strings.NewReader(discover+call), &output, toolTestConfig(t, backend))
	if !errors.Is(err, errMCPFrameTruncated) {
		t.Fatalf("unterminated run_review error = %v, want %v", err, errMCPFrameTruncated)
	}
	if backend.runReviewCalls != 0 {
		t.Fatalf("unterminated run_review calls = %d, want 0", backend.runReviewCalls)
	}
}

func TestServeRejectsOversizedFrameBeforeDispatch(t *testing.T) {
	base := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	for _, terminator := range []string{"\n", ""} {
		name := "unterminated"
		if terminator != "" {
			name = "newline"
		}
		t.Run(name, func(t *testing.T) {
			request := strings.Repeat(" ", maxMCPFrameBytes+1) + base + terminator
			var output bytes.Buffer
			err := Serve(context.Background(), strings.NewReader(request), &output, testConfig())
			if !errors.Is(err, errMCPFrameTooLarge) {
				t.Fatalf("oversized MCP frame error = %v, want %v", err, errMCPFrameTooLarge)
			}
			if output.Len() != 0 {
				t.Fatalf("oversized MCP frame wrote %q", output.String())
			}
		})
	}
}

func TestServeAcceptsMaximumSizedFrameAndCRLF(t *testing.T) {
	base := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	for _, terminator := range []string{"\n", "\r\n"} {
		t.Run(fmt.Sprintf("terminator-%q", terminator), func(t *testing.T) {
			padding := maxMCPFrameBytes - len(base) - len(terminator)
			if padding < 0 {
				t.Fatal("test request exceeds the MCP frame limit")
			}
			request := strings.Repeat(" ", padding) + base + terminator
			if len(request) != maxMCPFrameBytes {
				t.Fatalf("request length = %d, want %d", len(request), maxMCPFrameBytes)
			}
			response := decodeResponse(t, serveRequest(t, request))
			if response["error"] != nil {
				t.Fatalf("maximum-sized MCP frame = %#v", response)
			}
		})
	}
}

func TestServeCancellationClosesBlockingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader, input := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, reader, io.Discard, testConfig())
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for cancelled MCP shutdown")
	}
	_ = input.Close()
}

func TestServeRegistersBoundedToolSurfaceAndReturnsCommonEnvelope(t *testing.T) {
	backend := &toolBackendFake{getRunData: map[string]any{"run_id": "r_019f596a-cf80-7c67-b265-f37053d51ccf"}}
	discover := latestRequest(1, "server/discover", `{}`)
	list := latestRequest(2, "tools/list", `{}`)
	call := latestRequest(3, "tools/call", `{"name":"get_run","arguments":{"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, list, call)

	listed := decodeResponse(t, responses[1])["result"].(map[string]any)["tools"].([]any)
	names := make([]string, 0, len(listed))
	for _, raw := range listed {
		tool := raw.(map[string]any)
		names = append(names, tool["name"].(string))
		if tool["outputSchema"].(map[string]any)["$id"] != "https://mulgae.local/schemas/mulgae-mcp-tool-result.v1.schema.json" {
			t.Fatalf("tool output schema = %#v", tool["outputSchema"])
		}
	}
	if strings.Join(names, ",") != "await_review,cancel_review,get_run,list_findings,list_runs,preflight_review,run_review,start_review" {
		t.Fatalf("tool names = %v", names)
	}

	result := decodeResponse(t, responses[2])["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if structured["schema_version"] != toolResultSchemaVersion || structured["tool"] != toolGetRun ||
		structured["request_id"] != "i_019f596a-cf80-7c67-b265-f37053d51ccf" || structured["outcome"] != toolOutcomeSuccess {
		t.Fatalf("structured tool result = %#v", structured)
	}
	if result["isError"] != nil {
		t.Fatalf("successful tool call has isError = %v", result["isError"])
	}
	if backend.getRunCalls != 1 {
		t.Fatalf("get_run calls = %d, want 1", backend.getRunCalls)
	}
}

func TestServeLifecycleToolsReuseOneTerminalReview(t *testing.T) {
	backend := &toolBackendFake{}
	config := toolTestConfigWithIDs(t, backend,
		"i_019f596a-cf80-7c67-b265-f37053d51ccf",
		"i_019f596a-cf81-7c67-b265-f37053d51ccf",
		"i_019f596a-cf82-7c67-b265-f37053d51ccf",
	)
	discover := latestRequest(1, "server/discover", `{}`)
	start := latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"},"roles":["logic"]}}`)
	await := latestRequest(3, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	repeat := latestRequest(4, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	responses := serveRequestsWithConfig(t, config, discover, start, await, repeat)

	started := decodeResponse(t, responses[1])["result"].(map[string]any)["structuredContent"].(map[string]any)
	startData := started["data"].(map[string]any)
	if started["tool"] != toolStartReview || startData["invocation_id"] != "i_019f596a-cf80-7c67-b265-f37053d51ccf" || startData["state"] != string(invocationRunning) {
		t.Fatalf("start_review result = %#v", started)
	}
	for _, raw := range responses[2:] {
		terminal := decodeResponse(t, raw)["result"].(map[string]any)["structuredContent"].(map[string]any)
		data := terminal["data"].(map[string]any)
		if terminal["tool"] != toolAwaitReview || terminal["outcome"] != toolOutcomeSuccess ||
			data["invocation_id"] != "i_019f596a-cf80-7c67-b265-f37053d51ccf" ||
			data["run_id"] != "r_019f596a-cf80-7c67-b265-f37053d51ccf" {
			t.Fatalf("await_review result = %#v", terminal)
		}
	}
	if backend.runReviewCalls != 1 {
		t.Fatalf("lifecycle review executions = %d, want 1", backend.runReviewCalls)
	}
}

func TestServeCancelReviewAcknowledgesBeforeTerminalAwait(t *testing.T) {
	backend := &toolBackendFake{
		runReviewStarted: make(chan struct{}), runReviewCancelled: make(chan error, 1),
	}
	config := toolTestConfigWithIDs(t, backend,
		"i_019f596a-cf80-7c67-b265-f37053d51ccf",
		"i_019f596a-cf81-7c67-b265-f37053d51ccf",
		"i_019f596a-cf82-7c67-b265-f37053d51ccf",
	)
	discover := latestRequest(1, "server/discover", `{}`)
	start := latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"}}}`)
	cancel := latestRequest(3, "tools/call", `{"name":"cancel_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	await := latestRequest(4, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	responses := serveRequestsWithConfig(t, config, discover, start, cancel, await)

	acknowledgement := decodeResponse(t, responses[2])["result"].(map[string]any)["structuredContent"].(map[string]any)
	ackData := acknowledgement["data"].(map[string]any)
	if acknowledgement["tool"] != toolCancelReview || ackData["cancellation_accepted"] != true || ackData["cancellation_requested"] != true {
		t.Fatalf("cancel_review acknowledgement = %#v", acknowledgement)
	}
	terminal := decodeResponse(t, responses[3])["result"].(map[string]any)["structuredContent"].(map[string]any)
	failure := terminal["error"].(map[string]any)
	if terminal["tool"] != toolAwaitReview || terminal["outcome"] != toolOutcomeError || failure["class"] != "cancellation" || failure["retryable"] != false {
		t.Fatalf("cancelled await_review = %#v", terminal)
	}
	if backend.runReviewCalls != 1 || !errors.Is(<-backend.runReviewCancelled, context.Canceled) {
		t.Fatal("explicit cancellation did not reach the single review execution")
	}
}

func TestServeAwaitCancellationDoesNotCancelReviewExecution(t *testing.T) {
	backend := &toolBackendFake{
		runReviewStarted:   make(chan struct{}),
		runReviewRelease:   make(chan struct{}),
		runReviewCancelled: make(chan error, 1),
	}
	reader, input := io.Pipe()
	t.Cleanup(func() { _ = input.Close() })
	output := make(chan []byte, 5)
	done := make(chan error, 1)
	config := toolTestConfigWithIDs(t, backend,
		"i_019f596a-cf80-7c67-b265-f37053d51ccf",
		"i_019f596a-cf81-7c67-b265-f37053d51ccf",
		"i_019f596a-cf82-7c67-b265-f37053d51ccf",
	)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, config)
	}()

	writeMCPMessage(t, input, latestRequest(1, "server/discover", `{}`))
	_ = receiveMCPMessage(t, output)
	writeMCPMessage(t, input, latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"}}}`))
	started := decodeResponse(t, receiveMCPMessage(t, output))["result"].(map[string]any)["structuredContent"].(map[string]any)
	invocationID := started["data"].(map[string]any)["invocation_id"].(string)
	select {
	case <-backend.runReviewStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lifecycle review start")
	}

	writeMCPMessage(t, input, latestRequest(3, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"`+invocationID+`"}}`))
	writeMCPMessage(t, input, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3,"reason":"observer timeout"}}`+"\n")
	cancelled := decodeResponse(t, receiveMCPMessage(t, output))["result"].(map[string]any)["structuredContent"].(map[string]any)
	failure := cancelled["error"].(map[string]any)
	if failure["code"] != "await_cancelled" || failure["retryable"] != true {
		t.Fatalf("cancelled await_review = %#v", cancelled)
	}
	select {
	case err := <-backend.runReviewCancelled:
		t.Fatalf("observer cancellation reached review execution: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(backend.runReviewRelease)
	writeMCPMessage(t, input, latestRequest(4, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"`+invocationID+`"}}`))
	terminal := decodeResponse(t, receiveMCPMessage(t, output))["result"].(map[string]any)["structuredContent"].(map[string]any)
	if terminal["outcome"] != toolOutcomeSuccess || terminal["data"].(map[string]any)["invocation_id"] != invocationID {
		t.Fatalf("terminal await_review = %#v", terminal)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if backend.runReviewCalls != 1 {
		t.Fatalf("lifecycle review executions = %d, want 1", backend.runReviewCalls)
	}
}

func TestServeEOFDrainsActiveLifecycleReview(t *testing.T) {
	backend := &toolBackendFake{
		runReviewStarted:   make(chan struct{}),
		runReviewCancelled: make(chan error, 1),
		runReviewFinished:  make(chan struct{}),
	}
	reader, input := io.Pipe()
	output := make(chan []byte, 2)
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, toolTestConfig(t, backend))
	}()

	writeMCPMessage(t, input, latestRequest(1, "server/discover", `{}`))
	_ = receiveMCPMessage(t, output)
	writeMCPMessage(t, input, latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"}}}`))
	_ = receiveMCPMessage(t, output)
	select {
	case <-backend.runReviewStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lifecycle review start")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-backend.runReviewCancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MCP shutdown did not cancel the active lifecycle review")
	}
	select {
	case err := <-done:
		t.Fatalf("MCP shutdown returned before the lifecycle review finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(backend.runReviewFinished)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MCP shutdown did not drain the active lifecycle review")
	}
	if backend.runReviewCalls != 1 {
		t.Fatalf("lifecycle review executions = %d, want 1", backend.runReviewCalls)
	}
}

func TestServeAwaitReviewRejectsUnknownInvocation(t *testing.T) {
	backend := &toolBackendFake{}
	discover := latestRequest(1, "server/discover", `{}`)
	await := latestRequest(2, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	response := decodeResponse(t, serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, await)[1])
	structured := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	failure := structured["error"].(map[string]any)
	if failure["code"] != "invocation_not_found" || failure["retryable"] != false || backend.runReviewCalls != 0 {
		t.Fatalf("unknown await_review = %#v", structured)
	}
}

func TestServeToolFailuresAreTypedAndRedacted(t *testing.T) {
	secret := "private native path /Users/example/secret"
	failure, err := domain.NewFailure("query.read", domain.FailureArtifact, secret, errors.New(secret))
	if err != nil {
		t.Fatal(err)
	}
	backend := &toolBackendFake{getRunErr: failure}
	discover := latestRequest(1, "server/discover", `{}`)
	invalid := latestRequest(2, "tools/call", `{"name":"get_run","arguments":{"run_id":"invalid"}}`)
	failed := latestRequest(3, "tools/call", `{"name":"get_run","arguments":{"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, invalid, failed)

	assertToolFailure := func(raw []byte, class, code string) {
		t.Helper()
		result := decodeResponse(t, raw)["result"].(map[string]any)
		if result["isError"] != true {
			t.Fatalf("tool failure isError = %v", result["isError"])
		}
		structured := result["structuredContent"].(map[string]any)
		failure := structured["error"].(map[string]any)
		if structured["outcome"] != toolOutcomeError || failure["class"] != class || failure["code"] != code {
			t.Fatalf("tool failure = %#v", structured)
		}
		if strings.Contains(string(raw), secret) {
			t.Fatalf("tool failure leaks private error: %s", raw)
		}
	}
	assertToolFailure(responses[1], "usage", "invalid_arguments")
	assertToolFailure(responses[2], "artifact", "artifact_unavailable")
	if backend.getRunCalls != 1 {
		t.Fatalf("get_run calls = %d, want only the admitted call", backend.getRunCalls)
	}
}

func TestServeRunReviewPreservesRequestChangesOutcome(t *testing.T) {
	backend := &toolBackendFake{runReviewOutcome: toolOutcomeRequestChanges}
	discover := latestRequest(1, "server/discover", `{}`)
	call := latestRequest(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"},"roles":["logic"]}}`)
	responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, call)

	result := decodeResponse(t, responses[1])["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	if structured["outcome"] != toolOutcomeRequestChanges || result["isError"] != nil || backend.runReviewCalls != 1 {
		t.Fatalf("run_review result = %#v, calls = %d", result, backend.runReviewCalls)
	}
}

func TestServeRunReviewFailurePreservesAllocatedIdentityWithoutRetry(t *testing.T) {
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	timeout, err := domain.NewFailure("provider.execute", domain.FailureTimeout, "private provider failure", errors.New("private provider output"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &toolBackendFake{runReviewErr: reviewrun.NewAllocatedRunIdentityError(sessionID, runID, timeout)}
	discover := latestRequest(1, "server/discover", `{}`)
	call := latestRequest(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"},"roles":["logic"]}}`)
	response := decodeResponse(t, serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, call)[1])
	result := response["result"].(map[string]any)
	structured := result["structuredContent"].(map[string]any)
	failure := structured["error"].(map[string]any)
	if failure["session_id"] != sessionID.String() || failure["run_id"] != runID.String() || failure["retryable"] != false {
		t.Fatalf("run_review failure = %#v", structured)
	}
	if strings.Contains(string(response["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)), "private") {
		t.Fatalf("run_review failure leaked private details: %#v", structured)
	}
}

func TestServeAwaitReviewPreservesTerminalFailureIdentity(t *testing.T) {
	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}
	timeout, err := domain.NewFailure("provider.execute", domain.FailureTimeout, "private", errors.New("private provider output"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &toolBackendFake{runReviewErr: reviewrun.NewAllocatedRunIdentityError(sessionID, runID, timeout)}
	config := toolTestConfigWithIDs(t, backend,
		"i_019f596a-cf80-7c67-b265-f37053d51ccf",
		"i_019f596a-cf81-7c67-b265-f37053d51ccf",
	)
	discover := latestRequest(1, "server/discover", `{}`)
	start := latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"}}}`)
	await := latestRequest(3, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`)
	response := decodeResponse(t, serveRequestsWithConfig(t, config, discover, start, await)[2])
	structured := response["result"].(map[string]any)["structuredContent"].(map[string]any)
	failure := structured["error"].(map[string]any)
	if failure["class"] != "readiness" || failure["session_id"] != sessionID.String() ||
		failure["run_id"] != runID.String() || failure["retryable"] != false {
		t.Fatalf("terminal await failure = %#v", structured)
	}
	if strings.Contains(string(response["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)), "private") {
		t.Fatalf("terminal await leaked private details: %#v", structured)
	}
}

func TestServeRunReviewSendsProgressOnlyWhenRequested(t *testing.T) {
	backend := &toolBackendFake{}
	reader, input := io.Pipe()
	output := make(chan []byte, 4)
	done := make(chan error, 1)
	config := toolTestConfig(t, backend)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, config)
	}()
	if _, err := io.WriteString(input, latestRequest(1, "server/discover", `{}`)); err != nil {
		t.Fatal(err)
	}
	receiveMCPMessage(t, output)
	call := latestRequestWithProgress(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"}}}`, "review-progress")
	if _, err := io.WriteString(input, call); err != nil {
		t.Fatal(err)
	}

	first := decodeResponse(t, receiveMCPMessage(t, output))
	second := decodeResponse(t, receiveMCPMessage(t, output))
	response := decodeResponse(t, receiveMCPMessage(t, output))
	for index, notification := range []map[string]any{first, second} {
		if notification["method"] != "notifications/progress" {
			t.Fatalf("message %d = %#v, want progress notification", index, notification)
		}
		params := notification["params"].(map[string]any)
		if params["progressToken"] != "review-progress" || params["progress"] != float64(index) {
			t.Fatalf("progress %d = %#v", index, params)
		}
	}
	if response["id"] != float64(2) || response["result"] == nil || backend.runReviewCalls != 1 {
		t.Fatalf("run_review response = %#v, calls = %d", response, backend.runReviewCalls)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP shutdown")
	}
}

func TestServeInvalidRunReviewDoesNotClaimProgressAdmission(t *testing.T) {
	backend := &toolBackendFake{}
	discover := latestRequest(1, "server/discover", `{}`)
	call := latestRequestWithProgress(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"stdin"}}}`, "review-progress")
	response := decodeResponse(t, serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, call)[1])
	result := response["result"].(map[string]any)
	if result["isError"] != true || backend.runReviewCalls != 0 {
		t.Fatalf("invalid run_review response = %#v, calls = %d", response, backend.runReviewCalls)
	}
}

func TestServeRunReviewCancellationReachesBackendContext(t *testing.T) {
	backend := &toolBackendFake{runReviewStarted: make(chan struct{}), runReviewCancelled: make(chan error, 1)}
	reader, input := io.Pipe()
	output := make(chan []byte, 4)
	done := make(chan error, 1)
	config := toolTestConfig(t, backend)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, config)
	}()
	if _, err := io.WriteString(input, latestRequest(1, "server/discover", `{}`)); err != nil {
		t.Fatal(err)
	}
	receiveMCPMessage(t, output)
	if _, err := io.WriteString(input, latestRequest(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"}}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.runReviewStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for review start")
	}
	if _, err := io.WriteString(input, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"operator cancelled"}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-backend.runReviewCancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("backend cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for backend cancellation")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP shutdown")
	}
}

func TestServeParentCancellationCancelsActiveRunReview(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := &toolBackendFake{runReviewStarted: make(chan struct{}), runReviewCancelled: make(chan error, 1)}
	reader, input := io.Pipe()
	t.Cleanup(func() { _ = input.Close() })
	output := make(chan []byte, 2)
	done := make(chan error, 1)
	config := toolTestConfig(t, backend)
	go func() {
		done <- Serve(ctx, reader, channelWriter{output: output}, config)
	}()
	if _, err := io.WriteString(input, latestRequest(1, "server/discover", `{}`)); err != nil {
		t.Fatal(err)
	}
	receiveMCPMessage(t, output)
	if _, err := io.WriteString(input, latestRequest(2, "tools/call", `{"name":"run_review","arguments":{"target":{"kind":"workspace"}}}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.runReviewStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for review start")
	}

	cancel()
	select {
	case err := <-backend.runReviewCancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("backend cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parent cancellation did not reach active review")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for parent-cancelled MCP shutdown")
	}
}

func TestServePreflightAndBoundedResourceTemplates(t *testing.T) {
	uri := "mulgae://runs/r_019f596a-cf80-7c67-b265-f37053d51ccf/report"
	backend := &toolBackendFake{resource: ResourceContent{
		MIMEType: "text/markdown", Bytes: []byte("# Review\n"), Text: true,
	}}
	requests := []string{
		latestRequest(1, "server/discover", `{}`),
		latestRequest(2, "tools/call", `{"name":"preflight_review","arguments":{"target":{"kind":"stage"}}}`),
		latestRequest(3, "resources/templates/list", `{}`),
		latestRequest(4, "resources/read", `{"uri":"`+uri+`"}`),
	}
	responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), requests...)
	preflight := decodeResponse(t, responses[1])["result"].(map[string]any)["structuredContent"].(map[string]any)
	if preflight["tool"] != toolPreflight || preflight["outcome"] != toolOutcomeSuccess || backend.preflightCalls != 1 {
		t.Fatalf("preflight result = %#v, calls = %d", preflight, backend.preflightCalls)
	}
	templates := decodeResponse(t, responses[2])["result"].(map[string]any)["resourceTemplates"].([]any)
	if len(templates) != 2 || templates[0].(map[string]any)["uriTemplate"] != evidenceResourceTemplate ||
		templates[1].(map[string]any)["uriTemplate"] != reportResourceTemplate {
		t.Fatalf("resource templates = %#v", templates)
	}
	contents := decodeResponse(t, responses[3])["result"].(map[string]any)["contents"].([]any)
	if len(contents) != 1 || contents[0].(map[string]any)["text"] != "# Review\n" || backend.resourceCalls != 1 {
		t.Fatalf("resource contents = %#v, calls = %d", contents, backend.resourceCalls)
	}
}

func TestServeResourceFailureIsTypedBoundedAndNonReflective(t *testing.T) {
	secret := "/Users/private/project?token=secret"
	failure, err := domain.NewFailure("query.resource", domain.FailureArtifact, secret, errors.New(secret))
	if err != nil {
		t.Fatal(err)
	}
	backend := &toolBackendFake{resourceErr: failure}
	discover := latestRequest(1, "server/discover", `{}`)
	read := latestRequest(2, "resources/read", `{"uri":"mulgae://runs/r_019f596a-cf80-7c67-b265-f37053d51ccf/report"}`)
	response := serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, read)[1]
	decoded := decodeResponse(t, response)
	resourceError := decoded["error"].(map[string]any)
	if resourceError["code"] != float64(jsonrpc.CodeInvalidParams) || strings.Contains(string(response), secret) {
		t.Fatalf("resource error = %s", response)
	}
	data := resourceError["data"].(map[string]any)
	if data["class"] != "artifact" || data["code"] != "artifact_unavailable" {
		t.Fatalf("resource error data = %#v", data)
	}
}

func TestServeMalformedResourceURIPreservesConfigurationRejection(t *testing.T) {
	backend := &toolBackendFake{}
	discover := latestRequest(1, "server/discover", `{}`)
	read := latestRequest(2, "resources/read", `{"uri":"mulgae://runs/r_019f596a-cf80-7c67-b265-f37053d51ccf/report?offset=01"}`)
	response := serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, read)[1]
	decoded := decodeResponse(t, response)
	resourceError := decoded["error"].(map[string]any)
	data := resourceError["data"].(map[string]any)
	if resourceError["code"] != float64(jsonrpc.CodeInvalidParams) || data["class"] != "usage" ||
		data["code"] != "configuration_rejected" || backend.resourceCalls != 0 {
		t.Fatalf("malformed resource error = %s, calls = %d", response, backend.resourceCalls)
	}
}

func TestServeReadsEvidenceResourceTemplateWithQueryBinding(t *testing.T) {
	uri := "mulgae://runs/r_019f596a-cf80-7c67-b265-f37053d51ccf/findings/F001/evidence?target_sha256=sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	backend := &toolBackendFake{resource: ResourceContent{
		MIMEType: "application/octet-stream", Bytes: []byte{0x00, 0xff, 0x01},
	}}
	discover := latestRequest(1, "server/discover", `{}`)
	read := latestRequest(2, "resources/read", `{"uri":"`+uri+`"}`)
	response := decodeResponse(t, serveRequestsWithConfig(t, toolTestConfig(t, backend), discover, read)[1])
	contents := response["result"].(map[string]any)["contents"].([]any)
	if len(contents) != 1 || contents[0].(map[string]any)["blob"] != "AP8B" {
		t.Fatalf("evidence resource = %#v", contents)
	}
}

func TestResourceResultRejectsAmbiguousOrUnboundedContent(t *testing.T) {
	uri := "mulgae://runs/r_019f596a-cf80-7c67-b265-f37053d51ccf/report"
	base := ResourceResult{URI: uri, MIMEType: "text/markdown", Text: "ok", Meta: map[string]any{"io.mulgae/offset": 0}}
	if err := base.validate(uri); err != nil {
		t.Fatalf("valid resource result = %v", err)
	}
	for name, mutate := range map[string]func(*ResourceResult){
		"URI mismatch": func(result *ResourceResult) { result.URI += "?offset=1" },
		"both forms":   func(result *ResourceResult) { result.Blob = []byte("duplicate") },
		"empty": func(result *ResourceResult) {
			result.Text = ""
		},
		"oversized": func(result *ResourceResult) {
			result.Text = strings.Repeat("x", MaxResourceChunkBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.validate(uri); err == nil {
				t.Fatal("invalid resource result was accepted")
			}
		})
	}
}

func TestToolAdmissionRejectsAmbiguousOrUnboundedArguments(t *testing.T) {
	tests := []RunReviewInput{
		{Target: ReviewTarget{Kind: "stdin"}},
		{Target: ReviewTarget{Kind: "workspace", Value: "unexpected"}},
		{Target: ReviewTarget{Kind: "diff"}},
		{Target: ReviewTarget{Kind: "patch", Value: "change.patch"}, Roles: []string{"logic", "logic"}},
		{Target: ReviewTarget{Kind: "stage"}, Objective: strings.Repeat("x", 4097)},
	}
	for _, input := range tests {
		if err := validateRunReviewInput(input); !errors.Is(err, errInvalidToolArguments) {
			t.Fatalf("validateRunReviewInput(%#v) = %v", input, err)
		}
	}
	var decoded GetRunInput
	if err := decodeArguments(json.RawMessage(`{"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","unknown":true}`), &decoded); !errors.Is(err, errInvalidToolArguments) {
		t.Fatalf("unknown argument error = %v", err)
	}
	if err := decodeArguments(json.RawMessage(`{"run_id":"`+strings.Repeat("x", maxToolArgumentsBytes)+`"}`), &decoded); !errors.Is(err, errInvalidToolArguments) {
		t.Fatalf("oversized argument error = %v", err)
	}
}

func TestPublicToolErrorUsesFailurePrecedenceBeforeCancellation(t *testing.T) {
	unavailable := publicToolError(fmt.Errorf("query failed: %w", ErrRunStatusUnavailable), toolGetRun)
	if unavailable.Class != "artifact" || unavailable.Code != "run_status_unavailable" || unavailable.Stage != "query" || unavailable.Retryable {
		t.Fatalf("unavailable run status failure = %#v", unavailable)
	}
	artifact, err := domain.NewFailure("query.read", domain.FailureArtifact, "artifact failed", errors.New("private"))
	if err != nil {
		t.Fatal(err)
	}
	failure := publicToolError(errors.Join(context.Canceled, artifact), toolGetRun)
	if failure.Class != "artifact" || failure.Code != "artifact_unavailable" || failure.Stage != "query" {
		t.Fatalf("public failure = %#v", failure)
	}
	cancelled := publicToolError(context.Canceled, toolRunReview)
	if cancelled.Class != "cancellation" || cancelled.Stage != "execution" {
		t.Fatalf("cancelled failure = %#v", cancelled)
	}
	awaitCancelled := publicToolError(context.DeadlineExceeded, toolAwaitReview)
	if awaitCancelled.Class != "cancellation" || awaitCancelled.Code != "await_cancelled" ||
		awaitCancelled.Stage != "query" || !awaitCancelled.Retryable {
		t.Fatalf("cancelled await = %#v", awaitCancelled)
	}
	endedAwait := publicToolError(errInvocationRegistryClosed, toolAwaitReview)
	if endedAwait.Code != "invocation_registry_closed" || endedAwait.Stage != "transport" || endedAwait.Retryable {
		t.Fatalf("ended-session await = %#v", endedAwait)
	}
	timeout, err := domain.NewFailure("provider.execute", domain.FailureTimeout, "private", errors.New("private"))
	if err != nil {
		t.Fatal(err)
	}
	runFailure := publicToolError(timeout, toolRunReview)
	if runFailure.Retryable || runFailure.SessionID != nil || runFailure.RunID != nil {
		t.Fatalf("unidentified run failure = %#v", runFailure)
	}
	preflightFailure := publicToolError(timeout, toolPreflight)
	if !preflightFailure.Retryable || preflightFailure.SessionID != nil || preflightFailure.RunID != nil {
		t.Fatalf("read-only preflight failure = %#v", preflightFailure)
	}
}

func testConfig() Config {
	return Config{Name: "mulgae", Version: "test", ProjectRoot: "/work/project"}
}

func serveRequest(t *testing.T, request string) []byte {
	t.Helper()
	return serveRequests(t, request)[0]
}

func serveRequests(t *testing.T, requests ...string) [][]byte {
	t.Helper()
	return serveRequestsWithConfig(t, testConfig(), requests...)
}

func serveRequestsWithConfig(t *testing.T, config Config, requests ...string) [][]byte {
	t.Helper()
	reader, input := io.Pipe()
	output := make(chan []byte, len(requests))
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), reader, channelWriter{output: output}, config)
	}()
	responses := make([][]byte, 0, len(requests))
	for _, request := range requests {
		if _, err := io.WriteString(input, request); err != nil {
			t.Fatal(err)
		}
		select {
		case raw := <-output:
			responses = append(responses, raw)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for MCP response")
		}
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP shutdown")
	}
	return responses
}

func latestRequest(id int, method, params string) string {
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	if params == `{}` {
		params = `{` + meta + `}`
	} else {
		params = strings.TrimSuffix(params, `}`) + `,` + meta + `}`
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`+"\n", id, method, params)
}

func latestRequestWithProgress(id int, method, params, token string) string {
	meta := `"_meta":{"progressToken":` + fmt.Sprintf("%q", token) + `,"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	params = strings.TrimSuffix(params, `}`) + `,` + meta + `}`
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`+"\n", id, method, params)
}

func receiveMCPMessage(t *testing.T, output <-chan []byte) []byte {
	t.Helper()
	select {
	case message := <-output:
		return message
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for MCP message")
		return nil
	}
}

func writeMCPMessage(t *testing.T, input io.Writer, message string) {
	t.Helper()
	if _, err := io.WriteString(input, message); err != nil {
		t.Fatal(err)
	}
}

func toolTestConfig(t *testing.T, backend Backend) Config {
	return toolTestConfigWithIDs(t, backend, "i_019f596a-cf80-7c67-b265-f37053d51ccf")
}

func toolTestConfigWithIDs(t *testing.T, backend Backend, ids ...string) Config {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	schema, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "schemas", "mulgae-mcp-tool-result.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	config.Backend = backend
	var mu sync.Mutex
	next := 0
	config.NewRequestID = func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 1 {
			return ids[0], nil
		}
		if next >= len(ids) {
			return "", errors.New("test request IDs exhausted")
		}
		id := ids[next]
		next++
		return id, nil
	}
	config.ToolResultSchema = schema
	return config
}

type toolBackendFake struct {
	runReviewOutcome   string
	runReviewErr       error
	runReviewCalls     int
	runReviewStarted   chan struct{}
	runReviewRelease   chan struct{}
	runReviewCancelled chan error
	runReviewFinished  chan struct{}
	preflightCalls     int
	getRunData         map[string]any
	getRunErr          error
	getRunCalls        int
	resource           ResourceContent
	resourceErr        error
	resourceCalls      int
}

func (fake *toolBackendFake) RunReview(ctx context.Context, _ string, _ RunReviewInput) (BackendResult, error) {
	fake.runReviewCalls++
	if fake.runReviewStarted != nil {
		close(fake.runReviewStarted)
		if fake.runReviewRelease != nil {
			select {
			case <-fake.runReviewRelease:
				return BackendResult{Outcome: toolOutcomeSuccess, Data: map[string]any{"run_id": "r_019f596a-cf80-7c67-b265-f37053d51ccf"}}, nil
			case <-ctx.Done():
			}
		} else {
			<-ctx.Done()
		}
		if fake.runReviewCancelled != nil {
			fake.runReviewCancelled <- ctx.Err()
		}
		if fake.runReviewFinished != nil {
			<-fake.runReviewFinished
		}
		return BackendResult{}, ctx.Err()
	}
	if fake.runReviewErr != nil {
		return BackendResult{}, fake.runReviewErr
	}
	outcome := fake.runReviewOutcome
	if outcome == "" {
		outcome = toolOutcomeSuccess
	}
	return BackendResult{Outcome: outcome, Data: map[string]any{"run_id": "r_019f596a-cf80-7c67-b265-f37053d51ccf"}}, nil
}

func (fake *toolBackendFake) PreflightReview(context.Context, string, RunReviewInput) (BackendResult, error) {
	fake.preflightCalls++
	return BackendResult{Outcome: toolOutcomeSuccess, Data: map[string]any{"status": "eligible"}}, nil
}

func (fake *toolBackendFake) ListRuns(context.Context, ListRunsInput) (map[string]any, error) {
	return map[string]any{"runs": []any{}, "next_cursor": nil, "omitted_count": 0}, nil
}

func (fake *toolBackendFake) GetRun(context.Context, GetRunInput) (map[string]any, error) {
	fake.getRunCalls++
	return cloneMap(fake.getRunData), fake.getRunErr
}

func (fake *toolBackendFake) ListFindings(context.Context, ListFindingsInput) (map[string]any, error) {
	return map[string]any{"findings": []any{}}, nil
}

func (fake *toolBackendFake) ReadResource(context.Context, ResourceRequest) (ResourceContent, error) {
	fake.resourceCalls++
	return fake.resource, fake.resourceErr
}

type channelWriter struct {
	output chan<- []byte
}

func (writer channelWriter) Write(value []byte) (int, error) {
	writer.output <- append([]byte(nil), value...)
	return len(value), nil
}

func decodeResponse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &response); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return response
}
