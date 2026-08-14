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
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/irootkernel/mulgae/internal/domain"
)

func TestServeAdvertisesOnlyLatestProtocol(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	output := serveRequest(t, request)
	response := decodeResponse(t, output)
	result := response["result"].(map[string]any)
	versions := result["supportedVersions"].([]any)
	if len(versions) != 1 || versions[0] != ProtocolVersion {
		t.Fatalf("supported versions = %#v, want [%q]", versions, ProtocolVersion)
	}
	if _, present := result["capabilities"].(map[string]any)["logging"]; present {
		t.Fatal("latest server unexpectedly advertises deprecated logging capability")
	}
	if strings.Contains(string(output), "level=") {
		t.Fatalf("stdout contains non-protocol logging: %q", output)
	}
}

func TestServeRejectsLegacyInitializeWithSupportedVersion(t *testing.T) {
	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}` + "\n"
	response := decodeResponse(t, serveRequest(t, request))
	errorValue := response["error"].(map[string]any)
	if errorValue["code"] != float64(mcpsdk.CodeUnsupportedProtocolVersion) {
		t.Fatalf("error code = %v, want %d; response %#v", errorValue["code"], mcpsdk.CodeUnsupportedProtocolVersion, response)
	}
	data := errorValue["data"].(map[string]any)
	versions := data["supported"].([]any)
	if len(versions) != 1 || versions[0] != ProtocolVersion || data["requested"] != "2025-11-25" {
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
	if strings.Join(names, ",") != "get_run,list_findings,list_runs,run_review" {
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

func toolTestConfig(t *testing.T, backend Backend) Config {
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
	config.NewRequestID = func() (string, error) { return "i_019f596a-cf80-7c67-b265-f37053d51ccf", nil }
	config.ToolResultSchema = schema
	return config
}

type toolBackendFake struct {
	runReviewOutcome string
	runReviewCalls   int
	getRunData       map[string]any
	getRunErr        error
	getRunCalls      int
}

func (fake *toolBackendFake) RunReview(context.Context, string, RunReviewInput) (BackendResult, error) {
	fake.runReviewCalls++
	outcome := fake.runReviewOutcome
	if outcome == "" {
		outcome = toolOutcomeSuccess
	}
	return BackendResult{Outcome: outcome, Data: map[string]any{"run_id": "r_019f596a-cf80-7c67-b265-f37053d51ccf"}}, nil
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
