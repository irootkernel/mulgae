package mcpentry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestReviewToolTransportCharacterization(t *testing.T) {
	for _, tool := range []string{toolRunReview, toolPreflight, toolStartReview} {
		for _, test := range []struct {
			name, objective, binding, code string
			calls                          int
		}{
			{"at", strings.Repeat("x", 4096), "", "", 1},
			{"multibyte at", strings.Repeat("界", 1365) + "x", "", "", 1},
			{"over", strings.Repeat("x", 4097), "", "invalid_arguments", 0},
			{"multibyte over", strings.Repeat("界", 1366), "", "invalid_arguments", 0},
			{"binding before newline", "\n", "bad", "guard_invalid", 0},
			{"binding before flaglike", "--focus", "bad", "guard_invalid", 0},
			{"size before binding", strings.Repeat("x", 4097), "bad", "invalid_arguments", 0},
			{"empty", "", "", "", 1},
		} {
			t.Run(tool+"/"+test.name, func(t *testing.T) {
				backend := &toolBackendFake{}
				input := map[string]any{"target": map[string]any{"kind": "workspace"}, "objective": test.objective, "roles": []string{}}
				if test.binding != "" {
					input["expected_project_binding"] = test.binding
				}
				raw, err := json.Marshal(map[string]any{"name": tool, "arguments": input})
				if err != nil {
					t.Fatal(err)
				}
				responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "server/discover", `{}`), latestRequest(2, "tools/call", string(raw)))
				response := decodeResponse(t, responses[1])
				result := response["result"].(map[string]any)
				structured := result["structuredContent"].(map[string]any)
				if test.code != "" {
					want := map[string]any{"class": "usage", "code": test.code, "stage": "admission", "message": "The tool arguments are invalid.", "retryable": false, "session_id": nil, "run_id": nil}
					if test.code == "guard_invalid" {
						want["message"] = "Review admission rejected the request."
					}
					if structured["outcome"] != "error" || !reflect.DeepEqual(structured["error"], want) || structured["data"] != nil || result["isError"] != true {
						t.Fatalf("rejection=%#v", structured)
					}
				} else if structured["outcome"] != "success" || structured["error"] != nil {
					t.Fatalf("success=%#v", structured)
				}
				calls := backend.runReviewCalls + backend.preflightCalls
				if calls != test.calls {
					t.Fatalf("backend calls=%d want=%d", calls, test.calls)
				}
				if tool == toolRunReview && test.calls == 1 && (backend.runReviewInput.Target.Kind != "workspace" || backend.runReviewInput.Objective != test.objective || len(backend.runReviewInput.Roles) != 0) {
					t.Fatalf("input=%+v", backend.runReviewInput)
				}
			})
		}
	}
}

type startupStream struct{ calls int }

func (stream *startupStream) Read([]byte) (int, error) {
	stream.calls++
	return 0, errors.New("unexpected read")
}
func (stream *startupStream) Write(data []byte) (int, error) { stream.calls++; return len(data), nil }

func TestServePartialToolConfiguration(t *testing.T) {
	for mask := 1; mask < 7; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			backend := &toolBackendFake{}
			config := toolTestConfig(t, backend)
			if mask&1 == 0 {
				config.Backend = nil
			}
			if mask&2 == 0 {
				config.NewRequestID = nil
			}
			if mask&4 == 0 {
				config.ToolResultSchema = nil
			}
			stream := &startupStream{}
			err := Serve(context.Background(), stream, stream, config)
			if err == nil || err.Error() != "serve MCP: incomplete tool configuration" || stream.calls != 0 || backend.runReviewCalls+backend.preflightCalls != 0 {
				t.Fatalf("partial startup: err=%v stream=%d", err, stream.calls)
			}
		})
	}
}

func TestMCPRequestIdentityAdmission(t *testing.T) {
	for _, failure := range []bool{false, true} {
		for _, tool := range []string{toolRunReview, toolPreflight, toolStartReview, toolAwaitReview, toolCancelReview} {
			backend := &toolBackendFake{}
			config := toolTestConfig(t, backend)
			config.NewRequestID = func() (string, error) {
				if failure {
					return "", errors.New("private allocation cause")
				}
				return "i_malformed", nil
			}
			responses := serveRequestsWithConfig(t, config, latestRequest(1, "server/discover", `{}`), latestRequest(2, "tools/call", `{"name":"`+tool+`","arguments":{}}`))
			response := decodeResponse(t, responses[1])
			want := map[string]any{"code": float64(jsonrpc.CodeInternalError), "message": "Mulgae request identity is unavailable"}
			if !reflect.DeepEqual(response["error"], want) || backend.runReviewCalls+backend.preflightCalls != 0 {
				t.Fatalf("identity admission: %#v", response)
			}
		}
	}
}

func TestMCPLifecycleAndResultBounds(t *testing.T) {
	t.Run("malformed IDs preserve active execution", testMalformedLifecyclePreservesExecution)
	for _, tool := range []string{toolAwaitReview, toolCancelReview} {
		backend := &toolBackendFake{}
		responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "server/discover", `{}`), latestRequest(2, "tools/call", `{"name":"`+tool+`","arguments":{"invocation_id":"i_malformed"}}`))
		result := decodeResponse(t, responses[1])["result"].(map[string]any)
		structured := result["structuredContent"].(map[string]any)
		failure := structured["error"].(map[string]any)
		if failure["code"] != "invalid_arguments" || failure["stage"] != "admission" || failure["class"] != "usage" || backend.runReviewCalls != 0 {
			t.Fatalf("lifecycle admission: %#v", structured)
		}
	}
	for _, tool := range []string{toolGetContext, toolInspectReview, toolListFindings} {
		limit := maxToolResultBytes
		if tool != toolGetContext {
			limit = maxFindingPageResultBytes
		}
		for _, delta := range []int{-1, 0, 1} {
			result := ToolResult{SchemaVersion: "mulgae-mcp-tool-result.v1", Tool: tool, RequestID: "i_019f596a-cf80-7c67-b265-f37053d51ccf", Outcome: "success", Data: map[string]any{"payload": ""}}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			result.Data["payload"] = strings.Repeat("x", limit+delta-len(raw))
			raw, err = json.Marshal(result)
			if err != nil || len(raw) != limit+delta {
				t.Fatalf("boundary fixture len=%d err=%v", len(raw), err)
			}
			projected, err := renderToolResult(result)
			if delta > 0 {
				var rpc *jsonrpc.Error
				if !errors.As(err, &rpc) || rpc.Code != jsonrpc.CodeInternalError || rpc.Message != "Mulgae tool result is unavailable" || projected != nil {
					t.Fatalf("oversized result=%v err=%v", projected, err)
				}
			} else if err != nil || projected == nil {
				t.Fatalf("bounded result rejected: %v", err)
			}
		}
	}
	// Exercise the exact encoded limits through the SDK too. Backend production
	// occurs once for every size, including the rejected oversized result.
	for _, tool := range []string{toolGetContext, toolInspectReview, toolListFindings} {
		limit, arguments := maxToolResultBytes, `{}`
		if tool != toolGetContext {
			limit = maxFindingPageResultBytes
			arguments = `{"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf"}`
		}
		for _, delta := range []int{-1, 0, 1} {
			empty := ToolResult{SchemaVersion: "mulgae-mcp-tool-result.v1", Tool: tool, RequestID: "i_019f596a-cf80-7c67-b265-f37053d51ccf", Outcome: "success", Data: map[string]any{"payload": ""}}
			raw, err := json.Marshal(empty)
			if err != nil {
				t.Fatal(err)
			}
			backend := &oversizedResultBackend{limit: limit + delta - len(raw)}
			responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "server/discover", `{}`), latestRequest(2, "tools/call", `{"name":"`+tool+`","arguments":`+arguments+`}`))
			response := decodeResponse(t, responses[1])
			if backend.calls != 1 {
				t.Fatalf("SDK backend calls=%d want=1", backend.calls)
			}
			if delta > 0 {
				want := map[string]any{"code": float64(jsonrpc.CodeInternalError), "message": "Mulgae tool result is unavailable"}
				if !reflect.DeepEqual(response["error"], want) {
					t.Fatalf("SDK rendering failure: %#v", response)
				}
			} else {
				result, ok := response["result"].(map[string]any)
				if !ok || response["error"] != nil || result["isError"] == true {
					t.Fatalf("SDK rejected bounded result: %#v", response)
				}
				structured := result["structuredContent"].(map[string]any)
				raw, err := json.Marshal(structured)
				content := result["content"].([]any)[0].(map[string]any)["text"].(string)
				if err != nil || len(raw) != limit+delta || len(content) != limit+delta || structured["outcome"] != "success" || structured["error"] != nil {
					t.Fatalf("SDK boundary %s delta=%d encoded=%d text=%d err=%v", tool, delta, len(raw), len(content), err)
				}
			}
		}
	}
}

func testMalformedLifecyclePreservesExecution(t *testing.T) {
	backend := &toolBackendFake{runReviewStarted: make(chan struct{}), runReviewCancelled: make(chan error, 1)}
	reader, input := io.Pipe()
	output := make(chan []byte, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, reader, channelWriter{output: output}, toolTestConfig(t, backend)) }()
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = reader.Close() })
	writeMCPMessage(t, input, latestRequest(1, "server/discover", `{}`))
	_ = receiveMCPMessage(t, output)
	writeMCPMessage(t, input, latestRequest(2, "tools/call", `{"name":"start_review","arguments":{"target":{"kind":"workspace"}}}`))
	start := decodeResponse(t, receiveMCPMessage(t, output))["result"].(map[string]any)["structuredContent"].(map[string]any)
	id := start["data"].(map[string]any)["invocation_id"].(string)
	select {
	case <-backend.runReviewStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("review did not start")
	}
	for index, tool := range []string{toolAwaitReview, toolCancelReview} {
		writeMCPMessage(t, input, latestRequest(3+index, "tools/call", `{"name":"`+tool+`","arguments":{"invocation_id":"malformed"}}`))
		result := decodeResponse(t, receiveMCPMessage(t, output))["result"].(map[string]any)["structuredContent"].(map[string]any)
		if result["outcome"] != "error" || result["error"].(map[string]any)["code"] != "invalid_arguments" || backend.runReviewCalls != 1 {
			t.Fatalf("malformed lifecycle call changed execution: %#v", result)
		}
		select {
		case err := <-backend.runReviewCancelled:
			t.Fatalf("malformed lifecycle call cancelled execution: %v", err)
		default:
		}
	}
	writeMCPMessage(t, input, latestRequest(5, "tools/call", `{"name":"cancel_review","arguments":{"invocation_id":"`+id+`"}}`))
	_ = receiveMCPMessage(t, output)
	select {
	case <-backend.runReviewCancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("positive cancellation control failed")
	}
	_ = input.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type oversizedResultBackend struct {
	toolBackendFake
	calls int
	limit int
}

func (backend *oversizedResultBackend) result() (map[string]any, error) {
	backend.calls++
	return map[string]any{"payload": strings.Repeat("x", backend.limit)}, nil
}

func (backend *oversizedResultBackend) GetContext(context.Context) (map[string]any, error) {
	return backend.result()
}
func (backend *oversizedResultBackend) ListFindings(context.Context, ListFindingsInput) (map[string]any, error) {
	return backend.result()
}
func (backend *oversizedResultBackend) InspectReview(context.Context, ListFindingsInput) (map[string]any, error) {
	return backend.result()
}
