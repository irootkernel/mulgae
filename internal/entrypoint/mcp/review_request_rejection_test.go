package mcpentry

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestReviewToolSelectorPrecedence(t *testing.T) {
	for _, tool := range []string{toolRunReview, toolPreflight, toolStartReview} {
		for _, test := range []struct{ name, kind, value, objective, binding string }{
			{"commit selector wins", "commit", " HEAD", "\n", "bad"},
			{"diff selector wins", "diff", "HEAD", "--focus", "bad"},
			{"selector before objective", "commit", " HEAD", "\n", ""},
			{"flaglike commit admitted by tool", "commit", "--bad", "focus", ""},
			{"flaglike diff admitted by tool", "diff", "--base..HEAD", "focus", ""},
			{"flaglike binding rejected publicly", "workspace", "", "focus", "--bad"},
		} {
			backend := &toolBackendFake{}
			input := map[string]any{"target": map[string]any{"kind": test.kind}, "objective": test.objective}
			if test.value != "" {
				input["target"].(map[string]any)["value"] = test.value
			}
			if test.binding != "" {
				input["expected_project_binding"] = test.binding
			}
			raw, err := json.Marshal(map[string]any{"name": tool, "arguments": input})
			if err != nil {
				t.Fatal(err)
			}
			responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "tools/call", string(raw)))
			result := decodeResponse(t, responses[0])["result"].(map[string]any)
			structured := result["structuredContent"].(map[string]any)
			calls := backend.runReviewCalls + backend.preflightCalls
			wantCalls := 0
			if test.name == "flaglike commit admitted by tool" || test.name == "flaglike diff admitted by tool" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("%s: backend calls=%d want=%d", test.name, calls, wantCalls)
			}
			if wantCalls == 1 {
				if structured["outcome"] != "success" || structured["error"] != nil {
					t.Fatalf("supported tool grammar changed: %#v", structured)
				}
				continue
			}
			code, message := "invalid_arguments", "The tool arguments are invalid."
			if test.name == "flaglike binding rejected publicly" {
				code, message = "guard_invalid", "Review admission rejected the request."
			}
			want := map[string]any{"schema_version": "mulgae-mcp-tool-result.v1", "tool": tool, "request_id": "i_019f596a-cf80-7c67-b265-f37053d51ccf", "outcome": "error", "data": nil, "error": map[string]any{"class": "usage", "code": code, "stage": "admission", "message": message, "retryable": false, "session_id": nil, "run_id": nil}}
			if !reflect.DeepEqual(structured, want) || result["isError"] != true {
				t.Fatalf("predecessor public rejection drift: %#v", result)
			}
		}
	}
}
