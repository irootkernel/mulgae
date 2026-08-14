package mcpentry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestToolResultExampleIsSemanticallyValidAndTamperingFailsClosed(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "builtin", "assets", "examples", "mcp-tool-result.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var valid ToolResult
	if err := json.Unmarshal(raw, &valid); err != nil {
		t.Fatal(err)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid example: %v", err)
	}

	for name, mutate := range map[string]func(*ToolResult){
		"request identity": func(result *ToolResult) { result.RequestID = "client-owned" },
		"tool name":        func(result *ToolResult) { result.Tool = "PreflightReview" },
		"success error": func(result *ToolResult) {
			result.Error = &ToolError{Class: "internal", Code: "unexpected", Stage: "execution", Message: "Unexpected failure."}
		},
		"error data": func(result *ToolResult) {
			result.Outcome = "error"
			result.Error = &ToolError{Class: "internal", Code: "unexpected", Stage: "execution", Message: "Unexpected failure."}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("tampered tool result was accepted")
			}
		})
	}
}
