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
		"error data": func(result *ToolResult) {
			result.Data = map[string]any{"unexpected": true}
		},
		"incomplete failure identity": func(result *ToolResult) {
			result.Error.RunID = nil
		},
		"invalid failure identity": func(result *ToolResult) {
			invalid := "client-owned"
			result.Error.RunID = &invalid
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			if valid.Error != nil {
				failure := *valid.Error
				candidate.Error = &failure
			}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("tampered tool result was accepted")
			}
		})
	}
}
