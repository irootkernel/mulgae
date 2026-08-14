package mcpentry

import (
	"fmt"
	"regexp"
	"strings"
)

const toolResultSchemaVersion = "mulgae-mcp-tool-result.v1"

const (
	toolOutcomeSuccess        = "success"
	toolOutcomeRequestChanges = "request_changes"
	toolOutcomeError          = "error"
)

// ToolResult is the common structured-content envelope for Mulgae MCP tools.
type ToolResult struct {
	SchemaVersion string         `json:"schema_version"`
	Tool          string         `json:"tool"`
	RequestID     string         `json:"request_id"`
	Outcome       string         `json:"outcome"`
	Data          map[string]any `json:"data"`
	Error         *ToolError     `json:"error"`
}

// ToolError is a bounded, typed MCP tool failure without native paths or raw
// provider output.
type ToolError struct {
	Class     string `json:"class"`
	Code      string `json:"code"`
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Validate enforces the semantic relationships in the public tool envelope.
func (result ToolResult) Validate() error {
	if result.SchemaVersion != toolResultSchemaVersion {
		return fmt.Errorf("MCP tool result: invalid schema version")
	}
	if !matches(`^[a-z][a-z0-9_]{0,63}$`, result.Tool) {
		return fmt.Errorf("MCP tool result: invalid tool name")
	}
	if !matches(`^i_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, result.RequestID) {
		return fmt.Errorf("MCP tool result: invalid request ID")
	}
	switch result.Outcome {
	case toolOutcomeSuccess, toolOutcomeRequestChanges:
		if result.Data == nil || result.Error != nil {
			return fmt.Errorf("MCP tool result: successful outcome has invalid payload")
		}
	case toolOutcomeError:
		if result.Data != nil || result.Error == nil {
			return fmt.Errorf("MCP tool result: error outcome has invalid payload")
		}
		if err := result.Error.validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("MCP tool result: invalid outcome")
	}
	return nil
}

func newToolSuccess(tool, requestID, outcome string, data map[string]any) (ToolResult, error) {
	result := ToolResult{
		SchemaVersion: toolResultSchemaVersion,
		Tool:          tool,
		RequestID:     requestID,
		Outcome:       outcome,
		Data:          cloneMap(data),
	}
	if err := result.Validate(); err != nil {
		return ToolResult{}, err
	}
	return result, nil
}

func newToolFailure(tool, requestID string, failure ToolError) (ToolResult, error) {
	result := ToolResult{
		SchemaVersion: toolResultSchemaVersion,
		Tool:          tool,
		RequestID:     requestID,
		Outcome:       toolOutcomeError,
		Error:         &failure,
	}
	if err := result.Validate(); err != nil {
		return ToolResult{}, err
	}
	return result, nil
}

func (failure ToolError) validate() error {
	if !oneOf(failure.Class, "usage", "policy", "readiness", "artifact", "security", "cancellation", "internal") {
		return fmt.Errorf("MCP tool error: invalid class")
	}
	if !matches(`^[a-z][a-z0-9_]{0,63}$`, failure.Code) {
		return fmt.Errorf("MCP tool error: invalid code")
	}
	if !oneOf(failure.Stage, "admission", "execution", "validation", "publication", "query", "transport") {
		return fmt.Errorf("MCP tool error: invalid stage")
	}
	if strings.TrimSpace(failure.Message) == "" || len(failure.Message) > 512 {
		return fmt.Errorf("MCP tool error: invalid message")
	}
	return nil
}

func matches(pattern, value string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

func oneOf(value string, permitted ...string) bool {
	for _, candidate := range permitted {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	destination := make(map[string]any, len(source))
	for key, value := range source {
		destination[key] = value
	}
	return destination
}
