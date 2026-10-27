package mcpentry

import (
	"context"
	"testing"
)

type requirementsToolBackend struct {
	toolBackendFake
	input RunReviewInput
}

func (backend *requirementsToolBackend) PreflightReview(ctx context.Context, id string, input RunReviewInput) (BackendResult, error) {
	backend.input = input
	return backend.toolBackendFake.PreflightReview(ctx, id, input)
}

func TestRequirementsMCPPreflightPreservesLocalPathAndObjective(t *testing.T) {
	backend := &requirementsToolBackend{}
	responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "server/discover", `{}`), latestRequest(2, "tools/call", `{"name":"preflight_review","arguments":{"target":{"kind":"stage"},"requirements_path":"requirements.json","objective":"Preserve behavior.","roles":["logic"]}}`))
	result := decodeResponse(t, responses[1])["result"].(map[string]any)["structuredContent"].(map[string]any)
	if result["outcome"] != toolOutcomeSuccess || backend.preflightCalls != 1 || backend.input.RequirementsPath == nil || *backend.input.RequirementsPath != "requirements.json" || backend.input.Objective != "Preserve behavior." {
		t.Fatalf("MCP optional path admission: %+v", result)
	}
	request, err := NewReviewRequest(backend.input, "/fixture", "i_019f596a-cf80-7c67-b265-f37053d51ccf", true)
	path, present := request.RequirementsPath()
	if err != nil || !present || path != "requirements.json" {
		t.Fatalf("shared application request lost input: %v", err)
	}
}
