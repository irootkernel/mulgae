package mcpentry

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type statusFailureBackend struct {
	toolBackendFake
	err   error
	calls int
}

func (backend *statusFailureBackend) GetRun(context.Context, GetRunInput) (map[string]any, error) {
	backend.calls++
	return nil, backend.err
}

func TestMCPStatusFailureCharacterization(t *testing.T) {
	security, _ := domain.NewFailure("test.status", domain.FailureSecurityPolicy, "private security cause", nil)
	artifact, _ := domain.NewFailure("test.status", domain.FailureArtifact, "private artifact cause", nil)
	for _, test := range []struct {
		name                        string
		err                         error
		class, code, stage, message string
	}{
		{"security sibling", errors.Join(ports.ErrPublicationRunNotFound, security), "security", "security_rejected", "admission", "Mulgae rejected the request at a security boundary."},
		{"artifact sibling", errors.Join(ports.ErrRuntimeDiagnosticRunNotFound, artifact), "artifact", "artifact_unavailable", "query", "The requested verified artifact is unavailable."},
		{"sole cancellation", fmt.Errorf("diagnostic: %w", context.Canceled), "cancellation", "request_cancelled", "query", "The tool request was cancelled."},
		{"raw", errors.New("private raw cause"), "internal", "internal_failure", "query", "Mulgae could not complete the tool request."},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &statusFailureBackend{err: test.err}
			responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "tools/call", `{"name":"get_run","arguments":{"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf"}}`))
			result := decodeResponse(t, responses[0])["result"].(map[string]any)
			want := map[string]any{"schema_version": "mulgae-mcp-tool-result.v1", "tool": "get_run", "request_id": "i_019f596a-cf80-7c67-b265-f37053d51ccf", "outcome": "error", "data": nil, "error": map[string]any{"class": test.class, "code": test.code, "stage": test.stage, "message": test.message, "retryable": false, "session_id": nil, "run_id": nil}}
			if !reflect.DeepEqual(result["structuredContent"], want) || result["isError"] != true || backend.calls != 1 {
				t.Fatalf("public status error drift: %#v calls=%d", result, backend.calls)
			}
		})
	}
}
