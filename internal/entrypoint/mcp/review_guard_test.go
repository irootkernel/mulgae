package mcpentry

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
)

func TestReviewGuardValidationAndPublicFailure(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	bad := "invalid"
	for _, test := range []struct {
		name      string
		input     RunReviewInput
		preflight bool
		want      error
	}{
		{"unguarded", RunReviewInput{}, false, nil},
		{"paired", RunReviewInput{ExpectedProjectBinding: &d, ExpectedRequestDigest: &d}, false, nil},
		{"preflight", RunReviewInput{ExpectedProjectBinding: &d}, true, nil},
		{"half", RunReviewInput{ExpectedProjectBinding: &d}, false, reviewrun.ErrGuardIncomplete},
		{"invalid", RunReviewInput{ExpectedProjectBinding: &bad, ExpectedRequestDigest: &d}, false, reviewrun.ErrGuardInvalid},
		{"preflight request", RunReviewInput{ExpectedProjectBinding: &d, ExpectedRequestDigest: &d}, true, reviewrun.ErrGuardIncomplete},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateReviewGuard(test.input, test.preflight)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
			if err != nil {
				failure := publicToolError(err, toolRunReview)
				if failure.Code != test.want.Error() || failure.Class != "usage" {
					t.Fatalf("failure=%+v", failure)
				}
			}
		})
	}
}

func TestServePreservesReviewGuardsAcrossForegroundAndStart(t *testing.T) {
	binding := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	for _, tool := range []string{toolRunReview, toolStartReview} {
		t.Run(tool, func(t *testing.T) {
			backend := &toolBackendFake{}
			config := toolTestConfigWithIDs(t, backend,
				"i_019f596a-cf80-7c67-b265-f37053d51ccf",
				"i_019f596a-cf81-7c67-b265-f37053d51ccf")
			call := latestRequest(2, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":{"target":{"kind":"stage"},"expected_project_binding":%q,"expected_request_digest":%q}}`, tool, binding, digest))
			requests := []string{latestRequest(1, "server/discover", `{}`), call}
			if tool == toolStartReview {
				requests = append(requests, latestRequest(3, "tools/call", `{"name":"await_review","arguments":{"invocation_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf"}}`))
			}
			responses := serveRequestsWithConfig(t, config, requests...)
			terminal := decodeResponse(t, responses[len(responses)-1])["result"].(map[string]any)["structuredContent"].(map[string]any)
			if terminal["outcome"] != toolOutcomeSuccess {
				t.Fatalf("terminal = %#v", terminal)
			}
			actual := backend.runReviewInput
			if backend.runReviewCalls != 1 || actual.ExpectedProjectBinding == nil || *actual.ExpectedProjectBinding != binding || actual.ExpectedRequestDigest == nil || *actual.ExpectedRequestDigest != digest {
				t.Fatalf("guard transport lost: %+v, calls=%d", actual, backend.runReviewCalls)
			}
		})
	}
}
