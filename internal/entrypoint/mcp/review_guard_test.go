package mcpentry

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestPublicToolErrorPreservesLiveSourceReason(t *testing.T) {
	for _, test := range []struct {
		code  ports.LiveSourceErrorCode
		class string
	}{
		{ports.LiveSourceInvalid, "usage"},
		{ports.LiveSourceUnsafe, "security"},
		{ports.LiveSourceConflict, "usage"},
		{ports.LiveSourceRevision, "usage"},
		{ports.LiveSourceNoMergeBase, "usage"},
		{ports.LiveSourceUnavailable, "artifact"},
		{ports.LiveSourceUnsupported, "usage"},
	} {
		for _, tool := range []string{toolPreflight, toolRunReview, toolAwaitReview} {
			t.Run(tool+"/"+string(test.code), func(t *testing.T) {
				private := errors.New("/private/source: native Git diagnostics")
				source := ports.NewLiveSourceError(test.code, private)
				class, _ := reviewrun.LiveSourceFailureClass(test.code)
				wrapped, err := domain.NewFailure("review.source", class, "admission failed", source)
				if err != nil {
					t.Fatal(err)
				}
				for _, cause := range []error{source, wrapped} {
					failure := publicToolError(cause, tool)
					if failure.Code != string(test.code) || failure.Class != test.class || failure.Stage != "admission" || failure.Retryable ||
						!strings.Contains(failure.Message, "mulgae help workflows") || strings.Contains(failure.Message, "private") || strings.Contains(failure.Message, "native Git") {
						t.Fatalf("source reason lost or private cause exposed: %+v", failure)
					}
					if err := failure.validate(); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestPublicToolErrorLiveSourceReasonPreservesFailurePrecedence(t *testing.T) {
	source := ports.NewLiveSourceError(ports.LiveSourceRevision, errors.New("private revision"))
	for _, class := range []domain.FailureClass{domain.FailureSecurityPolicy, domain.FailureArtifact, domain.FailureInternal} {
		t.Run(string(class), func(t *testing.T) {
			competing, err := domain.NewFailure("review.cleanup", class, "private cause", nil)
			if err != nil {
				t.Fatal(err)
			}
			want := publicToolError(competing, toolRunReview)
			for _, joined := range []error{errors.Join(source, competing), errors.Join(competing, source)} {
				actual := publicToolError(joined, toolRunReview)
				if actual.Code != want.Code || actual.Class != want.Class || actual.Stage != want.Stage {
					t.Fatalf("source reason overrode stronger failure: got=%+v want=%+v", actual, want)
				}
			}
		})
	}
	unknown := ports.NewLiveSourceError("untrusted_code", errors.New("private cause"))
	if failure := publicToolError(unknown, toolRunReview); failure.Code != "internal_failure" {
		t.Fatalf("unknown source reason became public: %+v", failure)
	}
}

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
		{"independent binding", RunReviewInput{ExpectedProjectBinding: &d}, false, nil},
		{"preflight", RunReviewInput{ExpectedProjectBinding: &d}, true, nil},
		{"invalid", RunReviewInput{ExpectedProjectBinding: &bad}, false, reviewrun.ErrGuardInvalid},
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
	for _, tool := range []string{toolRunReview, toolStartReview} {
		t.Run(tool, func(t *testing.T) {
			backend := &toolBackendFake{}
			config := toolTestConfigWithIDs(t, backend,
				"i_019f596a-cf80-7c67-b265-f37053d51ccf",
				"i_019f596a-cf81-7c67-b265-f37053d51ccf")
			call := latestRequest(2, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":{"target":{"kind":"stage"},"expected_project_binding":%q}}`, tool, binding))
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
			if backend.runReviewCalls != 1 || actual.ExpectedProjectBinding == nil || *actual.ExpectedProjectBinding != binding {
				t.Fatalf("guard transport lost: %+v, calls=%d", actual, backend.runReviewCalls)
			}
		})
	}
}

func TestServeRejectsCaptureBoundRequestsBeforeProviderDispatch(t *testing.T) {
	for _, tool := range []string{toolRunReview, toolStartReview, toolPreflight} {
		t.Run(tool, func(t *testing.T) {
			backend := &toolBackendFake{}
			call := latestRequest(2, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":{"target":{"kind":"stage"},"expected_request_digest":%q}}`, tool, "sha256:"+strings.Repeat("a", 64)))
			responses := serveRequestsWithConfig(t, toolTestConfig(t, backend), latestRequest(1, "server/discover", `{}`), call)
			response := decodeResponse(t, responses[1])
			result, present := response["result"].(map[string]any)
			if !present || result["isError"] != true || backend.runReviewCalls != 0 || backend.preflightCalls != 0 {
				t.Fatalf("capture-bound request reached provider authority: %#v", response)
			}
		})
	}
}
