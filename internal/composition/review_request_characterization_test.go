//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

type requestCaptureService struct {
	calls, preflightCalls int
	request               mulgaeentry.ReviewRequest
}

func (service *requestCaptureService) capture(request mulgaeentry.ReviewRequest) error {
	service.request = request
	failure, _ := domain.NewFailure("test.capture", domain.FailureArtifact, "captured review request", nil)
	return failure
}
func (service *requestCaptureService) StartReviewRun(_ context.Context, request mulgaeentry.ReviewRequest, _ ports.AnchoredRoot) (mulgaeentry.ReviewRunResult, error) {
	service.calls++
	return mulgaeentry.ReviewRunResult{}, service.capture(request)
}
func (service *requestCaptureService) PreflightReview(_ context.Context, request mulgaeentry.ReviewRequest, _ ports.AnchoredRoot) (mulgaeentry.ReviewPreflightResult, error) {
	service.preflightCalls++
	return mulgaeentry.ReviewPreflightResult{}, service.capture(request)
}

func TestMCPReviewRequestMappingCompatibility(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		for _, target := range []mcpentry.ReviewTarget{{Kind: "workspace"}, {Kind: "stage"}, {Kind: "head"}, {Kind: "commit", Value: "HEAD"}, {Kind: "diff", Value: "main...HEAD"}} {
			for _, roles := range [][]string{nil, {}, {"testing", "logic"}} {
				root := mustMCPRoot(t, canonicalTestTempDir(t))
				artifact := mustMCPRoot(t, filepath.Join(root.String(), ".mulgae"))
				capture := &requestCaptureService{}
				backend, err := newMCPBoundTestBackend(root, artifact, newMCPTestApplicationWithReviewRuns(t, &mcpQueryFake{}, capture), &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
				if err != nil {
					t.Fatal(err)
				}
				input := mcpentry.RunReviewInput{Target: target, Roles: roles}
				execute := backend.RunReview
				if preflight {
					execute = backend.PreflightReview
				}
				_, err = execute(context.Background(), "i_019f596a-cf80-7c67-b265-f37053d51ccf", input)
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Stage() != "test.capture" || failure.Class() != domain.FailureArtifact || capture.calls+capture.preflightCalls != 1 {
					t.Fatalf("dispatch err=%v calls=%d/%d", err, capture.calls, capture.preflightCalls)
				}
				request := capture.request
				wantRoles := []string{"logic", "security", "maintainability", "product", "documentation", "testing"}
				if len(roles) != 0 {
					wantRoles = []string{"logic", "testing"}
				}
				objective, present := request.Objective()
				if request.Target().Kind() != target.Kind || request.Target().Value() != target.Value || request.Preflight() != preflight || request.RequestedRolesExplicit() != (len(roles) != 0) || !reflect.DeepEqual(request.Roles(), wantRoles) || present || objective != "" {
					t.Fatalf("mapped request=%+v", request)
				}
			}
		}
	}
	for _, preflight := range []bool{false, true} {
		for _, test := range []struct {
			name, objective, binding, id string
			wantStage                    string
		}{
			{"newline before binding", "\n", "bad", "i_019f596a-cf80-7c67-b265-f37053d51ccf", "mcp.admission"},
			{"flag before binding", "--focus", "bad", "i_019f596a-cf80-7c67-b265-f37053d51ccf", "mcp.admission"},
			{"malformed id", "focus", "", "i_bad", "mcp.admission"},
			{"binding", "focus", "bad", "i_019f596a-cf80-7c67-b265-f37053d51ccf", "mcp.admission"},
		} {
			root := mustMCPRoot(t, canonicalTestTempDir(t))
			artifact := mustMCPRoot(t, filepath.Join(root.String(), ".mulgae"))
			capture := &requestCaptureService{}
			backend, err := newMCPBoundTestBackend(root, artifact, newMCPTestApplicationWithReviewRuns(t, &mcpQueryFake{}, capture), &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
			if err != nil {
				t.Fatal(err)
			}
			input := mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "workspace"}, Objective: test.objective}
			if test.binding != "" {
				input.ExpectedProjectBinding = &test.binding
			}
			execute := backend.RunReview
			if preflight {
				execute = backend.PreflightReview
			}
			_, err = execute(context.Background(), test.id, input)
			var failure *domain.Failure
			if !errors.As(err, &failure) || failure.Class() != domain.FailureConfiguration || failure.Stage() != test.wantStage || capture.calls+capture.preflightCalls != 0 {
				t.Fatalf("%s: err=%v calls=%d/%d", test.name, err, capture.calls, capture.preflightCalls)
			}
			if test.objective != "focus" && errors.Is(err, reviewrun.ErrGuardInvalid) {
				t.Fatalf("binding masked objective syntax: %v", err)
			}
		}
	}
}
