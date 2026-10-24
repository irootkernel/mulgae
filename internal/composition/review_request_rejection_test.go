//go:build darwin && arm64

package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

const rejectionRequestID = "i_019f596a-cf80-7c67-b265-f37053d51ccf"

type reviewRejectionCase struct {
	phase       string
	name        string
	target      mcpentry.ReviewTarget
	objective   string
	binding     *string
	roles       []string
	id          string
	unavailable bool
	bound       bool
}

func reviewRejectionCases() []reviewRejectionCase {
	bad, flaglike, empty := "bad", "--bad", ""
	workspace := mcpentry.ReviewTarget{Kind: "workspace"}
	return []reviewRejectionCase{
		{phase: "target", name: "commit selector wins", target: mcpentry.ReviewTarget{Kind: "commit", Value: " HEAD"}, objective: "\n", binding: &bad},
		{phase: "target", name: "diff selector wins", target: mcpentry.ReviewTarget{Kind: "diff", Value: "HEAD"}, objective: "--focus", binding: &bad},
		{name: "flaglike commit operand", target: mcpentry.ReviewTarget{Kind: "commit", Value: "--bad"}, objective: "focus"},
		{name: "flaglike diff operand", target: mcpentry.ReviewTarget{Kind: "diff", Value: "--base..HEAD"}, objective: "focus"},
		{phase: "target", name: "unsupported target", target: mcpentry.ReviewTarget{Kind: "stdin"}},
		{name: "NUL objective", target: workspace, objective: "focus\x00", bound: true},
		{name: "CR objective", target: workspace, objective: "focus\r", bound: true},
		{name: "LF objective", target: workspace, objective: "focus\n"},
		{name: "flaglike objective", target: workspace, objective: "--focus"},
		{name: "objective over mapping bound", target: workspace, objective: strings.Repeat("x", 12001)},
		{name: "duplicate roles", target: workspace, roles: []string{"logic", "logic"}},
		{name: "unsupported role", target: workspace, roles: []string{"unknown"}},
		{name: "malformed request ID", target: workspace, id: "i_bad"},
		{phase: "guard", name: "invalid binding", target: workspace, binding: &bad},
		{phase: "guard", name: "empty binding", target: workspace, binding: &empty},
		{name: "flaglike binding", target: workspace, objective: "focus", binding: &flaglike},
		{phase: "backend", name: "unavailable backend", target: workspace, unavailable: true},
		{phase: "admitted", name: "admitted positive control", target: workspace, objective: "focus", bound: true},
	}
}

type rejectionCapture struct{ calls int }

func (capture *rejectionCapture) failure() error {
	capture.calls++
	failure, _ := domain.NewFailure("test.capture", domain.FailureArtifact, "captured review request", nil)
	return failure
}
func (capture *rejectionCapture) StartReviewRun(context.Context, mulgaeentry.ReviewRequest, ports.AnchoredRoot) (mulgaeentry.ReviewRunResult, error) {
	return mulgaeentry.ReviewRunResult{}, capture.failure()
}
func (capture *rejectionCapture) PreflightReview(context.Context, mulgaeentry.ReviewRequest, ports.AnchoredRoot) (mulgaeentry.ReviewPreflightResult, error) {
	return mulgaeentry.ReviewPreflightResult{}, capture.failure()
}

type rejectionObservation struct {
	Name      string
	Preflight bool
	Class     string
	Stage     string
	Reason    string
	Guard     bool
	Calls     int
	Public    mcpentry.ToolError
}

func observeReviewRejection(t *testing.T, test reviewRejectionCase, preflight bool) rejectionObservation {
	t.Helper()
	root := mustMCPRoot(t, canonicalTestTempDir(t))
	artifact := mustMCPRoot(t, filepath.Join(root.String(), ".mulgae"))
	capture := &rejectionCapture{}
	backend, err := newMCPBoundTestBackend(root, artifact, newMCPTestApplicationWithReviewRuns(t, &mcpQueryFake{}, capture), &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	if test.unavailable {
		backend.application = nil
	}
	input := mcpentry.RunReviewInput{Target: test.target, Objective: test.objective, ExpectedProjectBinding: test.binding, Roles: test.roles}
	if test.bound {
		project, err := backend.GetContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		binding := project["project_binding"].(string)
		input.ExpectedProjectBinding = &binding
	}
	execute := backend.RunReview
	if preflight {
		execute = backend.PreflightReview
	}
	id := test.id
	if id == "" {
		id = rejectionRequestID
	}
	_, err = execute(context.Background(), id, input)
	if err == nil {
		t.Fatal("expected characterization failure")
	}
	observed := rejectionObservation{Name: test.name, Preflight: preflight, Guard: errors.Is(err, reviewrun.ErrGuardInvalid), Calls: capture.calls}
	var failure *domain.Failure
	if errors.As(err, &failure) {
		observed.Class = string(failure.Class())
		observed.Stage = failure.Stage()
		observed.Reason = failure.Reason()
	} else {
		observed.Reason = err.Error()
	}
	observed.Public = projectReviewRejection(t, err, preflight)
	return observed
}

// Project the captured direct-call failure with valid public arguments. This
// observes its SDK envelope without claiming the rejected direct input can pass
// public admission.
func projectReviewRejection(t *testing.T, failure error, preflight bool) mcpentry.ToolError {
	t.Helper()
	backend := &rejectionProjectionBackend{failure: failure}
	result := callReviewRejectionTool(t, backend, preflight, mcpentry.RunReviewInput{Target: mcpentry.ReviewTarget{Kind: "workspace"}})
	if result.Outcome != "error" || result.Error == nil || backend.calls != 1 {
		t.Fatalf("failure projection: %+v calls=%d", result, backend.calls)
	}
	return *result.Error
}

func callReviewRejectionTool(t *testing.T, backend mcpentry.Backend, preflight bool, inputFields mcpentry.RunReviewInput) mcpentry.ToolResult {
	t.Helper()
	schema, err := os.ReadFile(filepath.Join("..", "builtin", "assets", "schemas", "mulgae-mcp-tool-result.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	serverInput, input := io.Pipe()
	output, serverOutput := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer input.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() {
		defer serverOutput.Close()
		defer serverInput.Close()
		done <- mcpentry.Serve(ctx, serverInput, serverOutput, mcpentry.Config{Name: "mulgae", Version: "test", ProjectRoot: "/fixture", Backend: backend, NewRequestID: func() (string, error) { return rejectionRequestID, nil }, ToolResultSchema: schema})
	}()
	tool := "run_review"
	if preflight {
		tool = "preflight_review"
	}
	fields, err := json.Marshal(inputFields)
	if err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + string(fields) + `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}` + "\n"
	if _, err := io.WriteString(input, request); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Error  json.RawMessage
		Result struct {
			StructuredContent mcpentry.ToolResult
			IsError           bool
		}
	}
	if err := json.NewDecoder(output).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	result := response.Result.StructuredContent
	if len(response.Error) != 0 || response.Result.IsError != (result.Outcome == "error") || result.SchemaVersion != "mulgae-mcp-tool-result.v1" || result.Tool != tool || result.RequestID != rejectionRequestID || result.Data != nil || result.Error == nil {
		t.Fatalf("SDK error envelope: %+v", response)
	}
	return result
}

type rejectionProjectionBackend struct {
	*mcpBackend
	failure error
	calls   int
}

func (backend *rejectionProjectionBackend) RunReview(context.Context, string, mcpentry.RunReviewInput) (mcpentry.BackendResult, error) {
	backend.calls++
	return mcpentry.BackendResult{}, backend.failure
}
func (backend *rejectionProjectionBackend) PreflightReview(context.Context, string, mcpentry.RunReviewInput) (mcpentry.BackendResult, error) {
	backend.calls++
	return mcpentry.BackendResult{}, backend.failure
}

// Expected outcomes were observed through the predecessor's actual backend and
// SDK at 028257e. Keep these literals independent of request mapping helpers.
func TestMCPReviewRequestRejectionCompatibility(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		for _, test := range reviewRejectionCases() {
			t.Run(fmt.Sprintf("%t/%s", preflight, test.name), func(t *testing.T) {
				observed := observeReviewRejection(t, test, preflight)
				want := expectedReviewRejection(test, preflight)
				if !reflect.DeepEqual(observed, want) {
					t.Fatalf("rejection drift: got %+v; predecessor %+v", observed, want)
				}
			})
		}
	}
}

func expectedReviewRejection(test reviewRejectionCase, preflight bool) rejectionObservation {
	label, stage := "review", "execution"
	if preflight {
		label, stage = "preflight", "query"
	}
	want := rejectionObservation{Name: test.name, Preflight: preflight, Class: "configuration_violation", Stage: "mcp.admission", Reason: "MCP " + label + " request is invalid", Public: mcpentry.ToolError{Class: "usage", Code: "configuration_rejected", Stage: "admission", Message: "The project configuration or request is invalid."}}
	switch test.phase {
	case "target":
		want.Reason = "MCP " + label + " target is invalid"
	case "guard":
		want.Guard = true
		want.Public.Code = "guard_invalid"
		want.Public.Message = "Review admission rejected the request."
	case "backend":
		want.Class = ""
		want.Stage = ""
		want.Reason = "MCP backend is unavailable"
		want.Public = mcpentry.ToolError{Class: "internal", Code: "internal_failure", Stage: stage, Message: "Mulgae could not complete the tool request."}
	case "admitted":
		want.Class = "artifact_failure"
		want.Stage = "test.capture"
		want.Reason = "captured review request"
		want.Calls = 1
		want.Public = mcpentry.ToolError{Class: "artifact", Code: "artifact_unavailable", Stage: stage, Message: "The requested verified artifact is unavailable."}
	}
	return want
}

// These operands pass the public JSON/selector grammar. The former CLI parse
// rejected them before application execution; direct mapping must do the same.
func TestMCPPublicReviewPreservesFlaglikeSelectorRejection(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		for _, target := range []mcpentry.ReviewTarget{{Kind: "commit", Value: "--bad"}, {Kind: "diff", Value: "--base..HEAD"}} {
			root := mustMCPRoot(t, canonicalTestTempDir(t))
			artifact := mustMCPRoot(t, filepath.Join(root.String(), ".mulgae"))
			capture := &rejectionCapture{}
			backend, err := newMCPBoundTestBackend(root, artifact, newMCPTestApplicationWithReviewRuns(t, &mcpQueryFake{}, capture), &mcpQueryFake{}, &mcpDiagnosticQueryFake{}, &mcpReportFake{}, filesystem.NewRunSelector())
			if err != nil {
				t.Fatal(err)
			}
			result := callReviewRejectionTool(t, backend, preflight, mcpentry.RunReviewInput{Target: target, Objective: "focus"})
			want := mcpentry.ToolError{Class: "usage", Code: "configuration_rejected", Stage: "admission", Message: "The project configuration or request is invalid."}
			if result.Error == nil || !reflect.DeepEqual(*result.Error, want) || capture.calls != 0 {
				t.Fatalf("public rejection=%+v execution calls=%d", result, capture.calls)
			}
		}
	}
}
