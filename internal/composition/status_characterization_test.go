//go:build darwin && arm64

package composition

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/domain"
	mcpentry "github.com/irootkernel/mulgae/internal/entrypoint/mcp"
	mulgaeentry "github.com/irootkernel/mulgae/internal/entrypoint/mulgae"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestMCPStatusAcquisitionCharacterization(t *testing.T) {
	root := mustMCPRoot(t, canonicalTestTempDir(t))
	artifact := mustMCPRoot(t, filepath.Join(root.String(), ".mulgae"))
	session := mustMCPSessionID(t, "s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run := mustMCPRunID(t, "r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	now := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: run, State: domain.RunFailed, StartedAt: now, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true})
	if err != nil {
		t.Fatal(err)
	}
	queries := &mcpQueryFake{resolveErr: ports.ErrPublicationRunNotFound}
	diagnostics := &mcpDiagnosticQueryFake{status: status}
	backend, err := newMCPBoundTestBackend(root, artifact, &mulgaeentry.Application{}, queries, diagnostics, &mcpReportFake{}, filesystem.NewRunSelector())
	if err != nil {
		t.Fatal(err)
	}
	data, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: run.String()})
	raw, _ := json.Marshal(data)
	const want = `{"ci_decision":null,"completed_at":"2026-07-23T06:00:00Z","content_verdict":null,"coverage_status":null,"diagnostic_only":true,"dropped_events":0,"failed_run_recovery":{"available":false,"source_kind":null,"run_id":null,"manifest_sha256":null,"accepted_roles":[],"retry_attempts":[],"unavailable_reason":"source_not_retained"},"final_artifact_uri":null,"kind":"diagnostic_status_read","last_seq":0,"publication_authority":false,"publication_status":null,"recovery_action":"none","report_resource_uri":null,"role_path_completed":0,"role_path_failed":0,"role_path_total":0,"role_report_uris":[],"run_id":"r_019f596a-cfe4-7c9c-b82e-7149158243ba","run_state":"failed","selected_roles":[],"session_id":"s_019f596a-cf80-7c67-b265-f37053d51ccf","started_at":"2026-07-23T06:00:00Z","terminal_cause":null,"terminal_phase":null,"updated_at":"2026-07-23T06:00:00Z"}`
	if string(raw) != want || err != nil || diagnostics.calls != 1 || diagnostics.sessionCalls != 0 {
		t.Fatalf("MCP status drift: %s err=%v calls=%d/%d", raw, err, diagnostics.calls, diagnostics.sessionCalls)
	}
	// Mixed missing preserves the original error without diagnostic dispatch.
	mixed := errors.Join(ports.ErrPublicationRunNotFound, errors.New("corrupt publication"))
	queries.resolveErr = mixed
	diagnostics.calls = 0
	_, err = backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: run.String()})
	if err != mixed || diagnostics.calls != 0 {
		t.Fatal("original publication cause lost")
	}
	// Q2: only completed failed/cancelled diagnostic records are public in MCP.
	queries.resolveErr = ports.ErrPublicationRunNotFound
	for _, state := range []domain.RunState{domain.RunPending, domain.RunRunning, domain.RunCancelled} {
		in := ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: run, State: state, StartedAt: now, UpdatedAt: now}
		if state == domain.RunCancelled {
			in.CompletedAt = now
			in.HasCompletedAt = true
		}
		status, err := ports.NewRuntimeDiagnosticRunStatus(in)
		if err != nil {
			t.Fatal(err)
		}
		diagnostics.status = status
		diagnostics.calls = 0
		data, err := backend.GetRun(context.Background(), mcpentry.GetRunInput{RunID: run.String()})
		if diagnostics.calls != 1 || diagnostics.sessionCalls != 0 {
			t.Fatal("MCP diagnostic dispatch changed")
		}
		if state == domain.RunCancelled {
			if err != nil || data["run_state"] != "cancelled" || data["publication_authority"] != false {
				t.Fatalf("cancelled diagnostic rejected: %#v %v", data, err)
			}
		} else if !errors.Is(err, mcpentry.ErrRunStatusUnavailable) || data != nil {
			t.Fatalf("nonterminal diagnostic widened: %s %#v %v", state, data, err)
		}
	}

}
