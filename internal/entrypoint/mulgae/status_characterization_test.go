//go:build darwin && arm64

package mulgae

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/irootkernel/mulgae/internal/app"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type statusDiagnosticCapture struct {
	status              ports.RuntimeDiagnosticRunStatus
	err                 error
	calls, sessionCalls int
}

func (fake *statusDiagnosticCapture) ReadRunStatus(context.Context, ports.AnchoredRoot, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.calls++
	return fake.status, fake.err
}
func (fake *statusDiagnosticCapture) ReadSessionRunStatus(context.Context, ports.AnchoredRoot, domain.SessionID, domain.RunID) (ports.RuntimeDiagnosticRunStatus, error) {
	fake.sessionCalls++
	return fake.status, fake.err
}

func statusDiagnosticFixture(t *testing.T, state domain.RunState) ports.RuntimeDiagnosticRunStatus {
	t.Helper()
	session, _ := domain.ParseSessionID(g006SessionID)
	run, _ := domain.ParseRunID(testRunID)
	now := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
	in := ports.RuntimeDiagnosticRunStatusInput{SessionID: session, RunID: run, State: state, StartedAt: now, UpdatedAt: now, SelectedRoles: []domain.Role{domain.RoleTesting}}
	if state == domain.RunFailed || state == domain.RunCancelled {
		in.CompletedAt = now
		in.HasCompletedAt = true
	}
	status, err := ports.NewRuntimeDiagnosticRunStatus(in)
	if err != nil {
		t.Fatal(err)
	}
	return status
}
func statusBranchFixture(t *testing.T, branch int, missing error) (foundationFixture, *statusDiagnosticCapture) {
	t.Helper()
	query := newG006QueryFake()
	diagnostics := &statusDiagnosticCapture{status: statusDiagnosticFixture(t, domain.RunFailed)}
	switch branch {
	case 0:
		query.resolveErr = missing
	case 1:
		query.resolveErr = ports.ErrPublicationRunNotFound
		diagnostics.err = missing
	case 2:
		query.status = RunStatusView{FailedRunRecovery: recovery.UnavailableStatus("source_not_retained"), SessionID: g006SessionID, RunID: testRunID, PublicationState: domain.PublicationNotPublished, RecoveryAction: domain.RecoveryActionResumeCollection}
		diagnostics.err = missing
	}
	fixture := newG006Fixture(t, query, newG006ReportFake())
	fixture.application.diagnosticQueries = diagnostics
	return fixture, diagnostics
}

// Payload wire expectations were recorded on M1C2; only the current envelope
// identity advances with the TASK-029 v23 cutover.
const statusWirePrefix = `{"schema_version":"mulgae-command-result.v26","command":"status","request":{"command":"status","output_format":"json","request_id":"i_019f596a-cf80-7c67-b265-f37053d51ccf","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf"},"completed_at":"2026-07-14T12:00:00.000Z",`
const statusUnavailableRecovery = `{"accepted_roles":[],"available":false,"manifest_sha256":null,"retry_attempts":[],"run_id":null,"source_kind":null,"unavailable_reason":"source_not_retained"}`
const statusDiagnosticResult = `{"completed_at":"2026-07-23T06:00:00Z","diagnostic_only":true,"dropped_events":0,"failed_run_recovery":` + statusUnavailableRecovery + `,"final_artifact_uri":null,"kind":"diagnostic_status_read","last_seq":0,"publication_authority":false,"publication_status":null,"recovery_action":"none","role_path_completed":0,"role_path_failed":0,"role_path_total":0,"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","run_state":"failed","selected_roles":["testing"],"session_id":"s_019f596a-cfe4-7c9c-b82e-7149158243ba","started_at":"2026-07-23T06:00:00Z","terminal_cause":null,"terminal_phase":null,"updated_at":"2026-07-23T06:00:00Z"}`
const statusPublicationResult = `{"failed_run_recovery":` + statusUnavailableRecovery + `,"final_artifact_uri":null,"kind":"status_read","publication_status":"not_published","recovery_action":"resume_collection","run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","run_state":null}`
const statusFailedResult = `{"final_artifact_uri":null,"kind":"status_failed","publication_status":null,"recovery_action":null,"run_id":"r_019f596a-cf80-7c67-b265-f37053d51ccf","run_state":null}`

func assertStatusWire(t *testing.T, fixture foundationFixture, diagnostics *statusDiagnosticCapture, want string, calls, sessionCalls int) {
	t.Helper()
	exit, kind, code, message, human, hint := 0, "success", "", "", "", "run mulgae doctor"
	result := statusDiagnosticResult
	switch want {
	case "diagnostic":
		human = "diagnostic run " + testRunID + ": state=failed role_paths=0/0 failed=0 recovery_action=none publication_authority=false\n"
	case "publication":
		result = statusPublicationResult
		human = "run_id: " + testRunID + "\nrun_state: unavailable\npublication_status: not_published\nrecovery_action: resume_collection\nfailed_run_recovery: unavailable (source_not_retained)\n"
	case "artifact":
		exit, kind, code, message, human = 7, "artifact", "artifact_unavailable", "A required artifact could not be read or written.", "mulgae: a required artifact could not be read or written"
	case "security":
		exit, kind, code, message, human = 8, "security", "security_rejected", "The secure output policy rejected the command output.", "mulgae: secure output policy rejected the command output"
	case "internal":
		exit, kind, code, message, human = 10, "internal", "internal_failure", "The command could not be completed.", "mulgae: command could not be completed"
	case "cancellation":
		exit, kind, code, message, human = 9, "cancellation", "request_cancelled", "The command was cancelled.", "mulgae: request was cancelled"
		hint = "retry the command when ready"
	default:
		t.Fatal("unknown literal expectation")
	}
	reasons := "[]"
	if exit != 0 {
		result = statusFailedResult
		reasonMessage := message + " Failure at stage cli.status with code " + code + "; hint: " + hint + "."
		encoded, _ := json.Marshal(reasonMessage)
		reasons = fmt.Sprintf(`[{"category":%q,"code":%q,"message":%s,"retryable":false,"artifact_uri":null}]`, kind, code, encoded)
		human += "\ncode: " + code + "\nstage: cli.status\nhint: " + hint + "\n"
	}
	wire := statusWirePrefix + fmt.Sprintf(`"exit":{"code":%d,"kind":%q},"reasons":%s,"result":%s}`, exit, kind, reasons, result) + "\n"
	for _, machine := range []bool{true, false} {
		diagnostics.calls, diagnostics.sessionCalls = 0, 0
		args := []string{"status", "--run", testRunID}
		if machine {
			args = append(args, "--output", "json")
		}
		got := fixture.application.Run(context.Background(), args, testAnchoredRoot(t))
		stdout, stderr := human, ""
		if exit != 0 {
			stdout, stderr = "", human
		}
		if machine {
			stdout, stderr = wire, ""
		}
		if int(got.ExitCode()) != exit || string(got.Stdout()) != stdout || string(got.Stderr()) != stderr || diagnostics.calls != calls || diagnostics.sessionCalls != sessionCalls {
			t.Errorf("machine=%t: exit=%d stdout=%q stderr=%q diagnostics=%d/%d; want exit=%d stdout=%q stderr=%q diagnostics=%d/%d", machine, got.ExitCode(), got.Stdout(), got.Stderr(), diagnostics.calls, diagnostics.sessionCalls, exit, stdout, stderr, calls, sessionCalls)
		}
	}
}

func TestStatusMissingErrorCharacterization(t *testing.T) {
	for branch := 0; branch < 3; branch++ {
		sentinel := ports.ErrPublicationRunNotFound
		if branch != 0 {
			sentinel = ports.ErrRuntimeDiagnosticRunNotFound
		}
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("branch%d/mixed%t", branch, mixed), func(t *testing.T) {
				cause := sentinel
				if mixed {
					cause = errors.Join(sentinel, mustG006Failure(t, domain.FailureSecurityPolicy))
				}
				f, d := statusBranchFixture(t, branch, cause)
				want, calls, sessionCalls := "diagnostic", 1, 0
				if branch == 1 {
					want = "artifact"
				}
				if branch == 2 {
					want, calls, sessionCalls = "publication", 0, 1
				}
				// M_test: Master Q1=A intentionally replaces the recorded mixed-security outcomes.
				if mixed {
					want = "security"
					if branch == 0 {
						calls = 0
					}
				}
				assertStatusWire(t, f, d, want, calls, sessionCalls)
			})
		}
	}
}

func TestStatusStrictMissingOnlyRegression(t *testing.T) {
	for branch := 0; branch < 3; branch++ {
		missing := ports.ErrPublicationRunNotFound
		if branch != 0 {
			missing = ports.ErrRuntimeDiagnosticRunNotFound
		}
		wrappers := []struct {
			name string
			err  error
		}{
			{"bare", missing}, {"ordinary", fmt.Errorf("lookup: %w", missing)},
			{"typed artifact", typedHandlerFailure("test.status", domain.FailureArtifact, "missing", missing)},
			{"single join", errors.Join(missing)},
			{"only missing join", errors.Join(missing, fmt.Errorf("lookup: %w", missing))},
		}
		for _, control := range wrappers {
			t.Run(fmt.Sprintf("branch%d/control/%s", branch, control.name), func(t *testing.T) {
				f, d := statusBranchFixture(t, branch, control.err)
				want, calls, sessionCalls := "diagnostic", 1, 0
				if branch == 1 {
					want = "artifact"
				}
				if branch == 2 {
					want, calls, sessionCalls = "publication", 0, 1
				}
				assertStatusWire(t, f, d, want, calls, sessionCalls)
			})
		}
		siblings := []struct {
			name string
			err  error
			want string
		}{
			{"artifact", mustG006Failure(t, domain.FailureArtifact), "artifact"},
			{"security", mustG006Failure(t, domain.FailureSecurityPolicy), "security"},
			{"internal", mustG006Failure(t, domain.FailureInternal), "internal"},
			{"raw", errors.New("independent raw failure"), "artifact"},
			{"cancelled", context.Canceled, "artifact"}, {"deadline", context.DeadlineExceeded, "artifact"},
		}
		for _, sibling := range siblings {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("branch%d/%s/reverse%t", branch, sibling.name, reverse), func(t *testing.T) {
					joined := errors.Join(missing, sibling.err)
					if reverse {
						joined = errors.Join(sibling.err, missing)
					}
					f, d := statusBranchFixture(t, branch, joined)
					want, calls, sessionCalls := sibling.want, 1, 0
					if branch == 0 {
						calls = 0
						if sibling.name == "cancelled" || sibling.name == "deadline" {
							want = "cancellation"
						}
					}
					if branch == 2 {
						calls, sessionCalls = 0, 1
					}
					assertStatusWire(t, f, d, want, calls, sessionCalls)
				})
			}
		}
	}
}

func TestStatusDiagnosticEligibilityCompatibility(t *testing.T) {
	for _, state := range []domain.RunState{domain.RunPending, domain.RunRunning, domain.RunFailed, domain.RunCancelled} {
		query := &g006QueryFake{resolveErr: ports.ErrPublicationRunNotFound}
		fixture := newG006Fixture(t, query, newG006ReportFake())
		diagnostics := &statusDiagnosticCapture{status: statusDiagnosticFixture(t, state)}
		fixture.application.diagnosticQueries = diagnostics
		got := fixture.application.Run(context.Background(), []string{"status", "--run", testRunID, "--output", "json"}, testAnchoredRoot(t))
		if got.ExitCode() != app.ExitCodeSuccess || commandResultKind(t, got.Stdout()) != "diagnostic_status_read" || !bytes.Contains(got.Stdout(), []byte(`"run_state":"`+string(state)+`"`)) || diagnostics.calls != 1 || diagnostics.sessionCalls != 0 {
			t.Fatalf("CLI diagnostic eligibility %s: %+v calls=%d/%d", state, got, diagnostics.calls, diagnostics.sessionCalls)
		}
	}
}

// Master Q1=A preserves a mixed publication failure regardless of whether the
// bypassed diagnostic lookup would succeed, fail or fail projection. Expected
// public outcomes follow that decision and the G1/G2 review examples.
func TestStatusMixedPublicationFailureRegression(t *testing.T) {
	for _, test := range []struct {
		name                    string
		publication, diagnostic domain.FailureClass
		invalidProjection       bool
		want                    string
	}{
		{"publication security before diagnostic artifact", domain.FailureSecurityPolicy, domain.FailureArtifact, false, "security"},
		{"publication artifact before diagnostic security", domain.FailureArtifact, domain.FailureSecurityPolicy, false, "artifact"},
		{"publication security before invalid diagnostic projection", domain.FailureSecurityPolicy, "", true, "security"},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse%t", test.name, reverse), func(t *testing.T) {
				publication := mustG006Failure(t, test.publication)
				mixed := errors.Join(ports.ErrPublicationRunNotFound, publication)
				if reverse {
					mixed = errors.Join(publication, ports.ErrPublicationRunNotFound)
				}
				fixture, diagnostics := statusBranchFixture(t, 0, mixed)
				if test.invalidProjection {
					session, _ := domain.ParseSessionID(g006SessionID)
					otherRun, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
					now := time.Date(2026, time.July, 23, 6, 0, 0, 0, time.UTC)
					status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
						SessionID: session, RunID: otherRun, State: domain.RunFailed,
						StartedAt: now, UpdatedAt: now, CompletedAt: now, HasCompletedAt: true,
					})
					if err != nil {
						t.Fatal(err)
					}
					diagnostics.status = status
				} else {
					diagnostics.err = mustG006Failure(t, test.diagnostic)
				}
				assertStatusWire(t, fixture, diagnostics, test.want, 0, 0)
			})
		}
	}
}
