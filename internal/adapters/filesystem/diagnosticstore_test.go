//go:build darwin && arm64

package filesystem

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type diagnosticStoreTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *diagnosticStoreTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	current := clock.now
	clock.now = clock.now.Add(time.Millisecond)
	return current
}

type diagnosticStoreFixture struct {
	root    string
	request ports.RuntimeDiagnosticOpenRequest
	store   ports.RuntimeDiagnosticSink
	clock   *diagnosticStoreTestClock
}

func newDiagnosticStoreFixture(t *testing.T) diagnosticStoreFixture {
	t.Helper()
	rootPath := t.TempDir()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	started := time.Date(2026, 7, 23, 6, 0, 0, 0, time.UTC)
	request, err := ports.NewRuntimeDiagnosticOpenRequest(root, session, run, started)
	if err != nil {
		t.Fatal(err)
	}
	clock := &diagnosticStoreTestClock{now: started}
	factory, err := NewDiagnosticStoreFactory(NewSecureWriter(), clock)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := factory.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return diagnosticStoreFixture{root: rootPath, request: request, store: sink, clock: clock}
}

func diagnosticStorePath(fixture diagnosticStoreFixture, suffix string) string {
	return filepath.Join(fixture.root, filepath.FromSlash(fixture.request.RunPath().String()), filepath.FromSlash(suffix))
}

func diagnosticStoreDraft(t *testing.T, fixture diagnosticStoreFixture, code domain.RuntimeDiagnosticEventCode) domain.RuntimeDiagnosticEventDraft {
	t.Helper()
	draft, err := domain.NewRuntimeDiagnosticEventDraft(domain.RuntimeDiagnosticEventInput{Level: domain.RuntimeDiagnosticInfo, Component: "runtime", Operation: "test", Event: code, SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID()})
	if err != nil {
		t.Fatal(err)
	}
	return draft
}

func TestDiagnosticStoreOpenCreatesPrivateInstalledRun(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	uri, installed := fixture.store.URI()
	if !installed || uri != fixture.request.RunPath() {
		t.Fatalf("URI = %q, %v", uri.String(), installed)
	}
	for _, path := range []string{"", "status.json", "kar-runtime.jsonl"} {
		info, err := os.Stat(diagnosticStorePath(fixture, path))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if path == "" {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	statusBytes, err := os.ReadFile(diagnosticStorePath(fixture, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status runtimeDiagnosticRunStatusWire
	if err := json.Unmarshal(statusBytes, &status); err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != ports.RuntimeDiagnosticRunStatusSchema || status.State != domain.RunRunning || !status.DiagnosticOnly || status.PublicationAuthority {
		t.Fatalf("unexpected initial status: %#v", status)
	}
}

func TestDiagnosticStoreAppendsCompleteEventsAndFinalizesExactlyOnce(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	event, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticRunStarted))
	if err != nil {
		t.Fatal(err)
	}
	if event.Sequence() != 1 {
		t.Fatalf("sequence = %d", event.Sequence())
	}
	completed := fixture.request.StartedAt().Add(time.Second)
	status, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunCompleted, StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true, LastSequence: event.Sequence()})
	if err != nil {
		t.Fatal(err)
	}
	finalize, err := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.store.Finalize(context.Background(), finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.LastSequence() != 2 || result.URI() != fixture.request.RunPath() {
		t.Fatalf("unexpected finalize result: %#v", result)
	}
	if _, err := fixture.store.Finalize(context.Background(), finalize); err == nil {
		t.Fatal("second finalize accepted")
	}
	logBytes, err := os.ReadFile(diagnosticStorePath(fixture, "kar-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(logBytes), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("log lines = %d", len(lines))
	}
	for index, line := range lines {
		var wire runtimeDiagnosticEventWire
		if err := json.Unmarshal([]byte(line), &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Sequence != uint64(index+1) {
			t.Fatalf("line %d sequence = %d", index, wire.Sequence)
		}
	}
	statusBytes, _ := os.ReadFile(diagnosticStorePath(fixture, "status.json"))
	var final runtimeDiagnosticRunStatusWire
	if err := json.Unmarshal(statusBytes, &final); err != nil {
		t.Fatal(err)
	}
	if final.State != domain.RunCompleted || final.LastSequence != 2 || final.PublicationAuthority {
		t.Fatalf("unexpected final status: %#v", final)
	}
}

func TestDiagnosticStoreAtomicallyReplacesAttemptAndInvocationStatus(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	event, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticAttemptStarted))
	if err != nil {
		t.Fatal(err)
	}
	attempt, _ := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	now := fixture.request.StartedAt().Add(time.Second)
	attemptStatus, err := ports.NewRuntimeDiagnosticAttemptStatus(ports.RuntimeDiagnosticAttemptStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), AttemptID: attempt, Role: domain.RoleSecurity, Provider: "zcode-main", Selection: ports.RuntimeDiagnosticPrimary, State: domain.AttemptRunning, StartedAt: fixture.request.StartedAt(), UpdatedAt: now, InvocationCount: 1, LastSequence: event.Sequence()})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.ReplaceAttemptStatus(context.Background(), attemptStatus); err != nil {
		t.Fatal(err)
	}
	invocationStatus, err := ports.NewRuntimeDiagnosticInvocationStatus(ports.RuntimeDiagnosticInvocationStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), AttemptID: attempt, InvocationID: "i_019f596a-d04a-7a7a-8b3c-123456789abc", Ordinal: 1, Purpose: ports.ProviderInvocationInitial, ProcessState: domain.InvocationRunning, ParseState: domain.ParseNotStarted, ValidationState: domain.ValidationNotStarted, StartedAt: fixture.request.StartedAt(), UpdatedAt: now, LastSequence: event.Sequence()})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.ReplaceInvocationStatus(context.Background(), invocationStatus); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"attempts/" + attempt.String() + "/status.json", "attempts/" + attempt.String() + "/invocations/001-initial/status.json"} {
		info, err := os.Stat(diagnosticStorePath(fixture, relative))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", relative, info.Mode().Perm())
		}
	}
	if err := fixture.store.ReplaceAttemptStatus(context.Background(), attemptStatus); err != nil {
		t.Fatalf("atomic replacement failed: %v", err)
	}
}
