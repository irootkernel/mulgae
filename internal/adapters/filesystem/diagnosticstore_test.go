//go:build darwin && arm64

package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
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
	for _, path := range []string{"", "status.json", "mulgae-runtime.jsonl"} {
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

func TestDiagnosticStatusReaderResolvesDiagnosticOnlyRunByRunID(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	completed := fixture.request.StartedAt().Add(time.Second)
	terminal, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunFailed,
		StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true,
		SelectedRoles: []domain.Role{domain.RoleTesting}, LaneTotal: 1, LaneFailed: 1,
		TerminalCause: domain.DiagnosticCausePublicationInstallationFailed,
		TerminalPhase: domain.DiagnosticPhasePublicationInstallation,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalize, err := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunFailed, domain.DiagnosticCausePublicationInstallationFailed, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Finalize(context.Background(), finalize); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	status, err := NewDiagnosticStatusReader().ReadRunStatus(context.Background(), root, fixture.request.RunID())
	if err != nil {
		t.Fatal(err)
	}
	if status.SessionID() != fixture.request.SessionID() || status.RunID() != fixture.request.RunID() || status.State() != domain.RunFailed ||
		status.TerminalCause() != domain.DiagnosticCausePublicationInstallationFailed || status.TerminalPhase() != domain.DiagnosticPhasePublicationInstallation {
		t.Fatalf("diagnostic status = session %s run %s state %s", status.SessionID(), status.RunID(), status.State())
	}
	missing, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bb")
	if _, err := NewDiagnosticStatusReader().ReadRunStatus(context.Background(), root, missing); !errors.Is(err, ports.ErrRuntimeDiagnosticRunNotFound) {
		t.Fatalf("missing diagnostic error = %v", err)
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
	if result.LastSequence() != 3 || result.URI() != fixture.request.RunPath() {
		t.Fatalf("unexpected finalize result: %#v", result)
	}
	if _, err := fixture.store.Finalize(context.Background(), finalize); err == nil {
		t.Fatal("second finalize accepted")
	}
	logBytes, err := os.ReadFile(diagnosticStorePath(fixture, "mulgae-runtime.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(logBytes), "\n"), "\n")
	if len(lines) != 3 {
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
	if final.State != domain.RunCompleted || final.LastSequence != 3 || final.PublicationAuthority {
		t.Fatalf("unexpected final status: %#v", final)
	}
	var closed runtimeDiagnosticEventWire
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &closed); err != nil {
		t.Fatal(err)
	}
	if closed.Event != domain.DiagnosticRuntimeClosed {
		t.Fatalf("last event = %q, want %q", closed.Event, domain.DiagnosticRuntimeClosed)
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

func diagnosticRawRequest(t *testing.T, stream domain.RuntimeDiagnosticStream, content string, maximum int64, aborted *atomic.Bool) ports.RuntimeDiagnosticRawRequest {
	t.Helper()
	attempt, _ := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	request, err := ports.NewRuntimeDiagnosticRawRequest(attempt, "i_019f596a-d04a-7a7a-8b3c-123456789abc", 1, ports.ProviderInvocationInitial, stream, strings.NewReader(content), maximum, []string{"provider:" + string(stream)}, func(error) { aborted.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestDiagnosticStorePersistsSeparatedBoundedRawStreamsThroughScanner(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	var aborted atomic.Bool
	stdout, err := fixture.store.PersistRaw(context.Background(), diagnosticRawRequest(t, domain.DiagnosticStdout, "safe stdout\n", 64, &aborted))
	if err != nil {
		t.Fatal(err)
	}
	stdoutURI, ok := stdout.URI()
	if !ok || !strings.HasSuffix(stdoutURI.String(), "/stdout.raw") || stdout.ByteLength() != int64(len("safe stdout\n")) {
		t.Fatalf("stdout result = %#v", stdout)
	}
	stdoutBytes, err := os.ReadFile(filepath.Join(fixture.root, filepath.FromSlash(stdoutURI.String())))
	if err != nil {
		t.Fatal(err)
	}
	if string(stdoutBytes) != "safe stdout\n" {
		t.Fatalf("stdout bytes = %q", stdoutBytes)
	}
	info, _ := os.Stat(filepath.Join(fixture.root, filepath.FromSlash(stdoutURI.String())))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("stdout mode = %o", info.Mode().Perm())
	}
	secret := "KKACHI_SECRET_password=value_7f20c84d"
	dropped, err := fixture.store.PersistRaw(context.Background(), diagnosticRawRequest(t, domain.DiagnosticStderr, secret, 1024, &aborted))
	if err == nil {
		t.Fatal("secret stream persisted")
	}
	var rejection *ports.RuntimeDiagnosticSecurityRejectionError
	var persistence *ports.RuntimeDiagnosticPersistenceError
	if !errors.As(err, &rejection) || errors.As(err, &persistence) {
		t.Fatalf("secret rejection classification = %T, %v", err, err)
	}
	drop, ok := dropped.Drop()
	if !ok || drop.Channel() != "provider_stderr" || !aborted.Load() {
		t.Fatalf("secret drop = %#v, aborted=%v", dropped, aborted.Load())
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("secret leaked through error")
	}
	if _, statErr := os.Stat(diagnosticStorePath(fixture, "attempts/a_019f596a-d048-79e7-b2b7-59822f012273/invocations/001-initial/stderr.raw")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("dropped stderr exists: %v", statErr)
	}
}

func TestDiagnosticStoreRawOverflowReturnsSafeDropAndRemovesTemporary(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	var aborted atomic.Bool
	result, err := fixture.store.PersistRaw(context.Background(), diagnosticRawRequest(t, domain.DiagnosticStdout, "overflow", 2, &aborted))
	if err == nil {
		t.Fatal("overflow persisted")
	}
	var rejection *ports.RuntimeDiagnosticSecurityRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("overflow classification = %T, %v", err, err)
	}
	drop, ok := result.Drop()
	if !ok || drop.Detector() != "maximum_bytes_exceeded" || !aborted.Load() {
		t.Fatalf("overflow result = %#v, aborted=%v", result, aborted.Load())
	}
	directory := diagnosticStorePath(fixture, "attempts/a_019f596a-d048-79e7-b2b7-59822f012273/invocations/001-initial")
	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") || entry.Name() == "stdout.raw" {
			t.Fatalf("unsafe overflow artifact remains: %s", entry.Name())
		}
	}
}

func TestDiagnosticStoreReservesTerminalTailAndRecordsOrdinaryDrops(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	concrete.mu.Lock()
	concrete.logBytes = ports.RuntimeDiagnosticLogMaxBytes - ports.RuntimeDiagnosticTailReserveBytes
	concrete.mu.Unlock()
	if _, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticLaneStarted)); !errors.Is(err, ports.ErrRuntimeDiagnosticEventDropped) {
		t.Fatalf("ordinary cap error = %v", err)
	}
	event, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticRunStarted))
	if err != nil {
		t.Fatalf("mandatory event did not use tail reserve: %v", err)
	}
	if event.Sequence() != 1 {
		t.Fatalf("mandatory sequence = %d", event.Sequence())
	}
	completed := fixture.request.StartedAt().Add(time.Second)
	status, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunCompleted, StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true, LastSequence: event.Sequence()})
	finalize, _ := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	if _, err := fixture.store.Finalize(context.Background(), finalize); err != nil {
		t.Fatal(err)
	}
	statusBytes, _ := os.ReadFile(diagnosticStorePath(fixture, "status.json"))
	var wire runtimeDiagnosticRunStatusWire
	if err := json.Unmarshal(statusBytes, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.DroppedEvents != 1 {
		t.Fatalf("dropped events = %d", wire.DroppedEvents)
	}
}

func TestDiagnosticStoreRecoversPartialJSONLineBeforeAppend(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	originalWrite := concrete.operations.write
	first := true
	concrete.operations.write = func(fd int, data []byte) (int, error) {
		if first {
			first = false
			count, err := originalWrite(fd, data[:len(data)/2])
			if err != nil {
				return count, err
			}
			return count, io.ErrShortWrite
		}
		return originalWrite(fd, data)
	}
	if _, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticLaneStarted)); err == nil {
		t.Fatal("partial append reported success")
	}
	concrete.closeLog()
	factory, _ := NewDiagnosticStoreFactory(NewSecureWriter(), fixture.clock)
	reopened, err := factory.Open(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	event, err := reopened.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticRunStarted))
	if err != nil {
		t.Fatal(err)
	}
	if event.Sequence() != 1 {
		t.Fatalf("recovered sequence = %d", event.Sequence())
	}
	logBytes, _ := os.ReadFile(diagnosticStorePath(fixture, "mulgae-runtime.jsonl"))
	if len(logBytes) == 0 || logBytes[len(logBytes)-1] != '\n' || strings.Count(string(logBytes), "\n") != 1 {
		t.Fatalf("recovered log is not one complete line: %q", logBytes)
	}
}

func TestDiagnosticStoreRollsBackPartialAppendBeforeSameSinkFinalize(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	originalWrite := concrete.operations.write
	first := true
	concrete.operations.write = func(fd int, data []byte) (int, error) {
		if first {
			first = false
			count, err := originalWrite(fd, data[:len(data)/2])
			return count, errors.Join(err, io.ErrShortWrite)
		}
		return originalWrite(fd, data)
	}
	if _, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticLaneStarted)); err == nil {
		t.Fatal("partial append reported success")
	}
	completed := fixture.request.StartedAt().Add(time.Second)
	status, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunCompleted, StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true})
	finalize, _ := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	result, err := fixture.store.Finalize(context.Background(), finalize)
	if err != nil || result.LastSequence() != 2 {
		t.Fatalf("same-sink finalize = %#v, %v", result, err)
	}
	assertDiagnosticLogSequences(t, diagnosticStorePath(fixture, "mulgae-runtime.jsonl"), 2)
}

func TestDiagnosticStoreRollsBackAppendAfterSyncFailure(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	originalSync := concrete.operations.fsync
	injected := errors.New("injected sync failure")
	first := true
	concrete.operations.fsync = func(fd int) error {
		if first {
			first = false
			return injected
		}
		return originalSync(fd)
	}
	if _, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticLaneStarted)); !errors.Is(err, injected) {
		t.Fatalf("sync failure = %v", err)
	}
	event, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticRunStarted))
	if err != nil || event.Sequence() != 1 {
		t.Fatalf("event after recovered sync failure = %#v, %v", event, err)
	}
	assertDiagnosticLogSequences(t, diagnosticStorePath(fixture, "mulgae-runtime.jsonl"), 1)
}

func TestDiagnosticStoreFinalizeRetryDoesNotDuplicateTerminalEvent(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	originalClose := concrete.operations.close
	injected := errors.New("injected close failure")
	concrete.operations.close = func(int) error { return injected }
	completed := fixture.request.StartedAt().Add(time.Second)
	status, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunCompleted, StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true})
	finalize, _ := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	if _, err := fixture.store.Finalize(context.Background(), finalize); !errors.Is(err, injected) {
		t.Fatalf("first finalize error = %v", err)
	}
	concrete.operations.close = originalClose
	result, err := fixture.store.Finalize(context.Background(), finalize)
	if err != nil || result.LastSequence() != 2 {
		t.Fatalf("retry finalize = %#v, %v", result, err)
	}
	assertDiagnosticLogSequences(t, diagnosticStorePath(fixture, "mulgae-runtime.jsonl"), 2)
}

func TestDiagnosticStoreRejectsReopenOfFinalizedRunWithoutChangingStatus(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	completed := fixture.request.StartedAt().Add(time.Second)
	status, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunCompleted, StartedAt: fixture.request.StartedAt(), UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true})
	finalize, _ := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	if _, err := fixture.store.Finalize(context.Background(), finalize); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(diagnosticStorePath(fixture, "status.json"))
	factory, _ := NewDiagnosticStoreFactory(NewSecureWriter(), fixture.clock)
	if _, err := factory.Open(context.Background(), fixture.request); err == nil {
		t.Fatal("finalized run reopened")
	}
	after, _ := os.ReadFile(diagnosticStorePath(fixture, "status.json"))
	if string(before) != string(after) {
		t.Fatal("terminal status changed during rejected reopen")
	}
}

func TestDiagnosticStoreRejectsPostInstallNamespaceSubstitution(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	concrete := fixture.store.(*DiagnosticStore)
	runPath := diagnosticStorePath(fixture, "")
	displaced := runPath + ".displaced"
	concrete.operations.afterStatusInstall = func() {
		concrete.operations.afterStatusInstall = func() {}
		if err := os.Rename(runPath, displaced); err != nil {
			t.Error(err)
			return
		}
		if err := os.Mkdir(runPath, 0o700); err != nil {
			t.Error(err)
		}
	}
	updated := fixture.request.StartedAt().Add(time.Second)
	status, _ := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{SessionID: fixture.request.SessionID(), RunID: fixture.request.RunID(), State: domain.RunRunning, StartedAt: fixture.request.StartedAt(), UpdatedAt: updated})
	err := fixture.store.ReplaceRunStatus(context.Background(), status)
	if !errors.Is(err, errDiagnosticNamespaceUncertain) {
		t.Fatalf("namespace substitution error = %v", err)
	}
	if _, installed := fixture.store.URI(); installed {
		t.Fatal("substituted namespace retained an installed diagnostic URI")
	}
	if _, err := os.Stat(filepath.Join(runPath, "status.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement namespace received status: %v", err)
	}
}

func assertDiagnosticLogSequences(t *testing.T, path string, want int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != want {
		t.Fatalf("log line count = %d, want %d", len(lines), want)
	}
	for index, line := range lines {
		var wire runtimeDiagnosticEventWire
		if err := json.Unmarshal([]byte(line), &wire); err != nil || wire.Sequence != uint64(index+1) {
			t.Fatalf("line %d is not a complete sequential event: %v", index, err)
		}
	}
}

func TestDiagnosticStoreConcurrentAppendProducesCompleteUniqueSequence(t *testing.T) {
	fixture := newDiagnosticStoreFixture(t)
	const count = 32
	var wait sync.WaitGroup
	sequences := make(chan uint64, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, err := fixture.store.Emit(context.Background(), diagnosticStoreDraft(t, fixture, domain.DiagnosticLaneStarted))
			if err != nil {
				t.Error(err)
				return
			}
			sequences <- event.Sequence()
		}()
	}
	wait.Wait()
	close(sequences)
	seen := map[uint64]bool{}
	for sequence := range sequences {
		if seen[sequence] {
			t.Fatalf("duplicate sequence %d", sequence)
		}
		seen[sequence] = true
	}
	if len(seen) != count {
		t.Fatalf("sequence count = %d", len(seen))
	}
	logBytes, _ := os.ReadFile(diagnosticStorePath(fixture, "mulgae-runtime.jsonl"))
	lines := strings.Split(strings.TrimSuffix(string(logBytes), "\n"), "\n")
	if len(lines) != count {
		t.Fatalf("line count = %d", len(lines))
	}
	for _, line := range lines {
		var wire runtimeDiagnosticEventWire
		if err := json.Unmarshal([]byte(line), &wire); err != nil {
			t.Fatalf("interleaved JSON line: %v", err)
		}
	}
}

func TestDiagnosticStoreRejectsSymlinkEscapeAndUnsafePermissions(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(string) error
	}{
		{"symlink", func(root string) error { return os.Symlink(t.TempDir(), filepath.Join(root, "diagnostics")) }},
		{"permissions", func(root string) error { return os.Mkdir(filepath.Join(root, "diagnostics"), 0o755) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := test.prepare(rootPath); err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
			session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
			run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
			request, _ := ports.NewRuntimeDiagnosticOpenRequest(root, session, run, time.Now().UTC())
			factory, _ := NewDiagnosticStoreFactory(NewSecureWriter(), &diagnosticStoreTestClock{now: time.Now().UTC()})
			if _, err := factory.Open(context.Background(), request); err == nil {
				t.Fatal("unsafe diagnostics namespace accepted")
			}
		})
	}
}

type diagnosticFailingRawWriter struct {
	delegate ports.SecureFileWriter
	failure  error
}

func (writer diagnosticFailingRawWriter) EnsurePrivateDir(root ports.AnchoredRoot, path ports.SafeRelativePath) error {
	return writer.delegate.EnsurePrivateDir(root, path)
}
func (writer diagnosticFailingRawWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	if strings.HasPrefix(request.Channel(), "provider_") {
		return ports.SecureWriteReceipt{}, nil, writer.failure
	}
	return writer.delegate.Write(ctx, request)
}

func TestDiagnosticStoreClassifiesRawWriterFailure(t *testing.T) {
	rootPath := t.TempDir()
	root, _ := ports.NewAnchoredRoot(rootPath)
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	started := time.Now().UTC()
	request, _ := ports.NewRuntimeDiagnosticOpenRequest(root, session, run, started)
	injected := errors.New("injected writer failure")
	factory, _ := NewDiagnosticStoreFactory(diagnosticFailingRawWriter{delegate: NewSecureWriter(), failure: injected}, &diagnosticStoreTestClock{now: started})
	sink, err := factory.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var aborted atomic.Bool
	_, err = sink.PersistRaw(context.Background(), diagnosticRawRequest(t, domain.DiagnosticStdout, "safe", 8, &aborted))
	var persistence *ports.RuntimeDiagnosticPersistenceError
	if !errors.As(err, &persistence) || persistence.Operation() != ports.DiagnosticPersistenceRaw || !errors.Is(err, injected) {
		t.Fatalf("writer error classification = %T %v", err, err)
	}
}
