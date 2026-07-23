package ports

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

func runtimeDiagnosticTestOpen(t *testing.T) RuntimeDiagnosticOpenRequest {
	t.Helper()
	root, err := NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	request, err := NewRuntimeDiagnosticOpenRequest(root, session, run, time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func runtimeDiagnosticTestDraft(t *testing.T, request RuntimeDiagnosticOpenRequest) domain.RuntimeDiagnosticEventDraft {
	t.Helper()
	draft, err := domain.NewRuntimeDiagnosticEventDraft(domain.RuntimeDiagnosticEventInput{
		Level: domain.RuntimeDiagnosticInfo, Component: "runtime", Operation: "run", Event: domain.DiagnosticRunStarted,
		SessionID: request.SessionID(), RunID: request.RunID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return draft
}

func TestInMemoryRuntimeDiagnosticSinkSerializesRunWideSequence(t *testing.T) {
	request := runtimeDiagnosticTestOpen(t)
	sink, err := NewInMemoryRuntimeDiagnosticSink(request)
	if err != nil {
		t.Fatal(err)
	}
	draft := runtimeDiagnosticTestDraft(t, request)
	const count = 64
	sequences := make(chan uint64, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, emitErr := sink.Emit(context.Background(), draft)
			if emitErr != nil {
				t.Error(emitErr)
				return
			}
			sequences <- event.Sequence()
		}()
	}
	wait.Wait()
	close(sequences)
	seen := make(map[uint64]bool, count)
	for sequence := range sequences {
		if sequence == 0 || sequence > count || seen[sequence] {
			t.Fatalf("invalid sequence %d", sequence)
		}
		seen[sequence] = true
	}
	if len(seen) != count {
		t.Fatalf("sequence count = %d", len(seen))
	}
}

func TestRuntimeDiagnosticRawRequestSeparatesStreamsAndCaps(t *testing.T) {
	request := runtimeDiagnosticTestOpen(t)
	sink, _ := NewInMemoryRuntimeDiagnosticSink(request)
	attempt, _ := domain.ParseAttemptID("a_019f596a-d048-79e7-b2b7-59822f012273")
	var aborted atomic.Bool
	raw, err := NewRuntimeDiagnosticRawRequest(attempt, "i_019f596a-d04a-7a7a-8b3c-123456789abc", 1, ProviderInvocationInitial, domain.DiagnosticStdout, bytes.NewReader([]byte("safe")), 4, []string{"provider:stdout"}, func(error) { aborted.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	result, err := sink.PersistRaw(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if uri, ok := result.URI(); !ok || uri.String() != request.RunPath().String()+"/attempts/"+attempt.String()+"/invocations/001-initial/stdout.raw" || result.ByteLength() != 4 {
		t.Fatalf("unexpected raw result: %#v", result)
	}
	overflow, _ := NewRuntimeDiagnosticRawRequest(attempt, "i_019f596a-d04a-7a7a-8b3c-123456789abc", 1, ProviderInvocationInitial, domain.DiagnosticStderr, bytes.NewReader([]byte("too-long")), 2, []string{"provider:stderr"}, func(error) { aborted.Store(true) })
	dropped, err := sink.PersistRaw(context.Background(), overflow)
	var rejection *RuntimeDiagnosticSecurityRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("overflow error = %T, want security rejection", err)
	}
	if drop, ok := dropped.Drop(); !ok || drop.Detector() != "maximum_bytes_exceeded" || rejection.Drop().Detector() != drop.Detector() || !aborted.Load() {
		t.Fatal("overflow did not return safe drop metadata and abort producer")
	}
}

func TestRuntimeDiagnosticPersistenceClassificationIsClosed(t *testing.T) {
	t.Parallel()
	cause := errors.New("disk failure")
	err := NewRuntimeDiagnosticPersistenceError(DiagnosticPersistenceEmit, DiagnosticPersistenceWriteFailure, cause)
	var persistence *RuntimeDiagnosticPersistenceError
	if !errors.As(err, &persistence) || persistence.Operation() != DiagnosticPersistenceEmit || persistence.Reason() != DiagnosticPersistenceWriteFailure || !errors.Is(err, cause) {
		t.Fatalf("unexpected classification: %v", err)
	}
	if err := NewRuntimeDiagnosticPersistenceError("unknown", DiagnosticPersistenceWriteFailure, cause); err == nil {
		t.Fatal("unknown persistence operation accepted")
	}
	if err := NewRuntimeDiagnosticPersistenceError(DiagnosticPersistenceEmit, "free_form", cause); err == nil {
		t.Fatal("free-form persistence reason accepted")
	}
}

func TestRuntimeDiagnosticStatusesValidateHierarchyAndDefensivelyCopy(t *testing.T) {
	request := runtimeDiagnosticTestOpen(t)
	roles := []domain.Role{domain.RoleSecurity, domain.RoleLogic}
	started := request.StartedAt()
	updated := started.Add(time.Second)
	status, err := NewRuntimeDiagnosticRunStatus(RuntimeDiagnosticRunStatusInput{SessionID: request.SessionID(), RunID: request.RunID(), State: domain.RunRunning, StartedAt: started, UpdatedAt: updated, SelectedRoles: roles, LaneTotal: 2, LastSequence: 3})
	if err != nil {
		t.Fatal(err)
	}
	roles[0] = domain.RoleTesting
	got := status.SelectedRoles()
	if len(got) != 2 || got[0] != domain.RoleLogic || got[1] != domain.RoleSecurity {
		t.Fatalf("roles not canonical or defensively copied: %v", got)
	}
	bad := RuntimeDiagnosticRunStatusInput{SessionID: request.SessionID(), RunID: request.RunID(), State: domain.RunRunning, StartedAt: updated, UpdatedAt: started}
	if _, err := NewRuntimeDiagnosticRunStatus(bad); err == nil {
		t.Fatal("backward timestamps accepted")
	}
}

func TestRuntimeDiagnosticFinalizeIsExactlyOnceAndNoopHasNoURI(t *testing.T) {
	request := runtimeDiagnosticTestOpen(t)
	started := request.StartedAt()
	completed := started.Add(time.Second)
	status, err := NewRuntimeDiagnosticRunStatus(RuntimeDiagnosticRunStatusInput{SessionID: request.SessionID(), RunID: request.RunID(), State: domain.RunCompleted, StartedAt: started, UpdatedAt: completed, CompletedAt: completed, HasCompletedAt: true})
	if err != nil {
		t.Fatal(err)
	}
	finalize, err := NewRuntimeDiagnosticFinalizeRequest(domain.RunCompleted, "", status)
	if err != nil {
		t.Fatal(err)
	}
	sink, _ := NewInMemoryRuntimeDiagnosticSink(request)
	result, err := sink.Finalize(context.Background(), finalize)
	if err != nil || !result.URI().Valid() || result.LastSequence() != 2 {
		t.Fatalf("finalize = %#v, %v", result, err)
	}
	if _, err := sink.Finalize(context.Background(), finalize); err == nil {
		t.Fatal("second finalize accepted")
	}
	noop, _ := NewNoopRuntimeDiagnosticSink(request)
	if _, installed := noop.URI(); installed {
		t.Fatal("noop sink exposed installed URI")
	}
}
