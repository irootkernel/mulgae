package mcpentry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	testInvocationOne = "i_019f596a-cf80-7c67-b265-f37053d51ccf"
	testInvocationTwo = "i_019f596a-cf81-7c67-b265-f37053d51ccf"
)

func TestInvocationRegistryOwnsOneExecutionAcrossAwaiters(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	backend := &invocationBackendFake{run: func(ctx context.Context, _ string, _ RunReviewInput) (BackendResult, error) {
		close(started)
		select {
		case <-ctx.Done():
			return BackendResult{}, ctx.Err()
		case <-release:
			return BackendResult{Outcome: toolOutcomeSuccess, Data: map[string]any{
				"run_id": "r_019f596a-cfe4-7c9c-b82e-7149158243ba",
				"nested": map[string]any{"state": "complete"},
			}}, nil
		}
	}}
	registry := mustInvocationRegistry(t, context.Background(), backend, 2)

	snapshot, err := registry.Start(testInvocationOne, RunReviewInput{Target: ReviewTarget{Kind: "workspace"}})
	if err != nil || snapshot.ID != testInvocationOne || snapshot.Phase != invocationRunning {
		t.Fatalf("start = %#v, %v", snapshot, err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("review execution did not start")
	}

	observerCtx, cancelObserver := context.WithCancel(context.Background())
	cancelObserver()
	if _, err := registry.Await(observerCtx, testInvocationOne); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled observer = %v, want context cancellation", err)
	}
	if calls := backend.Calls(); calls != 1 {
		t.Fatalf("review executions after observer cancellation = %d, want 1", calls)
	}

	awaited := make(chan invocationSnapshot, 1)
	go func() {
		result, awaitErr := registry.Await(context.Background(), testInvocationOne)
		if awaitErr != nil {
			return
		}
		awaited <- result
	}()
	close(release)
	var terminal invocationSnapshot
	select {
	case terminal = <-awaited:
	case <-time.After(time.Second):
		t.Fatal("awaiter did not receive terminal result")
	}
	if terminal.Phase != invocationTerminal || terminal.Err != nil || terminal.Result.Outcome != toolOutcomeSuccess {
		t.Fatalf("terminal invocation = %#v", terminal)
	}

	terminal.Result.Data["nested"].(map[string]any)["state"] = "mutated"
	repeated, err := registry.Await(context.Background(), testInvocationOne)
	if err != nil || repeated.Result.Data["nested"].(map[string]any)["state"] != "complete" || backend.Calls() != 1 {
		t.Fatalf("repeated await = %#v, %v; calls %d", repeated, err, backend.Calls())
	}
}

func TestInvocationRegistryExplicitCancellationIsIdempotent(t *testing.T) {
	started := make(chan struct{})
	backend := &invocationBackendFake{run: func(ctx context.Context, _ string, _ RunReviewInput) (BackendResult, error) {
		close(started)
		<-ctx.Done()
		return BackendResult{}, ctx.Err()
	}}
	registry := mustInvocationRegistry(t, context.Background(), backend, 1)
	if _, err := registry.Start(testInvocationOne, RunReviewInput{}); err != nil {
		t.Fatal(err)
	}
	<-started

	acknowledged, accepted, err := registry.Cancel(testInvocationOne)
	if err != nil || !accepted || !acknowledged.CancellationRequested {
		t.Fatalf("first cancellation = %#v, %t, %v", acknowledged, accepted, err)
	}
	terminal, err := registry.Await(context.Background(), testInvocationOne)
	if err != nil || terminal.Phase != invocationTerminal || !terminal.CancellationRequested || !errors.Is(terminal.Err, context.Canceled) {
		t.Fatalf("cancelled terminal invocation = %#v, %v", terminal, err)
	}
	_, accepted, err = registry.Cancel(testInvocationOne)
	if err != nil || accepted || backend.Calls() != 1 {
		t.Fatalf("repeated cancellation accepted=%t err=%v calls=%d", accepted, err, backend.Calls())
	}
}

func TestInvocationRegistryBoundsSessionIdentityAndRejectsUnknownIDs(t *testing.T) {
	backend := &invocationBackendFake{run: func(context.Context, string, RunReviewInput) (BackendResult, error) {
		return BackendResult{Outcome: toolOutcomeSuccess, Data: map[string]any{}}, nil
	}}
	registry := mustInvocationRegistry(t, context.Background(), backend, 1)
	if _, err := registry.Start(testInvocationOne, RunReviewInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Start(testInvocationOne, RunReviewInput{}); !errors.Is(err, errInvocationAlreadyExists) {
		t.Fatalf("duplicate start = %v", err)
	}
	if _, err := registry.Start(testInvocationTwo, RunReviewInput{}); !errors.Is(err, errInvocationLimitReached) {
		t.Fatalf("capacity start = %v", err)
	}
	if _, err := registry.Await(context.Background(), testInvocationTwo); !errors.Is(err, errInvocationNotFound) {
		t.Fatalf("unknown await = %v", err)
	}
	if _, _, err := registry.Cancel(testInvocationTwo); !errors.Is(err, errInvocationNotFound) {
		t.Fatalf("unknown cancel = %v", err)
	}
}

func TestInvocationRegistryShutdownCancelsAndDrainsActiveExecutions(t *testing.T) {
	started := make(chan struct{}, 2)
	backend := &invocationBackendFake{run: func(ctx context.Context, _ string, _ RunReviewInput) (BackendResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		return BackendResult{}, ctx.Err()
	}}
	registry := mustInvocationRegistry(t, context.Background(), backend, 2)
	for _, id := range []string{testInvocationOne, testInvocationTwo} {
		if _, err := registry.Start(id, RunReviewInput{}); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	<-started
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := registry.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{testInvocationOne, testInvocationTwo} {
		terminal, err := registry.Await(context.Background(), id)
		if err != nil || terminal.Phase != invocationTerminal || terminal.CancellationRequested || !errors.Is(terminal.Err, context.Canceled) {
			t.Fatalf("shutdown terminal %s = %#v, %v", id, terminal, err)
		}
	}
	if _, err := registry.Start("i_019f596a-cf82-7c67-b265-f37053d51ccf", RunReviewInput{}); !errors.Is(err, errInvocationRegistryClosed) {
		t.Fatalf("post-shutdown start = %v", err)
	}
}

func TestInvocationRegistryReportsSessionEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	registry := mustInvocationRegistry(t, ctx, &invocationBackendFake{run: func(context.Context, string, RunReviewInput) (BackendResult, error) {
		return BackendResult{}, nil
	}}, 1)
	if registry.SessionEnded() {
		t.Fatal("new invocation registry reports an ended session")
	}
	cancel()
	if !registry.SessionEnded() {
		t.Fatal("cancelled invocation registry reports a live session")
	}
}

func mustInvocationRegistry(t *testing.T, ctx context.Context, backend Backend, limit int) *invocationRegistry {
	t.Helper()
	registry, err := newInvocationRegistry(ctx, backend, limit)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

type invocationBackendFake struct {
	mu    sync.Mutex
	calls int
	run   func(context.Context, string, RunReviewInput) (BackendResult, error)
}

func (fake *invocationBackendFake) RunReview(ctx context.Context, id string, input RunReviewInput) (BackendResult, error) {
	fake.mu.Lock()
	fake.calls++
	fake.mu.Unlock()
	return fake.run(ctx, id, input)
}

func (fake *invocationBackendFake) Calls() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.calls
}

func (*invocationBackendFake) PreflightReview(context.Context, string, RunReviewInput) (BackendResult, error) {
	return BackendResult{}, nil
}
func (*invocationBackendFake) ListRuns(context.Context, ListRunsInput) (map[string]any, error) {
	return nil, nil
}
func (*invocationBackendFake) GetRun(context.Context, GetRunInput) (map[string]any, error) {
	return nil, nil
}
func (*invocationBackendFake) ListFindings(context.Context, ListFindingsInput) (map[string]any, error) {
	return nil, nil
}
func (*invocationBackendFake) ReadResource(context.Context, ResourceRequest) (ResourceContent, error) {
	return ResourceContent{}, nil
}
