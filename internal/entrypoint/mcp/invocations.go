package mcpentry

import (
	"context"
	"errors"
	"sync"
)

const maxSessionInvocations = 64

var (
	errInvocationRegistryClosed = errors.New("MCP invocation registry is closed")
	errInvocationLimitReached   = errors.New("MCP invocation limit reached")
	errInvocationNotFound       = errors.New("MCP invocation not found")
	errInvocationAlreadyExists  = errors.New("MCP invocation already exists")
)

type invocationPhase string

const (
	invocationRunning  invocationPhase = "running"
	invocationTerminal invocationPhase = "terminal"
)

type invocationSnapshot struct {
	ID                    string
	Phase                 invocationPhase
	CancellationRequested bool
	Result                BackendResult
	Err                   error
}

type invocationRegistry struct {
	mu      sync.Mutex
	ctx     context.Context
	backend Backend
	limit   int
	closed  bool
	entries map[string]*invocationEntry
}

type invocationEntry struct {
	id                    string
	phase                 invocationPhase
	cancellationRequested bool
	result                BackendResult
	err                   error
	cancel                context.CancelFunc
	done                  chan struct{}
}

func newInvocationRegistry(ctx context.Context, backend Backend, limit int) (*invocationRegistry, error) {
	if ctx == nil || backend == nil || limit < 1 {
		return nil, errors.New("MCP invocation registry: invalid configuration")
	}
	return &invocationRegistry{
		ctx: ctx, backend: backend, limit: limit,
		entries: make(map[string]*invocationEntry, limit),
	}, nil
}

func (registry *invocationRegistry) Start(id string, input RunReviewInput) (invocationSnapshot, error) {
	if registry == nil || !matches(requestIDPattern, id) {
		return invocationSnapshot{}, errInvalidToolArguments
	}
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return invocationSnapshot{}, errInvocationRegistryClosed
	}
	if _, exists := registry.entries[id]; exists {
		registry.mu.Unlock()
		return invocationSnapshot{}, errInvocationAlreadyExists
	}
	if len(registry.entries) >= registry.limit {
		registry.mu.Unlock()
		return invocationSnapshot{}, errInvocationLimitReached
	}
	executionCtx, cancel := context.WithCancel(registry.ctx)
	entry := &invocationEntry{
		id: id, phase: invocationRunning, cancel: cancel, done: make(chan struct{}),
	}
	registry.entries[id] = entry
	snapshot := snapshotInvocation(entry)
	registry.mu.Unlock()

	go registry.execute(executionCtx, entry, input)
	return snapshot, nil
}

func (registry *invocationRegistry) execute(ctx context.Context, entry *invocationEntry, input RunReviewInput) {
	result, err := registry.backend.RunReview(ctx, entry.id, input)
	registry.mu.Lock()
	entry.result = cloneBackendResult(result)
	entry.err = err
	entry.phase = invocationTerminal
	entry.cancel()
	close(entry.done)
	registry.mu.Unlock()
}

func (registry *invocationRegistry) Await(ctx context.Context, id string) (invocationSnapshot, error) {
	if registry == nil || ctx == nil || !matches(requestIDPattern, id) {
		return invocationSnapshot{}, errInvalidToolArguments
	}
	registry.mu.Lock()
	entry, exists := registry.entries[id]
	if !exists {
		registry.mu.Unlock()
		return invocationSnapshot{}, errInvocationNotFound
	}
	if entry.phase == invocationTerminal {
		snapshot := snapshotInvocation(entry)
		registry.mu.Unlock()
		return snapshot, nil
	}
	done := entry.done
	registry.mu.Unlock()

	select {
	case <-ctx.Done():
		return invocationSnapshot{}, ctx.Err()
	case <-done:
		registry.mu.Lock()
		snapshot := snapshotInvocation(entry)
		registry.mu.Unlock()
		return snapshot, nil
	}
}

func (registry *invocationRegistry) Cancel(id string) (invocationSnapshot, bool, error) {
	if registry == nil || !matches(requestIDPattern, id) {
		return invocationSnapshot{}, false, errInvalidToolArguments
	}
	registry.mu.Lock()
	entry, exists := registry.entries[id]
	if !exists {
		registry.mu.Unlock()
		return invocationSnapshot{}, false, errInvocationNotFound
	}
	accepted := entry.phase == invocationRunning && !entry.cancellationRequested
	if accepted {
		entry.cancellationRequested = true
		entry.cancel()
	}
	snapshot := snapshotInvocation(entry)
	registry.mu.Unlock()
	return snapshot, accepted, nil
}

func (registry *invocationRegistry) Shutdown(ctx context.Context) error {
	if registry == nil || ctx == nil {
		return errors.New("MCP invocation registry: invalid shutdown")
	}
	registry.mu.Lock()
	registry.closed = true
	done := make([]<-chan struct{}, 0, len(registry.entries))
	for _, entry := range registry.entries {
		if entry.phase == invocationRunning {
			entry.cancel()
			done = append(done, entry.done)
		}
	}
	registry.mu.Unlock()

	for _, terminal := range done {
		select {
		case <-terminal:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func snapshotInvocation(entry *invocationEntry) invocationSnapshot {
	return invocationSnapshot{
		ID: entry.id, Phase: entry.phase,
		CancellationRequested: entry.cancellationRequested,
		Result:                cloneBackendResult(entry.result), Err: entry.err,
	}
}

func cloneBackendResult(result BackendResult) BackendResult {
	return BackendResult{Outcome: result.Outcome, Data: clonePublicMap(result.Data)}
}

func clonePublicMap(source map[string]any) map[string]any {
	if source == nil {
		return nil
	}
	destination := make(map[string]any, len(source))
	for key, value := range source {
		destination[key] = clonePublicValue(value)
	}
	return destination
}

func clonePublicValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return clonePublicMap(value)
	case []any:
		cloned := make([]any, len(value))
		for index := range value {
			cloned[index] = clonePublicValue(value[index])
		}
		return cloned
	default:
		return value
	}
}
