package review

import (
	"context"
	"errors"
	"sync"
)

// workerJob and workerResult are deliberately value-only boundaries. In particular,
// they cannot carry a mutable domain.Run, domain.Attempt, role aggregate, or
// identity issuer into a worker goroutine.
type workerJob struct {
	job   InvocationJob
	start <-chan struct{}
}

type workerResult struct {
	job     InvocationJob
	outcome AttemptOutcome
}
type processWorkerCapacityAuthority struct {
	mu      sync.Mutex
	active  int
	limits  map[int]int
	changed chan struct{}
}

type processWorkerCapacityRegistration struct {
	authority *processWorkerCapacityAuthority
	limit     int
	closed    bool
}

var coordinatorProcessWorkerCapacity = &processWorkerCapacityAuthority{
	limits:  make(map[int]int),
	changed: make(chan struct{}),
}

func (authority *processWorkerCapacityAuthority) register(
	maxActiveLanes int,
) *processWorkerCapacityRegistration {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.limits[maxActiveLanes]++
	authority.signalLocked()
	return &processWorkerCapacityRegistration{
		authority: authority,
		limit:     maxActiveLanes,
	}
}

func (registration *processWorkerCapacityRegistration) acquire(ctx context.Context) error {
	if registration == nil || registration.authority == nil || ctx == nil {
		return errors.New("review coordinator: invalid process worker capacity registration")
	}
	authority := registration.authority
	for {
		authority.mu.Lock()
		if registration.closed {
			authority.mu.Unlock()
			return errors.New("review coordinator: closed process worker capacity registration")
		}
		limit := authority.effectiveLimitLocked()
		if authority.active < limit {
			authority.active++
			authority.mu.Unlock()
			return nil
		}
		changed := authority.changed
		authority.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (registration *processWorkerCapacityRegistration) releaseSlot() {
	authority := registration.authority
	authority.mu.Lock()
	authority.active--
	authority.signalLocked()
	authority.mu.Unlock()
}

func (registration *processWorkerCapacityRegistration) unregister() {
	if registration == nil || registration.authority == nil {
		return
	}
	authority := registration.authority
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if registration.closed {
		return
	}
	registration.closed = true
	authority.limits[registration.limit]--
	if authority.limits[registration.limit] == 0 {
		delete(authority.limits, registration.limit)
	}
	authority.signalLocked()
}

func (authority *processWorkerCapacityAuthority) effectiveLimitLocked() int {
	limit := 0
	for candidate := range authority.limits {
		if limit == 0 || candidate < limit {
			limit = candidate
		}
	}
	return limit
}

func (authority *processWorkerCapacityAuthority) signalLocked() {
	close(authority.changed)
	authority.changed = make(chan struct{})
}

// invocationScheduler owns worker lifetime only. It has no domain-state, repair,
// aggregation, or finalization authority; all of those remain in the
// coordinator goroutine.
type invocationScheduler struct {
	ctx      context.Context
	cancel   context.CancelFunc
	runtime  InvocationRuntime
	capacity *processWorkerCapacityRegistration

	results chan workerResult
	jobs    chan workerJob

	mu      sync.Mutex
	closed  bool
	workers sync.WaitGroup
}

func newInvocationScheduler(
	parent context.Context,
	runtime InvocationRuntime,
	maxActiveLanes, maxJobs int,
) *invocationScheduler {
	ctx, cancel := context.WithCancel(parent)
	if maxJobs < 1 {
		maxJobs = 1
	}
	scheduler := &invocationScheduler{
		ctx:      ctx,
		cancel:   cancel,
		runtime:  runtime,
		capacity: coordinatorProcessWorkerCapacity.register(maxActiveLanes),
		results:  make(chan workerResult, maxJobs),
		jobs:     make(chan workerJob, maxJobs),
	}
	scheduler.workers.Add(maxActiveLanes)
	for range maxActiveLanes {
		go scheduler.runWorker()
	}
	return scheduler
}

// admitWithGate queues a job behind a caller-owned start gate.
func (scheduler *invocationScheduler) admitWithGate(job InvocationJob, gate <-chan struct{}) bool {
	if gate == nil {
		return false
	}
	scheduler.mu.Lock()
	if scheduler.closed || scheduler.ctx.Err() != nil {
		scheduler.mu.Unlock()
		return false
	}
	select {
	case scheduler.jobs <- workerJob{job: job, start: gate}:
		scheduler.mu.Unlock()
		return true
	case <-scheduler.ctx.Done():
		scheduler.mu.Unlock()
		return false
	}
}

// admit queues a job behind a private start gate. Direct scheduler callers close
// the returned gate only after they have linearized their dispatch authority.
func (scheduler *invocationScheduler) admit(job InvocationJob) (func(), bool) {
	gate := make(chan struct{})
	if !scheduler.admitWithGate(job, gate) {
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(gate)
		})
	}, true
}

// submit is the immediate-admission helper for direct scheduler tests. The
// coordinator uses admit so its trace always precedes runtime execution.
func (scheduler *invocationScheduler) submit(job InvocationJob) bool {
	start, accepted := scheduler.admit(job)
	if !accepted {
		return false
	}
	start()
	return true
}

func (scheduler *invocationScheduler) runWorker() {
	defer scheduler.workers.Done()
	for queued := range scheduler.jobs {
		select {
		case <-queued.start:
			scheduler.runJob(queued.job)
		case <-scheduler.ctx.Done():
			scheduler.send(queued.job, scheduler.contextOutcome(queued.job, scheduler.ctx))
		}
	}
}

func (scheduler *invocationScheduler) runJob(job InvocationJob) {
	if !job.Limits().Valid() {
		scheduler.send(job, scheduler.conditionOutcome(job, AttemptConditionInternalInvariant))
		return
	}

	// Capacity acquisition is bounded by the enclosing run context. It does not
	// consume the provider's configured process timeout; InvocationRuntime starts
	// that timeout at the provider execution boundary.
	if scheduler.ctx.Err() != nil {
		scheduler.send(job, scheduler.contextOutcome(job, scheduler.ctx))
		return
	}

	if err := scheduler.capacity.acquire(scheduler.ctx); err != nil {
		scheduler.send(job, scheduler.contextOutcome(job, scheduler.ctx))
		return
	}
	defer scheduler.capacity.releaseSlot()
	if scheduler.ctx.Err() != nil {
		scheduler.send(job, scheduler.contextOutcome(job, scheduler.ctx))
		return
	}

	// Capacity contention belongs to the enclosing run budget. If it leaves less than a
	// complete provider window, fail before entering the runtime so the parent
	// deadline cannot masquerade as or truncate a provider timeout.
	if !contextCanRunFor(scheduler.ctx, job.Limits().Timeout()) {
		scheduler.send(job, scheduler.conditionOutcome(job, AttemptConditionTimeout))
		return
	}
	outcome := scheduler.runtime.Invoke(scheduler.ctx, job)
	conditions := []AttemptCondition{AttemptConditionInternalInvariant}
	if outcome.validFor(job) {
		conditions[0] = coordinatorOutcomeCondition(outcome)
	}
	scheduler.send(job, scheduler.reduceOutcome(job, outcome, scheduler.ctx, conditions...))
}

func (scheduler *invocationScheduler) contextOutcome(job InvocationJob, ctx context.Context) AttemptOutcome {
	return scheduler.reduceOutcome(job, AttemptOutcome{}, ctx)
}

func (scheduler *invocationScheduler) reduceOutcome(
	job InvocationJob,
	outcome AttemptOutcome,
	ctx context.Context,
	conditions ...AttemptCondition,
) AttemptOutcome {
	ctxErr := ctx.Err()
	deadlineExceeded := errors.Is(ctxErr, context.DeadlineExceeded)
	facts := make([]AttemptCondition, 0, len(conditions))
	for _, condition := range conditions {
		if deadlineExceeded && condition == AttemptConditionCancelled {
			continue
		}
		facts = append(facts, condition)
	}
	if len(facts) == 0 {
		if ctxErr != nil {
			return scheduler.conditionOutcome(job, invocationContextCondition(ctxErr))
		}
		facts = append(facts, AttemptConditionInternalInvariant)
	}
	condition, err := ReduceAttemptConditions(facts...)
	if err != nil {
		return scheduler.conditionOutcome(job, AttemptConditionInternalInvariant)
	}
	// The process layer cannot distinguish a provider-owned invocation timeout
	// from termination caused by the enclosing run context: both arrive as a
	// typed timed-out observation. Parent deadline provenance is authoritative.
	if condition == AttemptConditionProviderTimeout && errors.Is(scheduler.ctx.Err(), context.DeadlineExceeded) {
		condition = AttemptConditionTimeout
	}
	if ctxErr != nil {
		contextCondition := invocationContextCondition(ctxErr)
		if !conditionRetainsAuthorityAfterContext(condition, contextCondition) {
			condition = contextCondition
		}
	}
	if outcome.validFor(job) && coordinatorOutcomeCondition(outcome) == condition {
		return outcome
	}
	return scheduler.conditionOutcome(job, condition)
}
func invocationContextCondition(ctxErr error) AttemptCondition {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	return AttemptConditionCancelled
}

func (scheduler *invocationScheduler) conditionOutcome(job InvocationJob, condition AttemptCondition) AttemptOutcome {
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err == nil {
		return outcome
	}
	return AttemptOutcome{}
}

func (scheduler *invocationScheduler) send(job InvocationJob, outcome AttemptOutcome) {
	// The receipt caps the number of possible jobs, and results has that exact
	// capacity. Workers never close this shared channel.
	scheduler.results <- workerResult{job: job, outcome: outcome}
}

func (scheduler *invocationScheduler) cancelDispatch() {
	scheduler.cancel()
}

// close is called only after the coordinator has decided no repair
// can be generated. It joins workers but intentionally never closes results.
func (scheduler *invocationScheduler) close() {
	scheduler.mu.Lock()
	if scheduler.closed {
		scheduler.mu.Unlock()
		return
	}
	scheduler.closed = true
	close(scheduler.jobs)
	scheduler.mu.Unlock()
	scheduler.workers.Wait()
	scheduler.capacity.unregister()
	scheduler.cancel()
}
