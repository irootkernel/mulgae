package review

import (
	"context"
	"errors"
	"sync"

	"github.com/irootkernel/mulgae/internal/ports"
)

// laneJob and laneResult are deliberately value-only boundaries. In particular,
// they cannot carry a mutable domain.Run, domain.Attempt, role aggregate, or
// identity issuer into a lane goroutine.
type laneJob struct {
	job   InvocationJob
	start <-chan struct{}
}

type laneResult struct {
	job     InvocationJob
	outcome AttemptOutcome
}
type processLaneState struct {
	available  chan struct{}
	references int
}

type processLaneAuthority struct {
	mu    sync.Mutex
	lanes map[string]*processLaneState
}

type processLaneLease struct {
	authority *processLaneAuthority
	key       ports.ConcurrencyKey
	state     *processLaneState

	mu       sync.Mutex
	released bool
}

var coordinatorProcessLaneAuthority = &processLaneAuthority{
	lanes: make(map[string]*processLaneState),
}

type processLaneCapacityAuthority struct {
	mu      sync.Mutex
	active  int
	limits  map[int]int
	changed chan struct{}
}

type processLaneCapacityRegistration struct {
	authority *processLaneCapacityAuthority
	limit     int
	closed    bool
}

var coordinatorProcessLaneCapacity = &processLaneCapacityAuthority{
	limits:  make(map[int]int),
	changed: make(chan struct{}),
}

func (authority *processLaneCapacityAuthority) register(
	maxActiveLanes int,
) *processLaneCapacityRegistration {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.limits[maxActiveLanes]++
	authority.signalLocked()
	return &processLaneCapacityRegistration{
		authority: authority,
		limit:     maxActiveLanes,
	}
}

func (registration *processLaneCapacityRegistration) acquire(ctx context.Context) error {
	if registration == nil || registration.authority == nil || ctx == nil {
		return errors.New("review coordinator: invalid process lane capacity registration")
	}
	authority := registration.authority
	for {
		authority.mu.Lock()
		if registration.closed {
			authority.mu.Unlock()
			return errors.New("review coordinator: closed process lane capacity registration")
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

func (registration *processLaneCapacityRegistration) releaseSlot() {
	authority := registration.authority
	authority.mu.Lock()
	authority.active--
	authority.signalLocked()
	authority.mu.Unlock()
}

func (registration *processLaneCapacityRegistration) unregister() {
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

func (authority *processLaneCapacityAuthority) effectiveLimitLocked() int {
	limit := 0
	for candidate := range authority.limits {
		if limit == 0 || candidate < limit {
			limit = candidate
		}
	}
	return limit
}

func (authority *processLaneCapacityAuthority) signalLocked() {
	close(authority.changed)
	authority.changed = make(chan struct{})
}

func (authority *processLaneAuthority) acquire(
	ctx context.Context,
	key ports.ConcurrencyKey,
) (*processLaneLease, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if !key.Valid() {
		return nil, errors.New("review coordinator: invalid process lane key")
	}

	authority.mu.Lock()
	state := authority.lanes[key.String()]
	if state == nil {
		state = &processLaneState{available: make(chan struct{}, 1)}
		state.available <- struct{}{}
		authority.lanes[key.String()] = state
	}
	state.references++
	authority.mu.Unlock()

	select {
	case <-ctx.Done():
		authority.releaseReference(key, state, false)
		return nil, ctx.Err()
	case <-state.available:
		if err := ctx.Err(); err != nil {
			authority.releaseReference(key, state, true)
			return nil, err
		}
		return &processLaneLease{authority: authority, key: key, state: state}, nil
	}
}

func (authority *processLaneAuthority) releaseReference(
	key ports.ConcurrencyKey,
	state *processLaneState,
	returnToken bool,
) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if returnToken {
		state.available <- struct{}{}
	}
	state.references--
	if state.references == 0 && authority.lanes[key.String()] == state {
		delete(authority.lanes, key.String())
	}
}

func (lease *processLaneLease) Release() error {
	if lease == nil || lease.authority == nil || lease.state == nil || !lease.key.Valid() {
		return errors.New("review coordinator: invalid process lane lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return nil
	}
	lease.released = true
	lease.authority.releaseReference(lease.key, lease.state, true)
	return nil
}

type coordinatorLane struct {
	key   ports.ConcurrencyKey
	queue chan laneJob
}

// laneScheduler owns worker lifetime only. It has no domain-state, repair,
// fallback, aggregation, or finalization authority; all of those remain in the
// coordinator goroutine.
type laneScheduler struct {
	ctx      context.Context
	cancel   context.CancelFunc
	runtime  InvocationRuntime
	locker   ports.LaneLocker
	capacity *processLaneCapacityRegistration

	results chan laneResult

	mu      sync.Mutex
	closed  bool
	lanes   map[string]*coordinatorLane
	workers sync.WaitGroup
}

func newLaneScheduler(
	parent context.Context,
	runtime InvocationRuntime,
	locker ports.LaneLocker,
	maxActiveLanes, maxJobs int,
) *laneScheduler {
	ctx, cancel := context.WithCancel(parent)
	if maxJobs < 1 {
		maxJobs = 1
	}
	return &laneScheduler{
		ctx:      ctx,
		cancel:   cancel,
		runtime:  runtime,
		locker:   locker,
		capacity: coordinatorProcessLaneCapacity.register(maxActiveLanes),
		results:  make(chan laneResult, maxJobs),
		lanes:    make(map[string]*coordinatorLane),
	}
}

// admitWithGate queues a job behind a caller-owned start gate.
func (scheduler *laneScheduler) admitWithGate(job InvocationJob, gate <-chan struct{}) bool {
	if gate == nil {
		return false
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.closed || scheduler.ctx.Err() != nil {
		return false
	}
	key := job.Route().ConcurrencyKey()
	lane := scheduler.lanes[key.String()]
	if lane == nil {
		lane = &coordinatorLane{
			key:   key,
			queue: make(chan laneJob, cap(scheduler.results)),
		}
		scheduler.lanes[key.String()] = lane
		scheduler.workers.Add(1)
		go scheduler.runLane(lane)
	}
	select {
	case lane.queue <- laneJob{job: job, start: gate}:
		return true
	case <-scheduler.ctx.Done():
		return false
	}
}

// admit queues a job behind a private start gate. Direct scheduler callers close
// the returned gate only after they have linearized their dispatch authority.
func (scheduler *laneScheduler) admit(job InvocationJob) (func(), bool) {
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
func (scheduler *laneScheduler) submit(job InvocationJob) bool {
	start, accepted := scheduler.admit(job)
	if !accepted {
		return false
	}
	start()
	return true
}

func (scheduler *laneScheduler) runLane(lane *coordinatorLane) {
	defer scheduler.workers.Done()
	for {
		select {
		case queued, open := <-lane.queue:
			if !open {
				return
			}
			select {
			case <-queued.start:
				scheduler.runJob(queued.job)
			case <-scheduler.ctx.Done():
				scheduler.send(queued.job, scheduler.contextOutcome(queued.job, scheduler.ctx))
			}
		case <-scheduler.ctx.Done():
			for {
				select {
				case queued, open := <-lane.queue:
					if !open {
						return
					}
					scheduler.send(queued.job, scheduler.contextOutcome(queued.job, scheduler.ctx))
				default:
					return
				}
			}
		}
	}
}

func (scheduler *laneScheduler) runJob(job InvocationJob) {
	if !job.Limits().Valid() {
		scheduler.send(job, scheduler.conditionOutcome(job, AttemptConditionInternalInvariant))
		return
	}

	invocationCtx, cancelInvocation := context.WithTimeout(scheduler.ctx, job.Limits().Timeout())
	defer cancelInvocation()
	if invocationCtx.Err() != nil {
		scheduler.send(job, scheduler.contextOutcome(job, invocationCtx))
		return
	}

	processLease, err := coordinatorProcessLaneAuthority.acquire(
		invocationCtx,
		job.Route().ConcurrencyKey(),
	)
	if err != nil {
		scheduler.send(job, scheduler.reduceOutcome(job, AttemptOutcome{}, invocationCtx, laneAcquisitionCondition(err)))
		return
	}
	defer func() {
		if processLease.Release() != nil {
			scheduler.cancel()
		}
	}()
	if invocationCtx.Err() != nil {
		scheduler.send(job, scheduler.contextOutcome(job, invocationCtx))
		return
	}

	if err := scheduler.capacity.acquire(invocationCtx); err != nil {
		scheduler.send(job, scheduler.contextOutcome(job, invocationCtx))
		return
	}
	defer scheduler.capacity.releaseSlot()
	if invocationCtx.Err() != nil {
		scheduler.send(job, scheduler.contextOutcome(job, invocationCtx))
		return
	}

	var lease ports.LaneLease
	if scheduler.locker != nil {
		acquired, err := scheduler.locker.Acquire(invocationCtx, job.Route().ConcurrencyKey())
		if err != nil {
			scheduler.send(job, scheduler.reduceOutcome(job, AttemptOutcome{}, invocationCtx, laneAcquisitionCondition(err)))
			return
		}
		if nilInterface(acquired) {
			scheduler.send(job, scheduler.reduceOutcome(job, AttemptOutcome{}, invocationCtx, AttemptConditionInternalInvariant))
			return
		}
		if acquired.Key().String() != job.Route().ConcurrencyKey().String() {
			if acquired.Release() != nil {
				scheduler.send(job, scheduler.reduceOutcome(job, AttemptOutcome{}, invocationCtx, AttemptConditionInternalInvariant))
				return
			}
			scheduler.send(job, scheduler.reduceOutcome(job, AttemptOutcome{}, invocationCtx, AttemptConditionInternalInvariant))
			return
		}
		lease = acquired
	}

	outcome := scheduler.runtime.Invoke(invocationCtx, job)
	conditions := []AttemptCondition{AttemptConditionInternalInvariant}
	if outcome.validFor(job) {
		conditions[0] = coordinatorOutcomeCondition(outcome)
	}
	if lease != nil && lease.Release() != nil {
		conditions = append(conditions, AttemptConditionConfigurationViolation)
	}
	scheduler.send(job, scheduler.reduceOutcome(job, outcome, invocationCtx, conditions...))
}

func laneAcquisitionCondition(err error) AttemptCondition {
	if errors.Is(err, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	if errors.Is(err, context.Canceled) {
		return AttemptConditionCancelled
	}
	switch ports.ClassifyLaneAcquisitionFailure(err) {
	case ports.LaneAcquisitionUnavailable:
		return AttemptConditionProviderUnavailable
	case ports.LaneAcquisitionConfiguration:
		return AttemptConditionConfigurationViolation
	case ports.LaneAcquisitionSecurity:
		return AttemptConditionSecurityViolation
	default:
		return AttemptConditionInternalInvariant
	}
}

func (scheduler *laneScheduler) contextOutcome(job InvocationJob, ctx context.Context) AttemptOutcome {
	return scheduler.reduceOutcome(job, AttemptOutcome{}, ctx)
}

func (scheduler *laneScheduler) reduceOutcome(
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
			return scheduler.conditionOutcome(job, laneContextCondition(ctxErr))
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
		contextCondition := laneContextCondition(ctxErr)
		if !conditionRetainsAuthorityAfterContext(condition, contextCondition) {
			condition = contextCondition
		}
	}
	if condition == AttemptConditionValidReview && outcome.validFor(job) {
		return outcome
	}
	return scheduler.conditionOutcome(job, condition)
}
func laneContextCondition(ctxErr error) AttemptCondition {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return AttemptConditionTimeout
	}
	return AttemptConditionCancelled
}

func (scheduler *laneScheduler) conditionOutcome(job InvocationJob, condition AttemptCondition) AttemptOutcome {
	outcome, err := NewAttemptOutcome(job, nil, &condition)
	if err == nil {
		return outcome
	}
	return AttemptOutcome{}
}

func (scheduler *laneScheduler) send(job InvocationJob, outcome AttemptOutcome) {
	// The receipt caps the number of possible jobs, and results has that exact
	// capacity. Workers never close this shared channel.
	scheduler.results <- laneResult{job: job, outcome: outcome}
}

func (scheduler *laneScheduler) cancelDispatch() {
	scheduler.cancel()
}

// close is called only after the coordinator has decided no repair or fallback
// can be generated. It joins lanes but intentionally never closes results.
func (scheduler *laneScheduler) close() {
	scheduler.mu.Lock()
	if scheduler.closed {
		scheduler.mu.Unlock()
		return
	}
	scheduler.closed = true
	for _, lane := range scheduler.lanes {
		close(lane.queue)
	}
	scheduler.mu.Unlock()
	scheduler.workers.Wait()
	scheduler.capacity.unregister()
	scheduler.cancel()
}
