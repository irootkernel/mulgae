package reviewrun

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/ports"
)

type coordinationTimer func(time.Duration) (<-chan time.Time, func())

func newCoordinationTimer(delay time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(delay)
	return timer.C, func() { timer.Stop() }
}

// ownedReview separates the deadline guard from renewal I/O. Neither a stalled
// renewal nor caller cancellation can extend the known protected interval.
type ownedReview struct {
	coordinator *ReviewCoordinator
	request     ReviewAcquireRequest
	mu          sync.Mutex
	mutation    sync.Mutex
	record      ports.ReviewLockRecord
	grant       ports.ReviewLockGrantReference
	fault       error
	terminal    bool
	work        context.Context
	cancelWork  context.CancelCauseFunc
	renew       context.Context
	stopRenew   context.CancelFunc
	stop        chan struct{}
	stopOnce    sync.Once
	pulse       chan struct{}
	done        chan struct{}
	timer       coordinationTimer
}

func (c *ReviewCoordinator) startOwnedReview(ctx context.Context, req ReviewAcquireRequest, budget time.Duration) (*ownedReview, error) {
	outcome, err := c.acquireOwnedGrant(ctx, req, budget)
	if err != nil {
		return nil, err
	}
	mark, cancel := context.WithTimeout(context.WithoutCancel(ctx), coordinationCallBudget)
	record, err := c.intentStore.UpdateLocalDrain(mark, req.Root, req.SessionID, req.RunID, ports.ReviewLocalDrainUnverified, c.observationTime(outcome.Record))
	cancel()
	if err != nil {
		return nil, coordinationFailure(errors.Join(coordinationError(ports.ReviewCoordinationReasonPersistenceRefused, ports.ReviewLockOperationAcquire, true, err), c.settleUnusedGrant(req, outcome, false)), false)
	}
	work, cancelWork := context.WithCancelCause(ctx)
	renew, stopRenew := context.WithCancel(context.Background())
	owner := &ownedReview{coordinator: c, request: req, record: record, grant: *outcome.Grant, work: work, cancelWork: cancelWork, renew: renew, stopRenew: stopRenew, stop: make(chan struct{}), pulse: make(chan struct{}, 1), done: make(chan struct{}), timer: c.timer}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); owner.renewLoop() }()
	go func() { defer workers.Done(); owner.guardLoop() }()
	go func() { workers.Wait(); close(owner.done) }()
	if err := owner.admitExecution(budget); err != nil {
		return owner, err
	}
	return owner, nil
}

func (owner *ownedReview) fail(err error) {
	owner.mu.Lock()
	owner.fault = errors.Join(owner.fault, err)
	owner.mu.Unlock()
	owner.cancelWork(err)
}

func (owner *ownedReview) state() (ports.ReviewLockGrantReference, bool, error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.grant, owner.terminal, owner.fault
}

func (owner *ownedReview) preparationContext(budget time.Duration) (context.Context, context.CancelFunc) {
	grant, _, _ := owner.state()
	cause := coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationAcquire, false, nil)
	return context.WithDeadlineCause(owner.work, grant.MaxHoldDeadline.Add(-budget-coordinationDrainBudget), cause)
}

func (owner *ownedReview) preparationFailure(ctx context.Context, err error) error {
	var fault *ports.ReviewCoordinationError
	if errors.As(context.Cause(ctx), &fault) && fault.Reason == ports.ReviewCoordinationReasonHoldBudgetExceeded {
		return errors.Join(err, coordinationFailure(fault, true))
	}
	_, _, protection := owner.state()
	return errors.Join(err, coordinationFailure(protection, true))
}

func (owner *ownedReview) admitExecution(budget time.Duration) error {
	grant, _, fault := owner.state()
	if fault != nil {
		return coordinationFailure(fault, true)
	}
	now := owner.coordinator.clock.Now()
	if !now.Before(grant.LivenessDeadline) || grant.MaxHoldDeadline.Sub(now) < budget+coordinationDrainBudget {
		err := coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationRenew, false, nil)
		owner.fail(err)
		return coordinationFailure(err, true)
	}
	return owner.work.Err()
}

func (owner *ownedReview) beginTerminal() {
	owner.mu.Lock()
	if !owner.terminal && !owner.coordinator.clock.Now().Before(owner.grant.MaxHoldDeadline.Add(-coordinationDrainBudget)) {
		fault := coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationRenew, false, nil)
		owner.fault = errors.Join(owner.fault, fault)
		owner.cancelWork(fault)
	}
	owner.terminal = true
	owner.mu.Unlock()
	select {
	case owner.pulse <- struct{}{}:
	default:
	}
}

func (owner *ownedReview) guardLoop() {
	for {
		grant, terminal, fault := owner.state()
		if fault != nil {
			return
		}
		deadline := grant.MaxHoldDeadline
		if !terminal {
			deadline = deadline.Add(-coordinationDrainBudget)
		}
		if grant.LivenessDeadline.Before(deadline) {
			deadline = grant.LivenessDeadline
		}
		tick, stop := owner.timer(deadline.Sub(owner.coordinator.clock.Now()))
		select {
		case <-owner.stop:
			stop()
			return
		case <-owner.pulse:
			stop()
			continue
		case <-tick:
			stop()
			// Recheck under the state lock: a successful renewal may have
			// extended liveness while the old timer was ready.
			owner.mu.Lock()
			now := owner.coordinator.clock.Now()
			reason := ports.ReviewCoordinationReason("")
			if !now.Before(owner.grant.LivenessDeadline) || !now.Before(owner.grant.MaxHoldDeadline) {
				reason = ports.ReviewCoordinationReasonHoldExpired
			} else if !owner.terminal && !now.Before(owner.grant.MaxHoldDeadline.Add(-coordinationDrainBudget)) {
				reason = ports.ReviewCoordinationReasonHoldBudgetExceeded
			}
			if reason != "" {
				err := coordinationError(reason, ports.ReviewLockOperationRenew, true, nil)
				owner.fault = errors.Join(owner.fault, err)
				owner.cancelWork(err)
				owner.mu.Unlock()
				return
			}
			owner.mu.Unlock()
		}
	}
}

func (owner *ownedReview) renewLoop() {
	for {
		grant, _, fault := owner.state()
		if fault != nil {
			return
		}
		now := owner.coordinator.clock.Now()
		remaining := grant.LivenessDeadline.Sub(now)
		if maximum := grant.MaxHoldDeadline.Sub(now); maximum < remaining {
			remaining = maximum
		}
		if remaining <= 0 {
			owner.fail(coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationRenew, true, nil))
			return
		}
		tick, stop := owner.timer(remaining / 2)
		select {
		case <-owner.stop:
			stop()
			return
		case <-tick:
			stop()
		}
		owner.mutation.Lock()
		call, cancel := context.WithDeadline(owner.renew, minTime(owner.coordinator.clock.Now().Add(coordinationCallBudget), grant.LivenessDeadline, grant.MaxHoldDeadline))
		reply, err := owner.coordinator.transport.Renew(call, grant.GrantID)
		if err == nil {
			err = validateCoordinationReply(owner.record, reply, ports.ReviewLockOperationRenew)
		}
		if err == nil && (reply.Current.State != ports.ReviewLockStateGranted || !owner.coordinator.clock.Now().Before(*reply.Current.LivenessDeadline)) {
			err = coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationRenew, true, nil)
		}
		if err == nil {
			var record ports.ReviewLockRecord
			record, err = owner.coordinator.intentStore.UpdateObservation(call, owner.request.Root, owner.request.SessionID, owner.request.RunID, reply, owner.coordinator.observationTime(owner.record))
			if err != nil {
				err = coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, ports.ReviewLockOperationRenew, true, err)
			} else {
				owner.record = record
				owner.mu.Lock()
				owner.grant, _ = record.GrantReference()
				owner.mu.Unlock()
				select {
				case owner.pulse <- struct{}{}:
				default:
				}
			}
		}
		cancel()
		owner.mutation.Unlock()
		if err != nil {
			owner.fail(ensureCoordinationError(ports.ReviewLockOperationRenew, ports.ReviewCoordinationReasonAcquireUncertain, err))
			return
		}
	}
}

func minTime(first time.Time, rest ...time.Time) time.Time {
	for _, value := range rest {
		if value.Before(first) {
			first = value
		}
	}
	return first
}

// finish freezes all protection observations before local proof or disposition.
// A disposition failure is returned separately so it cannot erase a valid P2.
func (owner *ownedReview) finish(ctx context.Context, completed bool) (protection, disposition error) {
	grant, _, fault := owner.state()
	now := owner.coordinator.clock.Now()
	if fault == nil && (!now.Before(grant.LivenessDeadline) || !now.Before(grant.MaxHoldDeadline)) {
		owner.fail(coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationRenew, true, nil))
	}
	owner.stopOnce.Do(func() { close(owner.stop) })
	select {
	case <-owner.done:
		owner.stopRenew()
	case <-ctx.Done():
		owner.stopRenew()
		return coordinationFailure(coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationRenew, true, ctx.Err()), true), nil
	}
	_, _, fault = owner.state()
	protection = coordinationFailure(fault, true)
	if !completed {
		return protection, nil
	}
	owner.mutation.Lock()
	defer owner.mutation.Unlock()
	record, err := owner.coordinator.intentStore.UpdateLocalDrain(ctx, owner.request.Root, owner.request.SessionID, owner.request.RunID, ports.ReviewLocalDrainVerified, owner.coordinator.observationTime(owner.record))
	if err != nil {
		return errors.Join(protection, coordinationFailure(coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, ports.ReviewLockOperationRelease, true, err), true)), nil
	}
	owner.record = record
	call, cancel := context.WithTimeout(ctx, coordinationCallBudget)
	defer cancel()
	reply, err := owner.coordinator.transport.Release(call, owner.grant.GrantID)
	if err == nil {
		err = validateCoordinationReply(record, reply, ports.ReviewLockOperationRelease)
	}
	if err == nil && !reply.Current.State.IsTerminal() {
		err = coordinationError(ports.ReviewCoordinationReasonLockStateConflict, ports.ReviewLockOperationRelease, true, nil)
	}
	if err == nil {
		_, err = owner.coordinator.intentStore.UpdateObservation(call, owner.request.Root, owner.request.SessionID, owner.request.RunID, reply, owner.coordinator.observationTime(record))
		if err != nil {
			err = coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, ports.ReviewLockOperationRelease, true, err)
			// A failed write is operational only while the original verified
			// local proof and immutable grant identity remain readable.
			proof, found, proofErr := owner.coordinator.intentStore.LoadIntent(call, owner.request.Root, owner.request.SessionID, owner.request.RunID)
			if proofErr == nil {
				proofErr = proof.Validate()
			}
			if !found || proofErr != nil || proof.SchemaVersion != record.SchemaVersion || proof.LocalDrainState != ports.ReviewLocalDrainVerified || proof.Payload.PayloadSHA256 != record.Payload.PayloadSHA256 || proof.ObservedRequest == nil || !proof.ObservedRequest.State.WasGranted() {
				return errors.Join(protection, coordinationFailure(errors.Join(err, proofErr, coordinationError(ports.ReviewCoordinationReasonPersistenceRefused, ports.ReviewLockOperationRelease, true, nil)), true)), nil
			}
			if proofErr := validateCoordinationReply(record, ports.ReviewLockReply{Receipt: *proof.ObservedReceipt, Current: *proof.ObservedRequest}, ""); proofErr != nil {
				return errors.Join(protection, coordinationFailure(errors.Join(err, proofErr), true)), nil
			}
		}
	}
	if err != nil {
		err = ensureCoordinationError(ports.ReviewLockOperationRelease, ports.ReviewCoordinationReasonAcquireUncertain, err)
		if unsafeCoordinationDisposition(err) {
			return errors.Join(protection, coordinationFailure(err, true)), nil
		}
	}
	return protection, coordinationFailure(err, true)
}
