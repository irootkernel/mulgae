package reviewrun

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type coordinationTimer func(time.Duration) (<-chan time.Time, func())

func newCoordinationTimer(delay time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(delay)
	return timer.C, func() { timer.Stop() }
}

type reviewProtection interface {
	preparationContext(budget time.Duration) (context.Context, context.CancelFunc)
	preparationFailure(ctx context.Context, err error) error
	admitExecution(budget time.Duration) error
	workContext() context.Context
	cancel(cause error)
	beginTerminal()
	finish(ctx context.Context, completed bool) (protection, disposition error)
}

func (c *ReviewCoordinator) startReview(ctx context.Context, req ReviewAcquireRequest, budget time.Duration) (reviewProtection, error) {
	if c.hasLockGrant {
		borrowed, err := c.startBorrowedReview(ctx, req, budget)
		if borrowed == nil {
			return nil, err
		}
		return borrowed, err
	}
	owned, err := c.startOwnedReview(ctx, req, budget)
	if owned == nil {
		return nil, err
	}
	return owned, err
}

func (c *ReviewCoordinator) startBorrowedReview(ctx context.Context, req ReviewAcquireRequest, budget time.Duration) (*borrowedReview, error) {
	if ctx == nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "nil context",
		}), false)
	}
	if err := ctx.Err(); err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonContextCancelled,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "context cancelled before borrowed coordination admission",
			Cause:     err,
		}), false)
	}
	if !req.Root.Valid() {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid anchored root",
		}), false)
	}
	if _, err := domain.ParseSessionID(req.SessionID.String()); err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid session ID",
			Cause:     err,
		}), false)
	}
	if _, err := domain.ParseRunID(req.RunID.String()); err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid run ID",
			Cause:     err,
		}), false)
	}
	ref, err := ports.DecodeReviewBorrowedGrantReference(c.rawLockGrant)
	if err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonParentContextInvalid,
			Operation: ports.ReviewLockOperationHello,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   err.Error(),
			Cause:     err,
		}), false)
	}
	if ref.LockID != ports.HaepariReviewResourceID {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:     ports.ReviewCoordinationReasonLockStateConflict,
			Operation:  ports.ReviewLockOperationList,
			NativeCode: "CONFLICT",
			Retry:      ports.ReviewCoordinationRetryNever,
			Uncertain:  false,
			Message:    "borrowed grant lock_id does not match intended review resource",
		}), false)
	}

	existing, found, err := c.intentStore.LoadIntent(ctx, req.Root, req.SessionID, req.RunID)
	if err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "refused borrowed admission because existing intent could not be verified",
			Cause:     err,
		}), false)
	}
	if found {
		if err := existing.Validate(); err != nil {
			return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
				Operation: ports.ReviewLockOperationList,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: false,
				Message:   "persisted intent failed validation",
				Cause:     err,
			}), false)
		}
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonLockStateConflict,
			Operation:   ports.ReviewLockOperationList,
			NativeCode:  "CONFLICT",
			Retry:       ports.ReviewCoordinationRetryNever,
			Uncertain:   false,
			Message:     "existing child intent does not authorize borrowed provider replay",
			KnownRecord: &existing,
		}), false)
	}

	lookupCtx, cancelLookup := context.WithTimeout(ctx, coordinationCallBudget)
	installation, matched, err := c.admitBorrowedGrant(lookupCtx, ctx, ref, budget)
	cancelLookup()
	if err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, err), false)
	}

	now := c.clock.Now().UTC()
	refCopy := ref
	reqCopy := matched
	draft := ports.ReviewLockRecord{
		SchemaVersion:   artifactwire.HaepariLockIntentSchemaV3,
		LocalDrainState: ports.ReviewLocalDrainNotStarted,
		SessionID:       req.SessionID,
		RunID:           req.RunID,
		InstallationID:  installation.InstallationID,
		ResourceID:      ports.HaepariReviewResourceID,
		BorrowedGrant:   &refCopy,
		ObservedRequest: &reqCopy,
		PersistedAt:     now,
		UpdatedAt:       now,
	}
	persisted, err := c.intentStore.PersistIntent(ctx, req.Root, draft)
	if err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "refused borrowed admission because intent persistence failed",
			Cause:     err,
		}), false)
	}
	mark, cancelMark := context.WithTimeout(context.WithoutCancel(ctx), coordinationCallBudget)
	record, err := c.intentStore.UpdateLocalDrain(mark, req.Root, req.SessionID, req.RunID, ports.ReviewLocalDrainUnverified, c.observationTime(persisted))
	cancelMark()
	if err != nil {
		return nil, coordinationFailure(withCoordinationPhase("admission", false, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryInspectFirst,
			Uncertain: true,
			Message:   "failed to mark borrowed child local drain unverified",
			Cause:     err,
		}), false)
	}

	work, cancelWork := context.WithCancelCause(ctx)
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	borrowed := &borrowedReview{
		coordinator:      c,
		request:          req,
		record:           record,
		ref:              ref,
		parent:           matched,
		livenessDeadline: *matched.LivenessDeadline,
		maxHoldDeadline:  *matched.MaxHoldDeadline,
		livenessSeconds:  matched.LivenessSeconds,
		work:             work,
		cancelWork:       cancelWork,
		monitorCtx:       monitorCtx,
		stopMonitor:      stopMonitor,
		stop:             make(chan struct{}),
		pulse:            make(chan struct{}, 1),
		done:             make(chan struct{}),
		timer:            c.timer,
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); borrowed.monitorLoop() }()
	go func() { defer workers.Done(); borrowed.guardLoop() }()
	go func() { workers.Wait(); close(borrowed.done) }()
	if err := borrowed.admitExecution(budget); err != nil {
		return borrowed, err
	}
	return borrowed, nil
}

func (owner *ownedReview) workContext() context.Context {
	return owner.work
}

func (owner *ownedReview) cancel(cause error) {
	owner.cancelWork(cause)
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
			owner.fail(withCoordinationPhase("renew", true, ensureCoordinationError(ports.ReviewLockOperationRenew, ports.ReviewCoordinationReasonAcquireUncertain, err)))
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

func (c *ReviewCoordinator) admitBorrowedGrant(
	lookupCtx context.Context,
	callerCtx context.Context,
	ref ports.ReviewBorrowedGrantReference,
	budget time.Duration,
) (ports.ReviewLockInstallation, ports.ReviewLockRequest, error) {
	installation, err := c.transport.Hello(lookupCtx)
	if err != nil {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, classifyBorrowedLookupErr(callerCtx, ports.ReviewLockOperationHello, ports.ReviewCoordinationReasonControllerUnreachable, err)
	}
	if err := installation.Validate(); err != nil {
		reason := ports.ReviewCoordinationReasonProtocolIncompatible
		if strings.Contains(err.Error(), "missing capability") {
			reason = ports.ReviewCoordinationReasonCapabilityUnsupported
		}
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationHello,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	if installation.InstallationID != ref.InstallationID {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:     ports.ReviewCoordinationReasonInstallationMismatch,
			Operation:  ports.ReviewLockOperationHello,
			NativeCode: "CONFLICT",
			Retry:      ports.ReviewCoordinationRetryNever,
			Uncertain:  false,
			Message:    "borrowed grant installation_id does not match active controller installation_id",
		}
	}

	resource, err := c.transport.InspectResource(lookupCtx, ports.HaepariReviewResourceID)
	if err != nil {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, classifyBorrowedLookupErr(callerCtx, ports.ReviewLockOperationInspectResource, ports.ReviewCoordinationReasonResourceInvalid, err)
	}
	if err := resource.Validate(installation.InstallationID); err != nil {
		reason := ports.ReviewCoordinationReasonResourceInvalid
		if resource.InstallationID != "" && resource.InstallationID != installation.InstallationID {
			reason = ports.ReviewCoordinationReasonInstallationMismatch
		}
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationInspectResource,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   err.Error(),
			Cause:     err,
		}
	}

	matched, pageNow, err := c.inspectBorrowedGrant(lookupCtx, callerCtx, ref)
	if err != nil {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, err
	}
	if budget <= 0 || matched.MaxHoldSeconds > int64((1<<63-1)/time.Second) || matched.LivenessSeconds > int64((1<<63-1)/time.Second) || matched.LivenessDeadline.After(*matched.MaxHoldDeadline) {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "borrowed grant has invalid hold or liveness bounds",
		}
	}
	localNow := c.clock.Now()
	if !pageNow.Before(*matched.LivenessDeadline) || !pageNow.Before(*matched.MaxHoldDeadline) || !localNow.Before(*matched.LivenessDeadline) || !localNow.Before(*matched.MaxHoldDeadline) {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:     ports.ReviewCoordinationReasonHoldExpired,
			Operation:  ports.ReviewLockOperationList,
			NativeCode: "LOCK_EXPIRED",
			Retry:      ports.ReviewCoordinationRetryNever,
			Uncertain:  false,
			Message:    "borrowed grant expired before admission completed",
		}
	}
	required := budget + coordinationDrainBudget
	if time.Duration(matched.MaxHoldSeconds)*time.Second <= required || matched.MaxHoldDeadline.Sub(pageNow) <= required || matched.MaxHoldDeadline.Sub(localNow) <= required {
		return ports.ReviewLockInstallation{}, ports.ReviewLockRequest{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonHoldBudgetExceeded,
			Operation: ports.ReviewLockOperationList,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "borrowed grant remaining max_hold is insufficient for execution and drain budget",
		}
	}
	return installation, matched, nil
}

func (c *ReviewCoordinator) inspectBorrowedGrant(
	lookupCtx context.Context,
	callerCtx context.Context,
	ref ports.ReviewBorrowedGrantReference,
) (ports.ReviewLockRequest, time.Time, error) {
	var (
		cursor       string
		lastSequence int64
	)
	for {
		page, err := c.transport.ListLocks(lookupCtx, ports.HaepariReviewResourceID, cursor, 100)
		if err != nil {
			return ports.ReviewLockRequest{}, time.Time{}, classifyBorrowedLookupErr(callerCtx, ports.ReviewLockOperationList, ports.ReviewCoordinationReasonControllerUnreachable, err)
		}
		if len(page.Requests) > 100 {
			return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: ports.ReviewLockOperationList,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: false,
				Message:   "locks.list returned more than 100 requests",
			}
		}
		if err := page.Validate(ref.InstallationID); err != nil {
			reason := ports.ReviewCoordinationReasonProtocolIncompatible
			nativeCode := ""
			if page.InstallationID != "" && page.InstallationID != ref.InstallationID {
				reason = ports.ReviewCoordinationReasonInstallationMismatch
				nativeCode = "CONFLICT"
			}
			return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
				Reason:     reason,
				Operation:  ports.ReviewLockOperationList,
				NativeCode: nativeCode,
				Retry:      ports.ReviewCoordinationRetryNever,
				Uncertain:  false,
				Message:    err.Error(),
				Cause:      err,
			}
		}
		var matched *ports.ReviewLockRequest
		for i := range page.Requests {
			row := page.Requests[i]
			if row.Sequence <= lastSequence {
				return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
					Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
					Operation: ports.ReviewLockOperationList,
					Retry:     ports.ReviewCoordinationRetryNever,
					Uncertain: false,
					Message:   "locks.list returned non-progressing request sequence",
				}
			}
			lastSequence = row.Sequence
			if row.GrantID != "" && row.GrantID == ref.GrantID {
				if matched != nil {
					return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
						Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
						Operation: ports.ReviewLockOperationList,
						Retry:     ports.ReviewCoordinationRetryNever,
						Uncertain: false,
						Message:   "locks.list returned duplicate matching grant row",
					}
				}
				rowCopy := row
				matched = &rowCopy
			}
		}
		if matched != nil {
			if matched.State != ports.ReviewLockStateGranted {
				reason := ports.ReviewCoordinationReasonHoldExpired
				switch matched.State {
				case ports.ReviewLockStateReleased:
					reason = ports.ReviewCoordinationReasonLockReleased
				case ports.ReviewLockStateCancelled:
					reason = ports.ReviewCoordinationReasonLockCancelled
				case ports.ReviewLockStateQueueExpired:
					reason = ports.ReviewCoordinationReasonQueueExpired
				}
				return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
					Reason:     reason,
					Operation:  ports.ReviewLockOperationList,
					NativeCode: "LOCK_EXPIRED",
					Retry:      ports.ReviewCoordinationRetryNever,
					Uncertain:  false,
					Message:    "borrowed grant is not in granted state",
				}
			}
			if matched.GrantID != ref.GrantID || matched.Generation != ref.Generation {
				return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
					Reason:     ports.ReviewCoordinationReasonHoldExpired,
					Operation:  ports.ReviewLockOperationList,
					NativeCode: "LOCK_EXPIRED",
					Retry:      ports.ReviewCoordinationRetryNever,
					Uncertain:  false,
					Message:    "borrowed grant generation does not match active grant",
				}
			}
			if matched.LivenessDeadline == nil || matched.MaxHoldDeadline == nil || matched.GrantedAt == nil || matched.LivenessDeadline.After(*matched.MaxHoldDeadline) {
				return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
					Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
					Operation: ports.ReviewLockOperationList,
					Retry:     ports.ReviewCoordinationRetryNever,
					Uncertain: false,
					Message:   "borrowed grant has invalid deadline metadata",
				}
			}
			localNow := c.clock.Now()
			if !page.Now.Before(*matched.LivenessDeadline) || !page.Now.Before(*matched.MaxHoldDeadline) || !localNow.Before(*matched.LivenessDeadline) || !localNow.Before(*matched.MaxHoldDeadline) {
				return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
					Reason:     ports.ReviewCoordinationReasonHoldExpired,
					Operation:  ports.ReviewLockOperationList,
					NativeCode: "LOCK_EXPIRED",
					Retry:      ports.ReviewCoordinationRetryNever,
					Uncertain:  false,
					Message:    "borrowed grant liveness or max hold deadline has expired",
				}
			}
			return *matched, page.Now, nil
		}
		if !page.More {
			break
		}
		if len(page.Requests) == 0 || page.NextCursor == cursor || !validBorrowedCursor(page.NextCursor) {
			return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
				Operation: ports.ReviewLockOperationList,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: false,
				Message:   "locks.list returned malformed or non-progressing pagination cursor",
			}
		}
		cursor = page.NextCursor
	}
	return ports.ReviewLockRequest{}, time.Time{}, &ports.ReviewCoordinationError{
		Reason:     ports.ReviewCoordinationReasonLockNotFound,
		Operation:  ports.ReviewLockOperationList,
		NativeCode: "NOT_FOUND",
		Retry:      ports.ReviewCoordinationRetryNever,
		Uncertain:  false,
		Message:    "borrowed grant was not found in active lock list",
	}
}

const maxBorrowedCursorBytes = 2048

func validBorrowedCursor(cursor string) bool {
	if cursor == "" || len(cursor) > maxBorrowedCursorBytes {
		return false
	}
	for i := 0; i < len(cursor); i++ {
		if cursor[i] <= 0x20 || cursor[i] > 0x7e {
			return false
		}
	}
	return true
}

func classifyBorrowedLookupErr(callerCtx context.Context, op ports.ReviewLockOperation, fallback ports.ReviewCoordinationReason, err error) error {
	if callerCtx != nil && callerCtx.Err() != nil {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonContextCancelled,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: false,
			Message:   "context cancelled during borrowed lock lookup",
			Cause:     callerCtx.Err(),
		}
	}
	var coordErr *ports.ReviewCoordinationError
	if errors.As(err, &coordErr) {
		if coordErr.Reason == ports.ReviewCoordinationReasonContextCancelled || errors.Is(err, context.DeadlineExceeded) {
			return &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
				Operation: op,
				Retry:     ports.ReviewCoordinationRetryInspectFirst,
				Uncertain: false,
				Message:   "borrowed lock inspection timed out before completion",
			}
		}
		copied := *coordErr
		copied.Uncertain = false
		return &copied
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
			Operation: op,
			Retry:     ports.ReviewCoordinationRetryInspectFirst,
			Uncertain: false,
			Message:   "borrowed lock inspection timed out before completion",
		}
	}
	return &ports.ReviewCoordinationError{
		Reason:    fallback,
		Operation: op,
		Retry:     ports.ReviewCoordinationRetryInspectFirst,
		Uncertain: false,
		Message:   err.Error(),
		Cause:     err,
	}
}

type borrowedReview struct {
	coordinator      *ReviewCoordinator
	request          ReviewAcquireRequest
	mu               sync.Mutex
	mutation         sync.Mutex
	record           ports.ReviewLockRecord
	ref              ports.ReviewBorrowedGrantReference
	parent           ports.ReviewLockRequest
	livenessDeadline time.Time
	maxHoldDeadline  time.Time
	livenessSeconds  int64
	fault            error
	terminal         bool
	work             context.Context
	cancelWork       context.CancelCauseFunc
	monitorCtx       context.Context
	stopMonitor      context.CancelFunc
	stop             chan struct{}
	stopOnce         sync.Once
	pulse            chan struct{}
	done             chan struct{}
	timer            coordinationTimer
}

func (b *borrowedReview) workContext() context.Context {
	return b.work
}

func (b *borrowedReview) cancel(cause error) {
	b.cancelWork(cause)
}

func (b *borrowedReview) fail(err error) {
	b.mu.Lock()
	b.fault = errors.Join(b.fault, err)
	b.mu.Unlock()
	b.cancelWork(err)
}

func (b *borrowedReview) state() (liveness, maxHold time.Time, terminal bool, fault error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.livenessDeadline, b.maxHoldDeadline, b.terminal, b.fault
}

func (b *borrowedReview) preparationContext(budget time.Duration) (context.Context, context.CancelFunc) {
	_, maxHold, _, _ := b.state()
	cause := withCoordinationPhase("monitor", false, coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationList, false, nil))
	return context.WithDeadlineCause(b.work, maxHold.Add(-budget-coordinationDrainBudget), cause)
}

func (b *borrowedReview) preparationFailure(ctx context.Context, err error) error {
	var fault *ports.ReviewCoordinationError
	if errors.As(context.Cause(ctx), &fault) && fault.Reason == ports.ReviewCoordinationReasonHoldBudgetExceeded {
		return errors.Join(err, coordinationFailure(context.Cause(ctx), true))
	}
	_, _, _, protection := b.state()
	return errors.Join(err, coordinationFailure(protection, true))
}

func (b *borrowedReview) admitExecution(budget time.Duration) error {
	liveness, maxHold, _, fault := b.state()
	if fault != nil {
		return coordinationFailure(fault, true)
	}
	now := b.coordinator.clock.Now()
	if !now.Before(liveness) || maxHold.Sub(now) < budget+coordinationDrainBudget {
		err := withCoordinationPhase("monitor", false, coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationList, false, nil))
		b.fail(err)
		return coordinationFailure(err, true)
	}
	return b.work.Err()
}

func (b *borrowedReview) beginTerminal() {
	b.mu.Lock()
	if !b.terminal && !b.coordinator.clock.Now().Before(b.maxHoldDeadline.Add(-coordinationDrainBudget)) {
		fault := withCoordinationPhase("monitor", false, coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationList, false, nil))
		b.fault = errors.Join(b.fault, fault)
		b.cancelWork(fault)
	}
	b.terminal = true
	b.mu.Unlock()
	select {
	case b.pulse <- struct{}{}:
	default:
	}
}

func (b *borrowedReview) guardLoop() {
	for {
		liveness, maxHold, terminal, fault := b.state()
		if fault != nil {
			return
		}
		deadline := maxHold
		if !terminal {
			deadline = deadline.Add(-coordinationDrainBudget)
		}
		if liveness.Before(deadline) {
			deadline = liveness
		}
		tick, stop := b.timer(deadline.Sub(b.coordinator.clock.Now()))
		select {
		case <-b.stop:
			stop()
			return
		case <-b.pulse:
			stop()
			continue
		case <-tick:
			stop()
			b.mu.Lock()
			now := b.coordinator.clock.Now()
			reason := ports.ReviewCoordinationReason("")
			monitor := false
			if !now.Before(b.livenessDeadline) || !now.Before(b.maxHoldDeadline) {
				reason = ports.ReviewCoordinationReasonHoldExpired
				monitor = true
			} else if !b.terminal && !now.Before(b.maxHoldDeadline.Add(-coordinationDrainBudget)) {
				reason = ports.ReviewCoordinationReasonHoldBudgetExceeded
			}
			if reason != "" {
				err := withCoordinationPhase("monitor", monitor, coordinationError(reason, ports.ReviewLockOperationList, true, nil))
				b.fault = errors.Join(b.fault, err)
				b.cancelWork(err)
				b.mu.Unlock()
				return
			}
			b.mu.Unlock()
		}
	}
}

func (b *borrowedReview) monitorLoop() {
	for {
		liveness, maxHold, _, fault := b.state()
		if fault != nil {
			return
		}
		now := b.coordinator.clock.Now()
		remaining := liveness.Sub(now)
		if maximum := maxHold.Sub(now); maximum < remaining {
			remaining = maximum
		}
		if remaining <= 0 {
			b.fail(withCoordinationPhase("monitor", true, coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationList, true, nil)))
			return
		}
		delay := remaining / 3
		if window := time.Duration(b.livenessSeconds) * time.Second / 3; window > 0 && window < delay {
			delay = window
		}
		tick, stop := b.timer(delay)
		select {
		case <-b.stop:
			stop()
			return
		case <-tick:
			stop()
		}
		call, cancel := context.WithDeadline(b.monitorCtx, minTime(b.coordinator.clock.Now().Add(coordinationCallBudget), liveness, maxHold))
		matched, _, err := b.coordinator.inspectBorrowedGrant(call, nil, b.ref)
		cancel()
		select {
		case <-b.stop:
			return
		default:
		}
		if err == nil {
			if matched.InstallationID != b.ref.InstallationID ||
				matched.LockID != b.ref.LockID ||
				matched.GrantID != b.ref.GrantID ||
				matched.Generation != b.ref.Generation ||
				matched.RequestID != b.parent.RequestID ||
				matched.RequestKey != b.parent.RequestKey ||
				matched.Holder != b.parent.Holder ||
				matched.GrantedAt == nil || b.parent.GrantedAt == nil || !matched.GrantedAt.Equal(*b.parent.GrantedAt) ||
				matched.MaxHoldDeadline == nil || b.parent.MaxHoldDeadline == nil || !matched.MaxHoldDeadline.Equal(*b.parent.MaxHoldDeadline) ||
				matched.MaxHoldSeconds != b.parent.MaxHoldSeconds || matched.LivenessSeconds != b.parent.LivenessSeconds ||
				matched.LivenessDeadline == nil || matched.LivenessDeadline.After(*matched.MaxHoldDeadline) {
				err = coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, ports.ReviewLockOperationList, true, nil)
			}
		}
		if err != nil {
			b.fail(withCoordinationPhase("monitor", true, ensureCoordinationError(ports.ReviewLockOperationList, ports.ReviewCoordinationReasonHoldExpired, err)))
			return
		}
		b.mu.Lock()
		if matched.LivenessDeadline.After(b.livenessDeadline) {
			b.livenessDeadline = *matched.LivenessDeadline
			b.mu.Unlock()
			select {
			case b.pulse <- struct{}{}:
			default:
			}
		} else {
			b.mu.Unlock()
		}
	}
}

func (b *borrowedReview) finish(ctx context.Context, completed bool) (protection, disposition error) {
	liveness, maxHold, _, fault := b.state()
	now := b.coordinator.clock.Now()
	if fault == nil && (!now.Before(liveness) || !now.Before(maxHold)) {
		b.fail(withCoordinationPhase("monitor", true, coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationList, true, nil)))
	}
	b.stopOnce.Do(func() { close(b.stop) })
	b.stopMonitor()
	select {
	case <-b.done:
	case <-ctx.Done():
		return coordinationFailure(withCoordinationPhase("monitor", true, coordinationError(ports.ReviewCoordinationReasonHoldExpired, ports.ReviewLockOperationList, true, ctx.Err())), true), nil
	}
	_, _, _, fault = b.state()
	protection = coordinationFailure(fault, true)
	if !completed {
		return protection, nil
	}
	b.mutation.Lock()
	defer b.mutation.Unlock()
	record, err := b.coordinator.intentStore.UpdateLocalDrain(ctx, b.request.Root, b.request.SessionID, b.request.RunID, ports.ReviewLocalDrainVerified, b.coordinator.observationTime(b.record))
	if err != nil {
		return errors.Join(protection, coordinationFailure(withCoordinationPhase("drain", false, coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, ports.ReviewLockOperationList, true, err)), true)), nil
	}
	b.record = record
	return protection, nil
}
