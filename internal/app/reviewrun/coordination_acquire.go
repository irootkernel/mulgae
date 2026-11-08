package reviewrun

import (
	"context"
	"errors"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	coordinationCallBudget  = 30 * time.Second
	coordinationWaitSlice   = 15 * time.Second
	coordinationDrainBudget = 2 * time.Minute
)

func (c *ReviewCoordinator) acquireOwnedGrant(ctx context.Context, req ReviewAcquireRequest, executionBudget time.Duration) (ReviewAcquireOutcome, error) {
	call, cancel := context.WithTimeout(ctx, coordinationCallBudget)
	outcome, err := c.AcquireOrReplay(call, req)
	cancel()
	if outcome.ReplayedIntent && (outcome.Record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 || outcome.Record.LocalDrainState != ports.ReviewLocalDrainNotStarted) {
		return outcome, coordinationFailure(coordinationError(ports.ReviewCoordinationReasonLockStateConflict, ports.ReviewLockOperationAcquire, true, err), false)
	}
	if err != nil {
		var fault *ports.ReviewCoordinationError
		if errors.As(err, &fault) && fault.KnownReply != nil {
			return outcome, coordinationFailure(errors.Join(err, c.settleUnusedGrant(req, outcome, false)), false)
		}
		// One bounded exact-payload reconciliation can settle an uncertain send.
		// It never authorizes provider execution after the failed admission.
		if errors.As(err, &fault) && fault.Uncertain && (fault.Reason == ports.ReviewCoordinationReasonAcquireUncertain || fault.Reason == ports.ReviewCoordinationReasonControllerUnreachable || fault.Reason == ports.ReviewCoordinationReasonContextCancelled) && outcome.Record.Validate() == nil {
			reconcile, stop := context.WithTimeout(context.WithoutCancel(ctx), coordinationCallBudget)
			known, reconcileErr := c.AcquireOrReplay(reconcile, req)
			stop()
			if known.Reply.Current.RequestID != "" && (!known.ReplayedIntent || known.Record.LocalDrainState == ports.ReviewLocalDrainNotStarted) {
				reconcileErr = errors.Join(reconcileErr, c.settleUnusedGrant(req, known, ctx.Err() != nil))
			}
			return known, coordinationFailure(errors.Join(err, reconcileErr), false)
		}
		return outcome, coordinationFailure(err, false)
	}
	for outcome.Reply.Current.State == ports.ReviewLockStateQueued {
		if ctx.Err() != nil {
			return outcome, c.cancelUnusedGrant(ctx, req, outcome, nil)
		}
		wait, stop := context.WithTimeout(ctx, coordinationCallBudget)
		reply, waitErr := c.transport.Wait(wait, outcome.Reply.Current.RequestID, coordinationWaitSlice)
		stop()
		if waitErr != nil {
			if ctx.Err() != nil {
				return outcome, c.cancelUnusedGrant(ctx, req, outcome, waitErr)
			}
			var fault *ports.ReviewCoordinationError
			if errors.As(waitErr, &fault) && fault.NativeCode == "WAIT_TIMEOUT" && !fault.Uncertain {
				continue
			}
			return outcome, coordinationFailure(errors.Join(ensureCoordinationError(ports.ReviewLockOperationWait, ports.ReviewCoordinationReasonAcquireUncertain, waitErr), c.settleUnusedGrant(req, outcome, true)), false)
		}
		if err := validateCoordinationReply(outcome.Record, reply, ports.ReviewLockOperationWait); err != nil {
			return outcome, coordinationFailure(err, false)
		}
		outcome.Reply = reply
		persist, done := context.WithTimeout(context.WithoutCancel(ctx), coordinationCallBudget)
		record, persistErr := c.intentStore.UpdateObservation(persist, req.Root, req.SessionID, req.RunID, reply, c.observationTime(outcome.Record))
		done()
		if persistErr != nil {
			known := outcome.Record
			known.ObservedReceipt, known.ObservedRequest = &reply.Receipt, &reply.Current
			outcome.Record = known
			return outcome, coordinationFailure(errors.Join(coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, ports.ReviewLockOperationWait, true, persistErr), c.settleUnusedGrant(req, outcome, true)), false)
		}
		outcome.Record = record
		if grant, ok := record.GrantReference(); ok {
			outcome.Grant = &grant
		}
	}
	if ctx.Err() != nil {
		return outcome, c.cancelUnusedGrant(ctx, req, outcome, nil)
	}
	if outcome.Reply.Current.State != ports.ReviewLockStateGranted || outcome.Grant == nil {
		reason := ports.ReviewCoordinationReasonLockStateConflict
		switch outcome.Reply.Current.State {
		case ports.ReviewLockStateQueueExpired:
			reason = ports.ReviewCoordinationReasonQueueExpired
		case ports.ReviewLockStateCancelled:
			reason = ports.ReviewCoordinationReasonLockCancelled
		case ports.ReviewLockStateHoldExpired:
			reason = ports.ReviewCoordinationReasonHoldExpired
		case ports.ReviewLockStateReleased:
			reason = ports.ReviewCoordinationReasonLockReleased
		}
		return outcome, coordinationFailure(coordinationError(reason, ports.ReviewLockOperationAcquire, false, nil), false)
	}
	grant, now := *outcome.Grant, c.clock.Now()
	if executionBudget <= 0 || grant.MaxHoldSeconds > int64((1<<63-1)/time.Second) || grant.LivenessSeconds > int64((1<<63-1)/time.Second) || grant.LivenessDeadline.After(grant.MaxHoldDeadline) || !now.Before(grant.LivenessDeadline) {
		return outcome, coordinationFailure(errors.Join(coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, ports.ReviewLockOperationAcquire, false, nil), c.settleUnusedGrant(req, outcome, false)), false)
	}
	required := executionBudget + coordinationDrainBudget
	if time.Duration(grant.MaxHoldSeconds)*time.Second <= required || grant.MaxHoldDeadline.Sub(now) <= required {
		return outcome, coordinationFailure(errors.Join(coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationAcquire, false, nil), c.settleUnusedGrant(req, outcome, false)), false)
	}
	return outcome, nil
}

func (c *ReviewCoordinator) observationTime(record ports.ReviewLockRecord) time.Time {
	now := c.clock.Now().UTC()
	if now.Before(record.UpdatedAt) {
		return record.UpdatedAt
	}
	return now
}

func validateCoordinationReply(record ports.ReviewLockRecord, reply ports.ReviewLockReply, operation ports.ReviewLockOperation) error {
	current := reply.Current
	if err := reply.Validate(operation); err != nil {
		return coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, operation, true, err)
	}
	if current.InstallationID != record.InstallationID || current.LockID != record.ResourceID || current.RequestKey != record.Payload.RequestKey || current.Holder != record.Payload.Holder || record.ObservedRequest != nil && current.RequestID != record.ObservedRequest.RequestID {
		return coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, operation, true, nil)
	}
	if original := record.ObservedRequest; original != nil && original.State.WasGranted() && (current.GrantID != original.GrantID || current.Generation != original.Generation || current.MaxHoldDeadline == nil || original.MaxHoldDeadline == nil || !current.MaxHoldDeadline.Equal(*original.MaxHoldDeadline) || current.GrantedAt == nil || !current.GrantedAt.Equal(*original.GrantedAt) || current.MaxHoldSeconds != original.MaxHoldSeconds || current.LivenessSeconds != original.LivenessSeconds) {
		return coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, operation, true, nil)
	}
	if current.State == ports.ReviewLockStateGranted && current.LivenessDeadline.After(*current.MaxHoldDeadline) {
		return coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, operation, true, nil)
	}
	return nil
}

// This path has admitted no protected effect. A replay with unknown local proof
// is refused above and may never use this unused-grant disposition authority.
func (c *ReviewCoordinator) settleUnusedGrant(req ReviewAcquireRequest, outcome ReviewAcquireOutcome, abandon bool) error {
	if outcome.Record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 || outcome.Record.LocalDrainState != ports.ReviewLocalDrainNotStarted || outcome.Reply.Current.RequestID == "" || outcome.Reply.Current.State.IsTerminal() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), coordinationCallBudget)
	defer cancel()
	operation := ports.ReviewLockOperationCancel
	var reply ports.ReviewLockReply
	var err error
	if !abandon && outcome.Reply.Current.State == ports.ReviewLockStateGranted {
		operation = ports.ReviewLockOperationRelease
		reply, err = c.transport.Release(ctx, outcome.Reply.Current.GrantID)
	} else {
		reply, err = c.transport.Cancel(ctx, outcome.Reply.Current.RequestID)
	}
	if err != nil {
		return ensureCoordinationError(operation, ports.ReviewCoordinationReasonAcquireUncertain, err)
	}
	if err := validateCoordinationReply(outcome.Record, reply, operation); err != nil {
		return err
	}
	if !reply.Current.State.IsTerminal() {
		return coordinationError(ports.ReviewCoordinationReasonLockStateConflict, operation, true, nil)
	}
	_, err = c.intentStore.UpdateObservation(ctx, req.Root, req.SessionID, req.RunID, reply, c.observationTime(outcome.Record))
	if err != nil {
		return coordinationError(ports.ReviewCoordinationReasonObservationPersistFailed, operation, true, err)
	}
	return nil
}

func (c *ReviewCoordinator) cancelUnusedGrant(ctx context.Context, req ReviewAcquireRequest, outcome ReviewAcquireOutcome, observationErr error) error {
	if err := c.settleUnusedGrant(req, outcome, true); err != nil {
		return coordinationFailure(errors.Join(ctx.Err(), observationErr, err), false)
	}
	// Successful terminal cancellation reconciles the cancelled long poll's
	// transport uncertainty. Keep its original cause without claiming it remains
	// an unresolved native mutation.
	cause := coordinationError(ports.ReviewCoordinationReasonContextCancelled, ports.ReviewLockOperationCancel, false, errors.Join(ctx.Err(), observationErr))
	failure, _ := domain.NewFailure("review.coordination", domain.FailureCancelled, "review cancelled before protected work", cause)
	return failure
}
