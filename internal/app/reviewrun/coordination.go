package reviewrun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type ReviewCoordinator struct {
	intentStore  ports.ReviewCoordinationIntentStore
	transport    ports.ReviewLockTransport
	clock        ports.Clock
	timer        coordinationTimer
	rawLockGrant string
	hasLockGrant bool
}

func NewReviewCoordinator(
	intentStore ports.ReviewCoordinationIntentStore,
	transport ports.ReviewLockTransport,
	clock ports.Clock,
	rawLockGrant string,
	hasLockGrant bool,
) (*ReviewCoordinator, error) {
	if intentStore == nil || transport == nil || clock == nil {
		return nil, fmt.Errorf("review coordinator: nil dependency")
	}
	return &ReviewCoordinator{
		intentStore:  intentStore,
		transport:    transport,
		clock:        clock,
		timer:        newCoordinationTimer,
		rawLockGrant: rawLockGrant,
		hasLockGrant: hasLockGrant || rawLockGrant != "",
	}, nil
}

type ReviewAcquireRequest struct {
	Root         ports.AnchoredRoot
	SessionID    domain.SessionID
	RunID        domain.RunID
	QueueSeconds *int64
}

type ReviewAcquireOutcome struct {
	Installation   ports.ReviewLockInstallation
	Resource       ports.ReviewLockResource
	Record         ports.ReviewLockRecord
	Reply          ports.ReviewLockReply
	Grant          *ports.ReviewLockGrantReference
	ReplayedIntent bool
}

// AcquireOrReplay performs TASK-076's single-acquisition/replay foundation:
// read-only Hello + InspectResource("mulgae-review") admission, durable intent
// load or exclusive persistence before acquisition, one Acquire call with the
// exact persisted payload bytes, and post-acquire observation persistence.
func (c *ReviewCoordinator) AcquireOrReplay(
	ctx context.Context,
	req ReviewAcquireRequest,
) (ReviewAcquireOutcome, error) {
	if ctx == nil {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "nil context",
		}
	}
	if err := ctx.Err(); err != nil {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonContextCancelled,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "context cancelled before coordination admission",
			Cause:     err,
		}
	}
	if !req.Root.Valid() {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid anchored root",
		}
	}
	if _, err := domain.ParseSessionID(req.SessionID.String()); err != nil {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid session ID",
			Cause:     err,
		}
	}
	if _, err := domain.ParseRunID(req.RunID.String()); err != nil {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "invalid run ID",
			Cause:     err,
		}
	}
	if req.QueueSeconds != nil && (*req.QueueSeconds < 1 || *req.QueueSeconds > ports.HaepariMaxQueueSeconds) {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "queue_seconds out of valid native range",
		}
	}
	if c.hasLockGrant {
		if _, err := ports.DecodeReviewBorrowedGrantReference(c.rawLockGrant); err != nil {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonParentContextInvalid,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Uncertain: false,
				Message:   "HAEPARI_LOCK_GRANT is malformed",
				Cause:     err,
			}
		}
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:     ports.ReviewCoordinationReasonLockStateConflict,
			Operation:  ports.ReviewLockOperationAcquire,
			NativeCode: "CONFLICT",
			Retry:      ports.ReviewCoordinationRetryNever,
			Uncertain:  false,
			Message:    "inherited HAEPARI_LOCK_GRANT forbids owned lock acquisition",
		}
	}

	installation, err := c.transport.Hello(ctx)
	if err != nil {
		return ReviewAcquireOutcome{}, ensureCoordinationError(ports.ReviewLockOperationHello, ports.ReviewCoordinationReasonControllerUnreachable, err)
	}
	if err := installation.Validate(); err != nil {
		reason := ports.ReviewCoordinationReasonProtocolIncompatible
		if strings.Contains(err.Error(), "missing capability") {
			reason = ports.ReviewCoordinationReasonCapabilityUnsupported
		}
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationHello,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   err.Error(),
			Cause:     err,
		}
	}

	resource, err := c.transport.InspectResource(ctx, ports.HaepariReviewResourceID)
	if err != nil {
		return ReviewAcquireOutcome{}, ensureCoordinationError(ports.ReviewLockOperationInspectResource, ports.ReviewCoordinationReasonResourceInvalid, err)
	}
	if err := resource.Validate(installation.InstallationID); err != nil {
		reason := ports.ReviewCoordinationReasonResourceInvalid
		if resource.InstallationID != "" && resource.InstallationID != installation.InstallationID {
			reason = ports.ReviewCoordinationReasonInstallationMismatch
		}
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    reason,
			Operation: ports.ReviewLockOperationInspectResource,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   err.Error(),
			Cause:     err,
		}
	}

	existing, found, err := c.intentStore.LoadIntent(ctx, req.Root, req.SessionID, req.RunID)
	if err != nil {
		return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Message:   "refused lock.acquire because existing intent could not be verified",
			Cause:     err,
		}
	}

	var record ports.ReviewLockRecord
	var replayedIntent bool
	if found {
		if err := existing.Validate(); err != nil {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Message:   "persisted intent failed validation",
				Cause:     err,
			}
		}
		if existing.SchemaVersion == artifactwire.HaepariLockIntentSchemaV3 || existing.BorrowedGrant != nil {
			return ReviewAcquireOutcome{
				Installation:   installation,
				Resource:       resource,
				Record:         existing,
				ReplayedIntent: true,
			}, &ports.ReviewCoordinationError{
				Reason:      ports.ReviewCoordinationReasonLockStateConflict,
				Operation:   ports.ReviewLockOperationAcquire,
				Retry:       ports.ReviewCoordinationRetryNever,
				Uncertain:   false,
				Message:     "persisted borrowed coordination record cannot be replayed as owned acquisition",
				KnownRecord: &existing,
			}
		}
		if existing.InstallationID != installation.InstallationID {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonInstallationMismatch,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Message:   "persisted intent installation_id does not match active controller installation_id",
			}
		}
		if !sameQueueSeconds(existing.Payload.QueueSeconds, req.QueueSeconds) {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonAcquireConflict,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Message:   "requested queue_seconds conflicts with persisted immutable intent payload",
			}
		}
		record = existing
		replayedIntent = true
	} else {
		payload, err := ports.NewReviewLockRequestPayload(req.SessionID, req.RunID, req.QueueSeconds)
		if err != nil {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonAcquireInvalid,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Message:   err.Error(),
				Cause:     err,
			}
		}
		now := c.clock.Now().UTC()
		draft := ports.ReviewLockRecord{
			SchemaVersion:   artifactwire.HaepariLockIntentSchemaV2,
			LocalDrainState: ports.ReviewLocalDrainNotStarted,
			SessionID:       req.SessionID,
			RunID:           req.RunID,
			InstallationID:  installation.InstallationID,
			ResourceID:      ports.HaepariReviewResourceID,
			Payload:         payload,
			PersistedAt:     now,
			UpdatedAt:       now,
		}
		persisted, err := c.intentStore.PersistIntent(ctx, req.Root, draft)
		if err != nil {
			return ReviewAcquireOutcome{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonPersistenceRefused,
				Operation: ports.ReviewLockOperationAcquire,
				Retry:     ports.ReviewCoordinationRetryNever,
				Message:   "refused lock.acquire because intent persistence failed",
				Cause:     err,
			}
		}
		record = persisted
	}

	reply, err := c.transport.Acquire(ctx, record.Payload.CanonicalJSON)
	if err != nil {
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         record,
			ReplayedIntent: replayedIntent,
		}, ensureCoordinationError(ports.ReviewLockOperationAcquire, ports.ReviewCoordinationReasonAcquireUncertain, err)
	}

	if err := reply.Validate(ports.ReviewLockOperationAcquire); err != nil {
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         record,
			ReplayedIntent: replayedIntent,
		}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: true,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	if reply.Current.InstallationID != record.InstallationID {
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         record,
			ReplayedIntent: replayedIntent,
		}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonInstallationMismatch,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: true,
			Message:   "lock.acquire reply installation_id does not match persisted intent installation_id",
		}
	}
	if reply.Current.LockID != record.ResourceID ||
		reply.Current.RequestKey != record.Payload.RequestKey ||
		reply.Current.Holder != record.Payload.Holder {
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         record,
			ReplayedIntent: replayedIntent,
		}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: true,
			Message:   "lock.acquire reply identity fields do not match persisted request payload",
		}
	}
	if record.ObservedRequest != nil && record.ObservedRequest.RequestID != reply.Current.RequestID {
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         record,
			ReplayedIntent: replayedIntent,
		}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonProtocolIncompatible,
			Operation: ports.ReviewLockOperationAcquire,
			Retry:     ports.ReviewCoordinationRetryNever,
			Uncertain: true,
			Message:   "lock.acquire replay changed request_id for persisted intent",
		}
	}

	if err := validateCoordinationReply(record, reply, ports.ReviewLockOperationAcquire); err != nil {
		return ReviewAcquireOutcome{Installation: installation, Resource: resource, Record: record, ReplayedIntent: replayedIntent}, err
	}
	observedAt := c.clock.Now().UTC()
	if observedAt.Before(record.PersistedAt) {
		observedAt = record.PersistedAt
	}
	receiptCopy := reply.Receipt
	currentCopy := reply.Current
	knownRecord := record
	knownRecord.UpdatedAt = observedAt
	knownRecord.ObservedReceipt = &receiptCopy
	knownRecord.ObservedRequest = &currentCopy

	var grantPtr *ports.ReviewLockGrantReference
	if grantRef, ok := knownRecord.GrantReference(); ok {
		grantPtr = &grantRef
	}

	persistedObs, obsErr := c.intentStore.UpdateObservation(ctx, req.Root, req.SessionID, req.RunID, reply, observedAt)
	if obsErr != nil {
		knownRecordCopy := knownRecord
		replyCopy := reply
		return ReviewAcquireOutcome{
			Installation:   installation,
			Resource:       resource,
			Record:         knownRecord,
			Reply:          reply,
			Grant:          grantPtr,
			ReplayedIntent: replayedIntent,
		}, &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonObservationPersistFailed,
			Operation:   ports.ReviewLockOperationAcquire,
			Retry:       ports.ReviewCoordinationRetryInspectFirst,
			Uncertain:   true,
			Message:     "lock.acquire succeeded on controller but local observation persistence failed",
			KnownRecord: &knownRecordCopy,
			KnownReply:  &replyCopy,
			Cause:       obsErr,
		}
	}

	if grantRef, ok := persistedObs.GrantReference(); ok {
		grantPtr = &grantRef
	}
	return ReviewAcquireOutcome{
		Installation:   installation,
		Resource:       resource,
		Record:         persistedObs,
		Reply:          reply,
		Grant:          grantPtr,
		ReplayedIntent: replayedIntent,
	}, nil
}

func sameQueueSeconds(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func ensureCoordinationError(op ports.ReviewLockOperation, fallbackReason ports.ReviewCoordinationReason, err error) error {
	var coordErr *ports.ReviewCoordinationError
	if errors.As(err, &coordErr) {
		return err
	}
	return &ports.ReviewCoordinationError{
		Reason:    fallbackReason,
		Operation: op,
		Retry:     ports.ReviewCoordinationRetryInspectFirst,
		Uncertain: op == ports.ReviewLockOperationAcquire || op == ports.ReviewLockOperationWait || op == ports.ReviewLockOperationRenew || op == ports.ReviewLockOperationRelease || op == ports.ReviewLockOperationCancel,
		Message:   err.Error(),
		Cause:     err,
	}
}
