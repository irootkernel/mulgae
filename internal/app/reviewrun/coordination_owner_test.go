package reviewrun

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type ownerTestClock struct{}

func (ownerTestClock) Now() time.Time { return time.Now().UTC() }

type ownerTestStore struct {
	mu             sync.Mutex
	record         ports.ReviewLockRecord
	observationErr error
	localErr       error
	loadErr        error
}

func (store *ownerTestStore) LoadIntent(context.Context, ports.AnchoredRoot, domain.SessionID, domain.RunID) (ports.ReviewLockRecord, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return ports.ReviewLockRecord{}, false, store.loadErr
	}
	return store.record, store.record.SchemaVersion != "", nil
}
func (store *ownerTestStore) PersistIntent(_ context.Context, _ ports.AnchoredRoot, record ports.ReviewLockRecord) (ports.ReviewLockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.record = record
	return record, record.Validate()
}
func (store *ownerTestStore) UpdateObservation(_ context.Context, _ ports.AnchoredRoot, _ domain.SessionID, _ domain.RunID, reply ports.ReviewLockReply, at time.Time) (ports.ReviewLockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.observationErr != nil {
		return ports.ReviewLockRecord{}, store.observationErr
	}
	store.record.ObservedReceipt, store.record.ObservedRequest, store.record.UpdatedAt = &reply.Receipt, &reply.Current, at
	return store.record, store.record.Validate()
}
func (store *ownerTestStore) UpdateLocalDrain(_ context.Context, _ ports.AnchoredRoot, _ domain.SessionID, _ domain.RunID, state ports.ReviewLocalDrainState, at time.Time) (ports.ReviewLockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.localErr != nil {
		return ports.ReviewLockRecord{}, store.localErr
	}
	store.record.LocalDrainState, store.record.UpdatedAt = state, at
	return store.record, store.record.Validate()
}

type ownerTestTransport struct {
	mu                                                sync.Mutex
	installationID                                    string
	clock                                             ports.Clock
	current                                           ports.ReviewLockRequest
	queued                                            bool
	hold                                              time.Duration
	acquires, waits, releases, cancels, renews, lists int
	acquire                                           func(context.Context, []byte) (ports.ReviewLockReply, error)
	wait                                              func(context.Context, string) (ports.ReviewLockReply, error)
	releaseErr                                        error
	releaseCheck                                      func()
	renew                                             func(context.Context, string) (ports.ReviewLockReply, error)
	list                                              func(context.Context, string, string, int) (ports.ReviewLockList, error)
}

func (transport *ownerTestTransport) now() time.Time {
	if transport.clock != nil {
		return transport.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (transport *ownerTestTransport) instID() string {
	if transport.installationID != "" {
		return transport.installationID
	}
	return "test-installation"
}

func (transport *ownerTestTransport) Hello(context.Context) (ports.ReviewLockInstallation, error) {
	return ports.ReviewLockInstallation{Protocol: ports.HaepariProtocolID, ProtocolVersion: 1, InstallationID: transport.instID(), Capabilities: []string{ports.HaepariCapabilityManagedExecutionV1, ports.HaepariCapabilityAdvisoryLockV1}}, nil
}
func (transport *ownerTestTransport) InspectResource(context.Context, string) (ports.ReviewLockResource, error) {
	return ports.ReviewLockResource{InstallationID: transport.instID(), ResourceID: ports.HaepariReviewResourceID, Kind: "lock", Capacity: 1, ConfigurationDigest: strings.Repeat("a", 64), ConfigRevision: 1, Availability: "available"}, nil
}
func (transport *ownerTestTransport) reply(op ports.ReviewLockReceiptOperation) ports.ReviewLockReply {
	return ports.ReviewLockReply{Current: transport.current, Receipt: ports.ReviewLockReceipt{Operation: op, RequestID: transport.current.RequestID, GrantID: transport.current.GrantID, State: transport.current.State, RecordedAt: transport.now()}}
}
func (transport *ownerTestTransport) Acquire(ctx context.Context, raw []byte) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	transport.acquires++
	custom := transport.acquire
	transport.mu.Unlock()
	if custom != nil {
		return custom(ctx, raw)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	var payload struct {
		LockID     string `json:"lock_id"`
		RequestKey string `json:"request_key"`
		Holder     string `json:"holder"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ports.ReviewLockReply{}, err
	}
	now := transport.now()
	transport.current = ports.ReviewLockRequest{InstallationID: transport.instID(), LockID: payload.LockID, RequestID: "request-1", RequestKey: payload.RequestKey, Holder: payload.Holder, State: ports.ReviewLockStateQueued, Sequence: 1, Slot: -1, QueuedAt: now}
	if !transport.queued {
		transport.grant()
	}
	return transport.reply(ports.ReviewLockReceiptOperationAcquire), nil
}
func (transport *ownerTestTransport) grant() {
	now := transport.now()
	if transport.current.RequestID == "" {
		transport.current.InstallationID = transport.instID()
		transport.current.LockID = ports.HaepariReviewResourceID
		transport.current.RequestID = "request-1"
		transport.current.RequestKey = "mulgae-review.parent-session.parent-run"
		transport.current.Holder = "mulgae-review/parent-session/parent-run"
		transport.current.Sequence = 1
		transport.current.QueuedAt = now
	}
	live := now.Add(time.Minute)
	hold := transport.hold
	if hold == 0 {
		hold = 24 * time.Hour
	}
	maximum := now.Add(hold)
	transport.current.State, transport.current.GrantID, transport.current.Generation, transport.current.Slot = ports.ReviewLockStateGranted, "grant-1", 1, 0
	transport.current.GrantedAt, transport.current.LivenessDeadline, transport.current.MaxHoldDeadline = &now, &live, &maximum
	transport.current.LivenessSeconds, transport.current.MaxHoldSeconds = 60, int64(hold/time.Second)
}
func (transport *ownerTestTransport) Wait(ctx context.Context, id string, _ time.Duration) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	transport.waits++
	wait := transport.wait
	transport.mu.Unlock()
	if wait != nil {
		return wait(ctx, id)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.grant()
	return transport.reply(ports.ReviewLockReceiptOperationClaim), nil
}
func (transport *ownerTestTransport) Renew(ctx context.Context, id string) (ports.ReviewLockReply, error) {
	if transport.renew != nil {
		return transport.renew(ctx, id)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.renews++
	if id != transport.current.GrantID {
		return ports.ReviewLockReply{}, errors.New("wrong grant")
	}
	live := transport.now().Add(time.Minute)
	transport.current.LivenessDeadline = &live
	return transport.reply(ports.ReviewLockReceiptOperationRenew), nil
}
func (transport *ownerTestTransport) Release(_ context.Context, id string) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.releaseCheck != nil {
		transport.releaseCheck()
	}
	transport.releases++
	if transport.releaseErr != nil {
		return ports.ReviewLockReply{}, transport.releaseErr
	}
	if id != transport.current.GrantID {
		return ports.ReviewLockReply{}, errors.New("wrong grant")
	}
	now := transport.now()
	operation := ports.ReviewLockReceiptOperationRelease
	transport.current.State = ports.ReviewLockStateReleased
	if transport.clock != nil && (!now.Before(*transport.current.LivenessDeadline) || !now.Before(*transport.current.MaxHoldDeadline)) {
		transport.current.State = ports.ReviewLockStateHoldExpired
		operation = ports.ReviewLockReceiptOperationExpire
	}
	transport.current.EndedAt = &now
	return transport.reply(operation), nil
}
func (transport *ownerTestTransport) Cancel(_ context.Context, id string) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.cancels++
	if id != transport.current.RequestID {
		return ports.ReviewLockReply{}, errors.New("wrong request")
	}
	now := transport.now()
	transport.current.EndedAt = &now
	if transport.current.State == ports.ReviewLockStateGranted {
		transport.current.State = ports.ReviewLockStateReleased
	} else {
		transport.current.State = ports.ReviewLockStateCancelled
	}
	return transport.reply(ports.ReviewLockReceiptOperationCancel), nil
}
func (transport *ownerTestTransport) ListLocks(ctx context.Context, lockID, cursor string, limit int) (ports.ReviewLockList, error) {
	transport.mu.Lock()
	transport.lists++
	list := transport.list
	current := transport.current
	transport.mu.Unlock()
	if list != nil {
		return list(ctx, lockID, cursor, limit)
	}
	var requests []ports.ReviewLockRequest
	if current.RequestID != "" {
		requests = []ports.ReviewLockRequest{current}
	}
	return ports.ReviewLockList{
		InstallationID: transport.instID(),
		Now:            transport.now(),
		Requests:       requests,
	}, nil
}

func newOwnerTestCoordinator(t *testing.T) (*ReviewCoordinator, *ownerTestStore, *ownerTestTransport) {
	t.Helper()
	store := &ownerTestStore{}
	transport := &ownerTestTransport{}
	coordinator, err := NewReviewCoordinator(store, transport, ownerTestClock{}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, store, transport
}

func testLiveCoordination(t *testing.T) *ReviewCoordinator {
	t.Helper()
	coordinator, _, _ := newOwnerTestCoordinator(t)
	return coordinator
}
func ownerTestRequest(t *testing.T) ReviewAcquireRequest {
	t.Helper()
	root, _ := ports.NewAnchoredRoot(t.TempDir())
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	return ReviewAcquireRequest{Root: root, SessionID: session, RunID: run}
}
func TestReviewCoordinatorOwnedHoldAndDrain(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "verified"}[completed], func(t *testing.T) {
			coordinator, store, transport := newOwnerTestCoordinator(t)
			owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
				t.Fatal("effects admitted without durable unknown proof")
			}
			owner.beginTerminal()
			protection, disposition := owner.finish(context.Background(), completed)
			if protection != nil || disposition != nil {
				t.Fatalf("finish: %v / %v", protection, disposition)
			}
			if completed {
				if transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
					t.Fatal("verified cleanup did not release exact grant")
				}
			} else if transport.releases != 0 || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
				t.Fatal("unknown cleanup ended protection")
			}
		})
	}
}
func TestReviewCoordinatorOwnedInsufficientHold(t *testing.T) {
	coordinator, store, transport := newOwnerTestCoordinator(t)
	transport.hold = 3 * time.Minute
	_, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
	var fault *ports.ReviewCoordinationError
	if !errors.As(err, &fault) || fault.Reason != ports.ReviewCoordinationReasonHoldBudgetExceeded || transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
		t.Fatalf("insufficient unused grant: %v", err)
	}
}
func TestReviewCoordinatorOwnedWaitCancellationRace(t *testing.T) {
	coordinator, store, transport := newOwnerTestCoordinator(t)
	transport.queued = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport.wait = func(_ context.Context, id string) (ports.ReviewLockReply, error) {
		if id != "request-1" {
			t.Fatal("request replaced")
		}
		transport.mu.Lock()
		defer transport.mu.Unlock()
		if transport.waits == 1 {
			return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{Reason: ports.ReviewCoordinationReasonContextCancelled, Operation: ports.ReviewLockOperationWait, NativeCode: "WAIT_TIMEOUT"}
		}
		transport.grant()
		cancel()
		return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
			Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
			Operation: ports.ReviewLockOperationWait,
			Retry:     ports.ReviewCoordinationRetryInspectFirst,
			Uncertain: true,
			Message:   "controller transport interrupted",
			Cause:     context.Canceled,
		}
	}
	_, err := coordinator.startOwnedReview(ctx, ownerTestRequest(t), time.Minute)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureCancelled || !errors.Is(err, context.Canceled) || transport.acquires != 1 || transport.waits != 2 || transport.cancels != 1 || transport.releases != 0 || store.record.ObservedRequest.State != ports.ReviewLockStateReleased || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
		t.Fatalf("cancel race: %v / %+v", err, transport)
	}
	if cause, ok := CoordinationFailureReason(err); !ok || cause != domain.DiagnosticCauseCoordinationCancelled {
		t.Fatalf("expected haepari_cancelled after reconciled wait cancellation, got (%q, %v) for %v", cause, ok, err)
	}
	if summary, ok := coordinationDiagnosticSummary(err); !ok || summary.Phase() != "cancel" || summary.InvariantID() != string(domain.DiagnosticCauseCoordinationCancelled) {
		t.Fatalf("expected phase=cancel invariant=haepari_cancelled, got %+v (%v)", summary, ok)
	}

	// Sibling unresolved mutation (priority 30) and persistence failure (priority 50) must still outrank haepari_cancelled (priority 10).
	unresolvedCancel := &ports.ReviewCoordinationError{
		Reason:    ports.ReviewCoordinationReasonControllerUnreachable,
		Operation: ports.ReviewLockOperationCancel,
		Uncertain: true,
		Message:   "cancel disposition uncertain",
	}
	if cause, ok := CoordinationFailureReason(errors.Join(err, unresolvedCancel)); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
		t.Fatalf("expected unresolved sibling mutation to outrank haepari_cancelled, got (%q, %v)", cause, ok)
	}
	persistenceFault := &ports.ReviewCoordinationError{
		Reason:    ports.ReviewCoordinationReasonObservationPersistFailed,
		Operation: ports.ReviewLockOperationCancel,
		Uncertain: true,
		Message:   "observation persistence failed",
	}
	if cause, ok := CoordinationFailureReason(errors.Join(err, unresolvedCancel, persistenceFault)); !ok || cause != domain.DiagnosticCauseCoordinationPersistenceFailed {
		t.Fatalf("expected sibling persistence fault to outrank protection_lost and cancelled, got (%q, %v)", cause, ok)
	}

	// Full-tree security and internal failures must suppress coordination candidate selection.
	secFailure, _ := domain.NewFailure("test.security", domain.FailureSecurityPolicy, "security policy violation", err)
	if _, ok := CoordinationFailureReason(secFailure); ok {
		t.Fatal("expected FailureSecurityPolicy to suppress coordination failure reason")
	}
	intFailure, _ := domain.NewFailure("test.internal", domain.FailureInternal, "internal invariant violation", err)
	if _, ok := CoordinationFailureReason(intFailure); ok {
		t.Fatal("expected FailureInternal to suppress coordination failure reason")
	}
}
func TestReviewCoordinatorOwnedDispositionFailure(t *testing.T) {
	coordinator, store, transport := newOwnerTestCoordinator(t)
	owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport.releaseErr = errors.New("release unavailable")
	owner.beginTerminal()
	protection, disposition := owner.finish(context.Background(), true)
	if protection != nil || disposition == nil || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
		t.Fatalf("disposition erased completion: %v / %v", protection, disposition)
	}
}

type ownerControlledClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *ownerControlledClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}
func (clock *ownerControlledClock) advance(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

type ownerControlledTimer struct {
	delay time.Duration
	tick  chan time.Time
}

func TestReviewCoordinatorOwnedGuardDoesNotWaitForRenewal(t *testing.T) {
	coordinator, store, transport := newOwnerTestCoordinator(t)
	clock := &ownerControlledClock{now: time.Now().UTC()}
	coordinator.clock = clock
	created := make(chan ownerControlledTimer, 8)
	coordinator.timer = func(delay time.Duration) (<-chan time.Time, func()) {
		tick := make(chan time.Time, 1)
		created <- ownerControlledTimer{delay, tick}
		return tick, func() {}
	}
	entered, unblock := make(chan struct{}), make(chan struct{})
	transport.renew = func(ctx context.Context, _ string) (ports.ReviewLockReply, error) {
		close(entered)
		select {
		case <-unblock:
			return ports.ReviewLockReply{}, errors.New("renewal observation unavailable")
		case <-ctx.Done():
			return ports.ReviewLockReply{}, ctx.Err()
		}
	}
	owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.stopRenew()
	first, second := <-created, <-created
	renew, guard := first, second
	if renew.delay > guard.delay {
		renew, guard = guard, renew
	}
	renew.tick <- clock.Now()
	<-entered
	grant, _, _ := owner.state()
	clock.advance(grant.LivenessDeadline)
	guard.tick <- clock.Now()
	select {
	case <-owner.work.Done():
	case <-time.After(time.Second):
		t.Fatal("deadline guard waited for blocked renewal")
	}
	var fault *ports.ReviewCoordinationError
	if !errors.As(context.Cause(owner.work), &fault) || fault.Reason != ports.ReviewCoordinationReasonHoldExpired {
		t.Fatalf("wrong protection cause: %v", context.Cause(owner.work))
	}
	close(unblock)
	protection, _ := owner.finish(context.Background(), false)
	if protection == nil || transport.releases != 0 || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
		t.Fatal("native expiry supplied false local completion")
	}
}

func TestReviewCoordinatorOwnedPreparationDeadlineCause(t *testing.T) {
	coordinator, _, _ := newOwnerTestCoordinator(t)
	owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(owner.work)
	cause := coordinationError(ports.ReviewCoordinationReasonHoldBudgetExceeded, ports.ReviewLockOperationAcquire, false, nil)
	cancel(cause)
	provider, _ := domain.NewFailure("qualification", domain.FailureTimeout, "qualification deadline", context.DeadlineExceeded)
	got := owner.preparationFailure(ctx, provider)
	if runtimeDiagnosticFailureClass(got) != domain.FailureArtifact {
		t.Fatalf("owned reservation became provider timeout: %v", got)
	}
	if reason, ok := CoordinationFailureReason(got); !ok || reason != domain.DiagnosticCauseCoordinationHoldBudgetExceeded {
		t.Fatalf("lost bounded reservation cause: %v", got)
	}
	owner.beginTerminal()
	_, _ = owner.finish(context.Background(), true)
}

func TestReviewCoordinatorOwnedDispositionTrustBoundary(t *testing.T) {
	for _, boundary := range []string{"operational", "protocol", "security", "internal", "verified-proof-write", "observation-write", "observation-proof-read"} {
		t.Run(boundary, func(t *testing.T) {
			coordinator, store, transport := newOwnerTestCoordinator(t)
			owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			original := errors.New("private disposition failure")
			blocking := true
			switch boundary {
			case "operational":
				transport.releaseErr, blocking = original, false
			case "protocol":
				transport.releaseErr = coordinationError(ports.ReviewCoordinationReasonProtocolIncompatible, ports.ReviewLockOperationRelease, true, original)
			case "security", "internal":
				class := domain.FailureSecurityPolicy
				if boundary == "internal" {
					class = domain.FailureInternal
				}
				transport.releaseErr, _ = domain.NewFailure("test.disposition", class, "private failure", original)
			case "verified-proof-write":
				store.localErr = original
			case "observation-write":
				store.observationErr, blocking = original, false
			case "observation-proof-read":
				store.observationErr, store.loadErr = original, errors.New("local proof unreadable")
			}
			owner.beginTerminal()
			protection, disposition := owner.finish(context.Background(), true)
			if blocking && (protection == nil || disposition != nil) || !blocking && (protection != nil || disposition == nil) {
				t.Fatalf("wrong post-drain boundary: protection=%v disposition=%v", protection, disposition)
			}
			if !errors.Is(errors.Join(protection, disposition), original) {
				t.Fatal("original cause lost")
			}
			if boundary == "verified-proof-write" && transport.releases != 0 {
				t.Fatal("released before durable local proof")
			}
		})
	}
}

func TestReviewCoordinatorBorrowedHoldAndMonitor(t *testing.T) {
	rawGrant := `{"installation_id":"test-installation","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`

	t.Run("success-and-zero-parent-mutations", func(t *testing.T) {
		store := &ownerTestStore{}
		transport := &ownerTestTransport{}
		transport.grant()
		coordinator, err := NewReviewCoordinator(store, transport, ownerTestClock{}, rawGrant, true)
		if err != nil {
			t.Fatal(err)
		}
		protection, err := coordinator.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		if err != nil {
			t.Fatalf("expected valid borrowed admission, got %v", err)
		}
		if store.record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV3 || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified || store.record.BorrowedGrant == nil {
			t.Fatalf("expected persisted v3 unverified record before protected execution, got %+v", store.record)
		}
		protection.beginTerminal()
		protErr, dispErr := protection.finish(context.Background(), true)
		if protErr != nil || dispErr != nil {
			t.Fatalf("finish: %v / %v", protErr, dispErr)
		}
		if store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
			t.Fatalf("expected verified v3 local drain after completion, got %q", store.record.LocalDrainState)
		}
		if transport.acquires != 0 || transport.waits != 0 || transport.renews != 0 || transport.releases != 0 || transport.cancels != 0 {
			t.Fatalf("expected zero parent mutations by borrower, got %+v", transport)
		}
	})

	t.Run("parent-renewal-extends-child-liveness-and-loss-cancels-child", func(t *testing.T) {
		store := &ownerTestStore{}
		transport := &ownerTestTransport{}
		now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
		clock := &ownerControlledClock{now: now}
		live1 := now.Add(30 * time.Second)
		live2 := now.Add(60 * time.Second)
		maxHold := now.Add(30 * time.Minute)
		transport.current = ports.ReviewLockRequest{
			InstallationID:   "test-installation",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "request-1",
			RequestKey:       "mulgae-review.parent-session.parent-run",
			Holder:           "mulgae-review/parent-session/parent-run",
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "grant-1",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &now,
			LivenessDeadline: &live1,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  30,
			MaxHoldSeconds:   1800,
		}
		pollStep := 0
		transport.list = func(_ context.Context, _ string, _ string, _ int) (ports.ReviewLockList, error) {
			transport.mu.Lock()
			defer transport.mu.Unlock()
			pollStep++
			req := transport.current
			switch pollStep {
			case 1:
				// Initial admission.
			case 2:
				// Parent renewed liveness to live2.
				req.LivenessDeadline = &live2
				transport.current.LivenessDeadline = &live2
			default:
				// Parent released the lock while child is still running.
				ended := clock.Now()
				req.State = ports.ReviewLockStateReleased
				req.EndedAt = &ended
			}
			return ports.ReviewLockList{
				InstallationID: "test-installation",
				Now:            clock.Now(),
				Requests:       []ports.ReviewLockRequest{req},
			}, nil
		}
		created := make(chan ownerControlledTimer, 16)
		coordinator, err := NewReviewCoordinator(store, transport, clock, rawGrant, true)
		if err != nil {
			t.Fatal(err)
		}
		coordinator.timer = func(delay time.Duration) (<-chan time.Time, func()) {
			tick := make(chan time.Time, 1)
			created <- ownerControlledTimer{delay, tick}
			return tick, func() {}
		}
		protection, err := coordinator.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		if err != nil {
			t.Fatalf("admission: %v", err)
		}
		first, second := <-created, <-created
		monitorTimer, guardTimer := first, second
		if monitorTimer.delay > guardTimer.delay {
			monitorTimer, guardTimer = guardTimer, monitorTimer
		}
		// Advance past poll 1 and trigger monitor refresh -> observes renewed live2.
		clock.advance(now.Add(10 * time.Second))
		monitorTimer.tick <- clock.Now()
		// Wait for both guardLoop (re-armed via pulse) and monitorLoop to schedule next timers.
		nextA, nextB := <-created, <-created
		nextMonitor := nextA
		if nextB.delay < nextMonitor.delay {
			nextMonitor = nextB
		}
		// Advance past original live1 (35s) — child must STILL be valid because parent renewed to 60s.
		clock.advance(now.Add(35 * time.Second))
		if err := protection.admitExecution(time.Minute); err != nil {
			t.Fatalf("expected child execution still valid after parent renewal extension, got %v", err)
		}
		// Next monitor poll observes parent released -> cancels child work and classifies as haepari_protection_lost (phase monitor).
		nextMonitor.tick <- clock.Now()
		select {
		case <-protection.workContext().Done():
		case <-time.After(time.Second):
			t.Fatal("expected child work cancelled on parent release")
		}
		protection.beginTerminal()
		protErr, dispErr := protection.finish(context.Background(), true)
		if protErr == nil || dispErr != nil {
			t.Fatalf("expected protection loss without disposition error, got prot=%v disp=%v", protErr, dispErr)
		}
		if cause, ok := CoordinationFailureReason(protErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected haepari_protection_lost, got %q (%v)", cause, protErr)
		}
		if summary, ok := coordinationDiagnosticSummary(protErr); !ok || summary.Phase() != "monitor" || summary.InvariantID() != string(domain.DiagnosticCauseCoordinationProtectionLost) {
			t.Fatalf("expected phase=monitor invariant=haepari_protection_lost, got %+v", summary)
		}
		if transport.releases != 0 || transport.cancels != 0 || transport.renews != 0 {
			t.Fatalf("expected zero parent mutations on monitor loss, got %+v", transport)
		}
	})

	t.Run("stalled-list-guard-and-deferred-drain-before-and-after-expiry", func(t *testing.T) {
		for _, expireBeforeRetry := range []bool{false, true} {
			t.Run(fmt.Sprintf("expire_before_retry=%v", expireBeforeRetry), func(t *testing.T) {
				store := &ownerTestStore{}
				transport := &ownerTestTransport{}
				now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
				clock := &ownerControlledClock{now: now}
				live := now.Add(30 * time.Second)
				maxHold := now.Add(30 * time.Minute)
				transport.current = ports.ReviewLockRequest{
					InstallationID:   "test-installation",
					LockID:           ports.HaepariReviewResourceID,
					RequestID:        "request-1",
					RequestKey:       "mulgae-review.parent-session.parent-run",
					Holder:           "mulgae-review/parent-session/parent-run",
					State:            ports.ReviewLockStateGranted,
					Sequence:         1,
					GrantID:          "grant-1",
					Generation:       1,
					Slot:             0,
					QueuedAt:         now,
					GrantedAt:        &now,
					LivenessDeadline: &live,
					MaxHoldDeadline:  &maxHold,
					LivenessSeconds:  30,
					MaxHoldSeconds:   1800,
				}
				entered := make(chan struct{})
				calls := 0
				transport.list = func(ctx context.Context, _ string, _ string, _ int) (ports.ReviewLockList, error) {
					calls++
					if calls == 1 {
						return ports.ReviewLockList{
							InstallationID: "test-installation",
							Now:            clock.Now(),
							Requests:       []ports.ReviewLockRequest{transport.current},
						}, nil
					}
					close(entered)
					<-ctx.Done()
					return ports.ReviewLockList{}, ctx.Err()
				}
				created := make(chan ownerControlledTimer, 8)
				coordinator, err := NewReviewCoordinator(store, transport, clock, rawGrant, true)
				if err != nil {
					t.Fatal(err)
				}
				coordinator.timer = func(delay time.Duration) (<-chan time.Time, func()) {
					tick := make(chan time.Time, 1)
					created <- ownerControlledTimer{delay, tick}
					return tick, func() {}
				}
				protection, err := coordinator.startReview(context.Background(), ownerTestRequest(t), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				first, second := <-created, <-created
				monitorTimer, guardTimer := first, second
				if monitorTimer.delay > guardTimer.delay {
					monitorTimer, guardTimer = guardTimer, monitorTimer
				}
				monitorTimer.tick <- clock.Now()
				<-entered
				if expireBeforeRetry {
					clock.advance(live)
					guardTimer.tick <- clock.Now()
					select {
					case <-protection.workContext().Done():
					case <-time.After(time.Second):
						t.Fatal("borrowed deadline guard waited for stalled ListLocks")
					}
				}
				// First finish with completed=false (local drain unverified).
				protection.beginTerminal()
				protErr, _ := protection.finish(context.Background(), false)
				if store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
					t.Fatalf("expected unverified local drain retained, got %q", store.record.LocalDrainState)
				}
				if expireBeforeRetry && protErr == nil {
					t.Fatal("expected protection loss on expired guard")
				}
				// Deferred retry with completed=true.
				protRetry, dispRetry := protection.finish(context.Background(), true)
				if dispRetry != nil || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
					t.Fatalf("expected deferred retry to mark local drain verified without disposition error, got disp=%v state=%q", dispRetry, store.record.LocalDrainState)
				}
				if expireBeforeRetry {
					if protRetry == nil {
						t.Fatal("expected protection loss preserved after expiry even when later local drain verifies")
					}
					if cause, ok := CoordinationFailureReason(protRetry); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
						t.Fatalf("expected haepari_protection_lost preserved, got %q (%v)", cause, protRetry)
					}
				} else if protRetry != nil {
					t.Fatalf("expected nil protection error when deferred drain verifies before deadline, got %v", protRetry)
				}
			})
		}
	})

	t.Run("child-caller-cancellation-leaves-parent-intact-without-coordination-receipt", func(t *testing.T) {
		store := &ownerTestStore{}
		transport := &ownerTestTransport{}
		transport.grant()
		ctx, cancel := context.WithCancel(context.Background())
		coordinator, err := NewReviewCoordinator(store, transport, ownerTestClock{}, rawGrant, true)
		if err != nil {
			t.Fatal(err)
		}
		protection, err := coordinator.startReview(ctx, ownerTestRequest(t), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		select {
		case <-protection.workContext().Done():
		case <-time.After(time.Second):
			t.Fatal("expected child work context cancelled by caller")
		}
		protection.beginTerminal()
		protErr, dispErr := protection.finish(context.Background(), true)
		if protErr != nil || dispErr != nil {
			t.Fatalf("expected nil protection/disposition error when parent remains valid and child drain is proved, got %v / %v", protErr, dispErr)
		}
		if store.record.LocalDrainState != ports.ReviewLocalDrainVerified || transport.cancels != 0 || transport.releases != 0 {
			t.Fatalf("expected verified child drain and intact parent, got state=%q cancels=%d releases=%d", store.record.LocalDrainState, transport.cancels, transport.releases)
		}
	})
}

func TestReviewCoordinatorBorrowedAdmissionAndPagination(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	live := now.Add(time.Minute)
	maxHold := now.Add(30 * time.Minute)
	validGrant := `{"installation_id":"test-installation","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`

	baseRequest := func() ports.ReviewLockRequest {
		return ports.ReviewLockRequest{
			InstallationID:   "test-installation",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "request-1",
			RequestKey:       "mulgae-review.parent-session.parent-run",
			Holder:           "mulgae-review/parent-session/parent-run",
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "grant-1",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &now,
			LivenessDeadline: &live,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  60,
			MaxHoldSeconds:   1800,
		}
	}

	assertAdmissionClassification := func(t *testing.T, err error, wantCause domain.RuntimeDiagnosticCause, wantNativeCode string, wantClass domain.FailureClass) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected error with cause %q, got nil", wantCause)
		}
		if gotClass := runtimeDiagnosticFailureClass(err); gotClass != wantClass {
			t.Fatalf("failure class = %q, want %q (%v)", gotClass, wantClass, err)
		}
		cause, ok := CoordinationFailureReason(err)
		if !ok || cause != wantCause {
			t.Fatalf("CoordinationFailureReason = (%q, %v), want (%q, true) (%v)", cause, ok, wantCause, err)
		}
		summary, ok := coordinationDiagnosticSummary(err)
		if !ok || summary.Phase() != "admission" || summary.InvariantID() != string(wantCause) {
			t.Fatalf("summary = %+v (%v), want phase=admission invariant=%q", summary, ok, wantCause)
		}
		if wantNativeCode != "" {
			var coordErr *ports.ReviewCoordinationError
			if !errors.As(err, &coordErr) || coordErr.NativeCode != wantNativeCode {
				t.Fatalf("expected NativeCode=%q, got %+v", wantNativeCode, coordErr)
			}
		}
	}

	t.Run("malformed-and-wrong-installation-or-lock", func(t *testing.T) {
		store := &ownerTestStore{}
		transport := &ownerTestTransport{}
		clock := &ownerControlledClock{now: now}

		// Present-empty HAEPARI_LOCK_GRANT.
		coord, _ := NewReviewCoordinator(store, transport, clock, "", true)
		_, err := coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "", domain.FailureConfiguration)
		if transport.lists != 0 {
			t.Fatal("expected zero ListLocks calls on malformed grant")
		}

		// Wrong lock_id -> CONFLICT.
		coord, _ = NewReviewCoordinator(store, transport, clock, `{"installation_id":"test-installation","lock_id":"other-lock","grant_id":"grant-1","generation":1}`, true)
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "CONFLICT", domain.FailureConfiguration)

		// Wrong installation_id -> CONFLICT.
		coord, _ = NewReviewCoordinator(store, transport, clock, `{"installation_id":"other-installation","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`, true)
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "CONFLICT", domain.FailureConfiguration)
	})

	t.Run("unknown-grant-stale-generation-and-all-non-granted-or-expired-states", func(t *testing.T) {
		clock := &ownerControlledClock{now: now}

		// Unknown grant -> NOT_FOUND.
		store := &ownerTestStore{}
		transport := &ownerTestTransport{}
		coord, _ := NewReviewCoordinator(store, transport, clock, validGrant, true)
		_, err := coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "NOT_FOUND", domain.FailureConfiguration)

		// Stale generation -> LOCK_EXPIRED.
		req := baseRequest()
		req.Generation = 2
		transport.current = req
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "LOCK_EXPIRED", domain.FailureConfiguration)

		// Queued or never-granted states (no GrantID) -> NOT_FOUND even when queried by request_id as grant_id;
		// real ended previously granted states (with GrantID) -> LOCK_EXPIRED.
		endedAt := now.Add(-time.Second)
		for _, state := range []ports.ReviewLockState{
			ports.ReviewLockStateQueued,
			ports.ReviewLockStateCancelled,
			ports.ReviewLockStateQueueExpired,
		} {
			req := baseRequest()
			req.State = state
			req.Slot = -1
			req.GrantID = ""
			req.Generation = 0
			req.GrantedAt = nil
			req.LivenessDeadline = nil
			req.MaxHoldDeadline = nil
			req.LivenessSeconds = 0
			req.MaxHoldSeconds = 0
			if state != ports.ReviewLockStateQueued {
				req.EndedAt = &endedAt
			}
			transport.current = req
			for _, grantToQuery := range []string{
				validGrant,
				`{"installation_id":"test-installation","lock_id":"mulgae-review","grant_id":"request-1","generation":1}`,
			} {
				c, _ := NewReviewCoordinator(&ownerTestStore{}, transport, clock, grantToQuery, true)
				_, err := c.startReview(context.Background(), ownerTestRequest(t), time.Minute)
				assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "NOT_FOUND", domain.FailureConfiguration)
				var coordErr *ports.ReviewCoordinationError
				if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonLockNotFound {
					t.Fatalf("expected LockNotFound for never-granted state %q, got %+v", state, coordErr)
				}
				if transport.acquires != 0 || transport.releases != 0 || transport.cancels != 0 || transport.renews != 0 {
					t.Fatalf("expected zero mutations on borrowed admission refusal: %+v", transport)
				}
			}
		}
		for _, state := range []ports.ReviewLockState{
			ports.ReviewLockStateReleased,
			ports.ReviewLockStateHoldExpired,
		} {
			req := baseRequest()
			req.State = state
			req.EndedAt = &endedAt
			transport.current = req
			c, _ := NewReviewCoordinator(&ownerTestStore{}, transport, clock, validGrant, true)
			_, err := c.startReview(context.Background(), ownerTestRequest(t), time.Minute)
			assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "LOCK_EXPIRED", domain.FailureConfiguration)
			if transport.acquires != 0 || transport.releases != 0 || transport.cancels != 0 || transport.renews != 0 {
				t.Fatalf("expected zero mutations on ended granted admission refusal: %+v", transport)
			}
		}

		// Expired liveness and expired max_hold -> LOCK_EXPIRED.
		expired := now
		req = baseRequest()
		req.LivenessDeadline = &expired
		transport.current = req
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "LOCK_EXPIRED", domain.FailureConfiguration)

		req = baseRequest()
		req.MaxHoldDeadline = &expired
		req.LivenessDeadline = &expired
		transport.current = req
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "LOCK_EXPIRED", domain.FailureConfiguration)

		// Insufficient remaining max_hold -> haepari_hold_budget_exceeded, phase admission.
		shortMax := now.Add(3 * time.Minute)
		req = baseRequest()
		req.MaxHoldDeadline = &shortMax
		req.MaxHoldSeconds = 180
		transport.current = req
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationHoldBudgetExceeded, "", domain.FailureConfiguration)
	})

	t.Run("multipage-beyond-64-pages-same-page-now-and-cursor-validation", func(t *testing.T) {
		clock := &ownerControlledClock{now: now}
		nativeInstID := "local-0123456789abcdef"
		nativeGrant := `{"installation_id":"local-0123456789abcdef","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`

		type nativePageCursor struct {
			Kind         string `json:"kind"`
			Installation string `json:"installation"`
			Resource     string `json:"resource"`
			State        string `json:"state,omitempty"`
			Last         int64  `json:"last,omitempty"`
			Upper        int64  `json:"upper,omitempty"`
			LastID       string `json:"last_id,omitempty"`
			UpperID      string `json:"upper_id,omitempty"`
		}
		makeNativeCursor := func(last, upper int64) string {
			raw, err := json.Marshal(nativePageCursor{
				Kind:         "locks",
				Installation: nativeInstID,
				Resource:     ports.HaepariReviewResourceID,
				Last:         last,
				Upper:        upper,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded := base64.RawURLEncoding.EncodeToString(raw)
			if len(encoded) <= 128 || len(encoded) > 2048 {
				t.Fatalf("expected native-shaped cursor length in (128, 2048], got %d", len(encoded))
			}
			return encoded
		}

		// 66 pages (6,600 rows) with native-shaped >128-byte rawURL-base64 JSON cursors and matching grant on page 66 -> succeeds when page 66 Now is before deadline.
		transport := &ownerTestTransport{installationID: nativeInstID}
		page66Now := now.Add(5 * time.Second)
		const totalRows int64 = 6600
		transport.list = func(_ context.Context, _ string, cursor string, limit int) (ports.ReviewLockList, error) {
			if limit != 100 {
				t.Fatalf("expected limit 100, got %d", limit)
			}
			pageIdx := 0
			if cursor != "" {
				decoded, err := base64.RawURLEncoding.DecodeString(cursor)
				if err != nil {
					t.Fatalf("unexpected non-base64 cursor %q: %v", cursor, err)
				}
				var parsed nativePageCursor
				if err := json.Unmarshal(decoded, &parsed); err != nil || parsed.Kind != "locks" || parsed.Installation != nativeInstID || parsed.Resource != ports.HaepariReviewResourceID || parsed.State != "" || parsed.LastID != "" || parsed.UpperID != "" || parsed.Last <= 0 || parsed.Upper != totalRows || parsed.Upper < parsed.Last {
					t.Fatalf("unexpected decoded cursor %s: %v", decoded, err)
				}
				pageIdx = int(parsed.Last / 100)
			}
			rows := make([]ports.ReviewLockRequest, 0, 100)
			ended := now.Add(-time.Minute)
			for i := 1; i <= 100; i++ {
				seq := int64(pageIdx*100 + i)
				if pageIdx == 65 && i == 100 {
					match := baseRequest()
					match.InstallationID = nativeInstID
					match.Sequence = seq
					rows = append(rows, match)
					continue
				}
				rows = append(rows, ports.ReviewLockRequest{
					InstallationID:   nativeInstID,
					LockID:           ports.HaepariReviewResourceID,
					RequestID:        fmt.Sprintf("request-hist-%d", seq),
					RequestKey:       fmt.Sprintf("mulgae-review.hist.%d", seq),
					Holder:           "mulgae-review/hist/run",
					State:            ports.ReviewLockStateReleased,
					Sequence:         seq,
					GrantID:          fmt.Sprintf("grant-hist-%d", seq),
					Generation:       1,
					Slot:             0,
					QueuedAt:         ended,
					GrantedAt:        &ended,
					LivenessDeadline: &ended,
					MaxHoldDeadline:  &ended,
					EndedAt:          &ended,
					LivenessSeconds:  30,
					MaxHoldSeconds:   300,
				})
			}
			if pageIdx < 65 {
				return ports.ReviewLockList{
					InstallationID: nativeInstID,
					Now:            now,
					Requests:       rows,
					More:           true,
					NextCursor:     makeNativeCursor(int64((pageIdx+1)*100), totalRows),
				}, nil
			}
			return ports.ReviewLockList{
				InstallationID: nativeInstID,
				Now:            page66Now,
				Requests:       rows,
				More:           false,
			}, nil
		}
		store := &ownerTestStore{}
		coord, _ := NewReviewCoordinator(store, transport, clock, nativeGrant, true)
		protection, err := coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		if err != nil {
			t.Fatalf("expected 66-page lookup with >128-byte native cursors to succeed, got %v", err)
		}
		protection.beginTerminal()
		_, _ = protection.finish(context.Background(), true)
		if transport.lists != 66 {
			t.Fatalf("expected 66 ListLocks page calls, got %d", transport.lists)
		}

		// Same 66-page scan where page 1 Now is valid, but page 66 Now is at/after liveness_deadline -> must NOT borrow validity from page 1!
		page66Now = live
		transport.lists = 0
		coord, _ = NewReviewCoordinator(&ownerTestStore{}, transport, clock, nativeGrant, true)
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "LOCK_EXPIRED", domain.FailureConfiguration)

		// Oversized (>2048 bytes), blank/whitespace, and repeated non-progressing cursors -> ProtocolIncompatible, never NOT_FOUND.
		for _, badCursor := range []string{
			strings.Repeat("a", 2049),
			"",
			"   ",
			"cursor with space",
			makeNativeCursor(1, 2),
		} {
			step := 0
			transport.list = func(_ context.Context, _ string, _ string, _ int) (ports.ReviewLockList, error) {
				step++
				ended := now.Add(-time.Minute)
				return ports.ReviewLockList{
					InstallationID: nativeInstID,
					Now:            now,
					Requests: []ports.ReviewLockRequest{{
						InstallationID:   nativeInstID,
						LockID:           ports.HaepariReviewResourceID,
						RequestID:        fmt.Sprintf("request-hist-%d", step),
						RequestKey:       fmt.Sprintf("mulgae-review.hist.%d", step),
						Holder:           "mulgae-review/hist/run",
						State:            ports.ReviewLockStateReleased,
						Sequence:         int64(step),
						GrantID:          fmt.Sprintf("grant-hist-%d", step),
						Generation:       1,
						Slot:             0,
						QueuedAt:         ended,
						GrantedAt:        &ended,
						LivenessDeadline: &ended,
						MaxHoldDeadline:  &ended,
						EndedAt:          &ended,
						LivenessSeconds:  30,
						MaxHoldSeconds:   300,
					}},
					More:       true,
					NextCursor: badCursor,
				}, nil
			}
			coord, _ = NewReviewCoordinator(&ownerTestStore{}, transport, clock, nativeGrant, true)
			_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
			assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "", domain.FailureConfiguration)
			var coordErr *ports.ReviewCoordinationError
			if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonProtocolIncompatible {
				t.Fatalf("expected ProtocolIncompatible for bad/nonprogressing cursor (len=%d), got %+v", len(badCursor), coordErr)
			}
		}

		// Whole-inspection deadline timeout while caller ctx is still active -> inconclusive haepari_readiness_failed (FailureConfiguration), NOT cancelled or NOT_FOUND.
		transport.list = func(_ context.Context, _ string, _ string, _ int) (ports.ReviewLockList, error) {
			return ports.ReviewLockList{}, &ports.ReviewCoordinationError{
				Reason:    ports.ReviewCoordinationReasonContextCancelled,
				Operation: ports.ReviewLockOperationList,
				Retry:     ports.ReviewCoordinationRetryInspectFirst,
				Message:   "per-inspection deadline exceeded",
				Cause:     context.DeadlineExceeded,
			}
		}
		coord, _ = NewReviewCoordinator(&ownerTestStore{}, transport, clock, nativeGrant, true)
		_, err = coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "", domain.FailureConfiguration)
		var coordErr *ports.ReviewCoordinationError
		if !errors.As(err, &coordErr) || coordErr.Reason == ports.ReviewCoordinationReasonLockNotFound {
			t.Fatalf("whole-inspection timeout must not be labeled NOT_FOUND: %+v", coordErr)
		}

		// Actual caller cancellation during admission -> FailureCancelled, haepari_cancelled, phase admission.
		cancelledCtx, cancelCaller := context.WithCancel(context.Background())
		cancelCaller()
		_, err = coord.startReview(cancelledCtx, ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationCancelled, "", domain.FailureCancelled)
	})

	t.Run("persistence-refusal-and-same-run-replay-refusal", func(t *testing.T) {
		clock := &ownerControlledClock{now: now}
		transport := &ownerTestTransport{current: baseRequest()}

		// PersistIntent failure -> haepari_persistence_failed, phase admission, FailureArtifact.
		store := &ownerTestStore{localErr: errors.New("disk full")}
		coord, _ := NewReviewCoordinator(store, transport, clock, validGrant, true)
		_, err := coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationPersistenceFailed, "", domain.FailureArtifact)

		// Existing same-child v3 record -> refused with CONFLICT before provider execution.
		store = &ownerTestStore{}
		coord, _ = NewReviewCoordinator(store, transport, clock, validGrant, true)
		req := ownerTestRequest(t)
		protection, err := coord.startReview(context.Background(), req, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		protection.beginTerminal()
		_, _ = protection.finish(context.Background(), true)

		_, err = coord.startReview(context.Background(), req, time.Minute)
		assertAdmissionClassification(t, err, domain.DiagnosticCauseCoordinationReadinessFailed, "CONFLICT", domain.FailureConfiguration)
	})
}

func TestReviewCoordinatorOwnedFaultAndRecoveryMatrix(t *testing.T) {
	now := time.Now().UTC()

	t.Run("queue-expiry-and-uncertain-acquire-reconciliation-and-replay-refusal", func(t *testing.T) {
		// 1. Native queue expiry during Wait -> haepari_queue_expired, phase acquire, LocalDrainNotStarted.
		coordinator, store, transport := newOwnerTestCoordinator(t)
		transport.queued = true
		ended := now.Add(5 * time.Second)
		transport.wait = func(_ context.Context, _ string) (ports.ReviewLockReply, error) {
			transport.mu.Lock()
			defer transport.mu.Unlock()
			transport.current.State = ports.ReviewLockStateQueueExpired
			transport.current.EndedAt = &ended
			return transport.reply(ports.ReviewLockReceiptOperationExpire), nil
		}
		qSec := int64(5)
		req := ownerTestRequest(t)
		req.QueueSeconds = &qSec
		_, err := coordinator.startOwnedReview(context.Background(), req, time.Minute)
		if cause, ok := CoordinationFailureReason(err); !ok || cause != domain.DiagnosticCauseCoordinationQueueExpired {
			t.Fatalf("expected haepari_queue_expired, got %q (%v)", cause, err)
		}
		if store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
			t.Fatalf("expected LocalDrainNotStarted on queue expiry, got %q", store.record.LocalDrainState)
		}

		// 2. Uncertain first Acquire send automatically replays exact-same payload in acquireOwnedGrant and settles unused grant/request before refusing execution.
		for _, initialQueued := range []bool{false, true} {
			uStore := &ownerTestStore{}
			uTransport := &ownerTestTransport{queued: initialQueued}
			var firstPayload []byte
			uTransport.acquire = func(_ context.Context, raw []byte) (ports.ReviewLockReply, error) {
				uTransport.mu.Lock()
				defer uTransport.mu.Unlock()
				if uTransport.acquires == 1 {
					firstPayload = append([]byte(nil), raw...)
					var parsed struct {
						LockID     string `json:"lock_id"`
						RequestKey string `json:"request_key"`
						Holder     string `json:"holder"`
					}
					if err := json.Unmarshal(raw, &parsed); err != nil {
						return ports.ReviewLockReply{}, err
					}
					uTransport.current = ports.ReviewLockRequest{
						InstallationID: uTransport.instID(),
						LockID:         parsed.LockID,
						RequestID:      "request-1",
						RequestKey:     parsed.RequestKey,
						Holder:         parsed.Holder,
						State:          ports.ReviewLockStateQueued,
						Sequence:       1,
						Slot:           -1,
						QueuedAt:       now,
					}
					if !initialQueued {
						uTransport.grant()
					}
					return ports.ReviewLockReply{}, &ports.ReviewCoordinationError{
						Reason:    ports.ReviewCoordinationReasonAcquireUncertain,
						Operation: ports.ReviewLockOperationAcquire,
						Retry:     ports.ReviewCoordinationRetrySameKey,
						Uncertain: true,
						Message:   "post-write transport EOF during acquire",
					}
				}
				if !bytes.Equal(raw, firstPayload) {
					t.Fatalf("expected bounded replay to send exact same canonical payload bytes: got %s, want %s", raw, firstPayload)
				}
				return uTransport.reply(ports.ReviewLockReceiptOperationAcquire), nil
			}
			uCoord, _ := NewReviewCoordinator(uStore, uTransport, &ownerControlledClock{now: now}, "", false)
			uReq := ownerTestRequest(t)
			_, uErr := uCoord.startOwnedReview(context.Background(), uReq, time.Minute)
			if uErr == nil || runtimeDiagnosticFailureClass(uErr) != domain.FailureArtifact {
				t.Fatalf("expected FailureArtifact on uncertain acquire reconciliation (queued=%v), got %v", initialQueued, uErr)
			}
			if cause, ok := CoordinationFailureReason(uErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
				t.Fatalf("expected haepari_protection_lost on uncertain acquire reconciliation (queued=%v), got (%q, %v)", initialQueued, cause, ok)
			}
			if uTransport.acquires != 2 || uStore.record.SessionID != uReq.SessionID || uStore.record.RunID != uReq.RunID || uStore.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
				t.Fatalf("expected 2 acquires (1 uncertain + 1 exact replay), retained run identity, and LocalDrainNotStarted: acquires=%d record=%+v", uTransport.acquires, uStore.record)
			}
			if initialQueued {
				if uTransport.cancels != 1 || uTransport.releases != 0 || uStore.record.ObservedRequest.State != ports.ReviewLockStateCancelled {
					t.Fatalf("expected queued uncertain acquire to settle via Cancel once: %+v / %+v", uTransport, uStore.record.ObservedRequest)
				}
			} else {
				if uTransport.releases != 1 || uTransport.cancels != 0 || uStore.record.ObservedRequest.State != ports.ReviewLockStateReleased {
					t.Fatalf("expected granted uncertain acquire to settle via Release once: %+v / %+v", uTransport, uStore.record.ObservedRequest)
				}
			}
		}

		// 3. Pre-populated unverified v2 record refuses replay after protected effects without releasing or cancelling.
		sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
		runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
		payload, _ := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
		live := now.Add(time.Minute)
		maxHold := now.Add(30 * time.Minute)
		grantedCurrent := ports.ReviewLockRequest{
			InstallationID:   "test-installation",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "request-reconciled",
			RequestKey:       payload.RequestKey,
			Holder:           payload.Holder,
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "grant-reconciled",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &now,
			LivenessDeadline: &live,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  60,
			MaxHoldSeconds:   1800,
		}
		reconcileStore := &ownerTestStore{}
		reconcileTransport := &ownerTestTransport{}
		reconcileCoordinator, _ := NewReviewCoordinator(reconcileStore, reconcileTransport, &ownerControlledClock{now: now}, "", false)
		root, _ := ports.NewAnchoredRoot(t.TempDir())
		reconcileStore.record = ports.ReviewLockRecord{
			SchemaVersion:   artifactwire.HaepariLockIntentSchemaV2,
			LocalDrainState: ports.ReviewLocalDrainUnverified,
			SessionID:       sessionID,
			RunID:           runID,
			InstallationID:  "test-installation",
			ResourceID:      ports.HaepariReviewResourceID,
			Payload:         payload,
			ObservedReceipt: &ports.ReviewLockReceipt{
				Operation:  ports.ReviewLockReceiptOperationAcquire,
				RequestID:  "request-1",
				GrantID:    "grant-1",
				State:      ports.ReviewLockStateGranted,
				RecordedAt: now,
			},
			ObservedRequest: &grantedCurrent,
			PersistedAt:     now,
			UpdatedAt:       now,
		}
		reconcileStore.record.ObservedRequest.InstallationID = "test-installation"
		reconcileStore.record.ObservedRequest.RequestID = "request-1"
		reconcileStore.record.ObservedRequest.GrantID = "grant-1"
		_, err = reconcileCoordinator.startOwnedReview(context.Background(), ReviewAcquireRequest{Root: root, SessionID: sessionID, RunID: runID}, time.Minute)
		if cause, ok := CoordinationFailureReason(err); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected protection loss on replay after protected effects, got %q (%v)", cause, err)
		}
		if reconcileTransport.releases != 0 || reconcileTransport.cancels != 0 {
			t.Fatalf("replay with unverified local drain must never release/cancel existing grant: %+v", reconcileTransport)
		}
	})

	t.Run("controlled-active-max-hold-reservation-and-expiry-independent-of-liveness", func(t *testing.T) {
		rawGrant := `{"installation_id":"test-installation","lock_id":"mulgae-review","grant_id":"grant-1","generation":1}`
		for _, borrowed := range []bool{false, true} {
			for _, reachMaxHoldAtFinish := range []bool{false, true} {
				t.Run(fmt.Sprintf("borrowed=%v/expire_at_finish=%v", borrowed, reachMaxHoldAtFinish), func(t *testing.T) {
					base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
					clock := &ownerControlledClock{now: base}
					store := &ownerTestStore{}
					transport := &ownerTestTransport{hold: 5 * time.Minute, clock: clock}
					// Set liveness (10m) and max_hold (5m) initially to 5m for admission (since LivenessDeadline <= MaxHoldDeadline is required at admission),
					// so at T+3m (MaxHoldDeadline - 2m reserve), LivenessDeadline (T+5m) is still 2 minutes in the future!
					live := base.Add(5 * time.Minute)
					maxHold := base.Add(5 * time.Minute)
					transport.acquire = func(_ context.Context, raw []byte) (ports.ReviewLockReply, error) {
						transport.mu.Lock()
						defer transport.mu.Unlock()
						var parsed struct {
							LockID     string `json:"lock_id"`
							RequestKey string `json:"request_key"`
							Holder     string `json:"holder"`
						}
						_ = json.Unmarshal(raw, &parsed)
						transport.current = ports.ReviewLockRequest{
							InstallationID:   "test-installation",
							LockID:           parsed.LockID,
							RequestID:        "request-1",
							RequestKey:       parsed.RequestKey,
							Holder:           parsed.Holder,
							State:            ports.ReviewLockStateGranted,
							Sequence:         1,
							GrantID:          "grant-1",
							Generation:       1,
							Slot:             0,
							QueuedAt:         base,
							GrantedAt:        &base,
							LivenessDeadline: &live,
							MaxHoldDeadline:  &maxHold,
							LivenessSeconds:  300,
							MaxHoldSeconds:   300,
						}
						return ports.ReviewLockReply{
							Current: transport.current,
							Receipt: ports.ReviewLockReceipt{
								Operation:  ports.ReviewLockReceiptOperationAcquire,
								RequestID:  transport.current.RequestID,
								GrantID:    transport.current.GrantID,
								State:      transport.current.State,
								RecordedAt: base,
							},
						}, nil
					}
					transport.current = ports.ReviewLockRequest{
						InstallationID:   "test-installation",
						LockID:           ports.HaepariReviewResourceID,
						RequestID:        "request-1",
						RequestKey:       "mulgae-review.parent-session.parent-run",
						Holder:           "mulgae-review/parent-session/parent-run",
						State:            ports.ReviewLockStateGranted,
						Sequence:         1,
						GrantID:          "grant-1",
						Generation:       1,
						Slot:             0,
						QueuedAt:         base,
						GrantedAt:        &base,
						LivenessDeadline: &live,
						MaxHoldDeadline:  &maxHold,
						LivenessSeconds:  300,
						MaxHoldSeconds:   300,
					}
					created := make(chan ownerControlledTimer, 8)
					grantArg := ""
					if borrowed {
						grantArg = rawGrant
					}
					coord, err := NewReviewCoordinator(store, transport, clock, grantArg, borrowed)
					if err != nil {
						t.Fatal(err)
					}
					coord.timer = func(delay time.Duration) (<-chan time.Time, func()) {
						tick := make(chan time.Time, 1)
						created <- ownerControlledTimer{delay, tick}
						return tick, func() {}
					}
					protection, err := coord.startReview(context.Background(), ownerTestRequest(t), time.Minute)
					if err != nil {
						t.Fatalf("admission failed: %v", err)
					}
					first, second := <-created, <-created
					guardTimer := first
					if second.delay > guardTimer.delay {
						guardTimer = second
					}
					if !reachMaxHoldAtFinish {
						// Advance clock to MaxHoldDeadline - coordinationDrainBudget (T+3m), while LivenessDeadline (T+5m) remains valid!
						reserveBoundary := maxHold.Add(-coordinationDrainBudget)
						if !reserveBoundary.Before(live) {
							t.Fatalf("test setup error: reserveBoundary %v must be strictly before liveness %v", reserveBoundary, live)
						}
						clock.advance(reserveBoundary)
						guardTimer.tick <- clock.Now()
						select {
						case <-protection.workContext().Done():
						case <-time.After(time.Second):
							t.Fatal("expected guardLoop to cancel work at MaxHoldDeadline - 2m reserve while LivenessDeadline was still valid")
						}
						var fault *ports.ReviewCoordinationError
						if !errors.As(context.Cause(protection.workContext()), &fault) || fault.Reason != ports.ReviewCoordinationReasonHoldBudgetExceeded {
							t.Fatalf("expected HoldBudgetExceeded cause on workContext, got %v", context.Cause(protection.workContext()))
						}
						if admitErr := protection.admitExecution(time.Minute); admitErr == nil {
							t.Fatal("expected admitExecution to fail after max_hold cleanup reserve boundary reached")
						}
					}
					// Unverified terminal drain must retain LocalDrainUnverified without releasing.
					protection.beginTerminal()
					if reachMaxHoldAtFinish {
						clock.advance(maxHold)
					}
					protUnverified, dispUnverified := protection.finish(context.Background(), false)
					if protUnverified == nil || dispUnverified != nil || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified || transport.releases != 0 {
						t.Fatalf("expected unverified drain retained without release, got prot=%v disp=%v state=%q releases=%d", protUnverified, dispUnverified, store.record.LocalDrainState, transport.releases)
					}
					// Verified terminal drain updates LocalDrainVerified and releases (owned only), while preserving non-nil protection failure (never false completion).
					protVerified, dispVerified := protection.finish(context.Background(), true)
					if protVerified == nil || dispVerified != nil || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
						t.Fatalf("expected verified drain to preserve non-nil protection failure without disposition error, got prot=%v disp=%v state=%q", protVerified, dispVerified, store.record.LocalDrainState)
					}
					if borrowed {
						if transport.releases != 0 {
							t.Fatalf("borrowed review must never release parent grant: %d", transport.releases)
						}
					} else {
						wantState := ports.ReviewLockStateReleased
						wantOperation := ports.ReviewLockReceiptOperationRelease
						if reachMaxHoldAtFinish {
							wantState = ports.ReviewLockStateHoldExpired
							wantOperation = ports.ReviewLockReceiptOperationExpire
						}
						if transport.releases != 1 || store.record.ObservedRequest == nil || store.record.ObservedReceipt == nil || store.record.ObservedRequest.State != wantState || store.record.ObservedReceipt.Operation != wantOperation {
							t.Fatalf("owned drain must retain one valid terminal receipt: releases=%d request=%+v receipt=%+v", transport.releases, store.record.ObservedRequest, store.record.ObservedReceipt)
						}
					}
					wantCause := domain.DiagnosticCauseCoordinationHoldBudgetExceeded
					if reachMaxHoldAtFinish {
						wantCause = domain.DiagnosticCauseCoordinationProtectionLost
					}
					if cause, ok := CoordinationFailureReason(protVerified); !ok || cause != wantCause {
						t.Fatalf("expected cause %q, got (%q, %v) for %v", wantCause, cause, ok, protVerified)
					}
				})
			}
		}
	})

	t.Run("owned-deferred-drain-before-and-after-expiry-and-replacement-grant-rejection", func(t *testing.T) {
		for _, expireBeforeRetry := range []bool{false, true} {
			t.Run(fmt.Sprintf("expire_before_retry=%v", expireBeforeRetry), func(t *testing.T) {
				coordinator, store, transport := newOwnerTestCoordinator(t)
				clock := &ownerControlledClock{now: now}
				coordinator.clock = clock
				owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				owner.beginTerminal()
				protErr, dispErr := owner.finish(context.Background(), false)
				if protErr != nil || dispErr != nil || transport.releases != 0 || store.record.LocalDrainState != ports.ReviewLocalDrainUnverified {
					t.Fatalf("expected unverified state retained without release, got prot=%v disp=%v releases=%d", protErr, dispErr, transport.releases)
				}
				if expireBeforeRetry {
					grant, _, _ := owner.state()
					clock.advance(grant.LivenessDeadline)
				}
				protRetry, dispRetry := owner.finish(context.Background(), true)
				if dispRetry != nil || transport.releases != 1 || store.record.LocalDrainState != ports.ReviewLocalDrainVerified {
					t.Fatalf("expected deferred retry to verify local drain and release once, got disp=%v releases=%d state=%q", dispRetry, transport.releases, store.record.LocalDrainState)
				}
				if expireBeforeRetry {
					if protRetry == nil {
						t.Fatal("expected haepari_protection_lost retained when deferred cleanup finishes after lease expiry")
					}
					if cause, ok := CoordinationFailureReason(protRetry); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
						t.Fatalf("expected haepari_protection_lost, got %q (%v)", cause, protRetry)
					}
				} else if protRetry != nil {
					t.Fatalf("expected clean deferred finish before expiry, got %v", protRetry)
				}
			})
		}

		// Replacement grant ID on Renew must be rejected by validateCoordinationReply -> haepari_protection_lost.
		coordinator, _, transport := newOwnerTestCoordinator(t)
		clock := &ownerControlledClock{now: now}
		coordinator.clock = clock
		created := make(chan ownerControlledTimer, 8)
		coordinator.timer = func(delay time.Duration) (<-chan time.Time, func()) {
			tick := make(chan time.Time, 1)
			created <- ownerControlledTimer{delay, tick}
			return tick, func() {}
		}
		transport.renew = func(_ context.Context, _ string) (ports.ReviewLockReply, error) {
			transport.mu.Lock()
			defer transport.mu.Unlock()
			transport.current.GrantID = "grant-replacement"
			return transport.reply(ports.ReviewLockReceiptOperationRenew), nil
		}
		owner, err := coordinator.startOwnedReview(context.Background(), ownerTestRequest(t), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		first, second := <-created, <-created
		renewTimer := first
		if second.delay < renewTimer.delay {
			renewTimer = second
		}
		renewTimer.tick <- clock.Now()
		select {
		case <-owner.work.Done():
		case <-time.After(time.Second):
			t.Fatal("expected replacement grant ID on Renew to cancel owner work")
		}
		owner.beginTerminal()
		protErr, _ := owner.finish(context.Background(), true)
		if cause, ok := CoordinationFailureReason(protErr); !ok || cause != domain.DiagnosticCauseCoordinationProtectionLost {
			t.Fatalf("expected haepari_protection_lost on replacement grant rejection, got %q (%v)", cause, protErr)
		}
	})
}
