package reviewrun

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
	mu                                         sync.Mutex
	current                                    ports.ReviewLockRequest
	queued                                     bool
	hold                                       time.Duration
	acquires, waits, releases, cancels, renews int
	wait                                       func(context.Context, string) (ports.ReviewLockReply, error)
	releaseErr                                 error
	releaseCheck                               func()
	renew                                      func(context.Context, string) (ports.ReviewLockReply, error)
}

func (*ownerTestTransport) Hello(context.Context) (ports.ReviewLockInstallation, error) {
	return ports.ReviewLockInstallation{Protocol: ports.HaepariProtocolID, ProtocolVersion: 1, InstallationID: "test-installation", Capabilities: []string{ports.HaepariCapabilityManagedExecutionV1, ports.HaepariCapabilityAdvisoryLockV1}}, nil
}
func (*ownerTestTransport) InspectResource(context.Context, string) (ports.ReviewLockResource, error) {
	return ports.ReviewLockResource{InstallationID: "test-installation", ResourceID: ports.HaepariReviewResourceID, Kind: "lock", Capacity: 1, ConfigurationDigest: strings.Repeat("a", 64), ConfigRevision: 1, Availability: "available"}, nil
}
func (transport *ownerTestTransport) reply(op ports.ReviewLockReceiptOperation) ports.ReviewLockReply {
	return ports.ReviewLockReply{Current: transport.current, Receipt: ports.ReviewLockReceipt{Operation: op, RequestID: transport.current.RequestID, GrantID: transport.current.GrantID, State: transport.current.State, RecordedAt: time.Now().UTC()}}
}
func (transport *ownerTestTransport) Acquire(_ context.Context, raw []byte) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.acquires++
	var payload struct {
		LockID     string `json:"lock_id"`
		RequestKey string `json:"request_key"`
		Holder     string `json:"holder"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ports.ReviewLockReply{}, err
	}
	now := time.Now().UTC()
	transport.current = ports.ReviewLockRequest{InstallationID: "test-installation", LockID: payload.LockID, RequestID: "request-1", RequestKey: payload.RequestKey, Holder: payload.Holder, State: ports.ReviewLockStateQueued, Sequence: 1, Slot: -1, QueuedAt: now}
	if !transport.queued {
		transport.grant()
	}
	return transport.reply(ports.ReviewLockReceiptOperationAcquire), nil
}
func (transport *ownerTestTransport) grant() {
	now := time.Now().UTC()
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
	live := time.Now().UTC().Add(time.Minute)
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
	now := time.Now().UTC()
	transport.current.State, transport.current.EndedAt = ports.ReviewLockStateReleased, &now
	return transport.reply(ports.ReviewLockReceiptOperationRelease), nil
}
func (transport *ownerTestTransport) Cancel(_ context.Context, id string) (ports.ReviewLockReply, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.cancels++
	if id != transport.current.RequestID {
		return ports.ReviewLockReply{}, errors.New("wrong request")
	}
	now := time.Now().UTC()
	transport.current.EndedAt = &now
	if transport.current.State == ports.ReviewLockStateGranted {
		transport.current.State = ports.ReviewLockStateReleased
	} else {
		transport.current.State = ports.ReviewLockStateCancelled
	}
	return transport.reply(ports.ReviewLockReceiptOperationCancel), nil
}
func (*ownerTestTransport) ListLocks(context.Context, string, string, int) (ports.ReviewLockList, error) {
	return ports.ReviewLockList{}, errors.New("unexpected list")
}

func newOwnerTestCoordinator(t *testing.T) (*ReviewCoordinator, *ownerTestStore, *ownerTestTransport) {
	t.Helper()
	store := &ownerTestStore{}
	transport := &ownerTestTransport{}
	coordinator, err := NewReviewCoordinator(store, transport, ownerTestClock{})
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
		return ports.ReviewLockReply{}, context.Canceled
	}
	_, err := coordinator.startOwnedReview(ctx, ownerTestRequest(t), time.Minute)
	var failure *domain.Failure
	if !errors.As(err, &failure) || failure.Class() != domain.FailureCancelled || transport.acquires != 1 || transport.waits != 2 || transport.cancels != 1 || store.record.ObservedRequest.State != ports.ReviewLockStateReleased || store.record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
		t.Fatalf("cancel race: %v / %+v", err, transport)
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
