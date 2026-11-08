package reviewrun_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/reviewrun"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	current := c.now
	c.now = c.now.Add(time.Second)
	return current
}

type fakeIntentStore struct {
	record      ports.ReviewLockRecord
	hasRecord   bool
	loadErr     error
	persistErr  error
	updateErr   error
	loadCalls   int
	persistCall int
	updateCalls int
}

func (s *fakeIntentStore) LoadIntent(_ context.Context, _ ports.AnchoredRoot, _ domain.SessionID, _ domain.RunID) (ports.ReviewLockRecord, bool, error) {
	s.loadCalls++
	if s.loadErr != nil {
		return ports.ReviewLockRecord{}, false, s.loadErr
	}
	if !s.hasRecord {
		return ports.ReviewLockRecord{}, false, nil
	}
	return s.record, true, nil
}

func (s *fakeIntentStore) PersistIntent(_ context.Context, _ ports.AnchoredRoot, record ports.ReviewLockRecord) (ports.ReviewLockRecord, error) {
	s.persistCall++
	if s.persistErr != nil {
		return ports.ReviewLockRecord{}, s.persistErr
	}
	if s.hasRecord {
		return ports.ReviewLockRecord{}, errors.New("intent already exists")
	}
	if err := record.Validate(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	s.record = record
	s.hasRecord = true
	return record, nil
}

func (s *fakeIntentStore) UpdateObservation(_ context.Context, _ ports.AnchoredRoot, _ domain.SessionID, _ domain.RunID, reply ports.ReviewLockReply, updatedAt time.Time) (ports.ReviewLockRecord, error) {
	s.updateCalls++
	if s.updateErr != nil {
		return ports.ReviewLockRecord{}, s.updateErr
	}
	if !s.hasRecord {
		return ports.ReviewLockRecord{}, errors.New("intent absent")
	}
	receiptCopy := reply.Receipt
	currentCopy := reply.Current
	updated := s.record
	updated.UpdatedAt = updatedAt
	updated.ObservedReceipt = &receiptCopy
	updated.ObservedRequest = &currentCopy
	if err := updated.Validate(); err != nil {
		return ports.ReviewLockRecord{}, err
	}
	s.record = updated
	return updated, nil
}

func (s *fakeIntentStore) UpdateLocalDrain(_ context.Context, _ ports.AnchoredRoot, _ domain.SessionID, _ domain.RunID, state ports.ReviewLocalDrainState, updatedAt time.Time) (ports.ReviewLockRecord, error) {
	if !s.hasRecord || !state.Valid() {
		return ports.ReviewLockRecord{}, errors.New("invalid local drain update")
	}
	s.record.LocalDrainState, s.record.UpdatedAt = state, updatedAt
	return s.record, s.record.Validate()
}

type fakeLockTransport struct {
	inst            ports.ReviewLockInstallation
	helloErr        error
	res             ports.ReviewLockResource
	inspectErr      error
	acquireReplies  []ports.ReviewLockReply
	acquireErr      error
	acquirePayloads [][]byte
}

func (t *fakeLockTransport) Hello(_ context.Context) (ports.ReviewLockInstallation, error) {
	if t.helloErr != nil {
		return ports.ReviewLockInstallation{}, t.helloErr
	}
	return t.inst, nil
}

func (t *fakeLockTransport) InspectResource(_ context.Context, _ string) (ports.ReviewLockResource, error) {
	if t.inspectErr != nil {
		return ports.ReviewLockResource{}, t.inspectErr
	}
	return t.res, nil
}

func (t *fakeLockTransport) Acquire(_ context.Context, canonicalPayload []byte) (ports.ReviewLockReply, error) {
	t.acquirePayloads = append(t.acquirePayloads, append([]byte(nil), canonicalPayload...))
	if t.acquireErr != nil {
		return ports.ReviewLockReply{}, t.acquireErr
	}
	idx := len(t.acquirePayloads) - 1
	if idx >= len(t.acquireReplies) {
		idx = len(t.acquireReplies) - 1
	}
	return t.acquireReplies[idx], nil
}

func (t *fakeLockTransport) Wait(_ context.Context, _ string, _ time.Duration) (ports.ReviewLockReply, error) {
	return ports.ReviewLockReply{}, errors.New("not called in TASK-076")
}

func (t *fakeLockTransport) Renew(_ context.Context, _ string) (ports.ReviewLockReply, error) {
	return ports.ReviewLockReply{}, errors.New("not called in TASK-076")
}

func (t *fakeLockTransport) Release(_ context.Context, _ string) (ports.ReviewLockReply, error) {
	return ports.ReviewLockReply{}, errors.New("not called in TASK-076")
}

func (t *fakeLockTransport) Cancel(_ context.Context, _ string) (ports.ReviewLockReply, error) {
	return ports.ReviewLockReply{}, errors.New("not called in TASK-076")
}

func (t *fakeLockTransport) ListLocks(_ context.Context, _ string, _ string, _ int) (ports.ReviewLockList, error) {
	return ports.ReviewLockList{}, errors.New("not called in TASK-076")
}

func defaultValidInstallationAndResource() (ports.ReviewLockInstallation, ports.ReviewLockResource) {
	inst := ports.ReviewLockInstallation{
		Protocol:        ports.HaepariProtocolID,
		ProtocolVersion: ports.HaepariProtocolVersion,
		InstallationID:  "inst-01",
		Capabilities: []string{
			ports.HaepariCapabilityManagedExecutionV1,
			ports.HaepariCapabilityAdvisoryLockV1,
		},
	}
	res := ports.ReviewLockResource{
		InstallationID:       "inst-01",
		ResourceID:           ports.HaepariReviewResourceID,
		Kind:                 "lock",
		ConfigurationDigest:  strings.Repeat("a", 64),
		ConfigRevision:       1,
		AvailabilityRevision: 1,
		Availability:         "paused",
		Capacity:             1,
	}
	return inst, res
}

func TestReviewCoordinatorInitialAcquireAndIdempotentReplay(t *testing.T) {
	t.Parallel()

	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	expectedPayload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	grantedAt := now.Add(3 * time.Second)
	liveness := grantedAt.Add(30 * time.Second)
	maxHold := grantedAt.Add(300 * time.Second)

	queuedReceipt := ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationAcquire,
		RequestID:  "lreq_01",
		State:      ports.ReviewLockStateQueued,
		RecordedAt: now,
	}
	queuedReply := ports.ReviewLockReply{
		Receipt: queuedReceipt,
		Current: ports.ReviewLockRequest{
			InstallationID: "inst-01",
			LockID:         ports.HaepariReviewResourceID,
			RequestID:      "lreq_01",
			RequestKey:     expectedPayload.RequestKey,
			Holder:         expectedPayload.Holder,
			State:          ports.ReviewLockStateQueued,
			Sequence:       1,
			Slot:           -1,
			QueuedAt:       now,
		},
	}
	// On replay, Receipt is still the original queued acquire_receipt while Current is now granted.
	replayGrantedReply := ports.ReviewLockReply{
		Receipt: queuedReceipt,
		Current: ports.ReviewLockRequest{
			InstallationID:   "inst-01",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "lreq_01",
			RequestKey:       expectedPayload.RequestKey,
			Holder:           expectedPayload.Holder,
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "lgrant_01",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &grantedAt,
			LivenessDeadline: &liveness,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  30,
			MaxHoldSeconds:   300,
		},
	}

	inst, res := defaultValidInstallationAndResource()
	store := &fakeIntentStore{}
	transport := &fakeLockTransport{
		inst:           inst,
		res:            res,
		acquireReplies: []ports.ReviewLockReply{queuedReply, replayGrantedReply},
	}
	coord, err := reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	if err != nil {
		t.Fatal(err)
	}

	first, err := coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	if err != nil {
		t.Fatalf("first AcquireOrReplay: %v", err)
	}
	if first.ReplayedIntent || first.Grant != nil || first.Reply.Current.State != ports.ReviewLockStateQueued {
		t.Fatalf("unexpected first outcome: %+v", first)
	}
	if store.persistCall != 1 || store.updateCalls != 1 || len(transport.acquirePayloads) != 1 {
		t.Fatalf("unexpected store/transport counts: persist=%d update=%d acquire=%d", store.persistCall, store.updateCalls, len(transport.acquirePayloads))
	}

	// Second call must reuse the persisted intent without calling PersistIntent again, and send identical CanonicalJSON bytes.
	second, err := coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	if err != nil {
		t.Fatalf("second AcquireOrReplay: %v", err)
	}
	if !second.ReplayedIntent || second.Grant == nil || second.Grant.GrantID != "lgrant_01" || second.Grant.Slot != 0 {
		t.Fatalf("unexpected replay outcome: %+v", second)
	}
	if store.persistCall != 1 || store.updateCalls != 2 || len(transport.acquirePayloads) != 2 {
		t.Fatalf("unexpected replay counts: persist=%d update=%d acquire=%d", store.persistCall, store.updateCalls, len(transport.acquirePayloads))
	}
	if !bytes.Equal(transport.acquirePayloads[0], transport.acquirePayloads[1]) {
		t.Fatalf("expected identical acquire payload bytes across replay")
	}
}

func TestReviewCoordinatorRefusesAcquireWhenIntentPersistenceFails(t *testing.T) {
	t.Parallel()

	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	inst, res := defaultValidInstallationAndResource()

	store := &fakeIntentStore{persistErr: errors.New("ENOSPC")}
	transport := &fakeLockTransport{inst: inst, res: res}
	coord, err := reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}

	_, err = coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonPersistenceRefused || coordErr.Uncertain {
		t.Fatalf("expected haepari_persistence_refused (Uncertain=false), got %+v (%v)", coordErr, err)
	}
	if len(transport.acquirePayloads) != 0 {
		t.Fatalf("expected zero Acquire calls after persistence refusal, got %d", len(transport.acquirePayloads))
	}
}

func TestReviewCoordinatorRetainsKnownNativeResultWhenObservationPersistFails(t *testing.T) {
	t.Parallel()

	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	expectedPayload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	liveness := now.Add(30 * time.Second)
	maxHold := now.Add(300 * time.Second)
	grantedReply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{
			Operation:  ports.ReviewLockReceiptOperationAcquire,
			RequestID:  "lreq_01",
			GrantID:    "lgrant_01",
			State:      ports.ReviewLockStateGranted,
			RecordedAt: now,
		},
		Current: ports.ReviewLockRequest{
			InstallationID:   "inst-01",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "lreq_01",
			RequestKey:       expectedPayload.RequestKey,
			Holder:           expectedPayload.Holder,
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "lgrant_01",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &now,
			LivenessDeadline: &liveness,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  30,
			MaxHoldSeconds:   300,
		},
	}

	inst, res := defaultValidInstallationAndResource()
	store := &fakeIntentStore{updateErr: errors.New("disk I/O failure during RENAME_SWAP")}
	transport := &fakeLockTransport{
		inst:           inst,
		res:            res,
		acquireReplies: []ports.ReviewLockReply{grantedReply},
	}
	coord, err := reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonObservationPersistFailed || !coordErr.Uncertain {
		t.Fatalf("expected haepari_observation_persist_failed with Uncertain=true, got %+v (%v)", coordErr, err)
	}
	if outcome.Reply.Current.RequestID != "lreq_01" || outcome.Reply.Current.GrantID != "lgrant_01" {
		t.Fatalf("expected known native Reply preserved on observation persistence failure, got %+v", outcome.Reply)
	}
	if outcome.Grant == nil || outcome.Grant.GrantID != "lgrant_01" || outcome.Grant.Generation != 1 {
		t.Fatalf("expected known native GrantReference preserved on observation persistence failure, got %+v", outcome.Grant)
	}
	if coordErr.KnownRecord == nil || coordErr.KnownRecord.ObservedRequest == nil || coordErr.KnownRecord.ObservedRequest.GrantID != "lgrant_01" {
		t.Fatalf("expected KnownRecord populated on ReviewCoordinationError, got %+v", coordErr.KnownRecord)
	}
	if coordErr.KnownReply == nil || coordErr.KnownReply.Current.GrantID != "lgrant_01" {
		t.Fatalf("expected KnownReply populated on ReviewCoordinationError, got %+v", coordErr.KnownReply)
	}
}

func TestReviewCoordinatorAdmissionAndIdentityMismatchRefusals(t *testing.T) {
	t.Parallel()

	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)

	// 1. Missing advisory-lock/v1 capability.
	inst, res := defaultValidInstallationAndResource()
	inst.Capabilities = []string{ports.HaepariCapabilityManagedExecutionV1}
	store := &fakeIntentStore{}
	transport := &fakeLockTransport{inst: inst, res: res}
	coord, _ := reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	_, err = coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{Root: root, SessionID: sessionID, RunID: runID})
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonCapabilityUnsupported {
		t.Fatalf("expected haepari_capability_unsupported, got %+v (%v)", coordErr, err)
	}
	if store.persistCall != 0 || len(transport.acquirePayloads) != 0 {
		t.Fatal("expected zero persist/acquire calls when capability missing")
	}

	// 2. Resource capacity != 1.
	inst, res = defaultValidInstallationAndResource()
	res.Capacity = 2
	transport = &fakeLockTransport{inst: inst, res: res}
	coord, _ = reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	_, err = coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{Root: root, SessionID: sessionID, RunID: runID})
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonResourceInvalid {
		t.Fatalf("expected haepari_resource_invalid, got %+v (%v)", coordErr, err)
	}
	if store.persistCall != 0 || len(transport.acquirePayloads) != 0 {
		t.Fatal("expected zero persist/acquire calls when resource invalid")
	}

	// 3. Existing intent bound to a different installation_id.
	inst, res = defaultValidInstallationAndResource()
	payload, _ := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	store = &fakeIntentStore{
		hasRecord: true,
		record: ports.ReviewLockRecord{
			SchemaVersion:  "mulgae-haepari-lock-intent.v1",
			SessionID:      sessionID,
			RunID:          runID,
			InstallationID: "inst-other",
			ResourceID:     ports.HaepariReviewResourceID,
			Payload:        payload,
			PersistedAt:    now,
			UpdatedAt:      now,
		},
	}
	transport = &fakeLockTransport{inst: inst, res: res}
	coord, _ = reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	_, err = coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{Root: root, SessionID: sessionID, RunID: runID})
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonInstallationMismatch {
		t.Fatalf("expected haepari_installation_mismatch, got %+v (%v)", coordErr, err)
	}
	if len(transport.acquirePayloads) != 0 {
		t.Fatal("expected zero acquire calls when persisted installation_id mismatches")
	}
}

func TestReviewCoordinatorPreservesPersistedIntentAndReplaysAfterUncertainAcquire(t *testing.T) {
	t.Parallel()

	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	expectedPayload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	grantedAt := now.Add(2 * time.Second)
	liveness := grantedAt.Add(30 * time.Second)
	maxHold := grantedAt.Add(300 * time.Second)
	replayGrantedReply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{
			Operation:  ports.ReviewLockReceiptOperationAcquire,
			RequestID:  "lreq_01",
			GrantID:    "lgrant_01",
			State:      ports.ReviewLockStateGranted,
			RecordedAt: grantedAt,
		},
		Current: ports.ReviewLockRequest{
			InstallationID:   "inst-01",
			LockID:           ports.HaepariReviewResourceID,
			RequestID:        "lreq_01",
			RequestKey:       expectedPayload.RequestKey,
			Holder:           expectedPayload.Holder,
			State:            ports.ReviewLockStateGranted,
			Sequence:         1,
			GrantID:          "lgrant_01",
			Generation:       1,
			Slot:             0,
			QueuedAt:         now,
			GrantedAt:        &grantedAt,
			LivenessDeadline: &liveness,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  30,
			MaxHoldSeconds:   300,
		},
	}

	inst, res := defaultValidInstallationAndResource()
	store := &fakeIntentStore{}
	transport := &fakeLockTransport{
		inst: inst,
		res:  res,
		acquireErr: &ports.ReviewCoordinationError{
			Reason:      ports.ReviewCoordinationReasonAcquireUncertain,
			Operation:   ports.ReviewLockOperationAcquire,
			NativeCode:  "STORAGE_UNAVAILABLE",
			NativeRetry: ports.ReviewLockNativeRetryReconcile,
			Retry:       ports.ReviewCoordinationRetryReconcile,
			Uncertain:   true,
			Message:     "sqlite unavailable during lock.acquire",
		},
	}
	coord, err := reviewrun.NewReviewCoordinator(store, transport, &fakeClock{now: now})
	if err != nil {
		t.Fatal(err)
	}

	first, err := coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	var coordErr *ports.ReviewCoordinationError
	if !errors.As(err, &coordErr) || coordErr.Reason != ports.ReviewCoordinationReasonAcquireUncertain || !coordErr.Uncertain {
		t.Fatalf("expected haepari_acquire_uncertain (Uncertain=true), got %+v (%v)", coordErr, err)
	}
	if first.ReplayedIntent || first.Record.Payload.PayloadSHA256 != expectedPayload.PayloadSHA256 || first.Record.ObservedRequest != nil {
		t.Fatalf("expected persisted pre-acquire intent record returned on uncertain acquire, got %+v", first)
	}
	if !store.hasRecord || store.persistCall != 1 || store.updateCalls != 0 || len(transport.acquirePayloads) != 1 {
		t.Fatalf("unexpected store/transport state after uncertain acquire: hasRecord=%v persist=%d update=%d acquire=%d", store.hasRecord, store.persistCall, store.updateCalls, len(transport.acquirePayloads))
	}

	// Next call must replay the exact persisted key and canonical payload bytes without creating a new identity.
	transport.acquireErr = nil
	transport.acquireReplies = []ports.ReviewLockReply{replayGrantedReply}
	second, err := coord.AcquireOrReplay(context.Background(), reviewrun.ReviewAcquireRequest{
		Root:      root,
		SessionID: sessionID,
		RunID:     runID,
	})
	if err != nil {
		t.Fatalf("second AcquireOrReplay after uncertain acquire: %v", err)
	}
	if !second.ReplayedIntent || second.Grant == nil || second.Grant.GrantID != "lgrant_01" {
		t.Fatalf("unexpected replay outcome after uncertain acquire: %+v", second)
	}
	if store.persistCall != 1 || store.updateCalls != 1 || len(transport.acquirePayloads) != 2 {
		t.Fatalf("expected PersistIntent not called again on replay: persist=%d update=%d acquire=%d", store.persistCall, store.updateCalls, len(transport.acquirePayloads))
	}
	if !bytes.Equal(transport.acquirePayloads[0], transport.acquirePayloads[1]) {
		t.Fatal("expected identical acquire payload bytes replayed after uncertain acquire")
	}
}
