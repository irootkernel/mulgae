package ports_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestReviewLockRequestPayloadValidation(t *testing.T) {
	t.Parallel()

	sessionID, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	if err != nil {
		t.Fatal(err)
	}

	payloadNoQueue, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatalf("NewReviewLockRequestPayload(nil): %v", err)
	}
	if strings.Contains(string(payloadNoQueue.CanonicalJSON), "queue_seconds") {
		t.Fatalf("expected queue_seconds omitted when nil, got %s", payloadNoQueue.CanonicalJSON)
	}
	if payloadNoQueue.RequestKey != "mulgae-"+runID.String() {
		t.Fatalf("unexpected request_key %q", payloadNoQueue.RequestKey)
	}
	if payloadNoQueue.Holder != "mulgae:"+sessionID.String()+":"+runID.String() {
		t.Fatalf("unexpected holder %q", payloadNoQueue.Holder)
	}
	if !ports.ValidHaepariDigest(payloadNoQueue.NativePayloadDigest) {
		t.Fatalf("expected 64-hex native digest, got %q", payloadNoQueue.NativePayloadDigest)
	}
	if payloadNoQueue.PayloadSHA256 != "sha256:"+payloadNoQueue.NativePayloadDigest {
		t.Fatalf("expected sha256-prefixed digest, got %q", payloadNoQueue.PayloadSHA256)
	}

	queueSec := int64(120)
	payloadWithQueue, err := ports.NewReviewLockRequestPayload(sessionID, runID, &queueSec)
	if err != nil {
		t.Fatalf("NewReviewLockRequestPayload(120): %v", err)
	}
	if !strings.Contains(string(payloadWithQueue.CanonicalJSON), `"queue_seconds":120`) {
		t.Fatalf("expected queue_seconds in canonical JSON, got %s", payloadWithQueue.CanonicalJSON)
	}
	queueSec = 999
	if *payloadWithQueue.QueueSeconds != 120 {
		t.Fatalf("expected defensive copy of queue_seconds, got %d", *payloadWithQueue.QueueSeconds)
	}

	maxQueue := ports.HaepariMaxQueueSeconds
	if _, err := ports.NewReviewLockRequestPayload(sessionID, runID, &maxQueue); err != nil {
		t.Fatalf("expected max queue_seconds accepted: %v", err)
	}
	for _, invalid := range []int64{0, -1, ports.HaepariMaxQueueSeconds + 1} {
		v := invalid
		if _, err := ports.NewReviewLockRequestPayload(sessionID, runID, &v); err == nil {
			t.Fatalf("expected queue_seconds=%d rejected", invalid)
		}
	}

	tampered := payloadWithQueue
	tampered.PayloadSHA256 = "sha256:" + strings.Repeat("0", 64)
	if err := tampered.ValidateForIdentity(sessionID, runID); err == nil {
		t.Fatal("expected tampered PayloadSHA256 rejected")
	}

	otherRunID, err := domain.ParseRunID("r_019f596a-d174-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	if err := payloadWithQueue.ValidateForIdentity(sessionID, otherRunID); err == nil {
		t.Fatal("expected mismatched runID rejected")
	}
}

func TestReviewLockRequestSlotStateAndNativeHolderValidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	grantedAt := now.Add(2 * time.Second)
	livenessDeadline := grantedAt.Add(30 * time.Second)
	maxHoldDeadline := grantedAt.Add(300 * time.Second)
	endedAt := grantedAt.Add(15 * time.Second)

	queued := ports.ReviewLockRequest{
		InstallationID: "inst-01",
		LockID:         ports.HaepariReviewResourceID,
		RequestID:      "lreq_01",
		RequestKey:     "mulgae-r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		Holder:         " external-holder-with-leading-space-and-up-to-512-bytes " + strings.Repeat("x", 400),
		State:          ports.ReviewLockStateQueued,
		Sequence:       1,
		Slot:           -1,
		QueuedAt:       now,
	}
	if err := queued.Validate(); err != nil {
		t.Fatalf("queued request with valid 512-bound native holder: %v", err)
	}
	tooLongHolder := queued
	tooLongHolder.Holder = strings.Repeat("x", 513)
	if err := tooLongHolder.Validate(); err == nil {
		t.Fatal("expected holder > 512 bytes rejected")
	}
	blankHolder := queued
	blankHolder.Holder = "   "
	if err := blankHolder.Validate(); err == nil {
		t.Fatal("expected blank holder rejected")
	}

	badQueued := queued
	badQueued.Slot = 0
	if err := badQueued.Validate(); err == nil {
		t.Fatal("expected queued request with slot 0 rejected")
	}

	granted := queued
	granted.State = ports.ReviewLockStateGranted
	granted.Slot = 0
	granted.GrantID = "lgrant_01"
	granted.Generation = 1
	granted.GrantedAt = &grantedAt
	granted.LivenessDeadline = &livenessDeadline
	granted.MaxHoldDeadline = &maxHoldDeadline
	granted.LivenessSeconds = 30
	granted.MaxHoldSeconds = 300
	if err := granted.Validate(); err != nil {
		t.Fatalf("granted request: %v", err)
	}

	for _, state := range []ports.ReviewLockState{ports.ReviewLockStateReleased, ports.ReviewLockStateHoldExpired} {
		terminalGranted := granted
		terminalGranted.State = state
		terminalGranted.EndedAt = &endedAt
		if err := terminalGranted.Validate(); err != nil {
			t.Fatalf("terminal previously-granted state %s with slot 0: %v", state, err)
		}
		badSlot := terminalGranted
		badSlot.Slot = -1
		if err := badSlot.Validate(); err == nil {
			t.Fatalf("expected %s with slot -1 rejected", state)
		}
	}

	for _, state := range []ports.ReviewLockState{ports.ReviewLockStateCancelled, ports.ReviewLockStateQueueExpired} {
		terminalQueued := queued
		terminalQueued.State = state
		terminalQueued.EndedAt = &endedAt
		if err := terminalQueued.Validate(); err != nil {
			t.Fatalf("terminal never-granted state %s with slot -1: %v", state, err)
		}
		badGrant := terminalQueued
		badGrant.GrantID = "lgrant_01"
		if err := badGrant.Validate(); err == nil {
			t.Fatalf("expected %s with grant_id rejected", state)
		}
	}
}

func TestReviewLockReplyReplayAndTerminalValidation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	grantedAt := now.Add(2 * time.Second)
	liveness := grantedAt.Add(30 * time.Second)
	maxHold := grantedAt.Add(300 * time.Second)
	endedAt := grantedAt.Add(20 * time.Second)

	queuedReceipt := ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationAcquire,
		RequestID:  "lreq_01",
		State:      ports.ReviewLockStateQueued,
		RecordedAt: now,
	}
	grantedCurrent := ports.ReviewLockRequest{
		InstallationID:   "inst-01",
		LockID:           ports.HaepariReviewResourceID,
		RequestID:        "lreq_01",
		RequestKey:       "mulgae-r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		Holder:           "mulgae:s_019f596a-cf80-7c67-b265-f37053d51ccf:r_019f596a-cfe4-7c9c-b82e-7149158243ba",
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
	}

	// Acquire replay where original acquire receipt was queued, but current is now granted.
	replayQueuedToGranted := ports.ReviewLockReply{
		Receipt: queuedReceipt,
		Current: grantedCurrent,
	}
	if err := replayQueuedToGranted.Validate(ports.ReviewLockOperationAcquire); err != nil {
		t.Fatalf("expected queued->granted acquire replay accepted: %v", err)
	}

	// Acquire replay where original acquire receipt was granted, and current is now released.
	grantedReceipt := ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationAcquire,
		RequestID:  "lreq_01",
		GrantID:    "lgrant_01",
		State:      ports.ReviewLockStateGranted,
		RecordedAt: grantedAt,
	}
	releasedCurrent := grantedCurrent
	releasedCurrent.State = ports.ReviewLockStateReleased
	releasedCurrent.EndedAt = &endedAt
	replayGrantedToReleased := ports.ReviewLockReply{
		Receipt: grantedReceipt,
		Current: releasedCurrent,
	}
	if err := replayGrantedToReleased.Validate(ports.ReviewLockOperationAcquire); err != nil {
		t.Fatalf("expected granted->released acquire replay accepted: %v", err)
	}

	// Terminal release/cancel/wait replay where stored end_receipt has operation "expire".
	expiredReceipt := ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationExpire,
		RequestID:  "lreq_01",
		GrantID:    "lgrant_01",
		State:      ports.ReviewLockStateHoldExpired,
		RecordedAt: endedAt,
		Reason:     "liveness_deadline",
	}
	holdExpiredCurrent := releasedCurrent
	holdExpiredCurrent.State = ports.ReviewLockStateHoldExpired
	holdExpiredCurrent.Reason = "liveness_deadline"
	terminalReplay := ports.ReviewLockReply{
		Receipt: expiredReceipt,
		Current: holdExpiredCurrent,
	}
	for _, op := range []ports.ReviewLockOperation{
		ports.ReviewLockOperationRelease,
		ports.ReviewLockOperationCancel,
		ports.ReviewLockOperationWait,
	} {
		if err := terminalReplay.Validate(op); err != nil {
			t.Fatalf("expected stored expire end_receipt accepted for %s: %v", op, err)
		}
	}
}

func TestReviewLockInstallationAndResourceValidation(t *testing.T) {
	t.Parallel()

	if ports.ReviewLockOperationInspectResource != "resource.inspect" || !ports.ReviewLockOperationInspectResource.Valid() {
		t.Fatalf("expected ReviewLockOperationInspectResource = resource.inspect, got %q", ports.ReviewLockOperationInspectResource)
	}
	if ports.ReviewLockOperation("resources.inspect").Valid() {
		t.Fatal("expected plural resources.inspect operation rejected")
	}

	inst := ports.ReviewLockInstallation{
		Protocol:        ports.HaepariProtocolID,
		ProtocolVersion: ports.HaepariProtocolVersion,
		InstallationID:  "inst-01",
		Capabilities: []string{
			ports.HaepariCapabilityManagedExecutionV1,
			ports.HaepariCapabilityAdvisoryLockV1,
		},
	}
	if err := inst.Validate(); err != nil {
		t.Fatalf("valid installation: %v", err)
	}
	missingLockCap := inst
	missingLockCap.Capabilities = []string{ports.HaepariCapabilityManagedExecutionV1}
	if err := missingLockCap.Validate(); err == nil {
		t.Fatal("expected installation missing advisory-lock/v1 rejected")
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
	if err := res.Validate("inst-01"); err != nil {
		t.Fatalf("expected paused lock resource accepted: %v", err)
	}
	if err := res.Validate("inst-02"); err == nil {
		t.Fatal("expected mismatched installation_id rejected")
	}
	badCap := res
	badCap.Capacity = 2
	if err := badCap.Validate("inst-01"); err == nil {
		t.Fatal("expected capacity != 1 rejected")
	}
}

func TestReviewLockRecordAndGrantReferenceValidation(t *testing.T) {
	t.Parallel()

	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	record := ports.ReviewLockRecord{
		SchemaVersion:  artifactwire.HaepariLockIntentSchemaV1,
		SessionID:      sessionID,
		RunID:          runID,
		InstallationID: "inst-01",
		ResourceID:     ports.HaepariReviewResourceID,
		Payload:        payload,
		PersistedAt:    now,
		UpdatedAt:      now,
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("unobserved record: %v", err)
	}
	if _, ok := record.GrantReference(); ok {
		t.Fatal("expected no grant reference before observation")
	}

	// Observed replay where receipt was originally queued, and current is now granted.
	liveness := now.Add(30 * time.Second)
	maxHold := now.Add(300 * time.Second)
	receipt := ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationAcquire,
		RequestID:  "lreq_01",
		State:      ports.ReviewLockStateQueued,
		RecordedAt: now,
	}
	req := ports.ReviewLockRequest{
		InstallationID:   "inst-01",
		LockID:           ports.HaepariReviewResourceID,
		RequestID:        "lreq_01",
		RequestKey:       payload.RequestKey,
		Holder:           payload.Holder,
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
	}
	record.ObservedReceipt = &receipt
	record.ObservedRequest = &req
	if err := record.Validate(); err != nil {
		t.Fatalf("observed granted record from queued acquire receipt: %v", err)
	}
	ref, ok := record.GrantReference()
	if !ok || ref.GrantID != "lgrant_01" || ref.Generation != 1 || ref.Slot != 0 {
		t.Fatalf("unexpected grant reference: ok=%v ref=%+v", ok, ref)
	}
}

func TestReviewCoordinationErrorFormattingAndUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying disk failure")
	coordErr := &ports.ReviewCoordinationError{
		Reason:      ports.ReviewCoordinationReasonObservationPersistFailed,
		Operation:   ports.ReviewLockOperationAcquire,
		NativeCode:  "STORAGE_UNAVAILABLE",
		NativeRetry: ports.ReviewLockNativeRetryReconcile,
		Retry:       ports.ReviewCoordinationRetryInspectFirst,
		Uncertain:   true,
		Message:     "failed to persist post-acquire observation",
		Cause:       cause,
	}
	if !errors.Is(coordErr, cause) {
		t.Fatal("expected errors.Is to match underlying cause")
	}
	if !strings.Contains(coordErr.Error(), string(ports.ReviewCoordinationReasonObservationPersistFailed)) || !strings.Contains(coordErr.Error(), "native_retry=reconcile") {
		t.Fatalf("unexpected error string %q", coordErr.Error())
	}
}

func TestReviewLockBorrowedGrantReferenceAndV3Record(t *testing.T) {
	t.Parallel()

	validRaw := `{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":2}`
	borrowed, err := ports.DecodeReviewBorrowedGrantReference(validRaw)
	if err != nil {
		t.Fatalf("DecodeReviewBorrowedGrantReference(valid): %v", err)
	}
	if borrowed.InstallationID != "inst-01" || borrowed.LockID != "mulgae-review" || borrowed.GrantID != "lgrant_01" || borrowed.Generation != 2 {
		t.Fatalf("unexpected borrowed grant reference: %+v", borrowed)
	}

	// Syntactic decoding accepts another valid lock_id so wrong lock/installation can map to CONFLICT later.
	if otherLock, err := ports.DecodeReviewBorrowedGrantReference(`{"installation_id":"inst-02","lock_id":"other-lock","grant_id":"lgrant_01","generation":1}`); err != nil || otherLock.LockID != "other-lock" {
		t.Fatalf("expected valid identifier lock_id accepted syntactically, got %+v (%v)", otherLock, err)
	}

	for _, invalidRaw := range []string{
		"",
		"   ",
		"null",
		"{}",
		"[]",
		strings.Repeat(" ", ports.HaepariMaxParentContextBytes+1),
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":0}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":-1}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":null}`,
		`{"installation_id":null,"lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01"}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1,"extra":true}`,
		`{"Installation_ID":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`,
		`{"installation_id":"inst-01","installation_id":"inst-02","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`,
		`{"installation_id":"inst-01","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1} {}`,
		`{"installation_id":"-bad","lock_id":"mulgae-review","grant_id":"lgrant_01","generation":1}`,
	} {
		if _, err := ports.DecodeReviewBorrowedGrantReference(invalidRaw); err == nil {
			t.Fatalf("expected DecodeReviewBorrowedGrantReference(%q) to fail", invalidRaw)
		}
	}

	sessionID, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	runID, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	now := time.Date(2026, 11, 8, 5, 0, 0, 0, time.UTC)
	liveness := now.Add(30 * time.Second)
	maxHold := now.Add(5 * time.Minute)
	observedReq := ports.ReviewLockRequest{
		InstallationID:   "inst-01",
		LockID:           ports.HaepariReviewResourceID,
		RequestID:        "lreq_parent",
		RequestKey:       "parent-request-key",
		Holder:           "parent:holder",
		State:            ports.ReviewLockStateGranted,
		Sequence:         1,
		GrantID:          "lgrant_01",
		Generation:       2,
		Slot:             0,
		QueuedAt:         now,
		GrantedAt:        &now,
		LivenessDeadline: &liveness,
		MaxHoldDeadline:  &maxHold,
		LivenessSeconds:  30,
		MaxHoldSeconds:   300,
	}
	v3 := ports.ReviewLockRecord{
		SchemaVersion:   artifactwire.HaepariLockIntentSchemaV3,
		LocalDrainState: ports.ReviewLocalDrainNotStarted,
		SessionID:       sessionID,
		RunID:           runID,
		InstallationID:  "inst-01",
		ResourceID:      ports.HaepariReviewResourceID,
		BorrowedGrant:   &borrowed,
		ObservedRequest: &observedReq,
		PersistedAt:     now,
		UpdatedAt:       now,
	}
	if err := v3.Validate(); err != nil {
		t.Fatalf("valid v3 borrowed record rejected: %v", err)
	}
	if _, ok := v3.GrantReference(); ok {
		t.Fatal("v3 borrowed record must never produce owned ReviewLockGrantReference")
	}

	// Reject synthetic payload or observed receipt on v3 record.
	payload, _ := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	withPayload := v3
	withPayload.Payload = payload
	if err := withPayload.Validate(); err == nil {
		t.Fatal("expected v3 record with acquisition payload to fail validation")
	}
	withReceipt := v3
	withReceipt.ObservedReceipt = &ports.ReviewLockReceipt{
		Operation:  ports.ReviewLockReceiptOperationAcquire,
		RequestID:  "lreq_parent",
		GrantID:    "lgrant_01",
		State:      ports.ReviewLockStateGranted,
		RecordedAt: now,
	}
	if err := withReceipt.Validate(); err == nil {
		t.Fatal("expected v3 record with observed_receipt to fail validation")
	}
	nonGranted := observedReq
	ended := now.Add(time.Second)
	nonGranted.State = ports.ReviewLockStateReleased
	nonGranted.EndedAt = &ended
	withReleased := v3
	withReleased.ObservedRequest = &nonGranted
	if err := withReleased.Validate(); err == nil {
		t.Fatal("expected v3 record with non-granted observed_request to fail validation")
	}
}
