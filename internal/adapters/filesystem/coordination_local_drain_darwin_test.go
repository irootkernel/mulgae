//go:build darwin && arm64

package filesystem

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func coordinationV2Fixture(t *testing.T) ([]byte, ports.ReviewLockRecord) {
	t.Helper()
	data, err := os.ReadFile("testdata/haepari-lock-intent-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	record, err := decodeCoordinationIntentWire(data, session, run)
	if err != nil {
		t.Fatal(err)
	}
	return data, record
}

func TestCoordinationIntentStoreLocalDrainV2Compatibility(t *testing.T) {
	t.Parallel()
	data, record := coordinationV2Fixture(t)
	if record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV2 || record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
		t.Fatalf("invalid canonical v2 fixture: %+v", record)
	}
	for _, state := range []ports.ReviewLocalDrainState{ports.ReviewLocalDrainNotStarted, ports.ReviewLocalDrainUnverified, ports.ReviewLocalDrainVerified} {
		candidate := record
		candidate.LocalDrainState = state
		encoded, err := encodeCoordinationIntentWire(candidate)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeCoordinationIntentWire(encoded, record.SessionID, record.RunID)
		if err != nil || decoded.LocalDrainState != state {
			t.Fatalf("round trip %s: %+v, %v", state, decoded, err)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "local_drain_state")
	fields["schema_version"], _ = json.Marshal(artifactwire.HaepariLockIntentSchemaV1)
	legacy, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCoordinationIntentWire(legacy, record.SessionID, record.RunID)
	if err != nil || decoded.LocalDrainState != "" {
		t.Fatalf("v1 must retain unknown local proof: %+v, %v", decoded, err)
	}
	for _, test := range []struct{ name, schema, drain string }{
		{"missing", artifactwire.HaepariLockIntentSchemaV2, ""},
		{"null", artifactwire.HaepariLockIntentSchemaV2, "null"},
		{"unknown", artifactwire.HaepariLockIntentSchemaV2, `"native_expired"`},
		{"wrong_type", artifactwire.HaepariLockIntentSchemaV2, "true"},
		{"v1_extra", artifactwire.HaepariLockIntentSchemaV1, `"verified"`},
		{"v1_null_extra", artifactwire.HaepariLockIntentSchemaV1, "null"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var malformed map[string]json.RawMessage
			if err := json.Unmarshal(legacy, &malformed); err != nil {
				t.Fatal(err)
			}
			malformed["schema_version"], _ = json.Marshal(test.schema)
			if test.drain != "" {
				malformed["local_drain_state"] = json.RawMessage(test.drain)
			}
			encoded, err := json.Marshal(malformed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCoordinationIntentWire(encoded, record.SessionID, record.RunID); err == nil {
				t.Fatal("accepted malformed or cross-version local proof")
			}
		})
	}
}

func TestCoordinationIntentStoreLocalDrainTransitionsAndObservation(t *testing.T) {
	t.Parallel()
	fixture := newDiagnosticStoreFixture(t)
	t.Cleanup(func() { _, _ = fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture)) })
	_, record := coordinationV2Fixture(t)
	store := NewCoordinationIntentStore()
	ctx, root := context.Background(), fixture.request.Root()
	if _, err := store.PersistIntent(ctx, root, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainVerified, record.UpdatedAt); err == nil {
		t.Fatal("accepted skipped local effect admission")
	}
	now := record.UpdatedAt.Add(time.Second)
	grantedAt := now
	live, maximum := now.Add(30*time.Second), now.Add(time.Hour)
	reply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{Operation: ports.ReviewLockReceiptOperationAcquire, RequestID: "lreq_01", GrantID: "lgrant_01", State: ports.ReviewLockStateGranted, RecordedAt: now},
		Current: ports.ReviewLockRequest{InstallationID: record.InstallationID, LockID: record.ResourceID, RequestID: "lreq_01", RequestKey: record.Payload.RequestKey, Holder: record.Payload.Holder, State: ports.ReviewLockStateGranted, Sequence: 1, GrantID: "lgrant_01", Generation: 1, Slot: 0, QueuedAt: now, GrantedAt: &grantedAt, LivenessDeadline: &live, MaxHoldDeadline: &maximum, LivenessSeconds: 30, MaxHoldSeconds: 3600},
	}
	if _, err := store.UpdateObservation(ctx, root, record.SessionID, record.RunID, reply, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainUnverified, now); err != nil {
		t.Fatal(err)
	}
	// A native terminal receipt cannot turn unknown local completion into proof.
	ended := now.Add(time.Second)
	reply.Receipt.Operation, reply.Receipt.State, reply.Receipt.RecordedAt = ports.ReviewLockReceiptOperationRelease, ports.ReviewLockStateReleased, ended
	reply.Current.State, reply.Current.EndedAt = ports.ReviewLockStateReleased, &ended
	observed, err := store.UpdateObservation(ctx, root, record.SessionID, record.RunID, reply, ended)
	if err != nil || observed.LocalDrainState != ports.ReviewLocalDrainUnverified {
		t.Fatalf("native terminal erased local uncertainty: %+v, %v", observed, err)
	}
	updated, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainVerified, ended.Add(time.Second))
	if err != nil || updated.LocalDrainState != ports.ReviewLocalDrainVerified || updated.ObservedRequest.State != ports.ReviewLockStateReleased {
		t.Fatalf("local completion lost native observation: %+v, %v", updated, err)
	}
	if _, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainUnverified, ended.Add(2*time.Second)); err == nil {
		t.Fatal("accepted local proof regression")
	}
	if _, err := store.UpdateObservation(ctx, root, record.SessionID, record.RunID, reply, record.UpdatedAt); err == nil {
		t.Fatal("accepted stale observation over new proof")
	}
}

func coordinationV3Fixture(t *testing.T) ([]byte, ports.ReviewLockRecord) {
	t.Helper()
	data, err := os.ReadFile("testdata/haepari-lock-intent-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	session, _ := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	run, _ := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243ba")
	record, err := decodeCoordinationIntentWire(data, session, run)
	if err != nil {
		t.Fatal(err)
	}
	return data, record
}

func TestCoordinationIntentStoreBorrowedV3Lifecycle(t *testing.T) {
	t.Parallel()
	_, record := coordinationV3Fixture(t)
	if record.SchemaVersion != artifactwire.HaepariLockIntentSchemaV3 || record.BorrowedGrant == nil || record.ObservedRequest == nil || record.ObservedReceipt != nil || record.LocalDrainState != ports.ReviewLocalDrainNotStarted {
		t.Fatalf("invalid canonical v3 fixture: %+v", record)
	}
	for _, state := range []ports.ReviewLocalDrainState{ports.ReviewLocalDrainNotStarted, ports.ReviewLocalDrainUnverified, ports.ReviewLocalDrainVerified} {
		candidate := record
		candidate.LocalDrainState = state
		encoded, err := encodeCoordinationIntentWire(candidate)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeCoordinationIntentWire(encoded, record.SessionID, record.RunID)
		if err != nil || decoded.LocalDrainState != state || decoded.BorrowedGrant == nil || decoded.BorrowedGrant.GrantID != "lgrant_01" {
			t.Fatalf("v3 round trip %s: %+v, %v", state, decoded, err)
		}
	}

	fixture := newDiagnosticStoreFixture(t)
	t.Cleanup(func() { _, _ = fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture)) })
	store := NewCoordinationIntentStore()
	ctx, root := context.Background(), fixture.request.Root()

	persisted, err := store.PersistIntent(ctx, root, record)
	if err != nil {
		t.Fatalf("PersistIntent(v3): %v", err)
	}
	if _, err := store.PersistIntent(ctx, root, record); err == nil {
		t.Fatal("expected duplicate PersistIntent(v3) to fail")
	}
	// Borrowed v3 records must never accept native mutation receipt observations.
	now := persisted.UpdatedAt.Add(time.Second)
	reply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{Operation: ports.ReviewLockReceiptOperationRenew, RequestID: "lreq_parent_01", GrantID: "lgrant_01", State: ports.ReviewLockStateGranted, RecordedAt: now},
		Current: *persisted.ObservedRequest,
	}
	if _, err := store.UpdateObservation(ctx, root, record.SessionID, record.RunID, reply, now); err == nil {
		t.Fatal("accepted UpdateObservation on borrowed v3 record")
	}
	if _, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainVerified, now); err == nil {
		t.Fatal("accepted skipped unverified transition on borrowed v3 record")
	}
	unverified, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainUnverified, now)
	if err != nil || unverified.LocalDrainState != ports.ReviewLocalDrainUnverified {
		t.Fatalf("UpdateLocalDrain(unverified): %+v, %v", unverified, err)
	}
	verified, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainVerified, now.Add(time.Second))
	if err != nil || verified.LocalDrainState != ports.ReviewLocalDrainVerified {
		t.Fatalf("UpdateLocalDrain(verified): %+v, %v", verified, err)
	}
	if _, err := store.UpdateLocalDrain(ctx, root, record.SessionID, record.RunID, ports.ReviewLocalDrainUnverified, now.Add(2*time.Second)); err == nil {
		t.Fatal("accepted local drain regression on borrowed v3 record")
	}
}
