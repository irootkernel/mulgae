//go:build darwin && arm64

package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/app/clean"
	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func cleanupCoordinationRecord(t *testing.T, state ports.ReviewLocalDrainState) ports.ReviewLockRecord {
	t.Helper()
	_, record := coordinationV2Fixture(t)
	granted := record.PersistedAt.Add(time.Second)
	live, maximum, ended := granted.Add(30*time.Second), granted.Add(time.Hour), granted.Add(time.Second)
	record.LocalDrainState, record.UpdatedAt = state, ended
	record.ObservedReceipt = &ports.ReviewLockReceipt{Operation: ports.ReviewLockReceiptOperationRelease, RequestID: "lreq_01", GrantID: "lgrant_01", State: ports.ReviewLockStateReleased, RecordedAt: ended}
	record.ObservedRequest = &ports.ReviewLockRequest{InstallationID: record.InstallationID, LockID: record.ResourceID, RequestID: "lreq_01", RequestKey: record.Payload.RequestKey, Holder: record.Payload.Holder, State: ports.ReviewLockStateReleased, Sequence: 1, GrantID: "lgrant_01", Generation: 1, Slot: 0, QueuedAt: record.PersistedAt, GrantedAt: &granted, LivenessDeadline: &live, MaxHoldDeadline: &maximum, LivenessSeconds: 30, MaxHoldSeconds: 3600, EndedAt: &ended}
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	return record
}

func cleanupCoordinationFixture(t *testing.T, linked bool) (*CleanupStore, ports.AnchoredRoot, string, string, string) {
	t.Helper()
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session, run := "s_019f596a-cf80-7c67-b265-f37053d51ccf", "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	p2 := ""
	if linked {
		writeCleanupP2Fixture(t, root.String(), session, "", run, "completed", cleanupP2CompletedAt)
		p2 = ".mulgae/" + session + "/" + run + "/manifest.json"
	}
	diagnostic := writeCleanupDiagnosticFixture(t, root.String(), session, run, domain.RunFailed, cleanupP2CompletedAt, p2)
	return newCleanupStoreForTest(t, root), root, session, run, diagnostic
}

func TestCleanupStoreHaepariIntentProtectionBothRoots(t *testing.T) {
	t.Parallel()
	for _, linked := range []bool{false, true} {
		for _, kind := range []string{"unresolved", "active", "unverified", "legacy", "malformed", "symlink", "not_started", "verified"} {
			name := kind + "/diagnostic"
			if linked {
				name = kind + "/linked"
			}
			t.Run(name, func(t *testing.T) {
				store, root, session, run, diagnostic := cleanupCoordinationFixture(t, linked)
				record := cleanupCoordinationRecord(t, ports.ReviewLocalDrainVerified)
				switch kind {
				case "unresolved":
					record.ObservedReceipt, record.ObservedRequest = nil, nil
					record.LocalDrainState = ports.ReviewLocalDrainNotStarted
				case "active":
					record.ObservedReceipt.Operation, record.ObservedReceipt.State = ports.ReviewLockReceiptOperationAcquire, ports.ReviewLockStateGranted
					record.ObservedRequest.State, record.ObservedRequest.EndedAt = ports.ReviewLockStateGranted, nil
					record.LocalDrainState = ports.ReviewLocalDrainUnverified
				case "unverified":
					record.LocalDrainState = ports.ReviewLocalDrainUnverified
				case "legacy":
					record.SchemaVersion, record.LocalDrainState = artifactwire.HaepariLockIntentSchemaV1, ""
				case "not_started":
					record.LocalDrainState = ports.ReviewLocalDrainNotStarted
				}
				data, err := encodeCoordinationIntentWire(record)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "malformed" {
					data = []byte(`{"schema_version":"unknown"}`)
				}
				intent := filepath.Join(diagnostic, artifactwire.HaepariLockIntentFilename)
				if kind == "symlink" {
					external := filepath.Join(t.TempDir(), "intent")
					if err := os.WriteFile(external, data, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(external, intent); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(intent, data, 0600); err != nil {
					t.Fatal(err)
				}
				wantProtected := kind != "not_started" && kind != "verified"
				snapshot, err := store.Observe(context.Background())
				if err != nil || len(snapshot.Runs) != 1 {
					t.Fatalf("observation: %+v, %v", snapshot.Runs, err)
				}
				observation := snapshot.Runs[0]
				if (observation.Active || observation.Corrupt || observation.DiagnosticProtected) != wantProtected {
					t.Fatalf("incorrect local protection: %+v", observation)
				}
				tombstone := clean.Tombstone{RunID: run, PlanHash: cleanupTestHash("coordination")}
				if err := store.Tombstone(context.Background(), tombstone); err != nil {
					t.Fatal(err)
				}
				err = store.DeleteTombstoned(context.Background(), tombstone)
				if (err != nil) != wantProtected {
					t.Fatalf("protected=%t deletion=%v", wantProtected, err)
				}
				for _, path := range []string{diagnostic, filepath.Join(root.String(), session, run)} {
					if !linked && path != diagnostic {
						continue
					}
					_, statErr := os.Lstat(path)
					if wantProtected && statErr != nil || !wantProtected && !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("incorrect retained root %s: %v", path, statErr)
					}
				}
			})
		}
	}
}

func TestCleanupStoreHaepariIntentPreservesOrdinaryDiagnostics(t *testing.T) {
	t.Parallel()
	store, _, _, run, diagnostic := cleanupCoordinationFixture(t, false)
	for _, name := range []string{"mulgae-runtime.jsonl", "attempts/a_1/status.json", "invocations/0001-role/status.json", "invocations/0001-role/raw/stdout.log"} {
		path := filepath.Join(diagnostic, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("ordinary diagnostic content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tombstone := clean.Tombstone{RunID: run, PlanHash: cleanupTestHash("ordinary")}
	if err := store.Tombstone(context.Background(), tombstone); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTombstoned(context.Background(), tombstone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(diagnostic); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary diagnostic tree retained: %v", err)
	}
}

func TestCleanupStoreHaepariIntentDriftAfterSnapshotRetainsBothRoots(t *testing.T) {
	t.Parallel()
	for _, linked := range []bool{false, true} {
		store, root, session, run, diagnostic := cleanupCoordinationFixture(t, linked)
		record := cleanupCoordinationRecord(t, ports.ReviewLocalDrainVerified)
		data, err := encodeCoordinationIntentWire(record)
		if err != nil {
			t.Fatal(err)
		}
		intent := filepath.Join(diagnostic, artifactwire.HaepariLockIntentFilename)
		if err := os.WriteFile(intent, data, 0600); err != nil {
			t.Fatal(err)
		}
		err = store.WithCleanupTransaction(context.Background(), func(transaction clean.CleanupTransaction) error {
			before, err := transaction.Snapshot(context.Background())
			if err != nil {
				return err
			}
			record.UpdatedAt = record.UpdatedAt.Add(time.Second)
			changed, err := encodeCoordinationIntentWire(record)
			if err != nil {
				return err
			}
			if err := os.WriteFile(intent, changed, 0600); err != nil {
				return err
			}
			tombstone := clean.Tombstone{RunID: run, PlanHash: cleanupTestHash("drift")}
			if err := transaction.Tombstone(context.Background(), tombstone); err != nil {
				return err
			}
			if err := transaction.DeleteTombstoned(context.Background(), tombstone); err == nil {
				t.Fatal("intent drift was deleted")
			}
			after, err := store.Observe(context.Background())
			if err != nil {
				return err
			}
			if before.StoreEpoch == after.StoreEpoch {
				t.Fatal("exact intent bytes absent from cleanup epoch")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{diagnostic, filepath.Join(root.String(), session, run)} {
			if !linked && path != diagnostic {
				continue
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("intent drift removed a root: %v", err)
			}
		}
	}
}
