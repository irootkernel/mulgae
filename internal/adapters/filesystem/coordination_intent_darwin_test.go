//go:build darwin && arm64

package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/artifactwire"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCoordinationIntentStoreRequiresExistingDiagnosticRunStatus(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
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

	store := NewCoordinationIntentStore()
	if _, _, err := store.LoadIntent(context.Background(), root, sessionID, runID); err == nil {
		t.Fatal("expected LoadIntent to fail when diagnostic run status.json is absent")
	}
	if _, err := store.PersistIntent(context.Background(), root, record); err == nil {
		t.Fatal("expected PersistIntent to fail when diagnostic run status.json is absent")
	}
	if _, err := os.Stat(filepath.Join(rootPath, "diagnostics")); !os.IsNotExist(err) {
		t.Fatalf("expected no bare diagnostics directory created, stat err = %v", err)
	}
}

func TestCoordinationIntentStorePersistLoadAndExclusiveCreation(t *testing.T) {
	t.Parallel()

	fixture := newDiagnosticStoreFixture(t)
	defer func() {
		_, _ = fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture))
	}()

	sessionID := fixture.request.SessionID()
	runID := fixture.request.RunID()
	root := fixture.request.Root()
	store := NewCoordinationIntentStore()

	_, found, err := store.LoadIntent(context.Background(), root, sessionID, runID)
	if err != nil {
		t.Fatalf("LoadIntent before persist: %v", err)
	}
	if found {
		t.Fatal("expected found=false before PersistIntent")
	}

	queueSec := int64(90)
	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, &queueSec)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 6, 0, 1, 0, time.UTC)
	initial := ports.ReviewLockRecord{
		SchemaVersion:  artifactwire.HaepariLockIntentSchemaV1,
		SessionID:      sessionID,
		RunID:          runID,
		InstallationID: "inst-01",
		ResourceID:     ports.HaepariReviewResourceID,
		Payload:        payload,
		PersistedAt:    now,
		UpdatedAt:      now,
	}

	persisted, err := store.PersistIntent(context.Background(), root, initial)
	if err != nil {
		t.Fatalf("PersistIntent: %v", err)
	}
	if string(persisted.Payload.CanonicalJSON) != string(payload.CanonicalJSON) || persisted.Payload.PayloadSHA256 != payload.PayloadSHA256 {
		t.Fatalf("unexpected persisted payload: %+v", persisted.Payload)
	}

	intentPath := diagnosticStorePath(fixture, artifactwire.HaepariLockIntentFilename)
	info, err := os.Lstat(intentPath)
	if err != nil {
		t.Fatalf("stat haepari-lock.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("haepari-lock.json perm = %o, want 0600", info.Mode().Perm())
	}

	// Second PersistIntent must fail closed without overwriting.
	if _, err := store.PersistIntent(context.Background(), root, initial); err == nil {
		t.Fatal("expected second PersistIntent to fail closed (RENAME_EXCL)")
	}
}

func TestCoordinationIntentStoreUpdateObservationAndReplayCompatibility(t *testing.T) {
	t.Parallel()

	fixture := newDiagnosticStoreFixture(t)
	defer func() {
		_, _ = fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture))
	}()

	sessionID := fixture.request.SessionID()
	runID := fixture.request.RunID()
	root := fixture.request.Root()
	store := NewCoordinationIntentStore()

	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	persistedAt := time.Date(2026, 7, 23, 6, 0, 1, 0, time.UTC)
	initial := ports.ReviewLockRecord{
		SchemaVersion:  artifactwire.HaepariLockIntentSchemaV1,
		SessionID:      sessionID,
		RunID:          runID,
		InstallationID: "inst-01",
		ResourceID:     ports.HaepariReviewResourceID,
		Payload:        payload,
		PersistedAt:    persistedAt,
		UpdatedAt:      persistedAt,
	}
	if _, err := store.PersistIntent(context.Background(), root, initial); err != nil {
		t.Fatalf("PersistIntent: %v", err)
	}

	// Update with initial queued observation.
	queuedAt := persistedAt.Add(time.Second)
	queuedReply := ports.ReviewLockReply{
		Receipt: ports.ReviewLockReceipt{
			Operation:  ports.ReviewLockReceiptOperationAcquire,
			RequestID:  "lreq_01",
			State:      ports.ReviewLockStateQueued,
			RecordedAt: queuedAt,
		},
		Current: ports.ReviewLockRequest{
			InstallationID: "inst-01",
			LockID:         ports.HaepariReviewResourceID,
			RequestID:      "lreq_01",
			RequestKey:     payload.RequestKey,
			Holder:         payload.Holder,
			State:          ports.ReviewLockStateQueued,
			Sequence:       1,
			Slot:           -1,
			QueuedAt:       queuedAt,
		},
	}
	afterQueued, err := store.UpdateObservation(context.Background(), root, sessionID, runID, queuedReply, queuedAt)
	if err != nil {
		t.Fatalf("UpdateObservation(queued): %v", err)
	}
	if afterQueued.ObservedRequest == nil || afterQueued.ObservedRequest.State != ports.ReviewLockStateQueued || afterQueued.ObservedRequest.Slot != -1 {
		t.Fatalf("unexpected queued observation: %+v", afterQueued.ObservedRequest)
	}

	// Update with native acquire replay where receipt stays original queued acquire_receipt, while current is now granted.
	grantedAt := queuedAt.Add(3 * time.Second)
	liveness := grantedAt.Add(30 * time.Second)
	maxHold := grantedAt.Add(300 * time.Second)
	replayGrantedReply := ports.ReviewLockReply{
		Receipt: queuedReply.Receipt,
		Current: ports.ReviewLockRequest{
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
			QueuedAt:         queuedAt,
			GrantedAt:        &grantedAt,
			LivenessDeadline: &liveness,
			MaxHoldDeadline:  &maxHold,
			LivenessSeconds:  30,
			MaxHoldSeconds:   300,
		},
	}
	afterGranted, err := store.UpdateObservation(context.Background(), root, sessionID, runID, replayGrantedReply, grantedAt)
	if err != nil {
		t.Fatalf("UpdateObservation(replay granted): %v", err)
	}
	ref, ok := afterGranted.GrantReference()
	if !ok || ref.GrantID != "lgrant_01" || ref.Generation != 1 || ref.Slot != 0 {
		t.Fatalf("expected active grant reference after replay update, got ok=%v ref=%+v", ok, ref)
	}
	if !afterGranted.PersistedAt.Equal(persistedAt) {
		t.Fatalf("expected PersistedAt preserved: got %v want %v", afterGranted.PersistedAt, persistedAt)
	}

	// Reject update attempting to change RequestID.
	wrongReqID := replayGrantedReply
	wrongReqID.Receipt.RequestID = "lreq_02"
	wrongReqID.Current.RequestID = "lreq_02"
	if _, err := store.UpdateObservation(context.Background(), root, sessionID, runID, wrongReqID, grantedAt.Add(time.Second)); err == nil {
		t.Fatal("expected changed request_id rejected")
	}
}

func TestCoordinationIntentStoreTamperAndSymlinkRejection(t *testing.T) {
	t.Parallel()

	fixture := newDiagnosticStoreFixture(t)
	defer func() {
		_, _ = fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture))
	}()

	sessionID := fixture.request.SessionID()
	runID := fixture.request.RunID()
	root := fixture.request.Root()
	store := NewCoordinationIntentStore()

	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 6, 0, 1, 0, time.UTC)
	initial := ports.ReviewLockRecord{
		SchemaVersion:  artifactwire.HaepariLockIntentSchemaV1,
		SessionID:      sessionID,
		RunID:          runID,
		InstallationID: "inst-01",
		ResourceID:     ports.HaepariReviewResourceID,
		Payload:        payload,
		PersistedAt:    now,
		UpdatedAt:      now,
	}
	if _, err := store.PersistIntent(context.Background(), root, initial); err != nil {
		t.Fatal(err)
	}

	intentPath := diagnosticStorePath(fixture, artifactwire.HaepariLockIntentFilename)
	raw, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt payload_sha256 in file.
	corrupted := strings.Replace(string(raw), payload.PayloadSHA256, "sha256:"+strings.Repeat("f", 64), 1)
	if err := os.WriteFile(intentPath, []byte(corrupted), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadIntent(context.Background(), root, sessionID, runID); err == nil {
		t.Fatal("expected corrupted payload_sha256 rejected")
	}

	// Replace with symlink.
	otherFile := filepath.Join(fixture.root, "outside.json")
	if err := os.WriteFile(otherFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(intentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherFile, intentPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadIntent(context.Background(), root, sessionID, runID); err == nil {
		t.Fatal("expected symlinked haepari-lock.json rejected")
	}
}

func TestCoordinationIntentStoreCoexistsWithDiagnosticsAndCleanup(t *testing.T) {
	t.Parallel()

	fixture := newDiagnosticStoreFixture(t)
	sessionID := fixture.request.SessionID()
	runID := fixture.request.RunID()
	root := fixture.request.Root()
	store := NewCoordinationIntentStore()
	cleanupStore := newCleanupStoreForTest(t, root)

	observedBefore, err := cleanupStore.Observe(context.Background())
	if err != nil {
		t.Fatalf("CleanupStore.Observe before PersistIntent: %v", err)
	}
	if len(observedBefore.Runs) != 1 || observedBefore.Runs[0].Corrupt || observedBefore.Runs[0].RunID != runID.String() {
		t.Fatalf("unexpected cleanup observation before PersistIntent: %+v", observedBefore.Runs)
	}

	payload, err := ports.NewReviewLockRequestPayload(sessionID, runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 6, 0, 1, 0, time.UTC)
	initial := ports.ReviewLockRecord{
		SchemaVersion:  artifactwire.HaepariLockIntentSchemaV1,
		SessionID:      sessionID,
		RunID:          runID,
		InstallationID: "inst-01",
		ResourceID:     ports.HaepariReviewResourceID,
		Payload:        payload,
		PersistedAt:    now,
		UpdatedAt:      now,
	}
	if _, err := store.PersistIntent(context.Background(), root, initial); err != nil {
		t.Fatal(err)
	}

	rawIntent, err := os.ReadFile(diagnosticStorePath(fixture, artifactwire.HaepariLockIntentFilename))
	if err != nil {
		t.Fatalf("read persisted haepari-lock.json: %v", err)
	}
	observedAfterPersist, err := cleanupStore.Observe(context.Background())
	if err != nil {
		t.Fatalf("CleanupStore.Observe after PersistIntent: %v", err)
	}
	if len(observedAfterPersist.Runs) != 1 || observedAfterPersist.Runs[0].Corrupt {
		t.Fatalf("unexpected cleanup observation after PersistIntent: %+v", observedAfterPersist.Runs)
	}
	if delta := observedAfterPersist.Runs[0].RegularFileBytes - observedBefore.Runs[0].RegularFileBytes; delta != int64(len(rawIntent)) {
		t.Fatalf("expected CleanupStore RegularFileBytes delta %d for haepari-lock.json, got %d", len(rawIntent), delta)
	}

	// Verify private diagnostic coordination intent path is rejected by the support/export artifact namespace.
	intentRelPath, err := ports.NewSafeRelativePath(artifactwire.DiagnosticHaepariLockIntentPath(sessionID.String(), runID.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ports.ClassifyRunSupportArtifactPath(sessionID, runID, intentRelPath); err == nil {
		t.Fatal("expected private diagnostic haepari-lock.json path rejected by ClassifyRunSupportArtifactPath")
	}

	reader := NewDiagnosticStatusReader()
	status, err := reader.ReadRunStatus(context.Background(), root, runID)
	if err != nil {
		t.Fatalf("ReadRunStatus with haepari-lock.json present: %v", err)
	}
	if status.RunID() != runID {
		t.Fatalf("unexpected run ID %s", status.RunID())
	}

	if _, err := fixture.store.Finalize(context.Background(), mustDiagnosticFinalizeRequest(t, fixture)); err != nil {
		t.Fatalf("Finalize with haepari-lock.json present: %v", err)
	}

	// Verify intent remains readable after Finalize.
	loaded, found, err := store.LoadIntent(context.Background(), root, sessionID, runID)
	if err != nil || !found || loaded.Payload.PayloadSHA256 != payload.PayloadSHA256 {
		t.Fatalf("LoadIntent after Finalize: found=%v err=%v", found, err)
	}

	observed, err := cleanupStore.Observe(context.Background())
	if err != nil {
		t.Fatalf("CleanupStore.Observe with haepari-lock.json present: %v", err)
	}
	if len(observed.Runs) != 1 || observed.Runs[0].Corrupt || observed.Runs[0].RunID != runID.String() {
		t.Fatalf("unexpected cleanup observation with haepari-lock.json: %+v", observed.Runs)
	}
}

func mustDiagnosticFinalizeRequest(t *testing.T, fixture diagnosticStoreFixture) ports.RuntimeDiagnosticFinalizeRequest {
	t.Helper()
	completed := fixture.request.StartedAt().Add(2 * time.Second)
	terminal, err := ports.NewRuntimeDiagnosticRunStatus(ports.RuntimeDiagnosticRunStatusInput{
		SessionID:      fixture.request.SessionID(),
		RunID:          fixture.request.RunID(),
		State:          domain.RunFailed,
		StartedAt:      fixture.request.StartedAt(),
		UpdatedAt:      completed,
		CompletedAt:    completed,
		HasCompletedAt: true,
		SelectedRoles:  []domain.Role{domain.RoleTesting},
		RolePathTotal:  1,
		RolePathFailed: 1,
		TerminalCause:  domain.DiagnosticCausePublicationInstallationFailed,
		TerminalPhase:  domain.DiagnosticPhasePublicationInstallation,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := ports.NewRuntimeDiagnosticFinalizeRequest(domain.RunFailed, domain.DiagnosticCausePublicationInstallationFailed, terminal)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
