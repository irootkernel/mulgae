//go:build darwin && arm64

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/app/clean"
	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
	"golang.org/x/sys/unix"
)

type cleanupTestClock struct{ now time.Time }

func (clock cleanupTestClock) Now() time.Time { return clock.now }

const cleanupP2CompletedAt = "2026-07-18T12:34:56.123456789Z"

func TestCleanupStoreRejectsMissingPublicationAuthority(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCleanupStore(root, nil, clean.Policy{}, cleanupTestHash("policy"), cleanupTestClock{}); err == nil {
		t.Fatal("cleanup store accepted missing publication authority")
	}
}

func TestCleanupStoreRejectsUnsafeRunWithoutFollowingIt(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243ba"
	if err := os.MkdirAll(filepath.Join(root.String(), session), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root.String(), session, run)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 1 || !snapshot.Runs[0].Corrupt || snapshot.Runs[0].RegularFileBytes != 0 {
		t.Fatalf("unsafe run observation = %#v", snapshot.Runs)
	}
}

func TestCleanupStoreRetainsMalformedSelfHashedComposite(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	child := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	paths := writeCleanupP2Fixture(t, root.String(), session, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", child, "completed", cleanupP2CompletedAt)
	if err := os.WriteFile(filepath.Join(root.String(), paths.edge), []byte(`{"schema_version":"tampered"}`), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 1 || !snapshot.Runs[0].Corrupt || snapshot.Runs[0].Committed {
		t.Fatalf("counterfeit composite was accepted: %#v", snapshot.Runs)
	}
}
func TestCleanupStoreFailsClosedForPublicationLockSymlinks(t *testing.T) {
	for _, path := range []string{"store", "store/locks"} {
		t.Run(path, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root.String(), path)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(root.String(), path)); err != nil {
				t.Fatal(err)
			}
			if _, err := newCleanupStoreForTest(t, root).Snapshot(context.Background()); err == nil {
				t.Fatalf("cleanup accepted publication lock symlink %q", path)
			}
		})
	}
}

func TestCleanupStoreUsesPublicationLockIdentity(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	if err := store.WithCleanupTransaction(context.Background(), func(clean.CleanupTransaction) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root.String(), "store", "locks", "store.lock")); err != nil {
		t.Fatalf("publication lock identity was not created: %v", err)
	}
}
func TestCleanupStoreRejectsCleanupWriteSymlinkAncestors(t *testing.T) {
	plan := cleanupPlanForTest(t)
	tombstone := clean.Tombstone{
		RunID:    "r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		PlanHash: plan.PlanHash,
	}
	cases := []struct {
		name  string
		path  string
		write func(*CleanupStore) error
	}{
		{
			name: "clean dry run",
			path: "store/clean",
			write: func(store *CleanupStore) error {
				return store.PersistDryRunPlan(context.Background(), plan)
			},
		},
		{
			name: "plans dry run",
			path: "store/clean/plans",
			write: func(store *CleanupStore) error {
				return store.PersistDryRunPlan(context.Background(), plan)
			},
		},
		{
			name: "tombstones apply",
			path: "store/clean/tombstones",
			write: func(store *CleanupStore) error {
				return store.Tombstone(context.Background(), tombstone)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(filepath.Join(root.String(), testCase.path)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root.String(), testCase.path)); err != nil {
				t.Fatal(err)
			}
			if err := testCase.write(newCleanupStoreForTest(t, root)); err == nil {
				t.Fatalf("cleanup write accepted symlinked %q", testCase.path)
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("cleanup write created files outside root through %q: %#v", testCase.path, entries)
			}
		})
	}
}

func TestCleanupStoreRecoveryRejectsTombstoneSymlinkWithoutFollowingIt(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root.String(), "store", "clean"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root.String(), "store", "clean", "tombstones")); err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	if _, err := store.Tombstones(context.Background()); err == nil {
		t.Fatal("cleanup recovery accepted symlinked tombstone directory")
	}
	if err := store.DeleteTombstoned(context.Background(), clean.Tombstone{
		RunID:    "r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		PlanHash: cleanupPlanForTest(t).PlanHash,
	}); err == nil {
		t.Fatal("cleanup deletion accepted symlinked tombstone directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("cleanup recovery touched files outside root: %#v", entries)
	}
}
func TestCleanupStoreRejectsForgedTombstoneFilename(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	tombstone := clean.Tombstone{
		RunID:    "r_019f596a-cfe4-7c9c-b82e-7149158243ba",
		PlanHash: cleanupPlanForTest(t).PlanHash,
	}
	data, err := json.Marshal(tombstone)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root.String(), cleanupTombDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	forgedName := "r_019f596a-cfe4-7c9c-b82e-7149158243bb." + strings.TrimPrefix(tombstone.PlanHash, "sha256:") + ".json"
	if err := os.WriteFile(filepath.Join(root.String(), cleanupTombDirectory, forgedName), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Tombstones(context.Background()); err == nil {
		t.Fatal("tombstone recovery accepted a filename bound to a different run")
	}
}
func TestCleanupStoreObservesTerminalP2States(t *testing.T) {
	for _, state := range []string{"completed", "degraded", "failed"} {
		t.Run(state, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
			child := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
			writeCleanupP2Fixture(t, root.String(), session, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", child, state, cleanupP2CompletedAt)
			snapshot, err := newCleanupStoreForTest(t, root).Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Runs) != 1 || snapshot.Runs[0].Corrupt || !snapshot.Runs[0].Committed || !snapshot.Runs[0].Completed || snapshot.Runs[0].CompletedAt == nil || snapshot.Runs[0].CompletedAt.Format(time.RFC3339Nano) != cleanupP2CompletedAt {
				t.Fatalf("terminal P2 observation = %#v", snapshot.Runs)
			}
		})
	}
}

func TestCleanupStoreObservesAndDeletesTerminalDiagnosticOnlyRun(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	writeCleanupDiagnosticFixture(t, root.String(), session, run, domain.RunFailed, cleanupP2CompletedAt, "")
	store := newCleanupStoreForTest(t, root)
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 1 || snapshot.Runs[0].Kind != clean.RunKindDiagnosticOnly || snapshot.Runs[0].Committed || snapshot.Runs[0].Corrupt || snapshot.Runs[0].Active || !snapshot.Runs[0].Completed || snapshot.Runs[0].RegularFileBytes == 0 {
		t.Fatalf("diagnostic-only observation = %#v", snapshot.Runs)
	}
	tombstone := clean.Tombstone{RunID: run, PlanHash: cleanupPlanForTest(t).PlanHash}
	if err := store.Tombstone(context.Background(), tombstone); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTombstoned(context.Background(), tombstone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root.String(), "diagnostics", session, run)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("diagnostic-only run still exists: %v", err)
	}
}

func TestCleanupStoreDeletesOnlyExactlyLinkedDiagnosticWithP2(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		p2URI      func(string, string) string
		wantDelete bool
	}{
		{name: "linked", p2URI: func(session, run string) string { return ".kar/" + session + "/" + run + "/manifest.json" }, wantDelete: true},
		{name: "mismatched", p2URI: func(session, run string) string { return ".kar/" + session + "/" + run + "/other.json" }, wantDelete: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, err := ports.NewAnchoredRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
			run := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
			writeCleanupP2Fixture(t, root.String(), session, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", run, "completed", cleanupP2CompletedAt)
			writeCleanupDiagnosticFixture(t, root.String(), session, run, domain.RunCompleted, cleanupP2CompletedAt, testCase.p2URI(session, run))
			store := newCleanupStoreForTest(t, root)
			snapshot, err := store.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Runs) != 1 || snapshot.Runs[0].Kind != clean.RunKindPublication || snapshot.Runs[0].Corrupt {
				t.Fatalf("P2 observation changed by diagnostic link: %#v", snapshot.Runs)
			}
			if testCase.wantDelete && snapshot.ProtectedRegularFileBytes != 0 || !testCase.wantDelete && snapshot.ProtectedRegularFileBytes == 0 {
				t.Fatalf("protected bytes = %d", snapshot.ProtectedRegularFileBytes)
			}
			tombstone := clean.Tombstone{RunID: run, PlanHash: cleanupPlanForTest(t).PlanHash}
			if err := store.Tombstone(context.Background(), tombstone); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteTombstoned(context.Background(), tombstone); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(root.String(), session, run)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("P2 run still exists: %v", err)
			}
			_, err = os.Lstat(filepath.Join(root.String(), "diagnostics", session, run))
			if testCase.wantDelete && !errors.Is(err, os.ErrNotExist) || !testCase.wantDelete && err != nil {
				t.Fatalf("diagnostic existence error = %v, want delete %t", err, testCase.wantDelete)
			}
		})
	}
}

func TestCleanupStoreKeepsMalformedLinkedDiagnosticSeparateFromHealthyP2(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	run := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	writeCleanupP2Fixture(t, root.String(), session, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", run, "completed", cleanupP2CompletedAt)
	diagnosticPath := writeCleanupDiagnosticFixture(t, root.String(), session, run, domain.RunCompleted, cleanupP2CompletedAt, ".kar/"+session+"/"+run+"/manifest.json")
	if err := os.WriteFile(filepath.Join(diagnosticPath, "status.json"), []byte(`{"schema_version":"tampered"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := newCleanupStoreForTest(t, root).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 1 || snapshot.Runs[0].Corrupt || !snapshot.Runs[0].Committed || snapshot.ProtectedRegularFileBytes == 0 {
		t.Fatalf("malformed diagnostic contaminated P2 observation: %#v protected=%d", snapshot.Runs, snapshot.ProtectedRegularFileBytes)
	}
}

func TestCleanupStoreRetainsMalformedTerminalCompletion(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	session := "s_019f596a-cf80-7c67-b265-f37053d51ccf"
	child := "r_019f596a-cfe4-7c9c-b82e-7149158243bb"
	writeCleanupP2Fixture(t, root.String(), session, "r_019f596a-cfe4-7c9c-b82e-7149158243ba", child, "completed", "not-a-time")
	snapshot, err := newCleanupStoreForTest(t, root).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 1 || !snapshot.Runs[0].Corrupt || snapshot.Runs[0].Committed || snapshot.Runs[0].Completed {
		t.Fatalf("malformed terminal completion was accepted: %#v", snapshot.Runs)
	}
}

func TestAuthoritativeCompletionRejectsNonterminalOrNoncanonicalValues(t *testing.T) {
	for _, manifest := range []string{
		`{"state":"collecting","completed_at":"2026-07-18T12:34:56Z"}`,
		`{"state":"completed"}`,
		`{"state":"completed","completed_at":"2026-07-18T12:34:56+00:00"}`,
		`{"state":"failed","completed_at":"not-a-time"}`,
	} {
		if completedAt, ok := authoritativeCompletion([]byte(manifest)); ok || completedAt != nil {
			t.Fatalf("malformed completion accepted: %s", manifest)
		}
	}
}

func cleanupPlanForTest(t *testing.T) clean.CleanPlan {
	t.Helper()
	plan, err := clean.Plan(clean.RetentionSnapshot{
		Now:               time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC),
		StoreEpoch:        clean.StoreEpoch{Value: 1, SHA256: cleanupTestHash("epoch")},
		InputPolicySHA256: cleanupTestHash("policy"),
		Policy:            clean.Policy{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestCleanupStoreExistingImmutableRetrySyncsAndVerifiesNamespace(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	relative := "store/clean/plans/retry.json"
	data := []byte(`{"receipt":"same"}`)
	if err := store.writeImmutable(relative, data); err != nil {
		t.Fatal(err)
	}

	operations := defaultSecureWriterOperations()
	syncs := 0
	operations.fsync = func(fd int) error {
		syncs++
		return unix.Fsync(fd)
	}
	cleanupUseOperations(t, store, operations)
	if err := store.writeImmutable(relative, data); err != nil {
		t.Fatalf("equal immutable retry: %v", err)
	}
	if syncs == 0 {
		t.Fatal("equal immutable retry did not sync its containing directory")
	}
}

func TestCleanupStoreImmutableInstallCollisionSyncsEqualExistingFile(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	relative := "store/clean/plans/collision.json"
	data := []byte(`{"receipt":"same"}`)

	operations := defaultSecureWriterOperations()
	syncs := 0
	operations.fsync = func(fd int) error {
		syncs++
		return unix.Fsync(fd)
	}
	operations.renameatxNp = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint32) error {
		fd, err := unix.Openat(newDirectoryFD, newName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		if err := writeAll(fd, data); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Fsync(fd); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
		return unix.RenameatxNp(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	cleanupUseOperations(t, store, operations)
	if err := store.writeImmutable(relative, data); err != nil {
		t.Fatalf("equal immutable collision: %v", err)
	}
	if syncs == 0 {
		t.Fatal("equal immutable collision did not sync its containing directory")
	}
}
func TestCleanupStoreExistingImmutableRetryRejectsDirectorySwap(t *testing.T) {
	root, err := ports.NewAnchoredRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newCleanupStoreForTest(t, root)
	relative := "store/clean/plans/retry.json"
	data := []byte(`{"receipt":"same"}`)
	if err := store.writeImmutable(relative, data); err != nil {
		t.Fatal(err)
	}

	plans := filepath.Join(root.String(), "store", "clean", "plans")
	detached := filepath.Join(root.String(), "store", "clean", "plans-detached")
	operations := defaultSecureWriterOperations()
	swapped := false
	operations.fsync = func(fd int) error {
		if !swapped {
			swapped = true
			if err := os.Rename(plans, detached); err != nil {
				return err
			}
			if err := os.Mkdir(plans, 0700); err != nil {
				return err
			}
		}
		return unix.Fsync(fd)
	}
	cleanupUseOperations(t, store, operations)
	if err := store.writeImmutable(relative, data); err == nil {
		t.Fatal("equal immutable retry accepted swapped directory namespace")
	}
	if !swapped {
		t.Fatal("directory sync hook was not reached")
	}
	if _, err := os.Lstat(filepath.Join(plans, "retry.json")); !os.IsNotExist(err) {
		t.Fatalf("swapped namespace retained immutable receipt: %v", err)
	}
}

func cleanupUseOperations(t *testing.T, store *CleanupStore, operations secureWriterOperations) {
	t.Helper()
	previous := store.operations
	store.operations = operations
	t.Cleanup(func() {
		store.operations = previous
	})
}
func newCleanupStoreForTest(t *testing.T, root ports.AnchoredRoot) *CleanupStore {
	t.Helper()
	if err := os.Chmod(root.String(), 0o700); err != nil {
		t.Fatal(err)
	}
	publication, err := NewPublicationStore(publicationStoreTestValidator{}, cleanupTestClock{}, publicationStoreTestIDs{}, NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCleanupStore(root, publication, clean.Policy{}, cleanupTestHash("policy"), cleanupTestClock{})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type cleanupP2Paths struct{ edge string }

func writeCleanupP2Fixture(t *testing.T, root, session, parent, child, state, completedAt string) cleanupP2Paths {
	t.Helper()
	review := "019f596a-cfe4-7c9c-b82e-7149158243ba"
	prefix := session + "/" + child
	edgePath := "store/lineage-edges/e_" + review + ".json"
	finalPath := prefix + "/review_" + review + ".json"
	manifestPath := prefix + "/manifest.json"
	epochPath := "store/epochs/epoch_00000000000000000001.json"
	supportIndexPath := prefix + "/support/index.json"
	stagedPath := prefix + "/publication/staged/review_" + review + ".json.tmp"
	edge := map[string]any{"schema_version": "kar-lineage-edge.v1", "edge_id": "edge-1", "child": map[string]any{"session_id": session, "run_id": child, "review_id": review}, "parent_run_id": parent}
	edgeBytes := cleanupJSON(t, edge)
	final := map[string]any{"schema_version": "kar-review-artifact.v2", "session_id": session, "run_id": child, "review_id": review, "publication_status": "committed", "immutable_lineage": map[string]any{"parent_run_id": parent, "lineage_edge_path": edgePath, "lineage_edge_sha256": cleanupTestHash(string(edgeBytes))}}
	finalBytes := cleanupJSON(t, final)
	exitCode := 0
	switch state {
	case "degraded":
		exitCode = 4
	case "failed":
		exitCode = 1
	}
	manifest := map[string]any{
		"schema_version": "kar-run-manifest.v2", "session_id": session, "run_id": child, "run_type": "review", "state": state, "sealed": true,
		"created_at": completedAt, "started_at": completedAt, "completed_at": completedAt, "kar_version": "0.1.0",
		"immutable_lineage": map[string]any{"parent_run_id": parent, "source_run_id": nil, "source_review_id": nil, "source_finding_ref": nil, "replay_mode": nil, "lineage_edge_path": edgePath, "lineage_edge_sha256": cleanupTestHash(string(edgeBytes))},
		"target":            map[string]any{"manifest_path": "target/target-manifest.json", "content_sha256": cleanupTestHash("target")},
		"selected_roles":    []string{}, "required_roles": []string{}, "attempts": []any{}, "content_verdict": "no_findings", "coverage_status": "complete",
		"publication_status": "committed", "ci_decision": "pass", "ci_reason_codes": []string{"completed"}, "persisted_journal_state": "manifest_committed",
		"durable_observation_class": "P2_COMMITTED", "publication_authority": "P2", "derived_publication_status": "committed",
		"recovery_journal":   map[string]any{"expected_staged": map[string]any{"path": stagedPath, "sha256": cleanupTestHash(string(finalBytes))}, "expected_final": map[string]any{"path": finalPath, "sha256": cleanupTestHash(string(finalBytes))}, "validated_candidate_sha256": cleanupTestHash(string(finalBytes))},
		"composite_identity": map[string]any{"manifest": map[string]any{"path": manifestPath}, "lineage_edge": map[string]any{"path": edgePath, "sha256": cleanupTestHash(string(edgeBytes))}, "epoch": map[string]any{"path": epochPath}, "support_index": map[string]any{"path": supportIndexPath, "sha256": cleanupTestHash("support-index")}},
		"recovery_action":    "reconstruct_completed_status", "final_review": map[string]any{"review_id": review, "path": finalPath, "sha256": cleanupTestHash(string(finalBytes))},
		"failures": []any{}, "warnings": []string{}, "exit_code": exitCode,
	}
	manifestBytes := cleanupJSON(t, manifest)
	epoch := map[string]any{"schema_version": "kar-publication-epoch.v1", "store_epoch": 1, "manifest": map[string]any{"path": manifestPath, "sha256": cleanupTestHash(string(manifestBytes))}, "lineage_edge": map[string]any{"path": edgePath, "sha256": cleanupTestHash(string(edgeBytes))}, "final_review": map[string]any{"path": finalPath, "sha256": cleanupTestHash(string(finalBytes))}}
	for path, data := range map[string][]byte{edgePath: edgeBytes, finalPath: finalBytes, manifestPath: manifestBytes, epochPath: cleanupJSON(t, epoch)} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return cleanupP2Paths{edge: edgePath}
}

func writeCleanupDiagnosticFixture(t *testing.T, root, session, run string, state domain.RunState, completedAt, p2URI string) string {
	t.Helper()
	status := runtimeDiagnosticRunStatusWire{
		SchemaVersion:        ports.RuntimeDiagnosticRunStatusSchema,
		SessionID:            session,
		RunID:                run,
		State:                state,
		StartedAt:            completedAt,
		UpdatedAt:            completedAt,
		SelectedRoles:        []domain.Role{},
		LastSequence:         1,
		P2URI:                p2URI,
		DiagnosticOnly:       true,
		PublicationAuthority: false,
	}
	switch state {
	case domain.RunCompleted, domain.RunDegraded, domain.RunFailed, domain.RunCancelled:
		status.CompletedAt = completedAt
		status.TerminalCause = domain.DiagnosticCauseProviderExecutionFailed
	}
	runPath := filepath.Join(root, "diagnostics", session, run)
	if err := os.MkdirAll(runPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"status.json":       cleanupJSON(t, status),
		"kar-runtime.jsonl": []byte("{}\n"),
	} {
		if err := os.WriteFile(filepath.Join(runPath, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return runPath
}

func cleanupJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cleanupTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
