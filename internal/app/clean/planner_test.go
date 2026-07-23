package clean

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

const (
	cleanSession    = "s_018f4b76-2dbd-7000-8000-000000000001"
	cleanSessionTwo = "s_018f4b76-2dbd-7000-8000-000000000002"
	cleanRunOne     = "r_018f4b76-2dbd-7000-8000-000000000001"
	cleanRunTwo     = "r_018f4b76-2dbd-7000-8000-000000000002"
	cleanRunThree   = "r_018f4b76-2dbd-7000-8000-000000000003"
	cleanRunFour    = "r_018f4b76-2dbd-7000-8000-000000000004"
	cleanRunFive    = "r_018f4b76-2dbd-7000-8000-000000000005"
	cleanHash       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cleanHashTwo    = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func cleanTime(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return &parsed
}

func cleanSnapshot(runs []RunObservation) RetentionSnapshot {
	return RetentionSnapshot{
		Now:               time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		StoreEpoch:        StoreEpoch{Value: 4, SHA256: cleanHash},
		InputPolicySHA256: cleanHashTwo,
		Policy:            Policy{RetentionAgeSeconds: 1, MinAgeForSizeSeconds: 0, TargetBytes: 0},
		Runs:              runs,
	}
}

func oldRun(id string, bytes int64) RunObservation {
	return RunObservation{RunID: id, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2020-01-01T00:00:00Z"), Committed: true, RegularFileBytes: bytes}
}

func TestPlanNormalizesCollectionsAndIsPermutationInvariant(t *testing.T) {
	runs := []RunObservation{oldRun(cleanRunOne, 1), oldRun(cleanRunTwo, 2), oldRun(cleanRunThree, 3)}
	snapshot := cleanSnapshot(runs)
	first, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Runs = []RunObservation{runs[2], runs[0], runs[1]}
	second, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanHash != second.PlanHash {
		t.Fatalf("permutation changed hash: %s != %s", first.PlanHash, second.PlanHash)
	}
	if first.Policy.ExplicitKeepRunIDs == nil || first.RetentionProtection.RetainedSeedRunIDs == nil ||
		first.RetentionProtection.TransitiveAncestorProtection == nil || first.RetentionProtection.GraphAnomalyComponents == nil ||
		first.RunDecisions == nil || first.DeleteSets.AgeDeleteSet == nil || first.DeleteSets.SizeDeleteSet == nil ||
		first.OrderedActions == nil || first.OutcomeReasons == nil {
		t.Fatalf("plan has null collection: %#v", first)
	}
}

func TestPlanRetainsAuthoritySeparationForDiagnosticOnlyRuns(t *testing.T) {
	diagnostic := oldRun(cleanRunOne, 5)
	diagnostic.Kind = RunKindDiagnosticOnly
	diagnostic.Committed = false
	newestP2 := oldRun(cleanRunTwo, 3)
	newestP2.CompletedAt = cleanTime("2026-07-13T11:59:59Z")
	snapshot := cleanSnapshot([]RunObservation{diagnostic, newestP2})
	snapshot.ProtectedRegularFileBytes = 7
	plan, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DeleteSets.AgeDeleteSet) != 1 || plan.DeleteSets.AgeDeleteSet[0].RunID != cleanRunOne || plan.DeleteSets.AgeDeleteSet[0].RegularFileBytes != 5 {
		t.Fatalf("diagnostic-only retention selection = %#v", plan.DeleteSets.AgeDeleteSet)
	}
	if plan.ByteAccounting.InitialRegularFileBytes != 15 || plan.ByteAccounting.PlannedDeleteBytes != 5 || plan.ByteAccounting.ProjectedRegularFileBytes != 10 {
		t.Fatalf("diagnostic byte accounting = %#v", plan.ByteAccounting)
	}

	diagnostic.DiagnosticProtected = true
	protectedPlan, err := Plan(cleanSnapshot([]RunObservation{diagnostic, newestP2}))
	if err != nil {
		t.Fatal(err)
	}
	if len(protectedPlan.DeleteSets.AgeDeleteSet) != 0 || !containsReason(protectedPlan.RunDecisions, cleanRunOne, ReasonUncommitted) {
		t.Fatalf("mismatched diagnostic was not protected: %#v", protectedPlan.RunDecisions)
	}
}

func containsReason(decisions []RunDecision, runID string, reason Reason) bool {
	for _, decision := range decisions {
		if decision.RunID != runID {
			continue
		}
		for _, candidate := range decision.Reasons {
			if candidate == reason {
				return true
			}
		}
	}
	return false
}

func TestExecuteApplyRejectsForgedSelfHashedPlanWithoutReceipt(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), RunObservation{RunID: cleanRunTwo, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2026-07-13T11:59:59Z"), Committed: true, RegularFileBytes: 1}})
	dryRun, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := ApplyPlan(dryRun)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCleanStore{snapshot: snapshot}
	if err := ExecuteApply(context.Background(), store, apply); !IsFailure(err, FailureStalePlan) || len(store.tombstones) != 0 {
		t.Fatalf("forged receipt authorization = %v, %#v", err, store)
	}
}
func TestPlanRejectsUnknownKeepAndByteOverflow(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1)})
	snapshot.Policy.ExplicitKeepRunIDs = []string{cleanRunTwo}
	if _, err := Plan(snapshot); !IsFailure(err, FailureInvalidSnapshot) {
		t.Fatalf("unknown keep = %v", err)
	}
	snapshot.Policy.ExplicitKeepRunIDs = nil
	snapshot.Runs = []RunObservation{oldRun(cleanRunOne, math.MaxInt64), oldRun(cleanRunTwo, 1)}
	if _, err := Plan(snapshot); !IsFailure(err, FailureInvalidSnapshot) {
		t.Fatalf("overflow = %v", err)
	}
}

func TestPlanProtectsGraphAnomalies(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), oldRun(cleanRunTwo, 1), oldRun(cleanRunThree, 1)})
	snapshot.Edges = []LineageEdgeObservation{
		{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunTwo, EdgePath: "edges/one", SHA256: cleanHash}, Valid: true},
		{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunThree, ChildRunID: cleanRunTwo, EdgePath: "edges/two", SHA256: cleanHashTwo}, Valid: true},
	}
	plan, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.OrderedActions) != 0 {
		t.Fatalf("multiple-parent graph scheduled deletion: %#v", plan.OrderedActions)
	}
	snapshot.Edges = []LineageEdgeObservation{{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunOne, EdgePath: "edges/self", SHA256: cleanHash}, Valid: true}}
	plan, err = Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.DeleteSets.AgeDeleteSet) != 1 || plan.DeleteSets.AgeDeleteSet[0].RunID != cleanRunTwo {
		t.Fatalf("unrelated healthy run was not selected: %#v", plan.DeleteSets.AgeDeleteSet)
	}
}
func TestPlanScopesGraphAnomalyProtectionToAffectedComponent(t *testing.T) {
	healthyOld := oldRun(cleanRunThree, 1)
	healthyOld.SessionID = cleanSessionTwo
	healthyNewest := oldRun(cleanRunFour, 1)
	healthyNewest.SessionID = cleanSessionTwo
	healthyNewest.CompletedAt = cleanTime("2026-07-13T11:59:59Z")

	cases := []struct {
		name         string
		edges        []LineageEdgeObservation
		affectedRuns []string
	}{
		{
			name: "disconnected self edge",
			edges: []LineageEdgeObservation{
				{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunTwo, EdgePath: "edges/one-two", SHA256: cleanHash}, Valid: true},
				{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunOne, EdgePath: "edges/self", SHA256: cleanHashTwo}, Valid: true},
			},
			affectedRuns: []string{cleanRunOne, cleanRunTwo},
		},
		{
			name: "cycle",
			edges: []LineageEdgeObservation{
				{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunTwo, EdgePath: "edges/one-two", SHA256: cleanHash}, Valid: true},
				{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunTwo, ChildRunID: cleanRunOne, EdgePath: "edges/two-one", SHA256: cleanHashTwo}, Valid: true},
			},
			affectedRuns: []string{cleanRunOne, cleanRunTwo},
		},
		{
			name: "dangling child",
			edges: []LineageEdgeObservation{
				{LineageEdgeRef: LineageEdgeRef{ParentRunID: cleanRunOne, ChildRunID: cleanRunFive, EdgePath: "edges/dangling", SHA256: cleanHash}, Valid: true},
			},
			affectedRuns: []string{cleanRunOne},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), oldRun(cleanRunTwo, 1), healthyOld, healthyNewest})
			snapshot.Edges = test.edges
			plan, err := Plan(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.RetentionProtection.GraphAnomalyComponents) != 1 {
				t.Fatalf("anomaly components = %#v", plan.RetentionProtection.GraphAnomalyComponents)
			}
			component := plan.RetentionProtection.GraphAnomalyComponents[0]
			if test.name == "dangling child" {
				if !sameCleanStrings(component.AffectedRunIDs, []string{cleanRunOne, cleanRunTwo, cleanRunThree, cleanRunFour}) || len(plan.OrderedActions) != 0 {
					t.Fatalf("dangling lineage must protect the store: %#v", plan)
				}
				return
			}
			if !sameCleanStrings(component.AffectedRunIDs, test.affectedRuns) {
				t.Fatalf("affected runs = %#v; want %#v", component.AffectedRunIDs, test.affectedRuns)
			}
			if len(plan.DeleteSets.AgeDeleteSet) != 1 || plan.DeleteSets.AgeDeleteSet[0].RunID != cleanRunThree {
				t.Fatalf("unrelated healthy run was not selected: %#v", plan.DeleteSets.AgeDeleteSet)
			}
		})
	}
}

func sameCleanStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestExecuteApplyHoldsOneTransactionAndRejectsFreshEpochOrHash(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), RunObservation{RunID: cleanRunTwo, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2026-07-13T11:59:59Z"), Committed: true, RegularFileBytes: 1}})
	dryRun, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := ApplyPlan(dryRun)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCleanStore{snapshot: snapshot, dryRuns: []CleanPlan{dryRun}}
	store.beforeSnapshot = func() { store.snapshot.StoreEpoch.Value++ }
	if err := ExecuteApply(context.Background(), store, apply); !IsFailure(err, FailureStalePlan) {
		t.Fatalf("epoch race = %v", err)
	}
	if store.transactionCount != 1 || len(store.deleted) != 0 {
		t.Fatalf("transaction scope = %#v", store)
	}
	store.snapshot = snapshot
	store.beforeSnapshot = func() { store.snapshot.InputPolicySHA256 = cleanHash }
	if err := ExecuteApply(context.Background(), store, apply); !IsFailure(err, FailureStalePlan) {
		t.Fatalf("policy hash race = %v", err)
	}
	store.beforeSnapshot = nil
	apply.PlanHash = cleanHash
	if err := ExecuteApply(context.Background(), store, apply); !IsFailure(err, FailureStalePlan) {
		t.Fatalf("stale plan hash = %v", err)
	}
}

func TestExecuteApplyRecoversDurableTombstone(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), RunObservation{RunID: cleanRunTwo, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2026-07-13T11:59:59Z"), Committed: true, RegularFileBytes: 1}})
	dryRun, _ := Plan(snapshot)
	apply, _ := ApplyPlan(dryRun)
	store := &fakeCleanStore{snapshot: snapshot, dryRuns: []CleanPlan{dryRun}, failDelete: true}
	if err := ExecuteApply(context.Background(), store, apply); err == nil {
		t.Fatal("expected deletion fault")
	}
	store.failDelete = false
	if err := ResumeTombstones(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if len(store.tombstones) != 0 || len(store.deleted) != 1 {
		t.Fatalf("recovery = %#v", store)
	}
}

type fakeCleanStore struct {
	mu               sync.Mutex
	snapshot         RetentionSnapshot
	dryRuns          []CleanPlan
	tombstones       []Tombstone
	deleted          []string
	failDelete       bool
	beforeSnapshot   func()
	transactionCount int
}

func (store *fakeCleanStore) WithCleanupTransaction(_ context.Context, callback func(CleanupTransaction) error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.transactionCount++
	return callback(store)
}
func (store *fakeCleanStore) Snapshot(context.Context) (RetentionSnapshot, error) {
	if store.beforeSnapshot != nil {
		store.beforeSnapshot()
	}
	return store.snapshot.Clone(), nil
}
func (store *fakeCleanStore) DryRunPlan(_ context.Context, hash string) (CleanPlan, error) {
	for _, plan := range store.dryRuns {
		if plan.PlanHash == hash {
			return plan.Clone(), nil
		}
	}
	return CleanPlan{}, failure(FailureStalePlan, "dry-run receipt not found", nil)
}
func (store *fakeCleanStore) PersistDryRunPlan(_ context.Context, plan CleanPlan) error {
	store.dryRuns = append(store.dryRuns, plan.Clone())
	return nil
}
func (store *fakeCleanStore) Tombstones(context.Context) ([]Tombstone, error) {
	return append([]Tombstone(nil), store.tombstones...), nil
}
func (store *fakeCleanStore) Tombstone(_ context.Context, tombstone Tombstone) error {
	store.tombstones = append(store.tombstones, tombstone)
	return nil
}
func (store *fakeCleanStore) DeleteTombstoned(_ context.Context, tombstone Tombstone) error {
	if store.failDelete {
		return context.DeadlineExceeded
	}
	for index, current := range store.tombstones {
		if current == tombstone {
			store.tombstones = append(store.tombstones[:index], store.tombstones[index+1:]...)
			store.deleted = append(store.deleted, tombstone.RunID)
			return nil
		}
	}
	return failure(FailureTombstone, "missing tombstone", nil)
}
