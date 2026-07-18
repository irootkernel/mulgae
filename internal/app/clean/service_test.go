package clean

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type serviceClock struct{ now time.Time }

func (clock serviceClock) Now() time.Time { return clock.now }

type servicePolicySource struct {
	policy Policy
	hash   string
	err    error
}

func (source servicePolicySource) RetentionPolicy(context.Context) (Policy, string, error) {
	return source.policy.clone(), source.hash, source.err
}

type serviceValidator struct {
	calls int
	plans []CleanPlan
}

func (validator *serviceValidator) Validate(_ context.Context, id ports.AssetID, raw []byte) error {
	if id.String() != "https://kar.local/schemas/kar-clean-plan.v1.schema.json" {
		return errors.New("unexpected schema")
	}
	var plan CleanPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	if err := validatePlanCollections(plan); err != nil {
		return err
	}
	validator.calls++
	validator.plans = append(validator.plans, plan)
	return nil
}

func TestServiceDryRunPersistsSchemaValidatedReceiptAndAppliesExpectedHash(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{
		{RunID: cleanRunOne, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2026-07-10T12:00:00Z"), Committed: true, RegularFileBytes: 8},
		{RunID: cleanRunTwo, SessionID: cleanSessionTwo, Completed: true, CompletedAt: cleanTime("2026-07-13T11:59:59Z"), Committed: true, RegularFileBytes: 1},
	})
	store := &fakeCleanStore{snapshot: snapshot}
	validator := &serviceValidator{}
	service, err := NewService(serviceClock{now: snapshot.Now}, servicePolicySource{policy: snapshot.Policy, hash: snapshot.InputPolicySHA256}, validator, store)
	if err != nil {
		t.Fatal(err)
	}

	dryRun, err := service.Run(context.Background(), Request{Mode: ModeExplain})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.dryRuns) != 1 || !reflect.DeepEqual(store.dryRuns[0], dryRun.Plan) || len(dryRun.ExplainRows) != len(dryRun.Plan.RunDecisions)+1 || validator.calls != 1 {
		t.Fatalf("dry-run receipt or projection = %#v, %#v, %d", store.dryRuns, dryRun.ExplainRows, validator.calls)
	}

	applied, err := service.Run(context.Background(), Request{Mode: ModeApply, ExpectedPlanSHA256: dryRun.Plan.PlanHash})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Plan.Mode != "apply" || applied.Plan.ApplyIdentity == nil || applied.Plan.ApplyIdentity.DryRunPlanHash != dryRun.Plan.PlanHash || len(store.deleted) != 0 || validator.calls != 2 {
		t.Fatalf("apply did not use persisted expected receipt: %#v %#v %d", applied.Plan, store.deleted, validator.calls)
	}
}

func TestServiceFailsClosedWhenPolicyAuthorityIsAbsent(t *testing.T) {
	snapshot := cleanSnapshot(nil)
	store := &fakeCleanStore{snapshot: snapshot}
	validator := &serviceValidator{}
	service, err := NewService(serviceClock{now: snapshot.Now}, servicePolicySource{err: errors.New("authority unavailable")}, validator, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(context.Background(), Request{Mode: ModeDryRun}); !IsFailure(err, FailureInvalidSnapshot) || store.transactionCount != 0 || len(store.dryRuns) != 0 {
		t.Fatalf("absent authority must have no store effects: %v %#v", err, store)
	}
}
func TestServiceRejectsStalePolicyAndEpochWithoutNewApplyEffects(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{{RunID: cleanRunOne, SessionID: cleanSession, Completed: true, CompletedAt: cleanTime("2026-07-10T12:00:00Z"), Committed: true, RegularFileBytes: 8}})
	store := &fakeCleanStore{snapshot: snapshot}
	validator := &serviceValidator{}
	service, err := NewService(serviceClock{now: snapshot.Now}, servicePolicySource{policy: snapshot.Policy, hash: snapshot.InputPolicySHA256}, validator, store)
	if err != nil {
		t.Fatal(err)
	}
	dryRun, err := service.Run(context.Background(), Request{Mode: ModeDryRun})
	if err != nil {
		t.Fatal(err)
	}

	changed := snapshot.Policy
	changed.TargetBytes = 1
	policyChanged, err := NewService(serviceClock{now: snapshot.Now}, servicePolicySource{policy: changed, hash: cleanHash}, validator, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyChanged.Run(context.Background(), Request{Mode: ModeApply, ExpectedPlanSHA256: dryRun.Plan.PlanHash}); !IsFailure(err, FailureStalePlan) || len(store.deleted) != 0 {
		t.Fatalf("policy change must reject apply before deletion: %v %#v", err, store.deleted)
	}

	store.beforeSnapshot = func() { store.snapshot.StoreEpoch.Value++ }
	if _, err := service.Run(context.Background(), Request{Mode: ModeApply, ExpectedPlanSHA256: dryRun.Plan.PlanHash}); !IsFailure(err, FailureStalePlan) || len(store.deleted) != 0 {
		t.Fatalf("epoch change must reject apply before deletion: %v %#v", err, store.deleted)
	}
}

func TestServiceResumesTombstonesBeforePlanning(t *testing.T) {
	snapshot := cleanSnapshot([]RunObservation{oldRun(cleanRunOne, 1), oldRun(cleanRunTwo, 1)})
	recoveryPlan, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCleanStore{snapshot: snapshot, dryRuns: []CleanPlan{recoveryPlan}, tombstones: []Tombstone{{RunID: cleanRunOne, PlanHash: recoveryPlan.PlanHash}}}
	validator := &serviceValidator{}
	service, err := NewService(serviceClock{now: snapshot.Now}, servicePolicySource{policy: snapshot.Policy, hash: snapshot.InputPolicySHA256}, validator, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Run(context.Background(), Request{Mode: ModeDryRun})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.tombstones) != 0 || len(store.deleted) != 1 || store.deleted[0] != cleanRunOne || result.Plan.OrderedActions == nil {
		t.Fatalf("tombstone was not resumed before planning: %#v %#v", store, result.Plan)
	}
}

func TestResumeTombstonesRejectsOrphanedOrNonselectedReceipts(t *testing.T) {
	snapshot := cleanSnapshot(nil)
	nonselected, err := Plan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		dryRuns   []CleanPlan
		tombstone Tombstone
	}{
		{
			name:      "orphaned receipt",
			tombstone: Tombstone{RunID: cleanRunOne, PlanHash: cleanHash},
		},
		{
			name:      "receipt does not select run",
			dryRuns:   []CleanPlan{nonselected},
			tombstone: Tombstone{RunID: cleanRunOne, PlanHash: nonselected.PlanHash},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := &fakeCleanStore{snapshot: snapshot, dryRuns: testCase.dryRuns, tombstones: []Tombstone{testCase.tombstone}}
			if err := ResumeTombstones(context.Background(), store); !IsFailure(err, FailureInvalidSnapshot) {
				t.Fatalf("resume error = %v, want invalid snapshot", err)
			}
			if len(store.deleted) != 0 || len(store.tombstones) != 1 {
				t.Fatalf("unauthorized tombstone was deleted: %#v", store)
			}
		})
	}
}

func TestValidateDryRunReceiptRejectsSelfHashedDeleteSetOverflow(t *testing.T) {
	snapshot := cleanSnapshot(nil)
	plan := CleanPlan{
		SchemaVersion:       SchemaVersion,
		Mode:                "dry_run",
		StoreEpoch:          snapshot.StoreEpoch,
		InputPolicySHA256:   snapshot.InputPolicySHA256,
		Policy:              snapshot.Policy,
		RetentionProtection: RetentionProtection{RetainedSeedRunIDs: []string{}, TransitiveAncestorProtection: []AncestorProtection{}, GraphAnomalyComponents: []GraphAnomalyComponent{}},
		RunDecisions:        []RunDecision{},
		DeleteSets: DeleteSets{AgeDeleteSet: []DeleteSetEntry{
			{RunID: cleanRunOne, Reason: ReasonEligibleAge, RegularFileBytes: math.MaxInt64},
			{RunID: cleanRunTwo, Reason: ReasonEligibleAge, RegularFileBytes: math.MaxInt64},
			{RunID: cleanRunThree, Reason: ReasonEligibleAge, RegularFileBytes: math.MaxInt64},
		}, SizeDeleteSet: []DeleteSetEntry{}},
		OrderedActions: []OrderedAction{},
		ByteAccounting: ByteAccounting{InitialRegularFileBytes: math.MaxInt64, AgeDeleteBytes: math.MaxInt64 - 2, SizeDeleteBytes: 0, PlannedDeleteBytes: math.MaxInt64 - 2, ProjectedRegularFileBytes: 2, TargetBytes: 0, TargetReached: false},
		OutcomeReasons: []Reason{},
	}
	hash, err := PlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.PlanHash = hash
	if err := validateDryRunReceipt(plan, hash); !IsFailure(err, FailureInvalidSnapshot) {
		t.Fatalf("overflowed self-hashed receipt = %v, want invalid snapshot", err)
	}
	for _, test := range []struct {
		name       string
		tombstones []Tombstone
		request    Request
	}{
		{name: "apply", request: Request{Mode: ModeApply, ExpectedPlanSHA256: hash}},
		{name: "resume", tombstones: []Tombstone{{RunID: cleanRunOne, PlanHash: hash}}, request: Request{Mode: ModeDryRun}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeCleanStore{snapshot: snapshot, dryRuns: []CleanPlan{plan}, tombstones: append([]Tombstone(nil), test.tombstones...)}
			service, err := NewService(
				serviceClock{now: snapshot.Now},
				servicePolicySource{policy: snapshot.Policy, hash: snapshot.InputPolicySHA256},
				&serviceValidator{},
				store,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Run(context.Background(), test.request); !IsFailure(err, FailureInvalidSnapshot) {
				t.Fatalf("overflowed persisted receipt = %v, want invalid snapshot", err)
			}
			if len(store.deleted) != 0 || len(store.tombstones) != len(test.tombstones) {
				t.Fatalf("overflowed persisted receipt caused effects: tombstones=%#v deleted=%#v", store.tombstones, store.deleted)
			}
		})
	}
}
