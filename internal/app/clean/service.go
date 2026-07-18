package clean

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

// Tombstone is the durable authorization to remove one run. A deletion may be
// retried only from this record; an unjournaled partial directory is never
// inferred to be eligible for deletion.
type Tombstone struct {
	RunID    string
	PlanHash string
}

// CleanupTransaction is the exclusive artifact-store scope for a cleanup
// observation and its destructive effects.
type CleanupTransaction interface {
	Snapshot(context.Context) (RetentionSnapshot, error)
	DryRunPlan(context.Context, string) (CleanPlan, error)
	PersistDryRunPlan(context.Context, CleanPlan) error
	Tombstones(context.Context) ([]Tombstone, error)
	Tombstone(context.Context, Tombstone) error
	DeleteTombstoned(context.Context, Tombstone) error
}

// ApplyStore supplies durable deletion mechanics. WithCleanupTransaction MUST
// hold one exclusive store lock for the complete callback, including snapshot,
// validation, tombstone commits, and deletion.
type ApplyStore interface {
	WithCleanupTransaction(context.Context, func(CleanupTransaction) error) error
}

// RetentionPolicySource is the sole authority for cleanup retention policy.
// Implementations must return the exact resolved policy and its canonical digest.
type RetentionPolicySource interface {
	RetentionPolicy(context.Context) (Policy, string, error)
}

// SchemaValidator validates a candidate plan against the embedded clean-plan
// contract before it becomes a durable receipt.
type SchemaValidator interface {
	Validate(context.Context, ports.AssetID, []byte) error
}

// Mode selects a command-facing cleanup operation.
type Mode string

const (
	ModeDryRun  Mode = "dry_run"
	ModeExplain Mode = "explain"
	ModeApply   Mode = "apply"
)

// Request is a cleanup command selection. ExpectedPlanSHA256 is required only
// for ModeApply.
type Request struct {
	Mode               Mode
	ExpectedPlanSHA256 string
}

// Result is the immutable plan projection and optional deterministic explain rows.
type Result struct {
	Plan        CleanPlan
	ExplainRows []string
}

// Service composes explicit policy authority, a fixed clock, schema validation,
// and the durable cleanup store. It has no policy defaults or provider dependency.
type Service struct {
	clock     ports.Clock
	policy    RetentionPolicySource
	validator SchemaValidator
	store     ApplyStore
	schemaID  ports.AssetID
}

// NewService constructs a cleanup service with only explicit authorities.
func NewService(clock ports.Clock, policy RetentionPolicySource, validator SchemaValidator, store ApplyStore) (*Service, error) {
	if nilCleanDependency(clock) || nilCleanDependency(policy) || nilCleanDependency(validator) || nilCleanDependency(store) {
		return nil, errors.New("clean service: clock, policy source, schema validator, and apply store are required")
	}
	schemaID, err := ports.ParseAssetID("https://kar.local/schemas/kar-clean-plan.v1.schema.json")
	if err != nil {
		return nil, fmt.Errorf("clean service: clean plan schema ID: %w", err)
	}
	return &Service{clock: clock, policy: policy, validator: validator, store: store, schemaID: schemaID}, nil
}

// Run executes one command-facing cleanup operation. It always resumes durable
// tombstones before observing a new dry-run plan or executing a hash-bound apply.
func (service *Service) Run(ctx context.Context, request Request) (Result, error) {
	if service == nil || nilCleanDependency(service.clock) || nilCleanDependency(service.policy) || nilCleanDependency(service.validator) || nilCleanDependency(service.store) {
		return Result{}, failure(FailureInvalidSnapshot, "cleanup service is uninitialized", nil)
	}
	if ctx == nil {
		return Result{}, failure(FailureInvalidSnapshot, "cleanup context is required", nil)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	policy, policyHash, err := service.policy.RetentionPolicy(ctx)
	if err != nil {
		return Result{}, failure(FailureInvalidSnapshot, "resolve explicit retention policy", err)
	}
	if err := validatePolicyAuthority(policy, policyHash); err != nil {
		return Result{}, err
	}
	if err := ResumeTombstones(ctx, service.store); err != nil {
		return Result{}, err
	}

	switch request.Mode {
	case ModeDryRun, ModeExplain:
		if request.ExpectedPlanSHA256 != "" {
			return Result{}, failure(FailureInvalidSnapshot, "expected plan hash is only valid for apply", nil)
		}
		return service.dryRun(ctx, policy, policyHash, request.Mode == ModeExplain)
	case ModeApply:
		if !canonicalSHA256(request.ExpectedPlanSHA256) {
			return Result{}, failure(FailureInvalidSnapshot, "expected dry-run plan hash is required and canonical", nil)
		}
		return service.apply(ctx, policy, policyHash, request.ExpectedPlanSHA256)
	default:
		return Result{}, failure(FailureInvalidSnapshot, "unsupported cleanup mode", nil)
	}
}

func (service *Service) dryRun(ctx context.Context, policy Policy, policyHash string, explain bool) (Result, error) {
	var result Result
	err := service.store.WithCleanupTransaction(ctx, func(transaction CleanupTransaction) error {
		snapshot, err := transaction.Snapshot(ctx)
		if err != nil {
			return failure(FailureInvalidSnapshot, "observe cleanup store", err)
		}
		snapshot.Now = service.clock.Now().UTC()
		snapshot.Policy = policy.clone()
		snapshot.InputPolicySHA256 = policyHash
		plan, err := Plan(snapshot)
		if err != nil {
			return err
		}
		if err := service.validatePlan(ctx, plan); err != nil {
			return err
		}
		if err := transaction.PersistDryRunPlan(ctx, plan.Clone()); err != nil {
			return failure(FailureInvalidSnapshot, "persist immutable dry-run receipt", err)
		}
		result.Plan = plan.Clone()
		if explain {
			result.ExplainRows = explainRows(plan)
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (service *Service) apply(ctx context.Context, policy Policy, policyHash, expectedHash string) (Result, error) {
	var receipt CleanPlan
	if err := service.store.WithCleanupTransaction(ctx, func(transaction CleanupTransaction) error {
		loaded, err := transaction.DryRunPlan(ctx, expectedHash)
		if err != nil {
			return failure(FailureStalePlan, "load immutable dry-run receipt", err)
		}
		if err := validateDryRunReceipt(loaded, expectedHash); err != nil {
			return err
		}
		if loaded.InputPolicySHA256 != policyHash || !reflect.DeepEqual(loaded.Policy, policy) {
			return failure(FailureStalePlan, "resolved retention policy changed", nil)
		}
		receipt = loaded.Clone()
		return nil
	}); err != nil {
		return Result{}, err
	}
	apply, err := ApplyPlan(receipt)
	if err != nil {
		return Result{}, err
	}
	if err := service.validatePlan(ctx, apply); err != nil {
		return Result{}, err
	}
	if err := ExecuteApply(ctx, service.store, apply); err != nil {
		return Result{}, err
	}
	return Result{Plan: apply.Clone()}, nil
}

func (service *Service) validatePlan(ctx context.Context, plan CleanPlan) error {
	if err := validatePlanCollections(plan); err != nil {
		return err
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return failure(FailureInvalidSnapshot, "marshal clean plan", err)
	}
	if err := service.validator.Validate(ctx, service.schemaID, append([]byte(nil), raw...)); err != nil {
		return failure(FailureInvalidSnapshot, "validate clean plan schema", err)
	}
	return nil
}

func validatePolicyAuthority(policy Policy, policyHash string) error {
	if !canonicalSHA256(policyHash) || policy.RetentionAgeSeconds < 0 || policy.MinAgeForSizeSeconds < 0 || policy.TargetBytes < 0 || policy.ExplicitKeepRunIDs == nil {
		return failure(FailureInvalidSnapshot, "retention policy authority is invalid", nil)
	}
	seen := make(map[string]struct{}, len(policy.ExplicitKeepRunIDs))
	for _, id := range policy.ExplicitKeepRunIDs {
		if !canonicalRunID(id) {
			return failure(FailureInvalidSnapshot, "retention policy explicit keep run ID is invalid", nil)
		}
		if _, duplicate := seen[id]; duplicate {
			return failure(FailureInvalidSnapshot, "retention policy explicit keep run ID is duplicated", nil)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func explainRows(plan CleanPlan) []string {
	rows := make([]string, 1, len(plan.RunDecisions)+1)
	rows[0] = "plan_hash: " + plan.PlanHash
	for _, decision := range plan.RunDecisions {
		reasons := make([]string, len(decision.Reasons))
		for index, reason := range decision.Reasons {
			reasons[index] = string(reason)
		}
		rows = append(rows, decision.RunID+": "+decision.Decision+" ("+fmt.Sprintf("%v", reasons)+")")
	}
	return rows
}

func nilCleanDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

// ExecuteApply verifies an exact dry-run identity against a fresh observation,
// then executes only the listed tombstone/delete pairs. It never recomputes a
// retention plan.
func ExecuteApply(ctx context.Context, store ApplyStore, apply CleanPlan) error {
	if store == nil {
		return failure(FailureInvalidSnapshot, "apply store is required", nil)
	}
	if err := validateApplyPlan(apply); err != nil {
		return err
	}
	return store.WithCleanupTransaction(ctx, func(transaction CleanupTransaction) error {
		receipt, err := transaction.DryRunPlan(ctx, apply.ApplyIdentity.DryRunPlanHash)
		if err != nil {
			return failure(FailureStalePlan, "load immutable dry-run receipt", err)
		}
		if err := validateDryRunReceipt(receipt, apply.ApplyIdentity.DryRunPlanHash); err != nil {
			return err
		}
		expected, err := ApplyPlan(receipt)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(apply, expected) {
			return failure(FailureStalePlan, "apply plan does not match immutable dry-run receipt", nil)
		}
		current, err := transaction.Snapshot(ctx)
		if err != nil {
			return failure(FailureInvalidSnapshot, "observe store for apply", err)
		}
		if err := validateSnapshotIdentity(current); err != nil {
			return err
		}
		if current.StoreEpoch != apply.ApplyIdentity.ExpectedStoreEpoch || current.InputPolicySHA256 != apply.ApplyIdentity.ExpectedInputPolicySHA256 {
			return failure(FailureStalePlan, "store epoch or input policy changed", nil)
		}
		for _, action := range apply.OrderedActions {
			if err := ctx.Err(); err != nil {
				return err
			}
			tombstone := Tombstone{RunID: action.RunID, PlanHash: apply.ApplyIdentity.DryRunPlanHash}
			switch action.Action {
			case "tombstone":
				if err := transaction.Tombstone(ctx, tombstone); err != nil {
					return failure(FailureTombstone, "commit tombstone for "+action.RunID, err)
				}
			case "delete":
				if err := transaction.DeleteTombstoned(ctx, tombstone); err != nil {
					return failure(FailureTombstone, "delete tombstoned run "+action.RunID, err)
				}
			default:
				return failure(FailureInvalidSnapshot, "unsupported apply action", nil)
			}
		}
		return nil
	})
}

// ResumeTombstones completes durable deletions after an interrupted apply.
// Tombstones are sorted to make recovery deterministic and are not replanned.
func ResumeTombstones(ctx context.Context, store ApplyStore) error {
	if store == nil {
		return failure(FailureInvalidSnapshot, "apply store is required", nil)
	}
	return store.WithCleanupTransaction(ctx, func(transaction CleanupTransaction) error {
		tombstones, err := transaction.Tombstones(ctx)
		if err != nil {
			return failure(FailureInvalidSnapshot, "observe tombstones", err)
		}
		sort.Slice(tombstones, func(i, j int) bool {
			if tombstones[i].PlanHash != tombstones[j].PlanHash {
				return tombstones[i].PlanHash < tombstones[j].PlanHash
			}
			return tombstones[i].RunID < tombstones[j].RunID
		})
		seen := make(map[Tombstone]bool, len(tombstones))
		for _, tombstone := range tombstones {
			if !canonicalRunID(tombstone.RunID) || !canonicalSHA256(tombstone.PlanHash) {
				return failure(FailureInvalidSnapshot, "invalid durable tombstone", nil)
			}
			if seen[tombstone] {
				return failure(FailureInvalidSnapshot, "duplicate durable tombstone", nil)
			}
			seen[tombstone] = true
			if err := ctx.Err(); err != nil {
				return err
			}
			receipt, err := transaction.DryRunPlan(ctx, tombstone.PlanHash)
			if err != nil {
				return failure(FailureInvalidSnapshot, "load tombstone dry-run receipt", err)
			}
			if err := validateDryRunReceipt(receipt, tombstone.PlanHash); err != nil {
				return err
			}
			if !tombstoneSelectsRun(receipt, tombstone.RunID) {
				return failure(FailureInvalidSnapshot, "durable tombstone does not select run for deletion", nil)
			}
			if err := transaction.DeleteTombstoned(ctx, tombstone); err != nil {
				return failure(FailureTombstone, "resume tombstoned run "+tombstone.RunID, err)
			}
		}
		return nil
	})
}
func tombstoneSelectsRun(receipt CleanPlan, runID string) bool {
	for index := 0; index+1 < len(receipt.OrderedActions); index += 2 {
		tombstone, deletion := receipt.OrderedActions[index], receipt.OrderedActions[index+1]
		if tombstone.RunID == runID &&
			tombstone.Action == "tombstone" &&
			deletion.Action == "delete" &&
			deletion.RunID == runID &&
			tombstone.Sequence+1 == deletion.Sequence &&
			tombstone.Phase == deletion.Phase &&
			tombstone.Reason == deletion.Reason {
			return true
		}
	}
	return false
}

func validatePlanCollections(plan CleanPlan) error {
	if plan.Policy.ExplicitKeepRunIDs == nil || plan.RetentionProtection.RetainedSeedRunIDs == nil ||
		plan.RetentionProtection.TransitiveAncestorProtection == nil || plan.RetentionProtection.GraphAnomalyComponents == nil ||
		plan.RunDecisions == nil || plan.DeleteSets.AgeDeleteSet == nil || plan.DeleteSets.SizeDeleteSet == nil ||
		plan.OrderedActions == nil || plan.OutcomeReasons == nil {
		return failure(FailureInvalidSnapshot, "plan collections must be arrays", nil)
	}
	for _, protection := range plan.RetentionProtection.TransitiveAncestorProtection {
		if protection.LineageEdgeRefs == nil {
			return failure(FailureInvalidSnapshot, "ancestor lineage references must be an array", nil)
		}
	}
	for _, component := range plan.RetentionProtection.GraphAnomalyComponents {
		if component.AffectedRunIDs == nil || component.LineageEdgeRefs == nil {
			return failure(FailureInvalidSnapshot, "graph anomaly collections must be arrays", nil)
		}
	}
	for _, decision := range plan.RunDecisions {
		if decision.Reasons == nil {
			return failure(FailureInvalidSnapshot, "decision reasons must be an array", nil)
		}
	}
	return nil
}

func validateDryRunReceipt(receipt CleanPlan, expectedHash string) error {
	if receipt.SchemaVersion != SchemaVersion || receipt.Mode != "dry_run" || receipt.ApplyIdentity != nil {
		return failure(FailureInvalidSnapshot, "invalid immutable dry-run receipt", nil)
	}
	if err := validatePlanCollections(receipt); err != nil {
		return err
	}
	if err := validateSnapshotIdentity(RetentionSnapshot{StoreEpoch: receipt.StoreEpoch, InputPolicySHA256: receipt.InputPolicySHA256}); err != nil {
		return err
	}
	computed, err := PlanHash(receipt)
	if err != nil || receipt.PlanHash != expectedHash || computed != expectedHash {
		return failure(FailureStalePlan, "immutable dry-run receipt hash does not match", err)
	}
	accounting := receipt.ByteAccounting
	if accounting.InitialRegularFileBytes < 0 || accounting.AgeDeleteBytes < 0 ||
		accounting.SizeDeleteBytes < 0 || accounting.PlannedDeleteBytes < 0 ||
		accounting.ProjectedRegularFileBytes < 0 || accounting.TargetBytes < 0 {
		return failure(FailureInvalidSnapshot, "negative dry-run byte accounting", nil)
	}
	plannedDeleteBytes, ok := checkedAdd(accounting.AgeDeleteBytes, accounting.SizeDeleteBytes)
	if !ok || accounting.PlannedDeleteBytes != plannedDeleteBytes ||
		accounting.PlannedDeleteBytes > accounting.InitialRegularFileBytes ||
		receipt.Policy.TargetBytes != accounting.TargetBytes ||
		accounting.ProjectedRegularFileBytes != accounting.InitialRegularFileBytes-accounting.PlannedDeleteBytes ||
		accounting.TargetReached != (accounting.ProjectedRegularFileBytes <= accounting.TargetBytes) {
		return failure(FailureInvalidSnapshot, "invalid dry-run byte accounting", nil)
	}
	entries := map[string]DeleteSetEntry{}
	var ageBytes, sizeBytes int64
	for _, set := range []struct {
		entries []DeleteSetEntry
		reason  Reason
		bytes   *int64
	}{{receipt.DeleteSets.AgeDeleteSet, ReasonEligibleAge, &ageBytes}, {receipt.DeleteSets.SizeDeleteSet, ReasonEligibleSize, &sizeBytes}} {
		for _, entry := range set.entries {
			if !canonicalRunID(entry.RunID) || entry.Reason != set.reason || entry.RegularFileBytes < 0 {
				return failure(FailureInvalidSnapshot, "invalid dry-run delete set", nil)
			}
			if _, duplicate := entries[entry.RunID]; duplicate {
				return failure(FailureInvalidSnapshot, "duplicate dry-run delete entry", nil)
			}
			entries[entry.RunID] = entry
			total, ok := checkedAdd(*set.bytes, entry.RegularFileBytes)
			if !ok {
				return failure(FailureInvalidSnapshot, "dry-run delete set byte total overflows int64", nil)
			}
			*set.bytes = total
		}
	}
	if ageBytes != receipt.ByteAccounting.AgeDeleteBytes || sizeBytes != receipt.ByteAccounting.SizeDeleteBytes {
		return failure(FailureInvalidSnapshot, "delete sets do not match byte accounting", nil)
	}
	decisions := map[string]RunDecision{}
	for _, decision := range receipt.RunDecisions {
		if !canonicalRunID(decision.RunID) || len(decision.Reasons) == 0 {
			return failure(FailureInvalidSnapshot, "invalid dry-run decision", nil)
		}
		if _, duplicate := decisions[decision.RunID]; duplicate {
			return failure(FailureInvalidSnapshot, "duplicate dry-run decision", nil)
		}
		decisions[decision.RunID] = decision
	}
	if len(receipt.OrderedActions) != len(entries)*2 {
		return failure(FailureInvalidSnapshot, "actions do not match delete sets", nil)
	}
	selected := make(map[string]bool, len(entries))
	for index := 0; index < len(receipt.OrderedActions); index += 2 {
		tombstone, deletion := receipt.OrderedActions[index], receipt.OrderedActions[index+1]
		entry, exists := entries[tombstone.RunID]
		expectedReason := ReasonDeletedAge
		expectedDecision := "selected_age"
		expectedPhase := "age"
		if entry.Reason == ReasonEligibleSize {
			expectedReason = ReasonDeletedSize
			expectedDecision = "selected_size"
			expectedPhase = "size"
		}
		decision := decisions[tombstone.RunID]
		if !exists || tombstone.Sequence != index+1 || deletion.Sequence != index+2 ||
			tombstone.Action != "tombstone" || deletion.Action != "delete" ||
			tombstone.RunID != deletion.RunID || tombstone.Phase != expectedPhase || deletion.Phase != expectedPhase ||
			tombstone.Reason != expectedReason || deletion.Reason != expectedReason ||
			deletion.BytesReleased != entry.RegularFileBytes || decision.Decision != expectedDecision {
			return failure(FailureInvalidSnapshot, fmt.Sprintf("invalid dry-run action pair at sequence %d", tombstone.Sequence), nil)
		}
		delete(entries, tombstone.RunID)
		selected[tombstone.RunID] = true
	}
	if len(entries) != 0 {
		return failure(FailureInvalidSnapshot, "delete set missing action", nil)
	}
	for id, decision := range decisions {
		if (decision.Decision == "selected_age" || decision.Decision == "selected_size") != selected[id] {
			return failure(FailureInvalidSnapshot, "decisions do not match delete sets", nil)
		}
	}
	return nil
}

func validateApplyPlan(apply CleanPlan) error {
	if apply.Mode != "apply" || apply.ApplyIdentity == nil {
		return failure(FailureInvalidSnapshot, "apply identity is required", nil)
	}
	if err := validatePlanCollections(apply); err != nil {
		return err
	}
	if !canonicalSHA256(apply.ApplyIdentity.DryRunPlanHash) {
		return failure(FailureInvalidSnapshot, "dry-run plan hash is required and canonical", nil)
	}
	if err := validateSnapshotIdentity(RetentionSnapshot{StoreEpoch: apply.StoreEpoch, InputPolicySHA256: apply.InputPolicySHA256}); err != nil {
		return err
	}
	if apply.ApplyIdentity.ExpectedStoreEpoch.Value < 0 || !canonicalSHA256(apply.ApplyIdentity.ExpectedStoreEpoch.SHA256) || !canonicalSHA256(apply.ApplyIdentity.ExpectedInputPolicySHA256) {
		return failure(FailureInvalidSnapshot, "apply identity epoch or policy hash is invalid", nil)
	}
	computed, err := PlanHash(apply)
	if err != nil {
		return failure(FailureInvalidSnapshot, "canonicalize apply plan", err)
	}
	if apply.PlanHash != computed || apply.ApplyIdentity.DryRunPlanHash != computed {
		return failure(FailureStalePlan, "apply plan hash does not match content", nil)
	}
	if apply.StoreEpoch != apply.ApplyIdentity.ExpectedStoreEpoch || apply.InputPolicySHA256 != apply.ApplyIdentity.ExpectedInputPolicySHA256 {
		return failure(FailureStalePlan, "apply identity does not match plan inputs", nil)
	}
	if len(apply.OrderedActions)%2 != 0 {
		return failure(FailureInvalidSnapshot, "ordered actions must be tombstone/delete pairs", nil)
	}
	for i := 0; i < len(apply.OrderedActions); i += 2 {
		tombstone, deletion := apply.OrderedActions[i], apply.OrderedActions[i+1]
		if tombstone.Action != "tombstone" || deletion.Action != "delete" || !canonicalRunID(tombstone.RunID) || tombstone.RunID != deletion.RunID || tombstone.Sequence+1 != deletion.Sequence || tombstone.Phase != deletion.Phase || tombstone.Reason != deletion.Reason {
			return failure(FailureInvalidSnapshot, fmt.Sprintf("invalid action pair at sequence %d", tombstone.Sequence), nil)
		}
	}
	return nil
}

func IsFailure(err error, kind FailureKind) bool {
	var typed *Failure
	return errors.As(err, &typed) && typed.Kind == kind
}
