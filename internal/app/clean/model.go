// Package clean builds deterministic, side-effect-free retention plans.
package clean

import (
	"strings"
	"time"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
)

const SchemaVersion = "kar-clean-plan.v1"

type FailureKind string

const (
	FailureInvalidSnapshot FailureKind = "invalid_snapshot"
	FailureInvalidGraph    FailureKind = "invalid_graph"
	FailureInvalidPath     FailureKind = "invalid_path"
	FailureStalePlan       FailureKind = "stale_plan"
	FailureTombstone       FailureKind = "tombstone"
)

type Failure struct {
	Kind    FailureKind
	Message string
	Cause   error
}

func (failure *Failure) Error() string {
	if failure.Cause == nil {
		return "clean: " + string(failure.Kind) + ": " + failure.Message
	}
	return "clean: " + string(failure.Kind) + ": " + failure.Message + ": " + failure.Cause.Error()
}

func (failure *Failure) Unwrap() error { return failure.Cause }

func failure(kind FailureKind, message string, cause error) error {
	return &Failure{Kind: kind, Message: message, Cause: cause}
}

type Reason string

const (
	ReasonProtectedExplicit Reason = "protected_explicit"
	ReasonActive            Reason = "active"
	ReasonUncommitted       Reason = "uncommitted"
	ReasonCorrupt           Reason = "corrupt"
	ReasonNewestSession     Reason = "newest_session"
	ReasonAncestor          Reason = "ancestor"
	ReasonGraphAnomaly      Reason = "graph_anomaly"
	ReasonMissingTime       Reason = "missing_time"
	ReasonYoung             Reason = "young"
	ReasonEligibleAge       Reason = "eligible_age"
	ReasonEligibleSize      Reason = "eligible_size"
	ReasonDeletedAge        Reason = "deleted_age"
	ReasonDeletedSize       Reason = "deleted_size"
	ReasonTargetProtected   Reason = "target_not_reached_protected"
	ReasonStaleEpoch        Reason = "stale_epoch"
	ReasonPartialResume     Reason = "partial_delete_resume"
)

type Policy struct {
	RetentionAgeSeconds  int64    `json:"retention_age_seconds"`
	MinAgeForSizeSeconds int64    `json:"min_age_for_size_seconds"`
	TargetBytes          int64    `json:"target_bytes"`
	ExplicitKeepRunIDs   []string `json:"explicit_keep_run_ids"`
}

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return append([]T{}, values...)
}

func (p Policy) clone() Policy {
	p.ExplicitKeepRunIDs = cloneSlice(p.ExplicitKeepRunIDs)
	return p
}

type StoreEpoch struct {
	Value  int64  `json:"value"`
	SHA256 string `json:"sha256"`
}

type RunKind string

const (
	RunKindPublication    RunKind = "publication"
	RunKindDiagnosticOnly RunKind = "diagnostic_only"
)

type RunObservation struct {
	RunID               string
	SessionID           string
	Kind                RunKind
	Completed           bool
	CompletedAt         *time.Time
	Active              bool
	Committed           bool
	Corrupt             bool
	DiagnosticProtected bool
	RegularFileBytes    int64
}

func (r RunObservation) kind() RunKind {
	if r.Kind == "" {
		return RunKindPublication
	}
	return r.Kind
}

func (r RunObservation) completion() (time.Time, bool) {
	if !r.Completed || r.CompletedAt == nil || r.CompletedAt.IsZero() {
		return time.Time{}, false
	}
	return r.CompletedAt.UTC(), true
}

type LineageEdgeRef struct {
	ParentRunID string `json:"parent_run_id"`
	ChildRunID  string `json:"child_run_id"`
	EdgePath    string `json:"edge_path"`
	SHA256      string `json:"sha256"`
}

type LineageEdgeObservation struct {
	LineageEdgeRef
	// Valid is false when the edge record is malformed or fails its integrity checks.
	Valid bool
}

type RetentionSnapshot struct {
	Now                       time.Time
	StoreEpoch                StoreEpoch
	InputPolicySHA256         string
	Policy                    Policy
	Runs                      []RunObservation
	Edges                     []LineageEdgeObservation
	ProtectedRegularFileBytes int64
}

func (s RetentionSnapshot) Clone() RetentionSnapshot {
	s.Policy = s.Policy.clone()
	s.Runs = cloneSlice(s.Runs)
	for i := range s.Runs {
		if s.Runs[i].CompletedAt != nil {
			value := *s.Runs[i].CompletedAt
			s.Runs[i].CompletedAt = &value
		}
	}
	s.Edges = cloneSlice(s.Edges)
	return s
}
func canonicalRunID(value string) bool {
	_, err := domain.ParseRunID(value)
	return err == nil
}

func canonicalSessionID(value string) bool {
	_, err := domain.ParseSessionID(value)
	return err == nil
}

func canonicalSHA256(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validateSnapshotIdentity(snapshot RetentionSnapshot) error {
	if snapshot.StoreEpoch.Value < 0 || !canonicalSHA256(snapshot.StoreEpoch.SHA256) || !canonicalSHA256(snapshot.InputPolicySHA256) {
		return failure(FailureInvalidSnapshot, "invalid epoch or policy hash", nil)
	}
	return nil
}

type AncestorProtection struct {
	AncestorRunID           string           `json:"ancestor_run_id"`
	RetainedDescendantRunID string           `json:"retained_descendant_run_id"`
	LineageEdgeRefs         []LineageEdgeRef `json:"lineage_edge_refs"`
}
type GraphAnomalyComponent struct {
	AffectedRunIDs  []string         `json:"affected_run_ids"`
	LineageEdgeRefs []LineageEdgeRef `json:"lineage_edge_refs"`
}
type RetentionProtection struct {
	RetainedSeedRunIDs           []string                `json:"retained_seed_run_ids"`
	TransitiveAncestorProtection []AncestorProtection    `json:"transitive_ancestor_protection"`
	GraphAnomalyComponents       []GraphAnomalyComponent `json:"graph_anomaly_components"`
}
type RunDecision struct {
	RunID    string   `json:"run_id"`
	Decision string   `json:"decision"`
	Reasons  []Reason `json:"reasons"`
}
type DeleteSetEntry struct {
	RunID            string `json:"run_id"`
	CompletedAt      string `json:"completed_at"`
	RegularFileBytes int64  `json:"regular_file_bytes"`
	Reason           Reason `json:"reason"`
}
type DeleteSets struct {
	AgeDeleteSet  []DeleteSetEntry `json:"age_delete_set"`
	SizeDeleteSet []DeleteSetEntry `json:"size_delete_set"`
}
type OrderedAction struct {
	Sequence      int    `json:"sequence"`
	Phase         string `json:"phase"`
	Action        string `json:"action"`
	RunID         string `json:"run_id"`
	Reason        Reason `json:"reason"`
	BytesReleased int64  `json:"bytes_released"`
}
type ByteAccounting struct {
	InitialRegularFileBytes   int64 `json:"initial_regular_file_bytes"`
	AgeDeleteBytes            int64 `json:"age_delete_bytes"`
	SizeDeleteBytes           int64 `json:"size_delete_bytes"`
	PlannedDeleteBytes        int64 `json:"planned_delete_bytes"`
	ProjectedRegularFileBytes int64 `json:"projected_regular_file_bytes"`
	TargetBytes               int64 `json:"target_bytes"`
	TargetReached             bool  `json:"target_reached"`
}
type ApplyIdentity struct {
	DryRunPlanHash            string     `json:"dry_run_plan_hash"`
	ExpectedStoreEpoch        StoreEpoch `json:"expected_store_epoch"`
	ExpectedInputPolicySHA256 string     `json:"expected_input_policy_sha256"`
}
type CleanPlan struct {
	SchemaVersion       string              `json:"schema_version"`
	Mode                string              `json:"mode"`
	Now                 string              `json:"now"`
	StoreEpoch          StoreEpoch          `json:"store_epoch"`
	InputPolicySHA256   string              `json:"input_policy_sha256"`
	Policy              Policy              `json:"policy"`
	RetentionProtection RetentionProtection `json:"retention_protection"`
	RunDecisions        []RunDecision       `json:"run_decisions"`
	DeleteSets          DeleteSets          `json:"delete_sets"`
	OrderedActions      []OrderedAction     `json:"ordered_actions"`
	ByteAccounting      ByteAccounting      `json:"byte_accounting"`
	OutcomeReasons      []Reason            `json:"outcome_reasons"`
	PlanHash            string              `json:"plan_hash"`
	ApplyIdentity       *ApplyIdentity      `json:"apply_identity"`
}

func (p CleanPlan) Clone() CleanPlan {
	p.Policy = p.Policy.clone()
	p.RetentionProtection.RetainedSeedRunIDs = cloneSlice(p.RetentionProtection.RetainedSeedRunIDs)
	p.RetentionProtection.TransitiveAncestorProtection = cloneSlice(p.RetentionProtection.TransitiveAncestorProtection)
	for i := range p.RetentionProtection.TransitiveAncestorProtection {
		p.RetentionProtection.TransitiveAncestorProtection[i].LineageEdgeRefs = cloneSlice(p.RetentionProtection.TransitiveAncestorProtection[i].LineageEdgeRefs)
	}
	p.RetentionProtection.GraphAnomalyComponents = cloneSlice(p.RetentionProtection.GraphAnomalyComponents)
	for i := range p.RetentionProtection.GraphAnomalyComponents {
		c := &p.RetentionProtection.GraphAnomalyComponents[i]
		c.AffectedRunIDs = cloneSlice(c.AffectedRunIDs)
		c.LineageEdgeRefs = cloneSlice(c.LineageEdgeRefs)
	}
	p.RunDecisions = cloneSlice(p.RunDecisions)
	for i := range p.RunDecisions {
		p.RunDecisions[i].Reasons = cloneSlice(p.RunDecisions[i].Reasons)
	}
	p.DeleteSets.AgeDeleteSet = cloneSlice(p.DeleteSets.AgeDeleteSet)
	p.DeleteSets.SizeDeleteSet = cloneSlice(p.DeleteSets.SizeDeleteSet)
	p.OrderedActions = cloneSlice(p.OrderedActions)
	p.OutcomeReasons = cloneSlice(p.OutcomeReasons)
	if p.ApplyIdentity != nil {
		value := *p.ApplyIdentity
		p.ApplyIdentity = &value
	}
	return p
}
