package delta

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Service coordinates the immutable delta child workflow. It owns source
// identity, role, and lineage checks; the executor owns child execution and
// publication.
type Service struct {
	clock      ports.Clock
	ids        IdentityGenerator
	sources    SourceReader
	capturer   TargetCapturer
	comparator Comparator
	executor   ChildExecutor
}

// NewService constructs a delta service with the narrow capabilities needed to
// create a child run. Every dependency is required because omissions would
// weaken a fail-closed source or child invariant.
func NewService(clock ports.Clock, ids IdentityGenerator, sources SourceReader, capturer TargetCapturer, comparator Comparator, executor ChildExecutor) (*Service, error) {
	if nilDeltaDependency(clock) {
		return nil, fmt.Errorf("delta service: clock is required")
	}
	if nilDeltaDependency(ids) {
		return nil, fmt.Errorf("delta service: identity generator is required")
	}
	if nilDeltaDependency(sources) {
		return nil, fmt.Errorf("delta service: source reader is required")
	}
	if nilDeltaDependency(capturer) {
		return nil, fmt.Errorf("delta service: target capturer is required")
	}
	if nilDeltaDependency(comparator) {
		return nil, fmt.Errorf("delta service: comparator is required")
	}
	if nilDeltaDependency(executor) {
		return nil, fmt.Errorf("delta service: child executor is required")
	}
	return &Service{clock: clock, ids: ids, sources: sources, capturer: capturer, comparator: comparator, executor: executor}, nil
}

// StartDeltaRun captures the current target, compares it with the verified
// source snapshot, and delegates a fresh, lineage-bound child to the executor.
// It returns only after re-reading the source receipt to prove source invariance.
func (service *Service) StartDeltaRun(ctx context.Context, request StartRequest) (Result, error) {
	if service == nil || nilDeltaDependency(service.clock) || nilDeltaDependency(service.ids) || nilDeltaDependency(service.sources) || nilDeltaDependency(service.capturer) || nilDeltaDependency(service.comparator) || nilDeltaDependency(service.executor) {
		return Result{}, fmt.Errorf("delta service: dependencies are required")
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("delta context is required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := request.Target.validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if _, err := domain.ParseRunID(request.SourceRunID.String()); err != nil {
		return Result{}, fmt.Errorf("delta source: invalid source run ID: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	source, err := service.sources.ReadSource(ctx, request.SourceRunID)
	if err != nil {
		return Result{}, fmt.Errorf("delta source: %w", err)
	}
	source, err = source.normalized()
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := source.validate(request.SourceRunID); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	roles, err := childRoles(source.Roles, request.Roles)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	current, err := service.capturer.CaptureTarget(ctx, request.Target)
	if err != nil {
		return Result{}, fmt.Errorf("delta current target: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := current.validate("current"); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if current.Kind() != request.Target.Kind || current.Value() != request.Target.Value {
		return Result{}, fmt.Errorf("delta current target: capturer changed requested kind or value")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	currentIdentity := current.Identity()

	delta, err := service.comparator.Compare(ctx, source.Target, current)
	if err != nil {
		return Result{}, fmt.Errorf("delta compare: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	runID, err := service.ids.NewRunID(service.clock.Now())
	if err != nil {
		return Result{}, fmt.Errorf("delta child run ID: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	child, err := domain.NewChildRunFromImmutableSource(runID, domain.RunTypeDelta, source.SessionID, source.RunID, source.RunID, currentIdentity, roles)
	if err != nil {
		return Result{}, fmt.Errorf("delta child run: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	execution, err := service.executor.ExecuteDelta(ctx, (ChildRequest{
		Run:            child,
		SourceReviewID: source.ReviewID,
		SourceTarget:   source.Target,
		CurrentTarget:  current,
		Delta:          delta,
	}).clone())
	if err != nil {
		return Result{}, fmt.Errorf("delta execute: %w", err)
	}
	if execution.SessionID != child.SessionID() || execution.RunID != child.ID() || execution.ReviewArtifactURI == "" {
		return Result{}, fmt.Errorf("delta execute: child result does not bind the new child run")
	}
	if err := execution.ValidateTerminalExit(); err != nil {
		return Result{}, fmt.Errorf("delta execute: %w", err)
	}
	terminalExit, ok := execution.TerminalExit()
	if !ok {
		return Result{}, fmt.Errorf("delta execute: terminal exit is absent")
	}

	after, err := service.sources.ReadSource(context.WithoutCancel(ctx), request.SourceRunID)
	if err != nil {
		return Result{}, deltaSourceMutationFailure("source reread failed", err)
	}
	after, err = after.normalized()
	if err != nil {
		return Result{}, deltaSourceMutationFailure("source normalization failed", err)
	}
	if err := after.validate(request.SourceRunID); err != nil {
		return Result{}, deltaSourceMutationFailure("source validation failed", err)
	}
	if after.Receipt != source.Receipt || after.SessionID != source.SessionID || after.RunID != source.RunID || after.ReviewID != source.ReviewID ||
		after.Target.Kind() != source.Target.Kind() || after.Target.Value() != source.Target.Value() ||
		after.Target.SHA256() != source.Target.SHA256() ||
		!bytes.Equal(after.Target.Bytes(), source.Target.Bytes()) {
		return Result{}, deltaSourceMutationFailure("source changed during child execution", nil)
	}
	return NewResult(execution.SessionID, execution.RunID, execution.ReviewArtifactURI, execution.RoleReportURIs, terminalExit)
}

func deltaSourceMutationFailure(reason string, cause error) error {
	failure, err := domain.NewFailure("delta.source_reobservation", domain.FailureSecurityPolicy, reason, cause)
	if err != nil {
		return fmt.Errorf("delta source mutation classification: %w", err)
	}
	return failure
}

func childRoles(source []domain.RoleTask, requested []domain.Role) ([]domain.RoleTask, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("delta roles: at least one role is required")
	}
	byRole := make(map[domain.Role]domain.RoleTask, len(source))
	for _, task := range source {
		byRole[task.Role()] = task
	}
	seen := make(map[domain.Role]struct{}, len(requested))
	for _, role := range requested {
		if !role.Valid() {
			return nil, fmt.Errorf("delta roles: invalid role %q", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, fmt.Errorf("delta roles: duplicate role %q", role)
		}
		if _, exists := byRole[role]; !exists {
			return nil, fmt.Errorf("delta roles: source does not configure role %q", role)
		}
		seen[role] = struct{}{}
	}
	for _, required := range []domain.Role{domain.RoleLogic} {
		if _, exists := seen[required]; !exists {
			return nil, fmt.Errorf("delta roles: required role %q is missing", required)
		}
	}
	ordered := append([]domain.Role(nil), requested...)
	sort.Slice(ordered, func(i, j int) bool {
		return roleOrder(ordered[i]) < roleOrder(ordered[j])
	})
	roles := make([]domain.RoleTask, 0, len(ordered))
	for _, role := range ordered {
		sourceTask := byRole[role]
		task, err := domain.NewRoleTask(role, sourceTask.Required(), sourceTask.PrimaryProvider())
		if err != nil {
			return nil, fmt.Errorf("delta roles: source role %q is invalid: %w", role, err)
		}
		roles = append(roles, task)
	}
	return roles, nil
}

func roleOrder(role domain.Role) int {
	for index, candidate := range domain.FixedRoleOrder() {
		if role == candidate {
			return index
		}
	}
	return len(domain.FixedRoleOrder())
}

func nilDeltaDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
