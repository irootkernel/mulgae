package rerun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	appprompt "github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// ChildRunIssuer issues only fresh child run identities.
type ChildRunIssuer interface {
	NewRunID(time.Time) (domain.RunID, error)
}

// Config is the required authority used to construct rerun children.
type Config struct {
	Clock       ports.Clock
	IDs         ChildRunIssuer
	Assignments []review.Assignment
}

// Service starts child replay runs from verified, immutable attempt material.
type Service struct {
	sources  SourceReader
	executor ChildReplayExecutor
	config   Config
}

// NewService constructs a rerun service with the authority to read verified
// sources and execute fresh child runs.
func NewService(sources SourceReader, executor ChildReplayExecutor, config Config) (*Service, error) {
	if nilRerunDependency(sources) {
		return nil, fmt.Errorf("rerun service: source reader is required")
	}
	if nilRerunDependency(executor) {
		return nil, fmt.Errorf("rerun service: child executor is required")
	}
	if nilRerunDependency(config.Clock) || nilRerunDependency(config.IDs) || len(config.Assignments) == 0 {
		return nil, fmt.Errorf("rerun service: child run authority is incomplete")
	}
	config.Assignments = append([]review.Assignment(nil), config.Assignments...)
	return &Service{sources: sources, executor: executor, config: config}, nil
}

// StartRerun reads one immutable source attempt and executes it as a distinct
// child run. Once a valid child result is returned, the committed effect is
// never retried; source re-observation continues without caller cancellation
// so late cancellation cannot hide that effect.
func (service *Service) StartRerun(ctx context.Context, request Request) (Result, error) {
	if service == nil || nilRerunDependency(service.sources) || nilRerunDependency(service.executor) {
		return Result{}, fmt.Errorf("%w: service dependencies", ErrInvalidRequest)
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context is required", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}

	source, err := service.sources.ReadRerunSource(ctx, request.SourceRunID, request.SourceAttemptID)
	if err != nil {
		return Result{}, fmt.Errorf("rerun source: %w", err)
	}
	if err := validateSource(source, request); err != nil {
		return Result{}, err
	}
	child := childReplay(source, request.ReplayMode)
	run, err := newChildRun(source, request.ReplayMode, service.config)
	if err != nil {
		return Result{}, err
	}
	child.Run = run
	child.Assignments, err = selectedAssignmentsForSource(source, service.config.Assignments, request.ReplayMode)
	if err != nil {
		return Result{}, err
	}
	childResult, err := service.executor.ExecuteChildReplay(ctx, cloneChildReplay(child))
	if err != nil {
		return Result{}, err
	}
	if err := validateChild(childResult, child, source, request); err != nil {
		return Result{}, err
	}
	observed, err := service.sources.ReadRerunSource(context.WithoutCancel(ctx), request.SourceRunID, request.SourceAttemptID)
	if err != nil {
		return Result{}, rerunSourceMutationFailure("source reread failed", fmt.Errorf("%w: source reread: %w", ErrSourceMutated, err))
	}
	if err := validateSource(observed, request); err != nil {
		return Result{}, rerunSourceMutationFailure("source validation failed", fmt.Errorf("%w: %w", ErrSourceMutated, err))
	}
	if !sameSource(source, observed) {
		return Result{}, rerunSourceMutationFailure("source changed during child execution", ErrSourceMutated)
	}
	terminalExit, ok := childResult.TerminalExit()
	if !ok {
		return Result{}, ErrInvalidChild
	}
	return NewResult(childResult.SessionID, childResult.RunID, childResult.PromptManifestURI, childResult.RoleReportURIs, terminalExit)
}

func rerunSourceMutationFailure(reason string, cause error) error {
	failure, err := domain.NewFailure("rerun.source_reobservation", domain.FailureSecurityPolicy, reason, cause)
	if err != nil {
		return fmt.Errorf("rerun source mutation classification: %w", err)
	}
	return failure
}
func newChildRun(source SourceAttempt, mode ReplayMode, config Config) (domain.Run, error) {
	if !mode.Valid() {
		return domain.Run{}, fmt.Errorf("rerun child replay mode is invalid")
	}
	if nilRerunDependency(config.Clock) || nilRerunDependency(config.IDs) || len(config.Assignments) == 0 {
		return domain.Run{}, fmt.Errorf("rerun child run authority is incomplete")
	}
	selected, err := selectedAssignmentsForSource(source, config.Assignments, mode)
	if err != nil {
		return domain.Run{}, err
	}
	runID, err := config.IDs.NewRunID(config.Clock.Now())
	if err != nil {
		return domain.Run{}, fmt.Errorf("rerun child run ID: %w", err)
	}
	roles := make([]domain.RoleTask, 0, len(selected))
	for _, assignment := range selected {
		var fallback *string
		if route, ok := assignment.FallbackRoute(); ok {
			value := route.ProviderInstance()
			fallback = &value
		}
		task, err := domain.NewRoleTask(assignment.Role(), assignment.Required(), assignment.ProviderInstance(), fallback)
		if err != nil {
			return domain.Run{}, fmt.Errorf("rerun child role %q: %w", assignment.Role(), err)
		}
		roles = append(roles, task)
	}
	target := source.Target.Identity
	if target.Kind() == "" {
		return domain.Run{}, fmt.Errorf("rerun child target identity is required")
	}
	run, err := domain.NewRerunChildRunFromImmutableSource(
		runID, source.SessionID, source.RunID, source.RunID, target, roles[0],
	)
	if err != nil {
		return domain.Run{}, fmt.Errorf("rerun child run: %w", err)
	}
	return run, nil
}
func selectedAssignmentsForSource(source SourceAttempt, assignments []review.Assignment, mode ReplayMode) ([]review.Assignment, error) {
	selected := make([]review.Assignment, 0, 1)
	sourceRole := domain.Role(source.Prompt.Role)
	for _, assignment := range assignments {
		if assignment.Role() == sourceRole {
			selected = append(selected, assignment)
		}
	}
	if len(selected) != 1 {
		return nil, fmt.Errorf("rerun child replay requires one selected source role assignment")
	}
	if mode != ExactReplay {
		return selected, nil
	}

	assignment := selected[0]
	route := assignment.PrimaryRoute()
	if route.ProviderInstance() != source.ProviderInstance {
		fallback, ok := assignment.FallbackRoute()
		if !ok || fallback.ProviderInstance() != source.ProviderInstance {
			return nil, fmt.Errorf("rerun child exact replay requires the source provider route for its role")
		}
		route = fallback
	}
	exact, err := review.NewScheduledAssignment(assignment.Role(), assignment.Required(), route, nil)
	if err != nil {
		return nil, fmt.Errorf("rerun child exact provider route: %w", err)
	}
	return []review.Assignment{exact}, nil
}

func validateRequest(request Request) error {
	if !request.ReplayMode.Valid() {
		return fmt.Errorf("%w: replay mode", ErrInvalidRequest)
	}
	if _, err := parseRunID(request.SourceRunID); err != nil {
		return fmt.Errorf("%w: source run ID: %v", ErrInvalidRequest, err)
	}
	if _, err := parseAttemptID(request.SourceAttemptID); err != nil {
		return fmt.Errorf("%w: source attempt ID: %v", ErrInvalidRequest, err)
	}
	return nil
}

func validateSource(source SourceAttempt, request Request) error {
	if source.RunID != request.SourceRunID || source.AttemptID != request.SourceAttemptID {
		return fmt.Errorf("%w: source identity does not match request", ErrSourceCorrupt)
	}
	if _, err := parseSessionID(source.SessionID); err != nil {
		return fmt.Errorf("%w: source session ID: %v", ErrSourceCorrupt, err)
	}
	if _, err := parseReviewID(source.ReviewID); err != nil {
		return fmt.Errorf("%w: source review ID: %v", ErrSourceCorrupt, err)
	}
	if source.ProviderInstance == "" || !validTarget(source.Target) || !validPrompt(source.Prompt) || source.ImmutableSHA256 != sourceAttemptDigest(source) {
		return ErrSourceCorrupt
	}
	return nil
}

func validateChild(child ChildReplayResult, replay ChildReplay, source SourceAttempt, request Request) error {
	if _, err := parseSessionID(child.SessionID); err != nil || child.SessionID != source.SessionID {
		return ErrInvalidChild
	}
	if replay.Run.ID().String() != "" && child.RunID != replay.Run.ID() {
		return ErrInvalidChild
	}
	if _, err := parseRunID(child.RunID); err != nil || child.RunID == source.RunID {
		return ErrInvalidChild
	}
	if child.ParentRunID != source.RunID || child.SourceRunID != source.RunID || child.SourceReviewID != source.ReviewID || child.SourceAttemptID != source.AttemptID {
		return ErrInvalidChild
	}
	if child.ExecutionInvocationID == "" || child.PromptIdentity == "" || child.PromptManifestURI == "" || !validSHA256(child.PromptManifestSHA256) || child.ReplayMode != request.ReplayMode || child.ExactReplay != (request.ReplayMode == ExactReplay) {
		return ErrInvalidChild
	}
	if err := child.ValidateTerminalExit(); err != nil {
		return ErrInvalidChild
	}
	return nil
}

func childReplay(source SourceAttempt, mode ReplayMode) ChildReplay {
	publication := ChildPublicationContext{
		SessionID: source.SessionID, ParentRunID: source.RunID, SourceRunID: source.RunID,
		SourceReviewID: source.ReviewID, SourceAttemptID: source.AttemptID,
		SourceManifestURI: source.Prompt.URI, SourceManifestSHA256: source.Prompt.SHA256, ReplayMode: mode,
	}
	child := ChildReplay{
		SessionID: source.SessionID, ParentRunID: source.RunID, SourceRunID: source.RunID,
		SourceReviewID: source.ReviewID, SourceAttemptID: source.AttemptID, Mode: mode,
		Target: cloneTarget(source.Target), Scope: source.Prompt.Scope, Role: source.Prompt.Role, Publication: publication,
	}
	if mode == ExactReplay {
		child.Exact = &ExactInput{
			ComposedStdin: append([]byte(nil), source.Prompt.ComposedStdin...), ComposedStdinSHA256: source.Prompt.ComposedStdinSHA256,
			CompleteStdinSHA256: source.Prompt.CompleteStdinSHA256,
			SourceInvocationID:  source.Prompt.SourceInvocationID, SourceExecutionInvocationID: source.Prompt.ExecutionInvocationID, AdapterProfile: source.Prompt.AdapterProfile, SourceProviderInstance: source.ProviderInstance,
			TemplateID: source.Prompt.TemplateID, TemplateVersion: source.Prompt.TemplateVersion, TemplateSHA256: source.Prompt.TemplateSHA256,
			Parameters: append([]Parameter(nil), source.Prompt.Parameters...), SourceManifestURI: source.Prompt.URI, SourceManifestSHA256: source.Prompt.SHA256,
		}
	}
	return child
}

func cloneChildReplay(child ChildReplay) ChildReplay {
	child.Target = cloneTarget(child.Target)
	if child.Exact != nil {
		exact := *child.Exact
		exact.ComposedStdin = append([]byte(nil), exact.ComposedStdin...)
		exact.Parameters = append([]Parameter(nil), exact.Parameters...)
		child.Exact = &exact
	}
	return child
}

func cloneTarget(target Target) Target {
	return Target{Identity: target.Identity, Bytes: append([]byte(nil), target.Bytes...), SHA256: target.SHA256, CapturedArchive: append([]byte(nil), target.CapturedArchive...)}
}

func sameSource(left, right SourceAttempt) bool {
	return left.SessionID == right.SessionID && left.RunID == right.RunID && left.ReviewID == right.ReviewID && left.AttemptID == right.AttemptID && left.ProviderInstance == right.ProviderInstance && left.ImmutableSHA256 == right.ImmutableSHA256 && reflect.DeepEqual(left.Target, right.Target) && reflect.DeepEqual(left.Prompt, right.Prompt)
}

func validTarget(target Target) bool {
	if !validSHA256(target.SHA256) || target.SHA256 != digest(target.Bytes) {
		return false
	}
	return target.Identity.Kind() != "" && target.Identity.SHA256() == target.SHA256
}

func validPrompt(prompt PromptManifest) bool {
	if prompt.URI == "" || !validSHA256(prompt.SHA256) ||
		!validSHA256(prompt.ComposedStdinSHA256) || prompt.ComposedStdinSHA256 != digest(prompt.ComposedStdin) ||
		prompt.CompleteStdinSHA256 == "" || prompt.CompleteStdinSHA256 != appprompt.CompleteStdinSHA256(prompt.ComposedStdin) ||
		prompt.SourceInvocationID == "" || prompt.ExecutionInvocationID == "" || prompt.TemplateID == "" || prompt.TemplateVersion == "" || !validSHA256(prompt.TemplateSHA256) ||
		prompt.AdapterProfile == "" || prompt.Scope == "" || prompt.Role == "" {
		return false
	}
	for _, parameter := range prompt.Parameters {
		if parameter.Name == "" {
			return false
		}
	}
	return true
}

func digest(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

// SourceAttemptSHA256 returns the domain-separated digest adapters must bind to
// verified immutable source-attempt material. ImmutableSHA256 itself is excluded.
func SourceAttemptSHA256(source SourceAttempt) string {
	return sourceAttemptDigest(source)
}
func sourceAttemptDigest(source SourceAttempt) string {
	hasher := sha256.New()
	writeReplayDigestField(hasher, "domain", []byte("mulgae/rerun-source-attempt/v1"))
	writeReplayDigestField(hasher, "session_id", []byte(source.SessionID.String()))
	writeReplayDigestField(hasher, "run_id", []byte(source.RunID.String()))
	writeReplayDigestField(hasher, "review_id", []byte(source.ReviewID.String()))
	writeReplayDigestField(hasher, "attempt_id", []byte(source.AttemptID.String()))
	writeReplayDigestField(hasher, "provider_instance", []byte(source.ProviderInstance))
	writeReplayDigestField(hasher, "target_bytes", source.Target.Bytes)
	writeReplayDigestField(hasher, "captured_archive", source.Target.CapturedArchive)
	writeReplayDigestField(hasher, "target_sha256", []byte(source.Target.SHA256))
	writeReplayDigestField(hasher, "target_kind", []byte(source.Target.Identity.Kind()))
	writeReplayDigestField(hasher, "target_repository_id", []byte(source.Target.Identity.RepositoryID()))
	writeReplayDigestField(hasher, "target_base_oid", []byte(source.Target.Identity.BaseObjectID()))
	writeReplayDigestField(hasher, "target_head_oid", []byte(source.Target.Identity.HeadObjectID()))
	writeReplayDigestField(hasher, "target_head_tree_oid", []byte(source.Target.Identity.HeadTreeObjectID()))
	writeReplayDigestField(hasher, "target_index_tree_oid", []byte(source.Target.Identity.IndexTreeObjectID()))
	writeReplayDigestField(hasher, "target_git_mode", []byte(source.Target.Identity.GitMode()))
	writeReplayDigestField(hasher, "prompt_uri", []byte(source.Prompt.URI))
	writeReplayDigestField(hasher, "prompt_sha256", []byte(source.Prompt.SHA256))
	writeReplayDigestField(hasher, "composed_stdin", source.Prompt.ComposedStdin)
	writeReplayDigestField(hasher, "composed_stdin_sha256", []byte(source.Prompt.ComposedStdinSHA256))
	writeReplayDigestField(hasher, "complete_stdin_sha256", []byte(source.Prompt.CompleteStdinSHA256))
	writeReplayDigestField(hasher, "source_invocation_id", []byte(source.Prompt.SourceInvocationID))
	writeReplayDigestField(hasher, "execution_invocation_id", []byte(source.Prompt.ExecutionInvocationID))
	writeReplayDigestField(hasher, "template_id", []byte(source.Prompt.TemplateID))
	writeReplayDigestField(hasher, "template_version", []byte(source.Prompt.TemplateVersion))
	writeReplayDigestField(hasher, "template_sha256", []byte(source.Prompt.TemplateSHA256))
	writeReplayDigestField(hasher, "adapter_profile", []byte(source.Prompt.AdapterProfile))
	for index, parameter := range source.Prompt.Parameters {
		writeReplayDigestField(hasher, fmt.Sprintf("parameter.%d.name", index), []byte(parameter.Name))
		writeReplayDigestField(hasher, fmt.Sprintf("parameter.%d.value", index), []byte(parameter.Value))
	}
	writeReplayDigestField(hasher, "scope", []byte(source.Prompt.Scope))
	writeReplayDigestField(hasher, "role", []byte(source.Prompt.Role))
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeReplayDigestField(hasher interface{ Write([]byte) (int, error) }, name string, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(name)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write([]byte(name))
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func parseSessionID(id interface{ String() string }) (string, error) {
	value := id.String()
	if _, err := domain.ParseSessionID(value); err != nil {
		return "", err
	}
	return value, nil
}

func parseRunID(id interface{ String() string }) (string, error) {
	value := id.String()
	if _, err := domain.ParseRunID(value); err != nil {
		return "", err
	}
	return value, nil
}

func parseAttemptID(id interface{ String() string }) (string, error) {
	value := id.String()
	if _, err := domain.ParseAttemptID(value); err != nil {
		return "", err
	}
	return value, nil
}

func parseReviewID(id interface{ String() string }) (string, error) {
	value := id.String()
	if _, err := domain.ParseReviewID(value); err != nil {
		return "", err
	}
	return value, nil
}

func nilRerunDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
